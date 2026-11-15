// noragate daemon — the phone-side gate, as a single static binary.
//
// Why Go and not the Python prototype: this ships inside an APK as a native
// library, so it must be one self-contained arm64 binary with no interpreter
// and no Termux. Behaviour matches the Python gate; the control API is the
// contract, so both implementations answer the same requests.
//
// Design notes that matter:
//   - It never forwards. Every client connection is terminated here and a new
//     one is opened from the phone's own stack, which is why the far end sees
//     phone-shaped traffic (TTL 64, the phone's address, the phone's resolver).
//   - A VpnService that is up captures these sockets automatically, so the same
//     daemon puts a hotspot behind the tunnel without touching the framework.
//   - The egress guard exists because a kill-switch exclusion, a split-tunnel
//     rule and a dead tunnel all look identical from inside: traffic just
//     leaves direct.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ---------------------------------------------------------------- config ---

type clientMeta struct {
	Label string `json:"label,omitempty"`
	Deny  bool   `json:"deny,omitempty"`
	Cap   int64  `json:"cap,omitempty"` // bytes/sec, 0 = uncapped
	DNS   string `json:"dns,omitempty"` // per-client resolver
}

type config struct {
	Allow         []string              `json:"allow"`         // nil = every client
	ExpectEgress  []string              `json:"expect_egress"` // CIDRs
	BlockOnLeak   bool                  `json:"block_on_leak"`
	BlockOnChange bool                  `json:"block_on_change"`
	DefaultCap    int64                 `json:"default_cap"`
	DNS           string                `json:"dns"`
	UA            string                `json:"ua"`
	VPN           string                `json:"vpn"`
	Clients       map[string]clientMeta `json:"clients"`

	// The egress probe is the daemon's only outbound traffic that is not a
	// client's. These are start-time settings, not persisted config: a config
	// file written before the field existed must not be read as "probe off".
	egressURLs      []string
	egressProbeSecs int
	egressUA        string

	listen   string
	proxy    string
	state    string
	path     string
	uiDir    string
	maxConns int
	vpndir   string
}

// ----------------------------------------------------------------- state ---

type clientStats struct {
	Conns   int64            `json:"conns"`
	Open    int64            `json:"open"`
	Up      int64            `json:"up"`
	Down    int64            `json:"down"`
	Targets map[string]int64 `json:"targets"`
}

type dnsEvent struct {
	T      int64    `json:"t"`
	Client string   `json:"client"`
	Host   string   `json:"host"`
	Via    string   `json:"via"`
	Addrs  []string `json:"addrs"`
}

type daemon struct {
	mu       sync.Mutex
	cfg      config
	clients  map[string]*clientStats
	log      *slog.Logger
	egress   egressState
	dnsLog   []dnsEvent
	started  time.Time
	drivers  []vpnDriver
	total    atomic.Int64
	active   atomic.Int64
	resolver *net.Resolver
}

type egressState struct {
	State    string   `json:"state"`
	IP       string   `json:"ip"`
	Baseline string   `json:"baseline"`
	Checked  int64    `json:"checked"`
	History  []string `json:"history"`
}

func newDaemon(cfg config, log *slog.Logger) *daemon {
	d := &daemon{
		cfg:     cfg,
		clients: map[string]*clientStats{},
		log:     log,
		started: time.Now(),
	}
	if cfg.Clients == nil {
		cfg.Clients = map[string]clientMeta{}
	}
	d.cfg = cfg
	d.egress = egressState{State: "unknown"}
	d.drivers = loadDrivers(cfg.vpndir)
	if cfg.VPN != "" {
		d.activateVPN(cfg.VPN)
	}
	d.resolver = buildResolver(cfg.DNS)
	return d
}

// --------------------------------------------------------------- helpers ---

func (d *daemon) stats(ip string) *clientStats {
	d.mu.Lock()
	defer d.mu.Unlock()
	c, ok := d.clients[ip]
	if !ok {
		c = &clientStats{Targets: map[string]int64{}}
		d.clients[ip] = c
	}
	return c
}

func (d *daemon) open(ip, target string) {
	c := d.stats(ip)
	d.mu.Lock()
	c.Conns++
	c.Open++
	c.Targets[target]++
	d.mu.Unlock()
}

func (d *daemon) close(ip string) {
	c := d.stats(ip)
	d.mu.Lock()
	if c.Open > 0 {
		c.Open--
	}
	d.mu.Unlock()
}

func (d *daemon) bytes(ip string, up, down int64) {
	c := d.stats(ip)
	d.mu.Lock()
	c.Up += up
	c.Down += down
	d.mu.Unlock()
}

func (d *daemon) allowed(ip string) (bool, string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if m, ok := d.cfg.Clients[ip]; ok && m.Deny {
		return false, "blocked client"
	}
	if len(d.cfg.Allow) > 0 {
		found := false
		for _, a := range d.cfg.Allow {
			if a == ip {
				found = true
				break
			}
		}
		if !found {
			return false, "allowlist"
		}
	}
	if d.egress.State == "leak" || d.egress.State == "changed" {
		return false, "egress guard"
	}
	return true, ""
}

func (d *daemon) capFor(ip string) int64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	if m, ok := d.cfg.Clients[ip]; ok && m.Cap > 0 {
		return m.Cap
	}
	return d.cfg.DefaultCap
}

// pace is a token bucket per client: sleep just long enough to hold the rate.
type bucket struct {
	mu     sync.Mutex
	tokens map[string]*[2]float64 // [tokens, lastUnix]
}

var buckets = &bucket{tokens: map[string]*[2]float64{}}

func (b *bucket) pace(ip string, capBytes int64, n int64) {
	if capBytes <= 0 || n <= 0 {
		return
	}
	capf := float64(capBytes)
	b.mu.Lock()
	s, ok := b.tokens[ip]
	now := float64(time.Now().UnixNano()) / 1e9
	if !ok {
		s = &[2]float64{capf, now}
		b.tokens[ip] = s
	}
	s[0] = min(capf, s[0]+(now-s[1])*capf)
	s[1] = now
	s[0] -= float64(n)
	deficit := -s[0]
	b.mu.Unlock()
	if deficit > 0 {
		time.Sleep(time.Duration(min(1.0, deficit/capf)*1e9) * time.Nanosecond)
	}
}

// ---------------------------------------------------------------- tunnel ---

func (d *daemon) relay(a, b net.Conn, ip string, capBytes int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(clientToUp bool, dst, src net.Conn) {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
				if clientToUp {
					d.bytes(ip, int64(n), 0)
				} else {
					d.bytes(ip, 0, int64(n))
				}
				buckets.pace(ip, capBytes, int64(n))
			}
			if err != nil {
				break
			}
		}
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}
	go pipe(true, b, a)
	go pipe(false, a, b)
	wg.Wait()
}

// dialUpstream resolves on the phone and connects from its own stack. It must
// not hand the hostname to net.Dialer: that resolves through the system
// resolver, which on Android points at /etc/resolv.conf and fails for an app
// uid - the symptom is every dial erroring while the resolver looks configured.
func (d *daemon) dialUpstream(ctx context.Context, host, port, clientIP string) (net.Conn, error) {
	addrs, err := d.resolveOnPhone(ctx, clientIP, host)
	if err != nil {
		return nil, err
	}
	nd := net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	var lastErr error
	for _, a := range addrs {
		c, err := nd.DialContext(ctx, "tcp", net.JoinHostPort(a, port))
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no addresses")
	}
	return nil, lastErr
}

func buildResolver(server string) *net.Resolver {
	if server == "" {
		return net.DefaultResolver
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			nd := net.Dialer{Timeout: 5 * time.Second}
			return nd.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
		},
	}
}

// resolveOnPhone keeps the client's resolver off the wire, which is part of the
// identity story: the lookup rides the phone, and the tunnel when one is up.
func (d *daemon) resolveOnPhone(ctx context.Context, ip, host string) ([]string, error) {
	if net.ParseIP(host) != nil {
		return []string{host}, nil
	}
	d.mu.Lock()
	server := d.cfg.DNS
	if m, ok := d.cfg.Clients[ip]; ok && m.DNS != "" {
		server = m.DNS
	}
	d.mu.Unlock()

	r := d.resolver
	if server != d.cfg.DNS {
		r = buildResolver(server)
	}
	addrs, err := r.LookupHost(ctx, host)
	if err != nil && r != net.DefaultResolver {
		addrs, err = net.DefaultResolver.LookupHost(ctx, host)
	}
	if err != nil {
		return nil, err
	}
	d.mu.Lock()
	d.dnsLog = append(d.dnsLog, dnsEvent{
		T: time.Now().Unix(), Client: ip, Host: host, Via: server, Addrs: addrs,
	})
	if len(d.dnsLog) > 200 {
		d.dnsLog = d.dnsLog[len(d.dnsLog)-200:]
	}
	d.mu.Unlock()
	return addrs, nil
}

// activateVPN adopts a driver: its DNS if it names one, its exit ranges if it
// publishes any, and either way a fresh baseline so the guard measures this
// tunnel rather than the last one. Seams are what make a bridge look like a
// bridge; a driver is the same idea one layer up.
func (d *daemon) activateVPN(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if name == "" {
		d.cfg.VPN = ""
		d.egress.Baseline = ""
		d.egress.State = "unknown"
		d.log.Info("vpn driver cleared")
		return
	}
	drv := driverForPackage(d.drivers, "") // placeholder, replaced below
	for i := range d.drivers {
		if d.drivers[i].Name == name {
			drv = &d.drivers[i]
			break
		}
	}
	if drv == nil || drv.Name == "" {
		d.log.Warn("unknown vpn driver", "name", name)
		return
	}
	d.cfg.VPN = drv.Name
	if drv.DNS != "" {
		d.cfg.DNS = drv.DNS
		d.resolver = buildResolver(drv.DNS)
	}
	if len(drv.ExpectEgress) > 0 {
		d.cfg.ExpectEgress = drv.ExpectEgress
	} else {
		// No published ranges: learn them, and fail closed if the exit moves.
		d.cfg.ExpectEgress = nil
		d.cfg.BlockOnChange = true
	}
	d.egress.Baseline = ""
	d.egress.State = "unknown"
	d.log.Info("vpn driver active", "driver", drv.Name, "dns", d.cfg.DNS,
		"expect", d.cfg.ExpectEgress, "learn_baseline", len(drv.ExpectEgress) == 0)
}

// --------------------------------------------------------------- egress ---

// The daemon's entire outbound surface is this list. There is no telemetry, no
// update check and no analytics: if you point these at your own endpoint, or turn
// the probe off, the daemon makes no connections that are not client traffic.
var defaultEgressURLs = []string{
	"http://ifconfig.me/ip",
	"http://api.ipify.org/",
	"http://icanhazip.com/",
}

func (d *daemon) egressURLs() []string {
	if len(d.cfg.egressURLs) > 0 {
		return d.cfg.egressURLs
	}
	return defaultEgressURLs
}

func (d *daemon) fetchEgress(ctx context.Context) (string, error) {
	client := &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy: nil,
			// No Accept-Encoding either: the default gzip offer is a second
			// thing on the wire that nothing here needs.
			DisableCompression: true,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, err
				}
				return d.dialUpstream(ctx, host, port, "")
			},
		},
	}
	// Plain HTTP on purpose: a statically linked Go binary inside an APK has no
	// system CA bundle to verify a TLS chain against, so an https probe fails
	// with "certificate signed by unknown authority" on the phone. The probe is
	// only reading back our own address, and a captive portal cannot silently
	// swap it for a valid tunnel address.
	//
	// Headers are minimised deliberately. Setting User-Agent unconditionally is
	// what suppresses Go's own "Go-http-client/1.1" default — an empty value
	// means the header is not written at all. Measured on the wire, the whole
	// request is then one "Host:" line, which is the least this can say while
	// still being an HTTP request. A distinctive agent, or the Go default, is an
	// outbound signature that says "this device runs this tool".
	for _, u := range d.egressURLs() {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", d.cfg.egressUA)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		resp.Body.Close()
		ip := strings.TrimSpace(string(body))
		if net.ParseIP(ip) != nil {
			return ip, nil
		}
	}
	return "", errors.New("all egress probes failed")
}

// probeEgressOnce measures the daemon's own exit address once and folds it into
// the guard state. The ticker calls it, and so does anything that has just
// changed the path (a driver activation, a relearn) because those callers already
// know the stored reading is about a network that no longer exists.
func (d *daemon) probeEgressOnce(ctx context.Context) {
	ip, err := d.fetchEgress(ctx)
	d.mu.Lock()
	switch {
	case err != nil:
		d.egress.State = "unreachable"
		d.log.Warn("egress probe failed", "err", err)
	case len(d.cfg.ExpectEgress) > 0:
		if withinAny(ip, d.cfg.ExpectEgress) {
			d.egress.State = "ok"
		} else {
			d.egress.State = "leak"
		}
	case d.egress.Baseline == "":
		d.egress.Baseline = ip
		d.egress.State = "ok"
	case ip != d.egress.Baseline:
		d.egress.State = "changed"
		d.egress.History = append(d.egress.History, d.egress.Baseline+"->"+ip)
	default:
		d.egress.State = "ok"
	}
	if err == nil {
		d.egress.IP = ip
		d.egress.Checked = time.Now().Unix()
		if d.egress.State != "ok" {
			d.log.Warn("egress guard", "state", d.egress.State, "ip", ip, "baseline", d.egress.Baseline)
		}
	}
	d.mu.Unlock()
}

func (d *daemon) egressLoop(ctx context.Context, every time.Duration) {
	if every <= 0 {
		d.mu.Lock()
		d.egress.State = "disabled"
		d.mu.Unlock()
		if len(d.cfg.ExpectEgress) > 0 {
			d.log.Warn("egress probe disabled but expect_egress is set: the guard cannot verify anything, clients will not be refused")
		} else {
			d.log.Info("egress probe disabled: the daemon makes no outbound connections of its own")
		}
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		d.probeEgressOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func withinAny(ip string, cidrs []string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil && n.Contains(parsed) {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------------ main ---

func main() {
	var cfg config
	flag.StringVar(&cfg.listen, "listen", "127.0.0.1:1080", "SOCKS5 address")
	flag.StringVar(&cfg.proxy, "proxy", "127.0.0.1:8080", "HTTP proxy address")
	flag.StringVar(&cfg.state, "state", "127.0.0.1:8081", "control API address")
	flag.StringVar(&cfg.path, "config", defaultConfigPath(), "config file")
	flag.StringVar(&cfg.uiDir, "ui", "", "directory holding the web app")
	flag.IntVar(&cfg.maxConns, "max-conns", 256, "concurrent connection cap")
	flag.BoolVar(&cfg.BlockOnLeak, "block-on-leak", false, "refuse clients when egress leaves expect_egress")
	flag.StringVar(&cfg.DNS, "dns", "", "resolver for upstream lookups (empty = system)")
	flag.StringVar(&cfg.vpndir, "vpns", "", "directory of VPN driver JSON files")
	flag.StringVar(&cfg.VPN, "vpn", "", "active VPN driver name (empty = none)")
	var egressURLList string
	flag.StringVar(&egressURLList, "egress-url", "", "comma-separated URLs used to measure the exit address (default: three public IP-echo services)")
	flag.IntVar(&cfg.egressProbeSecs, "egress-probe", 300, "seconds between egress probes; 0 disables the probe, and the daemon then makes no outbound connections of its own")
	flag.StringVar(&cfg.egressUA, "egress-ua", "", "User-Agent sent with the egress probe (empty = send none)")
	verbose := flag.Bool("v", false, "debug logging")
	flag.Parse()
	if egressURLList != "" {
		for _, u := range strings.Split(egressURLList, ",") {
			if u = strings.TrimSpace(u); u != "" {
				cfg.egressURLs = append(cfg.egressURLs, u)
			}
		}
	}

	lvl := slog.LevelInfo
	if *verbose {
		lvl = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	slog.SetDefault(log)

	if disk, err := loadConfig(cfg.path); err == nil {
		disk.listen, disk.proxy, disk.state, disk.path, disk.uiDir, disk.maxConns, disk.vpndir =
			cfg.listen, cfg.proxy, cfg.state, cfg.path, cfg.uiDir, cfg.maxConns, cfg.vpndir
		disk.egressURLs, disk.egressProbeSecs, disk.egressUA =
			cfg.egressURLs, cfg.egressProbeSecs, cfg.egressUA
		if disk.VPN == "" {
			disk.VPN = cfg.VPN
		}
		if disk.DNS == "" {
			disk.DNS = cfg.DNS
		}
		cfg = disk
		log.Info("config loaded", "path", cfg.path)
	}

	d := newDaemon(cfg, log)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	probeEvery := time.Duration(cfg.egressProbeSecs) * time.Second
	if cfg.egressProbeSecs <= 0 {
		probeEvery = 0
	}
	go d.egressLoop(ctx, probeEvery)
	go d.serveProxy(ctx)

	var socksWg sync.WaitGroup
	socksWg.Add(1)
	go func() {
		defer socksWg.Done()
		d.serveSOCKS(ctx)
	}()

	if err := d.serveAPI(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("control API stopped", "err", err)
	}
	socksWg.Wait()
	log.Info("shutdown complete", "handled", d.total.Load())
}

func defaultConfigPath() string {
	if v := os.Getenv("NORAGATE_CONFIG"); v != "" {
		return v
	}
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "noragate", "config.json")
	}
	return "config.json"
}

func loadConfig(path string) (config, error) {
	var c config
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return c, err
	}
	if c.Clients == nil {
		c.Clients = map[string]clientMeta{}
	}
	return c, nil
}

func (d *daemon) saveConfig() error {
	d.mu.Lock()
	out := d.cfg
	d.mu.Unlock()
	out.listen, out.proxy, out.state, out.path, out.uiDir, out.maxConns, out.vpndir = "", "", "", "", "", 0, ""
	b, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(d.cfg.path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(d.cfg.path, b, 0o600)
}

// atoi is the strconv wrapper the API uses; kept separate so parse errors are
// reported as caller errors rather than panics.
func atoi(s string) (int64, error) { return strconv.ParseInt(s, 10, 64) }

var _ = bufio.NewReader // keep the import meaningful as the file grows
