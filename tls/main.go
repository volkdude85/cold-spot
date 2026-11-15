// noragate-tls — TLS termination at the gate, re-originated with a chosen ClientHello.
//
// A CONNECT tunnel passes the client's handshake through untouched, so the
// fingerprint reaching the far end is the client's, not the phone's (measured
// with ja3_probe: identical JA3 direct and through a plain tunnel). The only way
// to change it is to terminate TLS here and open a new handshake with a profile
// we choose — uTLS supplies the profiles.
//
// Practices reflected here (checked against Go 1.26/1.27 release notes on
// 2026-11-14 rather than recalled): signal.NotifyContext + Dialer.DialContext
// for cancellation, log/slog for structured logs, singleflight for certificate
// stampedes, os.Root for confined CA writes, and a prefix reader because a
// buffered CONNECT request can carry handshake bytes that a plain net.Conn
// rewrite would silently drop.
package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/sync/singleflight"
)

type config struct {
	listen   string
	caDir    string
	profile  string
	tlsPorts string
	dns      string
	insecure bool
	verbose  bool
	maxConns int
	timeout  time.Duration
}

var profiles = map[string]utls.ClientHelloID{
	"chrome":  utls.HelloChrome_Auto,
	"firefox": utls.HelloFirefox_Auto,
	"safari":  utls.HelloSafari_Auto,
	"ios":     utls.HelloIOS_Auto,
	"edge":    utls.HelloEdge_Auto,
	"android": utls.HelloAndroid_11_OkHttp,
	"random":  utls.HelloRandomizedALPN,
}

// prefixConn replays bytes already consumed by the CONNECT parser before
// reading from the underlying connection. Without it, a client that pipelines
// the TLS ClientHello onto its CONNECT request loses the handshake.
type prefixConn struct {
	net.Conn
	r io.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) { return c.r.Read(p) }

type authority struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	root    *os.Root
	flights singleflight.Group
	cache   sync.Map // host -> *tls.Certificate
}

// splitTarget accepts "host:port", a bare host, or an IPv6 literal.
func splitTarget(target string) (string, string, error) {
	if host, port, err := net.SplitHostPort(target); err == nil {
		return host, port, nil
	}
	if strings.HasPrefix(target, "[") && strings.HasSuffix(target, "]") {
		return strings.TrimSuffix(strings.TrimPrefix(target, "["), "]"), "443", nil
	}
	if target == "" {
		return "", "", errors.New("empty CONNECT target")
	}
	return target, "443", nil
}

func loadOrCreateCA(dir string, log *slog.Logger) (*authority, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	a := &authority{root: root}

	if crtPEM, err := root.ReadFile("ca.crt"); err == nil {
		if keyPEM, err2 := root.ReadFile("ca.key"); err2 == nil {
			kb, _ := pem.Decode(keyPEM)
			cb, _ := pem.Decode(crtPEM)
			if kb != nil && cb != nil {
				key, kerr := x509.ParseECPrivateKey(kb.Bytes)
				crt, cerr := x509.ParseCertificate(cb.Bytes)
				if kerr == nil && cerr == nil {
					a.cert, a.key = crt, key
					log.Info("loaded CA", "path", filepath.Join(dir, "ca.crt"))
					return a, nil
				}
			}
			log.Warn("CA files unreadable, regenerating")
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "noragate local CA", Organization: []string{"noragate"}},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := writeExclusive(root, "ca.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return nil, err
	}
	if err := writeExclusive(root, "ca.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return nil, err
	}
	a.cert, a.key = crt, key
	log.Info("generated CA", "path", filepath.Join(dir, "ca.crt"))
	return a, nil
}

// writeExclusive writes through os.Root so the path cannot escape the CA dir,
// and refuses to clobber an existing key.
func writeExclusive(root *os.Root, name string, data []byte, mode os.FileMode) error {
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}

func (a *authority) leafFor(host string) (*tls.Certificate, error) {
	if c, ok := a.cache.Load(host); ok {
		return c.(*tls.Certificate), nil
	}
	v, err, _ := a.flights.Do(host, func() (any, error) {
		if c, ok := a.cache.Load(host); ok {
			return c, nil
		}
		c, err := a.mint(host)
		if err != nil {
			return nil, err
		}
		a.cache.Store(host, c)
		return c, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*tls.Certificate), nil
}

func (a *authority) mint(host string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{"noragate"}},
		NotBefore:    time.Now().Add(-24 * time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.IPAddresses = []net.IP{ip}
	} else {
		tmpl.DNSNames = []string{host}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, a.cert, &key.PublicKey, a.key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: tmpl}, nil
}

// newResolver returns a resolver that talks to an explicit server. A statically
// linked Go binary on Android falls back to /etc/resolv.conf, which on this
// device points at [::1]:53 where nothing is listening for an app uid - that
// failure shows up as "dial tcp: lookup host: connection refused".
func newResolver(server string) *net.Resolver {
	if server == "" {
		return net.DefaultResolver
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := &net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
		},
	}
}

func resolveHost(ctx context.Context, r *net.Resolver, host string) (string, error) {
	if net.ParseIP(host) != nil {
		return host, nil
	}
	addrs, err := r.LookupHost(ctx, host)
	if err != nil && r != net.DefaultResolver {
		// A fixed resolver is not always usable: a VPN can block plain UDP/53 to
		// third parties while its own resolver works. Fall back rather than fail.
		slog.Debug("configured resolver failed, trying system", "err", err)
		addrs, err = net.DefaultResolver.LookupHost(ctx, host)
	}
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("no addresses for %s", host)
	}
	for _, a := range addrs { // prefer IPv4: the phone's v6 path is not guaranteed
		if net.ParseIP(a) != nil && net.ParseIP(a).To4() != nil {
			return a, nil
		}
	}
	return addrs[0], nil
}

func isTLSPort(cfg config, port string) bool {
	for _, p := range strings.Split(cfg.tlsPorts, ",") {
		if strings.TrimSpace(p) == port {
			return true
		}
	}
	return false
}

func dialUpstream(ctx context.Context, cfg config, host, port string) (net.Conn, error) {
	addr, err := resolveHost(ctx, newResolver(cfg.dns), host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	d := &net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr, port))
	if err != nil {
		return nil, fmt.Errorf("dial %s:%s: %w", host, port, err)
	}
	if !isTLSPort(cfg, port) {
		return raw, nil
	}
	u := utls.UClient(raw, &utls.Config{
		ServerName:         host,
		InsecureSkipVerify: cfg.insecure,
		NextProtos:         []string{"http/1.1"},
	}, profiles[cfg.profile])
	if err := u.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("utls handshake %s: %w", host, err)
	}
	return u, nil
}

// tunnel copies both directions and half-closes so neither side is truncated.
func tunnel(a, b net.Conn, label string) {
	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(name string, dst, src net.Conn) {
		defer wg.Done()
		n, err := io.Copy(dst, src)
		slog.Debug("copy finished", "dir", name, "bytes", n, "err", err, "conn", label)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
	}
	go pipe("up->client", a, b)
	go pipe("client->up", b, a)
	wg.Wait()
}

func handle(ctx context.Context, conn net.Conn, a *authority, cfg config, log *slog.Logger) {
	defer conn.Close()

	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(30 * time.Second)
	}
	_ = conn.SetReadDeadline(time.Now().Add(cfg.timeout))

	br := bufio.NewReader(conn)
	reqLine, err := br.ReadString('\n')
	if err != nil {
		return
	}
	fields := strings.Fields(reqLine)
	if len(fields) < 2 || !strings.EqualFold(fields[0], "CONNECT") {
		_, _ = io.WriteString(conn, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
		return
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
	}
	host, port, err := splitTarget(fields[1])
	if err != nil {
		_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\n\r\n")
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	log = log.With("client", conn.RemoteAddr().String(), "target", net.JoinHostPort(host, port))

	leaf, err := a.leafFor(host)
	if err != nil {
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		log.Error("mint failed", "err", err)
		return
	}
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	// ALPN must agree on both legs or the tunnel is two protocols shouting at
	// each other: uTLS's Chrome preset offers h2, so forcing http/1.1 on the
	// client side yields a SETTINGS frame and a hung request. Read the client's
	// offer from the ClientHello, dial upstream, then answer with the protocol
	// the upstream actually negotiated when the client supports it.
	var (
		up       net.Conn
		upMu     sync.Mutex
		dialErr  error
		dialOnce sync.Once
	)
	dialUp := func() {
		c, err := dialUpstream(ctx, cfg, host, port)
		upMu.Lock()
		up, dialErr = c, err
		upMu.Unlock()
	}

	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			dialOnce.Do(dialUp)
			upMu.Lock()
			u, uerr := up, dialErr
			upMu.Unlock()
			if uerr != nil {
				return nil, uerr
			}
			// utls returns its OWN ConnectionState type, not crypto/tls's, so an
			// assertion against tls.ConnectionState silently yields "" and the
			// tunnel ends up http/1.1 -> h2 (SETTINGS frame, hung request).
			proto := ""
			switch tc := u.(type) {
			case *utls.UConn:
				proto = tc.ConnectionState().NegotiatedProtocol
			case interface{ ConnectionState() tls.ConnectionState }:
				proto = tc.ConnectionState().NegotiatedProtocol
			}
			chosen := []string{"http/1.1"}
			if proto != "" {
				for _, p := range chi.SupportedProtos {
					if p == proto {
						chosen = []string{proto}
						break
					}
				}
			}
			log.Debug("alpn", "client", chi.SupportedProtos, "upstream", proto, "chosen", chosen)
			return &tls.Config{
				Certificates: []tls.Certificate{*leaf},
				MinVersion:   tls.VersionTLS12,
				NextProtos:   chosen,
			}, nil
		},
	}
	client := tls.Server(&prefixConn{Conn: conn, r: br}, serverCfg)
	hctx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()
	if err := client.HandshakeContext(hctx); err != nil {
		log.Warn("client handshake failed", "err", err)
		if up != nil {
			up.Close()
		}
		return
	}
	upMu.Lock()
	u, uerr := up, dialErr
	upMu.Unlock()
	if uerr != nil || u == nil {
		log.Error("upstream failed", "err", uerr)
		return
	}
	defer u.Close()
	log.Info("relay", "profile", cfg.profile)
	tunnel(client, u, net.JoinHostPort(host, port))
}

func main() {
	cfg := parseFlags()
	log := newLogger(cfg.verbose)
	slog.SetDefault(log)

	a, err := loadOrCreateCA(cfg.caDir, log)
	if err != nil {
		log.Error("CA setup failed", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	lc := net.ListenConfig{KeepAlive: 30 * time.Second}
	ln, err := lc.Listen(ctx, "tcp", cfg.listen)
	if err != nil {
		log.Error("listen failed", "addr", cfg.listen, "err", err)
		os.Exit(1)
	}
	log.Info("noragate-tls up", "listen", cfg.listen, "profile", cfg.profile,
		"tls_ports", cfg.tlsPorts, "max_conns", cfg.maxConns, "ca", filepath.Join(cfg.caDir, "ca.crt"))

	var active, total atomic.Int64
	sem := make(chan struct{}, cfg.maxConns)

	go func() {
		<-ctx.Done()
		log.Info("shutting down", "total_handled", total.Load())
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Warn("accept failed", "err", err)
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			_, _ = io.WriteString(conn, "HTTP/1.1 503 Service Unavailable\r\n\r\n")
			conn.Close()
			log.Warn("refused: at max conns", "max", cfg.maxConns)
			continue
		}
		total.Add(1)
		active.Add(1)
		go func() {
			defer func() {
				<-sem
				active.Add(-1)
			}()
			handle(ctx, conn, a, cfg, log)
		}()
	}
}

func parseFlags() config {
	var cfg config
	flag.StringVar(&cfg.listen, "listen", "0.0.0.0:8443", "CONNECT proxy address")
	flag.StringVar(&cfg.caDir, "ca", defaultCADir(), "CA directory")
	flag.StringVar(&cfg.profile, "profile", "chrome", "chrome|firefox|safari|ios|edge|android|random")
	flag.StringVar(&cfg.tlsPorts, "tls-ports", "443,8443,9443", "ports treated as TLS upstream")
	flag.StringVar(&cfg.dns, "dns", "1.1.1.1", "resolver for upstream lookups (empty = system)")
	flag.BoolVar(&cfg.insecure, "insecure", true, "skip upstream certificate verification")
	flag.BoolVar(&cfg.verbose, "v", true, "debug logging")
	flag.IntVar(&cfg.maxConns, "max-conns", 256, "concurrent connection cap")
	flag.DurationVar(&cfg.timeout, "timeout", 20*time.Second, "handshake timeout")
	flag.Parse()
	if _, ok := profiles[cfg.profile]; !ok {
		fmt.Fprintf(os.Stderr, "unknown profile %q; choose from chrome firefox safari ios edge android random\n", cfg.profile)
		os.Exit(2)
	}
	return cfg
}

func defaultCADir() string {
	if d, err := os.UserConfigDir(); err == nil {
		return filepath.Join(d, "noragate", "ca")
	}
	return filepath.Join(os.TempDir(), "noragate-ca")
}

func newLogger(verbose bool) *slog.Logger {
	lvl := slog.LevelInfo
	if verbose {
		lvl = slog.LevelDebug
	}
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
}
