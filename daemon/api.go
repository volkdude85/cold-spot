package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ------------------------------------------------------- HTTP proxy leg ---

// serveProxy is the HTTP proxy: CONNECT tunnels plus absolute-URI requests.
func (d *daemon) serveProxy(ctx context.Context) {
	srv := &http.Server{
		Addr:              d.cfg.proxy,
		Handler:           http.HandlerFunc(d.proxyHandler),
		ReadHeaderTimeout: 20 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	d.log.Info("http proxy listening", "addr", d.cfg.proxy)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		d.log.Error("proxy stopped", "err", err)
	}
}

func (d *daemon) proxyHandler(w http.ResponseWriter, r *http.Request) {
	ip := remoteAddr(r)
	if ok, why := d.allowed(ip); !ok {
		d.log.Warn("deny", "client", ip, "reason", why)
		http.Error(w, "denied: "+why, http.StatusForbidden)
		return
	}

	if r.Method == http.MethodConnect {
		d.handleConnect(w, r, ip)
		return
	}
	d.handlePlain(w, r, ip)
}

func (d *daemon) handleConnect(w http.ResponseWriter, r *http.Request, ip string) {
	target := r.Host
	if !strings.Contains(target, ":") {
		target = net.JoinHostPort(target, "443")
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		http.Error(w, "bad target", http.StatusBadRequest)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "cannot hijack", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer client.Close()

	d.open(ip, target)
	defer d.close(ip)

	up, err := d.dialUpstream(r.Context(), host, port, ip)
	if err != nil {
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		d.log.Warn("connect failed", "client", ip, "target", target, "err", err)
		return
	}
	defer up.Close()
	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	d.log.Debug("connect", "client", ip, "target", target)
	d.relay(client, up, ip, d.capFor(ip))
}

// httpTransport dials and resolves from the phone. The default transport would
// use the environment's proxy settings, which must never apply here.
func (d *daemon) httpTransport() *http.Transport {
	return &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			return d.dialUpstream(ctx, host, port, "")
		},
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 15 * time.Second,
	}
}

func (d *daemon) handlePlain(w http.ResponseWriter, r *http.Request, ip string) {
	if !r.URL.IsAbs() {
		http.Error(w, "absolute-URI required", http.StatusBadRequest)
		return
	}
	d.open(ip, r.URL.Host)
	defer d.close(ip)

	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.Header.Del("Proxy-Connection")
	out.Header.Del("Proxy-Authorization")
	d.mu.Lock()
	ua := d.cfg.UA
	d.mu.Unlock()
	if ua != "" {
		out.Header.Set("User-Agent", ua)
	}

	resp, err := d.httpTransport().RoundTrip(out)
	if err != nil {
		http.Error(w, "upstream failed", http.StatusBadGateway)
		d.log.Warn("plain request failed", "client", ip, "url", r.URL.String(), "err", err)
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	n, _ := io.Copy(w, resp.Body)
	d.bytes(ip, 0, n)
}

// --------------------------------------------------------- control API ---

func (d *daemon) serveAPI(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/state", d.apiState)
	mux.HandleFunc("/clients", d.apiClients)
	mux.HandleFunc("/egress", d.apiEgress)
	mux.HandleFunc("/vpns", d.apiVPNs)
	mux.HandleFunc("/config", d.apiConfig)
	mux.HandleFunc("/client", d.apiClient)
	mux.HandleFunc("/proxy.pac", d.apiPAC)
	mux.HandleFunc("/", d.apiUI)

	srv := &http.Server{
		Addr:              d.cfg.state,
		Handler:           cors(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	d.log.Info("control API listening", "addr", d.cfg.state)
	return srv.ListenAndServe()
}

func cors(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		h.ServeHTTP(w, r)
	})
}

type statePayload struct {
	Gate struct {
		Socks   string `json:"socks"`
		HTTP    string `json:"http"`
		State   string `json:"state_port"`
		Since   int64  `json:"since"`
		PACPath string `json:"pac"`
	} `json:"gate"`
	Guard struct {
		Armed         bool     `json:"armed"`
		BlockOnLeak   bool     `json:"block_on_leak"`
		BlockOnChange bool     `json:"block_on_change"`
		Expect        []string `json:"expect"`
		State         string   `json:"state"`
		Egress        string   `json:"egress"`
		Baseline      string   `json:"baseline"`
		Checked       int64    `json:"checked"`
		History       []string `json:"history"`
	} `json:"guard"`
	Allow       []string          `json:"allow"`
	Caps        map[string]int64  `json:"caps"`
	DefaultCap  int64             `json:"default_cap"`
	DNS         string            `json:"dns"`
	VPN         string            `json:"vpn"`
	DNSByClient map[string]string `json:"dns_by_client"`
	UA          string            `json:"ua"`
	DNSLog      []dnsEvent        `json:"dns_log"`
	Clients     map[string]any    `json:"clients"`
	Totals      map[string]int64  `json:"totals"`
}

func (d *daemon) snapshot() statePayload {
	d.mu.Lock()
	defer d.mu.Unlock()

	var p statePayload
	p.Gate.Socks = d.cfg.listen
	p.Gate.HTTP = d.cfg.proxy
	p.Gate.State = d.cfg.state
	p.Gate.Since = d.started.Unix()
	p.Gate.PACPath = "/proxy.pac"

	p.Guard.Armed = d.cfg.BlockOnLeak || d.cfg.BlockOnChange || len(d.cfg.ExpectEgress) > 0
	p.Guard.BlockOnLeak = d.cfg.BlockOnLeak
	p.Guard.BlockOnChange = d.cfg.BlockOnChange
	p.Guard.Expect = d.cfg.ExpectEgress
	p.Guard.State = d.egress.State
	p.Guard.Egress = d.egress.IP
	p.Guard.Baseline = d.egress.Baseline
	p.Guard.Checked = d.egress.Checked
	p.Guard.History = d.egress.History

	p.Allow = d.cfg.Allow
	p.DefaultCap = d.cfg.DefaultCap
	p.DNS = d.cfg.DNS
	p.VPN = d.cfg.VPN
	p.UA = d.cfg.UA
	p.DNSLog = d.dnsLog
	p.Caps = map[string]int64{}
	p.DNSByClient = map[string]string{}

	clients := map[string]any{}
	var conns, open, up, down int64
	for ip, c := range d.clients {
		meta := d.cfg.Clients[ip]
		clients[ip] = map[string]any{
			"conns": c.Conns, "open": c.Open, "up": c.Up, "down": c.Down,
			"targets": c.Targets, "label": meta.Label, "deny": meta.Deny,
		}
		conns += c.Conns
		open += c.Open
		up += c.Up
		down += c.Down
	}
	for ip, m := range d.cfg.Clients {
		if m.Cap > 0 {
			p.Caps[ip] = m.Cap
		}
		if m.DNS != "" {
			p.DNSByClient[ip] = m.DNS
		}
	}
	p.Clients = clients
	p.Totals = map[string]int64{
		"clients": int64(len(clients)), "conns": conns, "open": open, "up": up, "down": down,
	}
	return p
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (d *daemon) apiState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, d.snapshot())
}

func (d *daemon) apiClients(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, d.snapshot().Clients)
}

func (d *daemon) apiEgress(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, d.snapshot().Guard)
}

func (d *daemon) apiVPNs(w http.ResponseWriter, r *http.Request) {
	d.mu.Lock()
	active := d.cfg.VPN
	drivers := append([]vpnDriver(nil), d.drivers...)
	d.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"active": active, "drivers": drivers})
}

func (d *daemon) apiConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "POST only"})
		return
	}
	var body struct {
		Allow         *[]string `json:"allow"`
		ExpectEgress  *[]string `json:"expect_egress"`
		BlockOnLeak   *bool     `json:"block_on_leak"`
		BlockOnChange *bool     `json:"block_on_change"`
		DefaultCap    *int64    `json:"default_cap"`
		DNS           *string   `json:"dns"`
		UA            *string   `json:"ua"`
		VPN           *string   `json:"vpn"`
		// Relearn drops the pinned egress baseline and measures again immediately.
		// A fail-closed guard needs a door, or a legitimate network change is a lockout.
		Relearn *bool `json:"relearn"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "bad json"})
		return
	}
	var changed []string
	d.mu.Lock()
	if body.Allow != nil {
		d.cfg.Allow = *body.Allow
		changed = append(changed, "allow")
	}
	if body.ExpectEgress != nil {
		d.cfg.ExpectEgress = *body.ExpectEgress
		changed = append(changed, "expect_egress")
	}
	if body.BlockOnLeak != nil {
		d.cfg.BlockOnLeak = *body.BlockOnLeak
		changed = append(changed, "block_on_leak")
	}
	if body.BlockOnChange != nil {
		d.cfg.BlockOnChange = *body.BlockOnChange
		changed = append(changed, "block_on_change")
	}
	if body.DefaultCap != nil {
		d.cfg.DefaultCap = *body.DefaultCap
		changed = append(changed, "default_cap")
	}
	if body.DNS != nil {
		d.cfg.DNS = *body.DNS
		d.resolver = buildResolver(*body.DNS)
		changed = append(changed, "dns")
	}
	if body.UA != nil {
		d.cfg.UA = *body.UA
		changed = append(changed, "ua")
	}
	d.mu.Unlock()
	if body.VPN != nil {
		d.activateVPN(*body.VPN)
		// A driver change means a different tunnel, so the stored exit address is
		// already wrong. Measure again now rather than at the next tick.
		go d.probeEgressOnce(context.Background())
		changed = append(changed, "vpn="+*body.VPN)
	}
	if body.Relearn != nil && *body.Relearn {
		d.mu.Lock()
		d.egress.Baseline = ""
		d.egress.State = "unknown"
		d.egress.History = nil
		d.mu.Unlock()
		d.log.Info("guard relearn requested")
		// Probe now instead of waiting for the ticker: the caller asked because the
		// current reading is wrong, and a stale answer five minutes later is no answer.
		go d.probeEgressOnce(context.Background())
		changed = append(changed, "relearn")
	}

	err := d.saveConfig()
	d.log.Info("config update", "changed", changed, "err", err)
	writeJSON(w, http.StatusOK, map[string]any{"ok": err == nil, "changed": changed, "state": d.snapshot()})
}

func (d *daemon) apiClient(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"ok": false, "error": "POST only"})
		return
	}
	var body struct {
		IP    string  `json:"ip"`
		Label *string `json:"label"`
		Deny  *bool   `json:"deny"`
		Cap   *int64  `json:"cap"`
		DNS   *string `json:"dns"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.IP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "ip required"})
		return
	}
	d.mu.Lock()
	m := d.cfg.Clients[body.IP]
	if body.Label != nil {
		m.Label = *body.Label
	}
	if body.Deny != nil {
		m.Deny = *body.Deny
	}
	if body.Cap != nil {
		m.Cap = *body.Cap
	}
	if body.DNS != nil {
		m.DNS = *body.DNS
	}
	d.cfg.Clients[body.IP] = m
	d.mu.Unlock()

	err := d.saveConfig()
	writeJSON(w, http.StatusOK, map[string]any{"ok": err == nil, "client": map[string]clientMeta{body.IP: m}})
}

func (d *daemon) apiPAC(w http.ResponseWriter, r *http.Request) {
	host := remoteAddr(r)
	if local, _, err := net.SplitHostPort(r.Host); err == nil && local != "" {
		host = local
	}
	socksPort := portOf(d.cfg.listen, "1080")
	proxyPort := portOf(d.cfg.proxy, "8080")
	pac := "function FindProxyForURL(url, host) {\n" +
		"  if (isPlainHostName(host) || shExpMatch(host, \"*.local\") ||\n" +
		"      shExpMatch(host, \"127.*\") || shExpMatch(host, \"192.168.*\") ||\n" +
		"      shExpMatch(host, \"10.*\") || shExpMatch(host, \"172.16.*\")) {\n" +
		"    return \"DIRECT\";\n" +
		"  }\n" +
		"  return \"PROXY " + host + ":" + proxyPort + "; SOCKS5 " + host + ":" + socksPort + "; DIRECT\";\n" +
		"}\n"
	w.Header().Set("Content-Type", "application/x-ns-proxy-autoconfig")
	_, _ = io.WriteString(w, pac)
}

func portOf(addr, fallback string) string {
	if _, p, err := net.SplitHostPort(addr); err == nil && p != "" {
		return p
	}
	return fallback
}

var uiTypes = map[string]string{
	"index.html":    "text/html; charset=utf-8",
	"manifest.json": "application/manifest+json",
	"sw.js":         "text/javascript",
	"icon-192.png":  "image/png",
	"icon-512.png":  "image/png",
}

func (d *daemon) apiUI(w http.ResponseWriter, r *http.Request) {
	name := "index.html"
	if p := strings.TrimPrefix(r.URL.Path, "/"); p != "" && p != "ui" && p != "ui/" {
		name = filepath.Base(p)
	}
	ctype, ok := uiTypes[name]
	if !ok || d.cfg.uiDir == "" {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(filepath.Join(d.cfg.uiDir, name))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = io.Copy(w, f)
}

// ------------------------------------------------------------- utilities ---

func remoteAddr(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// sortedKeys keeps JSON output stable enough to diff in tests.
func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

var _ = strconv.Itoa
