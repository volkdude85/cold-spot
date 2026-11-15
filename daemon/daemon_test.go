package main

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"testing"
)

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestSocksAddrRoundTrip(t *testing.T) {
	cases := []struct {
		host string
		port uint16
	}{
		{"example.com", 443},
		{"192.0.2.10", 8080},
		{"2606:4700:4700::1111", 9443},
		{"a", 1},
	}
	for _, c := range cases {
		enc := encodeSocksAddr(c.host, c.port)
		host, port, off, ok := parseSocksAddr(enc)
		if !ok {
			t.Fatalf("%s: parse failed", c.host)
		}
		if off != len(enc) {
			t.Fatalf("%s: consumed %d of %d bytes", c.host, off, len(enc))
		}
		if host != c.host || port != c.port {
			t.Fatalf("got %s:%d want %s:%d", host, port, c.host, c.port)
		}
	}
}

func TestParseSocksAddrRejectsShort(t *testing.T) {
	for _, b := range [][]byte{{}, {1, 2, 3}, {3, 9, 'a'}, {4, 1, 2, 3}} {
		if _, _, _, ok := parseSocksAddr(b); ok {
			t.Fatalf("%v should not parse", b)
		}
	}
}

func TestSplitHostPort(t *testing.T) {
	h, p, err, ok := splitHostPort("example.com:443")
	if !ok || err != nil || h != "example.com" || p != 443 {
		t.Fatalf("got %q %d %v", h, p, err)
	}
	if _, _, _, ok := splitHostPort("nonsense"); ok {
		t.Fatal("expected failure")
	}
}

func TestWithinAny(t *testing.T) {
	cidrs := []string{"198.51.100.0/24", "2001:db8::/32"}
	if !withinAny("198.51.100.7", cidrs) {
		t.Fatal("198.51.100.7 should be inside")
	}
	if !withinAny("2001:db8::1", cidrs) {
		t.Fatal("v6 should be inside")
	}
	if withinAny("8.8.8.8", cidrs) {
		t.Fatal("8.8.8.8 should be outside")
	}
	if withinAny("not-an-ip", cidrs) {
		t.Fatal("garbage should not match")
	}
}

func TestItoa(t *testing.T) {
	cases := map[int64]string{0: "0", 1: "1", 443: "443", 65535: "65535", -7: "-7"}
	for in, want := range cases {
		if got := itoa(in); got != want {
			t.Fatalf("itoa(%d)=%q want %q", in, got, want)
		}
	}
}

func TestAllowed(t *testing.T) {
	d := newDaemon(config{}, quiet())
	d.egress.State = "ok"

	if ok, _ := d.allowed("10.0.0.1"); !ok {
		t.Fatal("no allowlist means everyone is allowed")
	}

	d.cfg.Allow = []string{"10.0.0.2"}
	if ok, why := d.allowed("10.0.0.1"); ok || why != "allowlist" {
		t.Fatalf("expected allowlist deny, got ok=%v why=%q", ok, why)
	}
	if ok, _ := d.allowed("10.0.0.2"); !ok {
		t.Fatal("listed client should pass")
	}

	d.cfg.Allow = nil
	d.cfg.Clients = map[string]clientMeta{"10.0.0.3": {Deny: true}}
	if ok, why := d.allowed("10.0.0.3"); ok || why != "blocked client" {
		t.Fatalf("expected blocked client, got ok=%v why=%q", ok, why)
	}

	d.cfg.Clients = map[string]clientMeta{}
	d.egress.State = "leak"
	if ok, why := d.allowed("10.0.0.9"); ok || why != "egress guard" {
		t.Fatalf("expected egress guard, got ok=%v why=%q", ok, why)
	}
}

func TestByteCountersAndSnapshot(t *testing.T) {
	d := newDaemon(config{}, quiet())
	d.open("10.0.0.1", "example.com:443")
	d.bytes("10.0.0.1", 100, 200)
	d.close("10.0.0.1")

	s := d.snapshot()
	if s.Totals["clients"] != 1 || s.Totals["conns"] != 1 || s.Totals["open"] != 0 {
		t.Fatalf("totals wrong: %v", s.Totals)
	}
	if s.Totals["up"] != 100 || s.Totals["down"] != 200 {
		t.Fatalf("byte totals wrong: %v", s.Totals)
	}
}

func TestPaceDoesNotBlockWithoutCap(t *testing.T) {
	b := &bucket{tokens: map[string]*[2]float64{}}
	b.pace("1.1.1.1", 0, 1<<20) // no cap: must return immediately
}

func TestPortOf(t *testing.T) {
	if got := portOf("127.0.0.1:1080", "1"); got != "1080" {
		t.Fatalf("got %q", got)
	}
	if got := portOf("", "8080"); got != "8080" {
		t.Fatalf("fallback got %q", got)
	}
}

func TestHostOf(t *testing.T) {
	a := &net.TCPAddr{IP: net.ParseIP("198.51.100.9"), Port: 5000}
	if got := hostOf(a); got != "198.51.100.9" {
		t.Fatalf("got %q", got)
	}
}

func TestSocksReplyShape(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go socksReply(c1, 0)
	buf := make([]byte, 10)
	if _, err := io.ReadFull(c2, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if buf[0] != 5 || buf[1] != 0 || buf[3] != 1 {
		t.Fatalf("bad reply %v", buf)
	}
	if binary.BigEndian.Uint16(buf[8:10]) != 0 {
		t.Fatal("bound port should be zero")
	}
}

// The UDP header starts at byte 3 (RSV RSV FRAG), so a parse offset is relative
// to the ATYP byte and must be added to 3 when slicing the datagram.
func TestUDPSliceOffset(t *testing.T) {
	datagram := []byte{0, 0, 0, 1, 192, 168, 0, 200, 0x23, 0x8b, 'p', 'a', 'y'}
	_, port, off, ok := parseSocksAddr(datagram[3:])
	if !ok || port != 9099 {
		t.Fatalf("parse: ok=%v port=%d", ok, port)
	}
	if got := string(datagram[3+off:]); got != "pay" {
		t.Fatalf("payload slice = %q, want %q", got, "pay")
	}
}
