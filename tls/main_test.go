package main

import (
	"bytes"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestSplitTarget(t *testing.T) {
	cases := []struct {
		in        string
		wantHost  string
		wantPort  string
		wantError bool
	}{
		{"example.com:443", "example.com", "443", false},
		{"example.com", "example.com", "443", false},
		{"[2606:4700::1111]:8443", "2606:4700::1111", "8443", false},
		{"[2606:4700::1111]", "2606:4700::1111", "443", false},
		{"192.0.2.10:9443", "192.0.2.10", "9443", false},
		{"", "", "", true},
	}
	for _, c := range cases {
		host, port, err := splitTarget(c.in)
		if (err != nil) != c.wantError {
			t.Fatalf("%q: err=%v want error=%v", c.in, err, c.wantError)
		}
		if c.wantError {
			continue
		}
		if host != c.wantHost || port != c.wantPort {
			t.Fatalf("%q -> %q,%q want %q,%q", c.in, host, port, c.wantHost, c.wantPort)
		}
	}
}

func TestIsTLSPort(t *testing.T) {
	cfg := config{tlsPorts: "443, 8443,9443"}
	for _, p := range []string{"443", "8443", "9443"} {
		if !isTLSPort(cfg, p) {
			t.Fatalf("port %s should be TLS", p)
		}
	}
	for _, p := range []string{"80", "8080", "22"} {
		if isTLSPort(cfg, p) {
			t.Fatalf("port %s should not be TLS", p)
		}
	}
}

// A client may pipeline its TLS ClientHello onto the CONNECT request; the
// buffered bytes must be replayed or the handshake is silently truncated.
func TestPrefixConnReplaysBufferedBytes(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	buffered := bytes.NewReader([]byte("hello-"))
	pc := &prefixConn{Conn: a, r: io.MultiReader(buffered, a)}

	go func() { _, _ = b.Write([]byte("world")) }()

	got := make([]byte, 11)
	if _, err := io.ReadFull(pc, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello-world" {
		t.Fatalf("got %q want %q", got, "hello-world")
	}
}

func TestMintChainsToCA(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	a, err := loadOrCreateCA(dir, log)
	if err != nil {
		t.Fatalf("CA: %v", err)
	}
	crt, err := a.leafFor("example.com")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	leaf, err := x509.ParseCertificate(crt.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(a.cert)
	if _, err := leaf.Verify(x509.VerifyOptions{DNSName: "example.com", Roots: pool}); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// second call must come from cache and stay identical
	again, err := a.leafFor("example.com")
	if err != nil {
		t.Fatalf("mint again: %v", err)
	}
	if !bytes.Equal(again.Certificate[0], crt.Certificate[0]) {
		t.Fatal("cache miss: certificate changed between calls")
	}
	// IP literal target gets an IP SAN
	ipCrt, err := a.leafFor("203.0.113.7")
	if err != nil {
		t.Fatalf("mint ip: %v", err)
	}
	ipLeaf, _ := x509.ParseCertificate(ipCrt.Certificate[0])
	if len(ipLeaf.IPAddresses) != 1 || ipLeaf.IPAddresses[0].String() != "203.0.113.7" {
		t.Fatalf("IP SAN missing: %v", ipLeaf.IPAddresses)
	}
}

func TestCAFilesArePrivate(t *testing.T) {
	dir := t.TempDir()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := loadOrCreateCA(dir, log); err != nil {
		t.Fatalf("CA: %v", err)
	}
	st, err := os.Stat(filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Fatalf("ca.key mode %v is too open", st.Mode().Perm())
	}
}
