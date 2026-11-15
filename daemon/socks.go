package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"syscall"
	"time"
)

// serveSOCKS runs the SOCKS5 listener: CONNECT and UDP ASSOCIATE.
func (d *daemon) serveSOCKS(ctx context.Context) {
	lc := net.ListenConfig{KeepAlive: 30 * time.Second}
	ln, err := lc.Listen(ctx, "tcp", d.cfg.listen)
	if err != nil {
		d.log.Error("socks listen failed", "addr", d.cfg.listen, "err", err)
		return
	}
	d.log.Info("socks5 listening", "addr", d.cfg.listen)
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	sem := make(chan struct{}, d.cfg.maxConns)
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			d.log.Warn("socks accept", "err", err)
			continue
		}
		select {
		case sem <- struct{}{}:
		default:
			conn.Close()
			d.log.Warn("refused: at max conns", "max", d.cfg.maxConns)
			continue
		}
		d.total.Add(1)
		d.active.Add(1)
		go func() {
			defer func() { <-sem; d.active.Add(-1) }()
			d.handleSOCKS(ctx, conn)
		}()
	}
}

func socksReply(conn net.Conn, code byte) {
	// VER REP RSV ATYP BND.ADDR BND.PORT
	_, _ = conn.Write([]byte{5, code, 0, 1, 0, 0, 0, 0, 0, 0})
}

func (d *daemon) handleSOCKS(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	ip := hostOf(conn.RemoteAddr())

	if ok, why := d.allowed(ip); !ok {
		d.log.Warn("deny", "client", ip, "reason", why)
		return
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil || hdr[0] != 5 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	// No authentication: the gate is bound to loopback or the LAN and access is
	// controlled by the allowlist, not by a shared secret on the wire.
	_, _ = conn.Write([]byte{5, 0})

	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return
	}
	cmd := req[1]
	host, port, err := readAddr(conn, req[3])
	if err != nil {
		socksReply(conn, 8)
		return
	}
	_ = conn.SetDeadline(time.Time{})

	switch cmd {
	case 1: // CONNECT
		d.socksConnect(ctx, conn, ip, host, port)
	case 3: // UDP ASSOCIATE
		d.socksUDP(ctx, conn, ip, host, port)
	default:
		socksReply(conn, 7)
	}
}

func (d *daemon) socksConnect(ctx context.Context, conn net.Conn, ip, host, port string) {
	target := net.JoinHostPort(host, port)
	d.open(ip, target)
	defer d.close(ip)

	up, err := d.dialUpstream(ctx, host, port, ip)
	if err != nil {
		d.log.Warn("connect failed", "client", ip, "target", target, "err", err)
		socksReply(conn, 5)
		return
	}
	defer up.Close()

	socksReply(conn, 0)
	d.log.Debug("socks connected", "client", ip, "target", target)
	d.relay(conn, up, ip, d.capFor(ip))
}

func (d *daemon) socksUDP(ctx context.Context, conn net.Conn, ip, host, port string) {
	// Bind on the interface the client reached us on.
	local := conn.LocalAddr().(*net.TCPAddr)
	us, err := net.ListenUDP("udp", &net.UDPAddr{IP: local.IP, Port: 0})
	if err != nil {
		socksReply(conn, 1)
		return
	}
	defer us.Close()

	bnd := us.LocalAddr().(*net.UDPAddr)
	reply := []byte{5, 0, 0, 1}
	reply = append(reply, bnd.IP.To4()...)
	reply = binary.BigEndian.AppendUint16(reply, uint16(bnd.Port))
	if _, err := conn.Write(reply); err != nil {
		return
	}
	d.log.Debug("udp associate", "client", ip, "bind", bnd.String())

	peers := map[string]*net.UDPConn{}
	defer func() {
		for _, p := range peers {
			p.Close()
		}
	}()

	buf := make([]byte, 65535)
	var lastClient *net.UDPAddr
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	go func() { // stop when the TCP control connection closes
		<-ctx.Done()
		us.SetReadDeadline(time.Now())
		_ = conn.SetReadDeadline(time.Now())
	}()

	for {
		n, caddr, err := us.ReadFromUDP(buf)
		if err != nil {
			return
		}
		lastClient = caddr
		if n < 10 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
			continue // malformed or fragmented: unsupported
		}
		// parseSocksAddr is given the buffer from the ATYP byte, so its offset is
		// relative to that slice. Slicing the original buf with it would leave
		// three header bytes glued to the front of every datagram.
		dstIP, dstPort, off, ok := parseSocksAddr(buf[3:n])
		if !ok {
			continue
		}
		payload := buf[3+off : n]
		key := net.JoinHostPort(dstIP, itoa(int64(dstPort)))
		peer, ok := peers[key]
		if !ok {
			ra, err := net.ResolveUDPAddr("udp", key)
			if err != nil {
				continue
			}
			peer, err = net.DialUDP("udp", nil, ra)
			if err != nil {
				continue
			}
			peers[key] = peer
			d.open(ip, "udp "+key)
			go func(p *net.UDPConn, key string) { // drain replies back to the client
				rb := make([]byte, 65535)
				for {
					n, err := p.Read(rb)
					if err != nil {
						return
					}
					hdr := []byte{0, 0, 0}
					h, pt, _, ok := splitHostPort(key)
					if !ok {
						continue
					}
					hdr = append(hdr, encodeSocksAddr(h, pt)...)
					if lastClient != nil {
						_, _ = us.WriteToUDP(append(hdr, rb[:n]...), lastClient)
						d.bytes(ip, 0, int64(n))
					}
				}
			}(peer, key)
		}
		if _, err := peer.Write(payload); err == nil {
			d.bytes(ip, int64(len(payload)), 0)
		}
	}
}

// ------------------------------------------------------------ wire format ---

func readAddr(conn net.Conn, atyp byte) (string, string, error) {
	switch atyp {
	case 1:
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", "", err
		}
		p := make([]byte, 2)
		if _, err := io.ReadFull(conn, p); err != nil {
			return "", "", err
		}
		return net.IP(b).String(), itoa(int64(binary.BigEndian.Uint16(p))), nil
	case 3:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return "", "", err
		}
		h := make([]byte, int(l[0]))
		if _, err := io.ReadFull(conn, h); err != nil {
			return "", "", err
		}
		p := make([]byte, 2)
		if _, err := io.ReadFull(conn, p); err != nil {
			return "", "", err
		}
		return string(h), itoa(int64(binary.BigEndian.Uint16(p))), nil
	case 4:
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return "", "", err
		}
		p := make([]byte, 2)
		if _, err := io.ReadFull(conn, p); err != nil {
			return "", "", err
		}
		return net.IP(b).String(), itoa(int64(binary.BigEndian.Uint16(p))), nil
	}
	return "", "", errors.New("bad atyp")
}

func parseSocksAddr(b []byte) (string, uint16, int, bool) {
	if len(b) < 1 {
		return "", 0, 0, false
	}
	switch b[0] {
	case 1:
		if len(b) < 7 {
			return "", 0, 0, false
		}
		return net.IP(b[1:5]).String(), binary.BigEndian.Uint16(b[5:7]), 7, true
	case 3:
		if len(b) < 2 {
			return "", 0, 0, false
		}
		l := int(b[1])
		if len(b) < 2+l+2 {
			return "", 0, 0, false
		}
		return string(b[2 : 2+l]), binary.BigEndian.Uint16(b[2+l : 2+l+2]), 2 + l + 2, true
	case 4:
		if len(b) < 19 {
			return "", 0, 0, false
		}
		return net.IP(b[1:17]).String(), binary.BigEndian.Uint16(b[17:19]), 19, true
	}
	return "", 0, 0, false
}

func encodeSocksAddr(host string, port uint16) []byte {
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return append(append([]byte{1}, v4...), byte(port>>8), byte(port))
		}
		return append(append([]byte{4}, ip.To16()...), byte(port>>8), byte(port))
	}
	out := []byte{3, byte(len(host))}
	out = append(out, host...)
	return append(out, byte(port>>8), byte(port))
}

func hostOf(a net.Addr) string {
	h, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return h
}

func splitHostPort(hostport string) (string, uint16, error, bool) {
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return "", 0, err, false
	}
	v, err := atoi(p)
	if err != nil {
		return "", 0, err, false
	}
	return h, uint16(v), nil, true
}

func itoa(v int64) string { return strconvFormatInt(v) }

// strconvFormatInt is separated so the SOCKS wire code has no direct strconv
// dependency and stays trivially testable.
func strconvFormatInt(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

var _ = syscall.Getpid
var _ sync.Mutex
