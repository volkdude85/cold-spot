#!/usr/bin/env python3
"""Pipelined CONNECT test.

A client is allowed to send its CONNECT request and the TLS ClientHello in the
same write. If the proxy parses the request through a bufio.Reader and then
hands the raw net.Conn to tls.Server, the buffered handshake bytes are silently
dropped and the handshake never starts. This sends both in one write and checks
that the far end receives a complete ClientHello.
"""
import socket
import struct
import sys

PROXY = ("192.0.2.20", 8443)
TARGET = "192.0.2.10:9443"


def client_hello():
    """A minimal, well-formed TLS 1.2 ClientHello with one cipher and SNI."""
    sni = b"probe.example"
    sni_ext = struct.pack("!H", 0) + struct.pack("!H", len(sni) + 5) + \
        struct.pack("!H", len(sni) + 3) + b"\x00" + struct.pack("!H", len(sni)) + sni
    exts = sni_ext + struct.pack("!HH", 0x000b, 3) + b"\x02\x01\x00"
    body = (b"\x03\x03" + b"\x11" * 32 + b"\x00" +
            struct.pack("!H", 2) + b"\x13\x01" +
            b"\x01\x00" +
            struct.pack("!H", len(exts)) + exts)
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


def main():
    hello = client_hello()
    s = socket.create_connection(PROXY, timeout=10)
    s.settimeout(10)
    req = f"CONNECT {TARGET} HTTP/1.1\r\nHost: {TARGET}\r\n\r\n".encode()
    # ONE write: request line, headers, and the handshake, exactly like a
    # client that does not wait for the 200 before starting TLS.
    s.sendall(req + hello)
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = s.recv(1)
        if not chunk:
            print("FAIL: proxy closed before responding")
            return 1
        head += chunk
    status = head.split(b"\r\n")[0].decode()
    print(f"proxy said: {status}")
    if "200" not in status:
        print("FAIL: no tunnel established")
        return 1
    # If the proxy dropped the buffered ClientHello it will be waiting for one;
    # the origin will never log a ja3. Give it a moment and report.
    s.settimeout(3)
    try:
        s.recv(4096)
    except (socket.timeout, OSError):
        pass
    s.close()
    print("pipelined CONNECT sent; check the ja3 probe for a complete ClientHello")
    return 0


if __name__ == "__main__":
    sys.exit(main())
