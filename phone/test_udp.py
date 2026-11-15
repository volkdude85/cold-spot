#!/usr/bin/env python3
"""End-to-end SOCKS5 UDP ASSOCIATE test against the phone gate.

Starts a UDP echo server on this box, asks the gate for a UDP association,
sends a datagram addressed to the echo, and checks the payload comes back.
"""
import socket
import struct
import sys
import threading
import time

PROXY = ("192.0.2.20", 1080)
ECHO = ("192.0.2.10", 9099)
PAYLOAD = b"udp-through-the-phone"


def echo_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(ECHO)
    s.settimeout(30)
    try:
        while True:
            data, addr = s.recvfrom(2048)
            s.sendto(b"echo:" + data, addr)
    except socket.timeout:
        pass
    finally:
        s.close()


def socks5_udp():
    t = socket.create_connection(PROXY, timeout=10)
    t.sendall(b"\x05\x01\x00")
    assert t.recv(2) == b"\x05\x00", "no-auth refused"
    # CMD 0x03 = UDP ASSOCIATE, DST 0.0.0.0:0
    t.sendall(b"\x05\x03\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack("!H", 0))
    rep = t.recv(10)
    assert rep[:2] == b"\x05\x00", f"associate failed: {rep!r}"
    atyp = rep[3]
    if atyp == 1:
        host = socket.inet_ntoa(rep[4:8])
    elif atyp == 3:
        ln = rep[4]
        host = rep[5:5 + ln].decode()
    else:
        host = socket.inet_ntop(socket.AF_INET6, rep[4:20])
    port = struct.unpack("!H", rep[-2:])[0]
    if host in ("0.0.0.0", ""):
        host = PROXY[0]
    print(f"association: {host}:{port}")

    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.settimeout(10)
    hdr = b"\x00\x00\x00\x01" + socket.inet_aton(ECHO[0]) + struct.pack("!H", ECHO[1])
    t0 = time.time()
    u.sendto(hdr + PAYLOAD, (host, port))
    data, _ = u.recvfrom(4096)
    dt = (time.time() - t0) * 1000
    # strip the SOCKS5 UDP header from the reply
    i = 4
    if data[3] == 1:
        i += 4
    elif data[3] == 3:
        i += 1 + data[4]
    else:
        i += 16
    i += 2
    body = data[i:]
    print(f"reply in {dt:.1f} ms: {body!r}")
    assert body == b"echo:" + PAYLOAD, f"payload mismatch: {body!r}"
    print("UDP through the gate: OK")
    u.close()
    t.close()


if __name__ == "__main__":
    threading.Thread(target=echo_server, daemon=True).start()
    time.sleep(0.5)
    socks5_udp()
