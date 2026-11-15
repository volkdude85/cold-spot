#!/usr/bin/env python3
"""JA3 probe — read a TLS ClientHello off the wire and fingerprint it.

The gate cannot fix a client's TLS fingerprint, because a CONNECT tunnel passes
the handshake through untouched. This measures exactly what still differs, so
the residual leak is a number instead of a caveat.

Usage: ja3_probe.py [port]     then  curl -k https://<host>:<port>/ from anywhere.
"""
import hashlib
import socket
import struct
import sys
import threading


def parse_client_hello(data):
    if len(data) < 6 or data[0] != 0x16:
        return None
    i = 5                                   # record header
    if data[i] != 0x01:
        return None
    i += 4                                  # handshake header
    i += 2                                  # legacy version
    i += 32                                 # random
    sid_len = data[i]
    i += 1 + sid_len
    cs_len = struct.unpack("!H", data[i:i + 2])[0]
    i += 2
    ciphers = [struct.unpack("!H", data[i + j:i + j + 2])[0] for j in range(0, cs_len, 2)]
    i += cs_len
    comp_len = data[i]
    i += 1 + comp_len
    ext_len = struct.unpack("!H", data[i:i + 2])[0]
    i += 2
    end = i + ext_len
    exts, curves, formats = [], [], []
    while i + 4 <= end:
        etype, elen = struct.unpack("!HH", data[i:i + 4])
        body = data[i + 4:i + 4 + elen]
        exts.append(etype)
        if etype == 10 and len(body) >= 2:          # supported_groups
            n = struct.unpack("!H", body[:2])[0]
            curves = [struct.unpack("!H", body[2 + k:4 + k])[0] for k in range(0, n, 2)]
        if etype == 11 and len(body) >= 1:          # ec_point_formats
            n = body[0]
            formats = list(body[1:1 + n])
        i += 4 + elen
    ja3 = "{},{},{},{},{}".format(
        "-".join(map(str, ciphers)),
        "-".join(map(str, exts)),
        "-".join(map(str, curves)),
        "-".join(map(str, formats)),
        "0")                                        # no GREASE filtering here
    return ja3, hashlib.md5(ja3.encode()).hexdigest(), len(ciphers), len(exts)


def handle(conn, addr):
    try:
        conn.settimeout(5)
        data = b""
        while len(data) < 4096:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 5:
                rec_len = struct.unpack("!H", data[3:5])[0]
                if len(data) >= 5 + rec_len:
                    break
        r = parse_client_hello(data)
        label = addr[0]
        if r:
            ja3, digest, nc, ne = r
            print(f"{label}: ja3={digest} ciphers={nc} extensions={ne}", flush=True)
            print(f"    raw={ja3[:120]}{'...' if len(ja3) > 120 else ''}", flush=True)
        else:
            print(f"{label}: not a ClientHello ({len(data)} bytes)", flush=True)
    except OSError as e:
        print(f"{addr[0]}: {e}", flush=True)
    finally:
        try:
            conn.close()
        except OSError:
            pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 9443
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(8)
    print(f"ja3 probe on 0.0.0.0:{port}", flush=True)
    while True:
        c, a = srv.accept()
        threading.Thread(target=handle, args=(c, a), daemon=True).start()
