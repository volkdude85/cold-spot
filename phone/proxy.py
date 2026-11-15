#!/usr/bin/env python3
"""
noragate - a phone-side egress gate.

Why this exists: when you USB-tether or hotspot from an Android phone, the kernel
*forwards* your client's packets, so the carrier sees a decremented TTL, a second
IPv6 host on the phone's prefix, and a foreign TCP stack. This daemon does the
opposite - it terminates the client's connection and originates a NEW one from the
phone's own network stack. Upstream therefore sees phone-originated flows: TTL 64,
the phone's address, the phone's resolver. No spoofing required, because the phone
really is the one talking.

And if a VpnService (Mullvad) is up, these sockets ride the tun automatically, so
the same daemon puts the whole hotspot behind the tunnel.

Protocols: SOCKS5 (CONNECT, optional user/pass) and HTTP proxy (CONNECT + absolute URI).
Stdlib only. No dependencies. Binds 0.0.0.0 so it works over rndis (USB), softap, wifi.
"""

import argparse
import base64
import ipaddress
import json
import os
import selectors
import socket
import ssl
import struct
import sys
import threading
import time

BUFSZ = 65536
TAG = "noragate"
UA_REWRITE = None
START_TS = time.time()
SOCKS_PORT = 1080
HTTP_PORT = 8080
STATE_PORT = 8081

# --- multi-VPN egress guard -------------------------------------------------
# The gate rides whatever VpnService happens to be up, so it needs no provider
# API. What it does need is proof the tunnel is actually carrying it: a
# kill-switch exclusion, a split-tunnel rule and a dropped tunnel all look
# identical from inside - connections simply start leaving direct.
EGRESS_HOSTS = [("ifconfig.me", "/ip"), ("api.ipify.org", "/"), ("icanhazip.com", "/")]
EGRESS = {"ip": None, "baseline": None, "state": "unknown", "checked": 0, "history": []}
EXPECT = None
BLOCK_ON_LEAK = False
BLOCK_ON_CHANGE = False
EGRESS_LOCK = threading.Lock()


def _egress_fetch(timeout=15):
    for host, path in EGRESS_HOSTS:
        try:
            raw = socket.create_connection((host, 443), timeout=timeout)
            s = ssl.create_default_context().wrap_socket(raw, server_hostname=host)
            s.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                       f"User-Agent: noragate\r\nConnection: close\r\n\r\n").encode())
            buf = b""
            while len(buf) < 8192:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
            s.close()
            body = buf.split(b"\r\n\r\n", 1)[-1].decode(errors="replace").strip()
            addr = body.splitlines()[0].strip() if body else ""
            ipaddress.ip_address(addr)
            return addr
        except (OSError, ValueError, ssl.SSLError):
            continue
    return None


def egress_ok():
    if not (BLOCK_ON_LEAK or BLOCK_ON_CHANGE):
        return True
    with EGRESS_LOCK:
        return EGRESS["state"] in ("ok", "unknown")


def egress_monitor(interval):
    while True:
        ip = _egress_fetch()
        with EGRESS_LOCK:
            if ip:
                if EGRESS["baseline"] is None:
                    EGRESS["baseline"] = ip
                if EXPECT is not None:
                    try:
                        inside = any(ipaddress.ip_address(ip) in n for n in EXPECT)
                    except ValueError:
                        inside = False
                    state = "ok" if inside else "leak"
                elif ip != EGRESS["baseline"]:
                    state = "changed"
                else:
                    state = "ok"
                if EGRESS["ip"] and ip != EGRESS["ip"]:
                    EGRESS["history"].append({"t": int(time.time()), "from": EGRESS["ip"], "to": ip})
                    EGRESS["history"] = EGRESS["history"][-20:]
                EGRESS["ip"] = ip
                EGRESS["state"] = state
                EGRESS["checked"] = int(time.time())
                if state != "ok":
                    log(f"EGRESS {state.upper()} ip={ip} baseline={EGRESS['baseline']}")
                else:
                    log(f"egress ok ip={ip}")
            else:
                EGRESS["state"] = "unreachable"
                log("egress check unreachable (all echo hosts failed)")
        time.sleep(interval)



def log(msg):
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {msg}", flush=True)


class Stats:
    """Per-client counters. This is the seed of the control surface."""

    def __init__(self):
        self.lock = threading.Lock()
        self.clients = {}

    def _c(self, ip):
        return self.clients.setdefault(ip, {
            "conns": 0, "open": 0, "up": 0, "down": 0,
            "targets": {}, "first": time.time(), "last": time.time(),
        })

    def conn_open(self, ip, target):
        with self.lock:
            c = self._c(ip)
            c["conns"] += 1
            c["open"] += 1
            c["last"] = time.time()
            c["targets"][target] = c["targets"].get(target, 0) + 1

    def conn_close(self, ip):
        with self.lock:
            c = self._c(ip)
            c["open"] = max(0, c["open"] - 1)
            c["last"] = time.time()

    def bytes(self, ip, up, down):
        with self.lock:
            c = self._c(ip)
            c["up"] += up
            c["down"] += down
            c["last"] = time.time()

    def dump(self):
        with self.lock:
            return json.loads(json.dumps(self.clients))


STATS = Stats()

# --- bandwidth caps ---------------------------------------------------------
CAPS = {}          # ip -> bytes/sec ; 0 / absent = uncapped
DEFAULT_CAP = 0
_BUCKETS = {}      # ip -> [tokens, last_ts]
_BUCKET_LOCK = threading.Lock()


def cap_for(ip):
    return CAPS.get(ip, DEFAULT_CAP)


def pace(ip, nbytes):
    """Token bucket: sleep just enough to hold the client at its cap."""
    cap = cap_for(ip)
    if not cap:
        return
    with _BUCKET_LOCK:
        now = time.time()
        b = _BUCKETS.setdefault(ip, [cap, now])
        b[0] = min(cap, b[0] + (now - b[1]) * cap)
        b[1] = now
        b[0] -= nbytes
        deficit = -b[0]
    if deficit > 0:
        time.sleep(min(1.0, deficit / cap))


# --- resolver ---------------------------------------------------------------
# Resolving on the phone is the point: the client's resolver never appears on
# the wire, and with a tunnel up the lookup itself rides it.
DNS_SERVER = None          # e.g. "9.9.9.9"; None = system resolver
DNS_BY_CLIENT = {}
_DNS_CACHE = {}
_DNS_LOCK = threading.Lock()
DNS_LOG = []


def _dns_query(server, name, qtype=1, timeout=4):
    tid = struct.pack("!H", int(time.time() * 1000) & 0xFFFF)
    header = tid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".") if p) + b"\x00"
    pkt = header + q + struct.pack("!HH", qtype, 1)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (server, 53))
        resp, _ = s.recvfrom(4096)
    finally:
        s.close()
    if resp[:2] != tid:
        return []
    ancount = struct.unpack("!H", resp[6:8])[0]
    i = 12
    while resp[i] != 0:                      # skip question name
        i += resp[i] + 1
    i += 5                                   # null + qtype + qclass
    out = []
    for _ in range(ancount):
        if resp[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while resp[i] != 0:
                i += resp[i] + 1
            i += 1
        rtype, _, _, rdlen = struct.unpack("!HHIH", resp[i:i + 10])
        i += 10
        rdata = resp[i:i + rdlen]
        i += rdlen
        if rtype == 1 and rdlen == 4:
            out.append((socket.AF_INET, socket.inet_ntoa(rdata)))
        elif rtype == 28 and rdlen == 16:
            out.append((socket.AF_INET6, socket.inet_ntop(socket.AF_INET6, rdata)))
    return out


def resolve(host, client_ip=None, port=0):
    """Return [(family, sockaddr)] for host, honouring a per-client resolver."""
    try:
        ipaddress.ip_address(host)
        return socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    except ValueError:
        pass
    server = DNS_BY_CLIENT.get(client_ip, DNS_SERVER)
    key = (server, host)
    with _DNS_LOCK:
        hit = _DNS_CACHE.get(key)
        if hit and hit[0] > time.time():
            addrs = hit[1]
        else:
            addrs = []
    if not addrs and server:
        try:
            addrs = _dns_query(server, host, 1) + _dns_query(server, host, 28)
        except OSError:
            addrs = []
        with _DNS_LOCK:
            _DNS_CACHE[key] = (time.time() + 120, addrs)
        log(f"dns {client_ip} {host} -> {[a[1] for a in addrs]} via {server}")
        DNS_LOG.append({"t": int(time.time()), "client": client_ip, "host": host,
                        "via": server, "addrs": [a[1] for a in addrs]})
        del DNS_LOG[:-200]
    if addrs:
        return [(f, socket.SOCK_STREAM, 0, "", (a, port)) for f, a in addrs]
    return socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)



def relay(a, b, client_ip):
    """Bidirectional copy until both sides are done."""
    sel = selectors.DefaultSelector()
    sel.register(a, selectors.EVENT_READ, ("a", b))
    sel.register(b, selectors.EVENT_READ, ("b", a))
    open_socks = {a, b}
    while open_socks:
        events = sel.select(timeout=300)
        if not events:
            break
        for key, _ in events:
            src = key.fileobj
            dst = key.data[1]
            try:
                data = src.recv(BUFSZ)
            except OSError:
                data = b""
            if not data:
                try:
                    sel.unregister(src)
                except (KeyError, ValueError):
                    pass
                open_socks.discard(src)
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                continue
            try:
                dst.sendall(data)
            except OSError:
                try:
                    sel.unregister(src)
                except (KeyError, ValueError):
                    pass
                open_socks.discard(src)
                continue
            if key.data[0] == "a":
                STATS.bytes(client_ip, len(data), 0)
            else:
                STATS.bytes(client_ip, 0, len(data))
            pace(client_ip, len(data))
    for s in (a, b):
        try:
            sel.unregister(s)
        except (KeyError, ValueError):
            pass
    sel.close()


def connect_upstream(host, port, timeout=20, client_ip=None):
    """Resolve and connect from the phone's own stack. IPv4 then IPv6."""
    last = None
    for family, stype, proto, _, addr in resolve(host, client_ip, port):
        try:
            s = socket.socket(family, stype, proto)
            s.settimeout(timeout)
            s.connect(addr)
            s.settimeout(None)
            return s
        except OSError as e:
            last = e
            try:
                s.close()
            except Exception:
                pass
    raise last or OSError("no address")


ALLOW = None  # None = allow all; else set of client IPs


CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config.json")
CLIENTS_META = {}   # ip -> {"label": str, "deny": bool}
CONFIG = {"allow": None, "expect_egress": None, "block_on_leak": False,
          "block_on_change": False, "labels": {}, "caps": {}, "default_cap": 0,
          "dns": None, "dns_by_client": {}, "ua": None}


def load_config():
    global ALLOW, EXPECT, BLOCK_ON_LEAK, BLOCK_ON_CHANGE, CLIENTS_META
    global CAPS, DEFAULT_CAP, DNS_SERVER, DNS_BY_CLIENT, UA_REWRITE
    try:
        with open(CONFIG_PATH) as f:
            disk = json.load(f)
    except (OSError, ValueError):
        return
    CONFIG.update({k: v for k, v in disk.items() if k in CONFIG})
    ALLOW = set(CONFIG["allow"]) if CONFIG["allow"] else None
    if CONFIG["expect_egress"]:
        EXPECT = [ipaddress.ip_network(x, strict=False) for x in CONFIG["expect_egress"]]
    BLOCK_ON_LEAK = bool(CONFIG["block_on_leak"] or EXPECT)
    BLOCK_ON_CHANGE = bool(CONFIG["block_on_change"])
    for ip, label in (CONFIG.get("labels") or {}).items():
        CLIENTS_META.setdefault(ip, {})["label"] = label
    CAPS = {ip: int(v) for ip, v in (CONFIG.get("caps") or {}).items() if int(v) > 0}
    DEFAULT_CAP = int(CONFIG.get("default_cap") or 0)
    DNS_SERVER = CONFIG.get("dns") or None
    DNS_BY_CLIENT = dict(CONFIG.get("dns_by_client") or {})
    UA_REWRITE = CONFIG.get("ua") or None
    log(f"config loaded: allow={sorted(ALLOW) if ALLOW else 'all'} "
        f"expect={[str(n) for n in EXPECT] if EXPECT else None} "
        f"leak_block={BLOCK_ON_LEAK} change_block={BLOCK_ON_CHANGE}")


def save_config():
    CONFIG["allow"] = sorted(ALLOW) if ALLOW else None
    CONFIG["expect_egress"] = [str(n) for n in EXPECT] if EXPECT else None
    CONFIG["block_on_leak"] = BLOCK_ON_LEAK
    CONFIG["block_on_change"] = BLOCK_ON_CHANGE
    CONFIG["labels"] = {ip: m["label"] for ip, m in CLIENTS_META.items() if m.get("label")}
    CONFIG["caps"] = {ip: v for ip, v in CAPS.items() if v}
    CONFIG["default_cap"] = DEFAULT_CAP
    CONFIG["dns"] = DNS_SERVER
    CONFIG["dns_by_client"] = dict(DNS_BY_CLIENT)
    CONFIG["ua"] = UA_REWRITE
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(CONFIG, f, indent=1)
        return True
    except OSError:
        return False


def snapshot():
    with EGRESS_LOCK:
        egress = dict(EGRESS)
    clients = STATS.dump()
    for ip, meta in CLIENTS_META.items():
        if ip in clients:
            clients[ip].update(meta)
    return {
        "gate": {"socks": SOCKS_PORT, "http": HTTP_PORT, "state_port": STATE_PORT, "since": START_TS,
                  "pac": f"/proxy.pac"},
        "guard": {"armed": bool(BLOCK_ON_LEAK or BLOCK_ON_CHANGE),
                  "block_on_leak": BLOCK_ON_LEAK, "block_on_change": BLOCK_ON_CHANGE,
                  "expect": [str(n) for n in EXPECT] if EXPECT else None,
                  "state": egress["state"], "egress": egress["ip"],
                  "baseline": egress["baseline"], "checked": egress["checked"],
                  "history": egress["history"]},
        "allow": sorted(ALLOW) if ALLOW else None,
        "denied": sorted(ip for ip, m in CLIENTS_META.items() if m.get("deny")),
        "caps": {ip: v for ip, v in CAPS.items()},
        "default_cap": DEFAULT_CAP,
        "dns": DNS_SERVER,
        "dns_by_client": dict(DNS_BY_CLIENT),
        "ua": UA_REWRITE,
        "dns_log": DNS_LOG[-40:],
        "clients": clients,
        "totals": {"clients": len(clients),
                   "conns": sum(c["conns"] for c in clients.values()),
                   "open": sum(c["open"] for c in clients.values()),
                   "up": sum(c["up"] for c in clients.values()),
                   "down": sum(c["down"] for c in clients.values())},
    }


def read_request(conn):
    conn.settimeout(10)
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < 65536:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    lines = head.decode(errors="replace").split("\r\n")
    method, path = ("GET", "/state")
    if lines and " " in lines[0]:
        parts = lines[0].split(" ")
        method, path = parts[0], parts[1]
    length = 0
    for line in lines[1:]:
        if line.lower().startswith("content-length:"):
            try:
                length = int(line.split(":", 1)[1].strip())
            except ValueError:
                length = 0
    body = rest
    while len(body) < length:
        chunk = conn.recv(4096)
        if not chunk:
            break
        body += chunk
    return method, path.split("?")[0], body.decode(errors="replace")


def apply_config(payload):
    """Writable half of the control surface."""
    global ALLOW, EXPECT, BLOCK_ON_LEAK, BLOCK_ON_CHANGE
    global CAPS, DEFAULT_CAP, DNS_SERVER, DNS_BY_CLIENT, UA_REWRITE, SOCKS_PORT, HTTP_PORT, STATE_PORT
    changed = []
    if "allow" in payload:
        v = payload["allow"]
        ALLOW = {str(x).strip() for x in v} if v else None
        changed.append(f"allow={sorted(ALLOW) if ALLOW else 'all'}")
    if "expect_egress" in payload:
        v = payload["expect_egress"]
        EXPECT = [ipaddress.ip_network(str(x).strip(), strict=False) for x in v] if v else None
        changed.append(f"expect={[str(n) for n in EXPECT] if EXPECT else None}")
    if "block_on_leak" in payload:
        BLOCK_ON_LEAK = bool(payload["block_on_leak"])
        changed.append(f"block_on_leak={BLOCK_ON_LEAK}")
    if "block_on_change" in payload:
        BLOCK_ON_CHANGE = bool(payload["block_on_change"])
        changed.append(f"block_on_change={BLOCK_ON_CHANGE}")
    if "caps" in payload:
        CAPS.clear()
        CAPS.update({k: int(v) for k, v in (payload["caps"] or {}).items() if int(v) > 0})
        changed.append(f"caps={CAPS}")
    if "default_cap" in payload:
        DEFAULT_CAP = int(payload["default_cap"] or 0)
        changed.append(f"default_cap={DEFAULT_CAP}")
    if "dns" in payload:
        DNS_SERVER = payload["dns"] or None
        changed.append(f"dns={DNS_SERVER}")
    if "dns_by_client" in payload:
        DNS_BY_CLIENT.clear()
        DNS_BY_CLIENT.update({k: v for k, v in (payload["dns_by_client"] or {}).items() if v})
        changed.append(f"dns_by_client={DNS_BY_CLIENT}")
    if "ua" in payload:
        UA_REWRITE = payload["ua"] or None
        changed.append(f"ua={UA_REWRITE}")
    ok = save_config()
    log("config update: " + ", ".join(changed or ["(no change)"]) + ("" if ok else " [persist failed]"))
    return {"ok": ok, "changed": changed}


def apply_client(payload):
    ip = str(payload.get("ip", "")).strip()
    if not ip:
        return {"ok": False, "error": "ip required"}
    meta = CLIENTS_META.setdefault(ip, {})
    if "label" in payload:
        meta["label"] = str(payload["label"])[:64]
    if "cap" in payload:
        v = int(payload["cap"] or 0)
        if v > 0:
            CAPS[ip] = v
        else:
            CAPS.pop(ip, None)
    if "dns" in payload:
        if payload["dns"]:
            DNS_BY_CLIENT[ip] = str(payload["dns"])
        else:
            DNS_BY_CLIENT.pop(ip, None)
    if "deny" in payload:
        meta["deny"] = bool(payload["deny"])
        (ALLOW.discard(ip) if ALLOW is not None else None) if meta["deny"] else None
    save_config()
    log(f"client {ip} -> {meta}")
    return {"ok": True, "client": {ip: meta}}


def pac_for(host_ip):
    """WPAD-style proxy autoconfig. Root-free auto-config for any browser that
    accepts a PAC URL - one field, no per-app proxy settings."""
    return (
        "function FindProxyForURL(url, host) {\n"
        "  if (isPlainHostName(host) || shExpMatch(host, \"*.local\") ||\n"
        "      shExpMatch(host, \"127.*\") || shExpMatch(host, \"192.168.*\") ||\n"
        "      shExpMatch(host, \"10.*\") || shExpMatch(host, \"172.16.*\")) {\n"
        "    return \"DIRECT\";\n"
        "  }\n"
        f"  return \"PROXY {host_ip}:{HTTP_PORT}; SOCKS5 {host_ip}:{SOCKS_PORT}; DIRECT\";\n"
        "}\n"
    )


UI_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui")
UI_FILES = {
    "index.html": "text/html; charset=utf-8",
    "manifest.json": "application/manifest+json",
    "sw.js": "text/javascript",
    "icon-192.png": "image/png",
    "icon-512.png": "image/png",
}


def serve_ui(conn, path):
    """Static shell for the control panel / installed web app."""
    name = "index.html" if path in ("/", "/ui", "/ui/", "") else path.split("/")[-1]
    ctype = UI_FILES.get(name)
    if ctype is None:
        conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        return
    try:
        with open(os.path.join(UI_DIR, name), "rb") as f:
            body = f.read()
    except OSError:
        conn.sendall(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        return
    conn.sendall(
        f"HTTP/1.1 200 OK\r\nContent-Type: {ctype}\r\n"
        f"Access-Control-Allow-Origin: *\r\nCache-Control: no-cache\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body
    )


def handle_state(conn, addr):
    """Control API: GET /state|/clients|/egress ; POST /config|/client."""
    try:
        method, path, body = read_request(conn)
        if method == "OPTIONS":
            conn.sendall(b"HTTP/1.1 204 No Content\r\n"
                         b"Access-Control-Allow-Origin: *\r\n"
                         b"Access-Control-Allow-Methods: GET,POST,OPTIONS\r\n"
                         b"Access-Control-Allow-Headers: Content-Type\r\n"
                         b"Access-Control-Max-Age: 600\r\n"
                         b"Content-Length: 0\r\nConnection: close\r\n\r\n")
            return
        status = "200 OK"
        if path == "/" or path == "/ui" or path == "/ui/" or path.split("/")[-1] in UI_FILES:
            serve_ui(conn, path)
            return
        if path == "/proxy.pac":
            body = pac_for(conn.getsockname()[0]).encode()
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\n"
                b"Access-Control-Allow-Origin: *\r\nCache-Control: no-store\r\n"
                + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                + body
            )
            return
        if method == "POST":
            try:
                payload = json.loads(body or "{}")
            except ValueError:
                payload = None
            if payload is None:
                status, result = "400 Bad Request", {"ok": False, "error": "bad json"}
            elif path == "/config":
                result = apply_config(payload)
            elif path == "/client":
                result = apply_client(payload)
            else:
                status, result = "404 Not Found", {"ok": False, "error": "unknown path"}
            body_obj = dict(result)
            body_obj["state"] = snapshot()
        elif path == "/state":
            body_obj = snapshot()
        elif path == "/clients":
            body_obj = snapshot()["clients"]
        elif path == "/egress":
            body_obj = snapshot()["guard"]
        else:
            status, body_obj = "404 Not Found", {"error": "unknown path",
                                                 "paths": ["/state", "/clients", "/egress", "/config", "/client"]}
        payload = json.dumps(body_obj, indent=1).encode()
        conn.sendall(
            f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\n"
            f"Access-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET,POST,OPTIONS\r\n"
            f"Access-Control-Allow-Headers: Content-Type\r\nCache-Control: no-store\r\n"
            f"Content-Length: {len(payload)}\r\nConnection: close\r\n\r\n".encode() + payload
        )
    except (OSError, ValueError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def client_allowed(ip):
    if CLIENTS_META.get(ip, {}).get("deny"):
        return False
    if ALLOW is not None and ip not in ALLOW:
        return False
    return egress_ok()

def _udp_relay(client_conn, client_ip, bind_host):
    """SOCKS5 UDP ASSOCIATE: terminate UDP on the phone and re-originate it."""
    us = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    us.bind((bind_host, 0))
    port = us.getsockname()[1]
    try:
        client_conn.sendall(b"\x05\x00\x00\x01" + socket.inet_aton(bind_host) + struct.pack("!H", port))
    except OSError:
        us.close()
        return
    log(f"socks UDP ASSOCIATE {client_ip} on {bind_host}:{port}")

    sel = selectors.DefaultSelector()
    us.setblocking(False)
    sel.register(us, selectors.EVENT_READ, "client")
    peers = {}          # peer sock -> (host, port)
    client_addr = [None]
    deadline = time.time() + 300

    def peer_for(host, port):
        try:
            ip = socket.gethostbyname(host)
        except OSError:
            return None
        p = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        p.setblocking(False)
        try:
            p.connect((ip, port))
        except OSError:
            p.close()
            return None
        sel.register(p, selectors.EVENT_READ, "peer")
        peers[p] = (host, port)
        STATS.conn_open(client_ip, f"udp {host}:{port}")
        return p

    try:
        while time.time() < deadline:
            for key, _ in sel.select(timeout=1.0):
                if key.data == "client":
                    try:
                        data, caddr = us.recvfrom(65535)
                    except OSError:
                        continue
                    client_addr[0] = caddr
                    if len(data) < 10 or data[0] or data[1] or data[2]:
                        continue                 # bad header or fragmented
                    atyp, i = data[3], 4
                    if atyp == 1:
                        host = socket.inet_ntoa(data[i:i + 4]); i += 4
                    elif atyp == 3:
                        ln = data[i]; i += 1
                        host = data[i:i + ln].decode(errors="replace"); i += ln
                    elif atyp == 4:
                        host = socket.inet_ntop(socket.AF_INET6, data[i:i + 16]); i += 16
                    else:
                        continue
                    dport = struct.unpack("!H", data[i:i + 2])[0]; i += 2
                    payload = data[i:]
                    p = peer_for(host, dport)
                    if p is None:
                        continue
                    try:
                        p.send(payload)
                        STATS.bytes(client_ip, len(payload), 0)
                    except OSError:
                        pass
                else:
                    p = key.fileobj
                    try:
                        payload = p.recv(65535)
                    except OSError:
                        continue
                    if not client_addr[0]:
                        continue
                    host, dport = peers.get(p, ("0.0.0.0", 0))
                    try:
                        ip = socket.inet_aton(host)
                        hdr = b"\x00\x00\x00\x01" + ip
                    except OSError:
                        hb = host.encode()
                        hdr = b"\x00\x00\x00\x03" + bytes([len(hb)]) + hb
                    us.sendto(hdr + struct.pack("!H", dport) + payload, client_addr[0])
                    STATS.bytes(client_ip, 0, len(payload))
    finally:
        for p in peers:
            try:
                sel.unregister(p)
            except (KeyError, ValueError):
                pass
            try:
                p.close()
            except OSError:
                pass
            STATS.conn_close(client_ip)
        sel.close()
        us.close()


def handle_socks5(conn, addr, auth):
    client_ip = addr[0]
    try:
        hdr = conn.recv(2)
        if len(hdr) < 2 or hdr[0] != 5:
            return
        nmethods = hdr[1]
        methods = conn.recv(nmethods) if nmethods else b""
        if auth:
            if 2 not in methods:
                conn.sendall(b"\x05\xff")
                return
            conn.sendall(b"\x05\x02")
            ver = conn.recv(1)
            ulen = conn.recv(1)
            user = conn.recv(ulen[0]) if ulen else b""
            plen = conn.recv(1)
            pw = conn.recv(plen[0]) if plen else b""
            if ver != b"\x01" or user.decode(errors="replace") != auth[0] or pw.decode(errors="replace") != auth[1]:
                conn.sendall(b"\x01\x01")
                return
            conn.sendall(b"\x01\x00")
        else:
            if 0 not in methods:
                conn.sendall(b"\x05\xff")
                return
            conn.sendall(b"\x05\x00")

        req = conn.recv(4)
        if len(req) < 4:
            return
        if req[1] == 3:   # UDP ASSOCIATE
            conn.recv(10)  # dst addr/port of the associate request (unused)
            _udp_relay(conn, client_ip, conn.getsockname()[0])
            return
        if req[1] != 1:   # CONNECT only otherwise
            conn.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return
        atyp = req[3]
        if atyp == 1:
            host = socket.inet_ntoa(conn.recv(4))
        elif atyp == 3:
            ln = conn.recv(1)[0]
            host = conn.recv(ln).decode(errors="replace")
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, conn.recv(16))
        else:
            conn.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
            return
        port = struct.unpack("!H", conn.recv(2))[0]

        target = f"{host}:{port}"
        STATS.conn_open(client_ip, target)
        try:
            up = connect_upstream(host, port, client_ip=client_ip)
        except OSError as e:
            log(f"socks DENY {client_ip} -> {target} ({e})")
            conn.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)
            STATS.conn_close(client_ip)
            return
        log(f"socks OK {client_ip} -> {target}")
        reply = b"\x05\x00\x00\x01" + socket.inet_aton("0.0.0.0") + struct.pack("!H", 0)
        conn.sendall(reply)
        relay(conn, up, client_ip)
        STATS.conn_close(client_ip)
        up.close()
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def handle_http(conn, addr):
    client_ip = addr[0]
    try:
        conn.settimeout(30)
        buf = b""
        while b"\r\n\r\n" not in buf and len(buf) < 65536:
            chunk = conn.recv(BUFSZ)
            if not chunk:
                return
            buf += chunk
        head, _, rest = buf.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        try:
            method, uri, ver = lines[0].decode(errors="replace").split(" ", 2)
        except ValueError:
            return
        headers = lines[1:]

        if method.upper() == "CONNECT":
            host, _, port = uri.rpartition(":")
            port = int(port or 443)
            target = f"{host}:{port}"
            STATS.conn_open(client_ip, target)
            try:
                up = connect_upstream(host, port, client_ip=client_ip)
            except OSError as e:
                conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                log(f"http DENY {client_ip} -> {target} ({e})")
                STATS.conn_close(client_ip)
                return
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            log(f"http CONNECT {client_ip} -> {target}")
            if rest:
                up.sendall(rest)
                STATS.bytes(client_ip, len(rest), 0)
            relay(conn, up, client_ip)
            STATS.conn_close(client_ip)
            up.close()
            return

        # absolute-URI plain request
        if not uri.startswith("http://"):
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return
        without_scheme = uri[len("http://"):]
        hostport, slash, path = without_scheme.partition("/")
        host, _, port = hostport.partition(":")
        port = int(port or 80)
        target = f"{host}:{port}"
        STATS.conn_open(client_ip, target)
        try:
            up = connect_upstream(host, port, client_ip=client_ip)
        except OSError as e:
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            STATS.conn_close(client_ip)
            return
        skip = (b"proxy-connection:", b"connection:", b"keep-alive:")
        out = [f"{method} /{path or ''} HTTP/1.1".encode()]
        for h in headers:
            if h.lower().startswith(b"user-agent:") and UA_REWRITE:
                out.append(("User-Agent: " + UA_REWRITE).encode())
            elif not h.lower().startswith(skip):
                out.append(h)
        out.append(b"Connection: close")
        up.sendall(b"\r\n".join(out) + b"\r\n\r\n" + rest)
        log(f"http GET {client_ip} -> {target}")
        relay(conn, up, client_ip)
        STATS.conn_close(client_ip)
        up.close()
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve(port, handler, name, auth=None, gated=True):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(64)
    log(f"{name} listening on 0.0.0.0:{port}")
    while True:
        try:
            conn, addr = srv.accept()
        except OSError:
            break
        if gated and not client_allowed(addr[0]):
            why = "allowlist" if (ALLOW is not None and addr[0] not in ALLOW) else "egress guard"
            log(f"deny {addr[0]} ({why})")
            conn.close()
            continue
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if handler is handle_socks5:
            t = threading.Thread(target=handler, args=(conn, addr, auth), daemon=True)
        else:
            t = threading.Thread(target=handler, args=(conn, addr), daemon=True)
        t.start()


def main():
    global ALLOW, EXPECT, BLOCK_ON_LEAK, BLOCK_ON_CHANGE, SOCKS_PORT, HTTP_PORT, STATE_PORT
    ap = argparse.ArgumentParser()
    ap.add_argument("--socks", type=int, default=1080)
    ap.add_argument("--http", type=int, default=8080)
    ap.add_argument("--state", type=int, default=8081, help="read-only control API")
    ap.add_argument("--user")
    ap.add_argument("--password")
    ap.add_argument("--allow", help="comma-separated client IPs; default all")
    ap.add_argument("--expect-egress", help="comma-separated CIDRs the tunnel must exit from")
    ap.add_argument("--egress-interval", type=int, default=300, help="seconds between egress checks")
    ap.add_argument("--block-on-leak", action="store_true", help="refuse clients when egress is outside --expect-egress")
    ap.add_argument("--block-on-change", action="store_true", help="refuse clients when egress moves off its baseline")
    args = ap.parse_args()

    global SOCKS_PORT, HTTP_PORT, STATE_PORT
    SOCKS_PORT, HTTP_PORT, STATE_PORT = args.socks, args.http, args.state
    load_config()

    if args.allow:
        ALLOW = {x.strip() for x in args.allow.split(",") if x.strip()}
        log(f"allowlist: {sorted(ALLOW)}")

    if args.expect_egress:
        EXPECT = [ipaddress.ip_network(x.strip(), strict=False)
                  for x in args.expect_egress.split(",") if x.strip()]
        log(f"expected egress: {[str(n) for n in EXPECT]}")
    BLOCK_ON_LEAK = args.block_on_leak or bool(EXPECT)
    BLOCK_ON_CHANGE = args.block_on_change
    if BLOCK_ON_LEAK or BLOCK_ON_CHANGE:
        log(f"egress guard armed (leak={BLOCK_ON_LEAK} change={BLOCK_ON_CHANGE})")

    auth = (args.user, args.password) if args.user else None
    if auth:
        log("SOCKS5 user/pass auth enabled")

    threading.Thread(target=egress_monitor, args=(args.egress_interval,), daemon=True).start()
    threading.Thread(target=serve, args=(args.http, handle_http, "http"), daemon=True).start()
    threading.Thread(target=serve, args=(args.socks, handle_socks5, "socks5", auth), daemon=True).start()
    threading.Thread(target=serve, args=(args.state, handle_state, "state", None, False), daemon=True).start()

    while True:
        time.sleep(15)
        snapshot = STATS.dump()
        with EGRESS_LOCK:
            egress = dict(EGRESS)
        try:
            with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "stats.json"), "w") as f:
                json.dump({"ts": time.time(), "egress": egress, "clients": snapshot}, f, indent=1)
        except OSError:
            pass
        for ip, c in snapshot.items():
            log(f"stat {ip} conns={c['conns']} open={c['open']} up={c['up']} down={c['down']}")


if __name__ == "__main__":
    main()
