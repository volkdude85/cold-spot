# What was measured, and how

Addresses in this file are placeholders (`<home-wan>`, `<carrier-egress>`, `<vpn-exit>`)
because the point is the *shape* of the result, not anyone's network. Byte counts, timings,
status codes and interface facts are real.

## The claim, measured end to end

From a laptop joined to the phone's hotspot, phone on cellular only, through the gate:

| path | endpoint | answer | bytes |
| --- | --- | --- | --- |
| laptop direct (household connection) | `/ip` v4-only | `<home-wan>` | 13 |
| laptop → gate → out | `/ip` dual-stack | `<carrier-egress>` (IPv6) | 39 |
| laptop → gate via SOCKS5 | `/ip` dual-stack | `<carrier-egress>` (IPv6) | 39 |
| laptop → gate → out | `v4.ident.me` | `<carrier-cgnat>` | 13 |
| laptop direct | `v4.ident.me` | `<home-wan>` | 13 |

**Two answers on two different networks.** That is the whole claim of the project: a client on
the hotspot is seen by the far end as the phone on cellular, not as a tethered host on the
household connection.

Gate-side accounting for that run, straight out of `/state`:

```
client 192.0.2.30   conns 6   up 77 B   down 281 B
```

Under 400 bytes total on the metered leg for the entire test — which is what makes the test
acceptable on a metered plan.

Note the CGNAT egress: the answer to the v4 endpoint is neither the phone's interface address
nor the household address. Expect that on any mobile carrier and do not mistake it for a leak.

## The VPN leg, measured

With a tunnel up, from a LAN client through the gate:

| path | answer |
| --- | --- |
| client direct | `<home-wan>` |
| client → gate → out | `<vpn-exit>` (the provider's range, a different ASN from the carrier) |

and the guard follows on its own:

```
vpn seam: candidates=[<browser-that-ships-a-vpnservice>, <vpn-app>] drivers=[<vpn>]
vpn seam: driver <vpn>
network (start) -> tun0/3: guard relearned
state: vpn <vpn>  guard ok  egress <vpn-exit>
```

## Proxy legs through the installed APK

```
SOCKS5 http          200
HTTP proxy https     200
UDP ASSOCIATE        reply 8.7 ms, payload intact (6.7–8.7 ms across runs)
UI / PAC served      200
egress               <phone-address>   (the phone, not the client)
```

`test_udp.py` measures the SOCKS5 `UDP ASSOCIATE` round-trip; `test_pipeline.py` sends a
request and a TLS ClientHello in a single write to catch buffers eating the handshake.

## TLS fingerprint

```
client's own stack      2b44d0971d74edd3a84ed9fc9b5f31b0   30 ciphers, 12 extensions
through the plain gate  2b44d0971d74edd3a84ed9fc9b5f31b0   30 ciphers, 12 extensions
through coldspot-tls    420f8db7b6195fb4800027a493c7cfc3   16 ciphers, 17 extensions
```

Identical through a plain tunnel — which is the honest baseline. The third row is the
opt-in TLS-terminating binary. Verified through the installed APK with the CA the app
generated on the device:

```
https://example.com   http=200  bytes=577  HTTP/2
```

## Framework facts, read off the device

```bash
adb shell dumpsys connectivity | grep -A1 'RequestorPkg: com.android.networkstack.tethering'
#   the upstream NetworkRequest carries NET_CAPABILITY_NOT_VPN

adb shell dumpsys tethering | grep 'Current upstream'
#   with the hotspot up: a physical interface (rmnet*/wlan*), never tun*
```

Two upstream callbacks exist. The automatic path follows the system default network, defined
as `NOT_VPN`. The other (`startObserveUpstreamNetworks`) builds its request with
`clearCapabilities()` and therefore has no `NOT_VPN`, so a tun does land in that map and feeds
the legacy `selectPreferredUpstreamType()` path. The framework can already represent a VPN as
an upstream; nothing automatic consults it.

## No-root ceiling, measured on a locked device

| lever | result |
| --- | --- |
| `pm grant <pkg> android.permission.WRITE_SECURE_SETTINGS` | works (`development` protection level) |
| `pm grant <pkg> android.permission.TETHER_PRIVILEGED` | refused — signature permission |
| `cmd overlay list` / enable an RRO from shell | works |
| replace `Settings.apk` / an APEX file | impossible — dm-verity + APEX signatures |

## Test suite

```
go vet ./...                  clean
go test ./...                 unit tests: SOCKS addr codec, allow/deny, caps, snapshot, guard
test_udp.py                   SOCKS5 UDP ASSOCIATE round-trip
test_pipeline.py              pipelined CONNECT + ClientHello
ja3_probe.py                  ClientHello fingerprint, for measuring the TLS gap
```

## What is not in these numbers

- The carrier's classification of any flow. See [LIMITS.md](LIMITS.md).
- Anything about a phone, carrier or provider other than the one this was built on.
- Throughput beyond "the proxy is not the bottleneck". The gate is a relay on a phone; measure
  your own link before drawing conclusions about speed.
