# Cold Spot

A gate that runs on an Android phone and lets a tethered or hotspot client use the phone's
connection **without the phone forwarding that client's packets**.

Everything else in this project follows from that one decision, so start there.

```
client  ──proxy──▶  Cold Spot on the phone  ──new connection──▶  carrier
                    (ordinary app sockets, so any VpnService
                     captures them automatically)
```

## Why this exists

Android's hotspot and USB tethering *forward* packets. Forwarding is what makes them
observable, and it is also what makes them impossible to put behind a VPN:

- The kernel decrements the hop count, so a tethered Linux client arrives upstream at
  TTL 63 and a Windows client at 127, against the phone's own 64.
- The carrier sees a second host on the phone's prefix.
- The tethering service picks its upstream with a `NetworkRequest` that carries
  `NET_CAPABILITY_NOT_VPN`. A `VpnService` tun can never satisfy that request, so the
  stock hotspot is never behind the VPN and no setting changes it.

Cold Spot does not forward. It terminates the client's connection and opens a **new** one
from the phone's own network stack. Upstream sees phone-originated flows — TTL 64, the
phone's address, the phone's resolver, Android's TCP stack. Nothing is spoofed: the phone
genuinely is the one talking. And because those are ordinary app sockets, a running
`VpnService` captures them automatically, which is how the same daemon also puts a hotspot
behind the tunnel — something the framework cannot do on its own.

## The three repositories

Three repositories. This one is the entry point — everything else is linked from here.

| repo | what it is |
| --- | --- |
| **[cold-spot](https://github.com/volkdude85/cold-spot)** ← you are here | the daemon, the drivers, the design record, the ROM patch, and the original prototype |
| **[cold-spot-android](https://github.com/volkdude85/cold-spot-android)** | the app shell: foreground service, WebView panel, VPN watcher, build scripts |
| **[cold-spot-graphing](https://github.com/volkdude85/cold-spot-graphing)** | a single-file telemetry dashboard that charts the gate's own counters and exit history |

To build the whole thing: clone all three side by side, then `cold-spot-android` picks up the
daemon from `../cold-spot` on its own.

```bash
git clone https://github.com/volkdude85/cold-spot
git clone https://github.com/volkdude85/cold-spot-android
git clone https://github.com/volkdude85/cold-spot-graphing
cd cold-spot-android && ./scripts/build-daemon.sh ../cold-spot && ./gradlew :app:assembleDebug
```

## Quick start

```bash
# 1. build the daemon for a phone
cd daemon
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o libnoragated.so .

# 2. run it on a desktop first — it is a normal Linux binary
go build -o coldspotd . && ./coldspotd -listen 127.0.0.1:1080 \
    -proxy 127.0.0.1:8080 -state 127.0.0.1:8081

# 3. point anything at it
curl -x http://127.0.0.1:8080 https://ifconfig.me
```

For the phone: see **cold-spot-android**, which wraps this binary in an APK.

## What the daemon is

One static Go binary. No interpreter, no root, no Termux, no dependency outside the
standard library.

- **SOCKS5** (`:1080`), **HTTP proxy** (`:8080`), **control API + panel** (`:8081`), optional
  **TLS-terminating proxy** (`:8443`) as a second binary.
- Originates every flow from the phone's own stack; never forwards.
- Resolves names on the phone (per-client resolver → configured resolver → system) and logs
  every lookup, because that log is the proof a client's DNS never reached the wire.
- Per-client token-bucket rate caps, allow/deny, labels, and byte counters.
- An **egress guard** that measures the daemon's own exit address and fails closed.

## The egress guard, and why it is the point

A kill-switch exclusion, a split-tunnel rule and a dead tunnel all look identical from
inside a phone: traffic simply leaves direct. Architecture cannot tell you which happened.
So the daemon measures its own exit address and refuses clients when the answer is not the
one it expects.

```
--expect-egress 203.0.113.0/24   ->  leak: exit 198.51.100.7, clients refused
--expect-egress 198.51.100.0/24  ->  ok:   exit 198.51.100.7, clients served
```

Providers whose exit ranges you do not want to hardcode get `--block-on-change` instead: pin
the first observed exit, refuse if it moves. Neither mode is useful without a way back, so
there is `POST /config {"relearn": true}` — clear the baseline, measure again immediately.
**A fail-closed guard without a relearn door is a lockout**, and that is not a theory: it
locked this project out for a full working session.

## The control API

```
GET  /state    the whole picture: gate, guard, clients, totals, dns log
GET  /clients  per-client counters
GET  /egress   guard state, current exit, baseline, change history
GET  /vpns     driver table and which one is active
POST /config   {"vpn":"mullvad"} | {"relearn":true} | {"dns":"1.1.1.1"} | {"block_on_change":true} | ...
POST /client   {"ip":"...","cap":n,"dns":"...","label":"...","deny":true}
GET  /proxy.pac
GET  /         the panel
```

Two deliberate choices, both learned the hard way:

- **The state API is ungated.** Access control applies to the proxy, not the panel. A wrong
  allowlist is exactly when you need to reach in and fix it.
- **`OPTIONS` answers 204 with CORS headers.** A JSON POST always preflights; without this
  the panel looks dead while `curl` works perfectly.

## What it sends out

The daemon's entire outbound surface is the egress probe: one plain-HTTP GET to a service that
answers with your address, so the guard can tell whether your traffic is really leaving through
the tunnel. That is the only connection the daemon makes that is not a client's.

Measured on the wire, the default request is a single header:

```
GET /ip HTTP/1.1
Host: ifconfig.me
```

No `User-Agent`, no `Accept-Encoding`, no cookies, nothing else. Go's own
`Go-http-client/1.1` default is suppressed deliberately — a distinctive agent on a periodic
request to an IP-echo service is an outbound signature that says *this device runs this tool*.

Three ways to control it:

| flag | effect |
| --- | --- |
| `-egress-url http://your.host/ip` | point the probe at an endpoint you control; the request never leaves your infrastructure |
| `-egress-probe 300` | seconds between probes (default 300, five minutes) |
| `-egress-probe 0` | **no probe at all.** The daemon then makes no outbound connections of its own |
| `-egress-ua "..."` | opt in to a User-Agent, if a server you control wants one |

Turning the probe off costs you the guard: with nothing measuring the exit address, the daemon
cannot tell a working tunnel from a dead one, and clients will not be refused. If you set
`-expect-egress` and disable the probe, it says so in the log rather than pretending.

Default hosts, if you leave `-egress-url` empty: `ifconfig.me`, `api.ipify.org`,
`icanhazip.com`. Replace them if you would rather not contact a third party.

## Documentation

| file | contents |
| --- | --- |
| [docs/DESIGN.md](docs/DESIGN.md) | every design decision and what it cost |
| [docs/PORTING.md](docs/PORTING.md) | **start here if your carrier, VPN or phone differs** |
| [docs/BUGS.md](docs/BUGS.md) | the bug/fix/test table — the fastest way to understand the internals |
| [docs/MEASUREMENTS.md](docs/MEASUREMENTS.md) | what was actually measured, and how |
| [docs/LIMITS.md](docs/LIMITS.md) | what this does not do, stated rather than hidden |
| [docs/CODE-STANDARDS.md](docs/CODE-STANDARDS.md) | **how we build** — the jSat standard, and where this project departs from it |
| [PROJECT-STANDARDS.md](PROJECT-STANDARDS.md) | what to expect here, and what is not being asked of you |
| [SECURITY.md](SECURITY.md) | what counts as a vulnerability, and what is deliberately out of scope |
| [CONTRIBUTING.md](CONTRIBUTING.md) | build, test, and the four rules that actually matter |
| [CHANGELOG.md](CHANGELOG.md) | what changed in each build |

## Honest status

Working, measured, and in daily use on a GrapheneOS Pixel with a Mullvad tunnel. The
daemon, the proxy legs, the guard, UDP, the driver seam and the panel all have
measurements behind them in [docs/MEASUREMENTS.md](docs/MEASUREMENTS.md).

Not finished: the cellular-carrier claim. What is provable from the device is that every
signal a carrier could use is neutralised. What the carrier's own classifier concluded is
**unmeasured**, and no amount of reading the framework makes it measured. See
[LIMITS.md](docs/LIMITS.md) for the meter-diff test that settles it on your own plan.

## How this was built

By an AI agent (DeepSeek V4.1 Flash, `deepseek-v4.1-flash:1017`) with a shell, adb on a real
device, and the ability to run what it wrote — which is the only reason any of the numbers in
these docs mean anything.

Two things about the method are worth knowing before you read the code. First, the pieces join at
**explicit seams** — the driver, the control API, the guard, the native binary — because a system
built piece by piece fails at the joins, not in the pieces. Second, the agent is told, repeatedly,
**not to trust its own training** and to go read the current documentation and reference
implementations instead: this model is weak on Go and weak on SQL, and saying so is more useful
than sounding confident.

The house standard is written down in [docs/CODE-STANDARDS.md](docs/CODE-STANDARDS.md), including
the honest part: the language order we prefer is C++ and assembly, and this project is Go and Java
because that is what an APK sandbox and a statically linked daemon actually need.

## License

MIT. See [LICENSE](LICENSE).
