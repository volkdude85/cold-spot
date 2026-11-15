# Design decisions, and what each one cost

A decision record written while building rather than after it. Every claim here has a
command or a measurement behind it, because the point of the file is that someone who does
not know the author can check the work instead of trusting it.

---

## 1. Do not forward — originate

**The decision.** Cold Spot runs as an ordinary app on the phone. It accepts a proxy
connection from a client and opens a *new* connection to the destination from the phone's
own network stack.

**Why.** Forwarding is the fingerprint. Three separate things give a tethered host away, and
all three are properties of forwarding rather than of the data:

| signal | what the carrier sees | fixable without root? |
| --- | --- | --- |
| IP hop count | tethered Linux arrives at TTL 63, Windows at 127, phone sends 64 | no — needs `iptables -t mangle -j TTL --ttl-set 64` |
| host count | a second IPv6 host on the phone's prefix | no |
| resolver | the client's DNS server, not the phone's | partly |

Setting TTL requires root, which a hardened ROM will not give you. So the answer is not to
suppress the signature, it is to not produce one: the phone accepts the client's flow, and
the phone is the thing that talks upstream. TTL 64, the phone's address, the phone's
resolver, one host. Nothing is spoofed and there is nothing to detect, because it is true.

**The bonus that makes the whole project work.** These are ordinary app sockets, so a
running `VpnService` captures them automatically. The same decision that hides the tethering
also puts the hotspot behind the VPN.

**What it cost.** The client has to be told to use the gate — a proxy field, `ALL_PROXY`, or
the PAC file. The version with *no* client configuration requires a ROM change (see §7).

---

## 2. The stock hotspot is never behind the VPN, and no setting changes that

**The measurement.** On the device:

```bash
adb shell dumpsys connectivity | grep -A1 'RequestorPkg: com.android.networkstack.tethering'
```

The tethering service's `NetworkRequest` carries `NET_CAPABILITY_NOT_VPN`. A `VpnService`
tun cannot satisfy a request that excludes VPNs, so hotspot clients are always NAT'd out the
physical interface.

**The nuance worth knowing.** There are *two* upstream callbacks in the framework.
`startTrackDefaultNetwork()` follows the system default (which is defined as `NOT_VPN` and is
the live path while `chooseUpstreamAutomatically` is true). `startObserveUpstreamNetworks()`
builds its request with `clearCapabilities()` and carries **no** `NOT_VPN`, so a tun *does*
land in that map and feeds the legacy `selectPreferredUpstreamType()` path. The framework can
already represent a VPN as an upstream; the automatic path simply never consults it. That
pair of callbacks is the precise hook a patched tethering module cuts.

---

## 3. Four routes to "hotspot behind the VPN", and why the app is one of them

Which route you take decides who can use the result. This is the honest map.

| route | client config | root | ROM build | who it is for |
| --- | --- | --- | --- | --- |
| **app-level gate** (proxy / PAC) — *this project* | yes, one field per device | no | no | anyone, today, any phone |
| **a router in front** (travel router / OpenWrt + WireGuard) | none | no | no | a household; beats every phone hack because it depends on no phone model |
| **root module** (policy routing + NAT below the framework) | none | yes | no | a rooted device |
| **patched tethering APEX** | none | no | yes | a phone that already runs a custom build |

Say which one you are building before writing code, and say it in those terms — "needs root"
and "nobody can use it" are not the same claim.

There is a root route in this repo's history and it needs exactly three things, and missing
any one makes it silently useless:

1. Turn tethering's BPF offload off (`device_config put connectivity override_tether_enable_bpf_offload
   false`). With offload on, packets bypass netfilter and your rules never see them.
2. A per-downstream policy rule (`ip rule add from all iif <rndis0|ncm0|swlan0|ap_br_wlan0>
   lookup <vpn-table> pref 17000`). Without it the clients keep the physical upstream no
   matter what you NAT.
3. NAT out the tun **and** reset the hop count (`iptables -t nat -A POSTROUTING -o tun0 -j
   MASQUERADE` plus `-j TTL --ttl-set 64`). The TTL line is the one thing no unrooted design
   can do, and it is the line that matters most for identity.

`patches/0001-tethering-vpn-upstream.patch` is the 35-line ROM route: a `DeviceConfig` flag,
an `isUsableVpn()`, a search over the capability-cleared map, and an early return in
`getCurrentPreferredUpstream()`.

---

## 4. Go, for the daemon

**The decision.** One statically linked Go binary.

**Why.** It has to ship inside an APK with no interpreter, no Termux and no root. Go
cross-compiles to `linux/arm64` statically, runs inside an app sandbox, and gives one
artifact that can be tested on a desktop first. It is also the language where the
concurrency model — one goroutine per connection, one selector loop per UDP association — is
the least code.

**What it cost, and both of these are real bugs:**

- Go's TLS cannot shape a ClientHello. Fingerprint work therefore needed a **separate uTLS
  binary**, and the two binaries have to agree on ALPN or the handshake completes and then
  hangs (see BUGS.md).
- A pure-Go binary on Android has **no system CA bundle** and no working
  `/etc/resolv.conf`. The first made every HTTPS egress probe fail on the phone; the second
  made every dial fail while the resolver "looked" configured.

---

## 5. The daemon ships as a `.so`

**The decision.** `libnoragated.so` is a renamed arm64 executable, packaged in `jniLibs`.

**Why.** Android will not execute a binary that an app wrote into its own data directory.
Native libraries are the exception — they are extracted into `nativeLibraryDir` and are
executable there. So the manifest carries `android:extractNativeLibs="true"` and the build
carries `packaging { jniLibs { useLegacyPackaging = true } }`, because otherwise AGP maps
the library straight out of the APK and `nativeLibraryDir` is empty. That symptom is
`ProcessBuilder: error=2, No such file or directory` on a device where `ls lib/` in the app
data dir shows nothing.

**The panel rides along.** The UI ships as assets, is extracted to `filesDir/ui` on first
start, and is served by the daemon itself on `127.0.0.1:8081`. Localhost is a secure
context, so the panel installs as a PWA with no certificate involved.

---

## 6. Drivers are data, not code

**The decision.** A provider is a JSON record: name, title, the packages that identify it,
an optional DNS to adopt, optional exit ranges, a note. Built-ins ship in the binary; any
`*.json` in the drivers directory is merged in, and a file with the same name as a built-in
overrides it.

**Why.** The gate never talks to a provider's API. It rides whatever tun is up. What differs
between providers is only what you expect to see on the wire. That is data. Supporting a new
provider should be dropping a file, not forking a daemon.

**A driver with no published exit ranges is not a failure case.** Activate it with the ranges
empty and arm `block-on-change`: the guard learns this tunnel's exit and fails closed if it
moves. That is what makes an unknown provider work without shipping a table of every exit
network on earth — and a table you ship stale is a false "leak" the first time the provider
adds a range.

**What it cost: naming the tunnel at all.** This turned out to be the hardest small problem in
the project, and the reasons are worth other people's time:

- `NetworkCapabilities.getOwnerUid()` answers `INVALID_UID` for an app that does not own the
  tunnel — the normal case — so the first look at a fresh tunnel names nothing.
- Never cache that empty answer as a driver. The VPN network does not change again, so a
  latched guess is permanent: the panel sits on "any other VpnService" forever while the VPN
  is connected.
- A `<queries><intent>` declaration for `android.net.VpnService` can still return an empty
  list even when present in the built manifest. `QUERY_ALL_PACKAGES` is what actually makes
  other apps' VPN services visible.
- Do **not** name the tunnel by counting candidates. Brave ships a `VpnService`, so "exactly
  one is installed" is false on an ordinary phone. Intersect every implementer against the
  driver table instead: the one that is a known driver is the tunnel.
- And the closing irony: **the provider name is cosmetic.** No built-in driver carries exit
  ranges or DNS, so `generic` and `mullvad` behave identically. Put the effort into the
  relearn path, not into naming.

---

## 7. The guard fails closed, and has a door

**The decision.** Measure the daemon's own exit address; refuse clients when it is not what
was expected.

**Why.** From inside the phone, a kill-switch exclusion, a split-tunnel rule and a dead
tunnel are indistinguishable — traffic just leaves directly. Only the exit address tells the
truth, and only if something is watching it.

**The door.** `POST /config {"relearn": true}` clears the baseline, sets state `unknown`, and
probes once immediately instead of waiting for the ticker. Without it, every legitimate
network change is a lockout: the stored baseline belongs to the old network, so every client
comes back `denied: egress guard` and the next probe re-confirms the new address as *changed*
against a baseline that is now wrong.

**A manual door is not enough.** A Wi-Fi↔cellular switch moves the exit with no `VpnService`
event at all, so the app watches the default network (a key of interface name + transport
bits) and posts a relearn on change — plus once on the first observation after start, because
the baseline on disk was measured on whatever network the phone was on last time. Treat "the
tunnel went away" as a network change too, on the transition only, not on every poll.

---

## 8. Resolve names on the phone

**The decision.** Name resolution happens on the phone: per-client resolver → configured
resolver → system resolver, with every lookup logged.

**Why.** A forwarded connection carries the client's DNS server with it, which is one of the
tell-tales. Resolving on the phone removes it — and the log is the evidence that the client's
resolver never reached the wire.

**What it cost.** `net.Dialer` resolves through `/etc/resolv.conf`, which means nothing to an
app uid, so every dial failed while the resolver looked configured. The fix is to resolve
explicitly and pass the network's real DNS from `LinkProperties`. There is a second-order
trap: a VPN can block plain UDP/53 to third parties while its own resolver works, so a fixed
resolver has to fall back to the system resolver on error. The resolver captured at app start
also goes stale the moment the network changes — push DNS again on every default-network
change, or watch every upstream request die as `context canceled`.

---

## 9. Two binaries, because a tunnel cannot change a fingerprint

**The decision.** Ship a second static binary, `libnoragatetls.so`, next to the daemon.

**Why.** A CONNECT tunnel passes the TLS handshake through untouched, so the client's JA3
reaches the far end unchanged. That is measured, not assumed:

```
client's own stack      2b44d0971d74edd3a84ed9fc9b5f31b0   30 ciphers, 12 extensions
through the plain gate  2b44d0971d74edd3a84ed9fc9b5f31b0   identical
through coldspot-tls    420f8db7b6195fb4800027a493c7cfc3   16 ciphers, 17 extensions
```

To change it you have to terminate the client's TLS and re-originate with a ClientHello you
chose. That needs a locally generated CA that the client trusts, which is why it is a
separate opt-in binary rather than the default.

**What it cost.** Two of the nastiest bugs in the project: ALPN disagreement between the legs
(handshake fine, request sent, GOAWAY, dead silence) and a `bufio.Reader` eating the first
bytes of the ClientHello before the connection was handed to `tls.Server`.

---

## 10. What was deliberately not done

- **No transparent capture.** It needs root and a `VpnService` of our own, which would fight
  the user's real VPN for the only tun.
- **No provider API integration.** The gate does not log in to anything, does not hold
  credentials, and does not know what a subscription is. It rides whatever tunnel exists.
- **No telemetry, no phone-home, no analytics.** The daemon has one outbound dependency and
  it is the egress probe reading its own address back.
- **No app-store packaging.** `QUERY_ALL_PACKAGES` and a bundled native daemon are normal for
  a device tool and a problem for a store listing. This is a tool you build.
- **No claim about the carrier.** See [LIMITS.md](LIMITS.md).
