# Porting: your carrier, your VPN, your phone

Cold Spot was built against one phone, one carrier and one VPN. This file is the map for
everything that will differ when you build it against yours. Read the section that matches
your situation; the design itself does not change, only the three things it has to be told
about.

**Nothing in this project assumes a specific carrier or provider.** If you find a place where
it does, that is a bug and not a requirement.

---

## 0. First: which route are you actually building?

| route | client config | root | ROM build |
| --- | --- | --- | --- |
| app-level gate — **this project** | one proxy field per device | no | no |
| router in front (OpenWrt + WireGuard) | none | no | no |
| root module on the phone | none | yes | no |
| patched tethering module (ROM) | none | no | yes |

Cold Spot is the first one. If you have a rooted phone or you build your own ROM, the other
routes get you a version with **no client configuration at all** — see §4 and §5 — and this
project's daemon is still useful underneath them.

---

## 1. Your carrier is different

### 1.1 Check what the framework will actually do

Three properties decide whether the stock hotspot is even relevant to your problem. Read them
before assuming anything.

```bash
# Is carrier entitlement enforcement even in play?
adb shell getprop net.tethering.noprovisioning
#   true  -> the carrier's entitlement service is never consulted
#   (empty/false) -> it is consulted; a plan without hotspot will refuse

# Is there a separate DUN APN in play?
adb shell settings get global tether_dun_required
adb shell dumpsys telephony.registry | grep -i isDunRequired
#   false / isDunRequired:false -> no DUN APN, no separate data path
```

A `setprop` that fails with `Failed to set property` is usually reporting that the value is
already in place, not that you were denied. `getprop` immediately afterwards.

### 1.2 What "different carrier" does *not* change

The origination design is carrier-agnostic. Whatever your operator does, the phone still
opens its own connections with TTL 64, its own address and its own resolver. There is no
per-carrier configuration and there should not be.

What *does* vary:

- **CGNAT vs public addressing.** Many mobile carriers hand out a private address behind
  carrier-grade NAT (`100.64.0.0/10`, or a public-looking address that is really shared). The
  exit address the guard sees will therefore be neither the phone's interface address nor
  stable. Expect the guard's learned baseline to be a CGNAT egress; that is normal and it is
  why `block-on-change` exists.
- **IPv6-first.** A dual-stack carrier will answer an IPv6-capable endpoint first, so a probe
  that only speaks IPv4 can appear to fail or to return a different address than a browser
  shows. Take both a v4-only and a dual-stack endpoint (`ifconfig.me/ip` and `v4.ident.me`) or
  you will quote an address the user cannot match to anything.
- **DNS interception.** Some carriers transparently intercept UDP/53. The gate resolves on the
  phone, so this affects the phone rather than the client — but it means a "fixed" third-party
  resolver may silently be the carrier's resolver. Verify with a lookup log rather than
  assuming.

### 1.3 Settle the carrier question with your own plan's meter

This is the only honest test, and it costs a few megabytes.

1. Record the account's usage meters **before** — total data, and hotspot data if the portal
   shows a separate bucket.
2. Push a **known, small** amount through the hotspot with the gate on. Tens of megabytes.
3. Read the meters again.

- Total moved, hotspot bucket flat → your traffic was classified as device data.
- Hotspot bucket also moved → the classifier caught it, and now you know a signal survived.
  That is worth reporting as an issue, because from the device side all four signals are
  neutralised and something else is being read.

Run it deliberately small and say the number. A single usage dial is the classifier's weak
spot too: if the plan only meters one total, hotspot classification is invisible to you and
you cannot conclude anything either way.

---

## 2. Your VPN is different

### 2.1 Find out what your VPN actually is on the device

```bash
# what is installed that could hold a tun
adb shell pm list packages | grep -iE 'vpn|wireguard|tailscale|proton|mullvad|ivpn|nord|surfshark|express'
```

The reliable test is not the name, it is whether the package implements `VpnService`. If you
have adb and a shell:

```bash
adb shell dumpsys package <pkg> | grep -n 'android.net.VpnService'
```

A `VpnService` implementer is a candidate. Note that some non-VPN apps ship one — Brave
browser does, for its firewall feature — which is why the app in this project does not count
candidates but intersects them against the driver table.

### 2.2 Write a driver

A driver is a JSON file. Drop it in the daemon's drivers directory (`-vpns <dir>`), or rely on
a built-in.

```json
{
  "name": "myvpn",
  "title": "My VPN",
  "packages": ["com.example.myvpn"],
  "dns": "10.64.0.1",
  "expect_egress": [],
  "notes": "WireGuard; the app's tunnel carries anything the phone sends."
}
```

- **`name`** is what the API and panel call it; keep it lowercase and stable.
- **`packages`** is how the phone recognises it. This is the only field that must be right for
  auto-detection.
- **`dns`** is adopted when the driver is activated. Leave it empty to keep whatever is
  configured. Many providers publish their in-tunnel resolver; using it is usually correct
  because a provider can block plain UDP/53 to third parties.
- **`expect_egress`** is optional and usually should be empty. With no ranges the guard learns
  this tunnel's exit and fails closed if it moves, which is the right behaviour for a provider
  whose ranges you do not control.
- **`notes`** is for the next person, including you in six months.

Built-ins ship for Mullvad, IVPN, Proton, Windscribe, NordVPN, ExpressVPN, Surfshark,
Tailscale, the official WireGuard app, and a `generic` fallback. A file with the same `name`
as a built-in overrides it, which is how you pin exit ranges without forking anything.

### 2.3 Your VPN blocks the LAN — this one bites everybody

Several providers, Mullvad included, ship a **"local network sharing"** setting that is **off
by default**. It does not merely hide the phone. It makes the phone's own listening ports
unreachable from the LAN while the tunnel is up, with no error anywhere: `curl` exits 0 with
nothing, and the daemon is listening the entire time.

A hotspot client is another device on the phone's LAN by definition, so this silently removes
the entire use case. Check for the equivalent setting in your provider's app before you spend
an evening debugging the proxy:

- Mullvad (Android): Settings → VPN settings → Local network sharing → Enable.
- Others: "allow LAN", "local network", "bypass local addresses", or a split-tunnel rule
  that excludes private ranges.

Expect the tunnel to re-establish and the exit address to move when you change it. The guard
should follow on its own; if it does not, that is the relearn path failing, not the VPN.

### 2.4 Kill switch and split tunneling

A kill-switch exclusion, a split-tunnel rule and a dead tunnel all look identical from inside
the phone: traffic simply leaves direct. Cold Spot's answer is the egress guard, and it is
worth understanding that the guard does not know *why* the exit moved — only that it did.

- If you split-tunnel the gate's own package out of the VPN, the guard will correctly report
  a leak and refuse clients. That is not a bug.
- If you split-tunnel *browser* packages but not the gate, you will get a working gate and an
  unprotected browser, which is the opposite of what most people intend.

---

## 3. Your phone or ROM is different

### 3.1 Requirements

- Android 10+ (`minSdk 29`). The control API and the tun handling both rely on API 29
  behaviour.
- Any device that is not running a ROM with a modified tethering module will have the stock
  `NOT_VPN` upstream request. That is the condition the whole design works around, not a
  blocker.
- arm64. Cross-compile for `linux/arm64`; nothing here is architecture-specific except that
  the packaged binary has to match the device.

### 3.2 Confirm the framework behaves the way this document says

```bash
adb shell dumpsys connectivity | grep -A1 'RequestorPkg: com.android.networkstack.tethering'
adb shell dumpsys tethering | grep 'Current upstream'
```

On a non-rooted device the first should show a request with `NOT_VPN` in its capabilities.
The second, with the hotspot up, should name a physical interface (`rmnet*`/`wlan*`), never a
`tun*`.

### 3.3 The no-root lever ladder

In order, cheapest first. Each one is a real lever with a real limit.

1. **`device_config put connectivity <key> <value>`** — writable from a plain adb shell, no
   root. Confirm the channel with a throwaway key (write, read back, delete) before trusting
   it. Keys read by `TetheringConfiguration` on current builds include
   `override_tether_enable_bpf_offload`, `tether_enable_legacy_dhcp_server`,
   `tether_enable_wear_tethering`.
2. **`settings put global tether_force_usb_functions <int>`** — overrides the USB gadget
   function set. Gadget choice sits below the IP layer: it changes the host driver and framing,
   never what the carrier can observe.
3. **A gate daemon on the phone** — the only route to a VPN-covered hotspot without root, and
   what this project is.
4. **Patched module / ROM build** — the only route to no client configuration.

### 3.4 The no-root ceiling, measured

On a locked, verified-boot device:

| lever | result |
| --- | --- |
| `pm grant <pkg> android.permission.WRITE_SECURE_SETTINGS` | **works** — protection level includes `development` |
| `pm grant <pkg> android.permission.TETHER_PRIVILEGED` | **refused** — signature permission; no app can call `startTethering` |
| `cmd overlay list` / enabling an RRO from shell | **works** |
| replacing `Settings.apk` or an APEX file | **impossible** — `/system_ext` is a dm-verity block device and APEX signatures are enforced |

So a runtime resource overlay can change wording and colour of the stock tether screen, and
dev-permission grants let an app write secure settings — but neither adds behaviour, and the
tether toggle stays the system's.

---

## 4. The root route

On a rooted device the whole hotspot can ride the tun without a ROM build, by moving traffic
*underneath* the framework. Three things are required and missing any one makes it silently
useless — see §3 of [DESIGN.md](DESIGN.md).

Make the script idempotent and reversible (`apply` / `clean` / `status`) and re-assert on a
timer: a VPN reconnect creates a new tun and the rules do not follow.

`clean` must delete by the mark you added, not by recomputing the interface set. Enumerate
`pref 17000` and loop until `ip rule del` fails; deleting `from all iif <iface>` only undoes
the interfaces still present, so a downstream that went away between `apply` and `clean` keeps
its rule forever.

You cannot test a root module on an unrooted phone, and claiming otherwise is a fabricated
green. Pre-flight it in three cheap steps and label the result what it is — "parses and
packages", not "works": `sh -n` every script, build the zip, then exercise `apply`/`clean`/
`apply` in a privileged container with a dummy tun. Give the dummy tun a route in its own
table first (`ip route add default dev tun0 table 4242`), or the VPN-table lookup legitimately
finds nothing, no policy rule is created, and a test that only counts masquerade and TTL lines
passes while the path that matters never ran.

---

## 5. The ROM route

`patches/0001-tethering-vpn-upstream.patch` is against the GrapheneOS
`platform_packages_modules_Connectivity` tree, 35 lines:

- a `DeviceConfig` flag (`vpn_upstream`),
- `isUsableVpn()` = `TRANSPORT_VPN` + `INTERNET`,
- a search over the capability-cleared upstream map,
- an early return at the top of `getCurrentPreferredUpstream()`.

Generate yours with `git diff` against a pristine tree and prove it with
`git stash && git apply --check`. An unverified patch is a guess.

The device side of getting a patched module onto a phone that ships locked — dm-verity, APEX
signatures, unlock → key → sync → build → sign → flash → relock — is a project in itself and
is not included here.

---

## 6. Building the daemon

```bash
cd daemon

# on a desktop, for testing
go build -o coldspotd .

# for a phone
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o libnoragated.so .
```

### Flags

Run `coldspotd -h` for the authoritative list. These are the ones that matter:

```
-listen   127.0.0.1:1080   SOCKS5 listen address
-proxy    127.0.0.1:8080   HTTP proxy listen address
-state    127.0.0.1:8081   control API + panel
-config   <path>           config file (persisted settings live here)
-dns      1.1.1.1          resolver to use on the phone (empty = system)
-vpns     <dir>            directory of driver JSON files
-vpn      <name>           active driver, by name
-ui       <dir>            directory holding the web panel
-max-conns 256             concurrent connection cap
-block-on-leak             refuse clients when the exit leaves expect_egress
-v                         debug logging
-egress-url   <urls>       comma-separated URLs used to measure the exit address
-egress-probe <secs>       seconds between probes; 0 disables the probe entirely
-egress-ua    <ua>         User-Agent for the probe (empty = send none)
```

**`expect_egress` and `block_on_change` are not flags.** They are persisted settings, so they go
in the config file or through the API:

```bash
curl -X POST -H 'Content-Type: application/json' \
  -d '{"expect_egress":["203.0.113.0/24"],"block_on_change":true}' \
  http://127.0.0.1:8081/config
```

The TLS leg is a **separate binary** with its own flags (`coldspot-tls -h`), not a flag on this
one.

### The outbound surface

The probe is the only connection the daemon makes that is not a client's. Point it at your own
endpoint (`-egress-url http://your.host/ip`) and nothing it does leaves your infrastructure; set
`-egress-probe 0` and it makes no outbound connections at all, at the cost of the guard. The
default request carries a single `Host:` header — no User-Agent, no Accept-Encoding.

### Configuration

Everything the API sets persists to a JSON config beside the daemon and is reloaded at
startup, which logs the loaded values. That startup line is the receipt: without it a restart
quietly reverts the user's configuration.

### Ports

`:8080` HTTP proxy, `:1080` SOCKS5, `:8081` API/panel, `:8443` TLS proxy. All four are
configurable; if you change them, change them in the Android app too — it hardcodes the API
port when it talks to the daemon and serves the panel from it.

---

## 7. Verifying on your network

A listening socket proves nothing. Exit identity proves everything.

```bash
# the client's own egress
curl -s https://ifconfig.me

# through the gate
curl -s -x http://<phone>:8080 https://ifconfig.me
curl -s --socks5-hostname <phone>:1080 https://ifconfig.me
```

Two **different** public addresses prove the phone originated the flow. Then:

```bash
curl -s <phone>:8081/state | jq '.guard, .clients, .totals'
```

- `guard.state` should be `ok` with `egress == baseline`.
- `clients` should name the client by the address it actually got, with non-zero counters.

And the test that matters most, which a LAN test cannot substitute for: put the phone on
**cellular only**, turn the hotspot on, join from a **separate host**, and repeat. The two
answers must belong to different networks — one from the household connection, one from the
carrier.

Two traps in that run:

- **Never make your primary/workstation the tethering client.** Enabling USB tethering while
  the phone is plugged into it brings an interface up that NetworkManager will adopt as a
  default route and DNS source; when tethering stops, that machine's whole network goes with
  it. Use a spare box, and keep its wired interface as the default route
  (`ipv4.never-default yes` on the Wi-Fi connection).
- **Turning the hotspot on changes the phone's own connectivity.** It drops Wi-Fi and
  therefore any wireless adb link. Plan for it: have a cable, or a way to turn Wi-Fi back on
  that does not need you.
