# Limits, stated rather than hidden

Everything here is something Cold Spot does **not** do, or does not prove. If a project
claims more than this list allows, it is overselling.

## It does not prove what your carrier concluded

This is the big one and it is not a technicality.

**What is established from the device** — provable with adb, on any phone:

- there is no `dun` APN in play (`isDunRequired:false`),
- carrier entitlement is never consulted when `net.tethering.noprovisioning` is true,
- the hop count is 64, not 63 or 127,
- there is one host on the phone's prefix, not two,
- name resolution happens on the phone.

**What is unmeasured** — what the carrier's classifier or billing pipeline did with a flow.
Classification happens on their side. No amount of reading the framework tells you the answer,
and a working build that "looks clean" is not evidence either.

The only falsifiable test is the meter on your own plan — see
[PORTING.md §1.3](PORTING.md).

## It does not hide a TLS fingerprint

A plain CONNECT tunnel passes the handshake through untouched, so the client's JA3 reaches the
far end unchanged. Measured: identical direct and through the gate.

The `coldspot-tls` binary closes this by terminating the client's TLS and re-originating with
a uTLS profile, and that requires installing its CA on the client. If you are not willing to
do that, the fingerprint gap is open and this project does not close it.

## It does not cover clients that cannot be configured

The gate is app-level: the client must be told to use it — proxy field, `ALL_PROXY`, or the
PAC file. Devices with no proxy support (many TVs, consoles, some IoT) cannot be pointed at
it. That needs either root on the phone or a router in front of them.

## It does not do transparent capture

No `iptables` redirect, no `VpnService` of its own. Transparent capture needs root, and a tun
of our own would fight the user's real VPN for the only tunnel slot on the device. The design
is deliberately the other way round: ride whatever tun exists.

## UDP is covered, transparent UDP is not

SOCKS5 `UDP ASSOCIATE` works and is tested. QUIC, games and UDP DNS through the gate need the
client to use SOCKS5 UDP; there is no transparent UDP interception without root.

## Its own outbound is the egress probe, and that is a choice you can remove

The daemon contacts one of three public IP-echo services (`ifconfig.me`, `api.ipify.org`,
`icanhazip.com`) every five minutes, over plain HTTP, to read back its own exit address. That is
the guard working — and it is also the only thing about this software an outside observer can
see without being a client of it.

The request is minimised to a single `Host:` header, but three things remain true unless you
change them:

- a periodic connection to a well-known IP-echo service is itself a pattern;
- plain HTTP means the request is readable in transit wherever the tunnel is not covering it;
- it goes to a third party who logs addresses.

`-egress-url` points it at your own endpoint. `-egress-probe 0` removes it, and removes the
guard with it — with nothing measuring the exit, the daemon cannot tell a live tunnel from a
dead one and will not refuse clients. There is no configuration that gives you a working guard
and no outbound at all; that trade is real and it is yours to make.

## It does not meter what it does not see

Per-client byte counters are the gate's own accounting. They are exact for traffic through the
proxy and blind to everything else on the phone. If a device on the hotspot ignores the proxy,
its bytes appear nowhere in `/state`.

## It is not a firewall

The allowlist and deny flags control who may use the proxy. They do not stop a client on the
hotspot from using the stock tethering path directly, because that path is not ours.

## It does not work on a phone that will not run unsigned-ish binaries

The daemon is a native executable inside the APK's `nativeLibraryDir`. That is an ordinary,
supported Android mechanism, but it does mean: no app store, and `QUERY_ALL_PACKAGES` in the
manifest. If your distribution channel forbids either, that is a real blocker and not
something to work around.

## It has been tested on one phone

One Android version, one carrier, one provider, in depth. The design is deliberately
carrier- and provider-agnostic, but "deliberately" is not "measured on your device". Treat
[PORTING.md](PORTING.md) as the list of what to check rather than as a compatibility list.

## And a note on what this is for

This is a tool for using a connection you pay for, on hardware you own, with the traffic
shaped so that it is honestly the phone's own traffic. It does not spoof anything: the phone
really is the one talking. If that distinction ever stops being true of the code, the code is
wrong.
