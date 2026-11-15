# Security policy

## Reporting

Open a [private security advisory](https://github.com/volkdude85/cold-spot/security/advisories/new),
or mail the address in the profile. Please do not open a public issue for a vulnerability.

This is one person's project, not a company. There is no SLA. What you can expect: an honest
reply, a reproduction attempt on real hardware, and if you are right, a fix and credit in the
changelog.

## What counts as a vulnerability here

Cold Spot is a proxy that runs on a phone and listens on its network. The interesting failures
are all about who can reach it and what it will do for them.

**In scope:**

- **Bypassing the allowlist or a client's `deny` flag.** Any way to get traffic proxied without
  being an allowed client.
- **Bypassing the egress guard** — getting traffic served while the exit is outside
  `expect_egress`, or while the guard is in a `leak` or `changed` state and `block_on_*` is armed.
- **Reaching the control API from off-device.** It is bound to `0.0.0.0` on purpose so a LAN
  panel can reach it, and it is ungated by design; that is a documented tradeoff, not a bug. A
  *remote code execution* or *file write* reachable through it would be.
- **Path traversal or arbitrary file read** in the panel's static file serving.
- **Request smuggling / response splitting** between the client leg and the upstream leg.
- **Memory exhaustion reachable by a client** — unbounded buffers, an unbounded number of
  concurrent connections or SOCKS associations.
- **The daemon escaping its sandbox** — writing outside its own app data or cache directories.
- **Anything that makes the guard report `ok` when traffic is not actually leaving through the
  tunnel.** A guard that lies is worse than no guard.

**Out of scope, and please read this before filing:**

- **Your carrier noticing.** That is the entire subject of the project. If your operator
  throttles, upsells or classifies the traffic, that is the problem being solved, not a bug —
  see [docs/LIMITS.md](docs/LIMITS.md) for exactly what is and is not provable from the device.
- **The TLS fingerprint gap.** A CONNECT tunnel passes the client's ClientHello through
  untouched. That is measured, written down, and closed only by the opt-in `coldspot-tls` binary.
- **Clients that ignore the proxy** using the stock tethering path instead. They were never
  covered.
- **The probe contacting a public IP-echo service.** Documented, minimised to a single `Host`
  header, and removable with `-egress-url` or `-egress-probe 0`.
- **The panel being reachable on the LAN with no password.** That is how you use it from another
  device. If you do not want that, bind the API to loopback.
- **Physical access to an unlocked phone.**

## Threat model, stated plainly

The thing this defends against is a network operator distinguishing tethered traffic from the
phone's own. It is **not** a defence against the operator, the app store, or the device
manufacturer — and it does not try to be. It does not hide what a client is doing from the phone,
from a VPN provider, or from the destination. It does not make you anonymous.

The daemon assumes the phone itself is trusted. If your device is compromised, so is this.

## Supported versions

The latest release only. There is no backport branch, and there will not be one: the daemon is
small enough that the fix is a new build.
