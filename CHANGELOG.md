# Changelog

All notable changes to this project. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow the number reported by
`dumpsys package io.coldspot.gate` on an installed phone.

## [0.9] — 2026-11-14

The release that made the VPN leg measured instead of architectural, and closed three ways the
gate could silently stop working.

### Added

- **`POST /config {"vpn":"<driver>"}` and a driver table** (`GET /vpns`). A provider is a JSON
  record — package names, optional DNS, optional exit ranges — merged over built-ins for Mullvad,
  IVPN, Proton, Windscribe, NordVPN, ExpressVPN, Surfshark, Tailscale, the official WireGuard app,
  and a `generic` fallback. A file with the same name overrides a built-in.
- **`POST /config {"relearn": true}`** — clears the egress baseline, sets state `unknown`, and
  probes immediately. A fail-closed guard needs a door or every network change is a lockout.
- **The probe is configurable**: `-egress-url`, `-egress-probe <secs>` (0 disables it), and
  `-egress-ua`. See README, *What it sends out*.
- **`coldspot-tls`** — an opt-in TLS-terminating proxy with selectable uTLS ClientHello profiles,
  as a second binary in the same APK.

### Changed

- **The egress probe request carries a single `Host:` header.** Go's own
  `Go-http-client/1.1` default and the gzip offer are both suppressed; measured on the wire at a
  local echo endpoint before and after.
- **The app watches the default network**, not just the tunnel: a Wi-Fi↔cellular switch moves the
  exit with no `VpnService` event, and it now posts a relearn on the change — and once at startup,
  because the persisted baseline belongs to whatever network the phone was on last time.
- `versionName` is bumped on every build. It had stayed at `0.1-prototype` for five of them,
  which is why a device could not report which build it was running.

### Fixed

- The driver panel could sit on "any other VpnService" forever with a VPN connected:
  `getOwnerUid()` answers `INVALID_UID` for a non-owner app, and the empty answer was being cached
  as the fallback driver. Detection now intersects installed `VpnService` implementers against the
  driver table instead of counting them (Brave ships one too), and needs `QUERY_ALL_PACKAGES` to
  see them at all.
- Every client refused with `denied: egress guard` after a network change, permanently.

See [docs/BUGS.md](docs/BUGS.md) for the full table with the test that holds each one.

## [0.4] — 2026-11-14

### Added

- VPN drivers, `GET /vpns`, and the app-side watcher that names the tunnel.

## [0.3] — 2026-11-14

### Added

- `coldspot-tls`: TLS termination and ClientHello control, verified with a CA minted on the device.

### Fixed

- ALPN disagreement between the client leg and the upstream leg (handshake completed, request
  sent, `GOAWAY http2_handshake_failed`).
- Pipelined clients hung because `bufio.Reader` consumed part of the ClientHello before the
  connection was handed to `tls.Server`.

## [0.2] — 2026-11-14

### Added

- The daemon packaged as `libnoragated.so` inside an APK, started by a foreground service, with
  the panel served from `assets` over `127.0.0.1:8081`.

### Fixed

- `ProcessBuilder: error=2` — AGP maps native libraries out of the APK by default, so
  `nativeLibraryDir` was empty until `extractNativeLibs` and `useLegacyPackaging` were set.
- The service dying on launch: a socket probe ran inside `onStartCommand`
  (`NetworkOnMainThreadException`).

## [0.1] — 2026-11-14

Initial prototype: a single Python file under Termux — SOCKS5 and HTTP proxy, per-client caps,
resolve-on-the-phone, PAC, and a small panel. Still in the repo as `phone/proxy.py`, because it is
the readable reference implementation.
