# Bugs found, and the test that now holds each one

This is the fastest way to understand the internals of this project: every row is a real
failure that cost real time, with the cause and the thing that now catches it. If you are
picking this up cold, read this before the source.

## The daemon and the proxy legs

| symptom | cause | fix | held by |
| --- | --- | --- | --- |
| Every dial failed while the resolver looked configured | `net.Dialer` resolves hostnames via `/etc/resolv.conf`, which means nothing to an app uid | resolve explicitly; pass the network's real DNS from `LinkProperties` | state shows the real DNS, SOCKS returns the phone's egress |
| Three junk bytes glued to the front of every UDP datagram | `parseSocksAddr` returns an offset relative to the ATYP byte; the caller sliced the original buffer with it | slice `buf[3+off:]` | `TestUDPSliceOffset` — asserts on the slice arithmetic, not on a live echo |
| Egress probe: "all probes failed" on the phone | HTTPS probe from a pure-Go binary with no system CA bundle | probe over plain HTTP — it only reads back our own address | guard reaches `ok` with a real IP |
| A fixed resolver stopped working behind a VPN | the VPN blocked plain UDP/53 to third parties while its own resolver worked | fall back to the system resolver on error | local run resolves via the VPN's DNS |
| Upstream requests died as `context canceled` after a network change | the resolver captured at app start belongs to the old network | push DNS again on every default-network change | requests survive a Wi-Fi→cellular switch |
| TLS gate: handshake OK, request sent, no response | uTLS returns its *own* `ConnectionState`, so the ALPN assertion read `""` and HTTP/1.1 was served to an h2 upstream — SETTINGS frame, then `GOAWAY http2_handshake_failed` | read `*utls.UConn.ConnectionState()` and serve the negotiated protocol | `example.com` → 200, HTTP/2 |
| TLS gate: pipelined clients hung | `bufio.Reader` consumed part of the ClientHello and the raw conn was then handed to `tls.Server` | `prefixConn` replays the buffered bytes | `test_pipeline.py`: request + handshake in one write |
| A stale listener answered just as convincingly as the new build | an older prototype process still held the port | kill every prior instance and require a result that only the new build could produce (a freshly minted CA, a new log line, a version string) | version/CA check in the verification script |

## The guard

| symptom | cause | fix | held by |
| --- | --- | --- | --- |
| Every client refused with `denied: egress guard`, permanently | the pinned baseline belonged to a previous network; the probe only ran on a timer and nothing re-learned on a network change, so the next probe re-confirmed the new address as *changed* | `POST /config {"relearn":true}` clears the baseline, sets `unknown`, probes immediately; the app posts it on every default-network change and once at startup | guard reaches `ok` after a Wi-Fi→cellular switch with no manual call |
| The panel showed "any other VpnService" while the VPN was connected | `getOwnerUid()` answers `INVALID_UID` for a non-owner app, the watcher cached that empty answer as the fallback driver, and the VPN network never changed again so the guess was never revisited | never post a guess; leave the configured driver alone and log once | `vpn seam: tunnel up, provider unnamed` appears once, the driver is unchanged |
| Driver auto-detection found nothing at all | a `<queries><intent>` declaration for `android.net.VpnService` returned an empty list even though it was in the built manifest | `QUERY_ALL_PACKAGES`, plus intersection against the driver table instead of counting candidates (Brave declares a VpnService too) | `vpn seam: candidates=[…] drivers=[mullvad]` |
| The gate was unreachable from the LAN while the VPN was up, with no error | the provider's "local network sharing" was off, which blocks LAN traffic into the phone | enable it in the provider app | `curl <phone>:8081/egress` returns 200 with the tunnel up |
| `dumpsys package` named a build four versions old | `versionName` was never bumped; five APKs shipped as `0.1-prototype` | bump it every release | `versionName` matches the artifact |

## The Android shell

| symptom | cause | fix | held by |
| --- | --- | --- | --- |
| Service died on launch, nothing in the log | `NetworkOnMainThreadException` — a socket probe ran inside `onStartCommand` | start path moved to a worker thread | app launches and logs `gate started` |
| `ProcessBuilder: error=2, No such file or directory` | AGP packages native libs unmapped by default, so `nativeLibraryDir` was empty | `android:extractNativeLibs="true"` plus `packaging { jniLibs { useLegacyPackaging = true } }` | `ls lib/` in the app data dir shows the binaries |
| `am startservice -a …TLS_ON` refused from adb | the service is `exported="false"` — correct hardening, not a bug | trigger the action from inside the app | documented; adb cannot drive it by design |
| The panel looked dead while `curl` worked perfectly | a JSON POST preflights, and `OPTIONS` was not answered | answer `OPTIONS` with 204 + CORS headers | panel buttons work |

## Cross-cutting lessons

- **Token parity is not a correctness gate.** A small numerical shift moves no greedy argmax.
  If you need proof of equivalence, compare the numbers, not the next token.
- **Measure before you theorise.** Every row above was diagnosed by an instrument — a log
  line, a counter, a byte count — and the two rows that took longest were the two where the
  first hypothesis was tested by reading code instead.
- **A watchdog can outlive its purpose.** A supervisor built to keep a prototype alive will
  happily restart it after the packaged app supersedes it, bind the same ports, and serve its
  own older UI. The state endpoint answers, the panel renders, and every number on it
  describes code that no longer ships. Retire it when the app takes over.
