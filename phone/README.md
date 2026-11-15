# The prototype (Python / Termux)

This is where the project started, kept because it is easier to read than the Go daemon and
easier to change while you are working out what a carrier or a VPN is doing.

`proxy.py` is a single-file SOCKS5 + HTTP proxy with the same design as the daemon:

- terminates the client's connection and opens a new one from the phone's stack,
- resolves names on the phone and logs every lookup,
- per-client caps and counters,
- serves a PAC file and a small panel,
- runs under Termux with no root.

It is ~970 lines of Python with no dependencies outside the standard library.

## Why it is still here

- **It is the reference.** When the Go daemon behaves oddly, the Python version is a second
  implementation of the same design and a place to read the logic without goroutines.
- **It is the fast path for experiments.** Changing a header or a resolver policy in Python
  and pointing a client at it takes seconds; the Go build has to cross-compile and reinstall.
- **It is a working implementation for a rooted or unrestricted device** where the APK route
  is not available.

## Running it

```bash
# on the phone, in Termux
pkg install python
python proxy.py --http :8080 --socks :1080 --state :8081
```

## Differences from the daemon

| | proxy.py | daemon |
| --- | --- | --- |
| runtime | Termux + Python | static binary inside an APK |
| needs a screen session to survive | yes | no (foreground service) |
| VPN driver detection | no — set the resolver by hand | yes, via the app's watcher |
| TLS fingerprint work | no | separate `coldspot-tls` binary |
| control API | basic | full, with the guard and relearn |

## Tests

`test_origin.py`, `test_udp.py`, `test_pipeline.py` and `ja3_probe.py` are client-side test
drivers. Point them at whatever address the phone has:

```bash
python test_udp.py            # SOCKS5 UDP ASSOCIATE round-trip
python test_pipeline.py       # request + ClientHello in one write
python ja3_probe.py <host>    # fingerprint the ClientHello you send
```

The addresses in those files are placeholders from the documentation ranges — set them to
your own before running.

## A warning about watchdogs

If you keep this running with a supervisor, **retire the supervisor when the APK takes over**.
A watchdog built to restart the prototype does not know it has been superseded: it restarts
the Python proxy, which binds the same ports and serves its own older panel. The API answers,
the UI renders, and every number on it describes code that no longer ships.
