# Contributing

Thanks for looking. This is a small project with strong opinions, so here is what makes a patch
easy to accept.

## Before you write code

Read [docs/DESIGN.md](docs/DESIGN.md). It records every decision and **what each one cost**. Most
"why doesn't it just…" questions are answered there, and a change that re-pays a cost the design
deliberately avoided needs to argue that the new cost is lower.

Read [PROJECT-STANDARDS.md](PROJECT-STANDARDS.md) for what to expect — it is a description of
how the project is built, not a rulebook you have to sign.

Read [docs/CODE-STANDARDS.md](docs/CODE-STANDARDS.md) for what "good" means here. Short version:
no memory holes, no placeholders, no UB, measure before asserting.

## The four rules that actually matter

1. **If you fix a bug, add a row to [docs/BUGS.md](docs/BUGS.md)** — symptom, cause, fix, and the
   test that now holds it. A fix without a test will come back. That file is the institutional
   memory of this project.
2. **If you add a claim to a document, add the command that proves it.** A number without a
   reproduction is an opinion.
3. **If you cannot test something, say what you could not test.** "Parses and packages" is an
   honest result. A fabricated green is not.
4. **No credentials, personal addresses, or machine-specific paths in a diff.** `local.properties`
   is gitignored for a reason; so is anything that looks like someone's LAN.

## Building and testing

### The daemon

```bash
cd daemon
go vet ./...
go test ./...
go test -race ./...
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "-s -w" -o /tmp/libnoragated.so .
```

Run it on your desktop before you touch a phone — it is an ordinary Linux binary:

```bash
go build -o /tmp/coldspotd .
/tmp/coldspotd -socks 127.0.0.1:1080 -proxy 127.0.0.1:8080 -state 127.0.0.1:8081
curl -x http://127.0.0.1:8080 https://ifconfig.me
curl -s 127.0.0.1:8081/state
```

### The TLS leg

```bash
cd tls && go vet ./... && go test ./...
```

### The Android app

```bash
cd ../cold-spot-android
./scripts/build-daemon.sh ../cold-spot
./gradlew :app:assembleDebug
```

If the daemon binary is missing, the app builds and installs fine and then dies on start with
`ProcessBuilder: error=2`. That is the most common way to get a green build that does nothing.

### The dashboard

No build step. Open `index.html`, or serve it from the daemon. If you change the script, check it:

```bash
python3 - <<'PY'
import re; h=open('index.html').read()
open('/tmp/g.js','w').write(re.search(r'<script>(.*?)</script>', h, re.S).group(1))
PY
node --check /tmp/g.js
```

## Style

Match the surrounding code. `gofmt` for Go, 4 spaces for Java and Python, 2 for YAML/JSON.
No new dependencies without a reason in the PR — the daemon has **no dependency outside the Go
standard library** and the dashboard has **none at all**, and both of those are features.

## Testing on a device

Two rules, learned expensively:

- **Never make your primary workstation the tethering client.** USB tethering brings an interface
  up that NetworkManager will adopt as a default route; when tethering stops, that machine's
  network goes with it.
- **Turning the hotspot on drops Wi-Fi, and therefore wireless adb.** Have a cable, or a way back.

## What gets rejected

- A change that trades the guard's honesty for convenience.
- A dependency that could be a hundred lines of stdlib.
- "It works on my machine" with no command attached.
- Anything that puts a real address, a real name, or a credential in this repository.

## Commit messages

Say what changed and why, in a few lines. The changelog is generated from them by a human, so
write it for that human.
