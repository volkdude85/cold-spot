# How we build things

This is the house standard, written down so a contributor knows what "good" means here before
they write a line. It is also, honestly, the standard this project did **not** get to apply in
its favourite language — §2 is where that is dealt with rather than glossed over.

---

## 1. The standard

**Language order, when the choice is ours: C++ over C over assembly at the edges.** Assembly
where the hot path actually is and only there — a hand-written kernel that cannot be beaten is
worth having; hand-written assembly everywhere is a maintenance bill with no return. Nothing
above C++ that allocates behind your back, and no framework between the code and the machine.

The shape of this is not arbitrary, and it is not ours originally. We call it the **jSat standard**,
and it came out of `@lauriewired`'s videos — the ones about memory, the stack, and why flight
software bans most of C++:

| video | what we took from it |
| --- | --- |
| [Mastering Memory: Allocation Techniques in C, C++, and ARM Assembly](https://youtu.be/HlUBE70h2C0) | where allocations actually come from, and why the fixed-size path is the one that holds |
| [Why Fighter Jets Ban 90% of C++ Features](https://youtu.be/Gv4sDL9Ljww) | exceptions, RTTI, the heap, dynamic dispatch and unbounded recursion all make the worst case unknowable — so they go |
| [the true reason C++ always wins](https://youtu.be/I7fEsbksKRE) | why the language sits where it does in the order above |
| [Your RAM Has a 60 Year Old Design Flaw. I Bypassed It.](https://youtu.be/KKbgulTp3FE) | the return/stack behaviour underneath every function call, which is the thing recursion spends |
| [What ACTUALLY happens during a Stack Overflow?](https://youtu.be/_6zAAhkU_Iw) | what the failure looks like when the bound was not known |
| [ARM Assembly: Lesson 1](https://youtu.be/kKtWsuuJEDs) · [Lesson 10 — Function Calls](https://youtu.be/pnnOL7kfkz0) · [Lesson 11 — Stack Operations](https://youtu.be/56VrSY-F7_o) | what the machine is doing while the language pretends it is not |

**On tail calls specifically**, because it is the usual objection to "no recursion": a tail call is
a jump, and where the compiler is obliged to make it one, recursion costs nothing. That obligation
is the whole argument — C and C++ compilers do it at `-O2` in practice, Go explicitly does not
guarantee it, and a recursive function that is *nearly* a tail call never gets it at all. So the
rule is not "never write recursion"; it is **do not depend on an optimisation you cannot prove
happened**. Write the loop, and read the assembly when it matters.

**No memory holes.** This is the rule everything else serves:

- No leaks. Ownership is expressed in the type system — RAII, no naked `new`/`delete`, no
  `malloc`/`free`, no `strtok`.
- No undefined behaviour, ever, including the comfortable kind. If it is UB it is a bug even
  when it happens to work.
- No recursion where an explicit stack belongs.
- Fixed arrays, not vectors of strings, when the size is knowable. A `std::string` where a
  `char[N]` fits is a heap allocation wearing a friendly name.
- No float arrays for weights. Quantised integers and explicit fixed-point are the default;
  floats are a decision you have to defend.

**It compiles clean or it does not ship.** `-Wall -Wextra -pedantic` with no suppressions. Warnings
you have decided to live with get fixed, not silenced.

**Thread-safe by construction.** Shared state is either owned by one goroutine/thread or guarded
explicitly; there is no "it's probably fine because it's fast".

**Architecture before code.** Decompose into the individual processes and write the design down
first. A file that grew is not a design.

**No placeholders.** No `TODO` that will never be done, no dead code kept "in case", no stubs
that return success. If it is not finished, say it is not finished — in the code and in the README.

**Measured, not compiled.** "It builds" is not a result. Neither is "it looks right". The
acceptance test is a number: allocations per operation, bytes moved, microseconds, a parity check
against a reference. Bit-exact comparison against a known-good implementation beats any amount of
reasoning about whether two code paths agree.

**No smoke tests.** A test that cannot fail is not a test. Run the real thing through the real
path, and when something cannot be tested on the target, label it "parses and packages" instead of
inventing a green.

**Measure the constraint before you change the design.** Three wrong hypotheses in a row is a
signal that nobody has instrumented the thing yet.

---

## 2. This project is Go and Java, and here is what that costs

The daemon is **Go** and the shell is **Java**, so the C++ rules above do not transfer literally —
Go has a garbage collector and an app framework owns the process. Pretending otherwise would be
the exact dishonesty §1 is against. What we hold instead:

| the rule | what it becomes here |
| --- | --- |
| no memory holes | no goroutine leaks, no unbounded buffers, no per-request allocation in a hot path where it can be avoided. Every listener has a bounded queue and an explicit shutdown path |
| no UB | Go removes most of it; what remains is races, and the answer is `-race` clean and state that is owned rather than shared |
| thread-safe by construction | one goroutine per connection; the daemon's state sits behind a single mutex with short critical sections, and nothing calls out while holding it |
| no placeholders | same rule, no exception |
| measured | every claim in [MEASUREMENTS.md](MEASUREMENTS.md) is a number or a command |
| architecture before code | [DESIGN.md](DESIGN.md) is a decision record, written while building, with the cost of each decision stated |

**Why Go at all**, given the preference above: the daemon has to run inside an APK with no
interpreter, no Termux and no root. A statically linked Go binary cross-compiles to `linux/arm64`
and runs in an app sandbox; a C++ daemon would need an entire stdlib and TLS stack cross-compiled
and shipped, for a proxy that spends its life waiting on sockets. Go is the right tool here even
though it is not the preferred one. That is a judgement about *this* job, not a change of doctrine.

**Why there is Python in the repo.** `phone/proxy.py` is the prototype — the reference
implementation, and the fast path for experiments where a Go rebuild is too slow to be useful. It
is not the delivery path and it is not held to the allocation rules; it is held to the same
*design* rules, which is the part that matters when you are reading it to understand the daemon.

**And assembly**: there is none in this project. A proxy is I/O-bound; there is no hot loop to
hand-write. Reaching for assembly here would be decoration.

---

## 3. Seams: bridge seamlessly

**Any two pieces that have to work together join at an explicit seam.** A seam is not a layer of
indirection added for its own sake — it is the place where the two sides are allowed to disagree,
made visible, and made testable on its own. Get the seams right and the pieces can be built in any
order, by anybody, and still fit.

That matters most when the thing is being built conversationally, piece by piece, with an AI doing
the typing. The failure mode there is not a piece that is wrong — it is two pieces that are each
internally fine and disagree at the join, which reads as a mysterious bug in whichever half you
happen to be looking at. A named seam turns that into a failing test that names the join.

**The seams in this project, and what each one is for:**

| seam | between | contract |
| --- | --- | --- |
| the driver | a VPN provider and the gate | a JSON record: package names, optional DNS, optional exit ranges. Adding a provider is a file, not a fork |
| the control API | the panel and the daemon | HTTP + JSON on `127.0.0.1:8081`, ungated on purpose, `OPTIONS` answered |
| the guard | what the network is doing and what the gate will allow | an exit address, a baseline, and three states: `ok` / `changed` / `leak` |
| the native daemon | the Android shell and the Go process | `libnoragated.so` in `nativeLibraryDir`, flags on the command line, log lines on stderr |
| the app's data directory | config that must survive a restart | one JSON file, written on change, reloaded at start, logged when loaded |

Rules that keep a seam a seam:

- **One seam per concern.** Two overlapping seams is how you get a bug that belongs to neither.
- **Write the contract down where the code is**, not in a document three directories away.
- **Test both sides of it.** A seam with a test on one side only is a place where the other side
  drifts.
- **The seam is invisible to the other side.** A provider should not know it is being described by
  a driver; a panel should not know whether the daemon is Go or C. If it can tell, the seam is in
  the wrong place.

> A seam is what makes a bridge look like a bridge rather than a pile of beams. The same is true one
> layer up: a driver is the same idea between a program and a provider.

## 4. Do not trust the weights

This is a standing instruction from the person who owns this project, and it is the single biggest
reason the code in here works:

> Do not rely on your training. Go and check what the current programming and AI methods actually
> are.

It is said often, and it is said for a specific reason. **This model is weak on Go and weak on SQL,
and the honest thing is to say so rather than let a confident-sounding recall paper over it.** Go's
error handling, its generics, its `net/http` corners and its scheduler are all places where an
internal prior is *plausible and wrong*. SQL likewise — dialect differences, window function
behaviour, locking semantics.

So the method is:

- **Read the current documentation instead of remembering it.** The language reference, the standard
  library source, the release notes. Not a summary of them.
- **Read the reference implementation before writing ours.** Upstream source, the merged pull
  request, the RFC. Where two implementations disagree, find out which one is authoritative and why.
- **Search the moment something feels like a dead end.** A hypothesis that failed twice is not a
  hypothesis to test a third time — it is a signal that the prior art has not been read yet.
- **Prefer what a search returns over what an internal prior says**, and especially about versions,
  defaults, and API shapes, which are exactly the things that go stale.
- **Then verify by running it.** Reading the docs and running the code are both required; either one
  alone produces a confident wrong answer.

[BUGS.md](BUGS.md) is partly a record of this working: the rows where the first answer was
wrong, the instrument that said so, and the test that now holds the correction. That file exists
because "I was sure" is not evidence.

## 5. What the release process holds

- **One commit per artifact that ships**, with the version in the build file matching the version
  `dumpsys` reports. An artifact that cannot be identified is an artifact you cannot debug.
- **The binary that ran is the binary in the repo.** Where that could not be established, it is
  written down as a defect, not quietly rebuilt and called equivalent.
- **Every measured claim names its command.** If a number is in a document, the way to reproduce
  it is in the document too.
- **The docs say what does not work.** [LIMITS.md](LIMITS.md) exists so nobody has to discover the
  gaps by trusting us.

---

## 6. What it was built with

Stated plainly, because "how was this made" is a fair question about published code and because
the answer is more useful than a list of logos.

**The model doing the work:** DeepSeek V4.1 Flash (`deepseek-v4.1-flash:1017`), running as an
agent with a shell, adb on a real device, and the ability to run what it wrote. It wrote most of
the Go and Java; every claim it made was checked by running the thing — that is what
[BUGS.md](BUGS.md) is, a record of the cases where the first answer was wrong and what the
instrument said instead.

**What that model is bad at**, stated here rather than discovered by a reader: **Go and SQL.**
Go's error handling, generics, `net/http` corners and scheduler behaviour are all places where its
recall is confident and unreliable; SQL dialects, window functions and locking the same. Which is
exactly why §4 exists and is not optional — the code is written by reading the current docs and
reference implementations, not by remembering them.

**Toolchain:**

| piece | what |
| --- | --- |
| OS | Arch Linux, x86_64 workstation; cross-compilation to `linux/arm64` |
| daemon | Go 1.22+, standard library only, `CGO_ENABLED=0` |
| TLS leg | Go + `github.com/refraction-networking/utls` for ClientHello control |
| Android | Java 17, AGP + Gradle, `compileSdk 36`, `minSdk 29` |
| proto | Python 3, standard library only |
| dashboard | plain HTML/CSS/JS on `<canvas>` — no framework, no build step |
| device work | `adb`, `dumpsys`, `uiautomator`, `logcat`, `netstat`, `ip` |
| verification | `curl` through the proxies, `go test`, `go vet`, `node --check`, `aapt2 dump badging` |

**Reference material that shaped the design:** the AOSP tethering module (`UpstreamNetworkMonitor`,
`TetheringConfiguration`) read from a device build; RFC 1928 (SOCKS5) and RFC 1929 (username/
password auth); Go's `net/http` and `crypto/tls`; the uTLS fingerprint profiles.

**What was NOT used, deliberately:** no cloud service, no telemetry SDK, no analytics, no crash
reporter, no framework. The daemon has no dependency outside the Go standard library, which is why
it can be a single static file on a phone.

---

## 7. For a contributor

1. Read [DESIGN.md](DESIGN.md) before proposing a change to the shape of anything. It records what
   each decision cost, so you can tell whether you are paying less.
2. If you fix a bug, add the row to [BUGS.md](BUGS.md) with the test that now holds it. A fix
   without one will come back.
3. If you add a claim to a document, add the command that proves it.
4. If you cannot test something on a device, say what you could not test. That sentence is worth
   more than a green tick.
5. If your change crosses a seam (§3), change the contract and both sides of it in the same
   commit. A seam updated on one side only is how two working halves stop fitting.
6. If you are an AI agent reading this: §4 is addressed to you first.
7. Match the surrounding code. This file describes intent, not a linter.
