# Project standards

> "Code of conduct makes it sound like I'm requiring them to follow rules, but I'm not. I don't
> want anybody to have to follow rules. I'm just kind of telling them the rules that I use to
> build it."

That is the whole file, really. **Nothing here is a contract and nobody signs anything.** This is a
description of how the project is built and what to expect from it — not a set of obligations for
anyone who shows up.

## Who is behind this

I am a **technician, not a coder**. Trades and bench work — instruments, controls, the kind of
fault-finding where you either find the thing or the machine stays broken. More years with a meter
in my hand than in an IDE, and I came to software that way rather than the other way round.

What that means for a project like this is not typing speed. It is knowing what the machine is
actually doing, and refusing to accept a design that does not match it. When something here says
"the tethering service asks for an upstream that excludes VPNs", that came out of `dumpsys` on a
real phone, not out of a tutorial.

Most of this code was written **in conversation** — what some people call vibe coding. I describe
what the thing has to do and how it has to fail, an AI writes it, and then we find out who was
right by measuring. That works when the person driving it has a clear picture of the target and
refuses to let a confident answer stand in for a measurement, and it is why so much of this
repository is instrument output rather than prose.

## The standards I hold myself to

Written down properly in [docs/CODE-STANDARDS.md](docs/CODE-STANDARDS.md): no memory holes, no
undefined behaviour, no placeholders, no dependency that could be a hundred lines of standard
library, measure before asserting, and state what you could not test rather than inventing a
green. The reasoning behind all of it — and where it came from — is in that file.

## What you can expect here

- **An honest answer**, including "you are right, that is a bug", and including "I do not know".
- **A correction taken as a gift** rather than as an attack, and given the same way — with the
  evidence attached.
- **Directness about the work.** "This is wrong, here is why, here is the number that shows it" is
  the house style. It is about the artefact, not about you.
- **Disagreement is fine.** You can think this software is pointless, harmful, or badly designed
  and say so. Bring the argument and it gets answered on its merits.

## What I am not asking of you

- You do not have to adopt these standards to file a bug or ask a question.
- You do not have to be polite, tactful, or agreeable.
- You do not have to read four documents before opening an issue — though
  [docs/LIMITS.md](docs/LIMITS.md) will save us both time.

## The one thing that gets removed

Publishing someone's private information — their address, employer, real name, location, or an
account they have not made public. That is the single hard line, and it is the same line that
governs this repository's own scrubbing rules: no real addresses, no names, no credentials in the
code or the docs.

Alongside it, and for the same reason: no harassment, no bigotry about who somebody is, and no
following a person from thread to thread.

None of that is a rule I am imposing on how anyone lives. It is what this particular place is for.

## About the language

People swear here, me included. A strong word in a bug report is not going to be moderated. Being
unpleasant to a person is a different thing, and that is what the paragraph above is about.
