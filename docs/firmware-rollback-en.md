# Your signature check does not stop a firmware rollback

This is not an implementation bug. It is something a signature cannot do
in principle.

---

## The scenario

You built over-the-air updates. The image is signed, the device verifies
the signature before installing, the verification key sits in a secure
element. "Someone pushes foreign firmware" is closed.

Now the attacker forges nothing.

He takes your own firmware, version 1.2 — genuine, signed with your key,
with a matching image digest. The one you shipped six months ago and later
found a hole in. And installs it.

The signature is valid. The digest matches. The key is yours. Verification
passes.

The device rolls back to a vulnerable version, and no signature check
notices — because **there is nothing to notice**: everything is genuine.

## Why a signature is powerless here

A signature answers one question: **who produced this.**

It does not answer **when**, and it does not answer **whether this is
still current**. To the cryptography, a signed 1.2 image is exactly as
valid today as on release day. A signature has no notion of time, or of
what you have learned since.

The same gap is wider than firmware updates. Take any device that signs
its own data:

It signs a **measured value**. The signature proves the value came out of
that device. It does not prove the value corresponds to reality.
Compromise whatever is fed to the signing step and you get a
non-repudiable falsehood carrying a flawless signature.

This is not a theoretical hole. It is the most common architectural
mistake in measurement and sensing systems: **a signature is placed where
proof is required, and the problem is considered solved.**

## What actually stops a rollback

Not code. Code can be patched, bypassed, cut out. What is needed is
**state that does not wind backwards.**

The ATECC608B and similar secure elements carry monotonic counters. They
move only upward and only by one. Writing an arbitrary value is refused by
the part — once the configuration zone is locked, that path is closed
permanently. The state survives complete loss of power.

The acceptance policy then looks like this:

Every release carries a version number. The device requires that number to
**exceed the current counter value**, and advances the counter **before**
installing. Version 1.2 after 1.3 is refused not because the code decided
so, but because the counter is already past it.

We verified this on real silicon, frame by frame:

**Valid release** — signature accepted by the element, image digest
matched, counter advanced, installed.

**Foreign signing key** — rejected by the chip's own verdict. The version
was higher than current, but it never reached the counter.

**Genuine older firmware with a known hole** — signature **valid**, image
**matching**, and refused: this version is spent. Stopped by state in
silicon, not by code.

**One byte changed after signing** — signature valid, image digest
mismatch. Refused.

After four refusals the counter stayed where it was. No failed attempt
moved it — otherwise an attacker would exhaust the version space by
retrying.

## The second case: the device is in enemy hands

Signature verification does not help here either. A captured device holds
every verification key, all the code, every detection threshold and the
exchange format.

What can be done about it depends on **where the thing the device cannot
work without actually lives.**

Working constants can sit encrypted under a key that **exists nowhere**.
It is derived at every start from an exchange between the device's secure
element and the public half of the commissioning station. The station's
private key is not on the device and never was.

The distinction matters: **there is no check to cut out of the firmware —
there is a computation for which half is missing.** A foreign element
computes a different number; the constants stay noise. We tested this by
substituting another part: manifest valid, release key genuine, code
intact — nothing to decrypt with.

## This is becoming a procurement requirement, not a matter of taste

As long as a product stays inside the country, this can be left alone.

Entering NATO markets removes that option. **AQAP 2110** is the Alliance
standard for design, development and production of defence materiel. It
sits on top of ISO 9001 and adds what a commercial quality system leaves
out: configuration management under ACMP 2100, risk management,
traceability, government quality assurance. Among its requirements is the
explicit **integration of cybersecurity into software development**, and
cyber risk within supply-chain risk management.

Two things make this practical rather than paperwork.

First: when a contract names AQAP 2110, the requirement **flows down the
chain** — to subcontractors and component suppliers. It does not stop at
the prime.

Second: the standard covers precisely the categories where Ukrainian
export is concentrated right now — unmanned systems, sensors, defence
electronics, communications and cryptography.

At that stage, "how do you ensure firmware integrity and data
authenticity" is not asked out of curiosity. And "we verify a signature"
does not answer it, for the reasons above.

## Limits worth stating yourself

Binding to the element makes a captured unit inoperable, but it **does not
protect the firmware image from being read** — reading goes past the
secure element. That is closed separately, by flash encryption on the
microcontroller.

The counter lives in the chip, not in the device. Swapping in a clean
element gives zero. This is closed by the fact that a foreign element
cannot open the sealed block at all: substituting the part in order to
roll back means losing the ability to operate. The two mechanisms compose.

On parts where I/O protection was disabled permanently at provisioning,
the shared secret crosses the bus in the clear. A logic analyser will
capture it. This is closed by an I/O protection key — that is, by a
decision made **before** the zones are locked, not after.

Capturing the device **together with its station** is not closed by
anything at device level. Only revoking the station from the trusted list
works, and that is infrastructure.

## In short

A signature proves authorship. It proves neither freshness nor truth.

Rollback is stopped by irreversible state in silicon, not by code.

What makes a device useless to an adversary is not a check that can be cut
out, but a computation for which half is missing.

And what looks today like engineering diligence becomes a line in the
contract requirements the moment you go for an export market.

---

*Petro Sidliarchuk, InfraVeritas LLC. Hardware root of trust in embedded
systems. Test protocols and source: github.com/sidliarchukpetro*
