# Witness integrity for measurement devices

A signature proves authorship. It does not prove truth.

This repository holds a working implementation of the alternative: a
device signs **the features a conclusion is computed from**, not the
conclusion itself, and the receiving side recomputes the verdict
independently. A disagreement between what the device claimed and what its
own signed numbers yield is itself a signal, and it denies trust.

The physics at the input is arbitrary. Canonicalisation, the consistency
check, the signature and the recomputation rule do not depend on what is
being measured.

---

## Why

A device that signs a fabricated or mistaken value produces a flawless
signature over it. And a signed conclusion — "target detected", "threshold
exceeded" — cannot be examined at all: the receiving side can accept or
discard it, but never establish what it was based on.

In a sensor network this matters more than jamming. A jammed node goes
silent, and that is visible. A node whose readings are substituted speaks,
and it is believed.

The problem is wider than an adversary. During our own trials an acoustic
detector confidently held a stable 84 Hz fundamental with harmonics and
reported a target. It was a power line a few hundred metres away. The
detector was not broken — it worked exactly as specified. The feature it
judged by simply belonged to something else in that location.

Full write-up: [English](docs/sensor-network-integrity-en.md) ·
[Українською](docs/sensor-network-integrity-ua.md)

---

## What is here

| File | What it does |
|---|---|
| `src/witness.py` | Canonical record form, consistency check, verdict rule |
| `src/sign.py` | Signing in a secure element (ATECC608B, slot 0) |
| `src/verify.py` | Signature verification and independent recomputation |

Roughly 900 lines. No detection logic: this is the trust layer, not a
sensor.

### The path

```
measurement → features → consistency check → signature in silicon → queue
                                                                      ↓
verdict ← recomputation ← registry ← signature ← receiving side
```

The consistency check comes **before** signing, not after. A record
claiming more confirmed frames than there were frames in total could not
have existed; it would carry a perfect signature and remain nonsense. The
check blocks the signature rather than accompanying it.

### Canonical form

97 bytes for a record with seven background tones. Fixed field order, all
values integer, no floating point — two implementations of one
canonicalisation drift apart, and then signatures stop matching for
reasons nobody can find.

```
0101236c9ec37928f6000000006a8c1847000001a0333f2d0f000001a0333f7b2f
00095e7000001770004f000000430043004300002a30004d04070000ea600000fa
00000109a0000128e00001482000015f900001731800000000000000000000
```

SHA-256 of this form is what the secure element signs.

---

## Running it

```
python3 src/witness.py          # canonical form and recomputed verdict
python3 src/sign.py             # signing on a live chip (requires ATECC608B)
python3 src/verify.py --selftest  # five scenarios, no chip required
```

The self-test covers: an honest record; numbers edited after signing; a
foreign signing key; a device claiming a target its own features do not
support; and an internally impossible record. Only the first is admitted.

`witness.py` and `verify.py` run anywhere. `sign.py` needs a provisioned
ATECC608B on I2C.

---

## What is proven, and on what

Signing, verification and rollback protection were exercised on real
silicon: two ATECC608B parts, configuration and data zones locked
irreversibly, keys generated in the die.

Test protocols recorded from actual output on the day of execution are
kept with the projects they came from. Highlights:

- shared secret computed independently by both sides, values matched;
  after the station's private key was removed from the host, the device
  still started and decrypted its constants
- monotonic counter moves only upward and only by one; writing an
  arbitrary value is refused by the chip; state survives complete loss of
  power
- a genuine, signed, intact older firmware version was refused as spent —
  stopped by state in silicon, not by code
- signature verdict rendered by the chip: valid signature yes; corrupted
  byte, different digest, foreign key — no

---

## Limits

Stated here rather than left to be found.

**Recomputation does not save you from a device that lies consistently.**
If whatever feeds the measurement input is compromised, the features will
be internally sound and the verdict will agree. That is closed by a second
channel of different physical nature, not by a signature.

**The verdict rule must be identical on both sides.** A version mismatch
looks exactly like a disagreement. The rule version is part of the record.

**The registry is a ceremony, not automation.** A public key included in
the record proves nothing — a forger signs with his own and encloses his
own. Its value lies in a responsible person having confirmed which key
belongs to which device. Automatic enrolment devalues the whole thing.

**Binding makes a captured device inoperable but does not protect the
firmware image from being read** — reading goes past the secure element.
That is closed separately, by flash encryption on the microcontroller.
See [firmware rollback](docs/firmware-rollback-en.md).

**On parts where I/O protection was disabled at provisioning**, the shared
secret crosses the bus in the clear. A logic analyser will capture it.
Closed by an I/O protection key — a decision made before the zones are
locked, not after.

---

## Also here

[Your signature check does not stop a firmware
rollback](docs/firmware-rollback-en.md) ·
[Українською](docs/firmware-rollback-ua.md)

On why signature verification does not prevent installing a genuine,
signed, older version with a known hole, and what does.

---

## Context

Built at InfraVeritas LLC, Ukraine, while working on hardware-backed
provenance for measurement devices. The same path previously ran on
electrical measurements — current and voltage signed in silicon, reaching
verification in a contract — and was then exercised on an acoustic sensor
node. The trust layer did not change; only the physics at the input did.

Petro Sidliarchuk · petro@infraveritas.pro

MIT
