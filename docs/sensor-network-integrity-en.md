# A sensor network whose readings cannot be checked

On a class of attack more expensive than jamming, and how it is closed at
device level.

---

## The setup

Several hundred acoustic nodes along a line. They detect targets, send
coordinates, and the picture is assembled in a situational awareness
system. An operator sees the situation; units act on it.

The adversary does not jam this network and does not try to break it.

He learns to **substitute its readings**. Not one node — dozens. The
message format is extracted from a captured device, the access credentials
with it, and from then on the system receives reports that look perfectly
normal.

Headquarters gets a picture that is not true. There is nothing to detect
this with: the sensor transmits a **conclusion**, not the evidence from
which a conclusion can be reconstructed.

A jammed node goes silent, and that is visible. A substituted node speaks,
and it is believed. The second case costs more.

## The problem is wider than the adversary

Even a fully sound, uncaptured node can transmit a falsehood.

A case from our own trials. An acoustic detector confidently held a stable
fundamental of 84 Hz with harmonics, frame after frame, and reported a
target. It was not a target: it was the hum of a power line a few hundred
metres away. Three measurement series in a row produced clean-looking
tables describing an interference source.

The detector was neither broken nor badly written. It worked exactly as
specified: look for a stable tone with harmonic structure, and it found
one. The feature it judged by simply belonged to something other than a
target in that location.

**No machine decision in a combat loop today comes with evidence from
which it can be reconstructed.** Not sensor detection, not target
classification, not an autonomous platform's decision about what
constitutes an object of attack. The system says "target", and one is left
taking that on trust — against the adversary and against one's own error
alike.

## Why a signature does not close this

The obvious first move is to sign the readings. This is done, it is
correct, and it does not close the problem.

**A signature proves authorship, not truth.** A device that signs a
fabricated or mistaken number produces a flawless signature over it. The
signature answers "who sent this"; the question is a different one: "is it
true, and how would anyone check."

And the other side: **a signed conclusion cannot be examined.** If the
message says "target detected" with a valid signature, the receiving side
can only accept or discard it wholesale. It cannot establish what the
conclusion was based on — that data was never sent.

## The approach: sign features, recompute the verdict

The node does not claim "target". It transmits **signed numbers from which
a conclusion is computed**, and the receiving side computes it again.

The canonical form of one witness record from a real run — 97 bytes:

```
0101236c9ec37928f6000000006a8c1847000001a0333f2d0f000001a0333f7b2f
00095e7000001770004f000000430043004300002a30004d04070000ea600000fa
00000109a0000128e00001482000015f900001731800000000000000000000
```

What is in there: device identifier, session number, observation window
bounds, the core fundamental and its spread across frames, how many frames
there were in total and how many were discarded as saturated, in how many
a harmonic series was found, how many fell inside the core, the longest
contiguous run, band level above background, spectral flatness, harmonic
count, the list of persistent tones at this position, climate.

No field that does not feed the verdict rule. Fixed order, all values
integer, no floating point — otherwise two sides derive different bytes
from the same data and the signature will not match.

The SHA-256 of this form is signed with a key inside a secure element that
never leaves the die.

**The receiving side does two independent things.** It verifies the
signature — establishing the numbers were not edited. And it **recomputes
the verdict from those same numbers** using the same rule.

Actual verification output:

```
element             01236c9ec37928f6ee
digest matches      yes   (numbers not edited after signing)
signature valid     yes
in registry         yes
key matches         yes
internally sound    yes

VERDICT (recomputed here): TARGET
  · core 614 Hz, 67 frames in core, 67 contiguous, 10.8 dB over background
  · tonal spectrum (flatness 0.077)

node claimed: TARGET
agrees — evidence and conclusion are consistent
admissible: YES
```

## What this gives in practice

**A node is caught making a false claim.** The same background tone the
detector once took for a target looks like this once signed:

```
VERDICT (recomputed here): NONE
  · band -3.2 dB over background (6 required)

node claimed: TARGET
DISAGREEMENT: node and recomputation reached different conclusions.
admissible: NO
```

The level is below background — the "target" was quieter than silence. The
node did not notice; the recomputation did. And this surfaces **not
through an operator listening in, but automatically**, from signed numbers.

A disagreement between the claim and the recomputation denies trust. A
valid signature under a false conclusion is worse than a forged record: it
means a device that looks sound is producing falsehoods, and the cause is
unknown — a different rule version, corrupted firmware, substituted logic.

**Internally impossible records are not signed at all.** If a record claims
more frames in the core than frames with a harmonic series, that pair of
numbers could not have existed:

```
blocked BEFORE signing: more frames in core than with a series
```

The check blocks the signature rather than accompanying it. Otherwise the
record would carry a perfect signature and remain nonsense.

**A device registry is mandatory.** The public key included in the record
itself proves nothing: a forger signs with his own and encloses his own.
The key is checked against a registry populated when the device was
physically in hand.

## Acoustics here is a test bed, not the subject

The path was exercised on an acoustic node: a rotating source with a
stable fundamental near 610 Hz, 20-second window, 79 frames.

But **the physics at the input is arbitrary.** Canonicalisation, the
consistency check, the signature and the recomputation rule do not depend
on it. The same path previously ran on electrical measurements — current
and voltage signed in silicon, reaching verification in a contract.

The practical conclusion: **the trust layer separates from the sensor.** It
does not depend on what is being measured, and it can be added to a system
already in the field without rebuilding its measurement side. What changes
is what gets transmitted: features instead of a conclusion.

This is not limited to sensors. Any machine decision in a combat loop —
target classification, an autonomous platform's selection of an object of
attack — has the same property: it either comes with evidence from which
it can be reconstructed, or it is taken on trust.

## A necessary condition: a device that does not work in foreign hands

A record signed with a key that can be extracted from a captured device is
worth nothing. So the trust layer rests on two things inside the element
itself.

**The key is born in silicon and never leaves the die.** Configuration and
data zones are locked irreversibly at provisioning.

**Working constants are encrypted under a key that exists nowhere.** It is
derived at every start from an exchange between the device's element and
the public half of the commissioning station. The station's private key is
not on the device and never was. There is no check to cut out of the
firmware — there is a computation for which half is missing. A foreign
element computes a different number; the constants stay noise.

Plus irreversible state: a monotonic counter in silicon that moves only
upward and survives loss of power. It closes a separate class of attack —
installing a genuine signed older version with a known hole — but that is
a separate discussion.

## Limits worth stating yourself

**The verdict rule must be identical on both sides.** A version mismatch
would look like a disagreement between node and recomputation. The rule
version is part of the record.

**Recomputation does not save you from a device that lies consistently.**
If whatever feeds the measurement input is compromised, the features will
be internally sound and the verdict will agree. That is closed not by a
signature but by a second channel of different physical nature — and that
is genuinely a separate problem.

**The registry is a ceremony, not automation.** Its value lies in a
responsible person having confirmed which key belongs to which device.
Automatic enrolment devalues the whole construction.

**Binding makes a captured unit inoperable but does not protect the
firmware image from being read** — reading goes past the secure element.
That is closed separately, by flash encryption on the microcontroller.

## In short

Substituted readings cost more than jammed ones: there is nothing to
detect the first with.

A signature proves authorship, not truth. A signed conclusion cannot be
examined.

A node should transmit features, not a verdict. The verdict is recomputed
independently, and a disagreement is itself a signal.

The trust layer does not depend on the physics at the input and can be
added to a working system without rebuilding its measurement side.

---

*Petro Sidliarchuk, InfraVeritas LLC. Hardware root of trust in embedded
systems. Test protocols recorded from actual output, and source:
github.com/sidliarchukpetro*
