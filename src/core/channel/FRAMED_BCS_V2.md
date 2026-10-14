# Candidate framed Gate transcript channel

`framed_bcs_v2.zig` is a byte-matched candidate for the reserved S31
`S31NAT9F` proof selector. No production verifier dispatches to it. The
selected raw Gate channel and proof bytes remain unchanged.

The channel begins with a required `StatementBinding` at event 0. Its 264-byte
payload is:

```text
ASCII("S31NAT9F") [8]
|| key digest [32]
|| circuit digest [32]
|| FRI configuration digest [32]
|| four source-tree descriptor digests [4 × 32], in fixed/main/interaction/composition order
|| FRI line-tree profile digest [32]
```

The caller must derive all eight digests from a sealed verification key and
checked geometry. This module does not validate those external derivations;
passing proof-controlled digests would break statement binding. The eventual
proof selector must freeze their schemas, Merkle profiles, and key custody.

Each hash uses `BLAKE2s-256("S31BCS2" || role:u8 || payload_len:le64 ||
event:le64 || payload)`. The channel owns a checked event cursor. One PoW
barrier consumes separate prefix and trial events, then absorbs a verified
nonce at the next event. A challenge draw stage consumes a checked stream of
60-byte raw-word frames. Its public result consists of two QM31 values as
eight canonical M31 limbs: a whole raw block is rejected if any word is at
least `2p`, then each accepted word is reduced by at most one subtraction of
`p=2^31-1`. Each residue has exactly two accepted preimages. At most eight
blocks are attempted per challenge block; exhaustion fails the channel.

The terminal query stage is available only after two accepted PoW barriers and
returns P08's `FramedQueryWordChannelV1`. Query indices use raw power-of-two
masking, with no M31 reduction. The framed channel does not itself enforce the
complete Gate root/challenge order. A selected verifier must own that schedule
and compare it to its key and wire revision.

`paired_gate_event_plan_v2.zig` is a candidate wrapper for that order. It
copies a nonempty, strictly descending fold-height roster into a fixed
64-entry array. Its methods accept only the next named operation from
statement through four source roots, both PoW barriers, paired FRI line roots
and terminal coefficients to raw queries. Wrong-stage method calls leave the
channel unchanged. Zig exposes the wrapper's mutable `channel`, `stage`,
`fold_heights` and `fold_index` fields, so callers can bypass those methods.
The copy protects against mutation of the input slice, not mutation of the
wrapper itself. A selected verifier must derive the roster from its sealed
key, keep this wrapper private, and use only its checked methods. This module
does not establish a type-enforced order for arbitrary external callers.

Each named challenge consumes one accepted eight-limb block:
lookup uses both QM31 values, while gamma, OOD seed, batch lambda and fold
alpha return only the first QM31 and discard the second. Rejected raw blocks
remain inside the same event. A future need for more accepted blocks changes
the transcript and requires a new version. The wrapper still relies on a
selected verifier to derive its statement and height roster from the sealed
key and to authenticate every proof field and Merkle opening.

The focused Zig tests pin digest, PoW and query vectors generated from S31's
Python `pcs_fri_framed_bcs_v2.py`, including the complete illustrative
four-root, two-track event plan for fold heights 17 and 16. A synthetic
rejection fixture pins counter consumption when the first block is invalid.

This is byte and stage-control evidence, not a BCS/ROM theorem, a Merkle hash
profile selection, or a native security-bit claim. The role-personalized
one-block Merkle option remains under evaluation separately.
