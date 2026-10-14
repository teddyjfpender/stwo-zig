# Candidate one-block line-tree Merkle profile

`blake2s_personalized_line_v2.zig` defines an experimental profile for **new
FRI line trees** under the reserved `S31NAT9F` selector. No verifier selects
this profile today. The four Gate source roots retain their production plain
BLAKE2s profile; a source opening cannot be silently reinterpreted as a line
opening.

The byte rules are fixed:

```text
leaf   = BLAKE2s-256(personal="S31P2LEF", data=canonical M31 row words in little-endian order)
parent = BLAKE2s-256(personal="S31P2PAR", data=left[32] || right[32])
```

The two eight-byte personalization values occupy BLAKE2s parameter words 6
and 7. They are **fixed role identifiers**, not truncated tree descriptors.
The parent message is 64 bytes and needs one BLAKE2s compression. The
prefixed two-block alternative puts a 64-byte node prefix before the same
64-byte child pair and needs two compressions.

Proof-owned leaf words pass through `hashCanonicalRow`, which rejects words
outside `[0, 2^31-2]`. `verifyPath` checks depth, index and sibling count
before hashing. Prover-side packed-row and four-lane methods take trusted
canonical data from the column builder; callers must validate extents.

The fixed personalization separates leaf and parent hashes. It does not bind
a tree's height, column roster, root epoch, fold height, or proof selector.
The selected verifier must derive a complete, versioned line-tree descriptor
from a sealed key and checked geometry, bind its digest in the initial
`StatementBinding`, and absorb each root at its named framed transcript event.
The current `line_profile_digest` is an external input, so this obligation is
open. Any security reduction must also state how BLAKE2s with distinct
personalization parameters is modeled; byte separation alone is not a
random-oracle theorem. Native proven security bits remain unset.

The focused tests compare leaf and parent outputs to independent Python
`hashlib.blake2s(..., person=...)` vectors, compare four-lane and scalar
parents, and reject malformed paths and noncanonical rows. A local ReleaseFast
microbenchmark on 500,000 parent hashes measured about 75–80 ms for this
profile after warmup, 72–73 ms for plain parents, and 115–119 ms for the
existing prefixed profile. The parent input varies on every iteration. These
figures estimate only hash cost on this machine; they are not whole-prover
measurements.
