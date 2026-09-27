# Full-digest BLAKE3 Span statement

The new `span_statement_blake3` facade carries fourteen full 256-bit identities
in 525 M31 words: a distinct B3SP tag, explicit format version 1, and sixteen
little-endian 16-bit limbs per digest. Its native types cannot be assigned legacy
eight-word identities. `fromCanonicalWords` rejects unsupported versions, legacy
tags, noncanonical digest limbs, nonzero padding and invalid execution semantics.

Legacy and BLAKE3 formats now instantiate the same Span contract and semantic
implementation. Encoding, decoding, adjacent-child folding, root coverage and
padding have one implementation. The old facade still exposes the pinned 412-word
ABI and legacy VM-claim constructor. The new facade deliberately has no constructor
that treats old Poseidon VM-claim digests or scalar memory roots as BLAKE3 hashes.
This removes duplicate future fold logic and connects the previous digest codec
to actual statement serialization and validation.

Qualification:

```
python3 scripts/zig_serial_build.py --cwd . test-riscv-statement-codecs -Doptimize=ReleaseSafe --summary all
```

Passed, final build run about 4 seconds / 465 MB reported peak RSS. The focused
root has a ten-named-test minimum and includes three existing R-012 statement
checks, four BLAKE3 Span checks and three full-digest codec checks. The new tests
exercise distinct-child native folding and complete root coverage, high-bit
mutations at every state digest byte, all 224 digest-limb coordinates with invalid
M31-canonical values, reciprocal format rejection, and three-leaf padding.
This is native statement qualification, not a recursive proof benchmark or a
cryptographic proof of a distinct-child aggregate.

Remaining: migrate statement arithmetic constraints and verifier-owned input
schedules, BLAKE3 identity preimages/hash bindings, public-claim and memory-root
authorities, segment wrapper/capture geometry, artifact admission and authenticated
keys. Defaults remain unchanged. The active recursion goal is incomplete.

Files under `source/` snapshot this change; `qualification.log` retains the final
build result. SHA256SUMS covers the relative evidence paths.
