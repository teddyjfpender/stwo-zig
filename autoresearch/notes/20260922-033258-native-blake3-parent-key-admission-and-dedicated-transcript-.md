---
title: Native BLAKE3 parent key admission and dedicated transcript qualified
author: Teddy Pender
created_utc: 2026-09-22T03:32:58Z
---

# BLAKE3 native-parent key and transcript admission

The complete native parent now uses its own protocol domain and key identity,
instead of the generic compression fixture transcript. The verifier-safe
`blake3_native_parent_protocol` requires an independently supplied expected key
identity and checks it again before transcript absorption or root admission.
Constructing or hashing a key does not itself authorize it.

Canonical SHA-256 artifact serialization binds the BLAKE3 suite, version,
diagnostic profile and outer PCS configuration; child statement/authority and
PCS configuration; all five arithmetic graph identities; bounded transcript
plan; ordered AIR semantics, geometry and log sizes; selector parameters,
relation registry, lookup-table kinds/geometry; and full 256-bit preprocessing
root. Child lifting uses an explicit presence tag, distinguishing null from
zero. SHA-256 identifies the artifact; BLAKE3 remains the proof transcript and
commitment hash. The transcript absorbs profile/configuration and all 256 bits
of the admitted identity before commitments.

The native proof gate reconstructs trusted preprocessing, derives and pins the
key, then uses the same admission contract for proving and independent core
verification. It rejects altered version, outer query count, expected key pin,
graph identity, child lifting presence and high-bit root substitution. The
complete parent proof verifies and final transcripts agree.

Observed diagnostic key identity:
`490efcad578b85ad136f5b6ac6f3b31ba0c73711e191a6305b4673f6680dcf22`.
This identifies this test statement/configuration and is not a production pin.

The shared proof harness accepts a protocol argument; existing callers retain
their original fixture transcript. Validation commands:

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment test-blake3-combined-fri -Doptimize=ReleaseSafe --summary all
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment -Doptimize=ReleaseSafe --summary all
```

The initial batch passed combined-FRI (1 test, 32 s / 7 GiB) and failed native
compilation on an explicit usize-to-u32 serialization cast. After fixing that
cast, the native gate reached terminal exit 0: 4/4 steps and 3/3 tests, 34 s /
2 GiB, compile 1 min / 5 GiB. The unchanged combined-FRI gate was not repeated.
Formatting and git diff --check pass. No build remains live.

Only diagnostic q8/PoW0 outer admission is implemented. The child remains
q1/PoW0. Existing Poseidon keys/proof artifacts are untouched. A production
artifact owner/codec and verifier entrypoint, reviewed production profile,
statement-independent keys, Metal, binary aggregation and parent-of-parent
qualification remain outstanding. This is not a production migration or a
speed benchmark.
