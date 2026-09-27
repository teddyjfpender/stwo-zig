---
title: Bounded BLAKE3 parent artifact codec and independent roundtrip qualified
author: Teddy Pender
created_utc: 2026-09-22T03:53:08Z
---

# Bounded native BLAKE3 parent artifact transport

A canonical external envelope now carries the parent key identifier, twenty
QM31 claims and the existing postcard proof body. The fixed 372-byte header
contains magic, envelope version, full 256-bit key identifier, canonical
little-endian claim words and exact u64 body length. The protocol remains
native-parent version 2; introducing this transport does not change its key
identity or Fiat-Shamir transcript.

Decode checks the verifier-owned key pin, header, canonical claims/cancellation
and exact size before allocating proof data. The existing allocation-free
postcard preflight checks every body sequence/configuration against geometry
reconstructed from the admitted verifier components. BLAKE3 hashes use raw
32-byte encoding; the existing Poseidon preflight entrypoint retains its
canonical-M31 encoding through a shared explicit-encoding helper. The existing
512 MiB proof limit applies, plus the fixed header.

Encode counts serialized bytes through a bounded sink before allocating the
output, writes the canonical envelope/body, and preflights its result. Decode
owns the resulting proof only after successful structural parsing and frees it
on subsequent validation failure. Cryptographic validity still requires the
independent verifier; decoding alone does not mint a verified capture.

Verifier component construction now has one stable heap owner shared by
preflight and verification. It owns definitions, relation plans, component
instances, table adapters and column logs; no duplicate composition-size or
mask-width formulas were introduced.

Real native-parent evidence:

- Envelope size: 111,428 bytes (111,056 proof-body bytes).
- Decode/re-encode is byte-identical.
- Truncated header/body, trailing bytes, wrong version/key, noncanonical claim,
  oversized body length, wrong PCS PoW and excessive commitment-count prefix
  all reject.
- Decoded owners are used for early-admission and compensated-claim failure
  tests, and for successful independent verification/capture. The proof is
  consumed on all verification paths.

The diagnostic key remains
`f76d51b30dce850ad74060c42808bed2f4dd5bee6cc5705673f00b4754d3c976`.
It is test evidence, not a production trust pin.

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-native-segment -Doptimize=ReleaseSafe --summary all
```

Terminal exit 0: 4/4 steps, 3/3 tests, 34 s / 2 GiB; compile 1 min / 5 GiB.
Formatting and git diff --check pass. No build remains live. No broad suite or
performance benchmark ran.

Remaining: standalone producer/API integration and persistent plans,
production-security-profile qualification, statement-independent keys, Metal,
binary aggregation and parent-of-parent qualification. Current proofs remain
q1/PoW0 child and q8/PoW0 parent; production defaults are unchanged.
