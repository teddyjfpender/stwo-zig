---
title: BLAKE3 v7 segment qualified at 70 queries and 26 PoW bits
author: Teddy Pender
created_utc: 2026-09-22T10:07:48Z
---

# BLAKE3 v7 segment: canonical-parameter qualification

2026-09-22, local dirty worktree, CPU ReleaseSafe. A non-final, signer-containing
Ethereum segment proves under the canonical SECURE_PCS_CONFIG: 70 queries,
26 PoW bits, log blowup 1, final layer degree bound 0, fold step 1. It serializes
as v7, decodes under BLAKE3, and passes independent extended-proof verification,
full dynamic capture validation and sidecar mutation rejection. Artifact bytes:
3,524,992. This is a synthetic segmented signer guest, not the canonical CSP input.

A failing allocator confirms that the opposite suite's artifact version and a
changed hasher ID reject before allocation. Identity-mutation tests now receive
the selected configuration rather than assuming diagnostic parameters. Explicit
suite/config/fixture options replace positional booleans; common ELF mutation is
shared. The fast fixture test still validates native memory snapshot admission.

8/8 build steps and 2/2 tests pass. Fixture runtime 549 ms (7 s compile); canonical
full proof/artifact/capture gate 19 s (approximately 3 min compile). Full gate
MaxRSS approximately 1 GiB, compile 6 GiB. Gate duration includes proving, decoding,
independent verification and negative checks: it is not an isolated performance
benchmark and must not be compared to CSP's ~1-second proving measurements.

Command:
```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-ethereum-segment-artifact-fixture test-blake3-ethereum-segment-secure -Doptimize=ReleaseSafe --summary all
```

Production routing/defaults, Metal, larger program/corpus qualification, reusable
recursive keys, multi-level aggregation and replacement of Poseidon-owned segment
boundary identities remain unfinished. This gate qualifies the v7 STARK suite at
canonical parameters; it does not migrate SegmentV2/V3's legacy identity hashes.
See ../20260922-blake3-segment-boundary-audit.md.
