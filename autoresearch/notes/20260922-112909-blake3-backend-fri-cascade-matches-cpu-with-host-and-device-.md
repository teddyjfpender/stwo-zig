---
title: BLAKE3 backend FRI cascade matches CPU with host and device inverses
author: Teddy Pender
created_utc: 2026-09-22T11:29:09Z
---

# BLAKE3 backend FRI cascade integration — 2026-09-22

The actual Metal backend line-cascade API now admits the exact core BLAKE3
hasher/channel pair. It serializes an 11-word state, restores the full u64 draw
counter, and reuses the existing runtime cascade with optional inverse receipts.
BLAKE2s retains its 10-word state. Unsupported hash/channel combinations return
without admission. This is mechanical integration of the already qualified
algorithm, not a new algorithm or a measured speed improvement.

Removed the duplicated runtime invocation for receipt/no-receipt paths; all
wrappers now share the exported suite-specialized implementation.

Validation command:

```
python3 scripts/zig_serial_build.py --cwd src/backends/metal test-blake3-fri-cascade -Doptimize=ReleaseSafe --summary all
```

Terminal result: 3/3 build steps, 7/7 tests pass; test execution 776 ms, 68 MiB
maximum RSS; compile 6 s, 577 MiB. These are test-run measurements, not proof times.
The existing CPU-oracle helper now calls the backend API too: BLAKE2s and BLAKE3
at 1,024 line values (host-prepared inverses), and BLAKE3 at 8,192 values
(device-generated inverses). Every root, final transcript digest/counter and
terminal evaluation matches CPU. All owned backend trees/columns are destroyed
under the testing allocator. Runtime cold/warm tests retain single-command,
single-wait checks and verify the inverse-generation dispatch difference.

Archived initial failures: test attempted to write through a const evaluation
view (fixed using the existing owned-allocation convention); the expanded-domain
test inherited a 1,024-value dispatch constant (now restricted to its original
shape, with cold/warm dispatch difference checked at both sizes). The larger
shape requires additional parent work; this was not a root or arithmetic failure.

Limits: the resident circle-to-line transaction still has its BLAKE2s-only gate;
the combined quotient/FRI transaction also remains BLAKE2s-only. This gate tests
the backend cascade, not a complete STARK, CSP run, or recursive proof. No default
suite promotion, production recursion qualification, or speedup claim follows.
