---
title: BLAKE3 combined quotient FRI matches CPU proofs and independent verification
author: Teddy Pender
created_utc: 2026-09-22T11:36:57Z
---

# BLAKE3 combined quotient/FRI transaction — 2026-09-22

The lazy FRI transaction now admits the exact BLAKE3 hasher/channel pair and
passes suite identity to the runtime. Compile-time suite selection determines
the 10-word BLAKE2s or 11-word BLAKE3 state at the typed runtime boundary. The
shared internal C binding accepts the suite-sized pointer. Full BLAKE3 counter
words are transferred and restored.

The quotient runtime admits family 3 locally (without widening the global family
predicate), validates canonical zero seeds/prefix and the initial error flag,
uses existing BLAKE3 leaf/parent pipelines, mixes the first root and draws the
circle-fold challenge with BLAKE3 framing, then passes the existing queued
transcript buffer to cascade_v2 with the family tag. Queue ordering and the prior
transaction scheduling remain unchanged. This is integration of existing
qualified arithmetic/hash algorithms, not a new algorithm or measured speedup.

The shared FRI test now has a lazy quotient variant for BLAKE3 and BLAKE2s. Its
source column is x cubed over 16,384 canonical circle evaluations, with the
correct sample at an extension-field circle point. CPU computeFriQuotients
provides independent quotient values; generic CPU FriProver commits those values,
while Metal FriProver.commitLazy computes quotients and FRI through the combined
transaction. Compare every root, intermediate inner column, complete proof and
transcript. Independent FRI verification passes on transcript-derived queries
against the CPU quotient values. Telemetry requires one FRI cascade epoch.
Parameters remain bounded FRI qualification: blowup log 1, terminal degree-bound
log 2, three queries, fold step 1. This is not a canonical CSP/STARK security gate.

Command:

```
python3 scripts/zig_serial_build.py --cwd src/backends/metal test-blake3-fri-cascade -Doptimize=ReleaseSafe --summary all
```

Terminal: 3/3 steps, 10/10 tests pass; execution 750 ms / 72 MiB maximum RSS;
compile 11 s / 850 MiB. These are test execution measurements, not proof timings.
Initial BLAKE3-only extension passed 9/9 before the BLAKE2s regression case was
added. No failed gate occurred in this integration.

Remaining: complete Metal BLAKE3 STARK/CSP qualification, captured work-receipt
qualification for this transaction, suite promotion, production recursion, and
remaining prover-owned Poseidon statement identities. No end-to-end speedup or
migration-completion claim follows from these tests.
