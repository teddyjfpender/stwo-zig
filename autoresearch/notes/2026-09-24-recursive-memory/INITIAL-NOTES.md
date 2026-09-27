# Recursive memory scaling — 2026-09-24

Objective: complete accelerated Ethereum authentication plus recursive root at
16 transactions and larger batches, reducing peak memory without weakening
70-query/26-PoW security settings. CPU only, serialized builds/proofs.

Baseline evidence is retained in `../2026-09-24-ethereum-recursive-comparison`:
16 transactions reached a verified leaf but failed its recursive parent at the
48 GiB worker limit; process footprint reached 55.68 GiB. G-row padding grew
from 2^23 to 2^24 and accounted for 87.89% of retained-row growth.

## Changes under qualification

- The canonical G schedule supports a fused three-input addition for typed
  backends. Other authors retain their two-add implementation.
- Packed G uses two binary carry digits with a quadratic exclusion of carry 3.
  Every limb equality is below 3*2^16, below the M31 modulus.
- XOR table membership already bounds both inputs and output to bytes. Remove
  duplicate range requests for initial b/d and addition outputs consumed by XOR.
  Initial a/c/message words and non-byte-aligned rotated outputs retain checks.
- Geometry: 90 -> 82 main columns; 46 -> 30 arithmetic lookup events;
  authenticated G: 112 -> 80 interaction columns. Maximum direct degree stays 2.
- Consuming parent proving releases source rows after interaction generation,
  before interaction commitment and FRI. Borrowed/reusable proving stays available.
- Semantic digests change with the authenticated AIR; keys must be regenerated.
  Historical proofs remain tied to their historical verifier/key.
- Core barycentric opening contexts store domain points in M31 (8 bytes per
  point) and two alternating derivative constants, replacing 48 bytes per point.
  Scratch recomputes a cheap numerator instead of retaining a third QM31 array
  (32 rather than 48 scratch bytes per point). No transcript/proof change.
- Native and execution parent pipelines consume their one-shot source rows by
  default. Reusable borrowed worker entry points retain their existing contract.

`test.log` retains arithmetic/reference, lookup, mutation and committed-proof
qualification. Benchmark observations will be recorded once roots verify.

## Initial result, before compact opening storage

The exact original 16-transaction guest/input now produces an independently
verified recursive root in 87.479 s process wall. Peak process footprint is
47,515,363,472 bytes (44.25 GiB), versus 59,783,170,280 bytes (55.68 GiB) at the
original failed run: a 20.52% reduction despite completing the proof. Worker
allocation peak is 48,910,360,988 bytes, below the unchanged 48 GiB cap.

This initial observation combines the smaller G circuit and source-row lifetime
change; it does not isolate their individual performance contribution. Its exact
binary and changed sources are retained as `local-host-initial-compact` and
`initial-source/`. Further measurements include compact opening storage.

Qualification so far: all 224 focused hash tests, 101 opening/allocation/work-pool
checks, the source-row release test and two shared Rust parser tests passed.
The 32/64 fixtures extend only batch/input bounds; existing 1..16 input bytes and
oracles are retained. Larger batches use the expanded guest binary, explicitly
hashed in each run. All proof runs retain q70/PoW26 and 16 requested CPU workers.

## Scaling follow-up

32 transactions verified before the final partition work (102.690 s). The first
64-transaction preparation revealed 22,144,640 active G rows padded to 33,554,432,
then failed the existing log-24 fixed-projection limit. The large temporary
memory-custody allocation was also visible before that rejection.

The final implementation therefore also:

- partitions G into four authenticated components with independently sized
  domains before execution-parent key derivation; logical rows, wire identities
  and multiplicities are preserved. Every shard is at most log 24. The final
  shard receives the remaining rows and zero padding. Allocation failure leaves
  the original preparation intact, and repeated finalization is idempotent;
- reconstructs trusted memory-custody updates individually and retains compact
  fixed metadata, rather than retaining full zero-filled fixed witness rows for
  every update simultaneously;
- drops four bottom Merkle layers on large **host** PCS/FRI trees and rebuilds
  requested lower hashes from retained columns. This includes the streaming PCS
  adoption path. Roots, ordering, query values and proof format are unchanged;
  backend-specific device tree adoption retains its original storage contract.

A two-partition attempt at 64 transactions passed shape admission but reached
48 GiB during interaction commitment. This diagnostic is retained as
`local-batch-64-prove-partitioned.*`; it is not a verified result. The final
four-partition attempt retains the same cap. The earlier `compact-opening`
32-transaction attempt failed before execution because its guest ELF still
advertised a 4 KiB input window; `expanded-io` fixes the guest linker declaration.
No prover input-admission rule was bypassed.

Additional focused checks: exact compact/full Merkle proof equality (BLAKE3 and
BLAKE2s, mixed column heights, multiple pruned depths); G partition permutation,
padding, idempotence and allocation failures; full/compact fixed-row append
parity and malformed metadata rejection. Their logs are retained here.
