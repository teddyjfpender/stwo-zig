# Overlapped Metal streaming leaves

## Problem and retained design

The prior bounded GPU route waits after every leaf dispatch and allocates a fresh
staging arena for every commitment. This experiment applies the bounded prefetch
and buffer reuse direction from the ZisK architecture investigation to the generic
streaming PCS path, with no CSP workload branches or security changes.

Two staging slots overlap CPU column copies with the previous GPU dispatch.
Commands run on the same ordered Metal queue; the CPU waits before overwriting
a slot and before copying final leaves. Deferred cleanup drains live commands
before returning their arena, including submission failure. Native finish consumes
the retained command owner on either success or failure.

The existing composition scratch pool is shared rather than duplicated. At most
two resident buffers can be active or idle in total. Leaf arenas have stable
64 MiB capacity. Only allocations of at most 128 MiB each remain cached, limiting
idle residency to 256 MiB; larger composition buffers are freed on release.
That cache bound does not bound the complete proof or live composition footprint.
Parent layers and Merkle ownership remain on the host.

`STWO_ZIG_SYNC_STREAM_LEAVES=1` is the same-binary synchronous/fresh-allocation
control. Default execution overlaps and pools. Both arms use two-slot geometry,
GPU leaves, GPU hash interactions and GPU hash composition. The prior
`STWO_ZIG_CPU_STREAM_LEAVES=1` diagnostic still selects host leaf hashing.
The comparison measures overlap plus pooling together, not their isolated effects.

The first cache policy retained very large idle composition buffers and was
rejected after footprint measurement. Its raw evidence and frozen binary are in
[rejected-large-cache](rejected-large-cache/README.md).

## Validation and reproduction

`python3 measure.py` uses the frozen candidate product and earlier canonical
commands for ECDSA precompile/32, SHA256/128, SHA256/2048 and Keccak/128.
It runs control/candidate/candidate/control, three samples per block, zero
warmups, 16 workers, 70 queries, 26 PoW bits, blowup 1, fold step 1 and last
layer degree 0. Every block must retain its earlier proof SHA256 and pass a fresh
artifact verification. Both device routes and overlap selection are asserted.
`python3 summarize.py` aggregates six samples per arm.

Complete time includes execution, witness, admission, proving, encoding and fresh
verification. The historical baseline uses execution+witness+proving; summary.json
reports that narrower mean separately. Process footprint is the maximum lifetime
physical footprint across blocks, not an allocation counter or instantaneous peak.

Focused tests compare every host/GPU Merkle layer across varied heights, chunk
boundaries and forced small tiles, with both overlap modes. They also exercise
pool reuse/capacity/eviction and command cleanup after rejected submission,
explicit wait, double wait and deferred draining.

## Remaining architectural gap

The G cohort in the SHA256/2048 device profile has 1,048,576 rows and 33 lookup
batches. Its authenticated AIR currently has 124 main columns, 16 fixed columns
and 132 base-field interaction columns (66 relation events, batch size two).
Main plus interaction alone is 1 GiB of field storage at that trace height,
before fixed columns and LDE expansion. This is arithmetic from current source
and recorded domain geometry, not a process-memory attribution.

The next substantial target is reducing the shared G representation and lookup
traffic, with independently checked constraints and canonical proof qualification.
A larger lookup batch must account for its increased constraint degree and
composition domain; fewer columns alone do not establish a win. Full original
CPU/Metal CSP recovery and native recursive-tree qualification remain open.

## Qualified matched results

| Workload | Complete median (s) | Main commitment (s) | Interaction commitment (s) | Candidate execution+witness+prove mean (s) |
| --- | ---: | ---: | ---: | ---: |
| ecdsa_secp256k1-32 | 0.762405 → 0.671348 | 0.104162 → 0.065837 | 0.118324 → 0.072207 | 0.519456 |
| sha256-128 | 1.704583 → 1.645509 | 0.127445 → 0.108931 | 0.142026 → 0.115526 | 1.190503 |
| sha256-2048 | 2.796937 → 2.671250 | 0.255456 → 0.215359 | 0.276369 → 0.228538 | 2.061876 |
| keccak-128 | 2.719645 → 2.622831 | 0.250242 → 0.211997 | 0.266608 → 0.219172 | 2.041129 |

All 48 timed proofs and 16 separate artifact verifications passed with unchanged
historical BLAKE3 proof hashes. Complete time improves by 11.9% for ECDSA and
3.5–4.5% for the larger measured cases. Peak physical footprints are effectively
unchanged at 1.74/4.53/8.04/7.79 GiB. This is a retained improvement over the
synchronous BLAKE3 path, not full recovery of the original Poseidon CSP basket.
No new CPU or recursive-parent timing is claimed.

The retained default product additionally passes all 16 positive CSP workloads,
with one proof and independent artifact verification per case and unchanged proof
hashes. These basket runs qualify correctness, not statistical timing. The separate
negative guest and CPU/recursive products were not rerun in this checkpoint.
