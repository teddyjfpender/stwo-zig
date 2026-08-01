# RISC-V base-field lookup and resident Metal quotient campaign

## Result

This increment keeps RISC-V opcode lookup construction in M31 until the LogUp
challenge boundary and indexes resident Metal quotient descriptors by their
sample batch. The first change removes unnecessary four-limb QM31 work from two
dominant CPU stages. The second changes the resident quotient descriptor scan
from `rows * batches * views` to `rows * (views + batches)` without adding a
dispatch, readback, or large numerator slab.

The measured candidate is clean commit
`5d540e94174e4a678088a5ad793306280aa70c40`. Both reports are complete CSP
matrices: 16 supported cases, one verified warmup and ten verified measured
samples per case, secure protocol, exact output checking, retained-proof
verification, and the secp256k1 bad-signature rejection gate.

| Backend | Report | SHA-256 |
| --- | --- | --- |
| CPU/SIMD | `vectors/reports/riscv_csp_benchmark_report.pr-candidate.cpu.json` | `267ce4f945f55827e2b1d66937a23a4cfa475c510c8009cdeb6d68723d4aa968` |
| Metal | `vectors/reports/riscv_csp_benchmark_report.pr-candidate.metal.json` | `24db225b8c82545f261c3d3cdfa292621b3d7f1e55a99834d05aae117dc7a0c0` |

The M5 Max was on battery with low-power mode disabled. The harness therefore
classifies both reports `power-condition-non-publishable`. These are formal
local validation artifacts and PR evidence, not judge-grade AC rankings.

## Headline matrix

`proof_duration` is execution + witness construction + proof generation;
verification is measured separately.

| CSP workload | CPU/SIMD | Metal | Proof SHA-256 |
| --- | ---: | ---: | --- |
| SHA-256 / 2 KiB | 1.339631 s | 1.278602 s | `1a8937ae2df3ae0d9b1385e296e11d2a481e6bce42f8b3d20bb9f1c9c0803ebe` |
| Keccak-256 / 2 KiB | 1.338311 s | 1.220994 s | `5a92f064ae6b091700255500980a809f6010a4996498cca5f14b0a8284e54918` |
| Poseidon2-M31 / 16 | 1.262714 s | 1.128064 s | `25a99c401a50d0790a3ea95cc39be96582d93afdffafaef92bd2949360c28f26` |
| secp256k1 ECDSA | 6.188567 s | 5.730425 s | `c2e599195df359a172588654755d6b996e7bd287c2ea974faf25bbdeff27ed6f` |

Every CPU and Metal row produced the same canonical proof bytes for the same
statement. The four statement digests are also identical across backends.

## Increment-local comparison

The immediate clean predecessor is commit
`6167545407a3472838b8c2527031a6a6610b6824`. Its five-sample focused reports
are retained beside the candidate reports:

| Backend | Report | SHA-256 |
| --- | --- | --- |
| CPU/SIMD | `vectors/reports/riscv_csp_benchmark_report.step-baseline.cpu.json` | `c2eea539f76faedd0654feb341d23c32ab7d1f7e28b04c0a623cb5dd788345cc` |
| Metal | `vectors/reports/riscv_csp_benchmark_report.step-baseline.metal.json` | `3793176bec53f87fd1a2b0caed5c4436eecad07f75480d2fed484b0f81116b4d` |

The sample counts differ (five baseline, ten candidate), so the table is local
engineering evidence rather than a calibrated autoresearch promotion verdict.

| CSP workload | CPU before -> after | CPU gain | Metal before -> after | Metal gain |
| --- | ---: | ---: | ---: | ---: |
| SHA-256 / 2 KiB | 1.379933 -> 1.339631 s | 2.92% | 1.477990 -> 1.278602 s | 13.49% |
| Keccak-256 / 2 KiB | 1.349208 -> 1.338311 s | 0.81% | 1.423410 -> 1.220994 s | 14.22% |
| Poseidon2-M31 / 16 | 1.318684 -> 1.262714 s | 4.24% | 1.472310 -> 1.128064 s | 23.38% |
| secp256k1 ECDSA | 6.953761 -> 6.188567 s | 11.00% | 7.418564 -> 5.730425 s | 22.76% |

Against the older committed campaign reports, the current CPU times are
64.32-88.90% lower and Metal times are 17.08-40.92% lower. Those older reports
have a different evidence class/OS snapshot, so these percentages are context,
not paired claims.

## Algorithmic problem match: CPU lookup construction

Task and semantics: reconstruct exactly the same ordered opcode relation
entries, dense table multiplicities, LogUp columns/claims, composition values,
quotient, transcript, and proof bytes.

All committed opcode columns are M31. The relation-entry polynomial uses base
field operations until challenges are applied, so the M31 embedding into QM31
is closed: evaluating an entry in M31 and embedding its result is identical to
embedding each input first and evaluating in QM31. The chosen transfer is
algebraic subfield specialization, not a new semantic implementation.

`opcode_entries.Entries(S)` was already generic. A private, layout-identical
one-limb scalar adapter instantiates the same builder over M31. Source-table
indices use the existing `schema.indexBase`; interaction denominators use the
existing `RelationElements.combineBase`; numerators are promoted only where
extension-field challenges enter.

The work remains linear in opcode rows and entries, but maximum row scratch
falls from 67 four-limb values (1,072 bytes) to 67 one-limb values (268 bytes),
and tuple arithmetic is base-field rather than general extension-field work.
An all-17-family real-row and padding-row differential test compares metadata,
values, numerators, and relation pairs against the shipped QM31 path.

One profiled ECDSA sample measured:

- lookup source ingest: 1.331401 -> 0.785828 s (40.98%);
- opcode interaction: 0.972640 -> 0.526672 s (45.85%);
- witness + proving boundary: 6.953761 -> 5.011823 s (27.93%).

The complete ten-sample matrix above is the end-to-end verdict and is more
conservative than that diagnostic sample.

## Algorithmic and Metal design match: resident quotient

Measured ECDSA geometry is 2,097,152 rows, 15,990 views, 11 batches, 8,742
source columns, four authenticated resident sources, and 4,677,877,760 logical
source bytes. The previous row-parallel kernel scanned all 15,990 descriptors
once per batch and discarded descriptors whose batch did not match.

The chosen canonical form is a stable counting-bucket / CSR-style segmented
layout over the small static batch key. Host planning validates and source-maps
every descriptor as before, stably groups descriptors by batch, and uploads
`batch_count + 1` offsets. Stability preserves the original within-batch term
order and transcript coefficient assignment. The kernel then consumes only the
contiguous range for each batch.

- descriptor inspections: 368,868,065,280 -> 33,556,529,152 (11x fewer);
- active source reads and field terms: unchanged;
- new metadata: 48 bytes of offsets plus one grouped 639,600-byte descriptor
  buffer;
- dispatches, command buffers, completion waits, output shape, resident-source
  ownership, and CPU fallback boundary: unchanged;
- no 352 MiB all-batch numerator slab and no new readback.

The ECDSA resident quotient profile moved from 910.535 ms GPU / 951.215 ms wall
to 271.058 ms GPU / 310.906 ms wall (70.23% GPU reduction). One immediately
post-build run produced a reproducible three-sample 21.214 s outlier series;
the patch was reverted pending diagnosis. A later isolated profiled proof was
6.659 s, and a clean three-sample uninstrumented confirmation was
6.689-6.795 s before the patch was reapplied. The complete ten-sample matrix is
the retained verdict. This outlier is recorded because build/thermal/power
state remains a material source of error on battery.

## Validation

- RISC-V frontend ReleaseSafe inventory: pass, including the new all-family
  base-vs-secure differential oracle.
- `test-riscv-cpu-product -Doptimize=ReleaseFast -j1`: pass; 393-source closure.
- native Metal lifecycle and independent verifier: pass.
- `test-riscv-metal -Doptimize=ReleaseFast -j1`: pass; 451-source closure.
- CPU complete CSP matrix: 16/16 rows, 160/160 measured proofs verified, all
  outputs exact, negative ECDSA rejected.
- Metal complete CSP matrix: 16/16 rows, 160/160 measured proofs verified,
  resident polynomial dispatch required, all outputs exact, negative ECDSA
  rejected.
- The local pinned Sail executable was unavailable, so Sail cross-check tests
  reported their explicit non-publication skip; the already-pinned Lean and
  generated-artifact gates are unchanged.

## Next transfers

The next CPU candidates are a global segmented scan over the 94 interaction
shards and authenticated AOT specialization of the repeated composition DAGs.
The next Metal candidate is native-geometry preaggregation grouped by
`(batch, lifting map)` under a bounded wave arena; it requires telemetry for
`sum(view.length)` and group count before implementation. Neither is included
in this increment.
