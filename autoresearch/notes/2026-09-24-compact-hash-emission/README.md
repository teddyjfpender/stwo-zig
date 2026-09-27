# Compact metadata during native hash witness emission — 2026-09-24

## Problem and change

The native parent already emitted G/XOR main values into final physical columns,
but its metadata owner still allocated entire logical rows and zeroed their main
prefixes. This duplicated 112 unused M31 fields per G row. All column-emitting
adapters now retain only fixed tails: ordinary frames, draws, bounded retries,
queries, transcript sequences, Merkle groups and complete STARK paths. Full-row
witness APIs remain differential oracles and retain their previous behavior.

The canonical fixture emits 2,444,008 G rows and 698,288 XOR rows. Generated
metadata storage falls from **1,301,608,832 to 173,175,424 bytes**, removing
**1,128,433,408 bytes** (1.051 GiB) of redundant allocation and initialization.
This does **not** remove the separately generated trusted full-row preprocessing.

The old storage-mode boolean and borrowed ArrayList overlays were removed.
An optional typed compact-metadata view now expresses the borrowed representation;
full G/XOR row slices are empty in that mode. Independent cursors preserve exact
emission counts. XOR multiplicity updates address the same fixed field in either
representation. Transcript identities serialize identical fixed fields. Parent
assembly checks exact owner slices and every generated metadata field against
independently constructed preprocessing before adopting main columns.

## Validation

Twelve unique focused ReleaseSafe tests pass across `test-blake3-hash`,
`test-blake3-frame-witness`, `test-blake3-transcript-plan`, `test-blake3-draw`,
`test-blake3-bounded-draw`, and `test-blake3-query-batch` in the CPU integration.
They cover full-row/main-column/interaction parity, cached Merkle groups, nonzero
column offsets and untouched padding, native rejection retries, private counters,
transcript role/capacity identity, malformed destinations and allocation failure.
The transcript-plan test now also mutates every G/XOR compact fixed field and
checks failed admission leaves the builder unchanged, including allocation failures.

The first compile exposed an inferred const empty slice; the next batch exposed
an old test assertion counting the now-empty full-row slice. Both were corrected.
`focused.log` and `focused-batch.log` retain those development failures;
`transcript-final.log` is the successful corrected transcript gate. The other five
gates passed in `focused-batch.log`. `format-check.log` is an empty successful
`zig fmt --check` over every changed Zig file.

`parent.log`: canonical authenticated-AOT Metal native parent qualification,
**7/7 tests passed**, q70/PoW26 for child and parent. The four matched measurement
processes also independently verify the child and parent, replay the transcript,
rekey a worker, reuse its fixed plan, and check outputs outlive that worker.
Each process retains six hash graph builds for 1540 openings and two retained plans.

Parent proof SHA-256 remains
`87eacb69ec7dcf9d5aad70f4f36ff5ac8839bf78366fb11e7ac20da38755ce7b`.
Parent/child proof sizes remain 857,591 / 483,375 bytes. AIRs, commitments,
transcript framing, canonical parameters, kernels and proof codecs are unchanged.

## Matched measurement

M5 Max, ReleaseFast, canonical fixture, two persistent parent workers. Separate frozen control and
candidate binaries with the same authenticated core bundle. Ordered serial
control/candidate/candidate/control; two observations per arm, compilation excluded.
The earlier version of this note incorrectly said 16 parent workers; that number
belongs to the CSP product measurements. The fixture explicitly configures and
asserts two parent workers in `blake3_parent_profile_test_support.zig`. This
documentation correction changes no measurement or executable.

Both arms use the preceding GPU interaction and bounded/mixed sampled-value paths.
The control is the **final** qualified binary from the previous host-barycentric
checkpoint, not its earlier sampler-only benchmark binary.

| Metric | Control | Compact emission |
|---|---:|---:|
| Complete fixture wall median | 20.182176 s | 19.836585 s |
| Recorded parent stage sum median | 7.328762 s | 7.270330 s |
| Peak physical footprint (maximum) | 27,759,276,320 B | 27,759,243,528 B |
| Peak RSS (maximum) | 20,885,241,856 B | 20,885,438,464 B |
| Tracked allocation peak | 11,993,422,982 B | 11,993,422,982 B |

Observed complete median is 1.71% lower, but this small four-process experiment
is not evidence of a large or stable speedup. The fixture includes child proving,
preparation, verification and teardown; it is not production recursive-root latency.
**Process peaks are unchanged**: removing temporary preparation storage does not
remove the larger later proving peak. The reliable result is elimination of the
redundant generated-metadata bytes while preserving proof identity and verification.

No CSP timings were rerun or relabeled: this change affects recursive witness
preparation. The complete original Poseidon CSP basket remains the acceptance
baseline; full CPU/Metal recovery and cross-prover superiority are not established.

## Reproduction and evidence

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-hash test-blake3-frame-witness test-blake3-transcript-plan test-blake3-draw test-blake3-bounded-draw test-blake3-query-batch -Doptimize=ReleaseSafe --summary all
STWO_RISCV_RECURSIVE_PARENT_PROFILE=1 STWO_RISCV_EXECUTION_PROFILE=1 python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal test-blake3-native-parent-aot -Dmetal-core-aot-bundle="$PWD/zig-out/share/stwo-zig/metal/core" -Doptimize=ReleaseFast --summary all
python3 autoresearch/notes/2026-09-24-compact-hash-emission/measure-parent.py
```

`binary.json` pins the frozen executables. `control-source` snapshots the preceding
recursion directory; `candidate-source` records changed production/test sources.
`changes.patch` records that recursion delta. These are local dirty-worktree
snapshots, not a claim that the repository HEAD alone reproduces the binaries.
`core` holds the authenticated bundle. Raw logs, per-run metrics and summarized
results are retained alongside the driver; `SHA256SUMS` covers the evidence.

## Remaining work

Compact the independently generated trusted preprocessing as well, and continue
removing intermediate witness materialization. Persistent preparation/proving
overlap and bounded scheduling, deeper PCS/DEEP fusion, full recursive-tree
qualification, and the separately reviewed parameter experiment remain open.
No change to canonical security parameters is part of this checkpoint.
