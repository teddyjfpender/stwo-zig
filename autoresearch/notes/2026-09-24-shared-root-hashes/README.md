# Fixed-schedule shared Merkle roots — 2026-09-24

## Implementation

All queries into the same authenticated tree share its final root-node BLAKE3 hash.
The first query owns that hash. Every later query retains its authenticated query-bit
selection, proves equality of all 16 ordered root-input words to the owner's inputs,
and retains its own equality to the canonical root. Owner input producer counts add
one consumer per later query; its root output count equals the query count. Namespace
allocation still reserves the original per-query span, leaving unused hash IDs instead
of shifting later query schedules. This depends only on public shape/query ordinal,
not private query positions or digest equality.

The implementation uses existing typed hash, path-select and byte-route AIRs, with no
new cryptographic component or weaker parameters. Parent keys still bind the new fixed
columns through their preprocessed commitment; historical parent keys are not silently
reused. Default native path preparation and its preallocation sizing agree on removed
G/XOR rows. Single-query and zero-depth openings retain their existing behavior.

For borrowed roots the host recomputes the native hash to reject inconsistent witness
inputs early. That check is supplementary: the AIR's input equalities and exact lookup
counts are what bind the proof. It cannot substitute for any equality constraint.

## Focused checks

Fourteen ReleaseSafe PCS checks pass. The new test joins three private paths over both
branches, verifies computed roots, compares every fixed column against independently
constructed trusted rows, checks exact recursion-wire tuple closure, and rejects
mutations of all 16 borrowed input-equality rows and all eight canonical-root bindings.
It also rejects invalid query ordinals and missing authenticated directions. A final
check flips an authenticated selection bit and confirms the direct constraints reject it.

The first compile needed two test syntax fixes. The first closure fixture supplied
one query-bit producer use although eight word selections consume it; its signed
ledger caught the missing seven uses. The fixture was corrected to eight uses and
then passed. Failure logs are retained. This was a fixture bookkeeping error, not a
reason to remove query-bit checks.

## Matched result — retained for row and memory reduction

Both final qualifications pass: **14/14 focused checks and 7/7 canonical tree checks**.
All four timed fixtures also pass all seven checks and independently verify their
three aggregates (12 measured aggregate artifacts total), at q70/PoW26 throughout.

M5 Max, ReleaseFast, sequential frozen ABBA comparison:

| Run | Arm | Complete fixture seconds | Peak physical GB |
|---|---|---:|---:|
| 1 | control | 63.601 | 45.153 |
| 2 | candidate | 63.177 | 44.784 |
| 3 | candidate | 62.921 | 44.783 |
| 4 | control | 64.856 | 45.153 |

Observed fixture median improves **64.229 to 63.049 seconds (1.8%)**.
Both candidates are faster than both controls, but there are only two samples per
arm and the difference is small relative to control variation. This is a modest
observed improvement, not evidence of a large or broadly established speedup.
The change is retained because it reduces actual hash work and memory, qualifies
both recursion levels, and shows no regression in this comparison.

Maximum observed physical peak falls **45.153 to 44.784 GB** (369,361,184 bytes).
Routed peak falls **30,309,734,580 to 29,832,517,385 bytes** (477,217,195 bytes,
1.6%). Retained root rows fall 5,110,278,888 to 5,038,525,504 bytes. These modest
memory reductions do not establish lower total memory than the historical Poseidon
prover, nor a reduction for ordinary CSP execution proofs.

| Phase median | Control seconds | Candidate seconds |
|---|---:|---:|
| Left leaf pair + preparation | 7.219 | 6.878 |
| Left aggregate + checks | 12.916 | 13.019 |
| Right leaf pair + preparation | 7.396 | 7.159 |
| Right aggregate + checks | 13.242 | 13.149 |
| Root preparation | 8.661 | 8.292 |
| Root aggregate + checks | 14.399 | 13.871 |

Phases omit some fixture setup, negative checks and cleanup; aggregate phases include
key setup, proof, encoding and independent verification. They are not bare proof time.

| Aggregate artifact | Control bytes | Candidate bytes |
|---|---:|---:|
| Left pair | 918,746 | 909,260 |
| Right pair | 911,657 | 909,096 |
| Root | 904,156 | 909,371 |

The root grows 5,215 bytes even though the pair artifacts shrink. Next-level effects
must continue to be measured; first-level row savings alone are insufficient.
The six census receipts confirm 170,016 G rows removed per leaf verifier and 208,656
per aggregate verifier. Remaining repeated upper-node work is 0.71–0.73 million G
rows per leaf and approximately 0.91 million per aggregate in this fixture, before
any additional routing cost. The larger sharing opportunity remains unimplemented.

## Acceptance

Canonical tree verification and matched next-level cost passed as recorded above. The previous census's full 30–38% opportunity is not implemented:
this shares only the guaranteed-common final root-node hash, and adds equality
routes. The remaining census now subtracts the already-shared root G rows.
Full CSP recovery and the broader recursion goal remain open.

## Lookup accounting

For each ordered input word, the owner's path-select producer serves its original
hash input consumers plus `queries - 1` equality consumers. Each later path-select
produces one word for its own equality. The equality row consumes both its local
word and the owner word with identical byte coordinates. The shared hash output
produces `queries` copies per digest word, balanced by the retained per-query root
equalities. All counts and endpoints are fixed by the public query ordinal/shape;
no witness-selected multiplicity or routing endpoint is introduced.

Namespace ordinals are checked against the complete reserved group span. Sharing
requires nonzero depth, at least two queries, authenticated direction endpoints and
a canonical root source. Sizing rejects unrepresentable query counts before casting.
The old group API remains usable for independent standalone openings; the canonical
native STARK path builder uses sharing automatically wherever applicable.

Initial canonical qualification passes **7/7 checks**, including actual parent-of-parent
verification, fresh artifact decoding, rejected wrong keys, adjacency and ownership.
The final build also includes the small malformed-count guard and the strengthened
selection-bit test. Source snapshots and timing refer to that final build.

## Reproduction

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-recursive-fused-pcs-opening -Doptimize=ReleaseSafe --summary all
STWO_RISCV_PATH_SHARING_CENSUS=1 STWO_RISCV_PARENT_BENCH_ALLOCATOR=smp STWO_RISCV_PARENT_BENCH_WORKERS=8 python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal test-blake3-native-tree-aot -Dmetal-core-aot-bundle="$PWD/zig-out/share/stwo-zig/metal/core" -Doptimize=ReleaseFast --summary all
python3 autoresearch/notes/2026-09-24-shared-root-hashes/measure.py
```

The frozen measurement uses control/candidate/candidate/control order, the SMP
allocator and eight workers. Control is the preceding destination-order join
checkpoint. Both executables use the archived authenticated bundle in
`../2026-09-24-canonical-parent-pipeline/core`. The driver checks each arm's artifact
sizes, canonical parameters, independently verified aggregates, root coverage and
routed budget, and records executable SHA-256, wall time, RSS and physical peak.
It does not require old and new proofs to have identical bytes. The diagnostic census
is enabled for qualification, and disabled for timing. No sample is discarded.

This is a dirty-worktree checkpoint with changed-source snapshots and a patch, not a
complete clean-checkout source archive. Timings include setup, negative checks,
preparation, proof, encoding, independent verification and cleanup. They are not
bare root-proving latency or ordinary CSP benchmark results.
