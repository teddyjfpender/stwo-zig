# Compact trusted Merkle-path preprocessing — 2026-09-24

## Change

The previous checkpoint removed full-row placeholders from generated hash metadata.
Trusted path preprocessing still accumulated full G/XOR rows, although only fixed
tails survived parent assembly. The canonical column-emitting path now allocates
one exact compact destination for all trusted path metadata and generates it
independently from canonical frame/Merkle topology. It never copies trusted values
from the live witness. Frame/group consumers update the same XOR multiplicities,
and parent assembly compares every live fixed field against trusted preprocessing.

The shared borrowed destination validates either full rows or compact trusted
tails and rejects mixed representations. Live row-generation APIs reject compact
trusted destinations. Full-row preprocessing remains the differential oracle.
The compact allocation has a separate owner and failure cleanup; generated metadata
remains borrowed from the final-column owner. Parent metadata admission handles
both trusted representations through one checked implementation.

Canonical trusted path metadata drops from **1,281,835,520 to 170,544,640 bytes**,
removing **1,111,290,880 bytes** (1.035 GiB) of full-row placeholders. Combined
with the preceding generated-metadata checkpoint, the logical storage removed is
**2,239,724,288 bytes** (2.086 GiB). This sum is not a process peak reduction.
ArrayList spare capacity from the former trusted-row builder is additional and
is not counted in that logical-byte comparison. Trusted transcript preprocessing
still retains full rows; this checkpoint does not claim that all preprocessing is compact.

## Validation

`focused.log`: three focused ReleaseSafe tests pass across
`test-blake3-frame-witness` and `test-blake3-transcript-plan`. Expanded checks cover:

- Compact trusted Merkle groups versus independent full-row preprocessing, with
  authenticated directions and root-source variants, exact fixed fields and receipts.
- Invalid lengths, mixed representations, forbidden live emission into trusted
  metadata, and out-of-range slices.
- Every partial allocation in compact group preparation and ownership cleanup.
- Parent admission with full or compact trusted rows, mutation of every retained
  G/XOR field, and allocation failures without leaking partial builder storage.

The existing row/main-column, transcript identity and retry checks remain active.
The CPU integration's larger path test was adapted to compare its independent
full-row oracle with compact trusted metadata; that larger diagnostic suite was
not rerun for this checkpoint.

`parent.log`: authenticated-AOT canonical Metal parent **7/7 tests passed**.
The four timed processes also independently verify child and parent at **q70/PoW26**,
replay the transcript, rekey and reuse the fixed plan, and verify outputs after
worker destruction. Six graph builds / two retained plans for 1540 openings remain.
All five successful parent processes retain the same proof SHA-256:
`87eacb69ec7dcf9d5aad70f4f36ff5ac8839bf78366fb11e7ac20da38755ce7b`.
Parent/child artifacts remain 857,591 / 483,375 bytes.

## Matched results

M5 Max, ReleaseFast, same authenticated core bundle. Frozen preceding/candidate
binaries, serial control/candidate/candidate/control, two processes per arm.
The persistent **parent worker pool has two workers**, as explicitly configured
and asserted by `blake3_parent_profile_test_support.zig`. The 16-worker CSP product
setting must not be attributed to this parent fixture. The previous compact-hash
note was corrected, with its checksum updated; no historical measurements changed.

| Metric | Previous checkpoint | Compact trusted paths |
|---|---:|---:|
| Complete fixture median | 20.064524 s | 19.656456 s |
| Parent stage sum median | 7.306029 s | 7.316330 s |
| Peak RSS maximum | 20,884,324,352 B | 20,887,404,544 B |
| Peak physical footprint maximum | 27,759,259,984 B | 27,759,489,576 B |
| Tracked worker allocation peak | 11,993,422,982 B | 11,993,422,982 B |

Complete median is 2.03% lower in this small sample; parent stages and process
peaks are effectively unchanged. The reliable result is removal of redundant
preparation storage with unchanged proof identity. This is neither a substantial
proving speedup nor subsecond recursion. Complete fixture time includes child
proving, preparation, verification and teardown, not just recursive parent proving.
Ordinary CSP paths are unchanged and were not benchmarked again.

## Existing scheduling path and next evidence needed

Inspection confirms `blake3_parent_pipeline.zig` already overlaps one preparation
producer with one persistent proving worker, using a bounded owned handoff and
CPU/memory admission. Native-child and tree-pair adapters already use it.
The four-leaf tree pipeline qualification uses `PCS_CONFIG` from
`blake3_execution_parent_protocol.zig`: diagnostic **q8/PoW0**, two proving workers.
It is not evidence of canonical full-tree throughput.

The next scheduling work should qualify this existing pipeline at canonical
settings and measure appropriate worker counts, not introduce another scheduler.
Full canonical CSP baseline recovery, deeper PCS/DEEP fusion, canonical full-tree
qualification, remaining full-row preprocessing, and the separately reviewed
recursion parameter experiment remain open. No security parameters changed here.

## Reproduction

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-blake3-frame-witness test-blake3-transcript-plan -Doptimize=ReleaseSafe --summary all
STWO_RISCV_RECURSIVE_PARENT_PROFILE=1 STWO_RISCV_EXECUTION_PROFILE=1 python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal test-blake3-native-parent-aot -Dmetal-core-aot-bundle="$PWD/zig-out/share/stwo-zig/metal/core" -Doptimize=ReleaseFast --summary all
python3 autoresearch/notes/2026-09-24-compact-trusted-paths/measure-parent.py
```

`binary.json` pins both binaries. `control-source` snapshots the preceding
recursion directory, `candidate-source` holds changed files, and `changes.patch`
records the recursion delta. These are dirty-worktree source snapshots, not a
claim that HEAD alone reproduces the binaries. Raw logs, per-run data, summary,
measurement driver and authenticated core bundle are retained. `format-check.log`
is the successful empty `zig fmt --check` output. `SHA256SUMS` covers the evidence.
