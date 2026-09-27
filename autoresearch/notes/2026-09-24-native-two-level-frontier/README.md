# Native two-level BLAKE3 frontier — 2026-09-24

The shared frontier is now integrated into canonical native recursion. The matched
four-leaf tree median improves **61.641 to 46.661 seconds (24.3%, 1.32×)**,
with q70/PoW26 preserved at every level. Both first-level aggregate G domains halve;
the root domain remains unchanged. This is retained production work, not a projected gain.

## Implementation and proof obligations

For each authenticated tree with at least two queries and depth at least two, three
shared hashes replace the last two hashes of every query. Private Boolean activity
flags adopt computed branch hashes or opaque unqueried siblings. Each query proves
its branch active and all 16 ordered inputs equal to that branch's shared preimage.
Root bindings and query-bit authentication remain constrained. Fixed endpoints and
lookup weights depend on public shape and query ordinal, not private positions.
Existing typed AIRs are reused; parent keys authenticate the changed fixed columns.
No host-only digest deduplication or weaker proof parameters is used.

Native capture reconstructs lower paths, validates consistent shared inputs/root,
and retains opaque siblings for unqueried branches. These early host checks supplement
the proof constraints. Trace and FRI paths share the implementation. The authenticated
high bit receives nine extra producer uses (eight old selections become seventeen).
Namespace reservation, preallocation, live emission and independent trusted fixed
metadata all use the same geometry. Depth-one trees retain root sharing; standalone
and single-query paths retain their applicable existing behavior.

Hash witnesses write directly into final G/XOR columns and borrow the cached canonical
node plan. Trusted metadata is generated independently. The default owned/full-row
API remains available for focused proof fixtures. No new cryptographic roster component
or guest-specific shortcut is introduced.

## Qualification

Canonical ReleaseFast qualification passes **7/7**, including fresh artifact decoding
and independent verification of both aggregate levels, wrong-key/adjacency/ownership
checks and the 48 GiB routed budget. All four timed fixtures also pass; all twelve
measured aggregate artifacts independently verify. The root covers four segments and
six cycles. This is a deliberately tiny sequential tree.

Final-source focused ReleaseSafe qualification passes **15/15**. Checks cover the standalone frontier proof, invalid inactive
queried branches, private-choice fixed-column invariance, native capture with one/two
leaves and either/both branches, wrong-root rejection, and full-row versus direct-column
parity at nonzero offsets. The standalone fixture uses diagnostic q8/PoW0; canonical
integration and every measured tree use q70/PoW26. The final focused log records this final-source result.

## Matched measurements

M5 Max, ReleaseFast, SMP allocator, eight admitted CPU workers. Frozen ABBA executables,
shared authenticated AOT bundle, serial runs, no samples discarded.

| Run | Arm | Complete fixture seconds |
|---|---|---:|
| 1 | control | 60.997 |
| 2 | candidate | 46.728 |
| 3 | candidate | 46.593 |
| 4 | control | 62.284 |

Control is the previous shared-root checkpoint. Two samples per arm establish a local
result, not a broad workload distribution. Timings include setup, preparation, proofs,
encoding, independent verification, negative checks and cleanup; they are neither
bare root proof times nor CSP execution benchmark times.

| Phase median | Control seconds | Candidate seconds |
|---|---:|---:|
| Left leaf pair + preparation | 6.713 | 6.520 |
| Left aggregate + checks | 12.715 | 6.101 |
| Right leaf pair + preparation | 6.956 | 6.779 |
| Right aggregate + checks | 12.959 | 6.104 |
| Root preparation | 8.214 | 7.263 |
| Root aggregate + checks | 13.707 | 13.233 |

Phase timers omit some setup/check/cleanup work. Aggregate phases include more than proving.
Maximum observed physical footprint falls **44,783,559,712 to 44,450,931,576 bytes**
(333 MB, 0.74%). Routed peak in timed runs falls **29,832,517,385 to 29,486,122,073**;
profiled qualification uses 1,264 additional routed bytes. Retained root rows fall
5,038,525,504 to 4,940,200,960 bytes. This does not establish lower memory than Poseidon.

| Aggregate | Control G rows | Candidate G rows | Candidate padded G rows |
|---|---:|---:|---:|
| Left pair | 4,461,408 | 4,141,536 | 4,194,304 |
| Right pair | 4,487,000 | 4,167,128 | 4,194,304 |
| Root | 6,853,504 | 6,032,768 | 8,388,608 |

Both control pair domains were 8,388,608. The root also benefits from smaller first-level
proofs, but still requires the same padded domain. Its actual work is below the old
6,457,472-row projection, which held previous first-level artifact geometry fixed.

| Artifact | Control bytes | Candidate bytes |
|---|---:|---:|
| Left pair | 909,260 | 853,044 |
| Right pair | 909,096 | 850,623 |
| Root | 909,371 | 903,838 |

## Reproduction and evidence

```sh
python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_cpu test-recursive-fused-pcs-opening -Doptimize=ReleaseSafe --summary all
STWO_RISCV_PATH_SHARING_CENSUS=1 STWO_RISCV_RECURSIVE_PARENT_PROFILE=1 STWO_RISCV_PARENT_BENCH_ALLOCATOR=smp STWO_RISCV_PARENT_BENCH_WORKERS=8 python3 scripts/zig_serial_build.py --cwd src/integrations/riscv_metal test-blake3-native-tree-aot -Dmetal-core-aot-bundle="$PWD/zig-out/share/stwo-zig/metal/core" -Doptimize=ReleaseFast --summary all
python3 autoresearch/notes/2026-09-24-native-two-level-frontier/measure.py
```

The driver checks canonical parameters, artifact sizes per arm, verified nodes, root
coverage, worker admission and routed budget. Timed runs omit diagnostic profiling.
It pins executable hashes and uses the archived core bundle in the canonical-parent-pipeline
checkpoint. Proof bytes need not match between changed circuits. Raw logs, geometry
receipts, source snapshots, relative patch and checksums are local evidence; this dirty
worktree checkpoint is not a complete clean-checkout archive.

## Next bottleneck and limits

The root proof/check phase remains 13.23 seconds, with 6.03 million actual G rows padded
to 8.39 million. Additional sharing must account for routing/selection overhead and
next-level proof geometry. Simply extending a dense frontier by one level should not
be assumed to cross the next power-of-two threshold. Persistent bounded scheduling,
effective arithmetic fusion and final-layout emission remain relevant.

Full CPU/Metal CSP baseline recovery is still open. This recursion change does not
supersede historical CSP numbers, establish subsecond recursion or a 10× total gain,
or demonstrate superiority to ZisK. A parameter experiment remains separately reviewed.
