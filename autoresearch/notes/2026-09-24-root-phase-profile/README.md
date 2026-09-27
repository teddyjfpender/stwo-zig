# Root quotient batch-range dispatch

Same M5 Max canonical four-leaf/two-level native BLAKE3 tree, eight requested
workers, SMP allocator, ReleaseFast, authenticated ABI-24 Metal bundle from
`../2026-09-24-blake3-rotate7-limbs/core`. All leaf and aggregate proofs retain
70 queries and 26 PoW bits. This is a small six-cycle fixture, not an Ethereum
block throughput result or a peer-prover comparison.

## Diagnosis

Nested recorder plumbing now exposes streaming main and interaction Merkle work.
The baseline root spends about 1.94s on main commitment (0.97s Merkle), 1.86s on
interaction commitment (1.07s Merkle), and 2.43s on FRI quotient build/commit.
The two intermediate quotient GPU stages take about 74ms and 72ms; the root takes
2,359ms. These domains differ, so those times are not a like-for-like speed ratio.

The root has 17,885,298,688 source bytes, 1,163 columns, 1,339 views, 150 source
runs, 14 batches and 16,777,216 rows. Its source exceeds the 32-bit flat word
address space and correctly takes the segmented path. Each segment previously
read and rewrote every batch's numerator at every row, even for absent batches.

## Generic fix

For every nonempty source run, find its already validated minimum and maximum
batch. Rebase the dispatch-only view batch indices and bind the numerator buffer
at the matching batch offset. Dispatch only that contiguous covered range.
The original source-run views remain intact for the independent parity observer.
Empty runs still skip dispatch; holes inside a covered range retain the existing
zero-contribution behavior. Accumulation order, original source provenance,
64-bit source validation, finalization, shaders, AIR and proof parameters are unchanged.

No workload-specific route or threshold is added. All segmented raw quotient
users receive this optimization. Sparse holes within the min/max interval and
repeated evaluation at the lifted row count remain further opportunities.

## Qualification and measurement

`rebuilt.log`: seven canonical tree checks pass. All three aggregate artifacts
independently verify and retain sizes 845993, 849496 and 889364 bytes.
Root quotient GPU time is 467.054ms, wall time 488.698ms in this initial profile,
versus 2359.480ms/2380.993ms in `quotient.log`. This is about a fivefold stage gain,
not a fivefold whole-tree gain. Matched ABBA totals are recorded separately.

The first `candidate.log` reused the old binary and is **not candidate evidence**.
An Objective-C imported fragment edit did not invalidate the enclosing Zig test
cache. Updating the top-level runtime translation unit forced recompilation;
`rebuilt.log` confirms compilation and `candidate-binary.json` pins the new binary.
`verbose.log` records the cache investigation and is not timed benchmark evidence.
A general build-dependency fix remains open; no claim is made that the comment
change permanently resolves imported-fragment cache invalidation.

`measure.py` runs frozen control/candidate/candidate/control binaries, checks
canonical parameters, independent aggregate verification, artifact sizes, device
hash coverage and allocation bounds. `results.json` contains raw wall and phase
timings; `summary.json` contains medians. No CSP timing is updated by this experiment.

## ZisK relationship and next targets

This is a local memory-traffic fix discovered through profiling, not code ported
from ZisK. The matched scalar primitive comparison remains in
`../2026-09-24-zisk-compression-comparison/README.md`: local 47.040ns versus pinned
peer 59.365ns for identical raw compression functionality. It establishes neither
hash-proof nor whole-prover superiority. Peer hash-proof benchmarking is still open.

Removing this ~2s bottleneck cannot deliver 10x over a ~38s tree. The larger
remaining targets are proved hash/PCS geometry, next-level domain padding,
commitment input volume, and direct final-layout witness generation. The current
segmented path also still repeats lower-height source work at the full lifted
row count; bounded native-height partials are a candidate for a separate experiment.

## Matched results

Four frozen-binary runs, ABBA, two samples per arm:

| Metric | Control | Candidate |
|---|---:|---:|
| Complete tree median | 41.05422s | 39.04920s |
| Root quotient GPU median | 2359.774ms | 467.188ms |
| Routed peak | 26,459,992,736 B | 26,459,992,736 B |
| Physical peak | 39,162,027,888 B | 39,162,355,736 B |

Complete fixture improves 4.88%, roughly 2.005 seconds. All twelve aggregate
artifacts independently verify at q70/PoW26; all runs confirm 8/8 hash-device
coverage. Peak memory is effectively unchanged. Two samples per arm establish a
local observation, not a robust production latency distribution. This session's
control is slower than the previous ~38s checkpoint; do not subtract this gain
from an unmatched older run to claim an unmeasured absolute time.

Retained: generic covered-batch dispatch and nested streaming-commit profiling.
No new CSP or ZisK proving result, no 10x total speedup, no parameter relaxation.
