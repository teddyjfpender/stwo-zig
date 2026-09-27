# Shared final-layout emission for execution-leaf pairs

Execution-leaf pairing now uses the reserved G/XOR columns qualified in
`../2026-09-24-shared-leaf-reservations/`. This is the default owned and borrowed
pair path, including the existing Ethereum specialization; single-leaf preparation
keeps its ordinary owned path. No AIR, protocol, shader or security parameters change.

Both children are admitted before either interaction is consumed. Each leaf is
proved and independently verified, then its authenticated parent plan is prepared.
Verified captures stay at stable stack addresses until emission completes. Consumed
execution owners are released after their respective plans are constructed. Custody
conversions own their edits, roots and witness rows and survive execution-owner
release; verifier admission remains borrowed for the whole operation.

Both native layouts and custody hash counts determine one shared allocation.
Sizing counts are not admission: span binding, independently derived custody fixed
rows, namespace checks, transactional append and final complete-reservation checks
remain mandatory. Each child emits directly into its logical partition and appends
custody G/XOR rows into the reserved suffix. Final aggregation transfers that backing
without copying hash main columns. Other cohorts retain the existing checked join.

Failure cleanup destroys plans before their captures and partitions before shared
backing. Aggregate preparation consumes both distinct partitions on success/error.
A failed second child still releases the first child and both custody conversions.

## Qualification and measurements

`tree.log`: all seven canonical Metal tree checks pass. The fixture includes actual
execution, adjacent segment admission, memory writes, two aggregate levels, owner
alias/admission rejection and bounded helper-pool failure/reuse. Three independently
verified artifacts retain sizes 845993/849496/889364 bytes, at 70 queries/26 PoW bits.
The routed peak remains 26,459,992,736 bytes in this qualification run.

`binaries.json` pins frozen control/candidate binaries. `measure.py` runs ABBA with
eight workers, SMP allocator, ReleaseFast, the same authenticated ABI-24 Metal bundle,
and checks each independently verified artifact and hash-device coverage. A build
lock serializes all timing against compilation. Local two-sample medians are not
production latency distributions or Ethereum block throughput.

CPU aggregation qualification and paired timing results are recorded separately.
The prior storage checkpoint already covers reserved suffix bounds, unchanged sibling
values, failed append cleanup and exact pointer retention. No new CSP timing or
peer-prover comparison is claimed by this step. The broader persistent scheduling,
fusion and reviewed parameter experiment remain open; 10x is unproven.

## Timing qualification limitation: low battery

The first complete ABBA sequence produced 37.037s control, 46.566s candidate,
52.620s candidate, and 54.654s control. Every run independently verified all three
aggregate artifacts. The control itself drifted sharply; these samples do not
establish an end-to-end improvement or regression attributable to this change.
`summary.json` retains the raw medians, not an accepted performance conclusion.

A read-only power check after this sequence reported Battery Power, 3% charge,
roughly seven minutes remaining. macOS reported no recorded thermal/performance
warning. This observation does not establish when the power state changed or prove
the cause of the drift, but makes additional timing unsuitable for acceptance.
`power-state.txt` records the observation. The reverse-order repeat was stopped
while waiting for the build lock, before it launched any benchmark. Its script is
retained for a powered follow-up; no repeat samples are claimed.

Implementation qualification and performance acceptance are separate here. Shared
emission is implemented and the canonical proof gate passes; its speed benefit
remains unqualified pending stable powered comparison. The original 10x objective
remains unproven.

## CPU qualification

`cpu-aggregation.log`: `test-riscv-blake3-aggregation -Doptimize=ReleaseFast`
passes. Existing diagnostic q8/PoW0 checks cover Ethereum signer/Keccak segments
with full memory custody and released witnesses/worker, the actual four-leaf tree,
adjacent aggregate and parent-of-parent, and persistent-worker overlap/ownership.
These CPU diagnostics do not replace canonical security measurements; canonical
q70/PoW26 evidence is the Metal tree gate and twelve timed aggregate verifications.
No new tests were added for these existing integration obligations.

The reverse-order script now checks external power before the sequence and before
and after every measured run. It records those power observations with accepted
samples and refuses battery-powered timing. Syntax was checked without running
another benchmark. All task-owned jobs have completed or, for the queued repeat,
been explicitly terminated before execution.

## Powered follow-up

After the user connected external power, the frozen binaries completed the
reverse-order candidate/control/control/candidate sequence. AC power was checked
before and after every run and recorded in `repeat-results.json`. All twelve
aggregate artifacts independently verified with the same sizes and q70/PoW26.

| Metric | Control | Shared leaf emission |
|---|---:|---:|
| Complete fixture median | 51.05353s | 48.91793s |
| Both leaf proof/preparation phases, median sum | 12.26685s | 10.68192s |
| Root preparation median | 3.96309s | 3.91189s |
| Routed peak | 26,459,992,736 B | 26,459,992,736 B |
| Physical peak | 39,161,847,568 B | 38,988,307,352 B |

Complete fixture median improves 4.18%; the combined leaf
phases improve 12.92%. The implementation is retained. There are two samples
per arm: candidate 47.721/50.114s, control 51.157/50.950s. These absolute times are
slower than the earlier ~38-second sessions, including for the unchanged control;
this is a matched local improvement, not a new sub-38-second baseline or a 10x gain.
The low-battery sequence remains archived separately and is not pooled into these
medians. The powered repeat resolves the earlier pending comparison for this change.
