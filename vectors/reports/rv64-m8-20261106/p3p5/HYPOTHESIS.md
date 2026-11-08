# P3/P5 scheduling candidates

Status: source hypothesis only; no build, GPU execution, acceptance, throughput,
memory qualification or request-time gain is claimed. Parent checkpoint:
`b68e02081`. Development remains limited to blocks `26235156` and `24628607`
on the available two RTX 5090 GPUs. Four-GPU placement and comb aggregation
remain deferred; no four-GPU validation is implied.

P3: `STWO_RV64_EARLY_SEGMENT_PARALLEL_SETUP=1` removes only the outer
per-segment setup mutex in the existing default-off early-native-segment route.
The resident setup cache already serializes equal-key construction and protects
its map, while independent components build outside that lock. The native,
program-metadata and fixed-authority caches synchronize their own ownership;
the source-key seal seam is thread-local. This may reduce setup head-of-line
blocking across device lanes. Setup wait/build timestamps separate the proposed
cause from capture/global-RAM/admission delays. The stage-1-start target remains
at most 1.4 seconds from the stated 2.55-second baseline [M, inherited scope
baseline; not remeasured here]. No target attainment is claimed.

P5: `STWO_RV64_CAPTURE_REPLAY_AHEAD=1` prelaunches later replay workers within
the existing worker-count window, allowing them to await immutable checkpoints
while the first segment runs. Today the launch loop stops at an unpublished
checkpoint, and checkpoint publication alone does not restart it. The required
next checkpoint still waits on the ordered owner, preserving recording-error
delivery. Known terminal bounds, ring capacity, exact checkpoint continuity,
ordered delivery, pass cancellation and worker joins remain mandatory. Report
checkpoint wait separately from replay wall time and useful retired steps;
the target of at least 100 MIPS aggregate is unmeasured.

`replay_wall_ns` spans first launch-window admission through the last consumed
replay, including required-checkpoint waits and consumer backpressure. It
excludes program/image initialization and the capture/ledger tail; it cannot
alone establish end-to-end capture throughput. `walk_checkpoint_wait_ns` is
included in summed worker time and is reported separately, not subtracted from
the aggregate replay wall denominator.

Both flags default off. Scheduling changes preserve final-scope allocation,
one cached capture seal, all-segment coverage, and original transcript/root
order. No cryptographic parameters, proof format, statement identity or claimed
conjectured-128-bit/hash-based security assumptions change. Existing global RAM
authority and exact inventory adoption checks remain intact.

The owner runs build/units, both development blocks, byte parity, fresh CPU
receivers, corpus and matched composed timing in priority order after P1
measurement/calibration. No additional two-lane trial precedes a calibrated fit.
Reject a candidate if its matched request time regresses, if stage-1-start or
capture throughput does not improve, or if any identity/receiver/corpus gate
fails. Raw evidence stays on the pod with a SHA reference; retained summaries
must remain below the checkpoint size cap.

Implementation is present behind both flags. Cheap static checks pass:
`git diff --check` and `zig fmt --check` for the changed Zig files. The pure
launch-policy module contains bounded-window, required-checkpoint, known-final-
bound and default-schedule cases for owner-side execution. No unit execution,
build, device run, timing, receiver or corpus result is claimed here.
