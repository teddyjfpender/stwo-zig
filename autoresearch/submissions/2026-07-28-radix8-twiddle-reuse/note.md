# Share radix-8 twiddles across forward FFT batches

## Model and harness

Model: OpenAI Codex. The measured candidate
`2a74f0a152c6b43fc6873ccc45ee185195cc50ae` is a source-only descendant
of frontier `cfd47be98a10598b90a898e787e5cd1c674b09e7`. The publication branch
adds a post-screen correctness repair for empty batches; the local performance
numbers below remain bound to the measured candidate. Qualification target:
`core_cpu/small/time`, Zig 0.15.2, ReleaseFast, paired S3.

## Hypothesis

Independent coefficient buffers share transform geometry and the same twiddle
tree. The existing scheduler invokes the packed radix-8 kernel separately for
each buffer, reloading the same seven packed twiddles for every buffer and
group. Hoisting those loads across the buffer batch should reduce repeated
addressing and cache traffic while leaving butterfly order and proof bytes
unchanged.

## Changes

The candidate adds forward-only batch kernels in
`src/prover/poly/circle/fft_radix8.zig`, exports them through
`fft_kernels.zig`, and uses them from the batched transform scheduler.
Single-buffer and inverse paths are unchanged. Both ordinary transforms and
duplicated-half expansion are covered by randomized differential tests against
independent packed radix-8 calls. The publication repair also makes an empty
forward batch an explicit no-op before geometry or twiddle work and locks the
observed RISC-V quotient geometry into a regression test.

## Results

Hosted qualification is pending the upstream workflow repair. A fresh local
advisory S3 screen against the exact canonical frontier completed 20 paired
rounds with `R = 1.001324` and portfolio CI `[0.980664, 1.022294]`. All five
local gates passed, the pinned Rust oracle verified the scored workload, and
proof bytes were identical. The harness classifies the result as
confirmed-neutral. The screen used `--guards none` to avoid the known
generic-runner guard-budget defect; it is not a qualification receipt,
attestation, judged result, or improvement claim.

The first publication CI run exposed a separate correctness defect in the
unmeasured RISC-V product path: the transaction-engine proof test invoked the
batch helper with zero buffers at `log = 7`, `highest_stage = 6`, and 64
twiddles. The original helper asserted a non-empty batch in checked builds and
continued into batch setup in ReleaseFast, where CI terminated with signal 11.
After the explicit empty-batch return and regression test were added, the full
RISC-V CPU product suite passed in both Debug and the CI-equivalent ReleaseFast
configuration. This is correctness evidence for the publication repair, not a
new performance measurement.

## Caveats

The mechanism helps only when multiple buffers share a forward transform.
Its extra loop structure may be neutral for very small batches or pressure
instruction cache on some hosts. It is therefore isolated from larger FFT
fusion ideas. The measured small-class result falsifies a material whole-proof
gain on this host; any central record must retain that neutral status unless an
independent judged run establishes otherwise. Because the timing verdict is
bound to the pre-repair measured commit, the repaired publication tree must be
re-measured before anyone attributes a performance ratio to the repair itself.
