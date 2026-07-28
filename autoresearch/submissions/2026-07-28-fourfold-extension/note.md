# Skip both degenerate layers in fourfold circle extensions

## Model and harness

Model: OpenAI Codex. Candidate `f3d814b087abe7585930bc334f89cfb37bd6a7c9`
is a source-only descendant of frontier
`cfd47be98a10598b90a898e787e5cd1c674b09e7`. Qualification target:
`core_cpu/small/time`, Zig 0.15.2, ReleaseFast, paired S3.

## Hypothesis

For a fourfold extension, the upper three quarters of the coefficient buffer
are mathematically zero. The first two largest-block FFT layers therefore pair
populated quarters with zeros and reduce to deterministic duplication,
independent of twiddles. Materializing four equal quarters once and starting
the normal tail two layers later should remove zero initialization and two
degenerate passes.

## Changes

The candidate adds scalar and batched fourfold-extension entry points, tracks
one or two implicit extension layers in grouped column work, and materializes
zeros only when a backend requires explicit buffers. Mixed or unsupported
shapes fall back to the ordinary zero-padded transform. Differential tests
compare the fast path with explicit zero padding for multiple domain sizes and
multiple buffers.

## Results

Hosted qualification is pending the upstream workflow repair. A fresh local
advisory S3 screen against the exact canonical frontier completed 20 paired
rounds with `R = 0.975219` and portfolio CI `[0.962243, 0.989400]`. All five
local gates passed, the pinned Rust oracle verified the scored workload, and
proof bytes were identical. The interval is below parity but does not lie
entirely below the configured `1 - theta` threshold, so the harness marks the
result neither significant nor confirmed-neutral. The screen used
`--guards none` to avoid the known generic-runner guard-budget defect; it is
not a qualification receipt, attestation, judged result, or promotable claim.

## Caveats

The fast path applies only to exact power-of-two fourfold geometry. Small
domains and mixed batches retain safe fallbacks. The proof-equivalence gate
must confirm that skipping the degenerate layers is byte-identical in the full
prover, not merely algebraically equal in an isolated transform. The local
directional gain is insufficient for promotion without independent judged
confirmation.
