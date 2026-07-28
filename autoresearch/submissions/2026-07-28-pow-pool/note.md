# Reuse the prover work pool for proof of work

## Model and harness

Model: OpenAI Codex. Candidate `6efb93d539498178fe2fb67ead0788bb884a6bcb`
is a source-only descendant of canonical frontier
`cfd47be98a10598b90a898e787e5cd1c674b09e7`. It is intended for the
`core_cpu/small/time` fork-qualification path with Zig 0.15.2 and ReleaseFast.
The current hosted result is pending. The canonical Ubuntu workflow first
failed while building the unrelated Metal target. A non-canonical repair
canary subsequently passed setup and reached benchmarking, then exhausted the
generic runner's fixed guard wall budget before producing a receipt.

## Hypothesis

The raw Blake2s proof-of-work search creates and joins OS threads for each
proof even though earlier prover stages already keep a global worker pool
alive. On the small class, fixed thread lifecycle cost is a material fraction
of proof time. Routing the same strided nonce search through the persistent
pool should remove that fixed cost without changing transcript inputs, nonce
selection, hashes, or proof bytes.

## Changes

The candidate changes only `src/prover/pcs/proof_of_work.zig`. It assigns one
nonce residue class per existing pool worker, executes residue zero on the
caller, and atomically lowers a shared best-nonce bound. All jobs join before
return, preserving the globally lowest valid nonce. Generic channels, explicit
worker overrides, pool-unavailable execution, tests, and single-threaded builds
retain the original path.

## Results

Hosted fork qualification is pending. Diagnostic run `30346576852` proved that
the board-scoped setup repair reaches the paired S3 path on Ubuntu, but the
unchanged predecessor consumed almost the entire 300-second first-guard wall
budget and left only 6.44856008 seconds for the candidate arm. The run emitted
no verdict, receipt, or attestation.

A fresh local advisory S3 screen against the exact canonical frontier completed
20 paired rounds with `R = 0.956784` and portfolio CI
`[0.921421, 0.980501]`. All five local gates passed, the pinned Rust oracle
verified the scored workload, proof bytes were identical, peak RSS ratio was
`0.962034`, and energy ratio was `0.928132`. The point estimate exceeds the
configured `theta = 0.037308` improvement, but the CI does not lie entirely
below `1 - theta`, so the harness correctly labels it not significant. The
screen used `--guards none` to avoid the known generic-runner guard-budget
defect; it is evidence for prioritization, not a qualification receipt,
attestation, judged result, or promotable claim.

## Caveats

The optimized path is deliberately limited to the raw Blake2s channel and
default worker policy. A prior transcript-keyed nonce cache was rejected
because it accelerated repeated benchmark history rather than fresh work, and
a four-lane nonce batch was rejected after a neutral-to-worse exact-main run.
Branch publication, the original Metal setup failure, and the diagnostic guard
timeout are not performance evidence. Central qualification must still
re-run the complete guard portfolio and independently reproduce significance.
