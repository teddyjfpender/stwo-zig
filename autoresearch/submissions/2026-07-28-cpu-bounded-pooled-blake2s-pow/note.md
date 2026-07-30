# Bound pooled Blake2s proof-of-work to four workers

## Model and harness

OpenAI Codex (GPT-5) developed and screened this change with the
repository-resident `stwo-perf` harness on Zig 0.15.2. The final claimed S3
evaluation compares candidate `e46ff331588e` with promoted predecessor
`78556fe7d3fa` on `core_cpu/small`, time dimension, using 20 paired ABBA rounds
on one host. Every timed proof was verified, every cross-arm proof digest
matched, and the pinned Rust Stwo oracle accepted the scored workload.

## Hypothesis

The prover already owns a persistent work pool. Creating and joining another
set of operating-system threads for Blake2s proof-of-work duplicates lifecycle
cost on a short complete-proof workload. Reusing the existing pool should
remove that cost, but allowing every available pool worker to grind can
increase memory and contention enough to violate the whole-suite resource
gate. A four-worker cap should keep the lifecycle win while avoiding the
resource regression.

The nonce search remains exact by assigning residue classes to workers,
checking eight increasing nonces per Blake2s batch, publishing candidates with
an atomic minimum, and waiting for all scheduled work before returning. This
preserves the lowest valid nonce rather than merely returning the first result
to race to completion.

## Changes

- Reuse the prover's global work pool for the default Blake2s proof-of-work
  path instead of creating dedicated threads inside the grind operation.
- Hash eight nonce candidates per fixed-prefix Blake2s call.
- Split the increasing search into worker residue classes and combine results
  through an atomic minimum.
- Limit the pooled search to at most four workers.
- Preserve the explicit `STWO_ZIG_POW_WORKERS` override and all non-Blake2s
  channel behavior.
- Add tests that compare the pooled search with the existing scalar result
  over several difficulties and worker counts, and that bind the result to the
  transcript.

## Results

The final S3 result is `R = 0.914657`, with the harness portfolio 95% confidence
interval `[0.895716, 0.931916]`; the frozen significance threshold is
`1 - theta = 0.962692`. Nineteen of twenty paired rounds were faster. Median
prove time moved from 1.438375 ms to 1.317000 ms.

All G1-G5 gates passed. Peak RSS ratio was 0.959330 with a 95% upper bound of
0.960609. Energy ratio was 0.898412 with a 95% upper bound of 0.909402.
Proof size remained 24,965 bytes, and the proof digest remained
`91741aec956846d52e50f7b8fef3ac93195dbcd76cdb89e25ed33a148bea5700`.
An independent reconstruction reproduced the statistical verdict and audited
all 54 artifact bindings.

## Caveats

This is a submitter-claimed local result, not a locked-host judged verdict.
Only `core_cpu/small` was claimed; no effect is asserted for other classes,
boards, host topologies, non-Blake2s channels, or runs that set the dedicated
worker override.

An earlier uncapped version improved time but failed G4 because peak RSS
regressed to 1.162817 of its predecessor. It was rejected rather than
submitted. The four-worker cap is the measured repair.

Fork qualification was attempted against the same current frontier, but the
canonical Ubuntu workflow failed before measurement because generic setup
tried to build the Apple-only Metal target. No qualification receipt or
remote-submission claim is made here; this PR uses the repository's documented
legacy submission path.
