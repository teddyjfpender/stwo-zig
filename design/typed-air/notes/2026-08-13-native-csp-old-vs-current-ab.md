# 2026-08-13 — Native EthProofs CSP old-versus-current A/B protocol

## Outcome

The repository now has a fail-closed path for answering one narrow performance
question: how does the current typed-AIR source snapshot compare with the clean
branch-start native RISC-V prover on the same machine?

This is not a recursion benchmark. Both arms run the native CPU leaf prover with
recursion and outer proving disabled. The comparison therefore detects regressions
or improvements in the RISC-V execution/AIR/prover path without allowing recursive
work to enter either timing cohort.

No measurement has been run as part of this implementation note. The checked
historical schema-v2 report remains context only and is never used as the A/B
denominator.

## Frozen comparison boundary

- Baseline: clean commit `b6c4f6326aee9c4f57432ac30c55c5b1f2296fab`,
  the committed branch state immediately before the current typed-AIR development
  cohort. Its schema-v3 harness predates runtime recursion attestation, so it is
  admitted only after the Git tree proves that the recursive source paths are absent.
- Current: an isolated, deterministic temporary commit whose tree exactly represents
  the active checkout. It must use the schema-v4 harness and attest
  `recursion_enabled=false` at run, summary, and row level.
- Workload: all 16 cases in `vectors/riscv_csp/manifest-v2.json`, bound to the exact
  nine-profile registry in `vectors/riscv_csp/recursion-shape-audit-v2.json`.
- Backend: CPU only, `ReleaseFast`, with explicit equal worker counts and separate
  Zig caches/build prefixes for each arm.
- Schedule: two rounds by default. Each case is launched serially in alternating
  `baseline,current` / `current,baseline` order. There are 64 partial invocations;
  no arms run concurrently.

The 2026-07-28 checked report at commit
`ed573380db2f7ee1bc364a091cf6c82a00500ec3` was captured with an older evidence
schema and on a different temporal cohort. The plan authenticates it and labels it
`context_only_not_ab_denominator`.

## Dirty-source snapshot protocol

The active branch does not need to be committed. The controller never stages,
commits, resets, checks out, or updates a ref in the active checkout.

1. Record active `HEAD`, porcelain-v2 status digest, and a content digest over every
   present tracked file plus every path returned by
   `git ls-files --others --exclude-standard`.
2. Reject unmerged entries, submodules, special files, and ignored files in build or
   benchmark input scopes. Known compiler/cache output directories are explicitly
   non-source. This closes the otherwise invisible-input gap.
3. Produce one `git diff --binary --full-index HEAD --` and enumerate the exact
   untracked payload.
4. Clone `HEAD` without local hard links, apply the binary patch, and copy the
   untracked payload with file modes/symlinks preserved.
5. Require pre-capture active digest = clone digest = post-capture active digest;
   also require the status, patch, untracked inventory, and untracked payload digest
   to remain unchanged throughout capture.
6. Create a deterministic commit with `git commit-tree` inside the isolated clone
   only. Record the temporary commit, Git tree object, source-content SHA-256, patch
   SHA-256/bytes, untracked payload SHA-256/count/bytes, and honest active dirty label.
7. Recreate the same temporary commit at execution time and require the entire arm
   description to equal the sealed plan. Preserve the otherwise unreachable commit
   in a hashed incremental Git bundle whose prerequisite is active `HEAD`.

Build outputs live only under ignored directories in each temporary clone. The clone
must remain Git-clean after build and after every proof.

## Quiet-host admission

A same-host pair is necessary but not sufficient for a performance claim. Before a
full plan is admitted, the controller records three one-second CPU/load samples after
one warm-up sample, macOS thermal/performance-warning state, kernel thermal-pressure
evidence, AC-power state, and low-power-mode state.

The deliberately strict v1 interference thresholds are:

- every measured sample at least 90% CPU idle;
- median CPU idle at least 95%;
- maximum one-minute load no more than 0.20 per logical CPU;
- no macOS thermal or performance warning;
- AC power and low-power mode disabled.

Failure does not produce a publishable full-cohort plan. It produces a sealed
`diagnostic_smoke_only_host_interference` plan with reasons. The tool never kills or
suspends user applications. A live quiet-host preflight is repeated immediately before
the full execution, so a quiet planning window cannot authorize a later busy run.

The two isolated `ReleaseFast` builds happen after that live admission and can heat the
machine themselves. Before the first measured proof, a bounded recovery gate therefore
repeats the complete idle/load/thermal/power policy up to 12 times with ten seconds between
attempts and fails closed if the host does not recover. Before every paired case, a second
bounded gate (three attempts, five seconds apart) enforces instantaneous idle, thermal, and
power state. It records one-minute load but does not reject on that field because the
preceding benchmark pair necessarily remains in the one-minute average. Both arms in a pair
share the same gate and run adjacently; the next pair cannot start from an actively busy or
thermally warned host. Every gate is sealed and linked from both launch receipts. No user
process is killed or suspended.

The smoke path is intentionally different: one sha256/128 proof per arm, zero warmups,
one retained verified sample. It may run when the quiet-host check fails because it emits
`diagnostic_smoke_only`, carries all interference reasons, sets
`performance_claims_allowed=false`, and cannot call the full report assembler. Its purpose
is to validate source capture, builds, native-only guards, proof retention, verification,
RSS capture, and report ingestion before spending hours on the matrix. Its post-build gate
is recorded as a warning/evidence surface and never upgrades smoke timing into a claim.

## Evidence and interpretation

Every full partial report must bind to its planned commit, manifest, host, canonical
input/guest/output/cycle tuple, clean trace provenance, `ReleaseFast` build identity,
retained verified proof digest and size, and positive peak RSS. Schema-v4 reports must
attest native-only execution explicitly. Schema-v3 is baseline-only and requires proof
that recursive sources did not exist.

The final report retains source-report hashes and raw verified end-to-end samples. Per
case and per arm it reports count, minimum, p50, nearest-rank p90/p95/p99, maximum, and
median absolute deviation for end-to-end time, plus descriptive distributions for proof
duration, verification duration, peak RSS, and proof bytes. A positive delta means the
current arm is larger or slower.

There is deliberately no cross-workload aggregate speedup: SHA-256, Keccak,
Poseidon2-M31, and secp256k1 do not have a justified common production weighting. A
case-level result is evidence; an average across unrelated cases would be presentation.

## Commands

Choose an explicit worker count appropriate for the machine. Evidence must be written
outside the repository or beneath an ignored path such as `vectors/.bench_artifacts/`, so
creating the plan cannot change the source snapshot.

```sh
python3 scripts/riscv_csp_ab_benchmark.py plan \
  --active-root . \
  --out vectors/.bench_artifacts/native-ab-plan.json \
  --rounds 2 --warmups 1 --samples 5 --workers 16 --timeout 3600

python3 scripts/riscv_csp_ab_benchmark.py validate-plan \
  vectors/.bench_artifacts/native-ab-plan.json
```

Run the mechanical smoke first, after the active strict proving job has ended:

```sh
python3 scripts/riscv_csp_ab_benchmark.py smoke \
  vectors/.bench_artifacts/native-ab-plan.json \
  --artifacts vectors/.bench_artifacts/native-ab-smoke-2026-08-13 \
  --confirm-heavyweight native-ethproof-csp-ab-smoke-v1
```

Only a `ready_ephemeral_current` plan can run the complete matrix:

```sh
python3 scripts/riscv_csp_ab_benchmark.py run \
  vectors/.bench_artifacts/native-ab-plan.json \
  --artifacts vectors/.bench_artifacts/native-ab-full-2026-08-13 \
  --confirm-heavyweight native-ethproof-csp-ab-v1
```

Both artifact directories are create-once. Existing evidence is never overwritten.
Any source mutation after planning requires a new plan; this is intentional.

## What this does not claim

- It does not benchmark recursive proving or establish recursive-proof completeness.
- It does not compare against an EthProofs result captured on another host.
- It does not convert the old checked schema-v2 report into a baseline.
- It does not claim that a smoke timing is representative.
- It does not hide build, proof, verification, power, RSS, or source-provenance failures
  by omitting a row.
