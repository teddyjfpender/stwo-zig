# 2026-08-12 — C-013 CPU capture readiness and claim boundary

## Outcome

The frozen C-013 CPU capture path is now executable end to end: it creates an
immutable 1,520-attempt plan, admits the session through A/A, journals every
fresh child and raw stream, retains a CPU reduction, and independently
recomputes every cell, interval, crossover, resource gate, and digest during
bundle validation. It does **not** produce an M6 promotion verdict. The
required Metal cohort and several receipt-contract fields are outside this
CPU bundle, and no capture can be admitted from the current dirty shared
development checkout.

The honest result for this checkpoint is therefore `NO_VERDICT` for C-013
measurement, with complete reproducible CPU tooling rather than an informal
or post-selected comparison.

## Methodology audit

The implementation replays ADR-0034 and the frozen performance protocol
without reducing the workload after observing a result:

- 80 A/A attempts run first. Failure or an interval wider than `0.06`, or an
  interval that excludes `1.0`, stops the session before M6.
- The admitted CPU cohort has 18 cells in shape-major/call-minor order: three
  shapes by `0/1/8/64/512/4096` calls.
- Every cell has ten excluded warmups per arm and three alternating paired
  rounds of ten measured proofs per arm: 1,440 M6 attempts.
- All 1,520 attempts are serial fresh processes, separated by one second,
  without retry, early stop, outlier deletion, replacement, or relabelling.
- Every report binds the secure PCS, clean commit/tree, executable, ELF,
  source-identical corpus input/output, schedule, shape, call count, proof,
  verification result, and Darwin v6 counters.
- Speed is software duration divided by precompile duration. Resource work is
  precompile divided by software. Three round-median ratios feed the pinned
  epoch-3 Hodges--Lehmann estimator and deterministic 4,000-sample 95%
  percentile bootstrap.
- Each of the 18 rows reports fresh-process launcher wall time, verified
  request, execution, proving and encoding time, verification time, peak RSS,
  process CPU, retired instructions, cycles, energy, proof bytes, execution
  steps, and exact preprocessed/main/interaction/committed cells.
- Crossover is computed separately for every shape. A portfolio or aggregate
  cannot hide a shape that crosses after 512 calls.

The retained `cpu-reduction.json` is deliberately labelled
`authenticated-cpu-lane-reduction-not-m6-promotion-receipt`. Its claim
boundary keeps `m6_promotion_outcome` null, names `metal-hybrid` as missing,
and records the remaining source/build/environment, verifier-receipt, and
complete-geometry evidence gaps. `validate-bundle` always recomputes the
document from the raw attempt ledger and rejects a changed result, unknown
file, reordered attempt, omitted failure, or digest drift.

## Stale-artifact failure found during the audit

The build-graph check ran the current v3 proof child, but the installed
`zig-out/bin/riscv-poseidon2-proof-child` was still an older v1 executable.
That distinction matters because the capture plan uses installed paths. A
green check target alone did not mean the capture artifact was current.

Plan construction now requires embedded protocol markers for the v3
Poseidon child, v2 A/A child, and v1 corpus tool. A stale installed executable
fails before plan publication with an instruction to install the ReleaseFast
capture artifacts. The audited runbook therefore has an explicit install step.

## Reproducible clean-snapshot runbook

Run these commands only after the candidate changes are committed and
`git status --porcelain=v1 --untracked-files=all` is empty:

```sh
zig build check-c013-poseidon2-pair check-c013-corpus-manifest \
  check-c013-aa-proof-child check-c013-poseidon2-proof-child \
  -Doptimize=ReleaseFast
zig build riscv-poseidon2-proof-child riscv-c013-aa-proof-child \
  riscv-c013-corpus-manifest -Doptimize=ReleaseFast
python3 scripts/typed_air_c013_capture.py plan \
  --output /absolute/create-only/path/c013-plan.json \
  --session-id SESSION_ID \
  --power-state 'AC power; Low Power Mode off; benchmark host isolated'
python3 scripts/typed_air_c013_capture.py validate-plan \
  /absolute/create-only/path/c013-plan.json
python3 scripts/typed_air_c013_capture.py capture \
  /absolute/create-only/path/c013-plan.json \
  --bundle /absolute/create-only/path/c013-bundle \
  --execute-frozen-1520-attempt-schedule
python3 scripts/typed_air_c013_capture.py validate-bundle \
  /absolute/create-only/path/c013-bundle
```

The schedule alone imposes 1,519 seconds (25 minutes 19 seconds) of cooldown.
Proof time is additional. In particular, ADR-0034 intentionally retains the
core-dominated 4,096-call software arm; its admission cannot be estimated
defensibly from a one-call dominant diagnostic or reduced after seeing host
cost. A resource failure is retained and yields no verdict.

## Gate receipts

The following commands pass on Darwin arm64, `Mac17,7`, 18 physical cores and
64 GiB memory:

- `python3 -m unittest` over the six C-013 suites: 31 tests, including
  deterministic reduction, total-work failure, geometry/reorder attacks,
  stale executable rejection, bundle inventory, and CPU/M6 claim separation.
- `python3 scripts/typed_air_performance_protocol.py`: protocol SHA-256
  `7c213ae7c35ac8f60f204fba8fa96357195186a29a6a626c0a67fd47984cf985`.
- the protocol mutation suite: 12 tests.
- the combined ReleaseFast C-013 semantic/corpus/A/A/proof-child preflight.
- the all-shape semantic preflight in Debug and ReleaseSafe as well as
  ReleaseFast.
- explicit ReleaseFast installation of all three default capture executables.

The all-shape one-call semantic preflight remains exact at
software/precompile VM steps `58,054/84`, `116,096/58,058`, and
`927,079/868,707` for dominant, balanced, and core-dominated respectively.
All arms publish the pinned one-call output digest
`0c425365ef3800a7bcd30f37b94cdf08f1ab3028a87b7dbc00749b6bb5087d06`.

After installing the current v3 child, one secure, dirty-tree, dominant
one-call diagnostic per arm produced the following directional data. It is
not a sample in the frozen cohort and carries no confidence interval or
performance verdict:

| Measure | Software | Precompile | Normalized ratio |
| --- | ---: | ---: | ---: |
| Fresh-child launcher wall ns | 1,206,460,875 | 773,017,333 | speed `1.560716` |
| Verified-request ns | 940,164,375 | 869,577,167 | speed `1.081174` |
| Proving ns | 806,227,917 | 736,519,375 | speed `1.094646` |
| Verification ns | 130,607,875 | 132,858,167 | work `1.017229` |
| Committed cells | 33,427,648 | 24,890,400 | work `0.744605` |
| Proof bytes | 796,112 | 1,013,632 | work `1.273228` |
| Peak physical footprint bytes | 1,300,825,672 | 1,189,791,208 | work `0.914643` |
| Process CPU ns | 8,509,653,417 | 8,865,247,250 | work `1.041787` |
| Retired instructions | 83,302,317,332 | 88,179,333,538 | work `1.058546` |
| Cycles | 34,291,522,630 | 36,295,489,935 | work `1.058439` |
| Energy nJ | 24,862,057,557 | 26,703,256,273 | work `1.074057` |

The sample confirms the intended tradeoff rather than a universal win:
committed cells and process wall time fall, while one-call proof bytes and
some total-work counters rise. Only the complete paired sweep can determine
whether the 512/4,096-call gates and uncertainty bounds pass.

## Remaining acceptance gap

Attempting to create the plan from the shared feature checkout fails closed:

```text
C-013 capture plan: FAIL: C-013 capture planning requires a clean Git snapshot
```

Even after a clean CPU capture, M6 performance promotion still requires the
Metal-hybrid cohort, authenticated resident-dispatch/zero-fallback evidence,
cross-lane proof invariants, protocol-complete source/build/toolchain and
environment closure, distinct native and independent verifier receipts, and
the final normative receipt renderer. C-013 must remain open until that
evidence exists; the CPU reducer must not be relabelled as the M6 verdict.
