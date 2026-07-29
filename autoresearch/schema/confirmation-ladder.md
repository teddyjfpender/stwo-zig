# Confirmation ladder — tiers, spending rule, proxy receipts

Contract: `autoresearch/TRACKS.md` §3.5 (the ladder), §3.6 (acceptance), §8
(wave-1 work items). This document is the schema reference for the harness
implementation of the ladder: what is registered where, what each tier emits,
and what an operator runs on the judge host.

Ranked truth is expensive. The ladder makes every step *before* ranked as cheap
as honesty allows, so agents iterate in seconds and the judge only ever confirms
already-evidenced wins.

| tier | cost target | what runs | emits | ranks? |
|---|---|---|---|---|
| T0 smoke | < 30 s | correctness smoke + ONE stage-profiled sample on the proxy fixture | `stwo_perf_ladder_t0_prefilter_v1` | never |
| T1 iterate | < 300 s | paired ABBA on proxy fixtures, sequential early stop, PoW-excluded boundary | `stwo_perf_ladder_t1_estimate_v1` | never |
| T2 claimed | < 2700 s | full dual-boundary paired run, real classes, guards impact-mapped | `verdict.json` (`kind: claimed`) | claimed only |
| T3 ranked | judge-scheduled | judged re-run + audits on the designated host | signed `verdict.json` (`kind: judged`) | the scored row |

## 1. Registration: `gates_policy.confirmation_ladder`

The whole ladder is one optional manifest block. **A manifest without it keeps
exactly the pre-ladder runner behavior** — that back-compatibility is a tested
property, not a hope.

```json
"confirmation_ladder": {
  "schema": "stwo_perf_confirmation_ladder_v1",
  "sequential_stop": {
    "enabled": false,
    "rule": "pocock_constant_boundary_bonferroni_v1",
    "alpha": 0.05,
    "stop_on_decisive_miss": true
  },
  "tiers": {
    "T0": {"cost_target_seconds": 30, "warmups": 1, "samples": 1,
           "min_phase_move": 0.02, "note": "..."},
    "T1": {"cost_target_seconds": 300, "note": "..."},
    "T2": {"cost_target_seconds": 2700, "note": "..."},
    "T3": {"cost_target_seconds": null, "note": "..."}
  },
  "proxy_validity": {
    "receipt_schema": "stwo_perf_proxy_validity_receipt_v1",
    "receipt_dir": "autoresearch/reference/proxy_validity",
    "min_correlation": 0.8,
    "min_observations": 5
  },
  "cost_telemetry": {"statistic": "median", "window": 5},
  "note": "..."
}
```

Validation lives in `manifest.py` (`_validate_confirmation_ladder`): the block
is all-or-nothing, tier targets must increase strictly down the ladder, and
`rule` must be the single registered spending rule. A half-registered design is
not a pre-registered design.

## 2. The sequential spending rule

**Rule id: `pocock_constant_boundary_bonferroni_v1`.**

* Looks happen at the end of each completed paired round `k` with
  `min_rounds ≤ k ≤ max_rounds`. The number of planned looks is therefore
  `K = max_rounds − min_rounds + 1`, fixed by the manifest before the run.
* The family-wise error `alpha` is spent evenly across those looks (a constant,
  Pocock-style boundary): look `k` decides on a bootstrap CI at level
  `1 − alpha/K`, using the same deterministic seed as the run's final CI.
* Stop conditions, evaluated against the bar `1 − theta`:
  * **decisive clear** — adjusted CI upper bound `< 1 − theta`;
  * **decisive miss** — adjusted CI lower bound `> 1 − theta`
    (only when `stop_on_decisive_miss`);
  * otherwise continue. Borderline effects pay full power to `max_rounds`.
* The existing precision rule (half-width `≤ theta/2`), the `min_rounds` floor,
  the `max_rounds` cap, and the wall-clock cap are all unchanged and still
  bind — the sequential rule can only stop a run *earlier*, never later.

Why this is honest: `alpha/K < alpha`, so the boundary is strictly stricter
than the fixed-sample gate. A decisive clear at any look would also have
cleared the nominal gate, so early stopping can never admit a run that the
full-power design would have rejected. The run records its own design in
`sequential_stop` evidence (rule, alpha, planned looks, look index, adjusted
level, adjusted CI, bar, decision) so a reader can audit the stop.

Arming:

* `sequential_stop.enabled` arms the rule on scored paired runs (T2/T3, A/A).
  It ships **false**: the ranked path keeps its fixed design until an era
  boundary deliberately changes it.
* The T1 iterate path arms the rule explicitly (`sequential_stop=True`) because
  T1 never ranks. It still refuses to run when the manifest has not registered
  the rule — the parameters are never ad hoc.

## 3. PoW-excluded fast boundary

`pow 26` is ~constant work and pure noise for paired deltas, so T0/T1 measure
`verified_request_minus_pow_ms` while T2/T3 keep the full boundary. Both
numbers are reported at T1: `request_ratio` (full) and `fast_request_ratio`
(PoW-excluded).

Fail-closed in three places:

1. `runner.POW_PHASE_SECONDS_FIELDS` maps a `report_schema` to the report path
   carrying the **measured** PoW seconds. It is deliberately **empty**: no
   shipped product emits a PoW cutpoint yet, so `--fast-boundary` refuses on
   every group today. The harness never subtracts a cost it did not measure.
   *Product handoff:* emit the PoW phase (§3.2 names it) and register the field
   path here; nothing else changes.

   Known near-miss on Cairo: the Cairo stage profile already records a
   `proof_of_work` stage with real seconds, but the phase mapping folds it into
   the `fri` phase, and the profile is recorded on a **discarded warmup** while
   the scored request time comes from the uninstrumented samples. Registering
   that number would subtract a duration measured on a *different invocation*
   than the one being timed. That is a decision about measurement scope, not a
   wiring detail, so it is left to a reviewed change: either publish per-sample
   PoW seconds in the `cairo_proof_v1` envelope, or accept the cross-invocation
   subtraction explicitly for T1 (which never ranks).
2. `runner.evaluate(..., fast_boundary=True)` always raises — the ranked and
   claimed paths cannot express a PoW-excluded number even by accident.
3. `stwo-perf run --fast-boundary` is rejected by the CLI with a pointer to
   `stwo-perf ladder t1 --fast-boundary`.

## 4. Proxy fixtures (`workload_registry.classes.<class>.proxy_fixture`)

A proxy is a **scaled shape at official parameters** — never weakened
parameters at a full shape (§3.3).

```json
"proxy_fixture": {
  "proxy_id": "cairo_all_opcodes_proxy",
  "args": "--fixture ... --warmups {warmups} --samples {samples}",
  "native_unit": "committed cells",
  "official_params": true,
  "target_workload_ids": ["cairo_all_opcodes"],
  "note": "scaled geometry, official pow 26 / 70 queries"
}
```

`official_params` must be `true`, and the args may not restate any security
parameter (`--pow-bits`, `--n-queries`, `--protocol`, `--security`,
`--functional` are refused outright): a proxy scales geometry only. Classes
without a proxy fixture are legal — the ladder then iterates on the full class
basket and says so with a loud marker.

## 5. Era validity receipts (`stwo_perf_proxy_validity_receipt_v1`)

Per era, per `(board, class)`, the judge host measures the proxy→class
predictive correlation and commits it as a receipt at
`<receipt_dir>/<board>-<class>-era<N>.json`. Receipts are era-frozen like
anchors. A proxy whose validity decays below `min_correlation` is rotated.

```json
{
  "schema": "stwo_perf_proxy_validity_receipt_v1",
  "board": "cairo_cpu",
  "era": 3,
  "workload_class": "huge",
  "proxy": {"proxy_id": "...", "args": "...", "native_unit": "...",
            "official_params": true},
  "target": {"workload_ids": ["..."]},
  "measured_at_utc": "2026-07-29T12:00:00Z",
  "host": {"identity_sha256": "<64 hex>", "chip": "Apple M5",
           "logical_cpu_count": 10},
  "harness_commit": "<12-40 hex>",
  "measurement": {
    "method": "paired_ln_ratio_pearson_v1",
    "observations": [
      {"proxy_ln_ratio": -0.11, "class_ln_ratio": -0.09,
       "proxy_evidence_sha256": "<64 hex>", "class_evidence_sha256": "<64 hex>"}
    ],
    "observation_count": 5,
    "correlation": 0.93,
    "min_correlation": 0.8,
    "min_observations": 5,
    "valid": true
  },
  "artifact_sha256": "<64 hex of the canonical observation list>"
}
```

Anti-fabrication properties, enforced by
`manifest.validate_proxy_validity_receipt`:

* the correlation is **recomputed** from the receipt's own observations and
  must match to 1e-9 — a receipt cannot assert a number its evidence does not
  support;
* every observation binds the sha256 of the measurement document it came from;
* a receipt may not weaken the registered `min_correlation` or
  `min_observations`;
* `valid` must agree with the receipt's own thresholds;
* the proxy identity must equal the manifest's declared fixture.

**Absence is never fatal and never fabricated.** With no receipt (or an invalid
one) `manifest.proxy_validity_state` reports `validated: false` and T0/T1
documents carry a `proxy unvalidated: ...` marker. T0/T1 never rank, so an
unvalidated proxy costs scheduling confidence, not correctness.

### Operator commands (M5 judge host)

Receipt generation is an M5 job: it consumes measurement documents that already
exist and computes nothing new about the machine. For each of at least
`min_observations` candidate/predecessor pairs, record one proxy run and one
class run, then assemble:

```sh
# 1. per historical pair, on the judge host, under the judge lock:
stwo-perf ladder t1 --board <track> --class <class> \
    --predecessor <predecessor-worktree> \
    --out /tmp/proxy-<n>.json
stwo-perf run --board <track> --class <class> \
    --predecessor <predecessor-worktree> \
    --out /tmp/class-<n>.json

# 2. assemble the era receipt (measures nothing; reads the runs above):
stwo-perf ladder proxy-receipt --board <track> --class <class> --era <N> \
    --observation /tmp/proxy-1.json:/tmp/class-1.json \
    --observation /tmp/proxy-2.json:/tmp/class-2.json \
    --observation /tmp/proxy-3.json:/tmp/class-3.json \
    --observation /tmp/proxy-4.json:/tmp/class-4.json \
    --observation /tmp/proxy-5.json:/tmp/class-5.json \
    --out autoresearch/reference/proxy_validity/<track>-<class>-era<N>.json

# 3. commit the receipt via a reviewed PR (era-frozen like anchors).
```

The command exits non-zero when the measured correlation is below the floor:
that is the rotation signal, and the receipt is still written so the decay is
on the record.

## 6. T0 phase-attribution prefilter

A submission names the phase it claims to move (§3.2 vocabulary). T0 runs one
stage-profiled sample per arm on the proxy fixture and requires that phase to
move by at least `tiers.T0.min_phase_move` before T1 is scheduled — a claimed
FRI win that only moves witness time dies in 30 seconds, not 45 minutes.

Phase evidence is read generically from whatever the group's report schema
provides: the declared cutpoints in `runner.PHASE_SECONDS_FIELDS` plus any
stage-profile tree in the report (`timing.stage_profiles`, `stage_profile`, or
a bare `stages` list, as `--stage-profile-out` writes), flattened to dotted
`stage:<parent>.<child>` names. A group whose reports carry no phase evidence
at all fails closed rather than silently passing every claim.

Registered rows: `native_proof_v7` (input/prove/serialize/verify/request),
`riscv_proof_v2` (execute/witness/prove/verify/request), and `cairo_proof_v1`,
whose row is **derived** from `manifest.CAIRO_PHASE_NAMES` so the ladder cannot
drift from the schema's canonical cutpoint set. Cairo's `serialize` is always
null (proof encode/write/hash is outside the recorder), so it drops out of the
measured set and a claim on it fails T0 closed — as does a claim on any phase
whose predecessor duration is zero (a prove-only workload's `execute`).

`tiers.T0.warmups` is **1**, not 0: the Cairo arm records its mandatory phase
profile on a discarded warmup, so a zero-warmup T0 would leave that track with
no phase evidence at all.

```sh
stwo-perf ladder t0 --board <track> --class <class> --phase fri \
    --predecessor <predecessor-worktree>
```

Exit code 1 means "T1 is not scheduled".

## 7. Tier cost targets in CI (§3.6)

`scripts/check_tier_cost_targets.py` reads the recorded telemetry —
`score.portfolio.measurement_seconds` from claimed (T2) and judged (T3)
verdicts, `measurement_seconds` from T0/T1 ladder documents — aggregates the
last `cost_telemetry.window` observations per `(track, tier)` with
`cost_telemetry.statistic`, and fails when the summary exceeds the tier's
registered target.

* Tracks are enumerated from `workload_registry.groups[*].board`, so a new
  track is covered the moment its group lands.
* T3 has no target (`null`): the judge never trades honesty for time.
* A `(track, tier)` with no telemetry passes with a loud note. Fail-closed
  applies to honesty, not to absent tracks.

Wiring: `autoresearch/tests/test_tier_cost_targets.py` invokes the check over
the repository, and the `autoresearch-validate` workflow already runs
`python3 -m unittest discover -s autoresearch/tests`, so the target is enforced
on every PR without adding a workflow step. Run it by hand with
`python3 scripts/check_tier_cost_targets.py`.
