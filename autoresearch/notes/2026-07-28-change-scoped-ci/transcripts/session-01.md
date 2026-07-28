# Session 01 — change-scoped CI

Implementation: Claude Opus 4.5. Orchestration: Claude Fable 5.
Worktree `/private/tmp/stwo-zig-cairo-native-throughput-10x`, branch
`feat/change-scoped-ci`, base `191e409f`.

## 1. Survey (and the premise failing)

Brief: "every PR runs every CI gate (~35+ jobs) regardless of what the diff
touches; build change-scoped CI."

Enumerated `.github/workflows/` — 14 workflows. Extracted `on:` blocks. Only
five trigger on `pull_request` at all, and three of those are already scoped:

- `ci.yml` — job `focused-plan` runs `scripts/ci_scope_plan.py --base --head`
  and emits `linux_matrix` / `macos_matrix` / `cuda_required`, consumed by
  `focused-linux` / `focused-macos` / `focused-cuda` via `fromJSON`.
- `riscv-sail-differential.yml` — a `scope` job computing `live_required` from
  the merge-base diff, same pattern.
- `benchmark-pages.yml` — `on.pull_request.paths` YAML anchor.
- `pr6-supremacy.yml` — unconditional `contract-smoke`.
- the autoresearch harness workflows — out of scope by instruction.

The rest (`audit`, `architecture-authority`, `native-oracle`,
`metal-calibration`, `qualify-fork`) are `workflow_dispatch`/`schedule` only.

So the premise is stale. Decision: do **not** rebuild what exists. Find the
actual defect in what exists.

Read `ci_scope_plan.py` (303 lines) and `conformance/ci-touchpoints-v1.json`
(404 lines). Selection is `always_lanes ∪ catalog(product_scope_lanes) ∪
rules[]`, fail-open when a path matches nothing. The defect is in `rules[]`: it
is a hand-written per-prefix lane list that duplicates the package dependency
graph. The brief explicitly forbids exactly that ("do NOT hand-maintain a
parallel path list for package-owned paths"), so the increment writes itself.

Also read `conformance/build-architecture-ci-plan-v1.json` before touching
anything. Despite the name it is *not* the PR lane plan — it is the
`architecture-authority` session's per-role BG-00…BG-14 command plan, from a
dispatch-only workflow, with no lane concept. Left alone.

## 2. Establishing the graph and measuring the drift

```
packages 17  edges 51
```
matching `scripts/check_package_workspace.py`'s own report
(`PASS (17 packages, 17 public modules, 51 dependency edges)`).

Then the mapping question: how do lanes bind to packages? Rather than write a
new table, noticed that 17 of the 34 lanes already name their package's
`build.zig` in a `--build-file` argument. So lane → package is derivable from
the policy itself — one fewer thing that can drift.

Computed, per package, the reverse-dependency closure and compared it against
the hand-written rule for that package's own prefix:

```
src/backend             MISSING=['cairo_cpu_integration', 'riscv_cpu_integration',
                                 'riscv_metal_integration'] EXTRA=[]
src/backends/cpu_scalar MISSING=['cairo_metal_integration',
                                 'riscv_metal_integration'] EXTRA=[]
src/core                MISSING=['cuda_backend'] EXTRA=[]
```

`EXTRA` empty everywhere: the hand list is a strict subset of the truth. It
under-selects, which is the unsafe direction — a `src/backend` change could
break `riscv_cpu_integration` and no lane would run.

## 3. The resolver

`scripts/ci_package_graph.py`, stdlib only, 220 lines. Notable decisions:

- dependency *paths* in the contracts are resolved back to package *names*,
  with `..` normalised; an unresolvable path raises rather than silently
  dropping an edge;
- `reverse_closure` iterates to a fixed point rather than recursing, so a cyclic
  graph terminates here even though the workspace validator rejects cycles;
- `owning_package` uses longest-prefix so a nested package is never shadowed,
  and returns `None` rather than guessing — the fail-open decision belongs to
  the caller, which is why `selection()` returns unowned paths instead of
  swallowing them;
- `lane_packages` raises if a lane's `--build-file` points at a directory no
  contract owns, because such a lane would silently never be graph-selected.

Smoke check:

```
packages 17 edges 51   bindings 17
['src/core/fields/m31.zig']       -> 16 lanes
['src/frontends/cairo/air.zig']   ->  4 lanes (cairo_* only)
['src/backend/mod.zig']           -> 14 lanes
['scripts/foo.py']                ->  0 lanes, unowned ['scripts/foo.py']
```

`src/core` selecting 16 of 17 is right: `stwo_metal_session` has no
dependencies, so nothing reaches it from core.

Wired into `ci_scope_plan.select_lanes` as an additional per-path union, before
the existing rules and fail-open. Ran the pre-existing suites first with the
graph *added but the policy not yet trimmed*: 51 tests OK. Backward compatible,
because fixture policies have no `--build-file` lanes and so bind nothing.

## 4. Trimming the policy

Migration, applied programmatically rather than by hand: for each rule, partition
prefixes into package-owned and other. Rules with mixed prefixes are **split**,
so non-package prefixes keep their original lanes verbatim — otherwise stripping
`native_cuda_integration` from a rule that also covers `scripts/cuda_` and
`tools/stwo-cuda-adapter-rs` would have silently dropped coverage for those.
Each package-owned prefix then sheds exactly the lanes its own graph closure
derives.

```
rules 29 -> 35
18 prefixes shed hand-listed package lanes
```

Then the property that actually matters. Replayed old algorithm vs new over
**every tracked file**:

```
6728 tracked files
=== DROPPED lanes (must be empty) ===
  none — every path selects at least what it selected before
=== ADDED lanes (drift fixed) ===
  +['cuda_backend']  85 files
  +['cairo_cpu_integration','riscv_cpu_integration','riscv_metal_integration']  20 files
  +['cairo_metal_integration','riscv_metal_integration']  5 files
```

Exactly the three predicted drift classes, nothing else, nothing lost.

## 5. Replay against real history

Found real commits rather than inventing diffs: scanned 400 commits of main for
ones touching only RISC-V package paths (`e6303646`, `a0e594e6`), took the
notes-only `ceb5b32f`, the metallib delivery `19026cae`, and PR #125's
`78556fe7...191e409f`.

The brief predicted PR #125 would fail open on
`scripts/riscv_poseidon_table_uniqueness.py`, and asked for the counterfactual
without it. It does fail open — but the counterfactual **also** comes out full,
because the same PR touched `build_support/products/aggregate.zig` and
`build_support/products/cairo_support.zig`, which are unmapped and fail open
too. Reported as measured, not as predicted.

Full table in the note. The honest shape of the result: reductions of 97% / 70%
/ 73% on notes-only, riscv-only, and cairo-only diffs were **already** being
achieved before this branch. This increment's numbers move *up* in one case
(`src/core`: 24 → 25 lanes, `+cuda_backend`). It is a correctness fix, not a
job-count win, and the note says so in its first section.

## 6. Workflow wiring

Considered converting the `fromJSON` matrix into 34 statically-declared jobs
with per-job `if:` guards, for visibly-skipped lanes. Rejected: `focused-verdict`
already is the single always-run required check, and it asserts unselected lanes
are genuinely `skipped` rather than merely absent. That is better
branch-protection ergonomics than 34 required checks, and the conversion would
be a ~2000-line rewrite of a working workflow.

Two additive changes instead, both inside `focused-plan`'s scope step:

- `--full-matrix` on push to main. Previously pushes were *also* diff-scoped,
  so there was no post-merge safety net. Now there is, and it keeps every lane's
  cache warm.
- `--github-summary` writes a 34-row selected/skipped table with the triggering
  path — the cheap substitute for statically-declared skipped jobs.

Used a bash array (`SCOPE_ARGS+=(--full-matrix)`) rather than an unquoted
variable so the shell stays lint-clean. Moved the `full_matrix` short-circuit
above the empty-diff guard so a push with an unusable `github.event.before`
still yields the full matrix rather than erroring.

## 7. Validation

```
scripts.tests.test_ci_package_graph                       28 tests OK
python3 -m unittest discover -s scripts/tests           1089 tests OK (18 skipped)
python3 scripts/check_source_conformance.py             no new violations
python3 scripts/check_package_workspace.py              PASS (17 packages, 51 edges)
zig fmt --check build.zig build_support src tools        clean
git diff 191e409f -- conformance/...json | grep -c '"commands"'   0
actionlint .github/workflows/ci.yml                     13 findings before, 13 after,
                                                        identical set (all pre-existing)
```

The `"commands"` count of 0 is the discipline check: no gate's *content* moved,
only its triggering.

## 8. Commits

- `ef2f76aa` Derive focused CI package lanes from the package graph
- packaging commit for this note and transcript

## What I would not claim

- No hosted CI run happened; this is local replay plus static validation.
- The 17 non-package lanes (product, aggregate, oracle, global) were neither
  derived nor audited for the same drift class. That is the obvious follow-up
  and is listed as residual risk 1.
- `vectors/**` and `pr6-supremacy.yml` remain unreduced. Both are named as
  known, deliberate gaps rather than quietly left out.
