# Change-scoped CI: deriving the lane closure from the package graph

- Implementation: Claude Opus 4.5
- Orchestration: Claude Fable 5
- Branch: `feat/change-scoped-ci` (base `191e409f`)
- Date: 2026-07-28

## Summary

The increment was commissioned as "every PR runs every CI gate; build
change-scoped CI". **The survey contradicted the premise.** Change-scoped CI
already ships: `ci.yml`'s `focused-plan` job computes a lane matrix from the PR
diff and the focused Linux/macOS/CUDA jobs consume it. A notes-only commit
already runs 1 lane, not 34.

The real defect is one level down. The package portion of that selection was a
**hand-maintained per-prefix lane list** in `conformance/ci-touchpoints-v1.json`
that duplicates the package dependency graph — and it had drifted, in the unsafe
direction: it *under-selected* transitive consumers. Three concrete cases, so a
change to `src/backend` could break `riscv_cpu_integration`'s build and no lane
would notice.

This increment replaces that list with a closure computed from the 17
`package.contract.json` files and their 51 declared edges, and adds two
workflow-level safety properties (full matrix on push to main; a visible
selected/skipped lane table).

Honest headline: **this is a correctness and maintainability fix, not a
job-count win.** The job-count reduction was already banked by the pre-existing
focused plan. Where the numbers move at all, they move *up* — 110 tracked files
now select lanes they should always have selected.

## Survey

### Workflows that trigger on `pull_request`

| Workflow | PR behaviour | Scoped today? |
|---|---|---|
| `ci.yml` | focused matrix via `focused-plan` → `ci_scope_plan.py` | yes — diff-scoped |
| `riscv-sail-differential.yml` | `scope` job computes `live_required` from the merge-base diff | yes — same pattern |
| `benchmark-pages.yml` | `on.pull_request.paths` anchor | yes — path filter |
| `pr6-supremacy.yml` | `contract-smoke` runs unconditionally (~15 min) | **no** |
| `validate.yml`, `judge.yml`, `promote.yml`, `automerge.yml`, `record.yml` | autoresearch harness | out of scope by instruction |

`audit.yml`, `architecture-authority.yml`, `native-oracle.yml`,
`metal-calibration.yml`, `qualify-fork.yml` are `workflow_dispatch`/`schedule`
only — they never run on a PR. There is no release workflow, consistent with the
stated non-goal.

### The existing resolver

`scripts/ci_scope_plan.py` (303 lines before this change) selects lanes from
three sources, unioned per changed path:

1. `always_lanes` — `["static"]`;
2. the product catalog (`zig-out/identity/product-matrix.json`, built by
   `zig build product-matrix-identity`) matched against each product's
   `module_roots` / `allowed_prefixes`, mapped through `product_scope_lanes`;
3. `rules[]` — hand-written `{prefixes, lanes}` pairs.

Fail-open already exists and is correct: a path matching nothing, and not under
`documentation_prefixes` or `externally_validated_prefixes`, selects the whole
matrix. `scripts/ci.py`'s `FAST_PLAN` is a separate local pre-commit tier and is
untouched.

### Lane ↔ package mapping, as it actually is

17 of the 34 lanes build exactly one package, and they say so themselves — each
names that package's `build.zig` in a `--build-file` argument:

```
backend_contracts   src/backend            metal_session       src/tools/metal_session
cairo_cpu_integration src/integrations/cairo_cpu   native_cuda_integration src/integrations/native_cuda
cairo_cuda_integration src/integrations/cairo_cuda native_examples     src/examples
cairo_frontend      src/frontends/cairo    proof_wire          src/interop/proof_wire
cairo_metal_integration src/integrations/cairo_metal  prover         src/prover
core                src/core               riscv_cpu_integration src/integrations/riscv_cpu
cpu_backend         src/backends/cpu_scalar riscv_frontend     src/frontends/riscv
cuda_backend        src/backends/cuda      riscv_metal_integration src/integrations/riscv_metal
metal_backend       src/backends/metal
```

The other 17 are product, aggregate, oracle, and global lanes (`static`,
`build_graph`, `package`, `native_cpu`, `native_oracle`, `riscv_cpu`,
`cairo_cpu`, `cairo_metal`, `aggregate_cpu`, `aggregate_metal`, `deferred`,
`native_cuda_static`, `native_cuda_device`, `native_metal`, `riscv_metal`,
`metal_compile`, `metal_aot`). Their scope is *not* package-derivable — see
residual risks — and they keep selecting through the catalog and the remaining
rules, unchanged.

### The drift

Comparing each package's graph closure against the hand-written rule for its own
prefix. Every difference is a **missing** lane; there were no spurious ones.

| Changed prefix | Lanes the hand list omitted | Why the graph finds them |
|---|---|---|
| `src/backend` | `cairo_cpu_integration`, `riscv_cpu_integration`, `riscv_metal_integration` | reached via `cpu_backend` / `metal_backend`, not declared directly |
| `src/backends/cpu_scalar` | `cairo_metal_integration`, `riscv_metal_integration` | reached via `metal_backend` |
| `src/core` | `cuda_backend` | `cuda_backend` → `backend_contracts` → `core` |

## Design

### The resolver

`scripts/ci_package_graph.py` (220 lines, stdlib only):

- `load_packages(root)` reads every `src/**/package.contract.json`, keyed by
  package name, and **resolves each declared relative dependency path back to a
  package name**. A moved or renamed package fails loudly here rather than
  silently dropping lanes.
- `reverse_closure(packages, seeds)` iterates to a fixed point — terminates on a
  cyclic graph even though the workspace validator rejects cycles separately.
- `lane_packages(policy, packages)` derives lane → package from the lane's own
  `--build-file` argument. A lane pointing at a build file no contract owns is an
  error, because it would silently never be graph-selected.
- `owning_package(path, packages)` — longest-prefix wins, so a nested package is
  never shadowed by its parent. Returns `None` rather than guessing.
- `selection(paths, ...)` returns `(lanes, unowned_paths)`. Unowned paths are
  *returned*, not swallowed: the fail-open decision stays with the caller.

`ci_scope_plan.select_lanes` unions the graph lanes in per path, before the
existing rules and fail-open logic. Nothing was removed from the selection
pipeline.

### Path → package mapping

A path belongs to the package whose contract directory is its longest matching
prefix. Derived entirely from where the 17 contract files sit — there is no
parallel path list to maintain, which was the point.

### Always-run set (explicit)

`always_lanes: ["static"]`, one lane, whose commands are the cheap global gates:

- `zig fmt --check build.zig build_support src tools`
- `python3 -m unittest discover -s scripts/tests -p 'test_*.py'`
- `scripts/check_build_monorepo_baseline.py`
- `scripts/check_source_conformance.py`
- `scripts/check_package_workspace.py` (the 17-package / 51-edge validator)
- `scripts/check_upstream_pins.py`

Plus the always-run workflow bookkeeping jobs, which are not lanes:
`focused-plan` itself (`if:` is event-scoped only, never diff-scoped) and
`focused-verdict` (`if: always()`), the single required check.

### Fail-open rules (bias: when unsure, run more)

| Changed path class | Selection |
|---|---|
| `build_support/**`, `scripts/**`, `.github/**`, `vectors/**`, `third_party/**`, root build files, anything else unmapped | **full matrix** |
| `README.md`, `CONTRIBUTING.md`, `LICENSE`, `docs/**`, `archive/**`, `conformance/**` (`documentation_prefixes`) | always-run set only |
| `autoresearch/**` (`externally_validated_prefixes` — validated by the harness's own workflow, constructs no product) | always-run set only |
| package-owned path | always-run + graph closure + catalog + remaining rules |

`*.md` at any depth inside those prefixes is covered; a `*.md` outside them
(e.g. a new root-level `NOTES.md`) fails open to the full matrix, which is the
correct direction.

### Workflow wiring

The existing shape is kept and I recommend keeping it:

- `focused-plan` (one cheap ubuntu job) emits `linux_matrix`, `macos_matrix`,
  `cuda_required`; the focused jobs consume them via `fromJSON`.
- **`focused-verdict` is the branch-protection anchor** — one always-run job
  that asserts each selected lane passed and each unselected one is genuinely
  `skipped`. This is strictly better than 34 individually-required checks, which
  is why I did **not** convert the matrix into 34 statically-declared jobs with
  per-job `if:` guards. That would be a ~2000-line workflow rewrite for worse
  branch-protection ergonomics.
- Two changes, both additive:
  - **push to main takes the full matrix** (`--full-matrix`), not a scoped
    selection. Post-merge safety net for any selection mistake a PR made, and it
    keeps every lane's compiler cache warm for the next PR.
  - **`--github-summary`** writes a table of all 34 lanes with
    selected/skipped and the triggering path, so a skipped lane is a visible,
    explained decision rather than a job that never appeared. This is the cheap
    substitute for statically-declared skipped jobs.

## Replay evidence

`FULL` = the 30 hosted-eligible lanes (4 of the 34 are `hosted: false` and never
enter a hosted matrix). `BEFORE` = the shipped selection at `191e409f`.
`AFTER` = this branch.

| Case | Paths | FULL | BEFORE | AFTER | AFTER vs FULL | Note |
|---|---|---|---|---|---|---|
| (a) merged PR #125 `78556fe7...191e409f` | 117 | 30 | 30 | 30 | 0% | fails open — `scripts/riscv_poseidon_table_uniqueness.py`, `scripts/check_build_configure_closure.py`, `scripts/tests/test_ci.py` |
| (a′) PR #125, `scripts/**` removed | 114 | 30 | 30 | 30 | 0% | **still** full: `build_support/products/aggregate.zig` and `cairo_support.zig` are unmapped and fail open too |
| (b) notes-only `ceb5b32f` | 1 | 30 | 1 | 1 | **97%** | `static` only |
| (c) riscv-only `e6303646` | 13 | 30 | 9 | 9 | **70%** | no cairo, metal-device, or cuda-device lane |
| (c′) riscv-only `a0e594e6` | 31 | 30 | 9 | 9 | **70%** | same 9 lanes |
| (d) metallib delivery `19026cae` | 2 | 30 | 30 | 30 | 0% | `vectors/**` fails open by design |
| (e) synthetic `src/core/fields/m31.zig` | 1 | 30 | 24 | **25** | 17% | **+`cuda_backend`** — drift fixed |
| (f) synthetic `src/frontends/cairo/air.zig` | 1 | 30 | 8 | 8 | **73%** | no `riscv_*`, no `native_cuda_device` |

The PR #125 counterfactual was checked honestly and the expected answer did not
hold: removing `scripts/**` does not bring it below full, because the same PR
also touched two unmapped `build_support/products/*.zig` files. Both are
correct fail-open triggers.

### Exhaustive safety check

The resolver was replayed over **all 6728 tracked files**, one at a time, old
algorithm vs new:

- **lanes dropped: 0** — no path selects less than it did before;
- lanes added: 110 files, exactly the three drift classes above
  (85 × `+cuda_backend`, 20 × `+cairo_cpu_integration, riscv_cpu_integration,
  riscv_metal_integration`, 5 × `+cairo_metal_integration,
  riscv_metal_integration`).

### Gate content is untouched

Every lane's `commands` array in `ci-touchpoints-v1.json` is byte-identical to
`191e409f`. Only `rules[]` (which prefixes trigger which lanes) changed. Verify
with:

```
git diff 191e409f -- conformance/ci-touchpoints-v1.json | grep -c '"commands"'   # 0
```

### Validation run

- `scripts/tests/test_ci_package_graph.py` — 28 tests (synthetic diamond graph,
  live repository graph, plan integration, fail-open, determinism)
- full `python3 -m unittest discover -s scripts/tests` — 1089 tests, OK
- `python3 scripts/check_source_conformance.py` — no new violations
- `python3 scripts/check_package_workspace.py` — PASS (17 packages, 51 edges)
- `zig fmt --check build.zig build_support src tools` — clean
- `actionlint .github/workflows/ci.yml` — 13 findings before, 13 after,
  identical set. All pre-existing (unknown self-hosted runner labels,
  release-gated `if: ${{ false }}` jobs, `workflow_dispatch` input typing).

## Governance callouts

**The orchestrator and user must review the workflow diff line by line.**
`.github/**` and the conformance CI-plan documents are human-review territory.

### Policy documents this change amends

1. **`conformance/ci-touchpoints-v1.json` — AMENDED (authoritative; must stay
   consistent with the workflow).** This is the live input to
   `ci_scope_plan.py`, not documentation, so it cannot be left stale. `rules[]`
   goes 29 → 35 entries: 18 package-owned prefixes shed the package lanes the
   graph now derives, and rules with mixed package/non-package prefixes were
   split so non-package prefixes keep their original lanes verbatim.
   `lanes`, `always_lanes`, `product_scope_lanes`, `documentation_prefixes`,
   and `externally_validated_prefixes` are unchanged.
   `test_policy_carries_no_hand_written_package_lane_for_owned_prefixes` fails
   if a graph-derivable lane is ever restated by hand again.

2. **`conformance/build-architecture-ci-plan-v1.json` — NOT TOUCHED, and not
   superseded.** Despite the name it is not the PR-lane plan: it is the
   `architecture-authority` session's per-role command plan (BG-00…BG-14
   evidence phases), driven by a `workflow_dispatch`-only workflow that never
   runs on a PR. It has no lane concept and no overlap with lane triggering.
   Deliberately left alone.

3. **`.github/workflows/ci.yml` — AMENDED, 2 hunks, both in `focused-plan`'s
   "Select affected product lanes" step.** No job was added, removed, renamed,
   or re-guarded; no `needs`, `if`, `runs-on`, `permissions`, or action pin
   changed. Review targets: the `SCOPE_ARGS` array and that `--full-matrix` is
   reached on push-to-main and *only* there.

4. **Autoresearch workflows — untouched**, as instructed:
   `validate.yml`, `judge.yml`, `promote.yml`, `automerge.yml`, `record.yml`.
   No change to the autoresearch CLI, ledger, MANIFEST, or `vectors/**`.

## Residual risks

1. **17 lanes are not package-derivable.** Product, aggregate, oracle, and
   global lanes still select via the catalog and the surviving hand rules. The
   same drift class can therefore still exist *there* — this increment neither
   fixed nor measured it. A follow-up should extend the derivation to product
   lanes by reading each product's declared module roots from the catalog and
   mapping them to packages.

2. **Cache warmth on skipped lanes.** A lane skipped across many PRs restores
   from an older `restore-keys` prefix and pays a cold-ish first build when it
   is eventually selected. The full matrix on push to main is the mitigation and
   is why it is worth its cost.

3. **`focused-plan` is a single point of failure** — if it fails,
   `focused-verdict` fails closed (`test "$PLAN_RESULT" = success`). Correct,
   but it means a resolver bug blocks all PRs. The 28 new contract tests run in
   the `static` lane, which is always selected.

4. **The 51-edge count is pinned in a test.** Adding a legitimate dependency
   makes `test_workspace_shape_is_pinned` fail. That is intentional — the
   closure consequences should be reviewed — but it is a friction point worth
   naming.

5. **`pr6-supremacy.yml`'s `contract-smoke` still runs unconditionally on every
   PR** (~15 min). Out of scope here; the obvious next reduction.

6. **`vectors/**` fails open to the full matrix**, so metallib and trace-vector
   deliveries pay for everything (case (d)). Correct under the stated bias, but
   if vector deliveries are frequent it is the highest-value place to add a
   *narrow, deliberately reviewed* mapping.

7. **Not executed in CI.** Everything above is local replay against historical
   diffs plus static validation. The first real hosted run is the PR itself, and
   the push-to-main full matrix is what will confirm the post-merge path.

## Human-in-the-loop

A human reviews this before use. The workflow and conformance-policy diffs in
particular need line-by-line review before merge.
