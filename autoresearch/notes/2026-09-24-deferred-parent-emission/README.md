# Deferred native-parent emission

The previous goal turn made verified build-cache progress. This checkpoint returns
to persistent planning and direct final-layout generation. It is a production-path
refactor toward shared aggregate emission, **not completion of copy elimination**.

## Implemented

`State.plan` constructs the validated composition/DEEP/FRI graphs, transcript plan,
links, roots, context and complete hash layout before allocating final hash columns.
A `Planned` owner retains those resources and borrows the admitted capture through
emission or destruction. `Planned.emit` consumes that owner on success or error;
destruction is idempotent and repeated emission returns `ConsumedParentPlan`.
Existing `State.init` delegates to plan/emit, preserving the caller API.

The two-child tree now runs bounded planning and emission waves. Both child layouts
are available before either emission starts. The caller-owned pool still admits
at most one helper plus the coordinator. Both waves drain all submitted work before
handling failure or releasing borrowed nodes and allocator resources. All successful
partial plans and witnesses are destroyed on failure. The final aggregate still
uses the existing namespace relocation and bounded consuming column join.

## Qualification

`lifecycle.log`: seven canonical Metal parent checks pass at q70/PoW26, including
independent verification. `STWO_RISCV_PARENT_PLAN_LIFECYCLE=1` also checks:

- Abandonment before emission and repeated destruction, with exact tracked cleanup.
- Successful emission consumes the plan and preserves its declared layout.
- Repeated emission is rejected after success and abandonment.
- Four allocation failures across emission consume the plan and release every
  tracked byte, including partial column/trace ownership.

The fixture records 167,173 allocations during emission. This is a useful scratch
reuse target, not a time attribution or evidence of a speedup by itself.

`tree.log`: seven canonical four-leaf/two-level tree checks pass. This includes
bounded worker use and reuse after a forced failure. All three aggregate artifacts
independently verify; sizes remain 845993/849496/889364 bytes and hash-device coverage
remains 8/8. Parameters and ABI-24 authenticated Metal bundle are unchanged.

Frozen ABBA measurements are in `results.json` and `summary.json`; the driver checks
independent verification, sizes, canonical parameters and allocation bounds in every
run. The control is the prior qualified covered-batch quotient binary. It predates
the build-closure bookkeeping fix; that fix changes compilation identity but not
runtime calculations. `binaries.json` pins both binaries. Changed-source snapshots
are not a clean-checkout reproduction of the surrounding dirty workspace.

## Remaining direct-emission work

The existing child path already emits G/XOR witnesses into per-child final columns;
there is no full logical G/XOR-row heap staging to remove there. The missing piece
is generating both children directly into the aggregate's shared columns, avoiding
the subsequent copy. This phase split supplies both layouts before allocation.

The next implementation needs explicit borrowed partition views with logical row
bases, single aggregate ownership of the backing columns, and namespace relocation
that respects those bases. It must preserve independently derived fixed metadata,
lookup multiplicities, non-overlapping writes, padding, final admission and all
failure cleanup. Do not pass an incomplete or shared-owned child `Prepared` to the
ordinary prover or destructor. Other cohorts can continue through the existing join
while G/XOR storage transfers exactly once after complete aggregate admission.

No new ZisK proving comparison, CSP measurement or 10x tree result is claimed.

## Matched observation

ABBA, two samples per arm, same M5 Max/ReleaseFast/eight workers/ABI-24 bundle:

| Metric | Control | Deferred candidate |
|---|---:|---:|
| Complete tree median | 38.67390s | 38.90060s |
| Root preparation median | 4.38705s | 4.43208s |
| Routed peak | 26,459,992,736 B | 26,459,992,736 B |
| Physical peak | 39,162,208,160 B | 39,162,060,608 B |

Total is 0.59% higher, within this run's observed variability; no speed gain or
process-memory gain is established. All twelve timed aggregate artifacts
independently verify with unchanged sizes and canonical parameters. Retained as
the explicit planning/emission ownership boundary needed for shared-layout work,
not as a completed copy-removal or performance result.
