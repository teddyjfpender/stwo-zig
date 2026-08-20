# P-003 quotient exact-work receipts

**Date:** 2026-08-15; reconciled 2026-08-20

**Status:** CPU and real-device Metal producer acceptance complete; quotient
preparation and row execution are part of the schema-9 16/16 closure

## Boundary

Quotient work is split into two independently planned and completed sites:

- `quotient_sample_preparation` owns random-power advances, conjugate-line
  construction, per-batch linear-term sums and determinants, and periodicity
  point construction;
- `quotient_row_execution` owns the selected numerator schedule, denominator
  inversions, bit-reversed domain construction, combined-plan construction,
  and row finalization.

Preparation is published only after the provider has successfully constructed
all plans, constants, workspaces, and scratch. Row execution is published only
after a contiguous full-domain CPU traversal or a successful Metal command
whose returned execution geometry passes host validation. Destroying a
profiled provider before row completion marks the request incomplete.

## Exact schedules

For `S` expanded samples, `D` distinct batches, `p` periodicity samples, and
`d` executed periodicity doubles, preparation reports:

```text
A = 5S + D + 2(d + p)
M = 6S + 2D + 4(d + p)
I = 0
```

The row receipt retains the fixed `A=5D, M=4D` contribution per row and adds
the schedule actually selected:

- scalar streaming: one QM31 numerator add per combined view and row;
- bounded scalar: one QM31 multiply/add per direct contribution, with the
  explicit four-coordinate compact-group schedule;
- bounded batched: exact planar M31 products/additions, including source-block
  reuse for lifted columns and compact groups;
- Metal combined, raw direct, segmented, and grouped-partial paths: a distinct
  path tag plus the native numerator geometry returned after command
  completion;
- host batch inversion: the selected classic, striped, or AArch64 packed CM31
  formula for each actual chunk;
- Metal direct inversion: exactly one CM31 inversion per row and sample batch;
- domain construction: host `toPoint` additions, per-worker bit-reversed walk
  initialization/delta tables/advances, or device `circle_pow` work on a real
  cache miss;
- combined-plan construction: four M31 additions and four M31
  multiplications per source-cell contribution.

Checked `u64` arithmetic is used throughout. Path, row, batch, contribution,
view, group, and plan-source geometry are bound before publication.

## Performance isolation

Ordinary proof requests never traverse the tally schedules. Contribution and
source-cell geometry walks are guarded by the work recorder, Metal receives a
null receipt pointer, and the configured Metal function is specialized by a
compile-time `capture_work` flag. The device performs its receipt-only row/group
walks only when profiling is requested. No scalar field primitive gained a
counter branch or atomic.

## Source ownership

Backend-independent authority:

- `src/prover_api/work_profile.zig`
- `src/prover/pcs/quotient_work_profile.zig`
- `src/prover/pcs/quotients/lazy_provider.zig`
- `src/prover/pcs/quotient_tile_executor.zig`
- `src/prover/pcs/quotient_ops.zig`
- `src/prover/pcs/scheme.zig`

Metal completion authority:

- `src/backends/metal/runtime/abi.h`
- `src/backends/metal/runtime/bindings.zig`
- `src/backends/metal/runtime/quotients.m`
- `src/backends/metal/runtime/polynomial_operations.zig`
- `src/backends/metal/runtime.zig`
- `src/backends/metal/commit_backend.zig`
- `src/backends/metal/runtime/resident_fri_transaction.zig`
- `src/tests/riscv/metal_backend_test.zig`

Inventory and closure authority:

- `src/prover_api/work_profile_inventory.zig`
- `scripts/typed_air_p003_completion.py`
- `scripts/tests/test_typed_air_p003_completion.py`
- `design/typed-air/artifacts/p003-work-profile-closure-v1/matrix-v1.json`

## Acceptance evidence

The list below records the original 2026-08-15 checkpoint:

Green on this checkout:

- focused quotient check-only Debug build;
- focused quotient executable Debug test, including preparation-before-row
  lifecycle and materialized/lazy output parity;
- Objective-C runtime syntax check for the complete amalgamated Metal runtime;
- 23/23 P-003 matrix and source-authority Python tests at the settled quotient
  schema.

Those pending Metal gates have now run. The terminal real-device Debug product
gate passed 3/3 after accepting 118 authenticated AOT exports and AOT/JIT
parity. Relation, quotient preparation, and quotient row execution each
planned and completed exactly once before the proof independently verified.
The gate took 305.58 seconds and reported 4,967,989,248-byte maximum RSS. It did
not emit separate proof, transcript, work, or shell identities, so this note
does not infer them from CPU evidence.

The canonical producer matrix now recomputes CPU, Metal, and joint coverage to
16 complete / 0 partial / 0 absent over inventory schema 9's 23 sites. Its
matrix and inventory SHA-256 values are
`b1eef5ccf8405de9373c11b8fe9bd505a331add0601ab1904a1b038df0ee24d1`
and `13807efba664c2abc49325a80d8bc67c15896e7250ea48416e0d58e0f029982f`.
This closes P-003 producer acceptance, not R-006: installed V4 smoke and the
normative 1/2/4/max-worker scaling receipt remain absent.
