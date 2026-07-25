# Session 16: SN2 resident mixed-height trace commitment

Date: 2026-07-25

## Question

Can the authenticated 58-entry Cairo base-writer schedule target its final
resident main-trace storage and cross the first mixed-height CUDA commitment
boundary without expanding every column to the largest component height?

## Result

Yes, for the main-trace destination and commitment boundary.

The resident bridge now:

1. maps every canonical schedule ordinal to its exact packed main-column span;
2. coalesces only contiguous columns with the same trace height;
3. performs the inverse circle transform in place for each packed cohort;
4. extends each cohort directly to its own commitment height;
5. absorbs the cohorts in canonical column order through the shared lifted
   progressive Blake2s builder;
6. reduces the sealed Merkle layout on the proof stream; and
7. copies the resulting root into its resident root slot with one
   device-to-device copy.

No dense maximum-height trace matrix, host copyback, runtime compilation, or
CPU fallback is present in this path.

`Bound.execute` uses the real common CUDA stage implementations:

- `stages.transform.Native`;
- `stages.commitment.Native`; and
- `native_cuda/common/commit_tree.zig`.

`executeWith` exists only as a dependency-injection seam for the focused
contract test. The production entry point is therefore an executable CUDA
stage adapter, not only a structural plan.

## Residency

Request-local slots retain the lifetime aliasing from the authenticated
resident plan. Twiddles and other process-cache values use a separately routed
fixed-address arena. Process-cache requirements are deliberately assigned the
whole proof lifetime, even when their in-request use intervals do not overlap;
immutable values cached across requests must never overwrite one another.

The routed provider selects the arena from the authenticated slot descriptor
and rejects missing or incorrectly sized extents. Callers cannot choose a
storage class.

## Launch-count language

The trace schedule contains 58 logical component entries and 57 launch owners.
`partial_ec_mul_generic` is a member of the `ec_op_builtin` composite, so it
does not own a second launch.

**This is not a count of physical CUDA kernel launches.** A launch owner may
execute several kernels. The native EC composite alone executes four physical
kernels, and transform, commitment, fixed-table, memory, and recorded-witness
owners have their own stage-specific launch cardinalities.

## Evidence

The focused deep gate compiled the exact SN2 composition and fixed-table
geometry and proved that all 58 writer spans cover the complete main tree:

```text
SN2 trace commitment compiles all 58 writer spans into compact mixed cohorts ... OK
mixed trace commitment transforms packed cohorts and copies only on device ... OK
All 21 tests passed.
```

The residency policy gate passed:

```text
process cache slots never alias across request-stage lifetimes ... OK
All 20 tests passed.
```

Repository guards:

```text
source conformance: 5 explained legacy findings
(5 active_native_backend, 0 deferred_todo), no new violations
git diff --check: clean
```

## Explicit remaining boundary

This session does **not** claim a complete trace-generation stage. The
following writer execution inputs are not yet materialized in the resident
plan:

- recorded-witness input and output pointer tables;
- execution-table pointers and strides;
- lookup-word and sub-word output arenas;
- multiplicity-table pointer sets;
- fixed-table and memory-writer request inputs;
- the native EC composite workspace and its member aliases; and
- the launch loop which prepares and executes all 57 launch owners.

Accordingly, the bridge exposes the exact resident destination for every
writer, but it does not yet invoke those writers. It also does not own stage
begin/end, transcript initialization/root mixing, the interaction or
composition commitment, or terminal proof assembly.

The next admissible step is to add those authenticated writer-specific slots
and launch bindings, populate the packed main trace in one proof transaction,
then run this real commitment path on an H100 before attaching interaction and
composition execution.
