# ADR-0019 — Authenticated witness and relation execution plans

**Status:** accepted
**Date:** 2026-08-05

## Context

H-003 and H-004 authenticate which typed Poseidon2 values occupy the current
426 temporary slots, but a layout receipt does not generate witness rows or
LogUp claims. Those consumers cross a stronger boundary: they write committed
storage and transcript-bound interaction data. A count-correct evaluator, a
wrapper around the production implementation, or a plan that is revalidated
only at construction can silently execute corrupted instructions after an
ownership transfer.

The current main trace is column-major, bit-reversed, and padded to a power of
two. Resident backends reserve its final 445-column storage before generation.
Creating another complete trace and copying it would double the widest live
allocation. Relation generation must preserve four signed events, their two
pairs-batched cumulative columns, eight committed M31 coordinates, and two
claims. The narrow Merkle path may carry its one-lane output to interaction
generation, but that shortcut is not evidence that the value is the permutation
output; closure against the separately committed row supplies that binding.

## Decision

The Poseidon compatibility pilot uses two separately versioned, authenticated
shadow plans.

The witness executor:

1. revalidates the complete H-003 plan and H-004 owned binding before compiling;
2. compiles only the canonical H-002 output closure into owned, topologically
   ordered field instructions and explicit input/materialization slot maps;
3. retains the program, materializer, activation, compatibility, function,
   input, output, and physical-binding identities;
4. owns reusable field scratch and borrows no arena, plan, or binding memory;
5. reauthenticates a transported executor by reconstructing the canonical
   compiled projection, not merely by comparing copied envelope fields;
6. validates its instruction projection and all destination/input ranges before
   the first write;
7. rejects overlapping input, destination, executor, instruction, or scratch
   storage before mutation; and
8. then allocates nothing, cannot return an error, zeroes padding, evaluates
   logical rows, and writes directly to the caller's bit-reversed final
   column-major storage.

One executor owns one mutable scratch vector and is intentionally non-reentrant.
Parallel generation uses one executor per worker; immutable instruction sharing
may be introduced later only with separately owned scratch and unchanged
authentication.

The relation plan:

1. is sealed to the same H-002/H-003/H-004 authority and reauthenticates once at
   each public bulk-use boundary;
2. fixes the existing four request events in order: full input, narrow output,
   wide output, and input/output I/O;
3. fixes their signed enabler/mode formulas, relation domains and versions,
   ABI arities, semantic widths, tuple projections, and absent access ordinal;
4. fixes batches `(input, narrow_output)` and `(wide_output, io)`, yielding two
   cumulative sums and eight committed interaction columns;
5. uses allocation-free private row kernels after bulk authentication; and
6. validates complete entries, interaction geometry and values, and public
   claims against a regenerated authenticated result.

The carried narrow output remains explicitly untrusted as permutation
semantics. A mismatched carried value must fail cancellation with the Merkle
counterpart and fail validation against interaction data derived from the
committed main row.

Both plans are shadow compatibility machinery. They do not become production
authorities, change the proof protocol, or justify removing the handwritten
path until H-007 exercises their committed artifacts in real CPU and Metal
proofs and the separate production-activation decision is accepted.

## Consequences

- Witness evaluation has no per-row allocation and no duplicate full trace.
- Every fallible witness check happens before caller-owned storage changes.
- Relation authentication is amortized once per bulk trace rather than once per
  row.
- Corrupt executable structure is distinguishable from a valid external
  binding envelope.
- Exact current layout, padding, event, batch, interaction, and claim order stay
  explicit protocol data.
- The executor's mutable scratch makes concurrency ownership honest rather than
  hiding a race behind a logically pure API.
- Compatibility evidence still makes no proving-speed or production-soundness
  claim; those require H-007 and the ordinary release ladder.

## Rejected alternatives

- **Call the production generator from the typed adapter:** rejected because it
  would test an API wrapper, not single-source witness execution.
- **Generate row-major temporary rows and transpose/copy:** rejected because it
  duplicates resident storage and weakens direct-to-final-memory discipline.
- **Trust only the H-004 count or external identity:** rejected because compiled
  instructions and slot maps can drift independently.
- **Authenticate on every row:** rejected because validation allocates and is a
  whole-plan trust boundary, not row work.
- **Share one executor across workers:** rejected because its scratch is mutable
  and would introduce a data race.
- **Treat a carried Merkle output as typed permutation evidence:** rejected
  because the relation closure and committed permutation row are the proof.

## Revisit when

H-007 produces real generated-artifact proof evidence, production activation is
proposed, a worker-safe immutable instruction owner is needed, interaction
generation gains caller-owned final storage, or a future compatibility policy
changes any event, batch, column, or claim identity.
