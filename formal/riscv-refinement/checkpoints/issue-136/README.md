# Issue 136 FV-1/FV-2 continuation checkpoint

**Checkpoint date:** 2026-07-31

This directory preserves the complete in-progress sources at the point the
FV-1/FV-2 work was checkpointed onto `main`. These files are continuation
material, not publication evidence. They deliberately live outside the
`RiscvRefinement` Lake library and outside the generated-Sail bridge runner, so
an unfinished proof cannot make the default build red or increase a receipt's
proved-opcode count.

The default Lake tree retains only the last kernel-clean local-AIR prefixes:

- `RiscvRefinement/Publication/TeamB/LoadStore.lean` ends after
  `fixedConsequences`; and
- `RiscvRefinement/Publication/TeamB/MulhDiv.lean` ends after
  `baseConstraintRootZeroAt` in the division section.

The generated-Sail publication sources are checkpoint-only because the current
carried receipt still binds the original two-normalizer `Pilot.lean` source.
`Pilot.fv1-kernel-clean.lean` preserves the expanded normalizer/step base and
`Composition.kernel-clean.lean` ends after
`generated_full_step_retirement_composition`. Keeping them here prevents an
unregenerated receipt from silently changing meaning. The snapshots here
contain everything beyond all of those cuts.

`Multiply.publication-wip.lean` is also preserved here. Its source reaches the
public MUL wrapper, but a clean default build remained CPU-bound after more
than 40 minutes, so it is not suitable for the canonical import or a receipt
until that elaboration is factored into bounded proof terms.

## Exact handoff

### Generated Sail composition

Kernel-clean work includes the exact decoder certificate, pointwise successful
result observer/eraser, factored active runner, trace erasure, generated
postlude, later-state preservation, and
`generated_full_step_retirement_composition`. The validation was serialized;
the largest cached base compilation used about 2.20 GB RSS and the factored
layers then compiled in under three seconds each at about 1.27 GB RSS.

`Composition.publication-wip.lean` continues with the neutral opcode selector
and the first public FENCE composition. `FENCE_accepted_air_refines` is
structurally assembled, but its `GeneratedFenceExecuteSuccess` record does not
elaborate yet: the generated `sail_barrier` labels are auto-implicit,
universe-polymorphic placeholders. Annotating the right-hand sides as
`SailM ExecutionResult` did not determine those universes. This is the next
FV-1 action. It must be resolved without weakening the exact generated-clause
claim; instantiating the erased barrier payloads to a concrete type is one
candidate, but requires an explicit review of what information the generated
concurrency interface preserves.

No public 46/46 generated-Sail publication theorem or receipt is established
by this checkpoint.

The staged receipt integration is preserved verbatim under
`receipt-publication-wip/`. It is intentionally not executable from the
canonical `scripts/` package: that version assumed all 46 publication
theorems existed and therefore correctly conflicts with today's carried
receipt. The canonical `scripts/riscv_refinement_publication.py` contains the
fail-closed target validator, and its regression suite requires the current
carried receipt to be rejected as publication evidence.

### Load/store

The canonical file is kernel-clean through `fixedConsequences` (17.30 s,
1.426 GB peak RSS for the source-prefix check; 15.83 s and 1.555 GB for the
canonical Lake build). That prefix includes exact production-node evaluation,
direct equations, bound-aware memory-address composition, exact fixed lookup
projection, sign witnesses, aligned-quarter interpretation, and the fixed
semantic bounds used to exclude the M31 alias cases.

`LoadStore.publication-wip.lean` adds clock validity, next-PC binding, the
reverse bridge, and public opcode wrappers. The latest clock edits project the
admission clock bounds before `omega`, locally increase recursion depth for
the source/destination clock calls, and use a shallow node-317 projection.
Those latest edits have not yet been kernel-validated. Resume with one serial
prefix check through `nextPcResultOfBindings`, then proceed to
`loadStoreHoldsOfAccepted` and the eight public wrappers.

### High multiplication and division

The high-multiply portion and the division evaluator/fixed-projection pipeline
are retained at the canonical path. The last confirmed division boundary
before direct-equation assembly completed in 44.88 s at 1.524 GB RSS; the
truncated canonical module subsequently completed its Lake build in 40.38 s
at 1.582 GB RSS.

`MulhDiv.publication-wip.lean` contains the remaining division proof and public
wrappers. A flat roughly 60-field `DirectEquations` constructor overflowed the
default process stack. Splitting it into eight `extends` parents still
flattened back to one large constructor. The snapshot's latest experiment uses
eight ordinary nested records with at most eight opaque proofs each and updates
downstream projections, but the combined prefix still stack-overflowed. The
next action is to compile only through each chunk boundary to identify whether
the overflow is in one chunk theorem or the final eight-field assembly; do not
raise the thread stack as a substitute for making the proof term reviewable.

### Other local AIR work

`Publication/TeamB/Shifts.lean` completed a full serialized kernel check
(a direct source check took about 141 s below 2.0 GB RSS; a clean Lake artifact
build took about 286 s). The production program identity/fixed-table inventory
and the already-landed opcode-family proofs remain part of the default Lake
tree. Their existence does not promote the aggregate 46-opcode claim.

The MUL continuation is non-gating for a different reason from division: the
source did not produce an error, but its monolithic elaboration did not finish
within a practical default-build window. Factor and validate it before moving
it back under `RiscvRefinement/Publication/TeamB/`.

## Promotion rule

The checkpoint snapshots must never be imported by the root module or counted
by a receipt. Promotion requires, in order:

1. move a finished declaration back to its canonical module;
2. for the generated bridge, promote the enhanced Pilot and Composition
   sources together rather than changing the receipt-bound Pilot alone;
3. compile the complete canonical modules with the default stack;
4. compile the neutral root import and run the proof-escape/axiom audit;
5. regenerate the generated-Sail and local publication receipts from the live
   pinned Sail toolchain; and
6. require the evidence builder to report exact 46/46 theorem identities from
   audit output, not from the metadata inventory alone.

Until all six steps pass, the authoritative values remain
`whole_frontend_verified = false` and `proof_system_soundness = false`.
