# ADR-0035 — Proof-carrying program control targets

**Status:** accepted
**Date:** 2026-08-11
**Amends:** ADR-0031's closed sequential-retirement target grammar

## Context

Sequential retirement originally admitted only `pc + 4` and the aligned JALR
target. JAL and conditional branches need non-sequential targets without a
caller-selected cast or an extra AIR equality. JAL derives its target entirely
from the authenticated program tuple. BRANCH_LT instead inherits a physical
`branch_target` column and an existing production root that binds that column
to the selected taken/fallthrough polynomial.

## Decision

Admit two closed, versioned proof forms.

`programControlTarget` constructs exactly one of:

```text
jump:   current_pc + offset
branch: current_pc + offset * condition + 4 * (1 - condition)
```

The named program request must carry the same PC, offset, and liveness. The
branch form also names the exact Boolean constraint for `condition`. The
resulting `.pc` alias may occur only in field zero of the adjacent state emit,
whose consume carries `current_pc` and whose clock is the closed next-clock
derivation.

`committedProgramControlTarget` authorizes an existing physical `.pc` target.
It binds the physical current/target columns, their compatibility scalar
views, the branch program request, the decision bit and Boolean constraint,
and the exact ungated semantic root:

```text
liveness_polynomial *
    (committed_target_polynomial - selected_target)
```

The subtraction order is canonical. The target scalar view, difference, and
root form a closed three-node use chain; the physical target has exactly one
legal use, as field zero of the adjacent state emit. The matching program
request must precede that retirement and use the consumed PC and identical
liveness. Mutation, omission, duplication, generic expression use, or a
sign-equivalent but differently shaped equality rejects.

Both forms have zero proof-protocol cost. They add no physical column, direct
constraint, lookup, witness operation, transcript draw, or proof material.
They add authenticated compiler metadata and allocation-free validation only.

Canonical identities advance without changing prior byte domains:

| Proof capability | Digest | Manifest |
| --- | --- | --- |
| derived program target | v9 | format 11 / schema 10 |
| committed physical program target | v10 | format 12 / schema 11 |

Older encoders reject the newer capability explicitly. Existing v1-v9
semantic digests and v3-v11 manifests retain their prior meaning.

## Consequences

JAL can retire to its exact program-derived target without inflating its AIR.
Branches with inherited target columns can make those columns trustworthy
without duplicating the production equality. The semantic digest now commits
to every premise and compatibility view; source spans remain diagnostic and
are excluded from semantic identity.

## Rejected alternatives

- A general `.felt -> .pc` cast: it would authorize arbitrary state targets.
- A caller-provided next PC: it restates the claim without evidence.
- Adding another target equality: it increases AIR and duplicates a shipped
  root.
- Accepting algebraically equivalent shapes: it weakens canonical identity and
  broadens the validator's trusted grammar.
- Reusing v9/v11 for committed targets: older consumers would silently accept
  metadata they cannot interpret.

## Revisit when

Revisit only if a more general refinement system preserves exact program/root
authentication, single-use state confinement, frozen identities, and the same
zero-protocol-cost boundary.
