# ADR-0039 — Authenticated auxiliary claims for recursive shared providers

**Status:** accepted
**Date:** 2026-08-14

**Classification:** recursion soundness boundary; changes the row-18 input
profile and therefore requires a new composition-circuit seal

## Context

The universal roster publishes one claimed LogUp sum per component.  That is
the correct global-closure interface, but the shipped general-mode Poseidon2
provider owns two independently constrained cumulative columns: one for the
`poseidon2` relation and one for `poseidon2_io`.  Its native verifier evaluates
430 direct constraints followed by two separate LogUp recurrence constraints.

The fixed child transcript carries the roster total at row 34.  Replaying the
native component from that total alone is impossible because the Horner
composition weights the two recurrence roots at different powers.  Choosing a
split as a graph constant would make the circuit proof-specific.  Replacing
both roots with a single summed recurrence would be a weaker AIR than the
native verifier and would permit errors in the two committed cumulative
columns to cancel.

## Decision

The recursion composition input profile has 38 secure claimed-sum inputs:

- indices `0..35` are the canonical universal-roster totals;
- index `36` is the native Poseidon2 `poseidon2` partial claim; and
- index `37` is the native Poseidon2 `poseidon2_io` partial claim.

The two tail values use the existing authenticated recursion
`claimed_sum(item, word)` source class.  They are not part of the 36-row global
sum and do not change the fixed proof transcript's roster.  A successful child
verifier publishes them transactionally beside its capture under a
domain-separated seal.  The child composition authority binds their canonical
limbs to input nodes 36 and 37 and requires their sum to equal fixed-wire row
34.  The row-34 graph then invokes the shipped generic Poseidon evaluator and
constrains both native recurrences in their original order.

Row 35 has a single claim and needs no auxiliary input.  It is replayed through
the shipped range-table interaction evaluator.

The composition producer and every trusted profile using the old 36-input
shape receive new format/profile identities.  Compatibility code may read the
old shape for diagnostics, but full parent-proof admission fails closed unless
the exact 38-input authority is present.

## Consequences

- Recursive verification is equation-identical to the native Poseidon
  provider; no cancellation-prone aggregate recurrence is introduced.
- The graph gains eight M31 input words.  This is negligible beside captured
  proof samples and avoids adding trace columns to the 36 components.
- The two partials remain explicit public verifier inputs even though global
  relation closure uses only their sum.
- Mutating either partial, swapping their order, retaining a stale seal, or
  changing the total while preserving an unauthenticated split must reject.
- V1 profiles and graph seals cannot be silently reused.

## Rejected alternatives

### Embed both partials as graph constants

Rejected because it produces one circuit identity per proof and lets detached
proof metadata become constraint authority.

### Verify only the summed recurrence

Rejected because it is not the native AIR and permits cross-column error
cancellation.

### Infer the split from the composition value

Rejected because an existential split can absorb the very composition error
the circuit is meant to detect.

## Revisit when

Revisit only if the native provider itself adopts a reviewed single-total
chained recurrence and native/recursive differential tests prove identical
constraint order and composition values.
