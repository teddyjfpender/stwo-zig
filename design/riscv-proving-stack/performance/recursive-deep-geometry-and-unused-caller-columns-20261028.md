# Recursive DEEP geometry and unused caller columns

## Authority of the input lane

`pcs_deep_circuit_circuit.Profile.validate` is the sample-aware authority. It
checks every committed column against the maximum field domain, and every
sampled column against the FRI lifting domain. A column whose layout is `none`
may have a larger committed domain: the native verifier's
`computeLiftingLogSize` also excludes columns with no samples. Such a column
contributes no DEEP quotient term, but remains in the commitment, input routing,
Merkle opening, and profile identity.

The lower `pcs_deep_input_witness_reference.LaneProfile` has no per-column
sample layouts. Its purpose is to describe input coordinates for an already
selected arithmetic graph. Its validator therefore bounds committed domains
by `MAX_LOG_SIZE`, rather than incorrectly treating every column as sampled.
It is not an independent PCS verifier and cannot certify that a sampled column
has valid quotient geometry.

The reviewed authority paths are:

- `pcs_deep_circuit_build.build` validates the full profile before construction.
  `pcs_deep_circuit_prepared.Prepared.init` builds that graph internally and
  retains it privately. `Circuit.validate` and evaluation validate the full
  profile again, including its identity and input bindings.
- Current B6 native, provider, caller and PAGE preparation creates that full
  DEEP graph from original component masks. Captured input validation also
  invokes the full profile validator. Cold fixed compilation derives the same
  graph independently; the final receiver pins the resulting key.
- The detached path in `detached_fri_core_part_11` explicitly validates its
  private PCS `Prepared` before lowering its lane profile. The original binary
  outer-source path obtains lane profiles and graphs from the captured owner's
  private PCS `Prepared` objects.
- Generic `pcs_deep_input_witness.Reference.authenticate` and heterogeneous
  `fri_rows_authority_heterogeneous_v2` accept graph/binding inputs. They check
  input shape, graph structure, exact identities and cross-component routing;
  they do **not** independently compile or certify native PCS semantics. Their
  program identities bind the exact graph and all committed column logs.
  Callers must independently admit that program or key. A caller-generated
  checksum alone is not proof authority, with either the old or new bound.

No production acceptance path was found that obtains a valid original DEEP
graph for a sampled column above the lifting domain through the lower lane.
The public generic compilation APIs remain conditional on independently
selected program authority; this review does not promote them to standalone
verifiers.

## Exact Keccak masks

The original caller-fused verifier uses a current/+27 pair at the common
composition step for its shared Keccak state. Its column can have a smaller
physical trace domain. This is distinct from a current/+27 pair at the physical
column step.

Layout tag 6 retains the physical-step rule: an explicit mask log must equal
the committed column log minus FRI blowup. New tag 7 requires an explicit mask
log equal to the common lifting log minus blowup. Both keep ordered offsets
`{0, 27}`. Original component masks select the tag; proof values cannot choose
it. Capture validation checks the exact two points at that selected step.

The focused ReleaseSafe differential gate compares both layouts with native
`pcs.quotients.friAnswers`, including an unopened committed column at log 14
with FRI lifting log 7. Both match recursive DEEP evaluation. Mutating a sample,
substituting the other step, changing the mask log, omitting tag 7's explicit
mask, marking the oversized column as sampled, or exceeding the maximum
committed domain is rejected. The legacy profile digest remains unchanged.

## Measured caller census and architectural opportunity

The genuine original-mask fixture contains one SHA call and one Keccak call.
These are geometry counts, not proving-time measurements:

| Original trace columns | Columns | Raw field cells |
| --- | ---: | ---: |
| Sampled by the caller-fused verifier | 10,799 | 307,752 |
| Not sampled by the caller-fused verifier | 4,340 | 103,062 |
| Total | 15,139 | 410,814 |

FRI blowup log is 1. Unsampled columns account for 28.67% of column positions
and 25.09% of raw cells. At four bytes per field element, their twofold extended
evaluations represent approximately 0.786 MiB in this tiny fixture, versus
3.134 MiB for all listed trace evaluations. The largest unsampled raw log is
13; the sampled maximum and composition mask log are 7. These ratios cannot
be extrapolated to Ethereum blocks without a larger opcode/caller census.

They are **not automatically removable columns**. The caller-fused proof
borrows the arithmetic caller's original fixed and main commitment trees and
requires the exact same first roots. Columns unused by the fused relation
verifier can still be essential to arithmetic correctness. Removing them from
the existing tree changes its root and breaks that shared witness binding.
Even unopened columns still participate in authenticated Merkle leaf hashing.

The sound architectural direction is to combine caller arithmetic semantics
and its program/state/table/memory relations in one proof, analogously to the
new native partitioned relation. Derive a complete union of original symbolic
equations and lookup entries, bind every physical claim, and commit the shared
fixed/main witness once. This removes the second verifier and its repeated
commitment/opening checks without pretending its arithmetic-only columns are
unused globally. A separate compact projection would require an explicitly
proved equality relation to the original committed witness, which may cost
more than it saves.

If all unsampled cells could be eliminated from an isolated fused representation
without introducing replacement costs, the geometry ceiling in this fixture
would be a 25.09% reduction, or 1.335× fewer cells. That is neither an end-to-end
speedup nor a valid prediction for the shared arithmetic tree. The larger
opportunity is eliminating duplicate proof work through one complete caller
layout; its benefit remains unmeasured. No pruning was implemented in this
round.
