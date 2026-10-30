# Independent admission of the complete mixed root

Status: implementation inventory, 2026-10-28. The new complete receiver requires
an independently trusted expected key, schedule and roster. A key derived from
the producer's live verifier rows is a useful consistency check; it is not an
independent admission mechanism. This note does not qualify the complete root.

## Existing boundary

`prover/block_v6_complete_root_receiver_v1.zig` takes an out-of-band `Policy`
containing the expected key identity, key, exact public wire schedule, exact
family/index/template roster, original global pins and PAGE context. It checks
security, roster identity and key identity, verifies the one parent proof, drops
proof storage, then closes the original global equations using precisely the
same authenticated public values. No base proof files are read by that receiver.

The remaining setup obligation is to produce that policy without learning the
expected verifier program from the proof, a producer-supplied fixed row array,
or a successful live capture. Recomputing a supplied key's hash does not meet
this obligation. Nor does comparing the producer against a key computed from
that same producer's rows.

## Coverage of current independent compilers

All paths below are relative to `src/frontends/riscv/`.

| Original child family | Complete independent original fixed roster | Missing work |
|---|---|---|
| Native partitioned B6JP-v3 | Implemented; semantic check passes | `block_v6_partitioned_fixed_roster_v1.zig` compiles original geometry, symbolic composition/DEEP/FRI, arithmetic, exact transcript, 4/5-tree PCS, private sources, public schedule and complete fixed rows. Full live/fixed parity and mixed joining remain. |
| RAM lanes | Implemented | Exact live/fixed parity at the actual production configuration, then mixed namespace composition. |
| Range16 | Implemented | Exact live/fixed parity at the actual production configuration, then mixed namespace composition. |
| ROM/program table | No | Original independent shape, equation, transcript, source/public and complete fixed assembly. |
| Native lookup | No | Same, preserving each independently admitted table kind and size. |
| Arithmetic caller | No | Original caller arithmetic shape and graph schedule, native transcript/PCS, complete fixed row assembly. |
| Fused caller | No | Exact caller fused relation basis, all original public/physical claims, transcript/PCS/source routing and fixed assembly. |
| Raw PAGE | Implemented, policy-specific | Independent semantic policy claims, exact live/fixed parity and mixed namespace composition. |
| Fold PAGE | Implemented, policy-specific | Independent semantic policy claims, exact live/fixed parity and mixed namespace composition. |

RAM/range entry point:
`recursion/block_v5_word_recursive_fixed_roster_v1.zig`:
`ForFamily(family).Owned.derive(allocator, admitted, expected_template,
retry_capacity, profile, limits)`.

PAGE entry point:
`recursion/block_v5_memory_source_page_recursive_fixed_roster_v1.zig`:
`ForKind(kind).Owned.derive(allocator, admitted, expected_template,
independent_semantic_claims, retry_capacity, profile, limits)`.

Both return original fixed rows, original public wire schedule and original
context. They deliberately retain `whole_family_live_parity_qualified = false`.
Their `validateLive` compares every fixed row, context and public wire against
an actual original-family preparation. An implemented factory is not evidence
that this complete parity gate has passed.

The numerous requester/public fixed-assembly modules compile verifiers of
already-recursive parent shapes. They do **not** supply the missing original
native, original ROM/lookup or original caller proof adapters above.

## Shared machinery that should be reused

1. `recursion/air/block_v6_partitioned_composition_v1.zig::recordConstraints`
   already records the complete original native semantics, clock equations,
   canonical relation partition and access equations. A cold compiler should
   call it with shape-derived symbolic inputs in exactly the live input order;
   it must not create a dummy `VerifiedCapture` or silently remove equations.
2. `recursion/block_v5_recursive_parent_fixed_assembly_v1.zig::Arithmetic`
   lowers the exact original composition, DEEP and FRI graphs. Its original
   six-lane reference and fused lowering also supply the MAIN identifier ports
   needed below, without private arithmetic evaluations.
3. `recursion/block_v5_recursive_parent_fixed_roster_v1.zig::compileOriginalRoster`
   performs original append order, source multiplicities, opening/native PCS
   fusion, active-selector supply and BLAKE3 G-row partition. The cold native
   family wrappers should authenticate their independently reconstructed inputs
   and call this compiler rather than building a parallel verifier layout.
4. `recursion/block_v5_native_recursive_fixed_pcs_v1.zig::ForCommitments`
   now supports explicitly selected four, five or ten commitment trees. The new
   `block_v6_partitioned_fixed_profile_v1.zig` independently reconstructs each
   optional-access profile. Shared path, opening and PCS compilers accept the
   statically selected five-tree grammar; full live parity remains necessary.
5. `recursion/air/block_v5_recursive_fixed_namespace_v1.zig` performs exact
   fixed-only namespace rebase. Two legacy arithmetic cohorts carry circuit
   identifiers in MAIN. Use `prepareForArithmetic` with the original lowering
   reference/plan; plain `prepare` must reject unresolved MAIN identifier ports.
   Do not infer those identifiers from a received private row.

## The mixed join has two namespace stages

The current producer uses singleton provider and auxiliary pieces. Even a
singleton is already rebased and its context is domain-separated by its family
adapter. Therefore the independent compiler must reproduce both stages:

```
original-family independent fixed rows + schedule + context
    |
    +-- native: original rows directly --------------------------+
    |                                                           |
    +-- provider: exact provider batch singleton rebase/context -+
    |                                                           |
    +-- caller/PAGE: exact auxiliary singleton rebase/context ---+
                                                                |
                          exact mixed rebase, join and schedule -+
                                                                |
                          independent fixed commitment + root key
```

The relevant live recipes are
`recursion/block_v6_provider_batch_prepare_v1.zig`,
`recursion/block_v6_auxiliary_direct_prepare_v1.zig`, and
`recursion/block_v6_mixed_direct_prepare_v1.zig`.

Preserve child grouping, input order, namespace bases, unique identifier sets,
namespace identity, each context domain/tag, original graph identities,
transcript identity, exact wire coordinates/use counts, and G partition timing.
The final mixed context includes the exact roster digest. A regrouped set of
otherwise identical children can produce a different valid key; the setup and
producer must choose the same canonical grouping.

After joining, use
`recursion/blake3_execution_parent_proof.zig::ForBackend(...).deriveKeyFromFixed`
and `block_v6_mixed_direct_protocol_v1.Key.fromGeometry` with the independently
constructed schedule and roster. This is the end of the factory, not its source
of authority.

## PAGE policy is an additional input, not just geometry

The existing `prover/block_v5_page_recursive_expected_setup_v1.zig` API requires
semantic claims from pinned pre-proof policy. PAGE cold shape reconstructs
`Original.Admission.init(..., public_claims, ...)`, which affects its public
graph. A new mixed factory can instead accept proposed public claims as inputs
provided it independently compiles the original equations, constrains every
required semantic relationship, and the final root binds precisely those same
claims. In that design the claims are untrusted parameters to a trusted compiler,
not trusted merely because an envelope supplied them. No successful proof token
or producer-selected graph is needed to compile their expected verifier.

`SourceRecursiveAdmissions.Owner` independently reconstructs context and original
fold operations. A claim-only record is not an independent expected key, but it
can supply proposed values for the trusted original equation compiler. The
factory API and tests must explicitly distinguish this new usage from the old
pinned-policy contract. Mismatched proposals between setup, authenticated root
public inputs and global closure must fail. No arbitrary graph, fixed row array
or expected key may be learned from those proposals.

## Concrete implementation contract

A complete factory should consume original independently admitted source owners,
PAGE semantic proposals bound to the same root public inputs, exact canonical family/index roster, retry
capacity, security profile and bounded allocation limits. It should return only
an owned root key, expected key identity, schedule and roster. No received proof,
`VerifiedCapture`, live `Prepared`, or producer fixed rows belongs in this API.
Claim-only decoded records may supply public scalar proposals; they cannot
nominate a verifier graph or fixed-row plan.

For each missing family, construct the shape and graph compiler first, then
transcript/PCS/source/public routing and full fixed roster. Keep the independent
arithmetic identifier port alive through each rebase. Construct and consume all
fixed pieces within the factory; free scratch before returning the narrow setup.
Do not expose a mutable caller-supplied fixed owner as trusted setup.

Required qualification: metadata equality against live rows for every family,
with and without access and every admitted caller/table shape; complete mixed
key/schedule equality; rejection of changed row, source coordinate, use count,
physical-claim placement, family/index, namespace grouping, retry capacity,
security config and PAGE policy. The final fresh receiver must reject wrong
independent key/roster and wrong public claims after producer memory is destroyed.
Existing successful live root proofs cannot substitute for these setup checks.

## Safe interim operating mode

An explicitly trusted, separately provisioned registry may pin a reviewed key
identity, complete key, exact public schedule, exact roster, security and source
policy for a particular supported workload shape. Verification then trusts that
registry as setup authority. This permits testing the proof/closure machinery,
but it does not establish that the cold factory exists or that a key created by
the same live producer is independently sound. New shapes must fail closed when
there is no trusted setup entry. A production qualification claim must state
which authority is used and how its expected program was established.

## Native compiler evidence

`block_v6_partitioned_recursive_fixed_v1.Owned.derive` accepts only independent
native admission and public claim proposals. It calls the original component
mask/degree metadata and exact `recordConstraints` kernel, with symbolic inputs
in original sample/challenge/public/randomness/OODS order. No proof, private
values, capture, invented verifier-success token or successful witness is used.
The first focused metadata fixture passed 11/11 tests, covering access trees in
both custody modes and no-access geometry, independent reconstruction, changed
template rejection, and unchanged graph identity under a changed public claim.
The complete roster codegen check passes. Whole-row/context/schedule/namespace
parity against a genuine live preparation is still explicitly unqualified.

`block_v6_partitioned_fixed_roster_v1.Owned` retains an independently reconstructed
namespace plan while its original Arithmetic lowering is alive. This includes
inverse/linear MAIN circuit identifiers; it does not guess them from fixed rows.
Its exact fixed-only result is the starting input for the final mixed join, not
an independently verified block result.

Native live/fixed follow-up: the actual proof-backed gate with
`STWO_B6_PARTITIONED_RECURSION=1 STWO_B6_PARTITIONED_FIXED_PARITY=1` passed
10/10 tests in ReleaseSafe. For its genuine RAM, custody-mode-1, diagnostic
8-query shape, every fixed row, public wire, context and namespace identifier
matches the live original verifier preparation exactly. No comparison was
weakened. This establishes parity for that tested shape, not all security
profiles, all instruction shapes or the complete mixed-root factory.
