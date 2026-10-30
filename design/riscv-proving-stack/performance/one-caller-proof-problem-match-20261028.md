# One caller proof: problem match and implementation boundary

Status: isolated original B6CJ1 proof and combined composition-circuit leg
qualified on real SHA/Keccak and nonempty secp256k1 recovery/Keccak fixtures.
The current B6 complete-root route is unchanged. The six-tree DEEP/FRI arithmetic and live transcript legs also pass. Complete
recursive Merkle/opening compilation and the independent recursive key factory
are still required before this protocol can replace its two recursive children.

Implemented isolated primitive: `block_v6_caller_joint_masks_v1.zig`, with its
dedicated test root. ReleaseSafe qualification passed four tests, including
all 64 ordered pairs of existing layout tags at two OODS points, distinct
physical/common +27 steps, empty columns, mismatched shared geometry,
route/source mutations, resource preflight and allocation-failure cleanup.
The planner unions exact circle translations independently of the OODS seed;
it retains both original layout/mask identities and exact original ordering
through routes. Mathematical aliases may share one sample while the original
source descriptors remain distinct. It does not grant proof authority or
extend the current DEEP layout vocabulary to an arbitrary union.

## Pre-implementation problem match

**Task and semantics.** Prove the conjunction of original precompile arithmetic
and caller program/state/table/memory constraints with one commitment opening,
composition polynomial and FRI proof. Keep every arithmetic physical LogUp
claim and every separately typed global accounting contribution. No provider
obligation may disappear by summing unlike relations.

**Inputs and scale.** Inputs are the independently admitted original statement,
caller binding, shared fixed/main roots, access root, frame and global seal.
The original-mask SHA1/Keccak1 fixture has 15,139 fused trace columns and 410,814
raw cells; 4,340 columns are not sampled by the fused verifier, but may be
required by arithmetic. This is fixture geometry, not an Ethereum estimate.
The cost model is field/FFT work, commitment and recursive hash work, plus
peak live allocations. The existing caller has two independent proof schedules.

**Structure and invariants.** Both proofs already lease the same fixed/main
trees and enforce identical caller roots. Their interactions and claims differ.
The native partitioned protocol demonstrates a later, stronger transformation
that keeps direct equations and covers every original lookup exactly once.
The immediate caller transformation is the conjunction of both original
constraint systems; it does not yet eliminate duplicate relation equations.

| Candidate | Relationship and guarantee | Fit and implementation | Risk |
| --- | --- | --- | --- |
| Batch both original component systems into one STARK | Exact conjunction, with independently bound randomized composition | Existing component accumulator, shared trees and joint relocation | Mask order, quotient normalization, transcript omissions |
| Direct equations plus one complete typed relation partition | Exact only after a symbolic coverage proof | B6 native layout is a local model | Caller SHA/Keccak/secp equations and relations have different decompositions |
| Delete unused fused columns | Not an equivalent transformation of shared commitments | At most 25.09% of fused cells in this fixture | Breaks root equality to arithmetic; requires a new proved projection |
| Aggregate the existing two proofs recursively | Exact but retains both base and verifier costs | Current complete route | Does not remove duplicated work |

**Chosen variant and mapping.** First use batched polynomial constraint
evaluation: concatenate the two original equation rosters under one independently
derived component schedule. Shared fixed/main columns map to one physical
tree; private interaction columns map to distinct trees. Original sample
coordinates map through an exact ordered union. Solution recovery exports
the original arithmetic and fused accounting contributions from one verified
public claim frame, not from fabricated legacy receipts.

**Prior implementation and evidence.** Stwo's original
[component accumulator](https://github.com/starkware-libs/stwo/blob/main/crates/prover/src/core/air/components.rs)
combines component quotient evaluations using a common random coefficient and
derives the maximum component degree. This supports component batching, not a
claim that arbitrary mask or transcript changes are valid. The repository's
`block_v6_joint_components_v1` already relocates trees and uses the existing
quotient-extension transform when composition splits differ. The stronger
`block_v6_partitioned_native_proof_v1` is the local implementation precedent
for a later complete caller relation partition. No external source code is
copied for this primitive.

**Complexity.** For C shared columns and at most S original samples per column,
stable exact union takes O(C S²) point comparisons and O(C S) output/route
storage; S is bounded explicitly. Each original sample has exactly one route
back into the union. This is a small bounded canonicalization problem, not an
optimization heuristic. Original ordering and duplicate occurrences remain
available through routes. The primitive does not change transcript claims.

**Prediction and falsifier.** One caller means one combined FRI/composition
instead of two. Shared roots are sampled under one joint schedule. Actual
constraint work remains approximately the sum in this first phase. Savings
are conditional: if composition-degree inflation, larger masks or recursive
columns dominate the removed proof overhead, this phase can regress. Measure
full prove+verify and parent row counts; reject a slower phase rather than
reporting proof-count reduction as performance.

**Correctness plan.** Exact mask coverage, repeated points, incompatible
ordering, empty masks, domain-separated steps, caps and allocation failures.
Then compare every original symbolic equation and point/domain accumulation
against the joint compiler. Genuine SHA, Keccak, secp and mixed proofs must
verify; altered physical claims, roots, route indices and missing components
must fail. Derive the recursive key independently from metadata, and qualify
it against the live joint verifier before replacing the current two children.

**Uncertainty.** No combined proof timing exists. A union may exceed the
current named DEEP sample-layout variants. Such a shape must be supported by
an exact authenticated offset schedule or rejected, never approximated.

## Minimal protocol and tree schedule

Use a new caller-joint version/domain and independent admission identity.

| Joint trace tree | Original arithmetic view | Original fused view |
| --- | --- | --- |
| 0 fixed | 0 | 0 |
| 1 main | 1 | 1 |
| 2 external access | absent | 2 |
| 3 arithmetic interaction | 2 | absent |
| 4 fused interaction | absent | 3 |
| 5 composition commitment | combined | combined |

Keep both interaction bases initially. Their exact tree positions and widths
must be part of the new template identity. The existing access first-round
lease owns trees 0–2 and may append interactions 3–4. The arithmetic producer
must expose its interaction columns/claims without consuming its first-round
owner or producing a separate proof. The caller and access owners must pass
the existing exact root and shared-column checks first.

The joint transcript starts from the authenticated global seal/challenges and
mixes a new domain, original caller binding, independent joint template,
geometry/route digest and access root. Mix the entire arithmetic physical
claim frame and every fused program/state/table/memory/range/count claim before
committing either interaction tree. Commit trees 3 and 4 in a fixed documented
order, then let the ordinary STARK engine derive one composition/OODS/FRI
schedule. Never reuse an old proof's later challenges or final channel.

## Changes needed for a complete implementation

1. **Original equations and geometry.** Build original arithmetic and fused
   owners, choose the canonical common composition split, and use a proved
   quotient-extension transform for lower-split components. Existing joint
   relocation only handles a one-step lift; larger differences must explicitly
   fail until their transform is supported. Build exact shared masks once and
   route each original component to its original ordered mask view. Domain
   evaluation uses the same tree remapping and quotient transformation.
2. **Shared main declaration.** Declare shared main columns exactly once.
   The existing native joint adapter's prefix-subset test is insufficient for
   general caller masks. The new isolated union primitive preserves both
   original orders; the component wrapper must consume its routes rather than
   forwarding a union array to code expecting a smaller original mask.
3. **Generation and original verification.** Extract original arithmetic
   interaction generation and fused interaction generation into owned results.
   Consume the retained access lease for one engine prove. Fresh verification
   reconstructs fixed roots, original statement/admission and both equation
   systems independently, then verifies the six-commitment proof.
4. **Recursive compiler.** Add an explicit six-commitment family profile to
   DEEP, path, opening and fixed-PCS adapters; current supported cardinalities
   cannot be silently widened. Record arithmetic then fused constraints in
   exactly the prover order, with one random-coefficient sequence. Both
   existing symbolic recorders need the same joint quotient normalization and
   mapped sample views. Use a new public bus and capture type carrying both
   claim sets. A cold key factory must reproduce the exact fixed schedule.
5. **Global receiver and roster.** One joint child replaces the paired
   arithmetic/fused roster entries. Its typed exports still expose both
   contributions, bound to the identical caller binding and census. Update
   codec version, mixed roster compiler, key schedule and public closure
   together; do not alias the old two-child identities.
6. **Second phase.** After the exact conjunction is qualified and measured,
   replace duplicated caller lookup work with one symbolic relation partition.
   A complete coverage proof must account for every original lookup entry's
   tuple, sign, symbolic multiplicity, active selector and physical batch.
   Direct arithmetic, range, clock, register and memory invariants remain.
   This can combine interaction storage into one basis and reduce six total
   commitments to five, but is a separate protocol/qualification step.


## Implemented qualification (2026-10-28)

The original proof path is `prover/block_v6_caller_joint_proof_v1.zig`.
It commits five trace trees and one composition tree. The verifier accepts
independent statement, caller binding, access root, frame, source seal and
security policy, rebuilds the fixed root, and verifies the actual STARK.
No previous arithmetic receipt is used to authorize the new proof. The result
exports an arithmetic open sum and the separately typed fused contributions;
all global providers remain obligations of the complete block receiver.

`block_v6_caller_joint_components_v1.zig` preserves original constraint order:
all arithmetic components, followed by fused memory/program/table components.
Its separate metadata roster follows the physical interaction-column order
(program/state/table/memory). Both are bijections of the original component
roster. Every original sample point is resolved from an exact union; no caller
may supply the geometry or routes. In particular, fused `{0, 27}` is a
non-prefix subset of native Keccak `{0, -2, -1, 1, 2, 27}`. A prefix alias
would silently read the wrong sample. The native one-step quotient-extension
transform is retained when arithmetic split 1 joins split 2. Larger unsupported
lifts fail. Local-zero caller recipes are explicitly unqualified and rejected.

`block_v6_caller_joint_interaction_v1.zig` uses the original public primitive
generators. Three existing caller helper functions were made public without
changing their bodies; there is no second private implementation of the
program/state fraction generator. Their original row/sign/multiplicity rules
and partition-major ordering remain unchanged.

Independent metadata is reconstructed by `block_v6_caller_joint_admission_v1`.
The distinct `B6CALLR1` codec has independent claim census, exact six-tree
inventory, security configuration, policy/template framing and allocation-free
postcard preflight. It does not infer a key or accepted roots from the wire.
`block_v6_caller_joint_capture_v1` performs actual original verification and
checks exact OODS masks, FRI-expanded column logs, claims and typed exports
against independent metadata. Its checksum is transport consistency only.

The new `recursion/air/block_v6_caller_joint_composition_v1.zig` records the
original arithmetic equations followed by the original fused equations with
one random-coefficient sequence. It routes shared samples back into each
original mask order, keeps physical-claim/aggregate equalities and the
arithmetic open-sum equality, and checks the real split composition opening.
Its source vocabulary is 47 universal challenge pairs, 14 arithmetic suffix
pairs, and 5 packed-memory pairs (132 scalar challenge coordinates). This is
not either legacy caller's profile and must not be cast to one.

Run the focused qualification from the repository root:

```sh
python3 scripts/zig_protocol_test.py \
  src/frontends/riscv/block_v6_caller_joint_proof_test_root.zig \
  -OReleaseSafe -fstrip --test-filter 'caller joint actual'
```

The two actual workloads pass with all original proofs freshly verified:

- SHA/Keccak and nonempty valid secp256k1 recovery/Keccak, using real guest
  execution and caller witnesses.
- Six commitments; exact arithmetic physical claims, all fused claim arrays,
  and exported receipts match the two original proof routes.
- Native original-versus-joint OODS equation/mask parity at two distinct seeds.
- Detached encode/decode/re-encode byte equality and fresh decoded proof capture.
- Changed projection claims, changed access root, wrong policy envelope,
  claim-count resource caps, and cancelling physical-batch mutations rejected.
  The latter mutation preserves the aggregate and still invalidates the proof.
- The actual combined composition circuit evaluates successfully on both
  workloads; changing a public claim fails with `UnsatisfiedCircuit`.

The qualified test security is diagnostic: 8 queries, blowup 1, PoW 0. This
is functional/soundness-regression evidence, not a claim of canonical-security
production qualification or cryptographic audit. No timing comparison has
been made. Structurally this replaces two caller composition/FRI schedules
with one and 9 total commitment-root occurrences with 6; it does not reduce
the five underlying witness/interaction bases yet.

Remaining integration is explicit: Merkle/opening source ports; exact public claim/clock/root wire schedule;
metadata-only fixed arithmetic/source compilation and independent key derivation;
live/cold fixed-row equality; a new mixed-root caller kind and matching global
exports. The existing arithmetic/fused enum entries must not be reused as
aliases. Then qualify canonical security and run a quiet-host matched A/B
before considering the stronger single-relation-partition transformation.


## Exact verifier-work census and next architecture (2026-10-29)

The genuine DEEP and FRI graphs evaluate successfully against the captured
original proof, and a hostile DEEP answer is rejected. Live transcript replay
ends at the exact captured channel state and exports all 66 challenge pairs
once. Cold/live transcript fixed-plan identities now match on both real
workloads after the repeated-draw fix below. This transcript seam is not an
independently qualified complete recursive key.

These are exact arithmetic-row counts from the same workloads and diagnostic
security above, not timings or Ethereum-block estimates:

| Workload | Separate arithmetic | Separate fused | Separate total | Joint | Reduction |
| --- | ---: | ---: | ---: | ---: | ---: |
| SHA + Keccak | 559,014 | 267,409 | 826,423 | 761,312 | 7.88% |
| Recovery + Keccak | 559,153 | 303,995 | 863,148 | 800,680 | 7.24% |

One composition/FRI removes useful fixed work but retains the duplicate lookup
bases. This is not an order-of-magnitude result. The next structural task is
one exact relation partition across caller arithmetic and accounting, with
symbolic coverage of every original tuple, sign, multiplicity and selector.
Inactive families require a new independently admitted geometry and proof of
absence; padded claims are not assumed zero and cannot simply be discarded.

The isolated `block_v7_caller_joint_source_v1` and
`block_v7_caller_joint_proof_v1` now use an explicit whole-execution epoch.
Their three first roots enter that epoch before any shared relation challenge.
A separate versioned caller suffix draws private arithmetic relations, then
absorbs every arithmetic and accounting physical claim before either
interaction root. The original fixed root and both equation systems are
reconstructed during fresh verification. Typed exports retain per-window
state/register, ROM, table, memory transition, byte-demand and private
residual obligations. A native entry identity, local frame and execution
ordinal bind each caller to its exact execution window. No legacy source seal
or legacy success receipt is manufactured. The genuine SHA/Keccak and nonempty recovery/Keccak gates pass all eight
tests under epoch version 2, including wrong execution identity, wrong access
root and cancelling physical-claim mutations. Both fresh verifiers close the
private residual and preserve exact external event counts (98 and 92). Test
security remains diagnostic q8/blowup1/PoW0. Full global closure belongs to
the separate execution receiver.

Actual original arithmetic trace geometry for these fixtures is 436,622 cells
(SHA/Keccak) and 1,160,160 cells (recovery/Keccak). Entire absent families
account for 17,694 and 11,406 cells respectively, or about 4.05% and 0.98%.
These columns were retained and proved in both gates. Omitting absent families
alone is therefore not the large raw-area improvement; recursive opening
width must be evaluated separately.


## Keccak width versus vertical layout: first cost boundary

The current paired Keccak shard uses 31 fixed columns, 2,204 main columns,
and 4,164 interaction columns: 6,399 total. At the minimum 32-row domain this
is 204,768 raw field cells. Its exact original OODS mask has 18,781 scalars:
31 fixed + 2,204 current main + 218 extra I/O samples + 8,000 extra state
samples + 8,328 interaction samples. This excludes the shared chi/xor tables,
external access and other caller families. It is a source-derived geometry
census, not a measured complete proof cost.

Keeping the current paired `a + 8*b` slice representation, a row per paired
round/lane has 24×25=600 rows, rounded to 1,024 before boundary and bus
overhead. Equal raw area permits at most 199 total columns. Separating the
two calls instead gives 2×24×25=1,200 rows, rounded to 2,048, and a 99-column
budget. These are different architectures, not interchangeable counts.
A row per paired round/bit has 24×1,600=38,400 rows, rounded to 65,536: equal area
would permit only three columns. Pure bit serialization therefore cannot
preserve current raw area once value/key/bus columns are counted. A narrower
verifier may still win recursive cost, but that must be measured against a
larger base witness, FFT domain and Merkle depth.

The next candidate is a moderate lane/tile layout, not unchecked row pruning.
Its independently fixed rho/pi schedule must bind call, round, lane and bit
position; every state consume must have exactly one matching production,
boundary I/O must match the caller, and all chi/xor normalization requests
must close against their genuine tables. The implementation decision needs
an exact admitted width and active-row census first. Track committed cells,
OODS scalars, per-query leaf words and actual recursive G rows separately;
none alone is an end-to-end speed prediction.

## Repeated transcript draws and independent setup

The first cold B6CJ plan comparison found that the generic transcript grammar's
`secure.output = null` means a fixed expected value, not a discarded output.
Using it for repeated Universal draws embedded their captured coordinates in
fixed rows. This preserved that live transcript but prevented a metadata-only
key from matching it across inputs. The same repeated-draw convention was
present in readonly caller v1 and global readonly v2; neither readonly family
is accepted by the qualified complete-root receiver.

The explicit `discard_output` grammar now preserves bounded hash execution,
rejection sampling, first-accepted selection and counter chaining, while
closing the selected coordinates through a private wire sink. It forbids an
export role and requires bounded compilation. The sink's fixed mode/identity/
weight bind this distinct grammar into the plan ID. Default null-output
semantics remain fixed expected values. A repeated branch has no arithmetic
consumer: its identical authenticated prefix deterministically recreates the
same challenges without pinning them into the key. Existing native transcript
bytes are unchanged.

The regression changes the public seed and discarded coordinates while
requiring identical fixed keys, checks the exact native counter/channel, and
rejects hostile selected-coordinate/counter relation mutations and invalid
discard/export combinations. Genuine combined-caller cold/live equality and
both readonly prefix byte-parity gates pass (five tests), preserving exact
original B5IC/B5IC2 channels and 54 exports while discarding only the 52
repeated draws. Both real
combined-caller workloads now pass exact cold/live fixed-plan equality in the
nine-test gate; an independent full recursive key remains outside the v7
native proof qualification.

## V7 recursive caller seam (implementation in progress)

The original v7 caller STARK already closes the internal arithmetic/projection
relation and exports typed global obligations. Its recursive adapter must
verify that actual protocol, not reconstruct a legacy seal to fit a convenient
adapter type. The chosen reuse boundary is original equation geometry and the
six-commitment union-mask PCS. Independent v7 admission rebuilds the nineteen
arithmetic components, program/state/table/access schedule, raw trace logs,
composition lift and exact epoch entry. Every physical claim is a public
operand bound before the two interaction roots.

The transcript exports Universal47, arithmetic14, Word5 and interval1 in stable
circuit slots, while preserving the real draw order: Universal47, Word5, two
separate single interval draws, then caller arithmetic14. The two single draws
must not become one eight-word draw. The shared exact epoch emitter handles
this distinction. Compatibility byte relations remain separately derived;
packed access equations use the actual word/universal challenges.

Qualification proceeds through actual original proof/capture, original
composition evaluation, independently derived DEEP/FRI shape, exact transcript
and cold/live fixed-plan identity, then explicit six-commitment Merkle/opening
and public-supply routing. Production authority remains unavailable until the
complete independently keyed parent and every typed global relation close.
Neither a capture checksum nor matching graph identifiers alone qualifies a
recursive caller proof. All existing four/five-tree and PAGE ten-tree entry
points retain their original strict shape gates.

The real SHA+Keccak fixture now passes that complete scoped parent path at
q8/PoW0. Its original six-tree proof is captured through independent v7
admission; a capture-free compiler reconstructs the same original composition
and every fixed verifier row, public wire, namespace and context. The emitted
parent has 754,885 fused arithmetic rows and encodes to 152,667 bytes. After
its producing plan and rows are destroyed, a detached receiver independently
reconstructs the public frame, recomputes the original fixed root and verifies
the parent under the cold-derived key. Compensated physical chi claims that
preserve the aggregate, a changed root-coordinate map, and a changed expected
key are rejected. Sixteen distributed composition public-operand mutations
also fail. These are correctness observations, not benchmark timings.

The scoped parent still exports OPEN program/state/register/table/memory
obligations. It is not a complete execution proof; the mixed receiver must bind
its execution window and close all original relations with native and provider
children. The nonempty recovery+Keccak fixture also passes the complete scoped
parent gate: 796,498 fused arithmetic rows, a 153,086-byte detached parent, exact
cold/live fixed roster and transcript, and the same hostile-claim, coordinate
and key checks. Its original composition has 278,732 rows and all sixteen
distributed public-operand mutations reject. Canonical security/full Ethereum
workloads remain separate from these diagnostic fixtures.
