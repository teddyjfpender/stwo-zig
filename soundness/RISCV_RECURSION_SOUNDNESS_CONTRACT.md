# RISC-V recursion soundness contract

**Status:** normative specification for the Poseidon2 in-circuit RISC-V
verifier ("the recursion lane"). It is a contract to be implemented and
audited, not a statement that the lane is sound today.

**Status date:** 2026-10-18 (tree `7227da406`).

**Current flag:**

```text
recursion_qualified = false
```

**Claim owner:** the RISC-V frontend ledger
[`RISCV_FRONTEND_VERIFICATION_STATUS.md`](RISCV_FRONTEND_VERIFICATION_STATUS.md).
That ledger takes precedence over any other claim about this lane. The flag
above may be flipped only by the ledger update rule in section 11.

**Evidence basis:**
[`../conformance/2026-10-18-riscv-frontend-soundness-audit.md`](../conformance/2026-10-18-riscv-frontend-soundness-audit.md)
("Recursive RISC-V proofs", divergences R-D1 to R-D7, finding R-F1) and the
native-route fixes A-F1, A-F2 and B-P1 recorded there.

**Claim boundary:** this contract fixes what a recursive RISC-V proof must
mean, which native code is the authority for each in-circuit check, which
identities every key must pin, and which gates must pass before
`recursion_qualified` becomes `true`. It does not establish proof-system
soundness, whole-frontend refinement (FV-3/FV-4/FV-5), or production security
parameters. Section 8 lists the non-claims.

The words **MUST**, **MUST NOT**, **SHOULD** and **MAY** are normative. Every
requirement names the file and identifier that is its anchor; an auditor
checks the code against that anchor, not against this prose. Items marked
`OPEN:` could not be fixed from the current code and must be resolved before
the gate that depends on them.

## 0. Vocabulary

| Term | Meaning | Anchor |
| --- | --- | --- |
| native proof | A core STARK proof of one RISC-V segment under the Poseidon2 Merkle hasher and scheduled channel. | `src/frontends/riscv/recursion/engine.zig:36-41` `ScheduledProverEngineForBackend` |
| leaf | A detached proof that verifies one native segment proof in-circuit and publishes one span statement. 39 catalog rows. | `src/frontends/riscv/recursion/air/segment_leaf_catalog_v2.zig:11-31` |
| parent | A detached proof that verifies two child proofs (leaf or parent) in-circuit and publishes their folded span. 29 catalog rows. | `src/frontends/riscv/recursion/air/detached_parent_catalog_v1.zig:6-35` |
| root | A parent published in `.root` mode: its folded span must be a complete `RootStatement`. | `src/frontends/riscv/recursion/span_continuation_v1.zig:15,28-32` |
| span statement | The frozen 412-word Stark-V V1 execution statement; leaves and folds share it. | `src/frontends/riscv/recursion/span_statement.zig:1-7`, `air/statement_input.zig:16` |
| continuation words | Span statement plus session, entry-lineage and exit-lineage digests: 436 words. | `span_continuation_v1.zig:9-13` |
| public claim | The fixed canonical VM public claim for one segment and its Poseidon2 digest. | `src/frontends/riscv/recursion/vm_public_claim.zig:19,83-110` |
| scheduled channel | The native Fiat-Shamir channel driven by an authenticated verifier plan; every mix/draw is a plan step. | `recursion/scheduled_channel.zig`, `recursion/native_scheduled_channel.zig` |
| plan, plan digest | The ordered `VerifierStep` list for one proof shape and its `authority_digest`. | `recursion/air/verifier_schedule.zig:138-190,333-476,593-623` |
| shape id, protocol id | Digests of the verifier-owned proof geometry and cryptographic suite bound in the first transcript frame. | `recursion/transcript_shape.zig:31-88`, `recursion/protocol.zig` |
| catalog identity | Digest of the complete leaf or parent component roster geometry; a key is admitted only against it. | `recursion/air/segment_outer_manifest_contract_v2.zig:140-156` |
| provider shell | The constraint wrapper around the shared Poseidon2 permutation AIR that fixes its enabler and mode flags. | `src/frontends/riscv/air/memory_commitment/hash_component.zig:40-47` |
| provider authority digest | The pinned receipt for the Poseidon2 provider source and geometry. | `recursion/air/universal_shared_geometry.zig:9-12`, `universal_provider_authority.zig:35-60` |
| admission | Independent, pinned key/expected-statement inputs supplied to a fresh verifier process; a bundle never supplies its own admission. | `recursion/detached_segment_command_v1.zig:18-27`, `detached_parent_command_v1.zig:13-34` |
| fixed wire | The verifier-owned fixed-dimension proof encoding consumed by the leaf circuit. | `recursion/fixed_wire_fixed_stark_proof_wire.zig:38-80` |

## 1. Scope and current divergence inventory

This contract covers the native-to-leaf boundary (sections 2 to 5), the
leaf-to-parent and parent-to-root boundaries (section 2), key identity
(section 6), the in-circuit verifier obligations (section 7) and the gates
(section 9). The divergences it closes are:

| Id | Divergence (audit record) | Closed by |
| --- | --- | --- |
| R-D1 | Scheduled transcript absorbs only the 28 aggregate claims; physical per-batch claims are free circuit inputs. | T-4, T-5, C-5, W-1 |
| R-D2 | Composition circuit replays the retired 7-constraint boundary AIR without public-root binding; profiles count 9. | C-2, C-3, W-2 |
| R-D3, R-D4 | Merkle multiplicity and atomic `poseidon2_io` changes picked up through native modules; identities move. | K-1, W-6 |
| R-D5 | Identity migration admits only the oldest legacy digest; committed keys cannot be migrated. | K-4, W-5 |
| R-D6 | Shard manifest replaced by public-claim digest and verifier-owned shape ids (accepted). | T-3 |
| R-D7 | Frozen leaf geometry predates native column changes; leaf proving faults with `AuthorityMismatch`. | K-6, W-3 |
| R-F1 | Universal provider shell admits narrow rows against full-IO requests. | P-1 to P-5, W-4 |
| R-D8 (new, audit 2026-10-18) | The native segment proof's tree-0 (preprocessed) root lacks an independently supplied in-circuit constant. V2 now labels the row `constant_mask = 1`, but `segment_transcript_outer_components_v2_source.zig:238-244` sets `constant_value` from that same proof-derived row; this is a self-equality, not key binding. Frozen V1 row 5 remains dynamic. The native verifier recomputes the root (`prover/statement_validation.zig:540-565` `verifyPreprocessedRoot`). | V-14, G-8, W-9 |
| R-D9 (new, audit 2026-10-18) | The scheduled lane drops `InteractionClaim.mixInto`'s interaction column log-size list (`air/transcript/claims.zig:75-78` mixes `log_sizes.len` and every `log_size`; `native_scheduled_channel.zig:109-118` absorbs only the 28 sums). | T-3(d) |

<!-- audit: R-D8/R-D9 added. R-D8 is the highest-severity gap found: the contract as drafted never required the native preprocessed commitment to be verifier-owned, so a literal implementation would admit a leaf whose native proof commits an attacker-chosen tree 0 (selectors, lookup tables). -->
<!-- audit: anchor paths corrected throughout: `poseidon2_universal_identity_v2.zig`, `poseidon2_universal_equations_v1.zig`, `poseidon2_universal_component_v1.zig` live in `src/frontends/riscv/air/memory_commitment/`; `poseidon2_identity_migration.zig` and `leaf_manifest_contract_test_root.zig` live in `src/frontends/riscv/`, not `recursion/`. -->
<!-- audit: also note P-2's phrase "compact degree-3 provider ... poseidon2_universal_component_v1.zig" refers to `src/frontends/riscv/air/memory_commitment/poseidon2_universal_component_v1.zig`, whose equations (`poseidon2_universal_equations_v1.zig:65-84` `entriesForIo`) emit the same four mode-weighted tuples as the wide layout, so it needs the same pin. -->

## 2. Statement model

### 2.1 Leaf statement

**S-1.** A leaf proof MUST establish exactly: "a native segment proof,
verified under the pinned protocol and the admitted catalog, accepts the
public claim whose Poseidon2 digest is bound in the leaf transcript, and the
412-word span statement published by the leaf is derived from that claim."
The derivation authority is `segment_leaf_authority.Prepared.init`
(`src/frontends/riscv/recursion/segment_leaf_authority.zig:83-137`): the
claim is encoded from `PublicData` (`vm_public_claim.encode`,
`vm_public_claim.zig:188-195`), the statement is
`span_statement.SegmentLeaf.init(data, &claim, protocolId())`, and
`validateAgainst` (`segment_leaf_authority.zig:138-176`) re-checks the claim
digest, the public I/O digests and every row-10 statement word.

**S-2.** The public claim layout is `vm_public_claim.canonical_layout`
(`vm_public_claim.zig:83-110`). The public roots are at fixed coordinates:
`program_root` tag 210 / present 211 / words from 212; `initial_rw_root` tag
220 / present 221 / words from 222; `final_rw_root` tag 230 / present 231 /
words from 232. The claim digest is
`hashCanonicalWords(words, VM_PUBLIC_CLAIM_HASH_DOMAIN = 0x5643)`
(`vm_public_claim.zig:19,176`), and the public-input / public-output digests
use domains `0x5649` / `0x564f` (`vm_public_claim.zig:20-21`). These
coordinates, domains and the 412-word statement layout
(`air/statement_input.zig:16`) are frozen; a change requires a new schema and
new keys (K-1).

**S-3.** In-circuit, the claim words enter through row 12
(`recursion/air/vm_public_claim_input.zig`), the digest is recomputed by row
13 (`recursion/air/vm_public_claim_hash.zig:18`, request at `:578`) and the
I/O digests by row 14 (`vm_public_io_hash.zig`). The leaf MUST NOT accept a
claim digest that was not recomputed from the same words that feed the
statement rows; `segment_leaf_authority.zig:6` ("no row accepts an
independently supplied digest") is the design invariant.

**S-4.** Native-route public-input validation is not replaced by the leaf.
The leaf verifies the native proof against a `PublicData` that has already
passed native statement validation (`native_scheduled_channel.zig:74-75`
calls `claim.validateAgainst` and `statement.validateAgainst` before the
first frame). A recursive proof over a segment whose native statement would be
rejected by the native verifier MUST be unprovable.

Audit note (2026-10-18): the anchors above are host-side checks in the
producer and discharge nothing by V-13. "Unprovable" MUST be established by
one of three in-circuit or admission mechanisms, and the implementer MUST
record which one covers each check of `prover/statement_validation.zig:87-99`
`validate(statement, .proof)` (`validateV1Boundary` + `validateGeometry`),
`verifier.zig:434-449` (`Protocol.validate`, claim/statement component
counts, `commitments.len == 4`, `native_infrastructure_typed_admission.validateStatement`):
(a) **key pin**: component geometry (family, log size, `n_rows`, column
count) is hashed into the leaf key identity through
`native_descriptors.mixIdentity` (`detached_segment_authority_boundary_v1.zig:14-37`,
`statement_v2_authority_preimage.zig:18-20` `.admitted_geometry`), so any
geometry-only validation is discharged by K-2/K-3; (b) **row semantics**: the
public-data checks are discharged by rows 11 and 15-17
(`statement_semantics_circuit.zig`, `vm_public_semantics_circuit.zig`); (c)
**structure**: `commitments.len == 4` is discharged by the fixed wire
(`segment_profile.zig:49-60` `DIMENSIONS.commitment_count = TREE_COUNT`).
Any `validate(.proof)` check that falls in none of (a)-(c) is a divergence
and MUST be added to section 1 before G-7 is attempted.

### 2.2 Parent statement

**S-5.** A parent proof MUST establish exactly: "two child proofs, each
verified in-circuit against a child key whose SHA-256 is pinned in the parent
key (`detached_parent_protocol_v1.zig:54,65` `child_key_sha256`), publish
continuation words `L` and `R`, and the parent publishes
`fold(L, R, mode)`." The fold authority is `span_continuation_v1.fold`
(`span_continuation_v1.zig:34-40`), which applies
`SpanStatement.fold` (`span_statement_semantics.zig:60-80`: same job, equal
child heights, adjacent slots, aligned parent slot, `empty` never before
`executed`, and `foldExecuted` for two executed spans) and propagates the
left session and lineage words.

**S-6.** The parent's child binding MUST be the child's public claim digest
carried into the parent public input through the child statement rows; this
is the "child statement bound through the public-claim hash into the parent
public input" obligation already present (audit record, "In-circuit verifier
readiness"). A parent MUST reject a child proof whose key identity differs
from the pinned `child_key_sha256`, and MUST reject swapped children
(`SlotsNotAdjacent`), gaps and duplicates (`SlotsMisaligned`,
`ChildHeightMismatch`).

Audit note (2026-10-18), mechanism as found in code: the child key identity
and the child's own tree-0 root are **fixed constants of the parent
transcript**, not absorbed proof data. `detached_prefix_preparation_v1.zig:184-190`
replays the child's standalone transcript (`plan.root(.tree0,
child.key().preprocessed_root)`, `Protocol.mixAdmission` which mixes
`key.identity()` and the expected words, `mixClaimsAndBoundary`) and
`PayloadSource.fixed()` (`:50-70`) marks `.tree0`, `.admission_header`,
`.key_identity`, `.public_frame`, `.claims_header`, `.boundary_header` as
constant words baked into the parent's preprocessing. The parent key field
`child_key_sha256` (`detached_parent_protocol_v1.zig:54,77`) is hashed into
the parent key identity but **no verifier re-derives the parent's tree 0 from
it**: `detached_parent_verifier_v1.zig:60` only compares `commitments[0]`
with `key.preprocessed_root`. Therefore the pin is load-bearing only if
admission regenerates the parent preprocessed tree from (manifest,
parameters, child key identities, publication mode) and checks it equals
`preprocessed_root`; see K-8 and G-8. The fold itself IS constrained
in-circuit: row 11 (`statement_semantics_circuit.zig`) evaluates the span
fold on graph nodes and `detached_parent_statement_preparation_v1.zig:195`
emits `span_continuation_v1.emitFoldChecks` on the same nodes, while
`detached_parent_protocol_v1.zig:96-107` `publicBoundary` requests every one
of the 436 published words exactly once, so the parent's published words are
the fold output and nothing else.

**S-7.** The host command surface is `detached_parent_command_v1.zig:134-147`:
`--fold-span` and `--fold-root` derive the expected parent words from two
child expected files (`foldExpected`), `--derive-span`/`--derive-expected`
derive them from native inputs, and the four-argument form
`verifyDirectory(bundle, key_sha256, root_words)` is the standalone verifier.
Expected words produced by these commands are inputs to admission, never
outputs of a proof.

### 2.3 Root

**S-8.** A root proof is a parent key with `publication_mode = .root`
(`detached_parent_protocol_v1.zig:49`). Its 436 continuation words MUST
satisfy `span_continuation_v1.validate(words, .root)`
(`span_continuation_v1.zig:28-32`), which requires
`span_statement.RootStatement.init` to accept the folded span (complete
coverage from slot 0 at minimal height). The exported public input of the
whole job is those 436 words plus the root key identity
(`KeyV1.identity`, `detached_parent_protocol_v1.zig:60-76`, which hashes the
profile, PCS config, manifest seal, challenge registry order, protocol id,
preprocessed root and child pins).

**S-9.** The expected root words MUST be supplied to the fresh root verifier
from an independently pinned admission file, as `riscv_recursive_product.py`
and `riscv_segment_v2_detached_tree_gate.py` do through mandatory admission
path and SHA-256 arguments.
A root whose expected words are taken from the producer's output is not
verified.

## 3. Transcript equivalence

**T-1 (authority).** The native verifier code is the sole authority for the
transcript. Concretely: `src/frontends/riscv/proof_transcript.zig`
(`proveToRelations` / `verifyToRelations`, lines 22-40 and 116-134;
`mixInteractionClaim`, lines 159-183), `src/frontends/riscv/air/statement.zig`
(`mixShardManifest` line 280, `mixPhysicalClaims` line 541),
`src/core/verifier.zig:213,244,281-288` and `src/core/pcs/verifier.zig:139,270-308`
with `src/core/fri.zig:74-138`. The scheduled channel
(`native_scheduled_channel.zig`) MUST be a framing of those calls, never a
second hand-written transcript. Any `@hasDecl` branch that makes the native
functions skip a mix when driven by the scheduled channel is a violation of
this requirement; the two present today
(`proof_transcript.zig:27,73,122,145` for `absorbRiscVPublicClaim` and
`proof_transcript.zig:166` for `absorbRiscVClaimedSums`) are addressed by T-3
and T-4.

**T-2 (draw rule).** Every value the native verifier mixes before a draw MUST
be absorbed, in the same order and with the same canonical M31 encoding,
before the same draw in-circuit. The in-circuit transcript rows
(`recursion/air/transcript_air.zig`, `transcript_binding.zig`,
`transcript_state.zig`, `transcript_word.zig`, `transcript_payload.zig`,
`pow_check.zig`, `pow_frame.zig`, `relation_challenge.zig`,
`verifier_randomness.zig`) consume the recorded `Execution`
(`transcript_program_contract.zig:102-124`), and
`Execution.replayNative` (`transcript_program_contract.zig:155-200`) is the
check that the recorded frames equal the native Poseidon2 channel primitive
frame by frame. `replayNative` MUST remain in the proving path of every leaf
and parent, and G-1 (section 9) MUST exercise it on real proofs.

**T-3 (accepted difference R-D6).** The scheduled lane replaces the native
`MainClaim.mixInto` + `mixShardManifest` prefix with
`absorb_public_claim` of the claim digest (`native_scheduled_channel.zig:99-109`)
and binds `protocol_id || shape_id` and the PCS parameter words in
`bind_protocol`, `bind_statement`, `bind_pcs_parameters`
(`native_scheduled_channel.zig:64-96`). This is acceptable only while all
three hold: (a) the component row counts, log sizes and column counts that
`mixShardManifest` would bind are pinned by the committed preprocessed tree and
the catalog identity (K-2); (b) `segment_profile.validateStatement`
(`segment_profile.zig:113-127`) is called before the first frame (K-6); and
(c) `transcript_shape.derive` (`transcript_shape.zig:31-88`) binds every
geometry axis that the fixed wire can carry (sampled value count, queried
values per query, claimed-sum counts, PoW bits, tree heights, FRI schedule);
and (d) the interaction column log-size list that `InteractionClaim.mixInto`
also mixes natively (`air/transcript/claims.zig:75-78`: `mixU64(log_sizes.len)`
then one `mixU64` per column) and that the scheduled lane drops
(`native_scheduled_channel.zig:109-118`) is pinned by the same key geometry
as (a), since every interaction column's log size is the owning component's
`log_size`.

Audit note (2026-10-18) on (a): the geometry facts `mixShardManifest` binds
(family/kind, `log_size`, `n_rows`, `n_columns` per component,
`statement.zig:280-310`) are already hashed into the leaf key identity via
`native_descriptors` (`detached_segment_protocol_v1.zig:70,111`,
`detached_segment_authority_boundary_v1.zig:26-37`), so a key admitted under
K-5 fixes them. What is NOT pinned is the consequence of that geometry: the
native tree-0 root is a deterministic function of the descriptors
(`prover/preprocessed.zig:123-175` `generate`: `is_first`/`is_active` with
`is_active` = first `n_rows` rows, plus the lookup-table tuples), the native
verifier recomputes and compares it (`statement_validation.zig:540-565`),
but the leaf circuit treats it as proof data (R-D8). (a) is therefore
discharged for the *transcript* only when V-14 lands; G-7 MUST include the
tree-0 negative control of G-8. `OPEN` (a) is downgraded from "undemonstrated"
to "demonstrable by G-7 + G-8 once V-14 is implemented".

**T-4 (physical claims, closes R-D1).** The plan MUST contain a typed step
that absorbs every physical claimed sum the components consume, mirroring
`mixPhysicalClaims` (`air/statement.zig:541-566`) exactly: the header
`{STWP, PCL1, n_components, n_infra, total}` (`PHYSICAL_CLAIM_DOMAIN_WORDS`,
`statement.zig:498`), then for each opcode component its
`batching.opcodeBatchCount(family)` claims, then for each infrastructure
component its `nClaimedSumsForInfra(kind)` claims, with `total` computed by
`physicalClaimCount` (`statement.zig:510-527`). Native order is canonical
first, then physical (`proof_transcript.zig:174-182`), so the new step is
placed immediately after `absorb_claimed_sums{count = 28}`
(`verifier_schedule.zig:394`) and before
`absorb_trace_commitment{round = .interaction, tree = 2}`
(`verifier_schedule.zig:395`). The step's `count` MUST enter the plan
encoding (`VerifierStep.encode`, `verifier_schedule.zig:192-235`) and the
shape id (`transcript_shape.zig:73` already carries
`claimed_sum_count`; a `physical_claimed_sum_count` word MUST be added).
`absorb_claimed_sums{28}` is retained because the native verifier mixes the
28 aggregates first; the alternative "absorb detailed and derive 28" is
rejected because it would not mirror the native value order.

Audit note (2026-10-18): "bit-exact" is the wrong standard and has been
removed. The scheduled channel is by construction a *different* byte
transcript (every step is an eight-word header frame, `transcript_program.zig`),
and natively the 28 sums are mixed as 28 single-element `mixFelts` calls
(`claims.zig:76`) while the scheduled lane absorbs them as one 28-element
payload. The invariant T-2/T-4 require is: the same **values**, in the same
**order**, before the same **draws**. With the detailed claims absorbed, the
in-circuit `selector·(canonical_i − Σ batches_i)` constraints (C-5) stop
being the only binding but remain necessary: the 28 canonical sums are what
the native verifier's `verifyGlobalCancellation` closes over
(`verifier.zig:592-595`), the detailed claims are what the component
constraints consume, and nothing else ties the two absorbed sets together.
Confirmed from `graph_build.zig:70-74,243-247`: the detailed claims consumed
by `pairConstraintGeneric` and the infrastructure evaluators are the same
`claims[]` wires that the aggregate constraints sum, so after W-1 sources
those wires from the row-5 payload there is exactly one copy.

**T-5 (bypass removal).** After T-4 lands, `proof_transcript.zig:166` MUST
no longer skip `mixPhysicalClaims` on any channel type. Two framings are
admissible and the implementer MUST pick one and record it: (i) keep a typed
`absorbRiscVClaimedSums` hook that absorbs the 28 sums as the
`absorb_claimed_sums{28}` step and add a typed `absorbRiscVPhysicalClaims`
hook that receives the header `{STWP, PCL1, n_components, n_infra, total}`
and the ordered per-component slices and frames them as the single
`absorb_physical_claims{total}` step; or (ii) make the generic path work by
having `native_scheduled_channel.Channel.mixU32s` accept exactly the T-4
header (today fail-closed, `native_scheduled_channel.zig:177-179`) and
`mixFelts` buffer the `n_components + n_infra` per-component calls of
`mixPhysicalClaims` (`statement.zig:558-565`) into one step that closes when
exactly `total` sums have arrived. In either case the dropped log-size list
of T-3(d) stays dropped and recorded. The `absorbRiscVPublicClaim` branch
(`proof_transcript.zig:27-33`) MAY remain as the R-D6 accepted difference,
but the else-branch MUST remain the native authority and the scheduled branch
MUST be tested against it by G-1.

<!-- audit: the original T-5 ("MUST call view.mixInto(channel) ... on every channel type") was not implementable as written: `view.mixInto` issues 28 one-element `mixFelts` calls plus `mixU64`s for the log-size list, which the scheduled channel's `mixSecurePayload` (one step per call, `native_scheduled_channel.zig:322-335`) and fail-closed `mixU64` outside PoW steps (`:181-200`) would reject. Rewritten to state the invariant and the two admissible framings. -->

**T-6 (step list).** For a leaf (schema `.vm`), the plan produced by
`Plan.initShape` (`verifier_schedule.zig:355-476`) MUST be, in order:

| # | Step | Native call it frames | Anchor |
| --- | --- | --- | --- |
| 1 | `bind_protocol` | none (verifier-owned `protocol_id || shape_id`) | `native_scheduled_channel.zig:77-86` |
| 2 | `bind_statement` | none (412 statement words) | `native_scheduled_channel.zig:87` |
| 3 | `bind_pcs_parameters` | none (`PCS_PARAMETER_WORDS`) | `verifier_schedule.zig:26`, `native_scheduled_channel.zig:89-92` |
| 4 | `absorb_trace_commitment{.preprocessed, 0}` | `commitment_scheme.commit` → `MC.mixRoot` | `src/core/pcs/verifier.zig:139`; `native_scheduled_channel.zig:147-175` |
| 5 | `absorb_trace_commitment{.main, 1}` | same | same |
| 6 | `absorb_public_claim` | R-D6 replacement of `MainClaim.mixInto` + `mixShardManifest` | `proof_transcript.zig:27-33` |
| 7 | `verify_and_absorb_interaction_pow{bits}` | `verifyPowNonce(INTERACTION_POW_BITS)` then `mixU64(nonce)` | `proof_transcript.zig:128-130`; `protocol.zig:43` (10 bits) |
| 8.. | `draw_relation_challenge{c}` × 12 | `Relations.draw` → `drawSecureFelts` pairs | `proof_transcript.zig:131`; `native_scheduled_channel.zig:260-282` |
| .. | `accumulate_public_logup_term{t}` × 70, `assert_global_logup_zero` | no transcript effect | `verifier_schedule.zig:21,388-393` |
| .. | `absorb_claimed_sums{28}` | `InteractionClaim.mixInto` | `proof_transcript.zig:174`; `air/transcript/claims.zig:75` |
| .. | **`absorb_physical_claims{total}`** (new, T-4) | `mixPhysicalClaims` | `air/statement.zig:541` |
| .. | `absorb_trace_commitment{.interaction, 2}` | `commit` → `mixRoot` | `src/core/pcs/verifier.zig:139` |
| .. | `draw_composition_randomness` | `channel.drawSecureFelt()` | `src/core/verifier.zig:213` |
| .. | `absorb_trace_commitment{.composition, 3}` | `commit` → `mixRoot` | `src/core/verifier.zig:237-242` |
| .. | `draw_oods_point` | `channel.drawSecureFelt()` | `src/core/verifier.zig:244` |
| .. | `evaluate_air_instruction{i}` × `air_instruction_count`, `assert_composition` | no transcript effect; see section 4 | `verifier_schedule.zig:401-409` |
| .. | `absorb_sampled_values{count}` | `channel.mixFelts(sampled_values_flat)` | `src/core/pcs/verifier.zig:270` |
| .. | `draw_deep_randomness` | `channel.drawSecureFelt()` | `src/core/pcs/verifier.zig:271` |
| .. | per FRI layer: `absorb_fri_commitment{l}`, `draw_fri_alpha{l}` | `MC.mixRoot(first/inner commitment)`, `drawSecureFelt()` | `src/core/fri.zig:74,81,101,111` |
| .. | `absorb_last_layer_coefficients{count}` | `channel.mixFelts(last_layer_poly.coefficients())` | `src/core/fri.zig:138` |
| .. | `verify_and_absorb_pcs_pow{bits}` | `verifyPowNonce(pow_bits)` then `mixU64(proof_of_work)` | `src/core/pcs/verifier.zig:303-306`; `protocol.zig:44` (16 bits) |
| .. | `draw_query_block{...}` × ⌈193/8⌉ | `sampleQueryPositionsWithRaw` → `drawU32s` | `src/core/pcs/verifier.zig:308`; `native_scheduled_channel.zig:206-230` |
| .. | trace openings, DEEP quotients, FRI folds, last layer, relation closures, `complete` | no transcript effect; section 7 | `verifier_schedule.zig:426-455` |

The native PCS configuration consumed by the scheduled channel MUST equal
`protocol.PCS_CONFIG` (`native_scheduled_channel.zig:382-395`
`validatePcsConfig`); a proof produced under any other configuration MUST be
rejected before the first frame.

**T-7 (PoW semantics).** Both proofs of work are verified in-circuit by rows 6
and 7 (`recursion/air/pow_check.zig`, `pow_frame.zig`) against the recorded
`pow_checks` (`transcript_program_contract.zig:181-190`: call id, drawn word
and trailing-zero bits). The draw used for a PoW check MUST NOT be exposed as
verifier randomness (`transcript_program_contract.zig:87-88`).

## 4. Constraint equivalence

**C-1 (authority).** The composition value the circuit reconstructs MUST equal
`Components.evalCompositionPolynomialAtPoint`
(`src/core/air/components.zig:260-278`) as invoked by the native verifier
(`src/core/verifier.zig:281-288`, rejection `OodsNotMatching`). The circuit
builders (`recursion/vm_air_composition_circuit_graph_build.zig`,
`recursion/ethereum_vm_composition_graph_base_v2.zig`) MUST obtain every
constraint program by calling the native evaluators, never by transcribing
them: `semantic_eval.Eval` for opcode semantics, `logup.pairConstraintGeneric`
with `opcode_entries` for opcode lookups, `program_interaction.evaluateGeneric`,
`clock_component.evaluateGeneric`, `merkle_node.evaluateGeneric`
(`src/frontends/riscv/air/memory_commitment/merkle_node.zig:225-266`),
`poseidon2_air.evaluateGeneric` and `interactionConstraintsGeneric`,
`table_interaction.evaluateGeneric`, and the memory boundary evaluator of C-2.

**C-2 (public roots, closes R-D2).** The memory boundary component MUST be
replayed with `MemoryBoundaryPolicy.evaluateGeneric(..., roots)`
(`src/frontends/riscv/air/component.zig:55-93`), producing
`memory_interaction.N_CONSTRAINTS = N_SUMS + 5 = 9` constraints
(`air/memory_commitment/interaction.zig:144`), with `roots =
RootParameters(S).fromPublic(initial_rw_root, final_rw_root)` exactly as the
native component does (`component.zig:626`). The two root-binding
constraints are `m·(m+1)·(k_i·root + b_i)` and `m·(m−1)·(k_f·root + b_f)`
(`interaction.zig:235-243`), where `(k, b) = (1, −root)` for a present root
and `(0, 1)` for an absent one (`interaction.zig:195-198`). The builder's
current call to `evaluateWithoutRootsGeneric`
(`vm_air_composition_circuit_graph_build.zig:283-293`;
`component.zig:96-111`; `interaction.zig:246`) is prohibited once this
contract is in force, and `N_CONSTRAINTS_WITHOUT_ROOTS` and
`evaluateWithoutRootsGeneric` SHOULD be deleted so the retired shape cannot be
re-selected.

**C-3 (root inputs).** The four root parameters per root (`N_ROOT_PARAMETERS
= 4`, `interaction.zig:149`) MUST be circuit inputs derived in-circuit from
the child's public claim words at the coordinates of S-2 (`initial_rw_root`
word 222, `final_rw_root` word 232, with the `present` words 221 and 231
selecting the absent-root form). They MUST be added to the composition
circuit `InputProfile`
(`recursion/air/composition_circuit_reference.zig:163-174`; `vmInputCount`
at `:441-460`) and bound through row 18
(`recursion/air/vm_air_composition_input.zig`) to the row-12 claim words.
Resolved (audit 2026-10-18): a **dedicated native-root input class** is
required. `InputProfile.vm_statement_root_count = 2`
(`composition_circuit_reference.zig:172`) is served by
`air/statement_input_roots_v3.zig` ("Ethereum row-10 profile", `:1-4`),
whose lowered degree is declared 4 (`:24` `LOWERED_MAXIMUM_CONSTRAINT_DEGREE`),
which violates C-7; and it binds roots at *statement* coordinates (row 10),
whereas the native component derives `RootParameters` from the *public
claim* (`component.zig:626` `fromPublic(initial_rw_root, final_rw_root)`),
i.e. row-12 words 221/222 and 231/232. The new class MUST carry four scalar
inputs per root `(k_i, b_i, k_f, b_f)` computed by a degree-≤2 selection on
the `present` word (`present·1 + (1−present)·0`, `present·(−root) +
(1−present)·1`) and MUST be bound by lookup to the row-12 claim words, not to
row 10. `vmInputCount` (`:441-460`) MUST add the new count as a separate
term so that every legacy VM input index is preserved for identity purposes.

**C-4 (constraint counts).** The per-component constraint counts used to size
the plan (`air_instruction_count`) MUST be taken from the native modules
through `vm_air_profile.constraintCountForInfra`
(`recursion/vm_air_profile.zig:376-392`) and
`vm_air_profile_v2_registry.constraintCount`
(`recursion/vm_air_profile_v2_registry.zig:11-36`), and the builder MUST fail
with `InvalidComponentOrder` when the replayed instruction count or the
consumed claim count differs (`vm_air_composition_circuit_graph_build.zig:396-402`).
The current mismatch (profiles count 9, builder emits 7) is the detector
working as intended; C-2 resolves it.

**C-5 (detailed claims, closes R-D1 in the circuit).** The per-batch claims
consumed by `pairConstraintGeneric` and the infrastructure evaluators
(`vm_air_composition_circuit_graph_build.zig:70-74,200,243-247,382`) MUST be
sourced from the transcript-authenticated payload of the T-4 step, not from
a provider's own committed trace
(`recursion/air/segment_publication_input_provider_v2.zig:1-12` currently
publishes the 21 detailed claims from its own trace). The aggregate
consistency constraints `selector·(canonical_i − Σ batches_i) = 0`
(`graph_build.zig:102-135`) SHOULD be retained as defence in depth but MUST
NOT be the only binding.

**C-6 (Merkle and Poseidon, R-D3/R-D4).** The Merkle node constraints
including `lhs_mult·(lhs_mult − cur_mult) = 0` and
`rhs_mult·(rhs_mult − cur_mult) = 0` (`merkle_node.zig:262-268`) and the
single atomic `poseidon2_io` request `[lhs, rhs, 0×14 ‖ cur, 0×15]`
(`merkle_node.zig:363-370`, `narrowIoTuple`,
`air/memory_commitment/poseidon2_layout.zig:22-34`) are inherited by calling
the native modules. The product `.poseidon2` component in the leaf MUST be
replayed with the `narrow_memory` shell constraints
(`hash_component.zig:737-770`: `enabler − is_active`, `wide`, `io`), which
the builder already emits (`graph_build.zig:342-346`).

**C-7 (degree bound).** The circuit MUST use the native quotient denominators
with the profile's `max_log_degree_bound` and `composition_log_split`
(`vm_air_profile.zig:86-100` `Profile.validate`;
`graph_build.zig:168-173,404-410`), which the native verifier derives from
`Components.compositionLogDegreeBound()` (`src/core/verifier.zig:197-212`).
The native constraint degrees are at most 3 (memory boundary: "Degree 3 in
trace columns", `interaction.zig:143`; Poseidon2 `MAXIMUM_CONSTRAINT_DEGREE =
3`, `poseidon2_layout.zig:11`; Merkle child binding degree 2,
`merkle_node.zig:255-263`). Every typed recursion row MUST keep
`MAXIMUM_CONSTRAINT_DEGREE = 3` (`vm_public_claim_hash.zig:33-35`,
`statement_input.zig:36-37`) because the provider protocol degree is pinned
to 3 (`universal_shared_geometry.zig:21`).

**C-8 (identity).** The circuit identity digest is
`circuitDigest(manifest_digest, graph_digest, reference_digest,
schedule_digest, input_profile, bindings)` (`graph_build.zig:451-458`) under
`CIRCUIT_ID = 1` (`recursion/vm_air_composition_circuit_error.zig:71`). C-2,
C-3 and C-5 change the graph; the new identity MUST be re-pinned and every
leaf key re-derived (K-1).

## 5. Poseidon2 provider shell

**P-1 (shell modes).** A provider row carries flags `wide` and `io`
(`poseidon2_layout.zig:15-16`), constrained boolean and mutually exclusive by
the permutation AIR (`poseidon2_wide_equations.zig:124-126`). It emits
exactly one live tuple per mode (`poseidon2_wide_equations.zig:197-209`;
compact twin `poseidon2_universal_equations_v1.zig:71-84`): narrow mode
(`wide = io = 0`) emits the atomic `poseidon2_io` tuple
`[input16 ‖ out0, 0×15]`; IO mode (`io = 1`) emits the atomic
`[input16 ‖ output16]` tuple; wide mode emits split `poseidon2` terms.
(Audit: the compact twin is `src/frontends/riscv/air/memory_commitment/poseidon2_universal_equations_v1.zig:65-84`
`entriesForIo`, same four weighted entries; it is not under `recursion/`.)

**P-2 (pinned flags per shell).** The `narrow_memory` shell pins `wide = io =
0` and `enabler = is_active` (`hash_component.zig:737-770`,
`N_POSEIDON_COMPONENT_CONSTRAINTS = 435`, `:837-846`). The `universal` shell
(`hash_component.zig:795-822`, 432 constraints) adds no mode constraint and
is selected by `recursion/air/universal_shared_provider.zig:165`. Every shell
admitted in the recursion lane MUST pin its mode: the universal shell MUST
constrain `enabler·(1 − io) = 0` (or equivalently `enabler·wide = 0` and
`enabler·(1 − io) = 0`), and the compact degree-3 provider
(`stwo.recursion.poseidon2-universal-degree3.v1`,
`poseidon2_universal_component_v1.zig`) MUST pin the same. A domain-separated
narrow tuple is an acceptable alternative only if every narrow requester
(`merkle_node.zig:363`, the guest Poseidon2 caller,
`air/guest_precompile/component_registry.zig:571`) changes with it; the pin is
preferred because it changes no requester.

**P-3 (one tuple shape per request).** Every consumer request on
`poseidon2_io` MUST match exactly one provider tuple shape. The recursion
consumers that request the full-IO tuple with free output columns are
`transcript_air.zig:463`, `trace_merkle.zig:419,528`, `fri_merkle_leaf.zig`,
`fri_merkle_node.zig`, `merkle_path.zig`, `vm_public_claim_hash.zig:578,660`
and `vm_public_io_hash.zig`; they MUST be served only by rows with `io = 1`.
The native product requesters (`merkle_node.zig`, the guest caller) request
the narrow tuple and MUST be served only by `narrow_memory` rows. A leaf
cohort therefore MUST NOT contain a provider whose shell admits both shapes.

**P-4 (consumer outputs are witness).** A consumer's output columns derive
their trust solely from the provider tuple. No consumer MAY constrain its own
permutation output other than by the `poseidon2_io` request (design
statement at `transcript_air.zig:3-6` and `vm_public_claim_hash.zig:5-7`).
Therefore P-2 is load-bearing: without it a prover zeroes output lanes 1..15
of a transcript, Merkle or claim-hash row and serves it with a narrow row
whose `out0` happens to match (R-F1).

**P-5 (Ethereum node).** `air/memory_commitment/ethereum_node_v1.zig:85-93`
(`providerCalls` sets `.io = true`) and `:161-168` request the full-IO tuple.
Any provider serving the Ethereum memory node is outside this contract
(section 8) but MUST, if ever re-admitted, be a shell with `io` pinned to 1.

Resolved (audit 2026-10-18). **Intent:** full-IO is intended, not an error.
The node's own doc comment (`ethereum_node_v1.zig:85-86`: "must authenticate
these full input/output pairs with its atomic `poseidon2_io` relation, not
its one-lane narrow-output relation") and the tuple construction
(`:155-167` `rowPairsGeneric`: `[inputs[c] ‖ outputs[c]]` for each of the 4
calls) are explicit; the audit record's expectation of a narrow request was
mistaken. **Tuple contents:** `outputs[c]` are the node's own committed
columns (`Row.outputs`, `:49`), constrained only by the link constraints
(`N_LINK_CONSTRAINTS`, `:31`: chaining of lanes into the next call's input
and of the digest words out of calls 2 and 3), so output lanes not consumed
by the chain or the digest are free witness. **Reachability:** the node is
referenced only by `ethereum_node_component_v1.zig`, `ethereum_path_v1.zig`,
`ethereum_word_tree_v1.zig`, `ethereum_node_proof_v1.zig` and the test root
`ethereum_commitment_v1_test_root.zig`; no prover roster in
`prover/base_component_assembly.zig` instantiates it. The product
Ethereum/CSP profiles (`ethereum_v5`, `ethereum_local_zero_v1`,
`ethereum_circuit_profile_v1.zig:39-46`) select `poseidonLayout() ==
.narrow_degree3_v1`, whose provider (`poseidon2_narrow_degree3_v1.zig:115-129`)
emits the narrow tuple with weight `main[0]` and the full-IO tuple with
weight **zero**, so on the product route no `io = 1` row exists and a node
request would simply be unservable (`LogupSumNonZero`). **Not
product-reachable; no native Critical.** **Latent hazard, binding on any
re-activation:** a narrow row `[in ‖ out0, 0×15]` is algebraically identical
to a node request whose `outputs[c][1..15]` are zero. If the node were ever
placed in a cohort with a provider that emits narrow rows (any
`narrow_memory` or `narrow_degree3_v1` provider, or the unpinned universal
shell), a prover could zero lanes 1..15 of every call, resetting the sponge
capacity to zero between calls; intermediate node digests would then carry
only lanes `{0, 7}` of genuine entropy (62 bits), giving ~2^31-work
collisions between distinct `(left, right)` children under one parent, i.e.
a memory-content equivocation. The root row still needs a genuine 7-lane
preimage, so the public root is not directly forgeable, but the sponge
security argument is void. Therefore: the Ethereum node MUST only ever be
served by a provider with `enabler·(1 − io) = 0`, and MUST NOT share a
`poseidon2_io` relation with any narrow emitter unless the narrow tuple is
domain-separated.

**P-6 (authority re-pin).** After P-2 the provider authority digest
(`universal_shared_geometry.zig:9-12`), the compact identity
(`poseidon2_universal_identity_v2.zig:16` `CANONICAL_DIGEST`), and the
`provider_authority_sha_id` carried in every manifest
(`segment_outer_manifest_contract_v2.zig:155`) MUST be regenerated, and
their seals re-recorded (K-1).

## 6. Identity and key lifecycle

**K-1 (invalidation rule).** Any change to a native AIR module called by the
builders of C-1, to `air/statement.zig`, `proof_transcript.zig`, the core
verifier transcript, the provider shells, the claim layout of S-2, the plan
step set, or `protocol.zig` invalidates every leaf key, every parent key, every
committed proof and every admission file. There is no partial re-pin. The
October 2026 changes trigger this rule; the stale artifact inventory is the
audit record's "Stale artifacts and regeneration order".

**K-2 (what a key pins).** A leaf key (`detached_segment_verifier_v1.KeyV1`,
`recursion/detached_segment_protocol_v1.zig`) MUST pin the catalog manifest
with its `catalog_identity`, the transcript / statement / public / boundary
manifest ids, `boundary_authority_sha_id`, `provider_authority_sha_id` and
`seal` (`segment_outer_manifest_contract_v2.zig:140-156`), the admission
parameters (`detached_segment_admission_v1.zig:7-24`: query reference and
Poseidon active rows), the source manifest and admitted verifier-key
authority (`src/frontends/riscv/leaf_manifest_contract_test_root.zig:30-43`;
the key struct itself is `detached_segment_protocol_v1.zig:61-71`, which
also pins `native_descriptors` and `wire_terms`, both hashed into
`identity()` at `:111-123`). A parent key
(`detached_parent_protocol_v1.zig:46-76`) MUST pin profile, PCS config,
manifest seal, challenge registry order, protocol id, preprocessed root and
both `child_key_sha256`. The plan digest and shape id are bound inside the
transcript (`bind_protocol`) and therefore inside every proof.

**K-3 (native source identity).** Every key MUST additionally pin the native
source identities it was derived from: the VM AIR profile manifest digest
(`vm_air_profile.zig:74-84` `Profile.manifest_digest`, hashed per component
with role, shard, constraint span and claim span, `:360-372`), the circuit
identity of C-8, and the provider authority digest of P-6. A key that pins a
stale identity MUST fail admission with a named error before any proof byte is
decoded: `InvalidCatalogGeometry`
(`recursion/air/segment_outer_typed_catalog_v2.zig:55,126-138,173-175`),
`CatalogIdentityMismatch` (`:153`), `AuthorityMismatch`
(`leaf_manifest_contract_test_root.zig:40`), or
`DetachedParentProfileMismatch` (`detached_parent_protocol_v1.zig:61`). The
committed q193 child key failing `InvalidCatalogGeometry` today
(`leaf_manifest_contract_test_root.zig:12-22`) is this rule working.

**K-4 (migration, R-D5).** `src/frontends/riscv/poseidon2_identity_migration.zig:30-31`
admits only `LEGACY_SOURCE_DIGEST`
(`src/frontends/riscv/air/memory_commitment/poseidon2_universal_identity_v2.zig:19`)
and rewrites it to `CANONICAL_DIGEST` (`:16`, `aebeb027…`);
`scripts/riscv_recursive_identity_migration.py:24` hard-codes `e37c589f…`,
a superseded canonical digest (audit-confirmed mismatch). Because K-1 invalidates every key
anyway, migration of the committed keys MUST NOT be attempted. The migration
tool and script MUST either be updated to the new canonical digest with the
previous canonical admitted as a reviewed legacy identity, or be marked
unusable for keys older than this contract. Re-derivation (W-6) is the
required path.

**K-5 (admission independence).** A fresh verifier MUST receive the key bytes
and an independent SHA-256 (`detached_segment_command_v1.zig:18-27`,
`detached_parent_command_v1.zig:13-34`), the expected statement words, the
claims file and the proof bytes, and nothing from the producer process. A
bundle, receipt, witness flag or producer log MUST NOT confer authority
(design goal, `small-detached-recursion-goal.md` "Required implementation
order" item 1).

**K-6 (frozen geometry, R-D7).** `segment_profile.zig:20-47` freezes 38 / 625
/ 200 / 8 columns per tree, column log degree 20, 871 tables and 1 071 sampled
values. These constants MUST be re-derived from the hardened native statement
and pinned again, and `segment_profile.validateStatement`
(`segment_profile.zig:113-127`) MUST be called before the transcript is bound
(`native_scheduled_channel.zig:64-96` `bindRiscVTranscript`) so geometry
drift fails with `StatementGeometryMismatch` before proving starts rather than
with `AuthorityMismatch` at `absorb_sampled_values`.

**K-8 (tree-0 regeneration at admission; new, audit 2026-10-18).** Both
standalone verifiers accept `commitments[0]` by comparing it with
`key.preprocessed_root` (`detached_segment_verifier_v1.zig:93`,
`detached_parent_verifier_v1.zig:60`) and never regenerate the preprocessed
tree; `detached_segment_protocol_v1.zig:1-4` already states that "admission
policy must additionally establish that Tree0 and all constant/output anchors
are statement-independent". This contract makes that mandatory: a key MUST
NOT be admitted (K-5) unless an independent process has regenerated its
preprocessed tree from the key's own fields (manifest geometry,
`parameters`, `wire_terms`, `native_descriptors`, publication mode and, for a
parent, the two child key identities and child `preprocessed_root`s that the
parent transcript bakes in as `PayloadSource.fixed()` constants,
`detached_prefix_preparation_v1.zig:50-70,184-190`) and found it equal to
`preprocessed_root`. Without this, `child_key_sha256` (S-6) and the
V-14 constant are pins in name only. The regeneration path is the producer's
`commitFixedColumns` (`src/integrations/riscv_cpu/recursive_segment_v2_detached_proof.zig:227-231`)
and the parent `deriveKey` (`recursive_segment_v2_detached_parent_proof.zig:156-161`);
the gate (G-8) MUST run it in a process that holds no proof.

**K-7 (pinned digests inventory).** The following pins MUST be regenerated
together and recorded in one receipt: `segment_profile.zig` constants;
`transcript_shape.zig` shape word list; the plan digests; the circuit
identity (C-8); `universal_shared_geometry.POSEIDON_SOURCE_AUTHORITY_DIGEST`;
`poseidon2_universal_identity_v2.CANONICAL_DIGEST`; the key hash in
`leaf_manifest_contract_test_root.zig:28`; the independently supplied
admission and alternate-workload SHA-256 values retained in each
`riscv_recursive_product.py` receipt;
`vectors/riscv_csp/recursion-shape-audit-v{1,2}.json`; and the transcript,
hash and provider contract digests named in the audit record.

## 7. In-circuit verifier obligations

Each obligation names the native check it mirrors and the typed row that
owns it. All are already present except V-5 (R-D1) and V-9 (R-D2).

| Id | Obligation | Native authority | In-circuit owner |
| --- | --- | --- | --- |
| V-1 | Interaction PoW at `INTERACTION_POW_BITS = 10` verified and absorbed before relation draws. | `proof_transcript.zig:129-131`; `protocol.zig:43` | rows 6-7 `pow_check.zig`, `pow_frame.zig` |
| V-2 | PCS PoW at `PCS_POW_BITS = 16` verified and absorbed before query draws. | `src/core/pcs/verifier.zig:303-306`; `protocol.zig:44` | rows 6-7 |
| V-3 | Every trace tree root (preprocessed, main, interaction, composition) absorbed and every queried leaf authenticated to it. | `src/core/pcs/verifier.zig:139` and decommit | rows 22-23 `merkle_root.zig`, `trace_merkle.zig`, row 33 `merkle_path.zig` |
| V-4 | Every FRI layer root absorbed and every fold opening authenticated to it. | `src/core/fri.zig:74,101` and `decommit` `:202` | rows 25-27 `fri_merkle_leaf.zig`, `fri_merkle_node.zig`, `fri_merkle_anchor.zig` |
| V-5 | 28 aggregate and all physical claims absorbed before the interaction commitment (T-4). | `proof_transcript.zig:159-183` | row 5 `transcript_payload.zig` (`vm_air_claimed_sum` kind, `:199`) plus the new physical kind |
| V-6 | FRI last-layer degree bound: coefficient count ≤ `2^log_last_layer_degree_bound` and last-layer evaluation consistent at every query. | `src/core/fri/commit_validation.zig:18-29`; `src/core/fri.zig:130-138` | row 28-29 `fri_verifier_control.zig`, `fri_verifier_input.zig`; `verify_last_layer{q}` steps |
| V-7 | Canonical query decoding: 31-bit decomposition with the all-ones alias excluded; verifier-owned mapping to positions. | `src/core/pcs/verifier.zig:308` | rows 20-21 `query_bits.zig`, `query_mapping.zig` |
| V-8 | OODS point drawn after all four commitments; composition randomness drawn after the interaction commitment. | `src/core/verifier.zig:213,244` | T-6 order; row 9 `verifier_randomness.zig` |
| V-9 | Composition-versus-mask equality at the OODS point over the hardened constraint set including public roots. | `src/core/verifier.zig:281-288` | row 18-19 `vm_air_composition_input.zig`, `vm_air_composition_control.zig`; `assert_composition` |
| V-10 | DEEP quotient equality with the values handed to FRI. | `src/core/pcs/verifier.zig` quotients | row 24 `pcs_deep_input.zig`, `pcs_deep_circuit.zig` |
| V-11 | Verifier-owned configuration: PCS parameters, tree heights, fold widths, query count are constants, never proof data. | `native_scheduled_channel.zig:382-395`; `transcript_shape.zig` | `bind_protocol`, `bind_pcs_parameters`; preprocessed columns of every row |
| V-12 | Child statement bound through the public-claim hash into the public input. | S-3, S-6 | rows 10-14 |
| **V-14** (new, R-D8) | The native proof's tree-0 (preprocessed) root absorbed at `absorb_trace_commitment{.preprocessed, 0}` MUST equal the verifier-owned root recomputed from the admitted geometry, i.e. the value `verifyPreprocessedRoot` compares against. In-circuit this is a `constant_mask = 1` payload (or a lookup against a key-pinned constant), never a `dynamicPayload(.commitment, ...)`. | `prover/statement_validation.zig:540-565`; `prover/preprocessed.zig:123-175` | row 5 `transcript_payload.zig` (`constant_mask`, `:490,521-522`); today `segment_transcript_outer_source_v2_prepared_v2.zig:474-479` classifies it dynamic. The constant MUST be pinned in the leaf key (K-8). |
| **V-15** (new) | Global LogUp cancellation with a verifier-computed public boundary: `Σ canonical claimed sums + public_boundary = 0` where the boundary equals `public_logup.sum(public_data, relations)` term for term (registers state, Merkle roots, memory access incl. public I/O, program access incl. the self-loop sentinel). | `verifier.zig:592-595` (`Protocol.publicBoundary` → `air/public_logup.zig:27-45`; `verifyGlobalCancellation`) | rows 15-17 `vm_public_semantics_circuit.zig` (public-LogUp graph) via `accumulate_public_logup_term{t}` × (70 + I/O terms, `verifier_schedule.zig:21`) and `assert_global_logup_zero`; the canonical sums consumed MUST be the row-5 `absorb_claimed_sums{28}` payload. G-2 MUST compare the graph's boundary with `public_logup.sum` on random claims. |
| **V-16** (new) | Proof-shape checks the native verifier performs before touching proof values are discharged structurally and MUST be stated as such: `commitments.len == 4` and `== trees + 1` (`verifier.zig:445`, `core/verifier.zig:215-217`), sampled-values mask shape (`core/verifier.zig:262-270`), decommitment/queried-value tree counts (`core/pcs/verifier.zig:260-262`), FRI layer count and last-layer coefficient count (`core/fri/commit_validation.zig:18-29`), Merkle witness exhaustion. In the leaf these are fixed by `segment_profile.DIMENSIONS` (`segment_profile.zig:49-60`), the fixed wire type (`fixed_wire_fixed_stark_proof_wire.zig:80-...`), the plan step counts and the verifier-owned `SampleLayout` in `graph_build.zig`. Any field of the fixed wire whose length or position is not fixed by `DIMENSIONS` is a violation. | as listed | fixed wire + plan; `query_mapping.zig` for the column→tree map |
| **V-17** (new) | Query semantics: the in-circuit decoding MUST reproduce `sampleQueryPositionsWithRaw` exactly, including de-duplication and ordering of repeated positions (`core/fri.zig` `unique`/`raw`), so that the number and order of FRI fold and Merkle-path steps per query match the native decommit. | `core/pcs/verifier.zig:308-312`; `core/fri.zig:195-215` | rows 20-21 `query_bits.zig`, `query_mapping.zig`; `verify_trace_merkle_path`/`fold_fri` step layout (`verifier_schedule.zig:426-455`) |

**V-13.** No obligation above MAY be discharged by a host-side check in the
producer. The standalone verifiers
(`recursion/detached_segment_verifier_v1.zig:1-3`,
`detached_parent_verifier_v1.zig:1-2`) are the acceptance boundary.

<!-- audit: V-14..V-17 added after comparing `verifyRiscVWithEngineUsingChannelImpl` (verifier.zig:406-770) and `core/verifier.zig` line by line against sections 3, 4 and 7. V-14 is the only one that is a soundness hole in the code as well as in the draft; V-15 exists in code (rows 15-17) but was not required by the draft; V-16/V-17 are structural and are recorded so a future wire change cannot silently relax them. -->

## 8. Non-claims

This contract does **not** claim or cover:

- proof-system soundness (`proof_system_soundness = false` in the ledger;
  PCS/FRI/list-decoding, randomized LogUp and Fiat-Shamir bit accounting are
  [`INDEPENDENT_PROOF_SYSTEM_VALIDATION.md`](INDEPENDENT_PROOF_SYSTEM_VALIDATION.md)
  work);
- FV-3 (`Word32`/M31 boundary), FV-4 (trace composition) or FV-5
  (reproduction); a sound recursion lane transports the native statement, it
  does not strengthen it;
- a security level for the q193 development profile (`protocol.zig:46`,
  `riscv_recursive_product.py:71` records
  `production_security_qualified: false`); `DEVELOPMENT_ONLY` remains true;
- the BLAKE3 recursion components (`recursion/air/blake3_*`,
  `recursion/blake3_*`), heterogeneous twins (`*_heterogeneous_v2.zig`);
- Metal or CUDA resident recursion backends and AOT bundles beyond the
  CPU/Metal artifact-parity check of G-5;
- the Ethereum and incremental composition programs
  (`ethereum_vm_composition_program_v2.zig`,
  `incremental_ethereum_vm_composition_program_v4.zig`,
  `ethereum_vm_composition_graph_base_v2.zig`) except that C-2 applies to
  their boundary-AIR replay sites if they are ever re-activated;
- the archived block-v5 route (`COMPOSITION_PREPARATION.md:1-5`);
- byte compatibility with any proof, key or bundle produced before
  `f8b64e96b`.

## 9. Qualification gates

`recursion_qualified` MAY be set to `true` only when every gate below has a
retained, reproducible passing record at the source revision named in the
ledger. Each gate names the test that implements it (existing or to be
created) and its pass criterion. A gate that is skipped under
`STWO_RECURSION_RUN_UNQUALIFIED_LANE` (`recursion_poseidon_leaf_test.zig:33`,
`leaf_manifest_contract_test_root.zig:10`) has not passed.

| Id | Gate | Implementation | Pass criterion |
| --- | --- | --- | --- |
| G-1 | Transcript byte-equivalence, native vs scheduled | New `src/tests/riscv/recursion_transcript_equivalence_test.zig`, modelled on `src/tests/riscv/transcript_path_test.zig:1-60` (event-recording channel wrapper) applied to the native verifier driven by `native_scheduled_channel.Channel`, plus `Execution.replayNative` (`transcript_program_contract.zig:155`) on the recorded leaf execution. | For one real leaf proof per profile: the ordered mix/draw/PoW event trace produced by the native prover equals that of the native verifier, equals the plan step sequence of T-6 with the exact payload word counts of `payloadWordCount` (`transcript_program_contract.zig:254-279`), and `replayNative` succeeds; the physical-claim frame is present with `total = physicalClaimCount`. Any `@hasDecl` bypass remaining in `proof_transcript.zig` fails the gate. |
| G-2 | Constraint-program equivalence | Extend `src/frontends/riscv/recursion/tests/recursion_air_composition_circuit_test.zig` (or new `vm_air_composition_equivalence_test.zig`) to evaluate the built circuit on the captured sampled values and compare with `Components.evalCompositionPolynomialAtPoint`. | For every admitted profile and for ≥ 64 random OODS seeds and random claim vectors: circuit accumulation equals the native value; `air_instruction_count` equals the sum of `constraintCountForInfra` and opcode counts; the memory component contributes 9 constraints with root inputs taken from claim words 222/232; and (V-15) the rows 15-17 public-LogUp graph evaluated on the same random claim vector and challenges equals `−public_logup.sum(public_data, relations)` so that `Σ canonical + boundary = 0` holds exactly when `verifyGlobalCancellation` would accept. |
| G-3 | Closed-forgery negative controls, in-circuit | New cases in `src/tests/riscv/recursion_poseidon_leaf_test.zig` (next to `runAdapterMutationFleet`, `recursion_poseidon_leaf_test_support.zig:245`) and `src/frontends/riscv/recursion/air/tests/universal_shared_provider_test.zig`. | Each is rejected by the standalone leaf verifier, not only by the native verifier: (a) per-batch claim shift with fixed aggregate (mirror of `malicious_prover_harness.zig:304-308`); (b) missing root binding: a boundary row with sign `+1` whose root is not `initial_rw_root`, and the sign-swap variant; (c) Merkle doubled leaf (`merkle_node.zig:700-701` mutation) ; (d) narrow provider row offered against a full-IO request with zero output lanes 1..15 (R-F1). Expected failures are named errors or `LogupSumNonZero`, never a crash. |
| G-4 | Key freshness | Extend `leaf_manifest_contract_test_root.zig` and `src/frontends/riscv/recursion/air/tests/segment_outer_adapter_manifest_v2_test.zig`. | A key whose `provider_authority_sha_id`, catalog identity, circuit identity or VM profile manifest digest differs from the current native identity fails admission with a named mismatch (`ManifestSealMismatch`, `InvalidCatalogGeometry`, `CatalogIdentityMismatch`, `AuthorityMismatch` or `DetachedParentProfileMismatch`) before proof decoding; the pre-October q193 key is such a negative control and MUST stay committed as one. |
| G-5 | End-to-end 1/2/4/8 with hostile substitution | `scripts/riscv_recursive_product.py --backend cpu` (and `--backend metal` for parity) over a regenerated admission; `scripts/riscv_segment_v2_detached_tree_gate.py`; `scripts/riscv_segment_v2_statement_substitution.py`; per-node `riscv_segment_v2_detached_gate.py:294-330` and `riscv_segment_v2_detached_parent_gate.py:268-345` mutation suites. | All genuine leaf, parent and root proofs verify in fresh processes with independently pinned keys and expected words; every same-geometry statement substitution (`riscv_recursive_product.py:185-201`), proof mutation, claim mutation, interaction-PoW case, changed canonical root, changed publication mode and lineage case is rejected with the expected error; CPU and Metal artifacts are byte-identical; `production_security_qualified` stays `false`. |
| G-6 | Build and suite | `zig build test-riscv-recursion-poseidon-leaf` (`build_support/products/riscv_cpu.zig:227-234`), `zig build test-riscv -Doptimize=ReleaseSafe`, `zig build test-riscv-prover`, `test-vm-air-profile-v2`, `test-detached-boundary`. | Green with the `STWO_RECURSION_RUN_UNQUALIFIED_LANE` skips removed and the leaf test body restored. |
| G-7 | R-D6 shard-geometry binding | New test beside G-1. | A leaf proof whose statement has a different component row count, log size or column count than the admitted catalog, but the same claim digest, is rejected by `validateStatement` or catalog admission before any transcript frame; this discharges T-3(a) together with G-8. |
| **G-8** (new) | Tree-0 / key-constant binding | New cases in `src/tests/riscv/recursion_poseidon_leaf_test.zig` and the parent gate `scripts/riscv_segment_v2_detached_parent_gate.py`. | (a) A native segment proof whose tree-0 commitment is replaced by the root of a prover-generated preprocessed tree (e.g. `is_active` extended by one row, or one lookup-table tuple altered) while every other proof field is re-proved consistently is rejected by the **standalone leaf verifier** (not only by the native verifier). (b) A parent key whose `child_key_sha256` or child `preprocessed_root` constants differ from the children actually proved fails K-8 regeneration (`preprocessed_root` mismatch) before any proof byte is read. (c) Regenerating the preprocessed tree of every committed leaf and parent key from the key's fields reproduces `preprocessed_root` exactly. |
| **G-9** (new) | No trusted-but-unabsorbed wire field | New static check beside G-1 over the row-5 payload metadata and the fixed wire. | For every `TranscriptPayloadRow` with `constant_mask = 0` the value is a fixed-wire field absorbed by its plan step before first use. Ordinary dynamic payloads are consumed (`input_use_count ≥ 1`) by exactly the named input rows; the `interaction_pow` and `pcs_pow` nonce payloads instead have `input_use_count = 0` and must each be consumed and verified by exactly one dedicated PoW plan step. For every field of `FixedStarkProofWire` there exists such a row or a Merkle/FRI path step that authenticates it; the detailed claims (post-W-1) and every commitment appear in this map; no row reads a wire field through any other path (e.g. the `segment_publication_input_provider_v2` route of R-D1 is gone). The check fails if any `constant_mask = 1` payload is not pinned by the key (K-8). |
| **G-10** (new) | Intra-lane prover/verifier transcript symmetry | Extend G-1 with the recording channel (`detached_segment_recording_components_v1.zig`, `recording_poseidon_channel_v4.zig`). | For every leaf and parent produced in G-5, the producer's recorded `Execution` (`transcript_program_contract.zig`) equals, frame for frame, the recording made by the standalone verifier's recording channel on the same proof bytes, and `replayNative` succeeds on both; any divergence is a lane-internal asymmetry and fails the gate. |

<!-- audit: G-8/G-9/G-10 added for brief items 7 and 8. G-2's pass criterion is extended below to the public boundary (V-15). -->

Each gate record MUST name the source revision, the admission file SHA-256s,
the binaries' SHA-256s and the regenerated pin values, in the style of
`vectors/reports/recursive-product-20260918/*/README.md`.

## 10. Work items

Ordered; each item's acceptance is checkable by an auditor from the named
anchors. Items 1 to 4 change identities and MUST land before any artifact is
regenerated.

**W-1 (R-D1, T-4/T-5/C-5).** Add `VerifierStep.absorb_physical_claims{count}`
with a new encode tag; append `physical_claimed_sum_count` to
`transcript_shape.derive` and `ScheduleShape`; insert the step after
`absorb_claimed_sums` in `Plan.initShape`; implement the header and payload
frame in `native_scheduled_channel` using the typed hook allowed by T-5;
the hook absorbs the exact T-4 header and ordered physical claims in one
scheduled operation after the canonical-aggregate hook. Carry the physical claims on the fixed wire
(`fixed_wire_fixed_stark_proof_wire.zig`, `Dimensions`); source row-18
detailed claims from the transcript payload instead of
`segment_publication_input_provider_v2`; update every file mirroring
`absorb_claimed_sums` (15 source files reference it; the audit record counts
~120 across tests and vectors). Acceptance: G-1 passes; `payloadWordCount`
returns `5 + 4·total` for the header and claims in the new step; plan digests
and shape ids change.

**W-2 (R-D2, C-2/C-3).** Replace `evaluateWithoutRootsGeneric` in
`vm_air_composition_circuit_graph_build.zig:283-293` and
`ethereum_vm_composition_graph_base_v2.zig` with `evaluateGeneric(...,
roots)`; add the root inputs to `InputProfile` and `vmInputCount`; bind them
in row 18 to the row-12 claim words at 221/222 and 231/232; remove every
publicly callable rootless composition evaluator. The seven-term core may
remain a private helper used only by the full nine-constraint evaluator.
Acceptance: G-2 passes; the builder no longer returns
`InvalidComponentOrder` on the hardened profile; the G-3(b) controls are
rejected; circuit identity changes.

**W-3 (R-D7, K-6).** Re-derive `segment_profile.zig` constants from the
hardened native statement (expected to move 38/625/200 and 1 071); call
`validateStatement` from `bindRiscVTranscript`. Acceptance: a mismatched
statement fails with `StatementGeometryMismatch` before proving; the
`segment_profile` self-test's pinned numbers are updated.

**W-4 (R-F1, P-2/P-6).** Add the `enabler·(1 − io) = 0` pin to the
universal shell (`hash_component.poseidonGeneralConstraintsGeneric`) and to
the compact degree-3 provider; update the comptime constraint-count pins
(`hash_component.zig:837-846`); regenerate the provider authority digest,
`CANONICAL_DIGEST`, and the sealed manifests. Acceptance: G-3(d) is rejected
with `LogupSumNonZero`; the Lean local check
`formal/riscv-refinement/check_recursive_air.py` is re-run and its source map
re-pinned if `poseidon2_universal_degree3_v1.zig` changed.

**W-5 (R-D5, K-4).** Decide and record: either update
`poseidon2_identity_migration.zig` and `riscv_recursive_identity_migration.py`
to the new canonical digest with the previous canonical as reviewed legacy, or
mark both as not applicable to pre-contract keys. Acceptance: the tool cannot
produce a key that passes G-4 from a pre-October key.

Decision (2026-10-18): retire both pre-contract migration tools. They now
fail closed; new keys must be derived from the re-aligned circuit and admitted
under fresh independent pins. No old bundle is promoted by migration.

**W-6 (regeneration runbook, K-1/K-7).** In order: (0) W-1 to W-4 landed and
identities re-pinned; (1) W-5 decided; (2) rebuild
`build-recursive-segment-v2-detached-leaf-producer`, `-parent-producer`,
`-detached-verifier`, `-parent-verifier`
(`src/integrations/riscv_cpu/build.zig:134,154,172,196`) and run the leaf
key setup; (3) `scripts/riscv_segment_v2_tree_key_setup.py` (parent
`derive-key`, `:145`) to prove leaves and derive parent keys; (4)
`scripts/riscv_segment_v2_detached_tree_gate.py` or
`scripts/riscv_recursive_product.py` for parent and root proofs plus hostile
gates, regenerating the other-admission control; (5) re-pin the K-7
inventory; (6) remove the `STWO_RECURSION_RUN_UNQUALIFIED_LANE` skips,
restore the leaf test body removed in `f8b64e96b`, run G-6. Acceptance: G-5
and G-6 records retained; `riscv_recursive_product.py` requires freshly
pinned admission and alternate-workload inputs instead of frozen constants.
The `build-recursive-segment-v2-leaf-key-setup` step now exists in
`src/integrations/riscv_cpu/build.zig`; its runner remains the same source.

**W-7 (gates G-1, G-2, G-3, G-4, G-7, G-8, G-9, G-10).** Create the tests
named in section 9 and wire them into `build_support/products/riscv_cpu.zig`
under a new `test-riscv-recursion-soundness` step. Acceptance: the step
exists, runs the named files with filters, and is green.

**W-9 (R-D8, V-14/K-8; new, audit 2026-10-18).** Make the native tree-0
root a verifier-owned constant of the leaf: compute it at key derivation from
`native_descriptors` by the same `preprocessed_trace.generate` +
`Engine.commit` path the native verifier uses
(`statement_validation.zig:547-563`), store it in the leaf key (new field,
hashed into `KeyV1.identity`), classify the `absorb_trace_commitment{.preprocessed,0}`
payload as `constant_mask = 1` in both the frozen V1 row-5 source and
`segment_transcript_outer_source_v2_prepared_v2.zig:474-479`, and implement
K-8 regeneration in the admission tooling. Acceptance: G-8 passes; the leaf
key identity and the transcript shape change (K-1). This item MUST land in
the same identity-changing batch as W-1 to W-4.

The V2 `constant_mask = 1` metadata alone does not discharge this obligation.
The current source takes the Tree-0 constant from a root independently
regenerated from native component descriptors, checks the proof frame against
it, and binds it into the source receipt. G-8 still requires a hostile
standalone leaf proof and independent key admission, plus parent-key
preprocessed-tree regeneration. A self-derived constant remains invalid even
if its row is committed in Tree 0.

**W-8 (ledger).** Apply section 11.

### Implementation checkpoint (2026-10-18)

| Work | State | Evidence or remaining condition |
| --- | --- | --- |
| W-1 | Native and V2 transcript implemented; gates open | The scheduled channel and fixed wire absorb the detailed physical claims after the 28 aggregates. `proof_transcript.zig` now selects that framing only for the exact scheduled-channel type; a test recorder exposing deceptive methods stays on the native path, and no `@hasDecl` dispatch remains in that file. The row-5 transcript payload publishes each detailed claim once, and row 18 consumes that same relation tuple once. Row 38 now contains only the 55 native LogUp boundary rows. The detached two-segment canonical CPU tree produced and independently verified both leaves and one parent root after fresh key setup and the row-38 geometry cleanup. Its gate report has SHA-256 `150db03cb8c21bf71ab3a758c735241ec7efe48979240575a43c4a22c6b4674e`; this is a local checkpoint, not a publication gate. G-1's event-by-event comparison and G-9's whole-wire mapping remain required. |
| W-2 | Composition graph assembled at development security; gates open | The V2 base graph evaluates all nine memory constraints with explicit native continuation-root inputs. Row 11 consumes the authenticated context words at indices 15 and 16 and relays their values into scope 6 for row 18; the focused row-11 test and a complete detached development tree pass. Root-bearing ProfileV2 programs use a distinct field-authority preimage while V1 rejects those bindings. G-2's differential coverage and G-3(b)'s hostile-root controls remain open. |
| W-3 | Geometry re-pinned | The hardened native leaf reported 38/627/204 columns; the frozen profile now has 877 table columns and 1,081 sampled values. |
| W-4 | Local shell fixed | Wide and compact providers constrain full IO; focused provider tests pass. End-to-end G-3(d) remains open. |
| W-5 | Migration retired | Both migration entry points fail closed for pre-contract keys. |
| W-6, W-7 | Open | Fresh 1/2/4/8 leaf-key setups completed and the focused `test-riscv-recursion-soundness` step passed 15/15 ReleaseSafe tests, but this step is only a subset of G-1 through G-10. Parent/root trees, Metal parity, adversarial cases, and the unskipped broad suites still require fresh final-identity evidence. The opt-in native leaf rejects aggregate-column and maximum-log geometry changes before transcript opening; exact re-pinned descriptor/catalog admission remains under test. |
| W-9 | Detached leaf partial | Leaf key pins native Tree0 and CPU admission independently regenerates it. Frozen V1 row-5 requires the admitted root. V2 row-5 receives a geometry-derived root separately from the proof, rejects a different proof frame, and places that root in the constant column and source identity. Parent `admit-key` regenerates the fixed key from **verified child proofs** and rejects re-pinned child-key and root mutations before parent proof production; it is not proof-free key-only reconstruction. **The leaf outer Tree0 cannot yet be independently regenerated from the current key:** its 578 fixed columns comprise 46,808,640 field cells. Row 11 has a value-independent recipe from the four retained-section counts bound into the key identity; rows 34–38 now have proof-free geometry/table recipes that match the production row-digest census. The remaining fixed-column families still require canonical key-only recipes. Copying a claimed root or raw columns is not an independent check. G-8(c) remains open for both leaf and parent, and the standalone hostile-proof G-8(a) control remains open. |
| W-8 | False | `recursion_qualified` stays false until every gate and independent review passes. |

The next K-8 leaf dependency is the PCS/FRI fixed-row profile. Its large
row-24 graph is generated without witness values, but the compiler requires
the exact per-column log sizes and ordered sample-mask layouts. Native Tree 0,
main, and interaction log sizes are now derived from the admitted component
descriptors by `detached_native_column_geometry_v1.zig`, checked before
native Tree0 regeneration, and can be compared with captured logs. The q193
security profile does not fix one native component roster: real q193 keys
have different component counts, so column counts must remain descriptor
driven. The native segment's sample-mask order is now specified alongside
those logs: Tree0 and Tree1 sample the current point; the authenticated
interaction columns sample current then previous; composition samples current.
The derived PCS profile can build its graph without proof input. Its exact
logs and mask order still need to be checked against a real captured profile
and used to regenerate row 24. A claimed profile digest or proof-derived layout
does not qualify as key-only regeneration.

The recursive AIR source map has been reviewed against the relocated S-box,
matrix, framework constraint, and interaction-prefix equations and re-pinned
to 18 files. `check_recursive_air.py` now passes its source and 10-theorem
Lean audit. Its claim remains limited to local algebra, not whole-prover
soundness.

The 2026-10-18 diagnostic two-leaf Metal run produced and independently
verified both leaves and the parent under `recursive_q193_v1`. The parent gate
passed 28 fresh-process cases (report SHA-256
`b04e95398226477a83a13acbe9072a51905c64e15846e97cb72f56dbdea04541`),
and the same-geometry statement-substitution gate passed six accept/reject
checks (report SHA-256
`b012b102267845ce36805c1dbe45a828c37c9bb614c1efc6e04fdb627a34abae`).
The CPU transcript comparison passed for two leaves and their parent (report
SHA-256 `8d5ba6447afe63dbf1a6ecbe043b91bf665cf65921a614cd331449947b6133bd`).
These diagnostic reports do not establish G-5 across 1/2/4/8 or G-10 for
Metal; the full product wrapper stopped before its final report when the Metal
parent gate lacked proof-free key admission. That wiring is repaired, and the
parent and substitution stages were rerun independently against the retained
verified leaves. G-8 and the remaining adversarial gates remain open.

The first key-only Tree0 reconstruction step now binds the four canonical
retained-section counts into the detached leaf key identity. Row 11's complete
preprocessed selector row can be regenerated from those counts, without wire
values or proof bytes, and is compared against every row of an authenticated
fixture. Fresh verification checks the key's counts against the independently
authenticated expected wire before proof decoding. A new one-leaf CPU product
and same-geometry statement-substitution gate pass under this identity
(`product.json` SHA-256
`cff1219829aef500804aa47eaaeb220c3244f6dface8f4200291b4f88b07fe5c`).
A one-leaf Metal product under the same admitted key also passes fresh
verification and statement substitution (`product.json` SHA-256
`eb9ae9f309ef8583eda58776775003aa3e00eecdb58db0c4388895c7ce3b3848`).
The native and outer preprocessed roots match the previous one-leaf fixture,
while the key identity changes. This is only a component of K-8: the other
fixed-column families and the parent root still require proof-free key-derived
regeneration before G-8(c) can pass.

A diagnostic Tree0 census over eight consecutive segment shapes produced four
distinct roots and 19 rows with varying fixed-column hashes. Two adjacent
segments with equal retained-section counts but different native
`base_alu_imm`/`load_store` row counts differed only in fixed rows 4 and 5;
this identifies the verifier transcript schedule as an input to the next
key-only recipe. Changing the initial memory word in a one-segment fixture
left all 39 fixed-row hashes and the outer Tree0 root unchanged. These are
finite observations, not a general statement-independence proof. The new
proof-free recipes for rows 11, 34 and 35 match the actual q193 census
SHA-256 values `6046533df3c32ae03a8caf2ee1d755a4c839b395cd7ba1aebc78d6f5dcdb48e3`,
`f6f8b08ada99b6065fd82b4afeba5e12f21693318865788702e11861b619f9fb`
and `72447854d4ba84f6eed889db85f0ee0d6c5529d2d1e80420f6e35f06e1173ffa`,
respectively; the focused soundness test pins all three.

## 11. Ledger update rule

1. `recursion_qualified` lives in
   [`RISCV_FRONTEND_VERIFICATION_STATUS.md`](RISCV_FRONTEND_VERIFICATION_STATUS.md)
   next to `whole_frontend_verified` and `proof_system_soundness`. It MUST be
   added there as `false` when this contract is adopted.
2. It MAY be flipped to `true` only by a commit that (a) names the source
   revision at which G-1 to G-10 passed, (b) links the retained gate records,
   (c) lists the regenerated K-7 pin values, and (d) is reviewed by one person
   who did not implement W-1 to W-7.
3. Any change caught by K-1 after the flip MUST set it back to `false` in the
   same commit as the change, and the audit-record section "Recursive RISC-V
   proofs" MUST be extended with the new divergence inventory.
4. While `false`, the phrases "recursive RISC-V proofs are sound", "the
   recursion lane is qualified" or equivalent are not permitted in any
   document, receipt or commit message. Accurate language is:

> The Poseidon2 recursive RISC-V verifier is specified by
> `soundness/RISCV_RECURSION_SOUNDNESS_CONTRACT.md` and is not qualified;
> no recursive RISC-V proof is relied on.

## Appendix A. Open items

| Where | Item | Audit status 2026-10-18 |
| --- | --- | --- |
| T-3 | Demonstrate by test (G-7) that catalog admission plus `validateStatement` pin every geometry fact `mixShardManifest` would otherwise bind. | Narrowed: geometry is pinned by the key's `native_descriptors`; the unpinned consequence is the native tree-0 root (R-D8). Closed by V-14 + G-7 + G-8. |
| C-3 | Choose between `InputProfile.vm_statement_root_count = 2` reuse and a dedicated native-root input class; confirm lowered degree stays 3. | **Resolved**: dedicated class required (roots_v3 is degree 4 and row-10-bound). See C-3. |
| P-5 | Record whether `ethereum_node_v1.zig` is intended to request the full-IO tuple; it currently does. | **Resolved**: full-IO is intended; not product-reachable; latent 2^31 collision hazard if ever paired with a narrow emitter. See P-5. |
| W-6 | `recursive-segment-v2-leaf-key-setup` build step was absent. | Resolved: `build-recursive-segment-v2-leaf-key-setup` now builds the existing runner. The proof and key regeneration sequence remains open until W-1 and W-2 land. |
| K-6 | Exact re-derived values of the `segment_profile.zig` constants were unknown. | Resolved locally: the opt-in hardened native leaf measured 38/627/204 columns, 877 table columns and 1,081 sampled values; `segment_profile.zig` now pins them. Reconfirm in the regenerated end-to-end gate. |
| S-4 | Map every `statement_validation.validate(.proof)` check to (a) key pin, (b) row semantics or (c) structure. | New, OPEN. |
| K-8 / W-9 | Native tree-0 root constant and key regeneration tooling. | Leaf-side key pin, V1/V2 row-5 constants, and independent CPU native-root regeneration are implemented. Parent `admit-key` regenerates from verified child proofs, but proof-free key-only regeneration of both outer leaf and parent Tree0 remains open, as does standalone hostile-proof qualification. |
