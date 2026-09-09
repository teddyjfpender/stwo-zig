# Raw V2 admission and register clocks — 2026-09-07

Read-only source audit; this note does not activate a profile or report a new proof/test result. References are repository-relative and describe the working tree on this date.

## Current boundary

The current inner transcript requires `selected_detailed_v3`; it explicitly rejects `field_authority_v4` (`src/integrations/riscv_cpu/recursive_common_ethereum_incremental_leaf_transcript_program_v4.zig:50`, corresponding `_support.zig:358`). The composition graph still selects outer flavor `ethereum_incremental_leaf_wrapper_v4`, not field flavor9 (`src/integrations/riscv_cpu/recursive_common_ethereum_incremental_leaf_composition_graph_v4.zig:44`). Tested opt-in helpers are not evidence of their activation.

Current cold replay is native-assisted: `rebuildVerifierInputs` cold-opens both child artifacts before materialization (`src/integrations/riscv_cpu/recursive_common_ethereum_incremental_leaf_universal_proof_v4_genuine_test.zig:843`); `FreshInput.coldOpen` decodes and invokes the complete cold verifier (`src/integrations/riscv_cpu/recursive_common_ethereum_incremental_leaf_input_v4.zig:69`). Native `StatementV2.validate` checks boundary clocks and monotonicity (`src/frontends/riscv/recursion/segment_statement_v2_contract.zig:274`). The missing relations below concern independent field-profile admission; they are not a demonstrated bypass of current native-assisted verification.

## Exact raw-word authority inventory

Ranges below are half-open. The sole layout is `src/frontends/riscv/recursion/segment_statement_v2_contract.zig:63`, exhaustively classified by `segment_statement_v2_transcript_layout.zig:117`.

| Raw words | Data | Required authority / proposed execution-only treatment |
| --- | --- | --- |
| `[0,4)` | Tag/version/flags | Fixed protocol constants. |
| `[4,12)` | `session_id` | Explicit external namespace admission; not implicitly the outer SessionV1 identity. |
| `[12,20)` | `job_id` | Derive from the authenticated span job preimage. |
| `[20,28)` | `position_id` | Derive from session/job, segment position, cycle and slot ranges. |
| `[28,52)` | Entry/exit/combined lineage IDs | Derive for canonical-document admission; depend on boundary metadata and namespace. Potential private committed metadata only under an explicitly narrower execution claim. |
| `[52,60)` | `base_statement_id` | Existing preimage derives it from412 authenticated span words. A private auxiliary ID must not substitute for that public binding. |
| `[60,472)` | SpanStatement | Existing scope0 route; preserve all412 same-value bindings. |
| `[472,480)`, `[484,492)` | Snapshot IDs | Snapshot identity semantics required for canonical-document admission; potentially private committed metadata for execution-only admission. |
| `[480,482)`, `[492,494)`, `[504,506)`, `[514,516)` | Four counts | Independently admitted geometry, with repeated retained-section counts using the same coordinates. Observing a count is not admission. |
| `[482,484)`, `[494,496)` | Continuation roots | Canonical split-u16 joins to statement295/378; actual public/native root semantics must remain. |
| `[496,504)`, `[506,514)` | Memory-clock IDs | Canonical-document admission needs their retained-clock identity semantics; potentially private committed metadata under execution-only admission. |
| `[516,580)`, `[580,644)` | Entry/exit register clocks | Existing scope5 transport; raw canonical/boundary clock relations remain missing as detailed below. |
| `[644,652)` | Completion tag/kind/address/value/clock | Explicit nonfinal profile may require absent tag plus seven zero words. This is distinct from the role completion tuple's program-fetch kind3 and clock0. |
| After652 | Four retained sections | Each has tag + two count limbs + four words per entry. Tags fixed; counts admitted and repeated consistently. Payload semantics required for full V2 validity; private hash inputs are only a candidate for an explicit execution-only claim. |

Shared scalar identity emission already exists at `src/frontends/riscv/recursion/segment_statement_v2_identity_preimage.zig:68` for job/base/position/lineage phases. A narrower claim must retain external session/job/position binding; it must never turn auxiliary witness bytes into proof-dependent preprocessing constants.

The reason execution-only auxiliary treatment is worth considering is concrete: `src/frontends/riscv/air/incremental_public_logup_v4.zig:238` subtracts sparse RW and sparse continuation-tree compensation before adding role-aware IO/program terms. Retained sparse arrays therefore do not independently remain in the resulting execution public sums. This observation alone does not admit a profile or discharge public roots, register clocks, role sources, or namespace bindings.

## Clock finding, narrowed against existing constraints

There are already real, active claim-clock constraints. `src/frontends/riscv/recursion/vm_public_semantics_circuit_constrain_output_header_and_addresses.zig:292` constrains canonical claim clocks, including register-last-clock words146–209, with `constrainCanonicalM31U32` and `constrainAccessClockWithinExecution`. Their graph takes canonical claim words and the412 span words (`:55`); `vm_public_semantics_circuit_contract.zig:233` equates the claim instruction count to the segment cycle count. These checks should not be duplicated or described as absent.

However, raw V2 entry/exit clocks are separate inputs. `src/integrations/riscv_cpu/recursive_common_ethereum_incremental_leaf_public_sums_v4_support.zig:282` allocates128 raw clock limbs; `:507` joins them into memory-access tuples, using `u32At` at `:738`. Their scope5 route supplies u16 bounds (`recursive_common_ethereum_incremental_leaf_statement_routing_v4.zig:90`). No pointwise equality ties these raw clock limbs to the canonical claim's register-last-clock limbs. The claim's segment-relative count is also not a substitute for the raw entry/end boundary cycles in the admitted native statement frame.

Native opcode memory constraints derive successor access clocks and range-check strict predecessor gaps (`src/frontends/riscv/air/semantics/common.zig:225`). They do not establish every raw boundary limb encoding: an untouched register's matching entry/exit tuples cancel, and the u16 pair `(65535,32767)` recomposes to the M31 modulus, hence field zero. That observation demonstrates why field tuple equality alone is insufficient; no end-to-end forged proof was constructed.

Native semantics are precise: `src/frontends/riscv/access_clock.zig:31` defines access clocks as `4*(instruction_clock-1)+ordinal+1`; legal nonzero residues are1,2,3 modulo4. `segment_statement_v2_contract.zig:390` requires positive execution length and checked end≤2^24; `:417` bounds each boundary clock by its respective cycle, and `:274` also requires entry≤exit. The bound is **4*boundary_cycle−1**, not boundary_cycle itself.

For the real retained STWIEF04 route, this native statement frame is already
**normalized leaf-local**, not the absolute block clock. The V4 capture observer
calls `segment_leaf_local_projection_v3.ProjectionV3`; its
`localStatementFromMetadata` sets native `executed.first_cycle=0` and the local
job's total cycles to the leaf count, while retaining segment index/count and
CPU/memory endpoints. The existing 2^24 check therefore bounds a single native
leaf. It does not imply a whole-block 16M-cycle ceiling or justify widening the
shared V2 limit. `FreshInputV4.statementWordsFromFresh` returns this local span.
Absolute block start/end remain u64 in the separate
`segment_leaf_local_authority_v3.MetadataV3`, with a native
`segment_leaf_local_verified_link_v3.VerifiedLinkV3` joining that metadata to a
verified local receipt. The exact global-to-local AIR linkage in the active
root remains a prerequisite; these native custody objects do not discharge it.
See `2026-09-07-real-leaf-readiness.md` for the complete source-path cross-check.

Smallest shared relation design: extend the existing public-sums graph using the existing scope5 limbs, not a new source/AIR. Bind boolean bit witnesses pointwise to each u16 limb; establish checked positive cycle range with end≤2^24; require each clock to be zero or have nonzero low-two-bit residue and `clock>>2 < boundary_cycle`; require entry≤exit per register. This bound already excludes M31 aliases. Reuse decomposition/comparison patterns from `statement_semantics_circuit_build.zig:230` and `:377`, and the access-clock construction at `vm_public_semantics_circuit_constrain_output_header_and_addresses.zig:375`. A shared zero-aware variant is necessary: the existing claim helper unconditionally checks bucket<cycle, so it rejects valid raw entry `(cycle0,clock0)`. Gate that comparison by nonzero while preserving existing positive-execution claim behavior.

Required regressions (not run or implemented by this audit):

- Accept cycle0/clock0 entry and untouched zero→zero registers.
- Reject modulus-as-zero limbs `(65535,32767)` even when entry/exit field tuples cancel.
- Reject nonzero residue0, e.g. clock4; accept the final legal subclock `4*b−1` and reject the first legal clock of the next bucket `4*b+1` at boundary cycle b.
- Reject exit<entry even if each independently fits its boundary; exercise a nonzero segment start.
- Reject cycle addition overflow, zero execution length, and end>2^24; accept end=2^24.
- Mutate raw clock limbs independently of canonical claim clocks, and vice versa, so tests cannot accidentally check only the already-constrained vector.
- Preserve raw transcript/hash same-word equality; reject omitted or duplicate root publishers and noncanonical root joins.

## Existing source owners and bounded activation order

Preprocessed-root authority comes from committing `secure_cohort.fillPreprocessedInto` under session PCS geometry (`src/integrations/riscv_cpu/recursive_common_ethereum_incremental_leaf_secure_cohort_v4.zig:441`). Reuse/factor `recursive_temporal_secure_parent_native_engine_v1.zig:1834`, which currently recomputes and compares the root but returns void. A proof-supplied root or cache key is not an independent owner. Wire term count already comes from `nativeCore().publicWireBoundaryTermCount()` (`recursive_common_ethereum_incremental_leaf_native_core_v4.zig:545`), derived from the immutable admitted public-term plan.

Bounded sequence: (1) implement and mutation-test raw boundary clock semantics; (2) settle explicit execution-only versus canonical-document admission, retaining external namespace binding; (3) compile schema4 shared frame descriptors without catchall dynamic constants; (4) select the existing raw/hash/root topology exactly once per word and close remaining typed source obligations; (5) supply outer field admission from the independently derived preprocessing root and plan term count before selecting flavor9. No step here authorizes activation.

The fixed topology owner is `src/frontends/riscv/recursion/ethereum_publication_routing_v1.zig:5`: raw hash scope1120, authority hash scope1121, raw source scope1114/base256. Root raw words482/483/494/495 export twice at source738/739/750/751: one use publishes the hash word, the other enters the canonical root join. Every other raw word publishes1120 once; activation must skip the old duplicate statement/clock hash-source rows. The opt-in row5 helper documents this at `air/ethereum_transcript_payload_raw_v1.zig:70`, and joins are implemented at `src/integrations/riscv_cpu/recursive_common_ethereum_incremental_leaf_native_identity_routing_v4.zig:135`.


## Implemented checkpoint after the audit

The raw-clock relation described above is now implemented in the existing public-sums graph under schema7, with 1,739 constrained private Boolean inputs and the same 128 raw limb sources. Five focused clock gates, the 121-case integration/small-proof run, the genuine complete wrapper lifecycle (3/3), and separate-process replay (1/1) passed. Public-sums program identity now binds Ethereum cohort keys and cache admission; unused geometry-only key helpers were subsequently removed and checked. See the [complete-proof receipt](2026-09-07-raw-clock-program-admission/complete-proof.json) and [separate-process receipt](2026-09-07-raw-clock-program-admission/fresh-process-replay.json).

This closes raw clock encoding, native-frame bounds and monotonicity in the active wrapper. It does not activate field-authority schema4/outer flavor9 or the global MetadataV3 link in the active root. The remaining inventory and narrower/full-document admission decision above still apply.
