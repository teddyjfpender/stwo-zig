# Keccak optimization must consume the existing AIR authority

Read-only review of the active Ethereum route after the native19 attribution. No production source edits, builds, or proof jobs. The first optimization should preserve the current admitted circuit, claim ordering, transcript, and worker policy; changing the compact lookup profile is a separate protocol decision.

## Existing sources of truth

Paths below are relative to `src/frontends/riscv/` unless otherwise specified.

| Concern | Existing authority to consume |
|---|---|
| Keccak execution semantics, round constants, rotations, paired-slot geometry | `air/guest_precompile/keccakf_authority.zig`; `keccakf_witness.zig` consumes it |
| Column placement and width | `air/guest_precompile/keccakf_trace.zig:33` (`Layout`), `keccakf_caller.zig` for appended caller columns; component `Placement` owns global offsets |
| Direct constraint expressions and canonical root order | `air/guest_precompile/keccakf_direct.zig:34`, **`evaluateGeneric(S, ..., sink)`**; shared today by native point, domain, and recursive recording scalar |
| Lookup tuple construction, event order, pairing and batch count | `air/guest_precompile/keccakf_interaction_plan.zig:63`, **`rowPairsGeneric`**; `rowPairs` and `rowPairsBase` are thin typed wrappers, not duplicate definitions |
| Relation combination and caller/public boundary | `keccakf_relations.zig`, `keccakf_caller.zig`, shared `air/logup.zig` relations; do not reconstruct challenge or tuple ordering in a backend |
| LogUp transition polynomial | `air/logup.zig:324`, **`pairConstraintGeneric`**; its scalar wrapper delegates unchanged |
| Witness interaction generation and table closure | `keccakf_interaction.zig` consumes the same interaction plan; `keccakf_tables.zig`, `keccakf_table_interaction.zig`, and `keccakf_table_component.zig` own fixed-table semantics/claims |
| State mask offsets and OODS geometry | `keccakf_component.zig:31` (`STATE_MASK_OFFSETS`); `recursion/sample_point_layout.zig` already imports it; production `maskPoints` supplies recursive extension mask admission |
| Circuit selection, component/claim order | `prover/ethereum_circuit_profile_v1.zig`, `prover/guest_precompile/ethereum_assembly.zig`, existing Ethereum statement/transcript modules; SIMD/GPU must not own an alternate roster |
| Recursive expressions | `recursion/ethereum_vm_composition_graph_extension_v2.zig:130` calls those same direct and lookup generics over the canonical recording scalar, then shared LogUp accumulation |

Domain versus point sampling, denominator construction, and accumulator sinks are legitimately different backends for the same formula. Keeping those adapters does not imply maintaining separate AIR semantics.

## SIMD and GPU boundary

For SIMD, retain the existing prepared input owner and row-index geometry. Pack independent evaluation rows; use the same direct evaluator and lookup/pair-constraint authority with a lane scalar and secure lane scalar. Preserve all off-domain rows: active selectors do not authorize skipping padded constraint evaluations at arbitrary evaluation points. Preserve canonical random-power indexing and per-row quotient denominators. `InteractionScalar(S)`, `lift`, `denominator`, and `mulSmall` currently specialize M31/QM31 and use a recording-scalar fallback; SIMD support must extend those shared scalar adapters explicitly, not copy `rowPairsGeneric` into a vector-only implementation. The typed field implementation supplies arithmetic; the frontend supplies formulas.

For GPU, the current Keccak adapter has **no** backend capability. `src/prover/air/component_programs.zig:48` explicitly requires exporters to derive programs from the production evaluator. Existing `base_polynomial_codegen.zig` and `lookup_polynomial_codegen.zig` under the Metal runtime consume content-addressed programs. Use this model and admitted source/AOT identity; never handwrite a second Metal Keccak constraint body or embed proof-specific challenges/claims in a fixed circuit identity.

There is a concrete ABI limitation: current `BasePolynomialCapabilityV1` exposes a contiguous current-main block plus one selector, while Keccak needs 29 row selectors, second-active, previous I/O and state windows at -2/-1/+1/+2/+27. Existing lookup capability parameter ordering is also specific and must be respected. Therefore attaching an existing current-row capability is not sufficient. Any future device input projection must be derived from the shared mask/layout authority and explicitly admitted by the capability contract. Do not disguise duplicated/shifted columns as an undocumented new frontend layout. SIMD over the existing owner avoids that capability expansion for the first measured fix.

## Concrete cleanup associated with the working replacement

1. **Remove repeated full-row orchestration, not the generic formulas.** Native point evaluation (`keccakf_component.zig:295`) and domain evaluation (`:641`) separately call direct constraints, construct lookup pairs, and append them in the same order; recursive recording repeats that ordering in `ethereum_vm_composition_graph_extension_v2.zig:196`. A small shared row evaluator/ordered sink seam can consume sampled inputs and emit direct constraints then LogUp transitions. Move all active callers together after point/domain/recording parity gates. Do not add a fourth independent loop for SIMD and leave three authoritative orders behind.
2. **Consolidate mask projection.** The offset array is shared, but `samplePoint` hardcodes sample ordinals 1–5, domain preparation hardcodes the six shift computations, and recursive recording names those offsets separately. Consume one named offset/projection table across those samplers when touching them. Keep native and recursive geometry tests proving exact positions, not just sample counts.
3. **Fix an actual stale description.** `keccakf_direct.zig` says 6,043 roots in its header; its compile-time check pins 6,174. The log 16 shard description in `keccakf_trace.zig` should state that it describes the legacy ceiling; the admitted Ethereum profile is log 18. These are documentation corrections, not authority changes.
4. **Keep genuine alternatives out of production ownership.** `keccakf_adaptive_profile_v1.zig` explicitly says non-production, and the throughput/xor-throughput plans intentionally change lookup interpretation. They are candidate experiments, not equivalent dead copies of the active compact AIR. No unused active Keccak proof route was established by this review. Do not delete them as a supposed correctness repair or silently promote them. If a later selected replacement supersedes an active loop, remove that loop in the same proof-gated change.

## Minimum promotion evidence

Retain genuine direct-row/caller/memory mutation cases from `keccakf_air_test.zig`; compare scalar and new domain output, including claim/pole failures and tail lanes. Existing recursive tests `Ethereum extension evaluators replay over the canonical recording scalar` and `Ethereum extension mask geometry is derived from production vtables` check the shared recording path. Consume the already working one-call full-VM serialization → producer destruction → independent verification route, then the 1/4/16-call ladder and retained native19 only after small gates pass. Confirm exact admitted identities and proof verification, not merely a faster component kernel. Root owns the serial execution lane and actual receipts.
