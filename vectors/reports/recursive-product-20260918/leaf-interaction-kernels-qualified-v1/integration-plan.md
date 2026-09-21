# Leaf interaction integration findings

The kernel/adapter checkpoint covers all 37 leaf and 29 parent typed AIRs, at 512 live rows and 509 live rows in a 512-row trace. The new exporter adds 12 distinct kernels (93 -> 105 additional exports) and leaves all previous declarations unchanged. It does not yet activate leaf proof dispatch.

Implement an explicit generation interface through the shared leaf writers. Avoid thread-local hooks or storing a borrowed generator context in retained workspaces. Avoid computing CPU interaction columns and then regenerating them on GPU. Keep a host-default wrapper for existing callers, with a generator-aware entry point for the actual detached leaf transaction.

A small host generator in `air/framework_interaction.zig` can expose the existing `generatePreparedInto` and `generatePreparedIntoWithDomainSums` surface, taking Framework as a comptime argument and the existing workspace. A leaf backend generator can implement that interface using `framework_device_interaction.generateInto`. Filter canonical leaf catalog entries at comptime by compatible Plan type, then require the authenticated plan's `semantic_digest` to match the selected Air. The plan stores that field explicitly. Use canonical `segment_leaf_parameters_v2.parametersFor(entry, key.parameters)` for profile values. The catalog's `requires_location` controls Air.build. Prefer existing retained direct plans where accessible; if a canonical direct program is rebuilt cold, keep ownership/error cleanup explicit and measure that overhead.

For audited GPU generation, obtain exact domain sums from `plan.auditPreparedDomainSums` using the GPU claim. This is independent CPU audit work, not duplicate CPU column generation. Existing noncore audits remain unchanged. The core's shared `prepared_interaction_generation` helper must accept the generator and preserve its optional independent audit and tuple-ledger projection. GPU errors propagate; fallback is only for an unavailable admitted device profile, as in the parent route.

Thread the explicit generator through:
- `detached_leaf_cohort_v2` -> noncore/core prepareInteractions, preserving both staged preparations before publication.
- `detached_leaf_noncore_runtime_v2`: transcript fill, statement fill, public fill, boundary rebuild, and verifier-input-provider rebuild.
- `segment_transcript_outer_components_v2_fill_interaction_into.zig`: ten framework calls.
- `segment_public_outer_components_v2_fill_interaction_into.zig`: four relay calls, public sums, and control relay.
- `segment_statement_outer_components_v2.zig`: row 11 delegates to statement.generateInteractionInto; follow that owning function. Row 10 is an intentionally inactive fast path: it authenticates the zero-row direct program and every numerator, then publishes zero columns. Preserve that validated zero path; do not add pointless device work merely to force 37 dispatches.
- `segment_leaf_outer_authority_v2_verify_authority_into.zig`: statement and public-logup writers, including the per-domain result.
- `segment_publication_input_provider_authority_v2.zig`: its framework writer returns domain sums.
- `detached_fri_core_part_03.zig` cold preparation and part21 generation orchestration: preserve cached relation-context validation and publication.

Only the actual detached leaf proof selects the backend generator. Its independently admitted `key.parameters` is available before interaction filling in `recursive_segment_v2_detached_proof.zig`. Extend telemetry checks with the actual active typed dispatch count (row10 remains verified zero); keep native-table 24-per-leaf and parent 116-per-parent checks distinct. Qualify complete CPU/Metal proofs and all hostile/same-geometry checks before claiming pipeline integration or a speedup.

Do not source GPU inputs from the external TreeStorage columns after commit: TreeStorage.commit transfers evaluation/backing ownership to PCS and empties its owned buffers. Those slice headers are not a new lifetime guarantee. The adapter's existing path builds columns from owned logical rows; preserve it.

Transaction storage is now shared in `transaction_storage_v2.zig`, with a byte-identical body after the direct manifest import change and a 16-test focused pass. Its full-proof qualification is intentionally pending the integrated leaf work. The legacy `recursive_segment_v2_outer_engine` also depends on publication/artifact contracts and a tracked Ethereum allocator; it needs a separate cohesive review, not blind substitution of its allocator.
