//! Cohesive internal authority extracted from recursive_fri_outer.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const prover_work_pool = context.d_prover_work_pool;
        const M31 = context.d_M31;
        const QM31 = context.d_QM31;
        const air = context.d_air;
        const composition_control_witness = context.d_composition_control_witness;
        const query_bits_witness = context.d_query_bits_witness;
        const query_mapping_witness = context.d_query_mapping_witness;
        const merkle_root_witness = context.d_merkle_root_witness;
        const pcs_witness = context.d_pcs_witness;
        const input_witness = context.d_input_witness;
        const lowering = context.d_lowering;
        const multiply_witness = context.d_multiply_witness;
        const inverse_witness = context.d_inverse_witness;
        const linear_witness = context.d_linear_witness;
        const merkle_path_witness = context.d_merkle_path_witness;
        const shared_provider = context.d_shared_provider;
        const universal = context.d_universal;
        const poseidon2_air = context.d_poseidon2_air;
        const LogIndex = context.d_LogIndex;
        const InputRelation = context.d_InputRelation;
        const CompositionControlRelation = context.d_CompositionControlRelation;
        const QueryBitsRelation = context.d_QueryBitsRelation;
        const QueryMappingRelation = context.d_QueryMappingRelation;
        const MerkleRootRelation = context.d_MerkleRootRelation;
        const PcsRelation = context.d_PcsRelation;
        const MultiplyRelation = context.d_MultiplyRelation;
        const InverseRelation = context.d_InverseRelation;
        const LinearRelation = context.d_LinearRelation;
        const MerklePathRelation = context.d_MerklePathRelation;
        const InputFramework = context.d_InputFramework;
        const VmInputFramework = context.d_VmInputFramework;
        const CompositionControlFramework = context.d_CompositionControlFramework;
        const QueryBitsFramework = context.d_QueryBitsFramework;
        const QueryMappingFramework = context.d_QueryMappingFramework;
        const MerkleRootFramework = context.d_MerkleRootFramework;
        const TraceMerkleFramework = context.d_TraceMerkleFramework;
        const PcsFramework = context.d_PcsFramework;
        const FriLeafFramework = context.d_FriLeafFramework;
        const FriNodeFramework = context.d_FriNodeFramework;
        const FriAnchorFramework = context.d_FriAnchorFramework;
        const ControlFramework = context.d_ControlFramework;
        const MultiplyFramework = context.d_MultiplyFramework;
        const InverseFramework = context.d_InverseFramework;
        const LinearFramework = context.d_LinearFramework;
        const MerklePathFramework = context.d_MerklePathFramework;
        const PublicBoundaryClaims = context.d_PublicBoundaryClaims;
        const Claims = context.d_Claims;
        const RelationDomain = context.d_RelationDomain;
        const ClosureAudit = context.d_ClosureAudit;
        const emptyDomainAudit = context.d_emptyDomainAudit;
        const recordDomainAudit = context.d_recordDomainAudit;
        const PreparedRelationRows = context.d_PreparedRelationRows;
        const Authority = context.d_Authority;
        const admittedSegmentLeafBundle = context.d_admittedSegmentLeafBundle;
        const InvocationBuffers = context.d_InvocationBuffers;
        const MerklePathBuffers = context.d_MerklePathBuffers;
        const PoseidonCallBuffers = context.d_PoseidonCallBuffers;
        const appendWireBoundaryTuples = context.d_appendWireBoundaryTuples;
        const verifierInputBoundaryClaim = context.d_verifierInputBoundaryClaim;
        const appendVerifierInputBoundaryTuples = context.d_appendVerifierInputBoundaryTuples;
        const placementOffset = context.d_placementOffset;
        const copyInteraction = context.d_copyInteraction;
        const TreeStorage = context.d_TreeStorage;

        pub fn fillInteraction(
            allocator: std.mem.Allocator,
            authority: *const Authority,
            tree: *TreeStorage,
            evaluations: input_witness.Evaluations,
            pcs_inputs: pcs_witness.InputWitness,
            arithmetic_evaluations: lowering.Evaluations,
            invocations: *const InvocationBuffers,
            query_witness: query_bits_witness.QueryWitness,
            root_witness: merkle_root_witness.RootWitness,
            merkle_paths: *const MerklePathBuffers,
            poseidon_calls: *const PoseidonCallBuffers,
            prepared_relation_rows: *const PreparedRelationRows,
            provider_relations: *const shared_provider.SharedProviderRelations,
            relations: *const universal.UniversalRelations,
            closure_audit: ?*ClosureAudit,
        ) !Claims {
            const segment_leaf_claims = if (authority.segment_transcript_inputs != null) blk: {
                const bundle = try admittedSegmentLeafBundle(authority);
                break :blk try bundle.fillInteractionInto(
                    &authority.manifest,
                    relations,
                    provider_relations,
                    tree.columns,
                );
            } else null;
            if (closure_audit) |audit| if (authority.segment_transcript_inputs != null) {
                const bundle = try admittedSegmentLeafBundle(authority);
                const bundle_audits = try bundle.auditInteractionDomains(
                    relations,
                    provider_relations,
                    segment_leaf_claims.?,
                    audit.tupleLedger(),
                );
                @memcpy(audit.rows[0..10], &bundle_audits.transcript);
                audit.rows[@intFromEnum(air.universal_roster.Component.statement_input)] =
                    bundle_audits.statement.statement_input;
                audit.rows[
                    @intFromEnum(
                        air.universal_roster.Component.statement_semantics_input,
                    )
                ] = bundle_audits.statement.statement_semantics;
                audit.rows[@intFromEnum(air.universal_roster.Component.range_check_8_8)] =
                    bundle_audits.statement.range_check;
                @memcpy(audit.rows[12..18], &bundle_audits.public);
            };
            const vm_input_claim = if (authority.vm_air != null) blk: {
                var generated = try VmInputFramework.generatePrepared(
                    allocator,
                    &authority.vm_air.?.relation,
                    prepared_relation_rows.vm_input,
                    authority.log_sizes[LogIndex.vm_input],
                    relations,
                );
                defer generated.deinit(allocator);
                copyInteraction(
                    tree,
                    placementOffset(authority, .vm_air_composition_input, 2),
                    &generated.columns,
                );
                try recordDomainAudit(
                    allocator,
                    &authority.vm_air.?.relation,
                    prepared_relation_rows.vm_input,
                    relations,
                    generated.claimed_sum,
                    closure_audit,
                    .vm_air_composition_input,
                );
                break :blk generated.claimed_sum;
            } else QM31.zero();
            const composition_control_claim = blk: {
                const rows = try allocator.alloc(
                    CompositionControlRelation.Row,
                    authority.composition_control_preprocessing.rows.len,
                );
                defer allocator.free(rows);
                for (
                    authority.composition_control_preprocessing.rows,
                    rows,
                ) |source, *destination| {
                    destination.* = composition_control_witness.logicalRow(
                        source,
                        .segment_leaf,
                    );
                }
                var generated = try CompositionControlFramework.generatePrepared(
                    allocator,
                    &authority.composition_control_relation,
                    rows,
                    authority.log_sizes[LogIndex.composition_control],
                    relations,
                );
                defer generated.deinit(allocator);
                copyInteraction(
                    tree,
                    placementOffset(authority, .vm_air_composition_control, 2),
                    &generated.columns,
                );
                try recordDomainAudit(
                    allocator,
                    &authority.composition_control_relation,
                    rows,
                    relations,
                    generated.claimed_sum,
                    closure_audit,
                    .vm_air_composition_control,
                );
                break :blk generated.claimed_sum;
            };
            const query_bits_claim = blk: {
                const query_parameters = try query_bits_witness.parameterValues(
                    authority.query_bits_reference,
                    query_witness.proofKind(),
                );
                const rows = try allocator.alloc(
                    QueryBitsRelation.Row,
                    authority.query_bits_preprocessing.rows.len,
                );
                defer allocator.free(rows);
                for (authority.query_bits_preprocessing.rows, rows) |source, *destination|
                    destination.* = try query_bits_witness.logicalRow(
                        source,
                        query_witness,
                        query_parameters,
                    );
                var generated = try QueryBitsFramework.generatePrepared(
                    allocator,
                    &authority.query_bits_relation,
                    rows,
                    authority.log_sizes[LogIndex.query_bits],
                    relations,
                );
                defer generated.deinit(allocator);
                copyInteraction(
                    tree,
                    placementOffset(authority, .query_bits, 2),
                    &generated.columns,
                );
                try recordDomainAudit(
                    allocator,
                    &authority.query_bits_relation,
                    rows,
                    relations,
                    generated.claimed_sum,
                    closure_audit,
                    .query_bits,
                );
                break :blk generated.claimed_sum;
            };
            const query_mapping_claim = blk: {
                const rows = try allocator.alloc(
                    QueryMappingRelation.Row,
                    authority.query_mapping_preprocessing.rows.len,
                );
                defer allocator.free(rows);
                for (authority.query_mapping_preprocessing.rows, rows) |source, *destination|
                    destination.* = try query_mapping_witness.logicalRow(source, query_witness);
                var generated = try QueryMappingFramework.generatePrepared(
                    allocator,
                    &authority.query_mapping_relation,
                    rows,
                    authority.log_sizes[LogIndex.query_mapping],
                    relations,
                );
                defer generated.deinit(allocator);
                copyInteraction(
                    tree,
                    placementOffset(authority, .query_mapping, 2),
                    &generated.columns,
                );
                try recordDomainAudit(
                    allocator,
                    &authority.query_mapping_relation,
                    rows,
                    relations,
                    generated.claimed_sum,
                    closure_audit,
                    .query_mapping,
                );
                break :blk generated.claimed_sum;
            };
            const merkle_root_claim = blk: {
                const rows = try allocator.alloc(
                    MerkleRootRelation.Row,
                    authority.merkle_root_preprocessing.rows.len,
                );
                defer allocator.free(rows);
                for (authority.merkle_root_preprocessing.rows, rows) |source, *destination|
                    destination.* = try merkle_root_witness.logicalRow(source, root_witness);
                var generated = try MerkleRootFramework.generatePrepared(
                    allocator,
                    &authority.merkle_root_relation,
                    rows,
                    authority.log_sizes[LogIndex.merkle_root],
                    relations,
                );
                defer generated.deinit(allocator);
                copyInteraction(
                    tree,
                    placementOffset(authority, .merkle_root, 2),
                    &generated.columns,
                );
                try recordDomainAudit(
                    allocator,
                    &authority.merkle_root_relation,
                    rows,
                    relations,
                    generated.claimed_sum,
                    closure_audit,
                    .merkle_root,
                );
                break :blk generated.claimed_sum;
            };
            const trace_merkle_claim = blk: {
                var generated = try TraceMerkleFramework.generatePrepared(
                    allocator,
                    &authority.trace_merkle_relation,
                    prepared_relation_rows.trace_merkle,
                    authority.log_sizes[LogIndex.trace_merkle],
                    relations,
                );
                defer generated.deinit(allocator);
                copyInteraction(
                    tree,
                    placementOffset(authority, .trace_merkle, 2),
                    &generated.columns,
                );
                try recordDomainAudit(
                    allocator,
                    &authority.trace_merkle_relation,
                    prepared_relation_rows.trace_merkle,
                    relations,
                    generated.claimed_sum,
                    closure_audit,
                    .trace_merkle,
                );
                break :blk generated.claimed_sum;
            };
            const pcs_deep_claim = blk: {
                const rows = try allocator.alloc(
                    PcsRelation.Row,
                    authority.pcs_preprocessing.rows.len,
                );
                defer allocator.free(rows);
                for (authority.pcs_preprocessing.rows, rows) |source, *destination| {
                    const value = pcs_inputs.lanes[source.lane].input_values[source.binding];
                    destination.* = pcs_witness.logicalInputs(
                        (pcs_witness.MainRow{
                            .enabler = M31.one(),
                            .value = value,
                        }).values(),
                        source.values(),
                        .segment_leaf,
                    );
                }
                var generated = try PcsFramework.generatePrepared(
                    allocator,
                    &authority.pcs_relation,
                    rows,
                    authority.log_sizes[LogIndex.pcs_deep],
                    relations,
                );
                defer generated.deinit(allocator);
                copyInteraction(
                    tree,
                    placementOffset(authority, .pcs_deep_input, 2),
                    &generated.columns,
                );
                try recordDomainAudit(
                    allocator,
                    &authority.pcs_relation,
                    rows,
                    relations,
                    generated.claimed_sum,
                    closure_audit,
                    .pcs_deep_input,
                );
                break :blk generated.claimed_sum;
            };
            const fri_leaf_claim = blk: {
                var generated = try FriLeafFramework.generatePrepared(
                    allocator,
                    &authority.fri_leaf_relation,
                    prepared_relation_rows.fri_leaf,
                    authority.log_sizes[LogIndex.fri_leaf],
                    relations,
                );
                defer generated.deinit(allocator);
                copyInteraction(
                    tree,
                    placementOffset(authority, .fri_merkle_leaf, 2),
                    &generated.columns,
                );
                try recordDomainAudit(
                    allocator,
                    &authority.fri_leaf_relation,
                    prepared_relation_rows.fri_leaf,
                    relations,
                    generated.claimed_sum,
                    closure_audit,
                    .fri_merkle_leaf,
                );
                break :blk generated.claimed_sum;
            };
            const fri_node_claim = blk: {
                var generated = try FriNodeFramework.generatePrepared(
                    allocator,
                    &authority.fri_node_relation,
                    prepared_relation_rows.fri_node,
                    authority.log_sizes[LogIndex.fri_node],
                    relations,
                );
                defer generated.deinit(allocator);
                copyInteraction(
                    tree,
                    placementOffset(authority, .fri_merkle_node, 2),
                    &generated.columns,
                );
                try recordDomainAudit(
                    allocator,
                    &authority.fri_node_relation,
                    prepared_relation_rows.fri_node,
                    relations,
                    generated.claimed_sum,
                    closure_audit,
                    .fri_merkle_node,
                );
                break :blk generated.claimed_sum;
            };
            const fri_anchor_claim = blk: {
                var generated = try FriAnchorFramework.generatePrepared(
                    allocator,
                    &authority.fri_anchor_relation,
                    prepared_relation_rows.fri_anchor,
                    authority.log_sizes[LogIndex.fri_anchor],
                    relations,
                );
                defer generated.deinit(allocator);
                copyInteraction(
                    tree,
                    placementOffset(authority, .fri_merkle_anchor, 2),
                    &generated.columns,
                );
                try recordDomainAudit(
                    allocator,
                    &authority.fri_anchor_relation,
                    prepared_relation_rows.fri_anchor,
                    relations,
                    generated.claimed_sum,
                    closure_audit,
                    .fri_merkle_anchor,
                );
                break :blk generated.claimed_sum;
            };
            const control_claim = blk: {
                var generated = try ControlFramework.generatePrepared(
                    allocator,
                    &authority.control_relation,
                    prepared_relation_rows.control,
                    authority.log_sizes[LogIndex.fri_control],
                    relations,
                );
                defer generated.deinit(allocator);
                copyInteraction(
                    tree,
                    placementOffset(authority, .fri_verifier_control, 2),
                    &generated.columns,
                );
                try recordDomainAudit(
                    allocator,
                    &authority.control_relation,
                    prepared_relation_rows.control,
                    relations,
                    generated.claimed_sum,
                    closure_audit,
                    .fri_verifier_control,
                );
                break :blk generated.claimed_sum;
            };
            const input_claim = blk: {
                const rows = try allocator.alloc(
                    InputRelation.Row,
                    authority.input_preprocessing.rows.len,
                );
                defer allocator.free(rows);
                for (authority.input_preprocessing.rows, rows) |source, *destination| {
                    const value = evaluations.at(source.lane).values[source.node_id]
                        .tryIntoM31() catch return error.AuthorityMismatch;
                    destination.* = input_witness.logicalInputs(
                        (input_witness.MainRow{
                            .enabler = M31.one(),
                            .value = value,
                        }).values(),
                        source.values(),
                        .segment_leaf,
                    );
                }
                var generated = try InputFramework.generatePrepared(
                    allocator,
                    &authority.input_relation,
                    rows,
                    authority.log_sizes[LogIndex.fri_input],
                    relations,
                );
                defer generated.deinit(allocator);
                copyInteraction(
                    tree,
                    placementOffset(authority, .fri_verifier_input, 2),
                    &generated.columns,
                );
                try recordDomainAudit(
                    allocator,
                    &authority.input_relation,
                    rows,
                    relations,
                    generated.claimed_sum,
                    closure_audit,
                    .fri_verifier_input,
                );
                break :blk generated.claimed_sum;
            };
            const multiply_claim = blk: {
                const rows = try allocator.alloc(MultiplyRelation.Row, invocations.multiply.len);
                defer allocator.free(rows);
                for (invocations.multiply, rows, 0..) |invocation, *destination, index| {
                    destination.* = multiply_witness.logicalInputs(
                        multiply_witness.mainRow(invocation),
                        multiply_witness.preprocessedRow(
                            authority.lowering_plan.multiply_rows[index],
                        ),
                        .segment_leaf,
                    );
                }
                var generated = try MultiplyFramework.generatePrepared(
                    allocator,
                    &authority.multiply_relation,
                    rows,
                    authority.log_sizes[LogIndex.multiply],
                    relations,
                );
                defer generated.deinit(allocator);
                copyInteraction(
                    tree,
                    placementOffset(authority, .qm31_mul, 2),
                    &generated.columns,
                );
                try recordDomainAudit(
                    allocator,
                    &authority.multiply_relation,
                    rows,
                    relations,
                    generated.claimed_sum,
                    closure_audit,
                    .qm31_mul,
                );
                break :blk generated.claimed_sum;
            };
            const inverse_claim = blk: {
                const rows = try allocator.alloc(InverseRelation.Row, invocations.inverse.len);
                defer allocator.free(rows);
                for (invocations.inverse, rows, 0..) |invocation, *destination, index| {
                    destination.* = inverse_witness.logicalInputs(
                        try inverse_witness.mainRow(invocation),
                        inverse_witness.preprocessedRow(
                            authority.lowering_plan.inverse_rows[index],
                        ),
                        .segment_leaf,
                    );
                }
                var generated = try InverseFramework.generatePrepared(
                    allocator,
                    &authority.inverse_relation,
                    rows,
                    authority.log_sizes[LogIndex.inverse],
                    relations,
                );
                defer generated.deinit(allocator);
                copyInteraction(
                    tree,
                    placementOffset(authority, .qm31_inv, 2),
                    &generated.columns,
                );
                try recordDomainAudit(
                    allocator,
                    &authority.inverse_relation,
                    rows,
                    relations,
                    generated.claimed_sum,
                    closure_audit,
                    .qm31_inv,
                );
                break :blk generated.claimed_sum;
            };
            const linear_claim = blk: {
                const rows = try allocator.alloc(LinearRelation.Row, invocations.linear.len);
                defer allocator.free(rows);
                for (invocations.linear, rows, 0..) |invocation, *destination, index| {
                    destination.* = linear_witness.logicalInputs(
                        try linear_witness.mainRow(invocation),
                        linear_witness.preprocessedRow(
                            authority.lowering_plan.linear_rows[index],
                        ),
                        .segment_leaf,
                    );
                }
                var generated = try LinearFramework.generatePrepared(
                    allocator,
                    &authority.linear_relation,
                    rows,
                    authority.log_sizes[LogIndex.linear],
                    relations,
                );
                defer generated.deinit(allocator);
                copyInteraction(
                    tree,
                    placementOffset(authority, .linear_ops, 2),
                    &generated.columns,
                );
                try recordDomainAudit(
                    allocator,
                    &authority.linear_relation,
                    rows,
                    relations,
                    generated.claimed_sum,
                    closure_audit,
                    .linear_ops,
                );
                break :blk generated.claimed_sum;
            };
            const merkle_path_claim = blk: {
                if (!merkle_paths.ready) return error.AuthorityMismatch;
                const rows = try allocator.alloc(
                    MerklePathRelation.Row,
                    merkle_paths.invocations.len,
                );
                defer allocator.free(rows);
                for (merkle_paths.invocations, rows) |invocation, *destination|
                    destination.* = try merkle_path_witness.logicalRow(invocation);
                var generated = try MerklePathFramework.generatePrepared(
                    allocator,
                    &authority.merkle_path_relation,
                    rows,
                    authority.log_sizes[LogIndex.merkle_path],
                    relations,
                );
                defer generated.deinit(allocator);
                copyInteraction(
                    tree,
                    placementOffset(authority, .merkle_path, 2),
                    &generated.columns,
                );
                try recordDomainAudit(
                    allocator,
                    &authority.merkle_path_relation,
                    rows,
                    relations,
                    generated.claimed_sum,
                    closure_audit,
                    .merkle_path,
                );
                break :blk generated.claimed_sum;
            };
            const poseidon2_claims = blk: {
                const calls = try poseidon_calls.callsView();
                const outputs = try poseidon_calls.outputsView();
                var generated = if (authority.log_sizes[LogIndex.poseidon2] >= 12 and
                    prover_work_pool.getGlobalPool() != null)
                    try poseidon2_air.generateIoInteractionFromOutputsParallel(
                        allocator,
                        calls,
                        outputs,
                        authority.log_sizes[LogIndex.poseidon2],
                        &provider_relations.native,
                        prover_work_pool.getGlobalPool().?,
                    )
                else
                    try poseidon2_air.generateIoInteractionFromOutputs(
                        allocator,
                        calls,
                        outputs,
                        authority.log_sizes[LogIndex.poseidon2],
                        &provider_relations.native,
                    );
                defer generated.deinit(allocator);
                copyInteraction(
                    tree,
                    placementOffset(authority, .poseidon2, 2),
                    &generated.columns,
                );
                try poseidon_calls.auditWitnessClaimClosure(
                    generated.claims.sums,
                    relations,
                );
                if (closure_audit) |audit| {
                    var row_audit = emptyDomainAudit();
                    row_audit.values[@intFromEnum(RelationDomain.poseidon2)] =
                        generated.claims.sums[0];
                    row_audit.values[@intFromEnum(RelationDomain.poseidon2_io)] =
                        generated.claims.sums[1];
                    row_audit.total = generated.claims.sums[0].add(
                        generated.claims.sums[1],
                    );
                    row_audit.logical_rows = calls.len;
                    row_audit.event_terms = try std.math.mul(usize, calls.len, 4);
                    audit.rows[@intFromEnum(air.universal_roster.Component.poseidon2)] =
                        row_audit;
                }
                break :blk generated.claims.sums;
            };
            const public_boundaries = PublicBoundaryClaims{
                .wire = try authority.lowering_plan.publicBoundaryClaim(
                    .segment_leaf,
                    relations,
                ),
                .verifier_input = try verifierInputBoundaryClaim(
                    authority,
                    relations,
                ),
            };
            if (closure_audit) |audit| {
                audit.public_boundaries = public_boundaries;
                if (audit.tupleLedger()) |ledger| {
                    try appendWireBoundaryTuples(
                        ledger,
                        &authority.lowering_plan,
                    );
                    try appendVerifierInputBoundaryTuples(
                        ledger,
                        authority,
                    );
                }
            }
            return .{
                .segment_leaf = segment_leaf_claims,
                .vm_input = vm_input_claim,
                .composition_control = composition_control_claim,
                .query_bits = query_bits_claim,
                .query_mapping = query_mapping_claim,
                .merkle_root = merkle_root_claim,
                .trace_merkle = trace_merkle_claim,
                .pcs_deep = pcs_deep_claim,
                .fri_leaf = fri_leaf_claim,
                .fri_node = fri_node_claim,
                .fri_anchor = fri_anchor_claim,
                .control = control_claim,
                .input = input_claim,
                .multiply = multiply_claim,
                .inverse = inverse_claim,
                .linear = linear_claim,
                .merkle_path = merkle_path_claim,
                .poseidon2 = poseidon2_claims,
                .public_boundaries = public_boundaries,
                .input_wire = try authority.lowering_plan.inputBoundaryClaim(
                    allocator,
                    authority.arithmetic_reference,
                    arithmetic_evaluations,
                    .segment_leaf,
                    relations,
                ),
            };
        }
    };
}
