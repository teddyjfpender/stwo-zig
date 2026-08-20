//! Cohesive internal authority extracted from recursive_fri_outer.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const M31 = context.d_M31;
        const recursion = context.d_recursion;
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
        const manifest_mod = context.d_manifest_mod;
        const shared_provider = context.d_shared_provider;
        const universal = context.d_universal;
        const MAX_ARITHMETIC_EVALUATION_LANES = context.d_MAX_ARITHMETIC_EVALUATION_LANES;
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
        const PCS_SEGMENT_CIRCUIT_ID = context.d_PCS_SEGMENT_CIRCUIT_ID;
        const PCS_LEFT_CIRCUIT_ID = context.d_PCS_LEFT_CIRCUIT_ID;
        const PCS_RIGHT_CIRCUIT_ID = context.d_PCS_RIGHT_CIRCUIT_ID;
        const PreparedQueryWitness = context.d_PreparedQueryWitness;
        const Claims = context.d_Claims;
        const RelationDomain = context.d_RelationDomain;
        const ClosureAudit = context.d_ClosureAudit;
        const ExactClosurePreflightV2 = context.d_ExactClosurePreflightV2;
        const emptyDomainAudit = context.d_emptyDomainAudit;
        const recordDomainAudit = context.d_recordDomainAudit;
        const PreparedRelationRows = context.d_PreparedRelationRows;
        const Authority = context.d_Authority;
        const admittedSegmentLeafBundle = context.d_admittedSegmentLeafBundle;
        const InvocationBuffers = context.d_InvocationBuffers;
        const MerklePathBuffers = context.d_MerklePathBuffers;
        const buildArithmeticEvaluations = context.d_buildArithmeticEvaluations;
        const prepareTupleClassifierRows = context.d_prepareTupleClassifierRows;
        const verifierInputBoundaryClaim = context.d_verifierInputBoundaryClaim;
        const preflightExactSegmentClosureV2 = context.d_preflightExactSegmentClosureV2;

        pub fn rebuildExactSegmentClosureV2(
            allocator: std.mem.Allocator,
            captured: *const recursion.captured_fri.Owned,
            authority: *Authority,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
            claims: Claims,
            vector: *const manifest_mod.ClaimVector,
        ) !ExactClosurePreflightV2 {
            if (authority.vm_air == null or
                authority.segment_transcript_inputs == null or
                claims.segment_leaf == null)
            {
                return error.SegmentClosurePublicationUnavailable;
            }
            try relations.validate();
            try provider_relations.validateAgainst(relations);

            var audit = ClosureAudit.init(allocator, false);
            defer audit.deinit();
            const bundle = try admittedSegmentLeafBundle(authority);
            const bundle_audits = try bundle.auditInteractionDomains(
                relations,
                provider_relations,
                claims.segment_leaf.?,
                null,
            );
            @memcpy(audit.rows[0..10], &bundle_audits.transcript);
            audit.rows[@intFromEnum(air.universal_roster.Component.statement_input)] =
                bundle_audits.statement.statement_input;
            audit.rows[
                @intFromEnum(air.universal_roster.Component.statement_semantics_input)
            ] = bundle_audits.statement.statement_semantics;
            audit.rows[@intFromEnum(air.universal_roster.Component.range_check_8_8)] =
                bundle_audits.statement.range_check;
            @memcpy(audit.rows[12..18], &bundle_audits.public);

            var inactive = try captured.evaluateInactive();
            defer inactive.deinit();
            var pcs_inactive = try captured.evaluatePcsInactive();
            defer pcs_inactive.deinit();
            var prepared_query = try PreparedQueryWitness.init(
                allocator,
                captured,
                authority.segment_transcript_inputs,
            );
            defer prepared_query.deinit();
            const query_witness = prepared_query.value;
            const root_witness = captured.merkleRootWitness();
            const evaluations = input_witness.Evaluations{
                .segment = &captured.evaluation,
                .left = &inactive,
                .right = &inactive,
            };

            const pcs_input_count = captured.pcs_circuit.bindings.len;
            const pcs_active_inputs = try allocator.alloc(M31, pcs_input_count);
            defer allocator.free(pcs_active_inputs);
            const pcs_inactive_inputs = try allocator.alloc(M31, pcs_input_count);
            defer allocator.free(pcs_inactive_inputs);
            try captured.pcs_circuit.inputValuesInto(
                &captured.pcs_evaluation,
                pcs_active_inputs,
            );
            try captured.pcs_circuit.inputValuesInto(
                &pcs_inactive,
                pcs_inactive_inputs,
            );
            const pcs_graph_digest = captured.pcs_circuit.graph().identity_digest;
            const pcs_inputs = pcs_witness.InputWitness{ .lanes = .{
                .{
                    .verifier_id = pcs_witness.SEGMENT_VERIFIER_ID,
                    .circuit_id = PCS_SEGMENT_CIRCUIT_ID,
                    .graph_digest = pcs_graph_digest,
                    .input_values = pcs_active_inputs,
                },
                .{
                    .verifier_id = pcs_witness.LEFT_RECURSION_VERIFIER_ID,
                    .circuit_id = PCS_LEFT_CIRCUIT_ID,
                    .graph_digest = pcs_graph_digest,
                    .input_values = pcs_inactive_inputs,
                },
                .{
                    .verifier_id = pcs_witness.RIGHT_RECURSION_VERIFIER_ID,
                    .circuit_id = PCS_RIGHT_CIRCUIT_ID,
                    .graph_digest = pcs_graph_digest,
                    .input_values = pcs_inactive_inputs,
                },
            } };

            var arithmetic_evaluation_storage: [MAX_ARITHMETIC_EVALUATION_LANES]lowering.Evaluation = undefined;
            const arithmetic_evaluations = try buildArithmeticEvaluations(
                authority,
                captured,
                &inactive,
                null,
                &arithmetic_evaluation_storage,
            );
            var invocations = try InvocationBuffers.init(
                allocator,
                authority.lowering_plan.counts(.segment_leaf),
            );
            defer invocations.deinit();
            try authority.lowering_plan.materializeInto(
                authority.arithmetic_reference,
                arithmetic_evaluations,
                .segment_leaf,
                invocations.view(),
            );

            var merkle_paths = try MerklePathBuffers.init(allocator, captured);
            defer merkle_paths.deinit();
            var prepared_relation_rows = try PreparedRelationRows.init(
                allocator,
                authority,
            );
            defer prepared_relation_rows.deinit();
            try prepareTupleClassifierRows(
                authority,
                captured,
                captured.traceOpeningWitness(),
                captured.friOpeningWitness(),
                query_witness,
                &merkle_paths,
                &prepared_relation_rows,
            );

            try recordDomainAudit(
                allocator,
                &authority.vm_air.?.relation,
                prepared_relation_rows.vm_input,
                relations,
                claims.vm_input,
                &audit,
                .vm_air_composition_input,
            );
            {
                const rows = try allocator.alloc(
                    CompositionControlRelation.Row,
                    authority.composition_control_preprocessing.rows.len,
                );
                defer allocator.free(rows);
                for (
                    authority.composition_control_preprocessing.rows,
                    rows,
                ) |source, *destination| destination.* =
                    composition_control_witness.logicalRow(source, .segment_leaf);
                try recordDomainAudit(
                    allocator,
                    &authority.composition_control_relation,
                    rows,
                    relations,
                    claims.composition_control,
                    &audit,
                    .vm_air_composition_control,
                );
            }
            {
                const parameters = try query_bits_witness.parameterValues(
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
                        parameters,
                    );
                try recordDomainAudit(
                    allocator,
                    &authority.query_bits_relation,
                    rows,
                    relations,
                    claims.query_bits,
                    &audit,
                    .query_bits,
                );
            }
            {
                const rows = try allocator.alloc(
                    QueryMappingRelation.Row,
                    authority.query_mapping_preprocessing.rows.len,
                );
                defer allocator.free(rows);
                for (
                    authority.query_mapping_preprocessing.rows,
                    rows,
                ) |source, *destination| destination.* =
                    try query_mapping_witness.logicalRow(source, query_witness);
                try recordDomainAudit(
                    allocator,
                    &authority.query_mapping_relation,
                    rows,
                    relations,
                    claims.query_mapping,
                    &audit,
                    .query_mapping,
                );
            }
            {
                const rows = try allocator.alloc(
                    MerkleRootRelation.Row,
                    authority.merkle_root_preprocessing.rows.len,
                );
                defer allocator.free(rows);
                for (authority.merkle_root_preprocessing.rows, rows) |source, *destination|
                    destination.* = try merkle_root_witness.logicalRow(
                        source,
                        root_witness,
                    );
                try recordDomainAudit(
                    allocator,
                    &authority.merkle_root_relation,
                    rows,
                    relations,
                    claims.merkle_root,
                    &audit,
                    .merkle_root,
                );
            }
            try recordDomainAudit(
                allocator,
                &authority.trace_merkle_relation,
                prepared_relation_rows.trace_merkle,
                relations,
                claims.trace_merkle,
                &audit,
                .trace_merkle,
            );
            {
                const rows = try allocator.alloc(
                    PcsRelation.Row,
                    authority.pcs_preprocessing.rows.len,
                );
                defer allocator.free(rows);
                for (authority.pcs_preprocessing.rows, rows) |source, *destination| {
                    const value = pcs_inputs.lanes[source.lane]
                        .input_values[source.binding];
                    destination.* = pcs_witness.logicalInputs(
                        (pcs_witness.MainRow{
                            .enabler = M31.one(),
                            .value = value,
                        }).values(),
                        source.values(),
                        .segment_leaf,
                    );
                }
                try recordDomainAudit(
                    allocator,
                    &authority.pcs_relation,
                    rows,
                    relations,
                    claims.pcs_deep,
                    &audit,
                    .pcs_deep_input,
                );
            }
            try recordDomainAudit(
                allocator,
                &authority.fri_leaf_relation,
                prepared_relation_rows.fri_leaf,
                relations,
                claims.fri_leaf,
                &audit,
                .fri_merkle_leaf,
            );
            try recordDomainAudit(
                allocator,
                &authority.fri_node_relation,
                prepared_relation_rows.fri_node,
                relations,
                claims.fri_node,
                &audit,
                .fri_merkle_node,
            );
            try recordDomainAudit(
                allocator,
                &authority.fri_anchor_relation,
                prepared_relation_rows.fri_anchor,
                relations,
                claims.fri_anchor,
                &audit,
                .fri_merkle_anchor,
            );
            try recordDomainAudit(
                allocator,
                &authority.control_relation,
                prepared_relation_rows.control,
                relations,
                claims.control,
                &audit,
                .fri_verifier_control,
            );
            {
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
                try recordDomainAudit(
                    allocator,
                    &authority.input_relation,
                    rows,
                    relations,
                    claims.input,
                    &audit,
                    .fri_verifier_input,
                );
            }
            {
                const rows = try allocator.alloc(
                    MultiplyRelation.Row,
                    invocations.multiply.len,
                );
                defer allocator.free(rows);
                for (invocations.multiply, rows, 0..) |invocation, *destination, index|
                    destination.* = multiply_witness.logicalInputs(
                        multiply_witness.mainRow(invocation),
                        multiply_witness.preprocessedRow(
                            authority.lowering_plan.multiply_rows[index],
                        ),
                        .segment_leaf,
                    );
                try recordDomainAudit(
                    allocator,
                    &authority.multiply_relation,
                    rows,
                    relations,
                    claims.multiply,
                    &audit,
                    .qm31_mul,
                );
            }
            {
                const rows = try allocator.alloc(
                    InverseRelation.Row,
                    invocations.inverse.len,
                );
                defer allocator.free(rows);
                for (invocations.inverse, rows, 0..) |invocation, *destination, index|
                    destination.* = inverse_witness.logicalInputs(
                        try inverse_witness.mainRow(invocation),
                        inverse_witness.preprocessedRow(
                            authority.lowering_plan.inverse_rows[index],
                        ),
                        .segment_leaf,
                    );
                try recordDomainAudit(
                    allocator,
                    &authority.inverse_relation,
                    rows,
                    relations,
                    claims.inverse,
                    &audit,
                    .qm31_inv,
                );
            }
            {
                const rows = try allocator.alloc(
                    LinearRelation.Row,
                    invocations.linear.len,
                );
                defer allocator.free(rows);
                for (invocations.linear, rows, 0..) |invocation, *destination, index|
                    destination.* = linear_witness.logicalInputs(
                        try linear_witness.mainRow(invocation),
                        linear_witness.preprocessedRow(
                            authority.lowering_plan.linear_rows[index],
                        ),
                        .segment_leaf,
                    );
                try recordDomainAudit(
                    allocator,
                    &authority.linear_relation,
                    rows,
                    relations,
                    claims.linear,
                    &audit,
                    .linear_ops,
                );
            }
            {
                if (!merkle_paths.ready) return error.AuthorityMismatch;
                const rows = try allocator.alloc(
                    MerklePathRelation.Row,
                    merkle_paths.invocations.len,
                );
                defer allocator.free(rows);
                for (merkle_paths.invocations, rows) |invocation, *destination|
                    destination.* = try merkle_path_witness.logicalRow(invocation);
                try recordDomainAudit(
                    allocator,
                    &authority.merkle_path_relation,
                    rows,
                    relations,
                    claims.merkle_path,
                    &audit,
                    .merkle_path,
                );
            }

            var poseidon_audit = emptyDomainAudit();
            poseidon_audit.values[@intFromEnum(RelationDomain.poseidon2)] =
                claims.poseidon2[0];
            poseidon_audit.values[@intFromEnum(RelationDomain.poseidon2_io)] =
                claims.poseidon2[1];
            poseidon_audit.total = claims.poseidon2[0].add(claims.poseidon2[1]);
            poseidon_audit.logical_rows = authority.poseidon2_row_count;
            poseidon_audit.event_terms = try std.math.mul(
                usize,
                authority.poseidon2_row_count,
                4,
            );
            audit.rows[@intFromEnum(air.universal_roster.Component.poseidon2)] =
                poseidon_audit;

            audit.public_boundaries = .{
                .wire = try authority.lowering_plan.publicBoundaryClaim(
                    .segment_leaf,
                    relations,
                ),
                .verifier_input = try verifierInputBoundaryClaim(authority, relations),
            };
            if (!audit.public_boundaries.eql(claims.public_boundaries))
                return error.AuthorityMismatch;
            for (audit.rows, vector.values) |row, expected| {
                if (!row.total.eql(expected)) return error.AuthorityMismatch;
            }
            return preflightExactSegmentClosureV2(
                authority,
                relations,
                claims,
                &audit,
            );
        }
    };
}
