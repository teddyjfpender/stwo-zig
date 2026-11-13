//! Cohesive internal authority extracted from recursive_fri_outer.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const M31 = context.d_M31;
        const columnRow = context.d_columnRow;
        const recursion = context.d_recursion;
        const air = context.d_air;
        const query_bits_witness = context.d_query_bits_witness;
        const merkle_root_witness = context.d_merkle_root_witness;
        const trace_merkle_witness = context.d_trace_merkle_witness;
        const pcs_witness = context.d_pcs_witness;
        const fri_leaf_witness = context.d_fri_leaf_witness;
        const fri_node_witness = context.d_fri_node_witness;
        const fri_anchor_witness = context.d_fri_anchor_witness;
        const control_witness = context.d_control_witness;
        const input_witness = context.d_input_witness;
        const multiply_witness = context.d_multiply_witness;
        const inverse_witness = context.d_inverse_witness;
        const linear_witness = context.d_linear_witness;
        const merkle_path_witness = context.d_merkle_path_witness;
        const transcript_payload_relation = context.d_transcript_payload_relation;
        const transcript_payload_witness = context.d_transcript_payload_witness;
        const verifier_randomness_relation = context.d_verifier_randomness_relation;
        const verifier_randomness_witness = context.d_verifier_randomness_witness;
        const statement_input_relation = context.d_statement_input_relation;
        const statement_input_witness = context.d_statement_input_witness;
        const statement_semantics_relation = context.d_statement_semantics_relation;
        const statement_semantics_witness = context.d_statement_semantics_witness;
        const LogIndex = context.d_LogIndex;
        const InputRelation = context.d_InputRelation;
        const QueryBitsRelation = context.d_QueryBitsRelation;
        const MerkleRootRelation = context.d_MerkleRootRelation;
        const PcsRelation = context.d_PcsRelation;
        const MultiplyRelation = context.d_MultiplyRelation;
        const InverseRelation = context.d_InverseRelation;
        const LinearRelation = context.d_LinearRelation;
        const MerklePathRelation = context.d_MerklePathRelation;
        const TUPLE_CLOSURE_FRONTIER_MASK = context.d_TUPLE_CLOSURE_FRONTIER_MASK;
        const TupleLedger = context.d_TupleLedger;
        const PreparedRelationRows = context.d_PreparedRelationRows;
        const Authority = context.d_Authority;
        const InvocationBuffers = context.d_InvocationBuffers;
        const MerklePathBuffers = context.d_MerklePathBuffers;
        const captureTracePathLeaves = context.d_captureTracePathLeaves;
        const captureFriPathLeaves = context.d_captureFriPathLeaves;
        const appendWireBoundaryTuples = context.d_appendWireBoundaryTuples;
        const appendVerifierInputBoundaryTuples = context.d_appendVerifierInputBoundaryTuples;
        const ColumnBuffer = context.d_ColumnBuffer;

        pub fn prepareTupleClassifierRows(
            authority: *Authority,
            captured: *const recursion.captured_fri.Owned,
            trace_opening_witness: trace_merkle_witness.OpeningWitness,
            fri_opening_witness: fri_leaf_witness.OpeningWitness,
            query_witness: query_bits_witness.QueryWitness,
            merkle_paths: *MerklePathBuffers,
            prepared_relation_rows: *PreparedRelationRows,
        ) !void {
            {
                var columns = try ColumnBuffer(trace_merkle_witness.MAIN_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.trace_merkle],
                );
                defer columns.deinit();
                try authority.trace_merkle_executor.generateMainInto(
                    &authority.trace_merkle_preprocessing,
                    authority.trace_merkle_reference,
                    &columns.views,
                    trace_opening_witness,
                );
                const selectors = trace_opening_witness.proofKind().selectors();
                for (
                    authority.trace_merkle_preprocessing.rows,
                    prepared_relation_rows.trace_merkle,
                    0..,
                ) |source, *destination, row_index| destination.* =
                    columnRow(trace_merkle_witness.MAIN_COLUMN_COUNT, &columns.views, row_index) ++
                    source.values() ++ .{
                        selectors[0],
                        selectors[1],
                        M31.fromCanonical(trace_merkle_witness.LEAF_TAG),
                        M31.fromCanonical(trace_merkle_witness.TRACE_POSITION_KIND),
                    };
                try captureTracePathLeaves(
                    merkle_paths,
                    captured,
                    authority.trace_merkle_preprocessing.rows,
                    &columns.views,
                );
            }
            {
                var columns = try ColumnBuffer(fri_leaf_witness.MAIN_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.fri_leaf],
                );
                defer columns.deinit();
                try authority.fri_leaf_executor.generateMainInto(
                    &authority.fri_leaf_preprocessing,
                    authority.fri_reference,
                    &columns.views,
                    fri_opening_witness,
                );
                const selectors = fri_opening_witness.proofKind().selectors();
                for (
                    authority.fri_leaf_preprocessing.rows,
                    prepared_relation_rows.fri_leaf,
                    0..,
                ) |source, *destination, row_index| destination.* =
                    columnRow(fri_leaf_witness.MAIN_COLUMN_COUNT, &columns.views, row_index) ++
                    source.values() ++ .{
                        selectors[0],
                        selectors[1],
                        M31.fromCanonical(fri_leaf_witness.LEAF_TAG),
                    };
            }
            {
                var columns = try ColumnBuffer(fri_node_witness.MAIN_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.fri_node],
                );
                defer columns.deinit();
                try authority.fri_node_executor.generateMainInto(
                    &authority.fri_node_preprocessing,
                    authority.fri_reference,
                    &columns.views,
                    fri_opening_witness,
                );
                const selectors = fri_opening_witness.proofKind().selectors();
                for (
                    authority.fri_node_preprocessing.rows,
                    prepared_relation_rows.fri_node,
                    0..,
                ) |source, *destination, row_index| destination.* =
                    columnRow(fri_node_witness.MAIN_COLUMN_COUNT, &columns.views, row_index) ++
                    source.values() ++ .{ selectors[0], selectors[1] };
            }
            {
                var columns = try ColumnBuffer(fri_anchor_witness.MAIN_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.fri_anchor],
                );
                defer columns.deinit();
                try authority.fri_anchor_executor.generateMainInto(
                    &authority.fri_anchor_preprocessing,
                    authority.fri_reference,
                    authority.vm_schedule,
                    authority.recursion_schedule,
                    &columns.views,
                    fri_opening_witness,
                );
                const selectors = fri_opening_witness.proofKind().selectors();
                for (
                    authority.fri_anchor_preprocessing.rows,
                    prepared_relation_rows.fri_anchor,
                    0..,
                ) |source, *destination, row_index| destination.* =
                    columnRow(fri_anchor_witness.MAIN_COLUMN_COUNT, &columns.views, row_index) ++
                    source.values() ++ .{
                        selectors[0],
                        selectors[1],
                        M31.fromCanonical(fri_anchor_witness.FRI_MERKLE_KIND),
                    };
                try captureFriPathLeaves(
                    merkle_paths,
                    captured,
                    authority.fri_anchor_preprocessing.rows,
                    &columns.views,
                );
            }
            try merkle_paths.materialize(captured);
            {
                var columns = try ColumnBuffer(control_witness.MAIN_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.fri_control],
                );
                defer columns.deinit();
                try authority.control_executor.generateMainInto(
                    &authority.control_preprocessing,
                    authority.control_reference,
                    &columns.views,
                    query_witness,
                );
                const selectors = query_witness.proofKind().selectors();
                for (
                    authority.control_preprocessing.rows,
                    prepared_relation_rows.control,
                    0..,
                ) |source, *destination, row_index| destination.* =
                    columnRow(control_witness.MAIN_COLUMN_COUNT, &columns.views, row_index) ++
                    source.values() ++ .{
                        selectors[0],
                        selectors[1],
                        M31.fromCanonical(control_witness.POSITION_FIELD),
                        M31.fromCanonical(control_witness.OFFSET_FIELD),
                    };
            }
        }

        pub fn collectTupleClosureFrontier(
            allocator: std.mem.Allocator,
            authority: *const Authority,
            evaluations: input_witness.Evaluations,
            pcs_inputs: pcs_witness.InputWitness,
            invocations: *const InvocationBuffers,
            query_witness: query_bits_witness.QueryWitness,
            root_witness: merkle_root_witness.RootWitness,
            merkle_paths: *const MerklePathBuffers,
            prepared_relation_rows: *const PreparedRelationRows,
            ledger: *TupleLedger,
        ) !void {
            const inputs = authority.segment_transcript_inputs orelse
                return error.AuthorityMismatch;
            const transcript_source = authority.segment_transcript orelse
                return error.AuthorityMismatch;
            try transcript_source.validateAgainst(
                authority.vm_schedule,
                authority.recursion_schedule,
                inputs.preprocessing,
                inputs.prepared,
            );

            {
                const rows = try allocator.alloc(
                    transcript_payload_relation.Row,
                    inputs.preprocessing.transcript_payload.rows.len,
                );
                defer allocator.free(rows);
                for (
                    rows,
                    inputs.preprocessing.transcript_payload.rows,
                    inputs.prepared.transcript_payload.values,
                ) |*destination, pp, value| destination.* =
                    try transcript_payload_witness.logicalRow(
                        pp,
                        value,
                        .segment_leaf,
                    );
                try appendFrontierTupleRows(
                    &transcript_source.owners.transcript_payload.relation,
                    ledger,
                    .transcript_payload,
                    rows,
                );
            }
            {
                const rows = try allocator.alloc(
                    verifier_randomness_relation.Row,
                    inputs.preprocessing.verifier_randomness.rows.len,
                );
                defer allocator.free(rows);
                for (
                    rows,
                    inputs.prepared.verifier_randomness.rows,
                    inputs.preprocessing.verifier_randomness.rows,
                ) |*destination, main, pp| destination.* =
                    verifier_randomness_witness.logicalInputs(
                        main,
                        pp,
                        .segment_leaf,
                    );
                try appendFrontierTupleRows(
                    &transcript_source.owners.verifier_randomness.relation,
                    ledger,
                    .verifier_randomness,
                    rows,
                );
            }

            try inputs.statement.prepared.validateAgainst(
                inputs.statement.authority,
                inputs.statement.workspace,
                inputs.public.leaf_preprocessing,
                inputs.public.data,
                inputs.public.leaf,
            );
            {
                const rows = try allocator.alloc(
                    statement_input_relation.Row,
                    inputs.statement.authority.statement_input_preprocessing.rows.len,
                );
                defer allocator.free(rows);
                for (
                    rows,
                    inputs.statement.authority.statement_input_preprocessing.rows,
                ) |*destination, source| destination.* =
                    try statement_input_witness.logicalRow(
                        source,
                        .{ .segment_leaf = &inputs.statement.prepared.statement_words },
                    );
                try appendFrontierTupleRows(
                    &inputs.statement.authority.statement_input_relation,
                    ledger,
                    .statement_input,
                    rows,
                );
            }
            {
                const rows = try allocator.alloc(
                    statement_semantics_relation.Row,
                    inputs.statement.authority.statement_semantics_preprocessing.rows.len,
                );
                defer allocator.free(rows);
                for (
                    rows,
                    inputs.statement.authority.statement_semantics_preprocessing.rows,
                    inputs.statement.prepared.statement_values,
                ) |*destination, source, value| destination.* =
                    try statement_semantics_witness.logicalRow(
                        source,
                        value,
                        .segment_leaf,
                    );
                try appendFrontierTupleRows(
                    &inputs.statement.authority.statement_semantics_relation,
                    ledger,
                    .statement_semantics_input,
                    rows,
                );
            }

            try inputs.public.source.validateAgainst(
                authority.vm_schedule,
                authority.recursion_schedule,
                inputs.public.leaf_preprocessing,
            );
            try inputs.public.prepared.validateAgainst(
                inputs.public.source,
                inputs.public.leaf_preprocessing,
                inputs.public.leaf,
                inputs.public.data,
            );
            try appendFrontierTupleRows(
                &inputs.public.source.owners.claim_hash.relation,
                ledger,
                .vm_public_claim_hash,
                inputs.public.prepared.claim_hash_rows,
            );
            try appendFrontierTupleRows(
                &inputs.public.source.owners.claim_semantics.relation,
                ledger,
                .vm_public_claim_semantics_input,
                inputs.public.prepared.claim_semantics_rows,
            );
            try appendFrontierTupleRows(
                &inputs.public.source.owners.public_logup.relation,
                ledger,
                .vm_public_logup_input,
                inputs.public.prepared.public_logup_rows,
            );

            try appendFrontierTupleRows(
                &authority.vm_air.?.relation,
                ledger,
                .vm_air_composition_input,
                prepared_relation_rows.vm_input,
            );
            {
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
                try appendFrontierTupleRows(
                    &authority.query_bits_relation,
                    ledger,
                    .query_bits,
                    rows,
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
                try appendFrontierTupleRows(
                    &authority.merkle_root_relation,
                    ledger,
                    .merkle_root,
                    rows,
                );
            }
            try appendFrontierTupleRows(
                &authority.trace_merkle_relation,
                ledger,
                .trace_merkle,
                prepared_relation_rows.trace_merkle,
            );
            {
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
                try appendFrontierTupleRows(
                    &authority.pcs_relation,
                    ledger,
                    .pcs_deep_input,
                    rows,
                );
            }
            try appendFrontierTupleRows(
                &authority.fri_leaf_relation,
                ledger,
                .fri_merkle_leaf,
                prepared_relation_rows.fri_leaf,
            );
            try appendFrontierTupleRows(
                &authority.fri_node_relation,
                ledger,
                .fri_merkle_node,
                prepared_relation_rows.fri_node,
            );
            try appendFrontierTupleRows(
                &authority.fri_anchor_relation,
                ledger,
                .fri_merkle_anchor,
                prepared_relation_rows.fri_anchor,
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
                try appendFrontierTupleRows(
                    &authority.input_relation,
                    ledger,
                    .fri_verifier_input,
                    rows,
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
                try appendFrontierTupleRows(
                    &authority.multiply_relation,
                    ledger,
                    .qm31_mul,
                    rows,
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
                try appendFrontierTupleRows(
                    &authority.inverse_relation,
                    ledger,
                    .qm31_inv,
                    rows,
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
                try appendFrontierTupleRows(
                    &authority.linear_relation,
                    ledger,
                    .linear_ops,
                    rows,
                );
            }
            if (!merkle_paths.ready) return error.AuthorityMismatch;
            {
                const rows = try allocator.alloc(
                    MerklePathRelation.Row,
                    merkle_paths.invocations.len,
                );
                defer allocator.free(rows);
                for (merkle_paths.invocations, rows) |invocation, *destination|
                    destination.* = try merkle_path_witness.logicalRow(invocation);
                try appendFrontierTupleRows(
                    &authority.merkle_path_relation,
                    ledger,
                    .merkle_path,
                    rows,
                );
            }
            try appendWireBoundaryTuples(ledger, &authority.lowering_plan);
            try appendVerifierInputBoundaryTuples(ledger, authority);
        }

        pub fn appendFrontierTupleRows(
            plan: anytype,
            ledger: *TupleLedger,
            component: air.universal_roster.Component,
            rows: anytype,
        ) !void {
            try plan.appendPreparedTupleContributions(
                ledger,
                @intCast(@intFromEnum(component)),
                rows,
                TUPLE_CLOSURE_FRONTIER_MASK,
            );
        }
    };
}
