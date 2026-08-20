//! Cohesive internal authority extracted from recursive_fri_outer.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const M31 = context.d_M31;
        const recursion = context.d_recursion;
        const vm_input_witness = context.d_vm_input_witness;
        const query_bits_witness = context.d_query_bits_witness;
        const query_mapping_witness = context.d_query_mapping_witness;
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
        const poseidon2_air = context.d_poseidon2_air;
        const LogIndex = context.d_LogIndex;
        const PreparedRelationRows = context.d_PreparedRelationRows;
        const Authority = context.d_Authority;
        const columnRow = context.d_columnRow;
        const admittedSegmentLeafBundle = context.d_admittedSegmentLeafBundle;
        const InvocationBuffers = context.d_InvocationBuffers;
        const MerklePathBuffers = context.d_MerklePathBuffers;
        const captureTracePathLeaves = context.d_captureTracePathLeaves;
        const captureFriPathLeaves = context.d_captureFriPathLeaves;
        const PoseidonCallBuffers = context.d_PoseidonCallBuffers;
        const placementOffset = context.d_placementOffset;
        const ColumnBuffer = context.d_ColumnBuffer;
        const TreeStorage = context.d_TreeStorage;

        pub fn fillMainConsumers(
            authority: *Authority,
            tree: *TreeStorage,
            evaluations: input_witness.Evaluations,
            pcs_inputs: pcs_witness.InputWitness,
            invocations: *InvocationBuffers,
            query_witness: query_bits_witness.QueryWitness,
            root_witness: merkle_root_witness.RootWitness,
            trace_opening_witness: trace_merkle_witness.OpeningWitness,
            fri_opening_witness: fri_leaf_witness.OpeningWitness,
            captured: *const recursion.captured_fri.Owned,
            merkle_paths: *MerklePathBuffers,
            poseidon_calls: *PoseidonCallBuffers,
            prepared_relation_rows: *PreparedRelationRows,
        ) !void {
            if (authority.segment_transcript_inputs != null) {
                const inputs = authority.segment_transcript_inputs.?;
                const bundle = try admittedSegmentLeafBundle(authority);
                try bundle.fillMainInto(
                    &authority.manifest,
                    tree.columns,
                );
                try poseidon_calls.appendTranscript(&inputs.prepared.execution);
                try poseidon_calls.appendPublic(
                    inputs.public.prepared,
                    inputs.public.leaf,
                );
            }
            if (authority.vm_air) |*vm_air| {
                var columns = try ColumnBuffer(vm_input_witness.MAIN_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.vm_input],
                );
                defer columns.deinit();
                try vm_air.executor.generateMainInto(
                    &vm_air.prepared.preprocessing,
                    &columns.views,
                    vm_air.prepared.schedule_values,
                    .segment_leaf,
                );
                columns.scatter(
                    tree,
                    placementOffset(authority, .vm_air_composition_input, 1),
                );
            }
            {
                var columns = try ColumnBuffer(query_bits_witness.MAIN_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.query_bits],
                );
                defer columns.deinit();
                try authority.query_bits_executor.generateMainInto(
                    &authority.query_bits_preprocessing,
                    authority.query_bits_reference,
                    &columns.views,
                    query_witness,
                );
                columns.scatter(tree, placementOffset(authority, .query_bits, 1));
            }
            {
                var columns = try ColumnBuffer(query_mapping_witness.MAIN_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.query_mapping],
                );
                defer columns.deinit();
                try authority.query_mapping_executor.generateMainInto(
                    &authority.query_mapping_preprocessing,
                    authority.query_mapping_reference,
                    &columns.views,
                    query_witness,
                );
                columns.scatter(tree, placementOffset(authority, .query_mapping, 1));
            }
            {
                var columns = try ColumnBuffer(merkle_root_witness.MAIN_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.merkle_root],
                );
                defer columns.deinit();
                try authority.merkle_root_executor.generateMainInto(
                    &authority.merkle_root_preprocessing,
                    authority.merkle_root_reference,
                    &columns.views,
                    root_witness,
                );
                columns.scatter(tree, placementOffset(authority, .merkle_root, 1));
            }
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
                try poseidon_calls.appendTraceMerkle(
                    authority.trace_merkle_preprocessing.rows,
                    &columns.views,
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
                columns.scatter(tree, placementOffset(authority, .trace_merkle, 1));
            }
            {
                var columns = try ColumnBuffer(pcs_witness.MAIN_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.pcs_deep],
                );
                defer columns.deinit();
                try authority.pcs_executor.generateMainInto(
                    &authority.pcs_preprocessing,
                    authority.pcs_reference,
                    &columns.views,
                    pcs_inputs,
                    .segment_leaf,
                );
                columns.scatter(tree, placementOffset(authority, .pcs_deep_input, 1));
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
                try poseidon_calls.appendFriLeaf(
                    authority.fri_leaf_preprocessing.rows,
                    &columns.views,
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
                columns.scatter(tree, placementOffset(authority, .fri_merkle_leaf, 1));
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
                try poseidon_calls.appendFriNodes(
                    authority.fri_node_preprocessing.rows,
                    &columns.views,
                );
                const selectors = fri_opening_witness.proofKind().selectors();
                for (
                    authority.fri_node_preprocessing.rows,
                    prepared_relation_rows.fri_node,
                    0..,
                ) |source, *destination, row_index| destination.* =
                    columnRow(fri_node_witness.MAIN_COLUMN_COUNT, &columns.views, row_index) ++
                    source.values() ++ .{ selectors[0], selectors[1] };
                columns.scatter(tree, placementOffset(authority, .fri_merkle_node, 1));
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
                columns.scatter(tree, placementOffset(authority, .fri_merkle_anchor, 1));
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
                columns.scatter(tree, placementOffset(authority, .fri_verifier_control, 1));
            }
            {
                var columns = try ColumnBuffer(input_witness.MAIN_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.fri_input],
                );
                defer columns.deinit();
                try authority.input_executor.generateMainInto(
                    &authority.input_preprocessing,
                    authority.reference,
                    &columns.views,
                    evaluations,
                    .segment_leaf,
                );
                columns.scatter(tree, placementOffset(authority, .fri_verifier_input, 1));
            }
            {
                var columns = try ColumnBuffer(multiply_witness.MAIN_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.multiply],
                );
                defer columns.deinit();
                try authority.multiply_executor.generateMainInto(
                    &columns.views,
                    invocations.multiply,
                    authority.log_sizes[LogIndex.multiply],
                );
                columns.scatter(tree, placementOffset(authority, .qm31_mul, 1));
            }
            {
                var columns = try ColumnBuffer(inverse_witness.MAIN_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.inverse],
                );
                defer columns.deinit();
                try authority.inverse_executor.generateMainInto(
                    &columns.views,
                    invocations.inverse,
                    authority.log_sizes[LogIndex.inverse],
                );
                columns.scatter(tree, placementOffset(authority, .qm31_inv, 1));
            }
            {
                var columns = try ColumnBuffer(linear_witness.MAIN_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.linear],
                );
                defer columns.deinit();
                try authority.linear_executor.generateMainInto(
                    &columns.views,
                    invocations.linear,
                    authority.log_sizes[LogIndex.linear],
                );
                columns.scatter(tree, placementOffset(authority, .linear_ops, 1));
            }
            {
                if (!merkle_paths.ready) return error.AuthorityMismatch;
                var columns = try ColumnBuffer(merkle_path_witness.MAIN_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.merkle_path],
                );
                defer columns.deinit();
                try authority.merkle_path_executor.generateMainInto(
                    &columns.views,
                    merkle_paths.invocations,
                    authority.log_sizes[LogIndex.merkle_path],
                );
                try poseidon_calls.appendMerklePaths(merkle_paths.invocations);
                columns.scatter(tree, placementOffset(authority, .merkle_path, 1));
            }
        }

        pub fn fillPoseidonMain(
            authority: *Authority,
            tree: *TreeStorage,
            poseidon_calls: *PoseidonCallBuffers,
        ) !void {
            var columns: [poseidon2_air.N_MAIN_COLUMNS][]M31 = undefined;
            const offset = placementOffset(authority, .poseidon2, 1);
            for (&columns, 0..) |*column, index|
                column.* = tree.column(offset + index);
            try authority.poseidon2_program.generateCanonicalMainInto(
                &columns,
                try poseidon_calls.callsView(),
                authority.log_sizes[LogIndex.poseidon2],
            );
            try poseidon_calls.captureOutputs(
                &columns,
                authority.log_sizes[LogIndex.poseidon2],
            );
        }

        pub fn fillMain(
            authority: *Authority,
            tree: *TreeStorage,
            evaluations: input_witness.Evaluations,
            pcs_inputs: pcs_witness.InputWitness,
            invocations: *InvocationBuffers,
            query_witness: query_bits_witness.QueryWitness,
            root_witness: merkle_root_witness.RootWitness,
            trace_opening_witness: trace_merkle_witness.OpeningWitness,
            fri_opening_witness: fri_leaf_witness.OpeningWitness,
            captured: *const recursion.captured_fri.Owned,
            merkle_paths: *MerklePathBuffers,
            poseidon_calls: *PoseidonCallBuffers,
            prepared_relation_rows: *PreparedRelationRows,
        ) !void {
            try fillMainConsumers(
                authority,
                tree,
                evaluations,
                pcs_inputs,
                invocations,
                query_witness,
                root_witness,
                trace_opening_witness,
                fri_opening_witness,
                captured,
                merkle_paths,
                poseidon_calls,
                prepared_relation_rows,
            );
            try fillPoseidonMain(authority, tree, poseidon_calls);
        }

        // Materializes only the relation-row dependencies that are not directly
        // available from captured/prepared inputs. Unlike `fillMain`, this path owns
        // no manifest-sized tree, performs no scatter, and does not evaluate the
        // Poseidon provider trace.
    };
}
