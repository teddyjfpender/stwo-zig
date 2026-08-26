//! Cohesive internal authority extracted from recursive_fri_outer.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const M31 = context.d_M31;
        const vm_input_air = context.d_vm_input_air;
        const vm_input_witness = context.d_vm_input_witness;
        const composition_control_witness = context.d_composition_control_witness;
        const query_bits_air = context.d_query_bits_air;
        const query_bits_witness = context.d_query_bits_witness;
        const query_mapping_air = context.d_query_mapping_air;
        const query_mapping_witness = context.d_query_mapping_witness;
        const merkle_root_air = context.d_merkle_root_air;
        const merkle_root_witness = context.d_merkle_root_witness;
        const trace_merkle_air = context.d_trace_merkle_air;
        const trace_merkle_witness = context.d_trace_merkle_witness;
        const pcs_air = context.d_pcs_air;
        const pcs_witness = context.d_pcs_witness;
        const fri_leaf_air = context.d_fri_leaf_air;
        const fri_leaf_witness = context.d_fri_leaf_witness;
        const fri_node_witness = context.d_fri_node_witness;
        const fri_anchor_air = context.d_fri_anchor_air;
        const fri_anchor_witness = context.d_fri_anchor_witness;
        const control_air = context.d_control_air;
        const control_witness = context.d_control_witness;
        const input_air = context.d_input_air;
        const input_witness = context.d_input_witness;
        const multiply_witness = context.d_multiply_witness;
        const inverse_witness = context.d_inverse_witness;
        const linear_witness = context.d_linear_witness;
        const framework = context.d_framework;
        const LogIndex = context.d_LogIndex;
        const Authority = context.d_Authority;
        const admittedSegmentLeafBundle = context.d_admittedSegmentLeafBundle;
        const placementOffset = context.d_placementOffset;
        const ColumnBuffer = context.d_ColumnBuffer;
        const TreeStorage = context.d_TreeStorage;

        pub fn vmInputParameters(
            kind: vm_input_witness.ProofKind,
        ) [vm_input_air.PARAMETER_COUNT]M31 {
            const selectors = kind.selectors();
            return .{
                selectors[0],
                selectors[1],
                M31.fromCanonical(vm_input_witness.SAMPLED_VALUE_KIND),
                M31.fromCanonical(vm_input_witness.VM_CLAIMED_SUM_KIND),
                M31.fromCanonical(vm_input_witness.RECURSION_CLAIMED_SUM_KIND),
                M31.fromCanonical(vm_input_witness.CHALLENGE_SCOPE),
                M31.fromCanonical(vm_input_witness.COMPOSITION_RANDOMNESS_KIND),
                M31.fromCanonical(vm_input_witness.OODS_POINT_KIND),
                M31.fromCanonical(vm_input_witness.TRANSCRIPT_CLAIMED_SUM_KIND),
            };
        }

        pub fn merkleRootParameters(
            kind: merkle_root_witness.ProofKind,
        ) [merkle_root_air.PARAMETER_COUNT]M31 {
            return kind.selectors()[0..2].*;
        }

        pub fn traceMerkleParameters(
            kind: trace_merkle_witness.ProofKind,
        ) [trace_merkle_air.PARAMETER_COUNT]M31 {
            const selectors = kind.selectors();
            return .{
                selectors[0],
                selectors[1],
                M31.fromCanonical(trace_merkle_witness.LEAF_TAG),
                M31.fromCanonical(trace_merkle_witness.TRACE_POSITION_KIND),
            };
        }

        pub fn friLeafParameters(
            kind: fri_leaf_witness.ProofKind,
        ) [fri_leaf_air.PARAMETER_COUNT]M31 {
            const selectors = kind.selectors();
            return .{
                selectors[0],
                selectors[1],
                M31.fromCanonical(fri_leaf_witness.LEAF_TAG),
            };
        }

        pub fn friAnchorParameters(
            kind: fri_anchor_witness.ProofKind,
        ) [fri_anchor_air.PARAMETER_COUNT]M31 {
            const selectors = kind.selectors();
            return .{
                selectors[0],
                selectors[1],
                M31.fromCanonical(fri_anchor_witness.FRI_MERKLE_KIND),
            };
        }

        pub fn queryBitsParameters(
            reference: query_bits_witness.Reference,
            kind: query_bits_witness.ProofKind,
        ) ![query_bits_air.PARAMETER_COUNT]M31 {
            return query_bits_witness.parameterValues(reference, kind);
        }

        pub fn queryMappingParameters(
            kind: query_mapping_witness.ProofKind,
        ) [query_mapping_air.PARAMETER_COUNT]M31 {
            const selectors = kind.selectors();
            return .{ selectors[0], selectors[1] };
        }

        pub fn controlParameters(
            kind: control_witness.ProofKind,
        ) [control_air.PARAMETER_COUNT]M31 {
            const selectors = kind.selectors();
            return .{
                selectors[0],
                selectors[1],
                M31.fromCanonical(control_witness.POSITION_FIELD),
                M31.fromCanonical(control_witness.OFFSET_FIELD),
            };
        }

        pub fn inputParameters(kind: input_witness.ProofKind) [input_air.PARAMETER_COUNT]M31 {
            const selectors = kind.selectors();
            return .{
                selectors[0],
                selectors[1],
                M31.fromCanonical(input_witness.FRI_ALPHA_KIND),
                M31.fromCanonical(input_witness.FRI_FOLD_KIND),
                M31.fromCanonical(input_witness.LAST_LAYER_KIND),
                M31.fromCanonical(input_witness.POSITION_FIELD),
                M31.fromCanonical(input_witness.OFFSET_FIELD),
                M31.fromCanonical(input_witness.COEFFICIENT_KIND),
            };
        }

        pub fn pcsParameters(kind: pcs_witness.ProofKind) [pcs_air.PARAMETER_COUNT]M31 {
            const selectors = kind.selectors();
            return .{
                selectors[0],
                selectors[1],
                M31.fromCanonical(pcs_witness.SAMPLED_VALUE_KIND),
                M31.fromCanonical(pcs_witness.OODS_POINT_KIND),
                M31.fromCanonical(pcs_witness.DEEP_RANDOMNESS_KIND),
                M31.fromCanonical(pcs_witness.DEEP_POSITION_KIND),
            };
        }

        pub fn fillPreprocessed(authority: *const Authority, tree: *TreeStorage) !void {
            if (authority.segment_transcript_inputs != null) {
                const bundle = try admittedSegmentLeafBundle(authority);
                try bundle.fillPreprocessedInto(
                    &authority.manifest,
                    tree.columns,
                );
            }
            if (authority.vm_air) |*vm_air| {
                var columns = try ColumnBuffer(vm_input_witness.PREPROCESSED_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.vm_input],
                );
                defer columns.deinit();
                try vm_air.executor.generatePreprocessedInto(
                    &vm_air.prepared.preprocessing,
                    &columns.views,
                );
                columns.scatter(
                    tree,
                    placementOffset(authority, .vm_air_composition_input, 0),
                );
            }
            {
                var columns = try ColumnBuffer(composition_control_witness.COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.composition_control],
                );
                defer columns.deinit();
                try authority.composition_control_preprocessing.generateInto(
                    &columns.views,
                    authority.vm_schedule,
                    authority.recursion_schedule,
                );
                columns.scatter(
                    tree,
                    placementOffset(authority, .vm_air_composition_control, 0),
                );
            }
            {
                var columns = try ColumnBuffer(query_bits_witness.PREPROCESSED_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.query_bits],
                );
                defer columns.deinit();
                try authority.query_bits_executor.generatePreprocessedInto(
                    &authority.query_bits_preprocessing,
                    authority.query_bits_reference,
                    &columns.views,
                );
                columns.scatter(tree, placementOffset(authority, .query_bits, 0));
            }
            {
                var columns = try ColumnBuffer(query_mapping_witness.PREPROCESSED_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.query_mapping],
                );
                defer columns.deinit();
                try authority.query_mapping_executor.generatePreprocessedInto(
                    &authority.query_mapping_preprocessing,
                    authority.query_mapping_reference,
                    &columns.views,
                );
                columns.scatter(tree, placementOffset(authority, .query_mapping, 0));
            }
            {
                var columns = try ColumnBuffer(merkle_root_witness.PREPROCESSED_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.merkle_root],
                );
                defer columns.deinit();
                try authority.merkle_root_executor.generatePreprocessedInto(
                    &authority.merkle_root_preprocessing,
                    authority.merkle_root_reference,
                    &columns.views,
                );
                columns.scatter(tree, placementOffset(authority, .merkle_root, 0));
            }
            {
                var columns = try ColumnBuffer(trace_merkle_witness.PREPROCESSED_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.trace_merkle],
                );
                defer columns.deinit();
                try authority.trace_merkle_executor.generatePreprocessedInto(
                    &authority.trace_merkle_preprocessing,
                    authority.trace_merkle_reference,
                    &columns.views,
                );
                columns.scatter(tree, placementOffset(authority, .trace_merkle, 0));
            }
            {
                var columns = try ColumnBuffer(pcs_witness.PREPROCESSED_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.pcs_deep],
                );
                defer columns.deinit();
                try authority.pcs_executor.generatePreprocessedInto(
                    &authority.pcs_preprocessing,
                    authority.pcs_reference,
                    &columns.views,
                );
                columns.scatter(tree, placementOffset(authority, .pcs_deep_input, 0));
            }
            {
                var columns = try ColumnBuffer(fri_leaf_witness.PREPROCESSED_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.fri_leaf],
                );
                defer columns.deinit();
                try authority.fri_leaf_executor.generatePreprocessedInto(
                    &authority.fri_leaf_preprocessing,
                    authority.fri_reference,
                    &columns.views,
                );
                columns.scatter(tree, placementOffset(authority, .fri_merkle_leaf, 0));
            }
            {
                var columns = try ColumnBuffer(fri_node_witness.PREPROCESSED_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.fri_node],
                );
                defer columns.deinit();
                try authority.fri_node_executor.generatePreprocessedInto(
                    &authority.fri_node_preprocessing,
                    authority.fri_reference,
                    &columns.views,
                );
                columns.scatter(tree, placementOffset(authority, .fri_merkle_node, 0));
            }
            {
                var columns = try ColumnBuffer(fri_anchor_witness.PREPROCESSED_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.fri_anchor],
                );
                defer columns.deinit();
                try authority.fri_anchor_executor.generatePreprocessedInto(
                    &authority.fri_anchor_preprocessing,
                    authority.fri_reference,
                    authority.vm_schedule,
                    authority.recursion_schedule,
                    &columns.views,
                );
                columns.scatter(tree, placementOffset(authority, .fri_merkle_anchor, 0));
            }
            {
                var columns = try ColumnBuffer(control_witness.PREPROCESSED_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.fri_control],
                );
                defer columns.deinit();
                try authority.control_executor.generatePreprocessedInto(
                    &authority.control_preprocessing,
                    authority.control_reference,
                    &columns.views,
                );
                columns.scatter(tree, placementOffset(authority, .fri_verifier_control, 0));
            }
            {
                var columns = try ColumnBuffer(input_witness.PREPROCESSED_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.fri_input],
                );
                defer columns.deinit();
                try authority.input_executor.generatePreprocessedInto(
                    &authority.input_preprocessing,
                    authority.reference,
                    &columns.views,
                );
                columns.scatter(tree, placementOffset(authority, .fri_verifier_input, 0));
            }
            {
                var columns = try ColumnBuffer(multiply_witness.PREPROCESSED_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.multiply],
                );
                defer columns.deinit();
                try authority.multiply_executor.generatePreprocessedInto(
                    &columns.views,
                    authority.lowering_plan.multiply_rows,
                    authority.log_sizes[LogIndex.multiply],
                );
                columns.scatter(tree, placementOffset(authority, .qm31_mul, 0));
            }
            {
                var columns = try ColumnBuffer(inverse_witness.PREPROCESSED_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.inverse],
                );
                defer columns.deinit();
                try authority.inverse_executor.generatePreprocessedInto(
                    &columns.views,
                    authority.lowering_plan.inverse_rows,
                    authority.log_sizes[LogIndex.inverse],
                );
                columns.scatter(tree, placementOffset(authority, .qm31_inv, 0));
            }
            {
                var columns = try ColumnBuffer(linear_witness.PREPROCESSED_COLUMN_COUNT).init(
                    authority.allocator,
                    authority.log_sizes[LogIndex.linear],
                );
                defer columns.deinit();
                try authority.linear_executor.generatePreprocessedInto(
                    &columns.views,
                    authority.lowering_plan.linear_rows,
                    authority.log_sizes[LogIndex.linear],
                );
                columns.scatter(tree, placementOffset(authority, .linear_ops, 0));
            }
            {
                const column = tree.column(placementOffset(authority, .poseidon2, 0));
                @memset(column, M31.zero());
                column[framework.committedRow(0, authority.log_sizes[LogIndex.poseidon2])] = M31.one();
            }
        }
    };
}
