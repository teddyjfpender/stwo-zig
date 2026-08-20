//! Merkle operations for the authenticated binary FRI source.

pub fn Operations(comptime Context: type) type {
    const Self = Context.Source;
    const PreparedAuthority = Self.PreparedAuthority;
    const CompositionWorkspace = Self.CompositionWorkspace;
    const Workspace = Self.Workspace;
    const ArithmeticWorkspace = Self.ArithmeticWorkspace;
    const MerkleWorkspace = Self.MerkleWorkspace;
    const RelationRows = Self.RelationRows;

    const M31 = Context.M31;
    const composition = Context.composition;
    const composition_input_witness = Context.composition_input_witness;
    const composition_control_witness = Context.composition_control_witness;
    const query_bits_witness = Context.query_bits_witness;
    const query_mapping_witness = Context.query_mapping_witness;
    const merkle_root_witness = Context.merkle_root_witness;
    const trace_merkle_witness = Context.trace_merkle_witness;
    const pcs_witness = Context.pcs_witness;
    const fri_leaf_witness = Context.fri_leaf_witness;
    const fri_node_witness = Context.fri_node_witness;
    const fri_anchor_witness = Context.fri_anchor_witness;
    const fri_control_witness = Context.fri_control_witness;
    const fri_input_witness = Context.fri_input_witness;
    const multiply_witness = Context.multiply_witness;
    const inverse_witness = Context.inverse_witness;
    const linear_witness = Context.linear_witness;
    const merkle_path_poseidon = Context.merkle_path_poseidon;
    const framework = Context.framework;
    const LEFT_CHILD = Context.LEFT_CHILD;
    const RIGHT_CHILD = Context.RIGHT_CHILD;
    const MERKLE_PATH_MAIN_COLUMN_COUNT = Context.MERKLE_PATH_MAIN_COLUMN_COUNT;
    const ColumnOffset = Context.ColumnOffset;
    const columnLogicalRow = Context.columnLogicalRow;
    const relationRowsDigest = Context.relationRowsDigest;
    const merkleInvocationCount = Context.merkleInvocationCount;
    const materializeMerkleWorkspace = Context.materializeMerkleWorkspace;
    const merkleWorkspaceDigest = Context.merkleWorkspaceDigest;
    const validateMerkleDestination = Context.validateMerkleDestination;
    const validateDestination = Context.validateDestination;
    const traceLogSize = Context.traceLogSize;

    return struct {
        pub fn prepareMerkleWorkspace(
            self: *const Self,
            fri_workspace: *const Workspace,
            merkle_workspace: *MerkleWorkspace,
        ) !void {
            try self.validate();
            return prepareMerkleWorkspaceAssumeAuthority(
                self,
                fri_workspace,
                merkle_workspace,
            );
        }

        pub fn prepareMerkleWorkspacePrepared(
            self: *const Self,
            authority: *const PreparedAuthority,
            fri_workspace: *const Workspace,
            merkle_workspace: *MerkleWorkspace,
        ) !void {
            try authority.validateFor(self);
            return prepareMerkleWorkspaceAssumeAuthority(
                self,
                fri_workspace,
                merkle_workspace,
            );
        }

        fn prepareMerkleWorkspaceAssumeAuthority(
            self: *const Self,
            fri_workspace: *const Workspace,
            merkle_workspace: *MerkleWorkspace,
        ) !void {
            try fri_workspace.validateFor(self);
            try merkle_workspace.validateGeometryFor(self);
            if (!fri_workspace.main_ready)
                return error.WorkspaceAuthorityMismatch;
            if (merkle_workspace.ready) {
                try merkle_workspace.validateReadyFor(self, fri_workspace);
                return;
            }
            try materializeMerkleWorkspace(
                self,
                fri_workspace,
                merkle_workspace,
            );
            merkle_workspace.fri_path_leaf_digest =
                fri_workspace.path_leaf_digest;
            merkle_workspace.authority_digest =
                merkleWorkspaceDigest(merkle_workspace);
            merkle_workspace.ready = true;
            try merkle_workspace.validateReadyFor(self, fri_workspace);
        }

        pub fn merkleLogSize(self: *const Self) !u32 {
            try self.validate();
            return traceLogSize(try merkleInvocationCount(self));
        }

        pub fn fillMerkleMainInto(
            self: *const Self,
            fri_workspace: *const Workspace,
            merkle_workspace: *const MerkleWorkspace,
            destination: [][]M31,
        ) !void {
            try self.validate();
            return fillMerkleMainAssumeAuthority(
                self,
                fri_workspace,
                merkle_workspace,
                destination,
            );
        }

        pub fn fillMerkleMainPreparedInto(
            self: *const Self,
            authority: *const PreparedAuthority,
            fri_workspace: *const Workspace,
            merkle_workspace: *const MerkleWorkspace,
            destination: [][]M31,
        ) !void {
            try authority.validateFor(self);
            return fillMerkleMainAssumeAuthority(
                self,
                fri_workspace,
                merkle_workspace,
                destination,
            );
        }

        fn fillMerkleMainAssumeAuthority(
            self: *const Self,
            fri_workspace: *const Workspace,
            merkle_workspace: *const MerkleWorkspace,
            destination: [][]M31,
        ) !void {
            try fri_workspace.validateFor(self);
            try merkle_workspace.validateReadyFor(self, fri_workspace);
            const log_sizes = [1]u32{merkle_workspace.log_size};
            const column_counts = [1]usize{MERKLE_PATH_MAIN_COLUMN_COUNT};
            try validateDestination(
                destination,
                log_sizes,
                column_counts,
                &.{},
                self,
            );
            try validateMerkleDestination(destination, merkle_workspace);

            for (destination) |column| @memset(column, M31.zero());
            for (merkle_workspace.logical_rows, 0..) |row, row_index| {
                const committed_row = framework.committedRow(
                    row_index,
                    merkle_workspace.log_size,
                );
                for (row, destination) |value, column| {
                    column[committed_row] = value;
                }
            }
        }

        pub fn merklePoseidonCalls(
            self: *const Self,
            fri_workspace: *const Workspace,
            merkle_workspace: *const MerkleWorkspace,
        ) ![]const merkle_path_poseidon.Call {
            try self.validate();
            try fri_workspace.validateFor(self);
            try merkle_workspace.validateReadyFor(self, fri_workspace);
            return merkle_workspace.poseidon_calls;
        }

        pub fn merklePoseidonCallsPrepared(
            self: *const Self,
            authority: *const PreparedAuthority,
            fri_workspace: *const Workspace,
            merkle_workspace: *const MerkleWorkspace,
        ) ![]const merkle_path_poseidon.Call {
            try authority.validateFor(self);
            try fri_workspace.validateFor(self);
            try merkle_workspace.validateReadyFor(self, fri_workspace);
            return merkle_workspace.poseidon_calls;
        }

        pub fn merklePoseidonOutputs(
            self: *const Self,
            fri_workspace: *const Workspace,
            merkle_workspace: *const MerkleWorkspace,
        ) ![]const [merkle_path_poseidon.WIDTH]u32 {
            try self.validate();
            try fri_workspace.validateFor(self);
            try merkle_workspace.validateReadyFor(self, fri_workspace);
            return merkle_workspace.poseidon_outputs;
        }

        pub fn merklePoseidonOutputsPrepared(
            self: *const Self,
            authority: *const PreparedAuthority,
            fri_workspace: *const Workspace,
            merkle_workspace: *const MerkleWorkspace,
        ) ![]const [merkle_path_poseidon.WIDTH]u32 {
            try authority.validateFor(self);
            try fri_workspace.validateFor(self);
            try merkle_workspace.validateReadyFor(self, fri_workspace);
            return merkle_workspace.poseidon_outputs;
        }

        pub fn merkleRelationRows(
            self: *const Self,
            fri_workspace: *const Workspace,
            merkle_workspace: *const MerkleWorkspace,
        ) ![]const [MERKLE_PATH_MAIN_COLUMN_COUNT]M31 {
            try self.validate();
            try fri_workspace.validateFor(self);
            try merkle_workspace.validateReadyFor(self, fri_workspace);
            return merkle_workspace.logical_rows;
        }

        pub fn prepareRelationRows(
            self: *const Self,
            composition_workspace: *const CompositionWorkspace,
            fri_workspace: *const Workspace,
            arithmetic_workspace: *const ArithmeticWorkspace,
            merkle_workspace: *const MerkleWorkspace,
            rows: *RelationRows,
        ) !void {
            try self.requireFullBundleAuthority();
            return prepareRelationRowsAssumeAuthority(
                self,
                composition_workspace,
                fri_workspace,
                arithmetic_workspace,
                merkle_workspace,
                rows,
            );
        }

        pub fn prepareRelationRowsPrepared(
            self: *const Self,
            authority: *const PreparedAuthority,
            composition_workspace: *const CompositionWorkspace,
            fri_workspace: *const Workspace,
            arithmetic_workspace: *const ArithmeticWorkspace,
            merkle_workspace: *const MerkleWorkspace,
            rows: *RelationRows,
        ) !void {
            try authority.validateFor(self);
            return prepareRelationRowsAssumeAuthority(
                self,
                composition_workspace,
                fri_workspace,
                arithmetic_workspace,
                merkle_workspace,
                rows,
            );
        }

        fn prepareRelationRowsAssumeAuthority(
            self: *const Self,
            composition_workspace: *const CompositionWorkspace,
            fri_workspace: *const Workspace,
            arithmetic_workspace: *const ArithmeticWorkspace,
            merkle_workspace: *const MerkleWorkspace,
            rows: *RelationRows,
        ) !void {
            try composition_workspace.validateFor(self);
            try fri_workspace.validateFor(self);
            try arithmetic_workspace.validateFor(self);
            try merkle_workspace.validateReadyFor(self, fri_workspace);
            try rows.validateGeometryFor(self);
            if (!fri_workspace.main_ready)
                return error.WorkspaceAuthorityMismatch;
            if (rows.ready) {
                try rows.validateReadyFor(self);
                return;
            }

            const composition_rows = self.composition_rows.?;
            for (
                composition_rows.input_preprocessing.rows,
                composition_rows.schedule_values,
                rows.composition_input,
            ) |source, value, *destination| destination.* =
                try composition_input_witness.logicalRow(
                    source,
                    value,
                    .binary_node,
                );
            for (
                composition_rows.control_preprocessing.rows,
                rows.composition_control,
            ) |source, *destination| destination.* =
                composition_control_witness.logicalRow(source, .binary_node);

            const left = self.children[LEFT_CHILD].capture;
            const right = self.children[RIGHT_CHILD].capture;
            const query_witness = query_bits_witness.QueryWitness{ .binary_node = .{
                .left = self.query_words[LEFT_CHILD],
                .right = self.query_words[RIGHT_CHILD],
            } };
            const root_witness = merkle_root_witness.RootWitness{ .binary_node = .{
                .left = .{ .trace = left.trace_roots, .fri = left.fri_roots },
                .right = .{ .trace = right.trace_roots, .fri = right.fri_roots },
            } };
            const query_parameters = try query_bits_witness.parameterValues(
                self.fri_rows.query_bits_reference,
                .binary_node,
            );
            for (
                self.fri_rows.query_bits_preprocessing.rows,
                rows.query_bits,
            ) |source, *destination| destination.* =
                try query_bits_witness.logicalRow(
                    source,
                    query_witness,
                    query_parameters,
                );
            for (
                self.fri_rows.query_mapping_preprocessing.rows,
                rows.query_mapping,
            ) |source, *destination| destination.* =
                try query_mapping_witness.logicalRow(source, query_witness);
            for (
                self.fri_rows.merkle_root_preprocessing.rows,
                rows.merkle_root,
            ) |source, *destination| destination.* =
                try merkle_root_witness.logicalRow(source, root_witness);

            const selectors = composition.ProofKind.binary_node.selectors();
            for (
                self.fri_rows.trace_merkle_preprocessing.rows,
                rows.trace_merkle,
                0..,
            ) |source, *destination, row_index| destination.* =
                columnLogicalRow(
                    trace_merkle_witness.MAIN_COLUMN_COUNT,
                    &fri_workspace.main_columns,
                    ColumnOffset.trace_merkle_main,
                    row_index,
                ) ++ source.values() ++ .{
                    selectors[0],
                    selectors[1],
                    M31.fromCanonical(trace_merkle_witness.LEAF_TAG),
                    M31.fromCanonical(trace_merkle_witness.TRACE_POSITION_KIND),
                };
            for (
                self.fri_rows.pcs_preprocessing.rows,
                rows.pcs_deep,
            ) |source, *destination| {
                const value = self.fri_rows.pcs_inputs.lanes[source.lane]
                    .input_values[source.binding];
                destination.* = pcs_witness.logicalInputs(
                    (pcs_witness.MainRow{
                        .enabler = M31.one(),
                        .value = value,
                    }).values(),
                    source.values(),
                    .binary_node,
                );
            }
            for (
                self.fri_rows.fri_leaf_preprocessing.rows,
                rows.fri_leaf,
                0..,
            ) |source, *destination, row_index| destination.* =
                columnLogicalRow(
                    fri_leaf_witness.MAIN_COLUMN_COUNT,
                    &fri_workspace.main_columns,
                    ColumnOffset.fri_leaf_main,
                    row_index,
                ) ++ source.values() ++ .{
                    selectors[0],
                    selectors[1],
                    M31.fromCanonical(fri_leaf_witness.LEAF_TAG),
                };
            for (
                self.fri_rows.fri_node_preprocessing.rows,
                rows.fri_node,
                0..,
            ) |source, *destination, row_index| destination.* =
                columnLogicalRow(
                    fri_node_witness.MAIN_COLUMN_COUNT,
                    &fri_workspace.main_columns,
                    ColumnOffset.fri_node_main,
                    row_index,
                ) ++ source.values() ++ .{ selectors[0], selectors[1] };
            for (
                self.fri_rows.fri_anchor_preprocessing.rows,
                rows.fri_anchor,
                0..,
            ) |source, *destination, row_index| destination.* =
                columnLogicalRow(
                    fri_anchor_witness.MAIN_COLUMN_COUNT,
                    &fri_workspace.main_columns,
                    ColumnOffset.fri_anchor_main,
                    row_index,
                ) ++ source.values() ++ .{
                    selectors[0],
                    selectors[1],
                    M31.fromCanonical(fri_anchor_witness.FRI_MERKLE_KIND),
                };
            for (
                self.fri_rows.control_preprocessing.rows,
                rows.fri_control,
                0..,
            ) |source, *destination, row_index| destination.* =
                columnLogicalRow(
                    fri_control_witness.MAIN_COLUMN_COUNT,
                    &fri_workspace.main_columns,
                    ColumnOffset.fri_control_main,
                    row_index,
                ) ++ source.values() ++ .{
                    selectors[0],
                    selectors[1],
                    M31.fromCanonical(fri_control_witness.POSITION_FIELD),
                    M31.fromCanonical(fri_control_witness.OFFSET_FIELD),
                };
            const evaluations = fri_input_witness.Evaluations{
                .segment = &self.fri_rows.inactive_fri_evaluation,
                .left = &left.evaluation,
                .right = &right.evaluation,
            };
            for (
                self.fri_rows.input_preprocessing.rows,
                rows.fri_input,
            ) |source, *destination| {
                const value = evaluations.at(source.lane).values[source.node_id]
                    .tryIntoM31() catch return error.CompositionAuthorityMismatch;
                destination.* = fri_input_witness.logicalInputs(
                    (fri_input_witness.MainRow{
                        .enabler = M31.one(),
                        .value = value,
                    }).values(),
                    source.values(),
                    .binary_node,
                );
            }

            const arithmetic_rows = self.arithmetic_rows.?;
            for (
                arithmetic_workspace.multiply_invocations,
                rows.multiply,
                0..,
            ) |invocation, *destination, row_index| destination.* =
                multiply_witness.logicalInputs(
                    multiply_witness.mainRow(invocation),
                    multiply_witness.preprocessedRow(
                        arithmetic_rows.plan.multiply_rows[row_index],
                    ),
                    .binary_node,
                );
            for (
                arithmetic_workspace.inverse_invocations,
                rows.inverse,
                0..,
            ) |invocation, *destination, row_index| destination.* =
                inverse_witness.logicalInputs(
                    try inverse_witness.mainRow(invocation),
                    inverse_witness.preprocessedRow(
                        arithmetic_rows.plan.inverse_rows[row_index],
                    ),
                    .binary_node,
                );
            for (
                arithmetic_workspace.linear_invocations,
                rows.linear,
                0..,
            ) |invocation, *destination, row_index| destination.* =
                linear_witness.logicalInputs(
                    try linear_witness.mainRow(invocation),
                    linear_witness.preprocessedRow(
                        arithmetic_rows.plan.linear_rows[row_index],
                    ),
                    .binary_node,
                );
            for (merkle_workspace.logical_rows, rows.merkle_path) |
                source,
                *destination,
            | destination.* = source;

            rows.authority_digest = relationRowsDigest(rows);
            rows.ready = true;
            try rows.validateReadyFor(self);
        }

        pub fn retainedRelationRows(
            self: *const Self,
            rows: *const RelationRows,
        ) !*const RelationRows {
            try self.requireFullBundleAuthority();
            try rows.validateReadyFor(self);
            return rows;
        }

        pub fn retainedRelationRowsPrepared(
            self: *const Self,
            authority: *const PreparedAuthority,
            rows: *const RelationRows,
        ) !*const RelationRows {
            try authority.validateFor(self);
            try rows.validateReadyFor(self);
            return rows;
        }
    };
}
