//! Fri operations for the authenticated binary FRI source.

pub fn Operations(comptime Context: type) type {
    const Self = Context.Source;
    const Boundary = Context.BoundaryType;
    const PreparedAuthority = Self.PreparedAuthority;
    const Workspace = Self.Workspace;

    const M31 = Context.M31;
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
    const LEFT_CHILD = Context.LEFT_CHILD;
    const RIGHT_CHILD = Context.RIGHT_CHILD;
    const FRI_ROW_COUNT = Context.FRI_ROW_COUNT;
    const PREPROCESSED_COLUMN_COUNT = Context.PREPROCESSED_COLUMN_COUNT;
    const MAIN_COLUMN_COUNT = Context.MAIN_COLUMN_COUNT;
    const PREPROCESSED_COLUMNS_PER_ROW = Context.PREPROCESSED_COLUMNS_PER_ROW;
    const MAIN_COLUMNS_PER_ROW = Context.MAIN_COLUMNS_PER_ROW;
    const ColumnOffset = Context.ColumnOffset;
    const friPathLeafDigest = Context.friPathLeafDigest;
    const validateDestination = Context.validateDestination;
    const scatterColumnsToCommitmentOrder = Context.scatterColumnsToCommitmentOrder;
    const columnArray = Context.columnArray;

    return struct {
        pub fn friLogSizes(self: *const Self) [FRI_ROW_COUNT]u32 {
            return self.fri_rows.log_sizes;
        }

        pub fn fillFriPreprocessedInto(
            self: *const Self,
            workspace: *Workspace,
            destination: [][]M31,
        ) !void {
            try self.validate();
            return fillFriPreprocessedAssumeAuthority(self, workspace, destination);
        }

        pub fn fillFriPreprocessedPreparedInto(
            self: *const Self,
            authority: *const PreparedAuthority,
            workspace: *Workspace,
            destination: [][]M31,
        ) !void {
            try authority.validateFor(self);
            return fillFriPreprocessedAssumeAuthority(self, workspace, destination);
        }

        fn fillFriPreprocessedAssumeAuthority(
            self: *const Self,
            workspace: *Workspace,
            destination: [][]M31,
        ) !void {
            try workspace.validateFor(self);
            try validateDestination(
                destination,
                self.fri_rows.log_sizes,
                PREPROCESSED_COLUMNS_PER_ROW,
                workspace.storage,
                self,
            );
            try generateFriPreprocessed(self, &workspace.preprocessed_columns);
            scatterColumnsToCommitmentOrder(
                destination,
                &workspace.preprocessed_columns,
            );
        }

        pub fn fillFriMainInto(
            self: *const Self,
            workspace: *Workspace,
            destination: [][]M31,
        ) !void {
            try self.validate();
            return fillFriMainAssumeAuthority(self, workspace, destination);
        }

        pub fn fillFriMainPreparedInto(
            self: *const Self,
            authority: *const PreparedAuthority,
            workspace: *Workspace,
            destination: [][]M31,
        ) !void {
            try authority.validateFor(self);
            return fillFriMainAssumeAuthority(self, workspace, destination);
        }

        fn fillFriMainAssumeAuthority(
            self: *const Self,
            workspace: *Workspace,
            destination: [][]M31,
        ) !void {
            try workspace.validateFor(self);
            try validateDestination(
                destination,
                self.fri_rows.log_sizes,
                MAIN_COLUMNS_PER_ROW,
                workspace.storage,
                self,
            );
            try generateFriMain(self, &workspace.main_columns);
            workspace.path_leaf_digest = friPathLeafDigest(
                self,
                &workspace.main_columns,
            );
            workspace.main_ready = true;
            scatterColumnsToCommitmentOrder(
                destination,
                &workspace.main_columns,
            );
        }

        fn generateFriPreprocessed(
            self: *const Self,
            columns: *[PREPROCESSED_COLUMN_COUNT][]M31,
        ) !void {
            try self.fri_rows.query_bits_executor.generatePreprocessedInto(
                &self.fri_rows.query_bits_preprocessing,
                self.fri_rows.query_bits_reference,
                columnArray(
                    query_bits_witness.PREPROCESSED_COLUMN_COUNT,
                    columns,
                    ColumnOffset.query_bits_pp,
                ),
            );
            try self.fri_rows.query_mapping_executor.generatePreprocessedInto(
                &self.fri_rows.query_mapping_preprocessing,
                self.fri_rows.query_mapping_reference,
                columnArray(
                    query_mapping_witness.PREPROCESSED_COLUMN_COUNT,
                    columns,
                    ColumnOffset.query_mapping_pp,
                ),
            );
            try self.fri_rows.merkle_root_executor.generatePreprocessedInto(
                &self.fri_rows.merkle_root_preprocessing,
                self.fri_rows.merkle_root_reference,
                columnArray(
                    merkle_root_witness.PREPROCESSED_COLUMN_COUNT,
                    columns,
                    ColumnOffset.merkle_root_pp,
                ),
            );
            try self.fri_rows.trace_merkle_executor.generatePreprocessedInto(
                &self.fri_rows.trace_merkle_preprocessing,
                self.fri_rows.trace_merkle_reference,
                columnArray(
                    trace_merkle_witness.PREPROCESSED_COLUMN_COUNT,
                    columns,
                    ColumnOffset.trace_merkle_pp,
                ),
            );
            try self.fri_rows.pcs_executor.generatePreprocessedInto(
                &self.fri_rows.pcs_preprocessing,
                self.fri_rows.pcs_reference,
                columnArray(
                    pcs_witness.PREPROCESSED_COLUMN_COUNT,
                    columns,
                    ColumnOffset.pcs_deep_pp,
                ),
            );
            try self.fri_rows.fri_leaf_executor.generatePreprocessedInto(
                &self.fri_rows.fri_leaf_preprocessing,
                self.fri_rows.fri_reference,
                columnArray(
                    fri_leaf_witness.PREPROCESSED_COLUMN_COUNT,
                    columns,
                    ColumnOffset.fri_leaf_pp,
                ),
            );
            try self.fri_rows.fri_node_executor.generatePreprocessedInto(
                &self.fri_rows.fri_node_preprocessing,
                self.fri_rows.fri_reference,
                columnArray(
                    fri_node_witness.PREPROCESSED_COLUMN_COUNT,
                    columns,
                    ColumnOffset.fri_node_pp,
                ),
            );
            try self.fri_rows.fri_anchor_executor.generatePreprocessedInto(
                &self.fri_rows.fri_anchor_preprocessing,
                self.fri_rows.fri_reference,
                self.vm_plan,
                self.recursion_plans[0],
                columnArray(
                    fri_anchor_witness.PREPROCESSED_COLUMN_COUNT,
                    columns,
                    ColumnOffset.fri_anchor_pp,
                ),
            );
            try self.fri_rows.control_executor.generatePreprocessedInto(
                &self.fri_rows.control_preprocessing,
                self.fri_rows.control_reference,
                columnArray(
                    fri_control_witness.PREPROCESSED_COLUMN_COUNT,
                    columns,
                    ColumnOffset.fri_control_pp,
                ),
            );
            try self.fri_rows.input_executor.generatePreprocessedInto(
                &self.fri_rows.input_preprocessing,
                self.fri_rows.input_reference,
                columnArray(
                    fri_input_witness.PREPROCESSED_COLUMN_COUNT,
                    columns,
                    ColumnOffset.fri_input_pp,
                ),
            );
        }

        fn generateFriMain(
            self: *const Self,
            columns: *[MAIN_COLUMN_COUNT][]M31,
        ) !void {
            const proof_kind: query_bits_witness.ProofKind = if (comptime @hasDecl(Boundary, "FRI_PROOF_KIND"))
                Boundary.FRI_PROOF_KIND
            else
                .binary_node;
            const query_witness = if (comptime proof_kind == .empty_leaf)
                query_bits_witness.QueryWitness{ .empty_leaf = {} }
            else blk: {
                break :blk query_bits_witness.QueryWitness{ .binary_node = .{
                    .left = self.query_words[LEFT_CHILD],
                    .right = self.query_words[RIGHT_CHILD],
                } };
            };
            const root_witness = if (comptime proof_kind == .empty_leaf)
                merkle_root_witness.RootWitness{ .empty_leaf = {} }
            else blk: {
                const left = self.children[LEFT_CHILD].capture;
                const right = self.children[RIGHT_CHILD].capture;
                break :blk merkle_root_witness.RootWitness{ .binary_node = .{
                    .left = .{ .trace = left.trace_roots, .fri = left.fri_roots },
                    .right = .{ .trace = right.trace_roots, .fri = right.fri_roots },
                } };
            };
            const trace_witness = if (comptime proof_kind == .empty_leaf)
                trace_merkle_witness.OpeningWitness{ .empty_leaf = {} }
            else blk: {
                const left = self.children[LEFT_CHILD].capture;
                const right = self.children[RIGHT_CHILD].capture;
                break :blk trace_merkle_witness.OpeningWitness{ .binary_node = .{
                    .left = .{
                        .queried_values = left.queried_values,
                        .raw_queries = left.raw_queries,
                    },
                    .right = .{
                        .queried_values = right.queried_values,
                        .raw_queries = right.raw_queries,
                    },
                } };
            };
            const fri_witness = if (comptime proof_kind == .empty_leaf)
                fri_leaf_witness.OpeningWitness{ .empty_leaf = {} }
            else blk: {
                const left = self.children[LEFT_CHILD].capture;
                const right = self.children[RIGHT_CHILD].capture;
                break :blk fri_leaf_witness.OpeningWitness{ .binary_node = .{
                    .left = .{
                        .raw_queries = left.raw_queries,
                        .layers = left.fri_layer_openings,
                    },
                    .right = .{
                        .raw_queries = right.raw_queries,
                        .layers = right.fri_layer_openings,
                    },
                } };
            };
            const evaluations = fri_input_witness.Evaluations{
                .segment = &self.fri_rows.inactive_fri_evaluation,
                .left = if (comptime proof_kind == .empty_leaf)
                    &self.fri_rows.inactive_fri_evaluation
                else
                    &self.children[LEFT_CHILD].capture.evaluation,
                .right = if (comptime proof_kind == .empty_leaf)
                    &self.fri_rows.inactive_fri_evaluation
                else
                    &self.children[RIGHT_CHILD].capture.evaluation,
            };

            try self.fri_rows.query_bits_executor.generateMainInto(
                &self.fri_rows.query_bits_preprocessing,
                self.fri_rows.query_bits_reference,
                columnArray(
                    query_bits_witness.MAIN_COLUMN_COUNT,
                    columns,
                    ColumnOffset.query_bits_main,
                ),
                query_witness,
            );
            try self.fri_rows.query_mapping_executor.generateMainInto(
                &self.fri_rows.query_mapping_preprocessing,
                self.fri_rows.query_mapping_reference,
                columnArray(
                    query_mapping_witness.MAIN_COLUMN_COUNT,
                    columns,
                    ColumnOffset.query_mapping_main,
                ),
                query_witness,
            );
            try self.fri_rows.merkle_root_executor.generateMainInto(
                &self.fri_rows.merkle_root_preprocessing,
                self.fri_rows.merkle_root_reference,
                columnArray(
                    merkle_root_witness.MAIN_COLUMN_COUNT,
                    columns,
                    ColumnOffset.merkle_root_main,
                ),
                root_witness,
            );
            try self.fri_rows.trace_merkle_executor.generateMainInto(
                &self.fri_rows.trace_merkle_preprocessing,
                self.fri_rows.trace_merkle_reference,
                columnArray(
                    trace_merkle_witness.MAIN_COLUMN_COUNT,
                    columns,
                    ColumnOffset.trace_merkle_main,
                ),
                trace_witness,
            );
            try self.fri_rows.pcs_executor.generateMainInto(
                &self.fri_rows.pcs_preprocessing,
                self.fri_rows.pcs_reference,
                columnArray(
                    pcs_witness.MAIN_COLUMN_COUNT,
                    columns,
                    ColumnOffset.pcs_deep_main,
                ),
                self.fri_rows.pcs_inputs,
                proof_kind,
            );
            try self.fri_rows.fri_leaf_executor.generateMainInto(
                &self.fri_rows.fri_leaf_preprocessing,
                self.fri_rows.fri_reference,
                columnArray(
                    fri_leaf_witness.MAIN_COLUMN_COUNT,
                    columns,
                    ColumnOffset.fri_leaf_main,
                ),
                fri_witness,
            );
            try self.fri_rows.fri_node_executor.generateMainInto(
                &self.fri_rows.fri_node_preprocessing,
                self.fri_rows.fri_reference,
                columnArray(
                    fri_node_witness.MAIN_COLUMN_COUNT,
                    columns,
                    ColumnOffset.fri_node_main,
                ),
                fri_witness,
            );
            try self.fri_rows.fri_anchor_executor.generateMainInto(
                &self.fri_rows.fri_anchor_preprocessing,
                self.fri_rows.fri_reference,
                self.vm_plan,
                self.recursion_plans[0],
                columnArray(
                    fri_anchor_witness.MAIN_COLUMN_COUNT,
                    columns,
                    ColumnOffset.fri_anchor_main,
                ),
                fri_witness,
            );
            try self.fri_rows.control_executor.generateMainInto(
                &self.fri_rows.control_preprocessing,
                self.fri_rows.control_reference,
                columnArray(
                    fri_control_witness.MAIN_COLUMN_COUNT,
                    columns,
                    ColumnOffset.fri_control_main,
                ),
                query_witness,
            );
            try self.fri_rows.input_executor.generateMainInto(
                &self.fri_rows.input_preprocessing,
                self.fri_rows.input_reference,
                columnArray(
                    fri_input_witness.MAIN_COLUMN_COUNT,
                    columns,
                    ColumnOffset.fri_input_main,
                ),
                evaluations,
                proof_kind,
            );
        }
    };
}
