//! Arithmetic operations for the authenticated binary FRI source.

pub fn Operations(comptime Context: type) type {
    const Self = Context.Source;
    const Boundary = Context.BoundaryType;
    const PreparedAuthority = Self.PreparedAuthority;
    const ArithmeticWorkspace = Self.ArithmeticWorkspace;

    const M31 = Context.M31;
    const multiply_witness = Context.multiply_witness;
    const inverse_witness = Context.inverse_witness;
    const linear_witness = Context.linear_witness;
    const lowering = Context.lowering;
    const LEFT_CHILD = Context.LEFT_CHILD;
    const RIGHT_CHILD = Context.RIGHT_CHILD;
    const ARITHMETIC_ROW_COUNT = Context.ARITHMETIC_ROW_COUNT;
    const ARITHMETIC_PREPROCESSED_COLUMN_COUNT = Context.ARITHMETIC_PREPROCESSED_COLUMN_COUNT;
    const ARITHMETIC_MAIN_COLUMN_COUNT = Context.ARITHMETIC_MAIN_COLUMN_COUNT;
    const ARITHMETIC_PREPROCESSED_COLUMNS_PER_ROW = Context.ARITHMETIC_PREPROCESSED_COLUMNS_PER_ROW;
    const ARITHMETIC_MAIN_COLUMNS_PER_ROW = Context.ARITHMETIC_MAIN_COLUMNS_PER_ROW;
    const ArithmeticColumnOffset = Context.ArithmeticColumnOffset;
    const validateDestination = Context.validateDestination;
    const validateArithmeticDestination = Context.validateArithmeticDestination;
    const scatterColumnsToCommitmentOrder = Context.scatterColumnsToCommitmentOrder;
    const columnArray = Context.columnArray;

    return struct {
        pub fn arithmeticLogSizes(self: *const Self) ![ARITHMETIC_ROW_COUNT]u32 {
            try self.requireCompositionAuthorities();
            return self.arithmetic_rows.?.log_sizes;
        }

        pub fn fillArithmeticPreprocessedInto(
            self: *const Self,
            workspace: *ArithmeticWorkspace,
            destination: [][]M31,
        ) !void {
            try self.requireCompositionAuthorities();
            return fillArithmeticPreprocessedAssumeAuthority(
                self,
                workspace,
                destination,
            );
        }

        pub fn fillArithmeticPreprocessedPreparedInto(
            self: *const Self,
            authority: *const PreparedAuthority,
            workspace: *ArithmeticWorkspace,
            destination: [][]M31,
        ) !void {
            try authority.validateFor(self);
            return fillArithmeticPreprocessedAssumeAuthority(
                self,
                workspace,
                destination,
            );
        }

        fn fillArithmeticPreprocessedAssumeAuthority(
            self: *const Self,
            workspace: *ArithmeticWorkspace,
            destination: [][]M31,
        ) !void {
            try workspace.validateFor(self);
            const rows = self.arithmetic_rows.?;
            try validateDestination(
                destination,
                rows.log_sizes,
                ARITHMETIC_PREPROCESSED_COLUMNS_PER_ROW,
                workspace.storage,
                self,
            );
            try validateArithmeticDestination(destination, workspace);
            try generateArithmeticPreprocessed(
                self,
                &workspace.preprocessed_columns,
            );
            scatterColumnsToCommitmentOrder(
                destination,
                &workspace.preprocessed_columns,
            );
        }

        pub fn fillArithmeticMainInto(
            self: *const Self,
            workspace: *ArithmeticWorkspace,
            destination: [][]M31,
        ) !void {
            try self.requireCompositionAuthorities();
            return fillArithmeticMainAssumeAuthority(self, workspace, destination);
        }

        pub fn fillArithmeticMainPreparedInto(
            self: *const Self,
            authority: *const PreparedAuthority,
            workspace: *ArithmeticWorkspace,
            destination: [][]M31,
        ) !void {
            try authority.validateFor(self);
            return fillArithmeticMainAssumeAuthority(self, workspace, destination);
        }

        fn fillArithmeticMainAssumeAuthority(
            self: *const Self,
            workspace: *ArithmeticWorkspace,
            destination: [][]M31,
        ) !void {
            try workspace.validateFor(self);
            const rows = self.arithmetic_rows.?;
            try validateDestination(
                destination,
                rows.log_sizes,
                ARITHMETIC_MAIN_COLUMNS_PER_ROW,
                workspace.storage,
                self,
            );
            try validateArithmeticDestination(destination, workspace);
            try generateArithmeticMain(
                self,
                workspace,
                &workspace.main_columns,
            );
            scatterColumnsToCommitmentOrder(
                destination,
                &workspace.main_columns,
            );
        }

        fn generateArithmeticPreprocessed(
            self: *const Self,
            columns: *[ARITHMETIC_PREPROCESSED_COLUMN_COUNT][]M31,
        ) !void {
            const rows = self.arithmetic_rows orelse
                return error.MissingCompositionAuthority;
            try rows.multiply_executor.generatePreprocessedInto(
                columnArray(
                    multiply_witness.PREPROCESSED_COLUMN_COUNT,
                    columns,
                    ArithmeticColumnOffset.multiply_pp,
                ),
                rows.plan.multiply_rows,
                rows.log_sizes[0],
            );
            try rows.inverse_executor.generatePreprocessedInto(
                columnArray(
                    inverse_witness.PREPROCESSED_COLUMN_COUNT,
                    columns,
                    ArithmeticColumnOffset.inverse_pp,
                ),
                rows.plan.inverse_rows,
                rows.log_sizes[1],
            );
            try rows.linear_executor.generatePreprocessedInto(
                columnArray(
                    linear_witness.PREPROCESSED_COLUMN_COUNT,
                    columns,
                    ArithmeticColumnOffset.linear_pp,
                ),
                rows.plan.linear_rows,
                rows.log_sizes[2],
            );
        }

        fn generateArithmeticMain(
            self: *const Self,
            workspace: *ArithmeticWorkspace,
            columns: *[ARITHMETIC_MAIN_COLUMN_COUNT][]M31,
        ) !void {
            const rows = self.arithmetic_rows orelse
                return error.MissingCompositionAuthority;
            var evaluations: [8]lowering.Evaluation = undefined;
            if (comptime @hasDecl(Boundary, "fillArithmeticEvaluations")) {
                try Boundary.fillArithmeticEvaluations(self, &evaluations);
            } else {
                evaluations = arithmeticEvaluations(self);
            }
            try rows.plan.materializeInto(
                rows.reference,
                .{ .lanes = evaluations[0..rows.lanes.len] },
                .binary_node,
                workspace.buffers(),
            );
            try rows.multiply_executor.generateMainInto(
                columnArray(
                    multiply_witness.MAIN_COLUMN_COUNT,
                    columns,
                    ArithmeticColumnOffset.multiply_main,
                ),
                workspace.multiply_invocations,
                rows.log_sizes[0],
            );
            try rows.inverse_executor.generateMainInto(
                columnArray(
                    inverse_witness.MAIN_COLUMN_COUNT,
                    columns,
                    ArithmeticColumnOffset.inverse_main,
                ),
                workspace.inverse_invocations,
                rows.log_sizes[1],
            );
            try rows.linear_executor.generateMainInto(
                columnArray(
                    linear_witness.MAIN_COLUMN_COUNT,
                    columns,
                    ArithmeticColumnOffset.linear_main,
                ),
                workspace.linear_invocations,
                rows.log_sizes[2],
            );
        }

        fn arithmeticEvaluations(self: *const Self) [8]lowering.Evaluation {
            const left = self.children[LEFT_CHILD];
            const right = self.children[RIGHT_CHILD];
            const left_composition = left.composition.?;
            const right_composition = right.composition.?;
            var evaluations: [8]lowering.Evaluation = undefined;
            evaluations[0..7].* = .{
                left_composition.evaluation,
                left_composition.evaluation,
                .{
                    .circuit_identity = left.capture.pcs_evaluation.circuit_identity,
                    .values = left.capture.pcs_evaluation.values,
                },
                .{
                    .circuit_identity = left.capture.evaluation.circuit_identity,
                    .values = left.capture.evaluation.values,
                },
                right_composition.evaluation,
                .{
                    .circuit_identity = right.capture.pcs_evaluation.circuit_identity,
                    .values = right.capture.pcs_evaluation.values,
                },
                .{
                    .circuit_identity = right.capture.evaluation.circuit_identity,
                    .values = right.capture.evaluation.values,
                },
            };
            if (self.shared_arithmetic) |input|
                evaluations[7] = input.evaluation;
            return evaluations;
        }
    };
}
