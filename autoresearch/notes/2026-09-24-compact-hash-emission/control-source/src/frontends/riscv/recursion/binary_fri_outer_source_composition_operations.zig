//! Composition operations for the authenticated binary FRI source.

pub fn Operations(comptime Context: type) type {
    const Self = Context.Source;
    const PreparedAuthority = Self.PreparedAuthority;
    const CompositionWorkspace = Self.CompositionWorkspace;

    const M31 = Context.M31;
    const composition_input_witness = Context.composition_input_witness;
    const composition_control_witness = Context.composition_control_witness;
    const COMPOSITION_ROW_COUNT = Context.COMPOSITION_ROW_COUNT;
    const COMPOSITION_PREPROCESSED_COLUMNS_PER_ROW = Context.COMPOSITION_PREPROCESSED_COLUMNS_PER_ROW;
    const COMPOSITION_MAIN_COLUMNS_PER_ROW = Context.COMPOSITION_MAIN_COLUMNS_PER_ROW;
    const validateDestination = Context.validateDestination;
    const scatterColumnsToCommitmentOrder = Context.scatterColumnsToCommitmentOrder;
    const columnArray = Context.columnArray;

    return struct {
        pub fn compositionLogSizes(
            self: *const Self,
        ) ![COMPOSITION_ROW_COUNT]u32 {
            try self.requireFullBundleAuthority();
            return self.composition_rows.?.log_sizes;
        }

        pub fn fillCompositionPreprocessedInto(
            self: *const Self,
            workspace: *CompositionWorkspace,
            destination: [][]M31,
        ) !void {
            try self.requireFullBundleAuthority();
            return fillCompositionPreprocessedAssumeAuthority(
                self,
                workspace,
                destination,
            );
        }

        pub fn fillCompositionPreprocessedPreparedInto(
            self: *const Self,
            authority: *const PreparedAuthority,
            workspace: *CompositionWorkspace,
            destination: [][]M31,
        ) !void {
            try authority.validateFor(self);
            return fillCompositionPreprocessedAssumeAuthority(
                self,
                workspace,
                destination,
            );
        }

        fn fillCompositionPreprocessedAssumeAuthority(
            self: *const Self,
            workspace: *CompositionWorkspace,
            destination: [][]M31,
        ) !void {
            try workspace.validateFor(self);
            const rows = self.composition_rows.?;
            try validateDestination(
                destination,
                rows.log_sizes,
                COMPOSITION_PREPROCESSED_COLUMNS_PER_ROW,
                workspace.storage,
                self,
            );
            const input_columns = columnArray(
                composition_input_witness.PREPROCESSED_COLUMN_COUNT,
                &workspace.preprocessed_columns,
                0,
            );
            try rows.input_executor.generatePreprocessedInto(
                &rows.input_preprocessing,
                input_columns,
            );
            const control_columns = columnArray(
                composition_control_witness.COLUMN_COUNT,
                &workspace.preprocessed_columns,
                composition_input_witness.PREPROCESSED_COLUMN_COUNT,
            );
            try rows.control_preprocessing.generateInto(
                control_columns,
                self.vm_plan,
                self.recursion_plans[0],
            );
            scatterColumnsToCommitmentOrder(
                destination,
                &workspace.preprocessed_columns,
            );
        }

        pub fn fillCompositionMainInto(
            self: *const Self,
            workspace: *CompositionWorkspace,
            destination: [][]M31,
        ) !void {
            try self.requireFullBundleAuthority();
            return fillCompositionMainAssumeAuthority(self, workspace, destination);
        }

        pub fn fillCompositionMainPreparedInto(
            self: *const Self,
            authority: *const PreparedAuthority,
            workspace: *CompositionWorkspace,
            destination: [][]M31,
        ) !void {
            try authority.validateFor(self);
            return fillCompositionMainAssumeAuthority(self, workspace, destination);
        }

        fn fillCompositionMainAssumeAuthority(
            self: *const Self,
            workspace: *CompositionWorkspace,
            destination: [][]M31,
        ) !void {
            try workspace.validateFor(self);
            const rows = self.composition_rows.?;
            try validateDestination(
                destination,
                rows.log_sizes,
                COMPOSITION_MAIN_COLUMNS_PER_ROW,
                workspace.storage,
                self,
            );
            try rows.input_executor.generateMainInto(
                &rows.input_preprocessing,
                &workspace.main_columns,
                rows.schedule_values,
                .binary_node,
            );
            scatterColumnsToCommitmentOrder(
                destination,
                &workspace.main_columns,
            );
        }
    };
}
