//! Interaction operations for the authenticated binary FRI source.

pub fn Operations(comptime Context: type) type {
    const Self = Context.Source;
    const PreparedAuthority = Self.PreparedAuthority;
    const RelationRows = Self.RelationRows;
    const RelationInteractionWorkspace = Self.RelationInteractionWorkspace;

    const std = Context.std;
    const M31 = Context.M31;
    const QM31 = Context.QM31;
    const composition_input_air = Context.composition_input_air;
    const composition_control_air = Context.composition_control_air;
    const query_bits_air = Context.query_bits_air;
    const query_mapping_air = Context.query_mapping_air;
    const merkle_root_air = Context.merkle_root_air;
    const trace_merkle_air = Context.trace_merkle_air;
    const pcs_air = Context.pcs_air;
    const fri_leaf_air = Context.fri_leaf_air;
    const fri_node_air = Context.fri_node_air;
    const fri_anchor_air = Context.fri_anchor_air;
    const fri_control_air = Context.fri_control_air;
    const fri_input_air = Context.fri_input_air;
    const multiply_air = Context.multiply_air;
    const inverse_air = Context.inverse_air;
    const linear_air = Context.linear_air;
    const merkle_path_air = Context.merkle_path_air;
    const universal = Context.universal;
    const universal_roster = Context.universal_roster;
    const relation_interaction = Context.relation_interaction;
    const CompositionInputFramework = Context.CompositionInputFramework;
    const CompositionControlFramework = Context.CompositionControlFramework;
    const QueryBitsFramework = Context.QueryBitsFramework;
    const QueryMappingFramework = Context.QueryMappingFramework;
    const MerkleRootFramework = Context.MerkleRootFramework;
    const TraceMerkleFramework = Context.TraceMerkleFramework;
    const PcsFramework = Context.PcsFramework;
    const FriLeafFramework = Context.FriLeafFramework;
    const FriNodeFramework = Context.FriNodeFramework;
    const FriAnchorFramework = Context.FriAnchorFramework;
    const FriControlFramework = Context.FriControlFramework;
    const FriInputFramework = Context.FriInputFramework;
    const MultiplyFramework = Context.MultiplyFramework;
    const InverseFramework = Context.InverseFramework;
    const LinearFramework = Context.LinearFramework;
    const MerklePathFramework = Context.MerklePathFramework;
    const TYPED_RELATION_ROW_COUNT = Context.TYPED_RELATION_ROW_COUNT;
    const TYPED_INTERACTION_COLUMNS_PER_ROW = Context.TYPED_INTERACTION_COLUMNS_PER_ROW;
    const validateDestination = Context.validateDestination;
    const copyColumns = Context.copyColumns;
    const columnArray = Context.columnArray;

    return struct {
        pub fn fillTypedInteractionsInto(
            self: *const Self,
            rows: *const RelationRows,
            workspace: *RelationInteractionWorkspace,
            relations: *const universal.UniversalRelations,
            destination: [][]M31,
        ) ![TYPED_RELATION_ROW_COUNT]QM31 {
            try self.requireFullBundleAuthority();
            return fillTypedInteractionsAssumeAuthority(
                self,
                rows,
                workspace,
                relations,
                destination,
            );
        }

        pub fn fillTypedInteractionsPreparedInto(
            self: *const Self,
            authority: *const PreparedAuthority,
            rows: *const RelationRows,
            workspace: *RelationInteractionWorkspace,
            relations: *const universal.UniversalRelations,
            destination: [][]M31,
        ) ![TYPED_RELATION_ROW_COUNT]QM31 {
            try authority.validateFor(self);
            return fillTypedInteractionsAssumeAuthority(
                self,
                rows,
                workspace,
                relations,
                destination,
            );
        }

        fn fillTypedInteractionsAssumeAuthority(
            self: *const Self,
            rows: *const RelationRows,
            workspace: *RelationInteractionWorkspace,
            relations: *const universal.UniversalRelations,
            destination: [][]M31,
        ) ![TYPED_RELATION_ROW_COUNT]QM31 {
            try rows.validateReadyFor(self);
            try workspace.validateFor(self, rows);
            try relations.validate();
            const log_sizes = (try self.bundleLogSizesAssumeAuthority())[0..TYPED_RELATION_ROW_COUNT].*;
            try validateDestination(
                destination,
                log_sizes,
                TYPED_INTERACTION_COLUMNS_PER_ROW,
                workspace.storage,
                self,
            );

            const composition_rows = self.composition_rows.?;
            const arithmetic_rows = self.arithmetic_rows.?;
            var result: [TYPED_RELATION_ROW_COUNT]QM31 = undefined;
            var column_at: usize = 0;
            result[0] = try CompositionInputFramework.generatePreparedInto(
                &workspace.composition_input,
                &composition_rows.input_relation,
                rows.composition_input,
                log_sizes[0],
                relations,
                columnArray(
                    composition_input_air.INTERACTION_COLUMN_COUNT,
                    &workspace.columns,
                    column_at,
                ),
            );
            column_at += composition_input_air.INTERACTION_COLUMN_COUNT;
            result[1] = try CompositionControlFramework.generatePreparedInto(
                &workspace.composition_control,
                &composition_rows.control_relation,
                rows.composition_control,
                log_sizes[1],
                relations,
                columnArray(
                    composition_control_air.INTERACTION_COLUMN_COUNT,
                    &workspace.columns,
                    column_at,
                ),
            );
            column_at += composition_control_air.INTERACTION_COLUMN_COUNT;
            result[2] = try QueryBitsFramework.generatePreparedInto(
                &workspace.query_bits,
                &self.fri_rows.query_bits_relation,
                rows.query_bits,
                log_sizes[2],
                relations,
                columnArray(
                    query_bits_air.INTERACTION_COLUMN_COUNT,
                    &workspace.columns,
                    column_at,
                ),
            );
            column_at += query_bits_air.INTERACTION_COLUMN_COUNT;
            result[3] = try QueryMappingFramework.generatePreparedInto(
                &workspace.query_mapping,
                &self.fri_rows.query_mapping_relation,
                rows.query_mapping,
                log_sizes[3],
                relations,
                columnArray(
                    query_mapping_air.INTERACTION_COLUMN_COUNT,
                    &workspace.columns,
                    column_at,
                ),
            );
            column_at += query_mapping_air.INTERACTION_COLUMN_COUNT;
            result[4] = try MerkleRootFramework.generatePreparedInto(
                &workspace.merkle_root,
                &self.fri_rows.merkle_root_relation,
                rows.merkle_root,
                log_sizes[4],
                relations,
                columnArray(
                    merkle_root_air.INTERACTION_COLUMN_COUNT,
                    &workspace.columns,
                    column_at,
                ),
            );
            column_at += merkle_root_air.INTERACTION_COLUMN_COUNT;
            result[5] = try TraceMerkleFramework.generatePreparedInto(
                &workspace.trace_merkle,
                &self.fri_rows.trace_merkle_relation,
                rows.trace_merkle,
                log_sizes[5],
                relations,
                columnArray(
                    trace_merkle_air.INTERACTION_COLUMN_COUNT,
                    &workspace.columns,
                    column_at,
                ),
            );
            column_at += trace_merkle_air.INTERACTION_COLUMN_COUNT;
            result[6] = try PcsFramework.generatePreparedInto(
                &workspace.pcs_deep,
                &self.fri_rows.pcs_relation,
                rows.pcs_deep,
                log_sizes[6],
                relations,
                columnArray(
                    pcs_air.INTERACTION_COLUMN_COUNT,
                    &workspace.columns,
                    column_at,
                ),
            );
            column_at += pcs_air.INTERACTION_COLUMN_COUNT;
            result[7] = try FriLeafFramework.generatePreparedInto(
                &workspace.fri_leaf,
                &self.fri_rows.fri_leaf_relation,
                rows.fri_leaf,
                log_sizes[7],
                relations,
                columnArray(
                    fri_leaf_air.INTERACTION_COLUMN_COUNT,
                    &workspace.columns,
                    column_at,
                ),
            );
            column_at += fri_leaf_air.INTERACTION_COLUMN_COUNT;
            result[8] = try FriNodeFramework.generatePreparedInto(
                &workspace.fri_node,
                &self.fri_rows.fri_node_relation,
                rows.fri_node,
                log_sizes[8],
                relations,
                columnArray(
                    fri_node_air.INTERACTION_COLUMN_COUNT,
                    &workspace.columns,
                    column_at,
                ),
            );
            column_at += fri_node_air.INTERACTION_COLUMN_COUNT;
            result[9] = try FriAnchorFramework.generatePreparedInto(
                &workspace.fri_anchor,
                &self.fri_rows.fri_anchor_relation,
                rows.fri_anchor,
                log_sizes[9],
                relations,
                columnArray(
                    fri_anchor_air.INTERACTION_COLUMN_COUNT,
                    &workspace.columns,
                    column_at,
                ),
            );
            column_at += fri_anchor_air.INTERACTION_COLUMN_COUNT;
            result[10] = try FriControlFramework.generatePreparedInto(
                &workspace.fri_control,
                &self.fri_rows.control_relation,
                rows.fri_control,
                log_sizes[10],
                relations,
                columnArray(
                    fri_control_air.INTERACTION_COLUMN_COUNT,
                    &workspace.columns,
                    column_at,
                ),
            );
            column_at += fri_control_air.INTERACTION_COLUMN_COUNT;
            result[11] = try FriInputFramework.generatePreparedInto(
                &workspace.fri_input,
                &self.fri_rows.input_relation,
                rows.fri_input,
                log_sizes[11],
                relations,
                columnArray(
                    fri_input_air.INTERACTION_COLUMN_COUNT,
                    &workspace.columns,
                    column_at,
                ),
            );
            column_at += fri_input_air.INTERACTION_COLUMN_COUNT;
            result[12] = try MultiplyFramework.generatePreparedInto(
                &workspace.multiply,
                &arithmetic_rows.multiply_relation,
                rows.multiply,
                log_sizes[12],
                relations,
                columnArray(
                    multiply_air.INTERACTION_COLUMN_COUNT,
                    &workspace.columns,
                    column_at,
                ),
            );
            column_at += multiply_air.INTERACTION_COLUMN_COUNT;
            result[13] = try InverseFramework.generatePreparedInto(
                &workspace.inverse,
                &arithmetic_rows.inverse_relation,
                rows.inverse,
                log_sizes[13],
                relations,
                columnArray(
                    inverse_air.INTERACTION_COLUMN_COUNT,
                    &workspace.columns,
                    column_at,
                ),
            );
            column_at += inverse_air.INTERACTION_COLUMN_COUNT;
            result[14] = try LinearFramework.generatePreparedInto(
                &workspace.linear,
                &arithmetic_rows.linear_relation,
                rows.linear,
                log_sizes[14],
                relations,
                columnArray(
                    linear_air.INTERACTION_COLUMN_COUNT,
                    &workspace.columns,
                    column_at,
                ),
            );
            column_at += linear_air.INTERACTION_COLUMN_COUNT;
            result[15] = try MerklePathFramework.generatePreparedInto(
                &workspace.merkle_path,
                &self.merkle_rows.relation,
                rows.merkle_path,
                log_sizes[15],
                relations,
                columnArray(
                    merkle_path_air.INTERACTION_COLUMN_COUNT,
                    &workspace.columns,
                    column_at,
                ),
            );
            column_at += merkle_path_air.INTERACTION_COLUMN_COUNT;
            std.debug.assert(column_at == workspace.columns.len);

            copyColumns(destination, &workspace.columns);
            return result;
        }

        pub fn auditTypedInteractionDomains(
            self: *const Self,
            allocator: std.mem.Allocator,
            rows: *const RelationRows,
            relations: *const universal.UniversalRelations,
            claims: [TYPED_RELATION_ROW_COUNT]QM31,
        ) ![TYPED_RELATION_ROW_COUNT]relation_interaction.DomainAudit {
            try self.requireFullBundleAuthority();
            return auditTypedInteractionDomainsAssumeAuthority(
                self,
                allocator,
                rows,
                relations,
                claims,
                null,
            );
        }

        pub fn auditTypedInteractionDomainsPrepared(
            self: *const Self,
            authority: *const PreparedAuthority,
            allocator: std.mem.Allocator,
            rows: *const RelationRows,
            relations: *const universal.UniversalRelations,
            claims: [TYPED_RELATION_ROW_COUNT]QM31,
        ) ![TYPED_RELATION_ROW_COUNT]relation_interaction.DomainAudit {
            try authority.validateFor(self);
            return auditTypedInteractionDomainsAssumeAuthority(
                self,
                allocator,
                rows,
                relations,
                claims,
                null,
            );
        }

        pub fn auditTypedInteractionDomainsPreparedWithTupleLedger(
            self: *const Self,
            authority: *const PreparedAuthority,
            allocator: std.mem.Allocator,
            rows: *const RelationRows,
            relations: *const universal.UniversalRelations,
            claims: [TYPED_RELATION_ROW_COUNT]QM31,
            tuple_ledger: *relation_interaction.TupleLedger,
        ) ![TYPED_RELATION_ROW_COUNT]relation_interaction.DomainAudit {
            try authority.validateFor(self);
            return auditTypedInteractionDomainsAssumeAuthority(
                self,
                allocator,
                rows,
                relations,
                claims,
                tuple_ledger,
            );
        }

        fn auditTypedInteractionDomainsAssumeAuthority(
            self: *const Self,
            allocator: std.mem.Allocator,
            rows: *const RelationRows,
            relations: *const universal.UniversalRelations,
            claims: [TYPED_RELATION_ROW_COUNT]QM31,
            tuple_ledger: ?*relation_interaction.TupleLedger,
        ) ![TYPED_RELATION_ROW_COUNT]relation_interaction.DomainAudit {
            try rows.validateReadyFor(self);
            try relations.validate();
            const composition_rows = self.composition_rows.?;
            const arithmetic_rows = self.arithmetic_rows.?;
            const result = [TYPED_RELATION_ROW_COUNT]relation_interaction.DomainAudit{
                try composition_rows.input_relation.auditPreparedDomainSums(
                    allocator,
                    rows.composition_input,
                    relations,
                    claims[0],
                ),
                try composition_rows.control_relation.auditPreparedDomainSums(
                    allocator,
                    rows.composition_control,
                    relations,
                    claims[1],
                ),
                try self.fri_rows.query_bits_relation.auditPreparedDomainSums(
                    allocator,
                    rows.query_bits,
                    relations,
                    claims[2],
                ),
                try self.fri_rows.query_mapping_relation.auditPreparedDomainSums(
                    allocator,
                    rows.query_mapping,
                    relations,
                    claims[3],
                ),
                try self.fri_rows.merkle_root_relation.auditPreparedDomainSums(
                    allocator,
                    rows.merkle_root,
                    relations,
                    claims[4],
                ),
                try self.fri_rows.trace_merkle_relation.auditPreparedDomainSums(
                    allocator,
                    rows.trace_merkle,
                    relations,
                    claims[5],
                ),
                try self.fri_rows.pcs_relation.auditPreparedDomainSums(
                    allocator,
                    rows.pcs_deep,
                    relations,
                    claims[6],
                ),
                try self.fri_rows.fri_leaf_relation.auditPreparedDomainSums(
                    allocator,
                    rows.fri_leaf,
                    relations,
                    claims[7],
                ),
                try self.fri_rows.fri_node_relation.auditPreparedDomainSums(
                    allocator,
                    rows.fri_node,
                    relations,
                    claims[8],
                ),
                try self.fri_rows.fri_anchor_relation.auditPreparedDomainSums(
                    allocator,
                    rows.fri_anchor,
                    relations,
                    claims[9],
                ),
                try self.fri_rows.control_relation.auditPreparedDomainSums(
                    allocator,
                    rows.fri_control,
                    relations,
                    claims[10],
                ),
                try self.fri_rows.input_relation.auditPreparedDomainSums(
                    allocator,
                    rows.fri_input,
                    relations,
                    claims[11],
                ),
                try arithmetic_rows.multiply_relation.auditPreparedDomainSums(
                    allocator,
                    rows.multiply,
                    relations,
                    claims[12],
                ),
                try arithmetic_rows.inverse_relation.auditPreparedDomainSums(
                    allocator,
                    rows.inverse,
                    relations,
                    claims[13],
                ),
                try arithmetic_rows.linear_relation.auditPreparedDomainSums(
                    allocator,
                    rows.linear,
                    relations,
                    claims[14],
                ),
                try self.merkle_rows.relation.auditPreparedDomainSums(
                    allocator,
                    rows.merkle_path,
                    relations,
                    claims[15],
                ),
            };
            if (tuple_ledger) |ledger| {
                const mask = relation_interaction.allDomainMask();
                try composition_rows.input_relation.appendPreparedTupleContributions(
                    ledger,
                    @intFromEnum(universal_roster.Component.vm_air_composition_input),
                    rows.composition_input,
                    mask,
                );
                try composition_rows.control_relation.appendPreparedTupleContributions(
                    ledger,
                    @intFromEnum(universal_roster.Component.vm_air_composition_control),
                    rows.composition_control,
                    mask,
                );
                try self.fri_rows.query_bits_relation.appendPreparedTupleContributions(
                    ledger,
                    @intFromEnum(universal_roster.Component.query_bits),
                    rows.query_bits,
                    mask,
                );
                try self.fri_rows.query_mapping_relation.appendPreparedTupleContributions(
                    ledger,
                    @intFromEnum(universal_roster.Component.query_mapping),
                    rows.query_mapping,
                    mask,
                );
                try self.fri_rows.merkle_root_relation.appendPreparedTupleContributions(
                    ledger,
                    @intFromEnum(universal_roster.Component.merkle_root),
                    rows.merkle_root,
                    mask,
                );
                try self.fri_rows.trace_merkle_relation.appendPreparedTupleContributions(
                    ledger,
                    @intFromEnum(universal_roster.Component.trace_merkle),
                    rows.trace_merkle,
                    mask,
                );
                try self.fri_rows.pcs_relation.appendPreparedTupleContributions(
                    ledger,
                    @intFromEnum(universal_roster.Component.pcs_deep_input),
                    rows.pcs_deep,
                    mask,
                );
                try self.fri_rows.fri_leaf_relation.appendPreparedTupleContributions(
                    ledger,
                    @intFromEnum(universal_roster.Component.fri_merkle_leaf),
                    rows.fri_leaf,
                    mask,
                );
                try self.fri_rows.fri_node_relation.appendPreparedTupleContributions(
                    ledger,
                    @intFromEnum(universal_roster.Component.fri_merkle_node),
                    rows.fri_node,
                    mask,
                );
                try self.fri_rows.fri_anchor_relation.appendPreparedTupleContributions(
                    ledger,
                    @intFromEnum(universal_roster.Component.fri_merkle_anchor),
                    rows.fri_anchor,
                    mask,
                );
                try self.fri_rows.control_relation.appendPreparedTupleContributions(
                    ledger,
                    @intFromEnum(universal_roster.Component.fri_verifier_control),
                    rows.fri_control,
                    mask,
                );
                try self.fri_rows.input_relation.appendPreparedTupleContributions(
                    ledger,
                    @intFromEnum(universal_roster.Component.fri_verifier_input),
                    rows.fri_input,
                    mask,
                );
                try arithmetic_rows.multiply_relation.appendPreparedTupleContributions(
                    ledger,
                    @intFromEnum(universal_roster.Component.qm31_mul),
                    rows.multiply,
                    mask,
                );
                try arithmetic_rows.inverse_relation.appendPreparedTupleContributions(
                    ledger,
                    @intFromEnum(universal_roster.Component.qm31_inv),
                    rows.inverse,
                    mask,
                );
                try arithmetic_rows.linear_relation.appendPreparedTupleContributions(
                    ledger,
                    @intFromEnum(universal_roster.Component.linear_ops),
                    rows.linear,
                    mask,
                );
                try self.merkle_rows.relation.appendPreparedTupleContributions(
                    ledger,
                    @intFromEnum(universal_roster.Component.merkle_path),
                    rows.merkle_path,
                    mask,
                );
            }
            return result;
        }
    };
}
