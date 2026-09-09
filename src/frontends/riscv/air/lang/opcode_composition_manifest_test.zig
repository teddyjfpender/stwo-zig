const std = @import("std");
const circle = @import("stwo_core").circle;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const subject = @import("opcode_composition_manifest.zig");
const compat_manifest = @import("compat_manifest.zig");
const static_registry = @import("static_profile_registry.zig");
const constraint_program = @import("../constraint_program.zig");
const component_order = @import("../component_order.zig");
const SemanticComponent = @import("../semantic_component.zig").SemanticComponent;
const opcode_component = @import("../lookups/opcode_component.zig");
const entry = @import("../lookups/entry.zig");
const opcode_entries = @import("../lookups/opcode_entries.zig");
const logup = @import("../logup.zig");
const relations_mod = @import("../relation_challenges.zig");
const statement_mod = @import("../statement.zig");
const base_component_assembly = @import("../../prover/base_component_assembly.zig");
const proof_finalize = @import("../../prover/proof_finalize.zig");
const proof_workspace = @import("../../prover/proof_workspace.zig");
const verifier = @import("../../prover/verifier.zig");
const trace = @import("../../runner/trace.zig");
const witness_layout = @import("../../witness_layout.zig");
const opcode_manifest_test_support = @import("opcode_composition_manifest_test_support.zig");

test "E-022 composition manifest has the exact 17-family compatibility geometry" {
    const expected_main = [_]usize{
        35, 35, 60, 51, 44, 37, 30, 37, 18, 29, 41, 20, 48, 39, 47, 67, 6,
    };
    const expected_direct = [_]usize{
        22, 22, 70, 67, 36, 33, 18, 33, 9, 17, 23, 10, 63, 17, 24, 79, 2,
    };
    const expected_lookups = [_]usize{
        18, 16, 20, 16, 14, 11, 9, 11, 7, 12, 18, 8, 16, 16, 22, 25, 3,
    };
    const expected_batch_sizes = [_]usize{
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2,
    };
    const expected_batches = [_]usize{
        9, 8, 10, 8, 7, 6, 5, 6, 4, 6, 9, 4, 8, 16, 22, 25, 2,
    };

    try std.testing.expectEqual(@as(usize, 17), subject.FAMILY_COUNT);
    var total_main: usize = 0;
    var total_direct: usize = 0;
    var total_lookups: usize = 0;
    var total_batches: usize = 0;
    var total_interaction: usize = 0;
    for (subject.BY_FAMILY, 0..) |item, index| {
        try std.testing.expectEqual(index, @as(usize, @intFromEnum(item.family)));
        try std.testing.expectEqual(expected_main[index], item.main_columns);
        try std.testing.expectEqual(expected_direct[index], item.direct_constraints);
        try std.testing.expectEqual(expected_lookups[index], item.lookup_events);
        try std.testing.expectEqual(expected_batch_sizes[index], item.lookup_batch_size);
        try std.testing.expectEqual(expected_batches[index], item.lookup_batches);
        try std.testing.expectEqual(4 * expected_batches[index], item.interaction_columns);
        try std.testing.expectEqual(item.lookup_batches, item.claim.detailed_claims);
        try std.testing.expectEqual(@as(usize, 1), item.claim.canonical_claim_slots);
        try std.testing.expectEqualDeep(subject.ADAPTER_ORDER, item.adapters);

        total_main += item.main_columns;
        total_direct += item.direct_constraints;
        total_lookups += item.lookup_events;
        total_batches += item.lookup_batches;
        total_interaction += item.interaction_columns;
    }
    try std.testing.expectEqual(@as(usize, 646), total_main);
    try std.testing.expectEqual(@as(usize, 545), total_direct);
    try std.testing.expectEqual(@as(usize, 243), total_lookups);
    try std.testing.expectEqual(@as(usize, 156), total_batches);
    try std.testing.expectEqual(@as(usize, 620), total_interaction);
    try std.testing.expectEqual(@as(usize, 67), subject.MAX_MAIN_COLUMNS);
    try std.testing.expectEqual(@as(usize, 79), subject.MAX_DIRECT_CONSTRAINTS);
    try std.testing.expectEqual(@as(usize, 25), subject.MAX_LOOKUP_EVENTS);
    try std.testing.expectEqual(@as(usize, 25), subject.MAX_LOOKUP_BATCHES);
    try std.testing.expectEqual(@as(usize, 100), subject.MAX_INTERACTION_COLUMNS);
}

test "E-022 composition manifest derives exact claim and adapter protocol order" {
    const expected = [_]subject.Family{
        .auipc,
        .base_alu_imm,
        .base_alu_reg,
        .branch_eq,
        .branch_lt,
        .div,
        .jal,
        .jalr,
        .load_store,
        .lt_imm,
        .lt_reg,
        .lui,
        .mul,
        .mulh,
        .shifts_imm,
        .shifts_reg,
        .fence,
    };
    try std.testing.expectEqualDeep(expected, subject.TRANSCRIPT_ORDER);
    for (expected, 0..) |family, index| {
        try std.testing.expectEqual(family, subject.familyAtCompositionIndex(index).?);
        try std.testing.expectEqual(index, subject.compositionIndex(family));
        try std.testing.expectEqual(
            component_order.transcriptComponentForOpcodeFamily(family),
            subject.transcriptComponent(family),
        );
        try std.testing.expectEqual(index, component_order.opcodeFamilyIndex(family));
    }
    try std.testing.expect(subject.familyAtCompositionIndex(expected.len) == null);
    try std.testing.expectEqualDeep(
        [_]subject.AdapterKind{ .semantic, .lookup },
        subject.ADAPTER_ORDER,
    );
}

test "E-022 composition manifest agrees with every live and compiled compatibility surface" {
    inline for (0..subject.FAMILY_COUNT) |index| {
        const family: subject.Family = @enumFromInt(index);
        const Authority = subject.authorityFor(family);
        const item = subject.descriptor(family);
        const profile = static_registry.DESCRIPTORS[index];

        try std.testing.expectEqual(Authority.MAIN_COLUMN_COUNT, item.main_columns);
        try std.testing.expectEqual(Authority.DIRECT_CONSTRAINT_COUNT, item.direct_constraints);
        try std.testing.expectEqual(Authority.LOOKUP_COUNT, item.lookup_events);
        try std.testing.expectEqual(Authority.LOOKUP_BATCH_SIZE, item.lookup_batch_size);
        try std.testing.expectEqualDeep(Authority.AUTHORITY_BINDING_DIGEST, item.authority_digest);

        try std.testing.expectEqual(@as(usize, trace.nColumnsForFamily(family)), item.main_columns);
        try std.testing.expectEqual(witness_layout.columnNames(family).len, item.main_columns);
        try std.testing.expectEqual(constraint_program.mainColumnCount(family), item.main_columns);
        try std.testing.expectEqual(constraint_program.constraintCount(family), item.direct_constraints);
        try std.testing.expectEqual(opcode_entries.entryCount(family), item.lookup_events);
        try std.testing.expectEqual(opcode_entries.batchSize(family), item.lookup_batch_size);
        try std.testing.expectEqual(opcode_entries.batchCount(family), item.lookup_batches);
        try std.testing.expectEqual(
            opcode_entries.interactionColumnCount(family),
            item.interaction_columns,
        );

        try std.testing.expectEqual(@as(usize, profile.physical_main_columns), item.main_columns);
        try std.testing.expectEqual(
            @as(usize, profile.authored_constraint_roots),
            item.direct_constraints,
        );
        try std.testing.expectEqual(
            @as(usize, profile.authored_lookup_events),
            item.lookup_events,
        );
        try std.testing.expectEqual(
            @as(usize, profile.audited_lookup_batch_size),
            item.lookup_batch_size,
        );

        try expectCanonicalMasks(item);
    }
}

test "E-022 generated compat-v1 manifests agree with the composition authority 17 of 17" {
    inline for (0..subject.FAMILY_COUNT) |index| {
        const family: subject.Family = @enumFromInt(index);
        const item = subject.descriptor(family);
        var generated = try compat_manifest.generate(std.testing.allocator, family);
        defer generated.deinit();
        try std.testing.expectEqual(family, generated.summary.family);
        try std.testing.expectEqual(@as(u32, @intCast(item.main_columns)), generated.summary.main_columns);
        try std.testing.expectEqual(
            @as(u32, @intCast(item.direct_constraints)),
            generated.summary.direct_constraints,
        );
        try std.testing.expectEqual(
            @as(u32, @intCast(item.lookup_events)),
            generated.summary.lookup_events,
        );
        try std.testing.expectEqual(
            @as(u32, @intCast(item.lookup_batches)),
            generated.summary.interaction_batches,
        );
    }
}

test "E-022 placement cursor preserves legacy offsets and fails atomically" {
    var cursor = subject.PlacementCursor{};

    const auipc = try cursor.append(.auipc, 29);
    try expectPlacement(auipc, .auipc, 0, 0, 1, 0, 1, 0, 0, 29, 24);

    const imm0 = try cursor.append(.base_alu_imm, 35);
    try expectPlacement(imm0, .base_alu_imm, 1, 2, 3, 2, 3, 29, 24, 35, 32);

    const imm1 = try cursor.append(.base_alu_imm, 35);
    try expectPlacement(imm1, .base_alu_imm, 2, 4, 5, 4, 5, 64, 56, 35, 32);

    const fence = try cursor.append(.fence, 6);
    try expectPlacement(fence, .fence, 3, 6, 7, 6, 7, 99, 88, 6, 8);
    try std.testing.expectEqualDeep(subject.PlacementCursor{
        .component_count = 4,
        .adapter_count = 8,
        .preprocessed_columns = 8,
        .main_columns = 105,
        .interaction_columns = 96,
    }, cursor);

    const before_bad_width = cursor;
    try std.testing.expectError(
        error.MainColumnCountMismatch,
        cursor.append(.div, 66),
    );
    try std.testing.expectEqualDeep(before_bad_width, cursor);

    var component_overflow = subject.PlacementCursor{
        .component_count = std.math.maxInt(usize),
    };
    const before_component_overflow = component_overflow;
    try std.testing.expectError(
        error.ComponentIndexOverflow,
        component_overflow.append(.fence, 6),
    );
    try std.testing.expectEqualDeep(before_component_overflow, component_overflow);

    var adapter_overflow = subject.PlacementCursor{
        .adapter_count = std.math.maxInt(usize),
    };
    const before_adapter_overflow = adapter_overflow;
    try std.testing.expectError(
        error.AdapterIndexOverflow,
        adapter_overflow.append(.fence, 6),
    );
    try std.testing.expectEqualDeep(before_adapter_overflow, adapter_overflow);

    var column_overflow = subject.PlacementCursor{
        .main_columns = std.math.maxInt(usize),
    };
    const before_column_overflow = column_overflow;
    try std.testing.expectError(
        error.ColumnIndexOverflow,
        column_overflow.append(.fence, 6),
    );
    try std.testing.expectEqualDeep(before_column_overflow, column_overflow);
}

test "E-022 infrastructure cursor owns fixed geometry and O(1) canonical placement" {
    const kinds = base_component_assembly.CANONICAL_INFRASTRUCTURE_ORDER;
    const expected_adapters = [_]base_component_assembly.InfrastructureAdapterKind{
        .trace,
        .trace,
        .hash,
        .hash,
        .clock_update,
        .lookup_table,
        .lookup_table,
        .lookup_table,
        .lookup_table,
        .lookup_table,
        .lookup_table,
    };
    const expected_preprocessed = [_]usize{ 2, 2, 2, 2, 2, 5, 2, 3, 4, 3, 3 };
    const expected_main = [_]usize{ 10, 8, 10, 445, 10, 1, 1, 1, 1, 1, 1 };
    const expected_interaction = [_]usize{ 16, 16, 12, 8, 8, 4, 4, 4, 4, 4, 4 };
    const opcode_final = subject.PlacementCursor{
        .component_count = 17,
        .adapter_count = 34,
        .preprocessed_columns = 34,
        .main_columns = 646,
        .interaction_columns = 620,
    };
    var cursor = base_component_assembly.InfrastructureCursor.init(opcode_final);

    for (kinds, 0..) |kind, index| {
        const item = base_component_assembly.infrastructureDescriptor(kind);
        try std.testing.expectEqual(kind, item.kind);
        try std.testing.expectEqual(expected_adapters[index], item.adapter_kind);
        try std.testing.expectEqual(@as(u8, @intCast(index)), item.order_rank);
        try std.testing.expectEqual(index == 1, item.repeatable);
        try std.testing.expectEqual(expected_preprocessed[index], item.preprocessed_columns);
        try std.testing.expectEqual(expected_main[index], item.main_columns);
        try std.testing.expectEqual(expected_interaction[index], item.interaction_columns);
        try std.testing.expectEqual(
            @as(usize, statement_mod.nPreprocessedColumnsForInfra(kind)),
            item.preprocessed_columns,
        );
        try std.testing.expectEqual(
            @as(usize, statement_mod.nInteractionColsForInfra(kind)),
            item.interaction_columns,
        );
        try std.testing.expectEqual(statement_mod.tableKind(kind), item.table_kind);

        const before = cursor;
        const placement = try cursor.append(kind, expected_main[index]);
        try std.testing.expectEqual(kind, placement.kind);
        try std.testing.expectEqual(expected_adapters[index], placement.adapter_kind);
        try std.testing.expectEqual(index, placement.infrastructure_index);
        try std.testing.expectEqual(34 + index, placement.adapter_index);
        try std.testing.expectEqual(before.preprocessed_columns, placement.preprocessed_column_offset);
        try std.testing.expectEqual(before.main_columns, placement.main_column_offset);
        try std.testing.expectEqual(before.interaction_columns, placement.interaction_column_offset);
    }
    try std.testing.expectEqualDeep(base_component_assembly.InfrastructureCursor{
        .infrastructure_count = 11,
        .adapter_count = 45,
        .preprocessed_columns = 64,
        .main_columns = 1133,
        .interaction_columns = 704,
        .hash_count = 2,
        .seen_singletons = 2045,
        .last_order_rank = 10,
    }, cursor);

    const before_bad_width = cursor;
    try std.testing.expectError(
        error.MainColumnCountMismatch,
        cursor.append(.range_check_m31, 2),
    );
    try std.testing.expectEqualDeep(before_bad_width, cursor);

    var order_cursor = base_component_assembly.InfrastructureCursor.init(opcode_final);
    _ = try order_cursor.append(.program, 10);
    _ = try order_cursor.append(.clock_update, 10);
    const before_bad_order = order_cursor;
    try std.testing.expectError(
        error.InfrastructureOrderMismatch,
        order_cursor.append(.merkle, 10),
    );
    try std.testing.expectEqualDeep(before_bad_order, order_cursor);
}

test "E-022 prover and verifier materialize the same 17-family placement plan" {
    const allocator = std.testing.allocator;
    const prover_workspace = try proof_workspace.ProofWorkspace.create(allocator);
    defer prover_workspace.destroy(allocator);
    const verifier_workspace = try proof_workspace.VerificationWorkspace.create(allocator);
    defer verifier_workspace.destroy(allocator);
    const claim = try allocator.create(statement_mod.RiscVInteractionClaim);
    defer allocator.destroy(claim);

    prover_workspace.statement.n_components = @intCast(subject.FAMILY_COUNT);
    for (subject.TRANSCRIPT_ORDER, 0..) |family, index| {
        prover_workspace.statement.component_descs[index] = .{
            .family = family,
            .log_size = @intCast(4 + index),
            .n_rows = 1,
            .n_columns = @intCast(subject.mainColumnCount(family)),
        };
    }
    populateCanonicalInfrastructure(&prover_workspace.statement);
    claim.initZeroInto();
    claim.n_components = @intCast(subject.FAMILY_COUNT);
    claim.n_infra = prover_workspace.statement.n_infra;
    const relations = relations_mod.Relations.dummy();

    const n_main: usize = @intCast(prover_workspace.statement.nMainColumns());
    const n_interaction: usize = @intCast(
        prover_workspace.statement.nInteractionColumns(),
    );
    try std.testing.expectEqual(@as(usize, 1133), n_main);
    try std.testing.expectEqual(@as(usize, 704), n_interaction);

    const prover_components = try proof_finalize.assemble(
        prover_workspace,
        &relations,
        claim,
        n_main,
        n_interaction,
    );
    const verifier_components = try verifier.assembleComponents(
        verifier_workspace,
        &prover_workspace.statement,
        claim,
        &relations,
        n_main,
        n_interaction,
    );
    try std.testing.expectEqual(@as(usize, 45), prover_components.len);
    try std.testing.expectEqual(prover_components.len, verifier_components.len);
    try std.testing.expectEqual(@as(usize, 2), prover_workspace.components.n_hash);
    try std.testing.expectEqual(@as(usize, 2), verifier_workspace.components.n_hash);

    var prover_cursor = subject.PlacementCursor{};
    var verifier_cursor = subject.PlacementCursor{};
    for (subject.TRANSCRIPT_ORDER, 0..) |family, index| {
        const declared_width: usize = @intCast(
            prover_workspace.statement.component_descs[index].n_columns,
        );
        const prover_placement = try prover_cursor.append(family, declared_width);
        const verifier_placement = try verifier_cursor.append(family, declared_width);
        try std.testing.expectEqualDeep(prover_placement, verifier_placement);

        const prover_semantic = &prover_workspace.components.semantic[index];
        const verifier_semantic = &verifier_workspace.components.semantic[index];
        try std.testing.expectEqual(family, prover_semantic.family);
        try std.testing.expectEqual(family, verifier_semantic.family);
        try std.testing.expectEqual(
            prover_placement.is_active_column,
            prover_semantic.is_active_col_idx,
        );
        try std.testing.expectEqual(
            prover_semantic.is_active_col_idx,
            verifier_semantic.is_active_col_idx,
        );
        try std.testing.expectEqual(
            prover_placement.main_column_offset,
            prover_semantic.main_col_offset,
        );
        try std.testing.expectEqual(
            prover_semantic.main_col_offset,
            verifier_semantic.main_col_offset,
        );

        const prover_lookup = &prover_workspace.components.opcode_lookup[index];
        const verifier_lookup = &verifier_workspace.components.opcode_lookup[index];
        try std.testing.expectEqual(family, prover_lookup.family);
        try std.testing.expectEqual(family, verifier_lookup.family);
        try std.testing.expectEqual(
            prover_placement.is_first_column,
            prover_lookup.is_first_col_idx,
        );
        try std.testing.expectEqual(
            prover_lookup.is_first_col_idx,
            verifier_lookup.is_first_col_idx,
        );
        try std.testing.expectEqual(
            prover_placement.main_column_offset,
            prover_lookup.main_col_offset,
        );
        try std.testing.expectEqual(
            prover_lookup.main_col_offset,
            verifier_lookup.main_col_offset,
        );
        try std.testing.expectEqual(
            prover_placement.interaction_column_offset,
            prover_lookup.interaction_col_offset,
        );
        try std.testing.expectEqual(
            prover_lookup.interaction_col_offset,
            verifier_lookup.interaction_col_offset,
        );

        try std.testing.expectEqual(
            @intFromPtr(prover_semantic),
            @intFromPtr(prover_components[prover_placement.semantic_adapter_index].ctx),
        );
        try std.testing.expectEqual(
            @intFromPtr(prover_lookup),
            @intFromPtr(prover_components[prover_placement.lookup_adapter_index].ctx),
        );
        try std.testing.expectEqual(
            @intFromPtr(verifier_semantic),
            @intFromPtr(verifier_components[verifier_placement.semantic_adapter_index].ctx),
        );
        try std.testing.expectEqual(
            @intFromPtr(verifier_lookup),
            @intFromPtr(verifier_components[verifier_placement.lookup_adapter_index].ctx),
        );
    }
    const expected_final = subject.PlacementCursor{
        .component_count = 17,
        .adapter_count = 34,
        .preprocessed_columns = 34,
        .main_columns = 646,
        .interaction_columns = 620,
    };
    try std.testing.expectEqualDeep(expected_final, prover_cursor);
    try std.testing.expectEqualDeep(expected_final, verifier_cursor);

    var infrastructure_cursor =
        base_component_assembly.InfrastructureCursor.init(prover_cursor);
    for (0..prover_workspace.statement.n_infra) |index| {
        const desc = prover_workspace.statement.infra_descs[index];
        const placement = try infrastructure_cursor.append(
            desc.kind,
            @intCast(desc.n_columns),
        );
        try std.testing.expectEqual(
            prover_workspace.statement.preprocessedOffsetForInfra(index),
            placement.preprocessed_column_offset,
        );
        switch (placement.adapter_kind) {
            .trace => {
                const prover_value = &prover_workspace.components.infra[index];
                const verifier_value = &verifier_workspace.components.infra[index];
                try expectInfrastructureOffsets(prover_value, placement);
                try expectInfrastructureOffsets(verifier_value, placement);
                try expectHandleContext(
                    prover_components[placement.adapter_index].ctx,
                    prover_value,
                );
                try expectHandleContext(
                    verifier_components[placement.adapter_index].ctx,
                    verifier_value,
                );
            },
            .hash => {
                const hash_index = placement.hash_index.?;
                const prover_value = &prover_workspace.components.hash[hash_index];
                const verifier_value = &verifier_workspace.components.hash[hash_index];
                try expectInfrastructureOffsets(prover_value, placement);
                try expectInfrastructureOffsets(verifier_value, placement);
                try expectHandleContext(
                    prover_components[placement.adapter_index].ctx,
                    prover_value,
                );
                try expectHandleContext(
                    verifier_components[placement.adapter_index].ctx,
                    verifier_value,
                );
            },
            .clock_update => {
                const prover_value = &prover_workspace.components.clock;
                const verifier_value = &verifier_workspace.components.clock;
                try expectInfrastructureOffsets(prover_value, placement);
                try expectInfrastructureOffsets(verifier_value, placement);
                try expectHandleContext(
                    prover_components[placement.adapter_index].ctx,
                    prover_value,
                );
                try expectHandleContext(
                    verifier_components[placement.adapter_index].ctx,
                    verifier_value,
                );
            },
            .lookup_table => {
                const table_index = component_order.lookupTableIndex(
                    placement.table_kind.?,
                );
                const prover_value = &prover_workspace.components.table[table_index];
                const verifier_value = &verifier_workspace.components.table[table_index];
                try expectInfrastructureOffsets(prover_value, placement);
                try expectInfrastructureOffsets(verifier_value, placement);
                try expectHandleContext(
                    prover_components[placement.adapter_index].ctx,
                    prover_value,
                );
                try expectHandleContext(
                    verifier_components[placement.adapter_index].ctx,
                    verifier_value,
                );
            },
        }
    }
    try std.testing.expectEqual(@as(usize, 64), infrastructure_cursor.preprocessed_columns);
    try std.testing.expectEqual(n_main, infrastructure_cursor.main_columns);
    try std.testing.expectEqual(n_interaction, infrastructure_cursor.interaction_columns);
}

test "E-022 shared assembly fails atomically on infrastructure width and order drift" {
    const allocator = std.testing.allocator;
    const prover_workspace = try proof_workspace.ProofWorkspace.create(allocator);
    defer prover_workspace.destroy(allocator);
    const verifier_workspace = try proof_workspace.VerificationWorkspace.create(allocator);
    defer verifier_workspace.destroy(allocator);
    const claim = try allocator.create(statement_mod.RiscVInteractionClaim);
    defer allocator.destroy(claim);

    prover_workspace.statement.n_components = 1;
    prover_workspace.statement.component_descs[0] = .{
        .family = .fence,
        .log_size = 4,
        .n_rows = 1,
        .n_columns = @intCast(subject.mainColumnCount(.fence)),
    };
    populateCanonicalInfrastructure(&prover_workspace.statement);
    claim.initZeroInto();
    claim.n_components = 1;
    claim.n_infra = prover_workspace.statement.n_infra;
    const relations = relations_mod.Relations.dummy();

    const merkle = prover_workspace.statement.infra_descs[2];
    prover_workspace.statement.infra_descs[2] =
        prover_workspace.statement.infra_descs[3];
    prover_workspace.statement.infra_descs[3] = merkle;
    try expectAssemblyRejectsAtomically(
        prover_workspace,
        verifier_workspace,
        claim,
        &relations,
    );

    const poseidon = prover_workspace.statement.infra_descs[2];
    prover_workspace.statement.infra_descs[2] =
        prover_workspace.statement.infra_descs[3];
    prover_workspace.statement.infra_descs[3] = poseidon;
    prover_workspace.statement.infra_descs[0].n_columns += 1;
    try expectAssemblyRejectsAtomically(
        prover_workspace,
        verifier_workspace,
        claim,
        &relations,
    );

    prover_workspace.statement.infra_descs[0].n_columns -= 1;
    prover_workspace.statement.n_components = 2;
    prover_workspace.statement.component_descs[0].family = .fence;
    prover_workspace.statement.component_descs[0].n_columns =
        @intCast(subject.mainColumnCount(.fence));
    prover_workspace.statement.component_descs[1] = .{
        .family = .auipc,
        .log_size = 4,
        .n_rows = 1,
        .n_columns = @intCast(subject.mainColumnCount(.auipc)),
    };
    claim.n_components = 2;
    try expectAssemblyRejectsAtomically(
        prover_workspace,
        verifier_workspace,
        claim,
        &relations,
    );
}

test "E-022 prover and verifier delegate one shared base assembly authority" {
    const prover_source = @embedFile("../../prover/proof_finalize.zig");
    const verifier_source = @embedFile("../../prover/verifier.zig");
    const shared_source = @embedFile("../../prover/base_component_assembly.zig");

    inline for (.{
        .{ prover_source, "        .prover," },
        .{ verifier_source, "        .verifier," },
    }) |case| {
        try expectContains(
            case[0],
            "const base_component_assembly = @import(\"base_component_assembly.zig\");",
        );
        try expectContains(case[0], "try base_component_assembly.assembleInto(");
        try expectContains(case[0], case[1]);
        try expectAbsent(case[0], "composition_manifest.PlacementCursor");
        try expectAbsent(case[0], "for (0..statement.n_components)");
        try expectAbsent(case[0], "for (0..statement.n_infra)");
        try expectAbsent(case[0], "preprocessedOffsetForInfra");
        try expectAbsent(case[0], "main_offset += desc.n_columns");
    }

    try expectContains(
        shared_source,
        "var opcode_cursor = composition_manifest.PlacementCursor{};",
    );
    try expectContains(
        shared_source,
        "var infrastructure_cursor = InfrastructureCursor.init(opcode_cursor);",
    );
    try expectContains(shared_source, "if (comptime direction == .prover)");
    try expectContains(shared_source, "components.active().len != placement.adapter_index");
    try expectContains(shared_source, "components.n_handles = 0;");
    try expectContains(shared_source, "components.n_hash = 0;");
    try expectAbsent(shared_source, "preprocessedOffsetForInfra");
    try expectAbsent(shared_source, "main_offset += desc.n_columns");
}

test "E-022 trace and witness geometry consumers retired their duplicate registries" {
    const trace_source = @embedFile("../../runner/trace.zig");
    const witness_source = @embedFile("../../witness_layout.zig");

    try expectContains(
        trace_source,
        "const composition_manifest = @import(\"../air/lang/opcode_composition_manifest.zig\");",
    );
    try expectContains(
        trace_source,
        "pub const MAX_FAMILY_COLUMNS: usize = composition_manifest.MAX_MAIN_COLUMNS;",
    );
    try expectContains(
        trace_source,
        "return @intCast(composition_manifest.mainColumnCount(family));",
    );
    try expectAbsent(trace_source, "@typeInfo(layouts.");
    try expectAbsent(trace_source, "layouts.BaseAluRegColumns");

    try expectContains(
        witness_source,
        "pub const canonical_families = composition_manifest.TRANSCRIPT_ORDER;",
    );
    try std.testing.expectEqualDeep(subject.TRANSCRIPT_ORDER, witness_layout.canonical_families);
    const expected_digest = "2163899f40e1bffb7f5d355b600ee4e013e7e4f63c205cedd01f6feb9d88f4f5";
    const actual_digest = std.fmt.bytesToHex(witness_layout.digest(), .lower);
    try std.testing.expectEqualStrings(expected_digest, &actual_digest);
    inline for (0..subject.FAMILY_COUNT) |index| {
        const family: subject.Family = @enumFromInt(index);
        try std.testing.expectEqual(
            subject.mainColumnCount(family),
            witness_layout.columnNames(family).len,
        );
    }
}

test "E-022 constraint program retired all four duplicated geometry switches" {
    const source = @embedFile("../constraint_program.zig");
    try expectContains(
        source,
        "const composition_manifest = @import(\"lang/opcode_composition_manifest.zig\");",
    );
    try expectContains(source, "return composition_manifest.lookupEventCount(family);");
    try expectContains(source, "return composition_manifest.lookupBatchSize(family);");
    try expectContains(source, "return composition_manifest.mainColumnCount(family);");
    try expectContains(source, "return composition_manifest.directConstraintCount(family);");
    try expectAbsent(
        source,
        ".base_alu_reg => typed_base_alu_reg_authority.LOOKUP_COUNT",
    );
    try expectAbsent(
        source,
        ".base_alu_reg => typed_base_alu_reg_authority.MAIN_COLUMN_COUNT",
    );
    try expectAbsent(
        source,
        ".base_alu_reg => typed_base_alu_reg_authority.DIRECT_CONSTRAINT_COUNT",
    );
}

test "E-022 opcode claim order has one manifest authority across production consumers" {
    const order_source = @embedFile("../component_order.zig");
    const statement_source = @embedFile("../statement.zig");
    const export_source = @embedFile("../relation_export.zig");

    try expectContains(
        order_source,
        "const composition_manifest = @import(\"lang/opcode_composition_manifest.zig\");",
    );
    try expectContains(
        order_source,
        "composition_manifest.TRANSCRIPT_ORDER;",
    );
    try expectContains(
        order_source,
        "return composition_manifest.compositionIndex(family);",
    );
    try expectContains(
        order_source,
        "return composition_manifest.transcriptComponent(family);",
    );

    try expectContains(
        statement_source,
        "composition_manifest.transcriptComponent(desc.family)",
    );
    try expectContains(
        export_source,
        "const component = composition_manifest.transcriptComponent(family);",
    );
    try expectAbsent(statement_source, "fn componentForFamily(");
    try expectAbsent(export_source, "fn componentForFamily(");
}

test {
    _ = @import("opcode_composition_manifest_extended_test.zig");
}
const expectCanonicalMasks = opcode_manifest_test_support.expectCanonicalMasks;
const expectBoundGeometry = opcode_manifest_test_support.expectBoundGeometry;
const expectMaskGeometry = opcode_manifest_test_support.expectMaskGeometry;
const expectPointEqual = opcode_manifest_test_support.expectPointEqual;
const expectPlacement = opcode_manifest_test_support.expectPlacement;
const populateCanonicalInfrastructure = opcode_manifest_test_support.populateCanonicalInfrastructure;
const expectInfrastructureOffsets = opcode_manifest_test_support.expectInfrastructureOffsets;
const expectHandleContext = opcode_manifest_test_support.expectHandleContext;
const expectAssemblyRejectsAtomically = opcode_manifest_test_support.expectAssemblyRejectsAtomically;
const containsPointer = opcode_manifest_test_support.containsPointer;
const expectContains = opcode_manifest_test_support.expectContains;
const expectAbsent = opcode_manifest_test_support.expectAbsent;
