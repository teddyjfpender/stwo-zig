const std = @import("std");
const stwo_core = @import("stwo_core");
const subject = @import("lookup_batch_execution.zig");
const planner = @import("lookup_batch_planner.zig");
const row_window = @import("row_window.zig");
const infra = @import("../../infra_trace.zig");
const production_entry = @import("../lookups/entry.zig");
const opcode_component = @import("../lookups/opcode_component.zig");
const opcode_interaction = @import("../lookups/opcode_interaction.zig");
const opcode_entries = @import("../lookups/opcode_entries.zig");
const relations_mod = @import("../relation_challenges.zig");
const trace = @import("../../runner/trace.zig");

const m31 = stwo_core.fields.m31;
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

test "lookup batch execution: selected native layouts preserve every row sum" {
    const relations = relations_mod.Relations.dummy();
    var state: u64 = 0xa014_5eed_cafe_beef;
    var current_batches: usize = 0;
    var selected_batches: usize = 0;

    for (0..trace.N_FAMILIES) |family_index| {
        const family: trace.OpcodeFamily = @enumFromInt(family_index);
        var plan = try subject.FamilyPlan.initNativeV1(
            std.testing.allocator,
            family,
        );
        defer plan.deinit();
        try plan.validate();
        current_batches += opcode_entries.batchCount(family);
        selected_batches += plan.batchCount();

        for (0..64) |_| {
            var columns: [trace.MAX_FAMILY_COLUMNS]QM31 = undefined;
            for (columns[0..trace.nColumnsForFamily(family)]) |*column| {
                column.* = randomQm31(&state);
            }
            const list = try opcode_entries.fromMain(
                family,
                columns[0..trace.nColumnsForFamily(family)],
            );

            var singleton_total = QM31.zero();
            for (list.entries[0..list.len]) |entry| {
                singleton_total = singleton_total.add(entry.numerator.mul(
                    try (try entry.denominator(&relations)).inv(),
                ));
            }

            var selected_total = QM31.zero();
            for (0..plan.batchCount()) |batch| {
                selected_total = selected_total.add(try subject.pairTerm(
                    try plan.rowPair(&list, batch, &relations),
                ));
            }
            try std.testing.expect(singleton_total.eql(selected_total));
        }
    }
    try std.testing.expectEqual(@as(usize, 155), current_batches);
    try std.testing.expectEqual(@as(usize, 137), selected_batches);
}

test "lookup batch execution: selected cumulative traces preserve row totals" {
    const log_size: u32 = 5;
    const row_count: usize = @as(usize, 1) << @intCast(log_size);
    const relations = relations_mod.Relations.dummy();
    var state: u64 = 0xc011_1de5_a014_0001;

    for (0..trace.N_FAMILIES) |family_index| {
        const family: trace.OpcodeFamily = @enumFromInt(family_index);
        var plan = try subject.FamilyPlan.initNativeV1(
            std.testing.allocator,
            family,
        );
        defer plan.deinit();

        var storage: [trace.MAX_FAMILY_COLUMNS][row_count]M31 = undefined;
        var columns: [trace.MAX_FAMILY_COLUMNS][]const M31 = undefined;
        const active_columns = trace.nColumnsForFamily(family);
        for (storage[0..active_columns], columns[0..active_columns]) |
            *column_storage,
            *column,
        | {
            for (column_storage) |*value| {
                state = state *% 6_364_136_223_846_793_005 +%
                    1_442_695_040_888_963_407;
                value.* = M31.fromU64(state >> 32);
            }
            column.* = column_storage;
        }

        var current = try opcode_interaction.generate(
            std.testing.allocator,
            family,
            columns[0..active_columns],
            log_size,
            &relations,
        );
        defer current.deinit(std.testing.allocator);
        var selected = try opcode_interaction.generateSelected(
            std.testing.allocator,
            &plan,
            columns[0..active_columns],
            log_size,
            &relations,
        );
        defer selected.deinit(std.testing.allocator);

        try std.testing.expect(current.total().eql(selected.total()));
        for (0..row_count) |committed_row| {
            try std.testing.expect(cumulativeTotalAt(
                &current,
                committed_row,
            ).eql(cumulativeTotalAt(&selected, committed_row)));
        }
    }
}

test "lookup batch execution: selected component accepts its trace and rejects mutation" {
    const log_size: u32 = 5;
    const row_count: usize = @as(usize, 1) << @intCast(log_size);
    const relations = relations_mod.Relations.dummy();
    const families = [_]trace.OpcodeFamily{ .mul, .mulh, .div };
    var state: u64 = 0xa014_c0de_0000_0001;

    for (families) |family| {
        var plan = try subject.FamilyPlan.initNativeV1(
            std.testing.allocator,
            family,
        );
        defer plan.deinit();
        var storage: [trace.MAX_FAMILY_COLUMNS][row_count]M31 = undefined;
        var columns: [trace.MAX_FAMILY_COLUMNS][]const M31 = undefined;
        const active_columns = trace.nColumnsForFamily(family);
        for (storage[0..active_columns], columns[0..active_columns]) |
            *column_storage,
            *column,
        | {
            for (column_storage) |*value| {
                state = state *% 6_364_136_223_846_793_005 +%
                    1_442_695_040_888_963_407;
                value.* = M31.fromU64(state >> 32);
            }
            column.* = column_storage;
        }
        var interaction = try opcode_interaction.generateSelected(
            std.testing.allocator,
            &plan,
            columns[0..active_columns],
            log_size,
            &relations,
        );
        defer interaction.deinit(std.testing.allocator);
        const component = try opcode_component.OpcodeLookupComponent.initSelectedVerifier(
            &plan,
            log_size,
            0,
            0,
            0,
            &relations,
            interaction.claims[0..interaction.n_batches],
        );
        try std.testing.expectEqual(plan.batchCount(), component.nConstraints());
        try std.testing.expectEqual(
            plan.selection.plan_digest,
            component.selected_plan_digest,
        );
        try component.mask_binding.validate();
        try std.testing.expectEqual(
            row_window.ComponentMaskBinding.Mode.compiler_selected,
            component.mask_binding.mode,
        );
        try std.testing.expectEqual(
            plan.selection.plan_digest,
            component.mask_binding.geometry_source_digest,
        );
        try std.testing.expectEqual(
            interaction.nColumns(),
            component.interactionColumnCount(),
        );
        try std.testing.expect(
            component.asProverComponent().backend_composition_capability == null,
        );
        var bounds = try component.traceLogDegreeBounds(std.testing.allocator);
        defer bounds.deinitDeep(std.testing.allocator);
        try std.testing.expectEqual(
            interaction.nColumns(),
            bounds.items[2].len,
        );
        try std.testing.expectEqual(@as(usize, 0), bounds.items[1].len);

        const placement = try infra.BitReversalTable.init(
            std.testing.allocator,
            log_size,
        );
        defer placement.deinit(std.testing.allocator);
        for (0..row_count) |logical_row| {
            const committed_row = placement.map(logical_row);
            const previous_row = placement.map(
                if (logical_row == 0) row_count - 1 else logical_row - 1,
            );
            var main = [_]QM31{QM31.zero()} ** trace.MAX_FAMILY_COLUMNS;
            for (columns[0..active_columns], main[0..active_columns]) |
                column,
                *value,
            | value.* = QM31.fromBase(column[committed_row]);
            var current = [_]QM31{QM31.zero()} ** production_entry.MAX_BATCHES;
            var previous = [_]QM31{QM31.zero()} ** production_entry.MAX_BATCHES;
            for (0..interaction.n_batches) |batch| {
                current[batch] = secureAt(&interaction, batch, committed_row);
                previous[batch] = secureAt(&interaction, batch, previous_row);
            }
            const evaluation = try component.evaluateRow(
                main[0..active_columns],
                current[0..interaction.n_batches],
                previous[0..interaction.n_batches],
                QM31.fromBase(if (logical_row == 0) M31.one() else M31.zero()),
            );
            try std.testing.expect(evaluation.allZero());

            if (logical_row == row_count / 2) {
                current[0] = current[0].add(QM31.one());
                const forged = try component.evaluateRow(
                    main[0..active_columns],
                    current[0..interaction.n_batches],
                    previous[0..interaction.n_batches],
                    QM31.zero(),
                );
                try std.testing.expect(!forged.allZero());
            }
        }
    }
}

test "lookup batch execution: setup is allocation-failure clean" {
    const authority = try subject.FamilyAuthority.discover(
        std.testing.allocator,
        .div,
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{authority},
    );
}

test "lookup batch execution: fixed family authority rejects every identity class" {
    const authority = try subject.FamilyAuthority.discover(
        std.testing.allocator,
        .div,
    );
    try authority.validate();

    var wrong_program = authority;
    wrong_program.program_digest[0] ^= 1;
    try std.testing.expectError(
        error.InvalidPlanFamily,
        wrong_program.validate(),
    );

    var wrong_event = authority;
    wrong_event.events[0].denominator_degree += 1;
    try std.testing.expectError(
        error.InvalidAuthorityDigest,
        wrong_event.validate(),
    );

    var wrong_order = authority;
    wrong_order.events[0].ordinal = 1;
    try std.testing.expectError(
        error.InvalidAuthorityDigest,
        wrong_order.validate(),
    );

    var wrong_count = authority;
    wrong_count.event_count -= 1;
    try std.testing.expectError(
        error.InvalidPlanFamily,
        wrong_count.validate(),
    );

    var pinned = try subject.FamilyPlan.initNativeAuthority(
        std.testing.allocator,
        authority,
    );
    defer pinned.deinit();
    pinned.expected_plan_digest_hex =
        subject.EXPECTED_NATIVE_V1_PLAN_DIGEST_HEX[0];
    try std.testing.expectError(error.InvalidPlanDigest, pinned.validate());
}

fn allocationFailureCase(
    allocator: std.mem.Allocator,
    authority: subject.FamilyAuthority,
) !void {
    var plan = try subject.FamilyPlan.initNativeAuthority(allocator, authority);
    defer plan.deinit();
}

test "lookup batch execution: selected trace generation is failure atomic" {
    const log_size: u32 = 3;
    const row_count: usize = @as(usize, 1) << @intCast(log_size);
    var plan = try subject.FamilyPlan.initNativeV1(
        std.testing.allocator,
        .mul,
    );
    defer plan.deinit();
    var storage = [_][row_count]M31{.{M31.zero()} ** row_count} **
        trace.MAX_FAMILY_COLUMNS;
    var columns: [trace.MAX_FAMILY_COLUMNS][]const M31 = undefined;
    for (
        storage[0..trace.nColumnsForFamily(.mul)],
        columns[0..trace.nColumnsForFamily(.mul)],
    ) |
        *column_storage,
        *column,
    | column.* = column_storage;
    const relations = relations_mod.Relations.dummy();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        traceAllocationFailureCase,
        .{
            &plan,
            columns[0..trace.nColumnsForFamily(.mul)],
            log_size,
            &relations,
        },
    );
}

fn traceAllocationFailureCase(
    allocator: std.mem.Allocator,
    plan: *const subject.FamilyPlan,
    columns: []const []const M31,
    log_size: u32,
    relations: *const relations_mod.Relations,
) !void {
    var result = try opcode_interaction.generateSelected(
        allocator,
        plan,
        columns,
        log_size,
        relations,
    );
    defer result.deinit(allocator);
}

test "lookup batch execution: family and batch bounds fail closed" {
    var plan = try subject.FamilyPlan.initNativeV1(
        std.testing.allocator,
        .lui,
    );
    defer plan.deinit();
    const relations = relations_mod.Relations.dummy();
    var columns = [_]QM31{QM31.zero()} ** trace.MAX_FAMILY_COLUMNS;
    var list = try opcode_entries.fromMain(
        .lui,
        columns[0..trace.nColumnsForFamily(.lui)],
    );
    try std.testing.expectError(
        error.InvalidBatchIndex,
        plan.rowPair(&list, plan.batchCount(), &relations),
    );
    list.len -= 1;
    try std.testing.expectError(
        error.InvalidEntryCount,
        plan.rowPair(&list, 0, &relations),
    );
}

test "lookup batch execution: a selected denominator collision rejects" {
    var list = production_entry.List{ .batch_size = 1 };
    const relation_values = [_]QM31{QM31.zero()} ** production_entry.MAX_ARITY;
    list.append(.{
        .domain = .range_check_20,
        .numerator = QM31.one(),
        .values = relation_values,
        .arity = 1,
    });
    var relations = relations_mod.Relations.dummy();
    relations.range_check_20 = relations_mod.RelationElements(1).init(
        QM31.zero(),
        QM31.one(),
    );
    const batch = planner.Batch{
        .first_event = 0,
        .event_count = 1,
        .terms = undefined,
    };
    const pair = try subject.rowPairFromBatch(&list, batch, &relations);
    try std.testing.expectError(error.DivisionByZero, subject.pairTerm(pair));
}

fn randomQm31(state: *u64) QM31 {
    var limbs: [4]u32 = undefined;
    for (&limbs) |*limb| {
        state.* = state.* *% 6_364_136_223_846_793_005 +%
            1_442_695_040_888_963_407;
        limb.* = @intCast((state.* >> 32) % m31.Modulus);
    }
    return QM31.fromU32Unchecked(limbs[0], limbs[1], limbs[2], limbs[3]);
}

fn cumulativeTotalAt(
    result: *const opcode_interaction.Result,
    row: usize,
) QM31 {
    var total = QM31.zero();
    for (0..result.n_batches) |batch| {
        total = total.add(QM31.fromM31(
            result.columns[4 * batch][row],
            result.columns[4 * batch + 1][row],
            result.columns[4 * batch + 2][row],
            result.columns[4 * batch + 3][row],
        ));
    }
    return total;
}

fn secureAt(
    result: *const opcode_interaction.Result,
    batch: usize,
    row: usize,
) QM31 {
    return QM31.fromM31(
        result.columns[4 * batch][row],
        result.columns[4 * batch + 1][row],
        result.columns[4 * batch + 2][row],
        result.columns[4 * batch + 3][row],
    );
}
