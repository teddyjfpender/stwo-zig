const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const constraint_program = @import("../constraint_program.zig");
const model = @import("../extract/model.zig");
const production_entry = @import("../lookups/entry.zig");
const symbolic = @import("../extract/symbolic.zig");
const trace = @import("../../runner/trace.zig");
const relation = @import("relation.zig");
const shadow_program = @import("shadow_program.zig");
const source = @import("source.zig");
const types = @import("types.zig");

const Builder = constraint_program.Builder(symbolic.Scalar);
const differential_seed: u64 = 0x5052_4f47_5241_4d32;

test "ordered shadow program exactly imports every production family" {
    var prng = std.Random.DefaultPrng.init(differential_seed);
    const random = prng.random();
    var column_values: [trace.MAX_FAMILY_COLUMNS + 1]m31.M31 = undefined;

    for (0..trace.N_FAMILIES) |family_index| {
        const family: trace.OpcodeFamily = @enumFromInt(family_index);
        var fixture = try SourceFixture.init(std.testing.allocator, family);
        defer fixture.deinit();
        var imported = try shadow_program.importBuilt(
            std.testing.allocator,
            family,
            &fixture.arena,
            fixture.main_column_count,
            fixture.selector,
            &fixture.program,
            source.SourceSpan.generated(),
        );
        defer imported.deinit();
        try imported.validate();

        try std.testing.expectEqual(fixture.main_column_count, imported.mainColumns().len);
        try std.testing.expectEqual(
            imported.imported.valueForSourceNode(fixture.selector.id).?,
            imported.selector,
        );
        try std.testing.expectEqual(fixture.selector.id, imported.source_selector);
        try std.testing.expectEqual(
            imported.imported.valueForSourceNode(fixture.program.active_row.id).?,
            imported.active_row,
        );
        try std.testing.expectEqual(
            fixture.program.active_row.id,
            imported.source_active_row,
        );
        for (imported.mainColumns(), fixture.column_ids[0..fixture.main_column_count]) |column, source_id|
            try std.testing.expectEqual(
                imported.imported.valueForSourceNode(source_id).?,
                column,
            );

        try std.testing.expectEqual(
            fixture.program.direct_constraints.len,
            imported.direct_constraints.len,
        );
        for (
            fixture.program.direct_constraints.values[0..fixture.program.direct_constraints.len],
            imported.direct_constraints,
            imported.direct_source_roots,
        ) |source_root, constraint_id, source_id| {
            const constraint = imported.imported.arena.constraint(constraint_id).?;
            try std.testing.expectEqual(
                imported.imported.valueForSourceNode(source_root.id).?,
                constraint.root,
            );
            try std.testing.expectEqual(source_root.id, source_id);
        }

        try std.testing.expectEqual(
            fixture.program.lookup_entries.len,
            imported.lookups.len,
        );
        try std.testing.expectEqual(
            fixture.program.lookup_entries.batch_size,
            imported.batch_size,
        );
        try std.testing.expectEqual(
            fixture.program.lookup_entries.batchCount(),
            imported.batchCount(),
        );
        for (
            fixture.program.lookup_entries.entries[0..fixture.program.lookup_entries.len],
            imported.lookups,
            0..,
        ) |source_lookup, lookup, lookup_index| {
            const schema = relation.getById(lookup.schema).?;
            try std.testing.expectEqual(
                @intFromEnum(source_lookup.domain),
                @intFromEnum(schema.domain),
            );
            try std.testing.expectEqual(expectedRole(source_lookup.role), lookup.role);
            try std.testing.expectEqual(source_lookup.access_ordinal, lookup.access_ordinal);
            try std.testing.expectEqual(
                imported.imported.valueForSourceNode(source_lookup.numerator.id).?,
                lookup.numerator,
            );
            try std.testing.expectEqual(source_lookup.numerator.id, lookup.source_numerator);
            const fields = imported.lookupFields(lookup_index).?;
            const source_fields = imported.sourceLookupFields(lookup_index).?;
            try std.testing.expectEqual(@as(usize, source_lookup.arity), fields.len);
            for (
                source_lookup.values[0..source_lookup.arity],
                fields,
                source_fields,
            ) |source_value, field, source_field| {
                try std.testing.expectEqual(
                    imported.imported.valueForSourceNode(source_value.id).?,
                    field,
                );
                try std.testing.expectEqual(source_value.id, source_field);
            }
        }
        try std.testing.expect(imported.lookupFields(imported.lookups.len) == null);
        try std.testing.expect(imported.sourceLookupFields(imported.lookups.len) == null);

        for (0..4) |_| {
            for (column_values[0..fixture.arena.names.items.len]) |*value|
                value.* = m31.M31.fromU64(random.int(u32));
            try expectReplayEquivalent(
                &fixture.arena,
                &imported,
                column_values[0..fixture.arena.names.items.len],
            );
        }
    }
}

test "production builder returns a self-contained validated shadow program" {
    for (0..trace.N_FAMILIES) |family_index| {
        const family: trace.OpcodeFamily = @enumFromInt(family_index);
        var imported = try shadow_program.buildProduction(
            std.testing.allocator,
            family,
            source.SourceSpan.generated(),
        );
        defer imported.deinit();
        try imported.validate();
        try std.testing.expectEqual(
            Builder.mainColumnCount(family),
            imported.mainColumns().len,
        );
        try std.testing.expectEqual(
            Builder.constraintCount(family),
            imported.direct_constraints.len,
        );
        try std.testing.expectEqual(
            constraint_program.entryCount(family),
            imported.lookups.len,
        );
    }
}

test "ordered shadow program construction is structurally deterministic" {
    var first = try shadow_program.buildProduction(
        std.testing.allocator,
        .div,
        source.SourceSpan.generated(),
    );
    defer first.deinit();
    var second = try shadow_program.buildProduction(
        std.testing.allocator,
        .div,
        source.SourceSpan.generated(),
    );
    defer second.deinit();

    try std.testing.expectEqual(first.family, second.family);
    try std.testing.expectEqual(first.main_column_count, second.main_column_count);
    try std.testing.expectEqual(first.selector, second.selector);
    try std.testing.expectEqual(first.active_row, second.active_row);
    try std.testing.expectEqual(first.batch_size, second.batch_size);
    try std.testing.expectEqualDeep(
        first.imported.arena.nodesView(),
        second.imported.arena.nodesView(),
    );
    try std.testing.expectEqualDeep(
        first.imported.arena.constraintsView(),
        second.imported.arena.constraintsView(),
    );
    try std.testing.expectEqualSlices(
        types.ValueId,
        first.imported.columns,
        second.imported.columns,
    );
    try std.testing.expectEqualSlices(
        types.ConstraintId,
        first.direct_constraints,
        second.direct_constraints,
    );
    try std.testing.expectEqualDeep(first.lookups, second.lookups);
    try std.testing.expectEqualSlices(
        types.ValueId,
        first.lookup_values,
        second.lookup_values,
    );
    try std.testing.expectEqual(first.imported.arena.names.items.len, second.imported.arena.names.items.len);
    for (first.imported.arena.names.items, second.imported.arena.names.items) |lhs, rhs|
        try std.testing.expectEqualStrings(lhs, rhs);
}

test "ordered shadow program validator rejects corrupted owned metadata" {
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .lui,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();

    const saved_main_count = imported.main_column_count;
    imported.main_column_count -= 1;
    try std.testing.expectError(error.InvalidColumnLayout, imported.validate());
    imported.main_column_count = saved_main_count;

    const saved_selector = imported.selector;
    imported.selector = imported.mainColumns()[0];
    try std.testing.expectError(error.InvalidSelector, imported.validate());
    imported.selector = saved_selector;

    const saved_active = imported.active_row;
    imported.active_row = @enumFromInt(std.math.maxInt(u32));
    try std.testing.expectError(error.InvalidActiveRow, imported.validate());
    imported.active_row = saved_active;

    const saved_constraint_id = imported.direct_constraints[0];
    imported.direct_constraints[0] = imported.direct_constraints[1];
    try std.testing.expectError(error.InvalidConstraintMap, imported.validate());
    imported.direct_constraints[0] = saved_constraint_id;

    const saved_constraints = imported.direct_constraints;
    imported.direct_constraints = saved_constraints[0 .. saved_constraints.len - 1];
    try std.testing.expectError(error.InvalidConstraintCount, imported.validate());
    imported.direct_constraints = saved_constraints;

    const saved_category = imported.imported.arena.constraints.items[0].category;
    imported.imported.arena.constraints.items[0].category = .boundary;
    try std.testing.expectError(error.InvalidConstraintMetadata, imported.validate());
    imported.imported.arena.constraints.items[0].category = saved_category;

    const saved_batch_size = imported.batch_size;
    imported.batch_size = 0;
    try std.testing.expectError(error.InvalidBatchSize, imported.validate());
    imported.batch_size = saved_batch_size;

    const saved_lookups = imported.lookups;
    imported.lookups = saved_lookups[0 .. saved_lookups.len - 1];
    try std.testing.expectError(error.InvalidLookupCount, imported.validate());
    imported.lookups = saved_lookups;

    const saved_range = imported.lookups[0].fields;
    imported.lookups[0].fields.start += 1;
    try std.testing.expectError(error.InvalidLookupRange, imported.validate());
    imported.lookups[0].fields = saved_range;

    const saved_numerator = imported.lookups[0].numerator;
    imported.lookups[0].numerator = @enumFromInt(std.math.maxInt(u32));
    try std.testing.expectError(error.InvalidNumerator, imported.validate());
    imported.lookups[0].numerator = saved_numerator;

    const saved_value = imported.lookup_values[0];
    imported.lookup_values[0] = @enumFromInt(std.math.maxInt(u32));
    try std.testing.expectError(error.InvalidLookupValue, imported.validate());
    imported.lookup_values[0] = saved_value;

    const saved_span = imported.lookups[0].source_span;
    imported.lookups[0].source_span.start.byte_offset = 1;
    try std.testing.expectError(error.InvalidSourceSpan, imported.validate());
    imported.lookups[0].source_span = saved_span;
    try imported.validate();
}

test "ordered shadow import rejects the wrong source boundary" {
    var fixture = try SourceFixture.init(std.testing.allocator, .lui);
    defer fixture.deinit();
    try std.testing.expectError(
        error.InvalidMainColumnCount,
        shadow_program.importBuilt(
            std.testing.allocator,
            .lui,
            &fixture.arena,
            fixture.main_column_count - 1,
            fixture.selector,
            &fixture.program,
            source.SourceSpan.generated(),
        ),
    );
    try std.testing.expectError(
        error.InvalidSourceSelector,
        shadow_program.importBuilt(
            std.testing.allocator,
            .lui,
            &fixture.arena,
            fixture.main_column_count,
            .{ .id = fixture.column_ids[0] },
            &fixture.program,
            source.SourceSpan.generated(),
        ),
    );
}

const SourceFixture = struct {
    arena: symbolic.Arena,
    main_column_count: usize,
    column_ids: [trace.MAX_FAMILY_COLUMNS]u32,
    selector: symbolic.Scalar,
    program: Builder.ConstraintProgram,

    fn init(
        allocator: std.mem.Allocator,
        family: trace.OpcodeFamily,
    ) !SourceFixture {
        var arena = symbolic.Arena.init(allocator);
        errdefer arena.deinit();
        symbolic.begin(&arena);
        defer symbolic.end();

        const main_column_count = Builder.mainColumnCount(family);
        var columns: [trace.MAX_FAMILY_COLUMNS]symbolic.Scalar = undefined;
        try model.declareColumns(
            &arena,
            family,
            columns[0..main_column_count],
        );
        var column_ids: [trace.MAX_FAMILY_COLUMNS]u32 = undefined;
        for (columns[0..main_column_count], column_ids[0..main_column_count]) |column, *id|
            id.* = column.id;
        const selector = arena.column("is_active");
        const built = try Builder.build(
            family,
            columns[0..main_column_count],
            selector,
        );
        return .{
            .arena = arena,
            .main_column_count = main_column_count,
            .column_ids = column_ids,
            .selector = selector,
            .program = built,
        };
    }

    fn deinit(self: *SourceFixture) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

fn expectedRole(role: production_entry.EventRole) relation.Role {
    return switch (role) {
        .request => .request,
        .consume => .consume,
        .emit => .emit,
    };
}

fn expectReplayEquivalent(
    source_arena: *const symbolic.Arena,
    imported: *const shadow_program.ImportedProgram,
    column_values: []const m31.M31,
) !void {
    const source_out = try std.testing.allocator.alloc(
        m31.M31,
        source_arena.nodes.items.len,
    );
    defer std.testing.allocator.free(source_out);
    const imported_out = try std.testing.allocator.alloc(
        m31.M31,
        imported.imported.arena.nodeCount(),
    );
    defer std.testing.allocator.free(imported_out);
    symbolic.replay(source_arena, column_values, source_out);
    try imported.imported.replay(column_values, imported_out);
    for (source_out, imported.imported.source_to_value) |expected, imported_id|
        try std.testing.expectEqual(
            expected.toU32(),
            imported_out[types.idIndex(imported_id)].toU32(),
        );
}

fn allocationFailureCase(
    allocator: std.mem.Allocator,
    fixture: *const SourceFixture,
) !void {
    var imported = try shadow_program.importBuilt(
        allocator,
        .lui,
        &fixture.arena,
        fixture.main_column_count,
        fixture.selector,
        &fixture.program,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
}

test "ordered shadow import releases every partial allocation" {
    var fixture = try SourceFixture.init(std.testing.allocator, .lui);
    defer fixture.deinit();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{&fixture},
    );
}
