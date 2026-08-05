const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const runtime_program = @import("../extract/runtime_program.zig");
const symbolic = @import("../extract/symbolic.zig");
const trace = @import("../../runner/trace.zig");
const compat_layout = @import("compat_layout.zig");
const lower_lookup = @import("lower_lookup.zig");
const oracle = @import("lower_test_oracle.zig");
const relation = @import("relation.zig");
const shadow_program = @import("shadow_program.zig");
const source = @import("source.zig");
const types = @import("types.zig");

test "LUI lookup lowering preserves normalized events and physical batches" {
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .lui,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);
    var lowered = try lower_lookup.lower(
        std.testing.allocator,
        &imported,
        &layout,
    );
    defer lowered.deinit();

    try std.testing.expectEqual(@as(usize, 7), lowered.events.len);
    try std.testing.expectEqual(@as(u8, 2), lowered.batch_size);
    try std.testing.expectEqual(@as(usize, 4), lowered.batches.len);
    try expectMetadata(&imported, &layout, &lowered);

    var production = try runtime_program.buildLookups(std.testing.allocator, .lui);
    defer production.deinit();
    var normalized = try oracle.normalizeLookup(std.testing.allocator, &production);
    defer normalized.deinit();
    try std.testing.expectEqualSlices(
        symbolic.Node,
        normalized.nodes,
        lowered.polynomials.nodes,
    );
    try std.testing.expectEqualSlices(
        u32,
        normalized.roots,
        lowered.polynomials.roots,
    );

    var second = try lower_lookup.lower(
        std.testing.allocator,
        &imported,
        &layout,
    );
    defer second.deinit();
    try std.testing.expectEqualSlices(
        symbolic.Node,
        lowered.polynomials.nodes,
        second.polynomials.nodes,
    );
    try std.testing.expectEqualSlices(
        u32,
        lowered.polynomials.roots,
        second.polynomials.roots,
    );
    try std.testing.expectEqualSlices(lower_lookup.Event, lowered.events, second.events);
    try std.testing.expectEqualSlices(lower_lookup.Batch, lowered.batches, second.batches);
}

test "lookup lowering exactly normalizes and replays all production families" {
    var prng = std.Random.DefaultPrng.init(0x4c4f_4f4b_5550_5631);
    const random = prng.random();
    for (0..trace.N_FAMILIES) |family_index| {
        const family: trace.OpcodeFamily = @enumFromInt(family_index);
        var imported = try shadow_program.buildProduction(
            std.testing.allocator,
            family,
            source.SourceSpan.generated(),
        );
        defer imported.deinit();
        const layout = try compat_layout.build(&imported);
        var lowered = try lower_lookup.lower(
            std.testing.allocator,
            &imported,
            &layout,
        );
        defer lowered.deinit();
        try expectMetadata(&imported, &layout, &lowered);

        var production = try runtime_program.buildLookups(
            std.testing.allocator,
            family,
        );
        defer production.deinit();
        var normalized = try oracle.normalizeLookup(
            std.testing.allocator,
            &production,
        );
        defer normalized.deinit();
        try std.testing.expectEqualSlices(
            symbolic.Node,
            normalized.nodes,
            lowered.polynomials.nodes,
        );
        try std.testing.expectEqualSlices(
            u32,
            normalized.roots,
            lowered.polynomials.roots,
        );

        const columns = try std.testing.allocator.alloc(M31, production.column_count);
        defer std.testing.allocator.free(columns);
        const production_values = try std.testing.allocator.alloc(
            M31,
            production.nodes.len,
        );
        defer std.testing.allocator.free(production_values);
        const lowered_values = try std.testing.allocator.alloc(
            M31,
            lowered.polynomials.nodes.len,
        );
        defer std.testing.allocator.free(lowered_values);
        for (0..4) |_| {
            for (columns) |*column|
                column.* = M31.fromU64(random.int(u32));
            try oracle.replayLookup(&production, columns, production_values);
            try lowered.polynomials.replay(columns, lowered_values);
            for (production.entries, lowered.events) |expected, actual| {
                try expectFieldEqual(
                    production_values[expected.numerator],
                    lowered_values[actual.numerator],
                );
                for (expected.values[0..expected.arity], actual.valueSlice().?) |want, got| {
                    try expectFieldEqual(
                        production_values[want],
                        lowered_values[got],
                    );
                }
                const signed_liveness = switch (actual.role) {
                    .request, .consume => lowered_values[actual.liveness].neg(),
                    .emit => lowered_values[actual.liveness],
                };
                try expectFieldEqual(
                    lowered_values[actual.numerator],
                    signed_liveness,
                );
            }
        }
    }
}

test "lookup lowering rejects a pre-signed role mismatch" {
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .lui,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);
    const saved = imported.lookups[0].numerator;
    imported.lookups[0].numerator = imported.active_row;
    defer imported.lookups[0].numerator = saved;
    try std.testing.expectError(
        error.InvalidNumeratorSign,
        lower_lookup.lower(std.testing.allocator, &imported, &layout),
    );
}

test "lookup lowering validator rejects corrupted normalized programs" {
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .lui,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);
    var program = try lower_lookup.lower(
        std.testing.allocator,
        &imported,
        &layout,
    );
    defer program.deinit();

    const saved_schema = program.events[0].schema;
    program.events[0].schema = @enumFromInt(std.math.maxInt(u16));
    try std.testing.expectError(error.UnknownSchema, program.validate());
    program.events[0].schema = saved_schema;

    const consume_index = findRole(program.events, .consume).?;
    const saved_role = program.events[consume_index].role;
    program.events[consume_index].role = .emit;
    try std.testing.expectError(error.InvalidNumeratorSign, program.validate());
    program.events[consume_index].role = saved_role;

    const saved_liveness = program.events[0].liveness;
    program.events[0].liveness = std.math.maxInt(u32);
    try std.testing.expectError(error.InvalidEventRoot, program.validate());
    program.events[0].liveness = saved_liveness;

    const numerator_index = program.events[0].numerator;
    const saved_numerator = program.polynomials.nodes[numerator_index];
    program.polynomials.nodes[numerator_index].rhs = 1;
    try std.testing.expectError(error.NonCanonicalNode, program.validate());
    program.polynomials.nodes[numerator_index] = saved_numerator;

    const tail_index: usize = program.events[0].arity;
    program.events[0].values[tail_index] = 0;
    try std.testing.expectError(error.InvalidValueTail, program.validate());
    program.events[0].values[tail_index] = std.math.maxInt(u32);

    const saved_root = program.polynomials.roots[0];
    program.polynomials.roots[0] = program.polynomials.roots[1];
    try std.testing.expectError(error.InvalidRootOrder, program.validate());
    program.polynomials.roots[0] = saved_root;

    const saved_first_event = program.batches[0].first_event;
    program.batches[0].first_event = 1;
    try std.testing.expectError(error.InvalidBatchLayout, program.validate());
    program.batches[0].first_event = saved_first_event;

    const saved_reference = program.batches[0].interaction_columns[0];
    program.batches[0].interaction_columns[0].tree = .main;
    try std.testing.expectError(error.InvalidBatchLayout, program.validate());
    program.batches[0].interaction_columns[0] = saved_reference;

    const saved_batch_size = program.batch_size;
    program.batch_size = 1;
    try std.testing.expectError(error.InvalidBatchLayout, program.validate());
    program.batch_size = saved_batch_size;
    try program.validate();
}

test "lookup lowering releases every partial allocation" {
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .div,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        lowerFailureCase,
        .{ &imported, &layout },
    );
}

fn lowerFailureCase(
    allocator: std.mem.Allocator,
    imported: *const shadow_program.ImportedProgram,
    layout: *const compat_layout.Layout,
) !void {
    var lowered = try lower_lookup.lower(allocator, imported, layout);
    defer lowered.deinit();
}

fn expectMetadata(
    imported: *const shadow_program.ImportedProgram,
    layout: *const compat_layout.Layout,
    lowered: *const lower_lookup.Program,
) !void {
    try lowered.validate();
    try std.testing.expectEqual(imported.family, lowered.family);
    try std.testing.expectEqual(imported.batch_size, lowered.batch_size);
    try std.testing.expectEqual(imported.lookups.len, lowered.events.len);
    for (imported.lookups, lowered.events, 0..) |expected, actual, index| {
        const fields = imported.lookupFields(index).?;
        try std.testing.expectEqual(expected.schema, actual.schema);
        try std.testing.expectEqual(expected.role, actual.role);
        try std.testing.expectEqual(expected.access_ordinal, actual.access_ordinal);
        try std.testing.expectEqual(fields.len, actual.valueSlice().?.len);
    }
    try std.testing.expectEqual(imported.batchCount(), lowered.batches.len);
    for (lowered.batches, 0..) |batch, batch_index| {
        const first_event = batch_index * imported.batch_size;
        try std.testing.expectEqual(first_event, batch.first_event);
        try std.testing.expectEqual(
            @min(@as(usize, imported.batch_size), imported.lookups.len - first_event),
            batch.event_count,
        );
        for (batch.interaction_columns, 0..) |reference, coordinate| {
            const interaction_index =
                batch_index * batch.interaction_columns.len + coordinate;
            try std.testing.expectEqual(
                layout.interactions()[interaction_index].reference,
                reference,
            );
        }
    }
}

fn expectFieldEqual(expected: M31, actual: M31) !void {
    try std.testing.expect(expected.eql(actual));
}

fn findRole(events: []const lower_lookup.Event, role: relation.Role) ?usize {
    for (events, 0..) |event, index| if (event.role == role) return index;
    return null;
}

comptime {
    if (@sizeOf(types.RelationSchemaId) != @sizeOf(u16))
        @compileError("lookup corruption test assumes the pinned schema ID width");
}
