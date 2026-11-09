const std = @import("std");
const prover_component = @import("stwo_prover_engine").air.component_prover;
const runtime_program = @import("stwo_riscv_rv32").modules.air_extract_runtime_program;
const symbolic = @import("stwo_riscv_air_lang").modules.shared_air_extract_symbolic;
const trace = @import("stwo_riscv_rv32").modules.runner_trace;
const compat_layout = @import("stwo_riscv_rv32").modules.air_lang_compat_layout;
const lower_constraint = @import("stwo_riscv_rv32").modules.air_lang_lower_constraint;
const lower_lookup = @import("stwo_riscv_rv32").modules.air_lang_lower_lookup;
const lower_runtime = @import("stwo_riscv_rv32").modules.air_lang_lower_runtime;
const oracle = @import("stwo_riscv_air_lang").modules.lower_test_oracle;
const shadow_program = @import("stwo_riscv_rv32").modules.air_lang_shadow_program;
const source = @import("stwo_riscv_air_lang").modules.source;

const no_node = std.math.maxInt(u32);

test "runtime direct export has exact canonical nodes roots and columns for every family" {
    for (0..trace.N_FAMILIES) |family_index| {
        const family: trace.OpcodeFamily = @enumFromInt(family_index);
        var imported = try shadow_program.buildProduction(
            std.testing.allocator,
            family,
            source.SourceSpan.generated(),
        );
        defer imported.deinit();
        const layout = try compat_layout.build(&imported);
        var actual = try lower_runtime.buildDirect(
            std.testing.allocator,
            &imported,
            &layout,
        );
        defer actual.deinit();

        var production = try runtime_program.build(std.testing.allocator, family);
        defer production.deinit();
        var expected = try oracle.normalizeBase(std.testing.allocator, &production);
        defer expected.deinit();
        try expectNodes(expected.nodes, actual.nodes);
        try std.testing.expectEqualSlices(u32, expected.roots, actual.roots);
        try std.testing.expectEqual(production.column_count, actual.column_count);
        try actual.validate();
    }
}

test "runtime lookup export has exact canonical entries columns and batches for every family" {
    for (0..trace.N_FAMILIES) |family_index| {
        const family: trace.OpcodeFamily = @enumFromInt(family_index);
        var imported = try shadow_program.buildProduction(
            std.testing.allocator,
            family,
            source.SourceSpan.generated(),
        );
        defer imported.deinit();
        const layout = try compat_layout.build(&imported);
        var actual = try lower_runtime.buildLookups(
            std.testing.allocator,
            &imported,
            &layout,
        );
        defer actual.deinit();

        var production = try runtime_program.buildLookups(
            std.testing.allocator,
            family,
        );
        defer production.deinit();
        var expected = try oracle.normalizeLookup(std.testing.allocator, &production);
        defer expected.deinit();
        try expectNodes(expected.nodes, actual.nodes);
        try std.testing.expectEqual(production.column_count, actual.column_count);
        try std.testing.expectEqual(production.batch_size, actual.batch_size);
        try std.testing.expectEqual(production.entries.len, actual.entries.len);
        try std.testing.expectEqual(production.batchCount(), actual.batchCount());
        try std.testing.expectEqual(production.parameterCount(), actual.parameterCount());

        var root_cursor: usize = 0;
        for (production.entries, actual.entries) |production_entry, actual_entry| {
            try std.testing.expectEqual(production_entry.arity, actual_entry.arity);
            try std.testing.expectEqual(expected.roots[root_cursor], actual_entry.numerator);
            root_cursor += 1;
            for (actual_entry.values[0..actual_entry.arity]) |value| {
                try std.testing.expectEqual(expected.roots[root_cursor], value);
                root_cursor += 1;
            }
            for (actual_entry.values[actual_entry.arity..]) |unused|
                try std.testing.expectEqual(no_node, unused);
        }
        try std.testing.expectEqual(expected.roots.len, root_cursor);
        try actual.validate();
    }
}

test "runtime exporters reject malformed lowered owners before copying" {
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .lui,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);

    var direct = try lower_constraint.lower(
        std.testing.allocator,
        &imported,
        &layout,
    );
    defer direct.deinit();
    const saved_column_count = direct.column_count;
    direct.column_count = 0;
    try std.testing.expectError(
        error.InvalidColumnLayout,
        lower_runtime.exportDirect(std.testing.allocator, &direct),
    );
    direct.column_count = saved_column_count;

    var lookups = try lower_lookup.lower(
        std.testing.allocator,
        &imported,
        &layout,
    );
    defer lookups.deinit();
    const saved_role = lookups.events[1].role;
    lookups.events[1].role = .emit;
    try std.testing.expectError(
        error.InvalidNumeratorSign,
        lower_runtime.exportLookups(std.testing.allocator, &lookups),
    );
    lookups.events[1].role = saved_role;
}

test "runtime direct export releases every partial allocation" {
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .div,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        directFailureCase,
        .{ &imported, &layout },
    );
}

test "runtime lookup export releases every partial allocation" {
    var imported = try shadow_program.buildProduction(
        std.testing.allocator,
        .div,
        source.SourceSpan.generated(),
    );
    defer imported.deinit();
    const layout = try compat_layout.build(&imported);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        lookupFailureCase,
        .{ &imported, &layout },
    );
}

fn directFailureCase(
    allocator: std.mem.Allocator,
    imported: *const shadow_program.ImportedProgram,
    layout: *const compat_layout.Layout,
) !void {
    var runtime = try lower_runtime.buildDirect(allocator, imported, layout);
    defer runtime.deinit();
}

fn lookupFailureCase(
    allocator: std.mem.Allocator,
    imported: *const shadow_program.ImportedProgram,
    layout: *const compat_layout.Layout,
) !void {
    var runtime = try lower_runtime.buildLookups(allocator, imported, layout);
    defer runtime.deinit();
}

fn expectNodes(
    expected: []const symbolic.Node,
    actual: []const prover_component.BasePolynomialNode,
) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |want, got| {
        try std.testing.expectEqual(@intFromEnum(want.op), @intFromEnum(got.op));
        try std.testing.expectEqual(want.lhs, got.lhs);
        try std.testing.expectEqual(want.rhs, got.rhs);
        try std.testing.expectEqual(want.value, got.value);
    }
}
