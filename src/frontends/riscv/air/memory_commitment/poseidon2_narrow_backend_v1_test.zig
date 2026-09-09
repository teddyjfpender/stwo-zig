const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const programs = @import("stwo_prover_engine").air.component_prover;
const Relations = @import("../relation_challenges.zig").Relations;
const logup = @import("../logup.zig");

fn evaluate(nodes: []const programs.BasePolynomialNode, values: []QM31, columns: []const QM31) void {
    for (nodes, 0..) |node, index| values[index] = switch (node.op) {
        .constant => QM31.fromBase(M31.fromCanonical(node.value)),
        .column => columns[node.value],
        .add => values[node.lhs].add(values[node.rhs]),
        .sub => values[node.lhs].sub(values[node.rhs]),
        .mul => values[node.lhs].mul(values[node.rhs]),
        .neg => values[node.lhs].neg(),
    };
}

test "Ethereum narrow degree3 Poseidon backend DAG preserves direct lookup and capability ordering" {
    try checkExport(@import("poseidon2_narrow_degree3_v1.zig"), @import("poseidon2_narrow_backend_v1.zig"), @import("poseidon2_narrow_component_v1.zig").Component, true);
}

test "universal degree3 Poseidon backend preserves native direct and independent prefix constraints" {
    try checkExport(@import("poseidon2_universal_degree3_v1.zig"), @import("poseidon2_narrow_backend_v1.zig").Universal, @import("poseidon2_universal_component_v1.zig").Component, false);
}

fn checkExport(comptime air: type, comptime backend: type, comptime Component: type, comptime binds_active: bool) !void {
    const allocator = std.testing.allocator;
    var relations: Relations = undefined;
    inline for (std.meta.fields(Relations), 0..) |field, index| {
        const seed: u32 = @intCast(index);
        @field(relations, field.name) = @TypeOf(@field(relations, field.name)).init(QM31.fromU32Unchecked(41 + seed, 5, 8, 2), QM31.fromU32Unchecked(7 + seed, 3, 1, 6));
    }
    const claims = [2]QM31{ QM31.fromU32Unchecked(19, 1, 5, 4), QM31.fromU32Unchecked(23, 9, 6, 2) };
    const component = Component{ .log_size = 4, .n_rows = 3, .is_first_col_idx = 7, .is_active_col_idx = 9, .main_col_offset = 11, .interaction_col_offset = 13, .relations = &relations, .claims = claims };
    const capability = component.asProverComponent().backend_composition_capability.?.base_lookup_polynomial_v1;
    const exports = try capability.export_capabilities(&component);
    try std.testing.expectEqual(backend.DIRECT_PARTITION_COUNT, exports.base_partition_count);
    const lookup_capability = exports.lookup;
    try std.testing.expectEqual(@as(usize, 7), lookup_capability.selector_column);
    try std.testing.expectEqual(@as(usize, 13), lookup_capability.first_interaction_column);
    var lookup = try lookup_capability.export_program(&component, allocator);
    defer lookup.deinit();
    try lookup.validate();
    const parameters = try lookup_capability.export_parameters(&component, allocator);
    defer allocator.free(parameters);
    try std.testing.expectEqual(lookup.parameterCount(), parameters.len);
    try std.testing.expectEqual(backend.LOOKUP_PROGRAM_ID, lookup_capability.program_id);
    const lookup_values = try allocator.alloc(QM31, lookup.nodes.len);
    defer allocator.free(lookup_values);
    var covered: usize = 0;
    var rng = std.Random.DefaultPrng.init(0x91873bcd);
    const random = rng.random();
    // Arbitrary extension-field inputs check the complete polynomials, including
    // invalid witness values, rather than only zero residuals on valid rows.
    var inputs: [air.N_MAIN_COLUMNS + 1]QM31 = undefined;
    for (&inputs) |*value| value.* = QM31.fromU32Unchecked(random.uintLessThan(u32, 10000), random.uintLessThan(u32, 10000), random.uintLessThan(u32, 10000), random.uintLessThan(u32, 10000));
    const expected = if (binds_active) air.evaluateGeneric(QM31, inputs[0..air.N_MAIN_COLUMNS].*, inputs[air.N_MAIN_COLUMNS]) else air.evaluateGeneric(QM31, inputs[0..air.N_MAIN_COLUMNS].*);
    for (exports.base_partitions[0..exports.base_partition_count], 0..) |partition, partition_index| {
        try std.testing.expectEqual(covered, partition.constraints.start);
        try std.testing.expectEqual(@as(usize, if (binds_active) 9 else 7), partition.capability.selector_column);
        try std.testing.expectEqual(backend.DIRECT_PROGRAM_ID | partition_index, partition.capability.program_id);
        try std.testing.expectEqual(@as(usize, 11), partition.capability.first_main_column);
        var program = try partition.capability.export_program(&component, allocator);
        defer program.deinit();
        try program.validate();
        try std.testing.expectEqual(partition.constraints.count, program.roots.len);
        const values = try allocator.alloc(QM31, program.nodes.len);
        defer allocator.free(values);
        evaluate(program.nodes, values, &inputs);
        for (program.roots, expected[covered..][0..program.roots.len]) |root, native| try std.testing.expectEqualDeep(native, values[root]);
        covered += program.roots.len;
    }
    try std.testing.expectEqual(air.N_CONSTRAINTS, covered);
    try std.testing.expectEqual(covered, exports.lookup_constraints.start);
    try std.testing.expectEqual(air.N_SUMS, exports.lookup_constraints.count);
    evaluate(lookup.nodes, lookup_values, inputs[0..air.N_MAIN_COLUMNS]);
    var denominators: [4]QM31 = undefined;
    var parameter_cursor: usize = 0;
    for (lookup.entries, &denominators) |entry, *denominator| {
        denominator.* = parameters[parameter_cursor].neg();
        for (entry.values[0..entry.arity], 0..) |root, index| denominator.* = denominator.add(parameters[parameter_cursor + 1 + index].mul(lookup_values[root]));
        parameter_cursor += 1 + entry.arity;
    }
    const native_pairs = air.rowPairsGeneric(QM31, inputs[0..air.N_MAIN_COLUMNS].*, &relations);
    const sums = [2]QM31{ inputs[5], inputs[6] };
    const previous = [2]QM31{ inputs[7], inputs[8] };
    const native_constraints = air.interactionConstraintsGeneric(QM31, inputs[0..air.N_MAIN_COLUMNS].*, inputs[9], sums, previous, claims, &relations);
    for (native_pairs, 0..) |native_pair, index| {
        const pair = logup.RowPair{ .n1 = lookup_values[lookup.entries[2 * index].numerator], .d1 = denominators[2 * index], .n2 = lookup_values[lookup.entries[2 * index + 1].numerator], .d2 = denominators[2 * index + 1] };
        try std.testing.expectEqualDeep(native_pair, pair);
        const actual = logup.pairConstraintGeneric(QM31, sums[index], previous[index], inputs[9], parameters[parameter_cursor + index], pair);
        try std.testing.expectEqualDeep(native_constraints[index], actual);
    }
    try std.testing.expectError(error.InvalidPoseidonNarrowPartitionV1, backend.buildDirect(allocator, backend.DIRECT_PARTITION_COUNT));
    var invalid = component;
    invalid.log_size = 0;
    try std.testing.expectError(error.InvalidPoseidonNarrowComponentV1, capability.export_capabilities(&invalid));
    try std.testing.expectError(error.InvalidPoseidonNarrowComponentV1, lookup_capability.export_program(&invalid, allocator));
    try std.testing.expectError(error.InvalidPoseidonNarrowComponentV1, lookup_capability.export_parameters(&invalid, allocator));
    try std.testing.expectError(error.InvalidPoseidonNarrowComponentV1, exports.base_partitions[0].capability.export_program(&invalid, allocator));
}

// Record once, then exercise valid modes and retained AIR rejection patterns.
// Changing the unused selector must never suppress universal padding constraints.
test "universal degree3 backend constrains modes and padding independently of selector" {
    const air = @import("poseidon2_universal_degree3_v1.zig");
    const narrow_backend = @import("poseidon2_narrow_backend_v1.zig");
    const backend = narrow_backend.Universal;
    const allocator = std.testing.allocator;
    try std.testing.expect(backend.DIRECT_PROGRAM_ID != narrow_backend.DIRECT_PROGRAM_ID);
    try std.testing.expect(backend.LOOKUP_PROGRAM_ID != narrow_backend.LOOKUP_PROGRAM_ID);
    var lookup = try backend.buildLookup(allocator);
    defer lookup.deinit();
    const lookup_values = try allocator.alloc(QM31, lookup.nodes.len);
    defer allocator.free(lookup_values);
    var directs: [backend.DIRECT_PARTITION_COUNT]programs.OwnedBasePolynomialProgram = undefined;
    var initialized: usize = 0;
    defer for (directs[0..initialized]) |*program| program.deinit();
    for (&directs, 0..) |*program, index| {
        program.* = try backend.buildDirect(allocator, index);
        initialized += 1;
    }
    const rows = [_]air.Row{
        try air.fill(.{ .input = .{17} ** 16 }),
        try air.fill(.{ .input = .{29} ** 16, .wide = true }),
        try air.fill(.{ .input = .{43} ** 16, .io = true }),
        air.paddingRow(),
    };
    for (rows) |row| {
        for (0..4) |mutation| {
            var inputs: [air.N_MAIN_COLUMNS + 1]QM31 = undefined;
            for (inputs[0..air.N_MAIN_COLUMNS], row) |*value, word| value.* = QM31.fromBase(word);
            switch (mutation) {
                0 => {},
                1 => inputs[air.WIDE_COLUMN - 1] = inputs[air.WIDE_COLUMN - 1].add(QM31.one()),
                2 => inputs[0] = QM31.fromU32Unchecked(2, 0, 0, 0),
                3 => {
                    inputs[air.WIDE_COLUMN] = QM31.one();
                    inputs[air.IO_COLUMN] = QM31.one();
                },
                else => unreachable,
            }
            const expected = air.evaluateGeneric(QM31, inputs[0..air.N_MAIN_COLUMNS].*);
            var rejected = false;
            for (expected) |value| rejected = rejected or !value.isZero();
            try std.testing.expectEqual(mutation != 0, rejected);
            for ([_]QM31{ QM31.zero(), QM31.one(), QM31.fromU32Unchecked(5, 7, 11, 13) }) |selector| {
                inputs[air.N_MAIN_COLUMNS] = selector;
                var covered: usize = 0;
                for (directs) |program| {
                    const values = try allocator.alloc(QM31, program.nodes.len);
                    defer allocator.free(values);
                    evaluate(program.nodes, values, &inputs);
                    for (program.roots, expected[covered..][0..program.roots.len]) |root, native| try std.testing.expectEqualDeep(native, values[root]);
                    covered += program.roots.len;
                }
            }
            evaluate(lookup.nodes, lookup_values, inputs[0..air.N_MAIN_COLUMNS]);
            const entries = air.entriesGeneric(QM31, inputs[0..air.N_MAIN_COLUMNS].*);
            try std.testing.expectEqual(entries.len, lookup.entries.len);
            for (lookup.entries, entries.entries[0..entries.len]) |entry, native| {
                try std.testing.expectEqual(native.arity, entry.arity);
                try std.testing.expectEqualDeep(native.numerator, lookup_values[entry.numerator]);
                for (entry.values[0..entry.arity], native.values[0..native.arity]) |root, value| try std.testing.expectEqualDeep(value, lookup_values[root]);
            }
        }
    }
}
