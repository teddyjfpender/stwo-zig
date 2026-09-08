const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const programs = @import("stwo_prover_engine").air.component_prover;
const air = @import("poseidon2_narrow_degree3_v1.zig");
const backend = @import("poseidon2_narrow_backend_v1.zig");
const Component = @import("poseidon2_narrow_component_v1.zig").Component;
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
    const allocator = std.testing.allocator;
    var relations: Relations = undefined;
    inline for (std.meta.fields(Relations)) |field| @field(relations, field.name) = @TypeOf(@field(relations, field.name)).init(QM31.fromU32Unchecked(41, 5, 8, 2), QM31.fromU32Unchecked(7, 3, 1, 6));
    const claims = [2]QM31{ QM31.fromU32Unchecked(19, 1, 5, 4), QM31.fromU32Unchecked(23, 9, 6, 2) };
    const component = Component{ .log_size = 4, .n_rows = 3, .is_first_col_idx = 7, .is_active_col_idx = 9, .main_col_offset = 11, .interaction_col_offset = 13, .relations = &relations, .claims = claims };
    const capability = backend.Namespace(Component).capability().base_lookup_polynomial_v1;
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
    const lookup_values = try allocator.alloc(QM31, lookup.nodes.len);
    defer allocator.free(lookup_values);
    var covered: usize = 0;
    var rng = std.Random.DefaultPrng.init(0x91873bcd);
    const random = rng.random();
    // Arbitrary extension-field inputs check the complete polynomials, including
    // invalid witness values, rather than only zero residuals on valid rows.
    var inputs: [air.N_MAIN_COLUMNS + 1]QM31 = undefined;
    for (&inputs) |*value| value.* = QM31.fromU32Unchecked(random.uintLessThan(u32, 10000), random.uintLessThan(u32, 10000), random.uintLessThan(u32, 10000), random.uintLessThan(u32, 10000));
    const expected = air.evaluateGeneric(QM31, inputs[0..air.N_MAIN_COLUMNS].*, inputs[air.N_MAIN_COLUMNS]);
    for (exports.base_partitions[0..exports.base_partition_count]) |partition| {
        try std.testing.expectEqual(covered, partition.constraints.start);
        try std.testing.expectEqual(@as(usize, 9), partition.capability.selector_column);
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
}
