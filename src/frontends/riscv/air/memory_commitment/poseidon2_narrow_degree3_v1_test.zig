const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const air = @import("poseidon2_narrow_degree3_v1.zig");
const legacy = @import("poseidon2_air.zig");
const native = @import("poseidon2.zig");
const relations_mod = @import("../relation_challenges.zig");
const logup = @import("../logup.zig");

fn expectZero(values: anytype) !void {
    for (values) |value| try std.testing.expect(value.isZero());
}

fn secure(row: air.Row) [air.N_MAIN_COLUMNS]QM31 {
    var result: [air.N_MAIN_COLUMNS]QM31 = undefined;
    for (&result, row) |*out, value| out.* = QM31.fromBase(value);
    return result;
}

test "Ethereum narrow degree3 Poseidon matches native permutation and exact lookup entries" {
    var prng = std.Random.DefaultPrng.init(0x309f_3287);
    const random = prng.random();
    var relations: relations_mod.Relations = undefined;
    inline for (std.meta.fields(relations_mod.Relations)) |field| {
        @field(relations, field.name) = @TypeOf(@field(relations, field.name)).init(
            QM31.fromU32Unchecked(41, 5, 8, 2),
            QM31.fromU32Unchecked(7, 3, 1, 6),
        );
    }
    for (0..64) |_| {
        const left = random.uintLessThan(u32, @import("stwo_core").fields.m31.Modulus);
        const right = random.uintLessThan(u32, @import("stwo_core").fields.m31.Modulus);
        const expected = native.hashPair(left, right);
        const call = legacy.Call.narrowWithOutput(left, right, expected);
        const row = try air.fill(call);
        try expectZero(air.evaluateGeneric(M31, row, M31.one()));
        const output = air.outputGeneric(M31, row);
        try std.testing.expectEqual(expected, output[0].toU32());
        const legacy_row = legacy.fill(call);
        try std.testing.expectEqualDeep(legacy.output(legacy_row), output);
        var legacy_secure: [legacy.N_MAIN_COLUMNS]QM31 = undefined;
        for (&legacy_secure, legacy_row) |*out, value| out.* = QM31.fromBase(value);
        const pairs = air.rowPairsGeneric(QM31, secure(row), &relations);
        try std.testing.expectEqualDeep(legacy.rowPairs(legacy_secure, &relations), pairs);
    }
}

test "Ethereum narrow degree3 Poseidon constrains every row and rejects invalid padding and modes" {
    const active = try air.fill(legacy.Call.narrow(17, 39));
    const padding = air.paddingRow();
    try expectZero(air.evaluateGeneric(M31, padding, M31.zero()));
    for ([_]air.Row{ active, padding }, [_]M31{ M31.one(), M31.zero() }) |row, selector| {
        for (0..air.N_MAIN_COLUMNS) |column| {
            var changed = row;
            changed[column] = changed[column].add(M31.one());
            var rejected = false;
            for (air.evaluateGeneric(M31, changed, selector)) |residual| rejected = rejected or !residual.isZero();
            if (!rejected) std.debug.print("Unconstrained narrow Poseidon column={} active={}\n", .{ column, selector.toU32() });
            try std.testing.expect(rejected);
        }
    }
    var rejected_zero_padding = false;
    for (air.evaluateGeneric(M31, .{M31.zero()} ** air.N_MAIN_COLUMNS, M31.zero())) |value| rejected_zero_padding = rejected_zero_padding or !value.isZero();
    try std.testing.expect(rejected_zero_padding);
    var invalid = legacy.Call.narrow(17, 39);
    invalid.input[2] = 1;
    try std.testing.expectError(error.InvalidPoseidonNarrowInputV1, air.fill(invalid));
    invalid = legacy.Call.narrow(17, 39);
    invalid.wide = true;
    try std.testing.expectError(error.UnsupportedPoseidonNarrowModeV1, air.fill(invalid));
    invalid.wide = false;
    invalid.io = true;
    try std.testing.expectError(error.UnsupportedPoseidonNarrowModeV1, air.fill(invalid));
    try std.testing.expectError(error.PoseidonNarrowOutputMismatchV1, air.fill(legacy.Call.narrowWithOutput(17, 39, native.hashPair(17, 39) + 1)));
}

// Conservative polynomial degree replay through the production generic AIR.
const Degree = struct {
    degree: u32,
    pub fn zero() Degree {
        return .{ .degree = 0 };
    }
    pub fn one() Degree {
        return zero();
    }
    pub fn fromBase(_: M31) Degree {
        return zero();
    }
    pub fn add(a: Degree, b: Degree) Degree {
        return .{ .degree = @max(a.degree, b.degree) };
    }
    pub fn sub(a: Degree, b: Degree) Degree {
        return a.add(b);
    }
    pub fn neg(a: Degree) Degree {
        return a;
    }
    pub fn mul(a: Degree, b: Degree) Degree {
        return .{ .degree = a.degree + b.degree };
    }
    pub fn square(a: Degree) Degree {
        return a.mul(a);
    }
};

test "Ethereum narrow degree3 Poseidon keeps quotient expansion and reduces complete row geometry" {
    const variable = Degree{ .degree = 1 };
    const result = air.evaluateGeneric(Degree, .{variable} ** air.N_MAIN_COLUMNS, variable);
    var maximum: u32 = 0;
    for (result) |value| maximum = @max(maximum, value.degree);
    const lookup = logup.pairConstraintGeneric(Degree, variable, variable, variable, Degree.one(), .{ .n1 = variable, .d1 = variable, .n2 = variable, .d2 = variable });
    try std.testing.expectEqual(@as(u32, 3), lookup.degree);
    try std.testing.expectEqual(air.MAX_CONSTRAINT_DEGREE, maximum);
    try std.testing.expectEqual(@as(usize, 287), air.N_MAIN_COLUMNS);
    try std.testing.expectEqual(@as(usize, 286), air.N_CONSTRAINTS);
    const legacy_cells = @as(u64, 2 + legacy.N_MAIN_COLUMNS + legacy.N_INTERACTION_COLUMNS) << 22;
    const narrow_cells = @as(u64, 2 + air.N_MAIN_COLUMNS + air.N_INTERACTION_COLUMNS) << 22;
    try std.testing.expectEqual(@as(u64, 158) << 22, legacy_cells - narrow_cells);
    // Same trace height and degree3→quotient2N. LDEblowup1 saves5.30GB atlog22.
    try std.testing.expectEqual(@as(u64, 5301600256), (legacy_cells - narrow_cells) * 8);
}

test "Ethereum narrow degree3 Poseidon component admission and callbacks compile" {
    const Component = @import("poseidon2_narrow_component_v1.zig").Component;
    const relations = @import("../relation_challenges.zig").Relations.dummy();
    const component = Component{ .log_size = 4, .n_rows = 3, .is_first_col_idx = 0, .is_active_col_idx = 1, .main_col_offset = 0, .interaction_col_offset = 0, .relations = &relations, .claims = .{ QM31.zero(), QM31.zero() } };
    const handle = component.asProverComponent();
    const verifier = component.asVerifierComponent();
    try std.testing.expectEqual(@as(usize, 288), handle.nConstraints());
    try std.testing.expectEqual(@as(usize, 288), verifier.nConstraints());
    var bounds = try handle.traceLogDegreeBounds(std.testing.allocator);
    defer {
        for (bounds.items) |tree| std.testing.allocator.free(tree);
        bounds.deinit(std.testing.allocator);
    }
    try std.testing.expectEqual(@as(usize, 287), bounds.items[1].len);
    var main = try air.generateMain(std.testing.allocator, &.{ legacy.Call.narrow(1, 2), legacy.Call.narrow(3, 4) }, 4);
    defer main.deinit(std.testing.allocator);
}

test "Ethereum narrow degree3 Poseidon central profile rejects legacy width and parallel rows match serial" {
    const assembly = @import("../../prover/base_component_assembly.zig");
    const manifest = @import("../lang/opcode_composition_manifest.zig");
    var cursor = assembly.InfrastructureCursor.init(manifest.PlacementCursor{});
    try std.testing.expectError(error.MainColumnCountMismatch, cursor.append(.poseidon2, air.N_MAIN_COLUMNS));
    try std.testing.expectError(error.MainColumnCountMismatch, cursor.appendWithCircuit(.poseidon2, legacy.N_MAIN_COLUMNS, .fixed_program_narrow_v1));
    const placement = try cursor.appendWithCircuit(.poseidon2, air.N_MAIN_COLUMNS, .fixed_program_narrow_v1);
    try std.testing.expectEqual(@as(usize, air.N_MAIN_COLUMNS), placement.main_columns);
    const allocator = std.testing.allocator;
    const calls = [_]legacy.Call{ legacy.Call.narrow(3, 7), legacy.Call.narrow(5, 11) };
    var serial = try air.generateMain(allocator, &calls, 4);
    defer serial.deinit(allocator);
    var generated = try air.generateMain(allocator, &.{}, 4);
    defer generated.deinit(allocator);
    const table = try @import("../../infra_trace.zig").BitReversalTable.init(allocator, 4);
    defer table.deinit(allocator);
    var inverse: [16]usize = undefined;
    for (table.mapping, 0..) |committed, logical| inverse[committed] = logical;
    const tasks = @import("stwo_prover_engine").task_graph;
    var cancellation = tasks.CancellationToken{};
    var context = tasks.TaskContext{ .user_context = &generated, .cancellation = &cancellation, .key = .{ .epoch = 0, .stage_rank = 0, .component_registry_index = 0, .shard_or_chunk_index = 0 }, .worker_budget = @import("stwo_prover_engine").work_pool.WorkerBudget.serial(), .task_class = .leaf, .exclusive_lease = null, .child_wait_group = null };
    const generators = @import("../../prover/main_trace_plan_execution_production_generators.zig");
    for ([_]@import("../../prover/main_trace_plan.zig").RowRange{ .{ .start = 0, .len = 5 }, .{ .start = 5, .len = 11 } }) |range| {
        const result = try generators.fillNarrowPoseidonRange(&generated.values, &calls, &inverse, range, null, &context);
        try std.testing.expect(result.completed);
    }
    for (serial.values, generated.values) |expected, actual| try std.testing.expectEqualSlices(M31, expected, actual);
}
