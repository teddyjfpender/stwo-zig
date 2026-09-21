//! Differential and negative gates for the separately versioned provider.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const air = @import("poseidon2_universal_degree3_v1.zig");
const legacy = @import("poseidon2_air.zig");
const relations_mod = @import("../relation_challenges.zig");

fn zeros(values: anytype) !void {
    for (values) |value| try std.testing.expect(value.isZero());
}
fn rejected(row: air.Row) bool {
    for (air.evaluateGeneric(M31, row)) |value| if (!value.isZero()) return true;
    return false;
}
fn secure(row: anytype) [row.len]QM31 {
    var result: [row.len]QM31 = undefined;
    for (&result, row) |*out, value| out.* = QM31.fromBase(value);
    return result;
}

test "universal degree3 Poseidon matches legacy permutation and all relation modes" {
    var prng = std.Random.DefaultPrng.init(0x303_142_3);
    const random = prng.random();
    var relations: relations_mod.Relations = undefined;
    inline for (std.meta.fields(relations_mod.Relations)) |field| {
        @field(relations, field.name) = @TypeOf(@field(relations, field.name)).init(QM31.fromU32Unchecked(41, 5, 8, 2), QM31.fromU32Unchecked(7, 3, 1, 6));
    }
    for (0..3) |mode| for (0..64) |_| {
        var call = legacy.Call{ .input = undefined, .wide = mode == 1, .io = mode == 2 };
        for (&call.input) |*word| word.* = random.uintLessThan(u32, core.fields.m31.Modulus);
        const row = try air.fill(call);
        const old = legacy.fill(call);
        try zeros(air.evaluateGeneric(M31, row));
        try zeros(air.evaluateGeneric(QM31, secure(row)));
        try std.testing.expectEqualDeep(legacy.output(old), air.outputGeneric(M31, row));
        const old_entries = legacy.entriesGeneric(QM31, secure(old));
        const new_entries = air.entriesGeneric(QM31, secure(row));
        try std.testing.expectEqual(old_entries.len, new_entries.len);
        for (old_entries.entries[0..old_entries.len], new_entries.entries[0..new_entries.len]) |expected, actual| {
            try std.testing.expectEqual(expected.domain, actual.domain);
            try std.testing.expectEqualDeep(expected.numerator, actual.numerator);
            try std.testing.expectEqual(expected.arity, actual.arity);
            try std.testing.expectEqualSlices(QM31, expected.values[0..expected.arity], actual.values[0..actual.arity]);
        }
        try std.testing.expectEqualDeep(legacy.rowPairs(secure(old), &relations), air.rowPairsGeneric(QM31, secure(row), &relations));
        var columns: [air.N_MAIN_COLUMNS][]const M31 = undefined;
        for (&columns, 0..) |*column, index| column.* = row[index..][0..1];
        try std.testing.expectEqualDeep(legacy.output(old), air.outputFromColumns(M31, columns, 0));
        const projected = air.entriesFromColumns(QM31, columns, 0);
        const expected_pairs = legacy.rowPairs(secure(old), &relations);
        for (expected_pairs, 0..) |expected_pair, index| try std.testing.expectEqualDeep(expected_pair, try projected.pair(index, &relations));
    };
}

test "universal degree3 Poseidon constrains all permutation columns even in padding" {
    var call = legacy.Call{ .input = undefined, .io = true };
    for (&call.input, 0..) |*word, lane| word.* = @intCast(lane * 431 + 17);
    const active = try air.fill(call);
    const padding = air.paddingRow();
    try zeros(air.evaluateGeneric(M31, padding));
    try std.testing.expect(rejected(.{M31.zero()} ** air.N_MAIN_COLUMNS));
    for ([_]air.Row{ active, padding }) |row| {
        for (1..air.WIDE_COLUMN) |column| {
            var changed = row;
            changed[column] = changed[column].add(M31.one());
            try std.testing.expect(rejected(changed));
        }
        for ([_]usize{ 0, air.WIDE_COLUMN, air.IO_COLUMN }) |column| {
            var changed = row;
            changed[column] = M31.fromCanonical(2);
            try std.testing.expect(rejected(changed));
        }
        var conflicting = row;
        conflicting[air.WIDE_COLUMN] = M31.one();
        conflicting[air.IO_COLUMN] = M31.one();
        try std.testing.expect(rejected(conflicting));
    }
    call.wide = true;
    try std.testing.expectError(error.InvalidPoseidonUniversalModeV1, air.fill(call));
    call.wide = false;
    call.input[7] = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidPoseidonUniversalInputV1, air.fill(call));
}

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

test "universal degree3 provider saves padded cells without raising quotient degree" {
    const variable = Degree{ .degree = 1 };
    var maximum: u32 = 0;
    for (air.evaluateGeneric(Degree, .{variable} ** air.N_MAIN_COLUMNS)) |value| maximum = @max(maximum, value.degree);
    try std.testing.expectEqual(@as(u32, 3), maximum);
    try std.testing.expectEqual(@as(usize, 303), air.N_MAIN_COLUMNS);
    try std.testing.expectEqual(@as(usize, 288), air.N_CONSTRAINTS);
    const saved_bytes = @as(u64, legacy.N_MAIN_COLUMNS - air.N_MAIN_COLUMNS) * (@as(u64, 1) << 18) * @sizeOf(M31);
    try std.testing.expectEqual(@as(u64, 142) << 20, saved_bytes);
    const Component = @import("poseidon2_universal_component_v1.zig").Component;
    const relations = relations_mod.Relations.dummy();
    const value = Component{ .log_size = 4, .n_rows = 3, .is_first_col_idx = 0, .is_active_col_idx = 0, .main_col_offset = 0, .interaction_col_offset = 0, .relations = &relations, .claims = .{ QM31.zero(), QM31.zero() } };
    try value.validate();
    const handle = value.asProverComponent();
    const verifier = value.asVerifierComponent();
    try std.testing.expectEqual(@as(usize, 290), handle.nConstraints());
    try std.testing.expectEqual(@as(usize, 290), verifier.nConstraints());
    var bounds = try handle.traceLogDegreeBounds(std.testing.allocator);
    defer {
        for (bounds.items) |tree| std.testing.allocator.free(tree);
        bounds.deinit(std.testing.allocator);
    }
    try std.testing.expectEqual(@as(usize, 1), bounds.items[0].len);
    try std.testing.expectEqual(@as(usize, 303), bounds.items[1].len);
}

test "universal degree3 verifier-only callbacks preserve point evaluation and reject short masks" {
    const Prover = @import("poseidon2_universal_component_v1.zig").Component;
    const relations = relations_mod.Relations.dummy();
    const native = Prover{ .log_size = 4, .n_rows = 3, .is_first_col_idx = 0, .is_active_col_idx = 0, .main_col_offset = 0, .interaction_col_offset = 0, .relations = &relations, .claims = .{ QM31.one(), QM31.fromU32Unchecked(3, 5, 7, 11) } };
    try checkVerifierPointCallbacks(native, @import("poseidon2_universal_equations_v1.zig"));
}

test "wide universal Poseidon verifier preserves retained native callbacks" {
    const Prover = @import("hash_component.zig").HashComponent;
    const relations = relations_mod.Relations.dummy();
    const native = Prover{ .kind = .poseidon2, .poseidon_shell = .universal, .log_size = 4, .n_rows = 3, .is_first_col_idx = 0, .is_active_col_idx = 0, .main_col_offset = 0, .interaction_col_offset = 0, .relations = &relations, .poseidon_claims = .{ QM31.one(), QM31.fromU32Unchecked(3, 5, 7, 11) } };
    try checkVerifierPointCallbacks(native, @import("poseidon2_wide_equations.zig"));
}

fn checkVerifierPointCallbacks(native: anytype, comptime Equations: type) !void {
    const Verifier = @import("poseidon2_degree3_verifier.zig").Component(Equations);
    try std.testing.expect(!@hasDecl(Verifier, "asProverComponent"));
    const allocator = std.testing.allocator;
    var detached: Verifier = undefined;
    inline for (std.meta.fields(Verifier)) |field| {
        @field(detached, field.name) = if (comptime std.mem.eql(u8, field.name, "claims") and @hasField(@TypeOf(native), "poseidon_claims")) native.poseidon_claims else @field(native, field.name);
    }
    const point = core.circle.SECURE_FIELD_CIRCLE_GEN.mul(29);
    var masks = try detached.asVerifierComponent().maskPoints(allocator, point, 5);
    defer masks.deinitDeep(allocator);
    var native_masks = try native.asVerifierComponent().maskPoints(allocator, point, 5);
    defer native_masks.deinitDeep(allocator);
    try std.testing.expectEqualDeep(native_masks.items, masks.items);
    try std.testing.expectEqual(native.asVerifierComponent().nConstraints(), detached.asVerifierComponent().nConstraints());
    try std.testing.expectEqual(native.asVerifierComponent().compositionLogSplit(), detached.asVerifierComponent().compositionLogSplit());

    const trees = try allocator.alloc([][]QM31, masks.items.len);
    var initialized: usize = 0;
    defer {
        for (trees[0..initialized]) |tree| {
            for (tree) |column| allocator.free(column);
            allocator.free(tree);
        }
        allocator.free(trees);
    }
    for (masks.items, trees) |points, *tree| {
        tree.* = try allocator.alloc([]QM31, points.len);
        var columns: usize = 0;
        errdefer {
            for (tree.*[0..columns]) |column| allocator.free(column);
            allocator.free(tree.*);
        }
        for (points, tree.*, 0..) |samples, *column, index| {
            column.* = try allocator.alloc(QM31, samples.len);
            for (column.*, 0..) |*value, sample| value.* = QM31.fromBase(M31.fromU64(1 + index * 3 + sample));
            columns += 1;
        }
        initialized += 1;
    }
    const values = core.air.components.MaskValues.initOwned(trees);
    var expected = core.air.accumulation.PointEvaluationAccumulator.init(QM31.fromU32Unchecked(5, 7, 11, 13));
    var actual = core.air.accumulation.PointEvaluationAccumulator.init(QM31.fromU32Unchecked(5, 7, 11, 13));
    try native.asVerifierComponent().evaluateConstraintQuotientsAtPoint(point, &values, &expected, 5);
    try detached.asVerifierComponent().evaluateConstraintQuotientsAtPoint(point, &values, &actual, 5);
    try std.testing.expectEqualDeep(expected.finalize(), actual.finalize());
    var short_trees = trees[0..3].*;
    short_trees[1] = short_trees[1][0 .. short_trees[1].len - 1];
    const short = core.air.components.MaskValues.initOwned(&short_trees);
    try std.testing.expectError(error.InvalidProofShape, detached.asVerifierComponent().evaluateConstraintQuotientsAtPoint(point, &short, &actual, 5));
    detached.log_size = 30;
    try std.testing.expectError(error.InvalidPoseidonNarrowComponentV1, detached.validate());
}
