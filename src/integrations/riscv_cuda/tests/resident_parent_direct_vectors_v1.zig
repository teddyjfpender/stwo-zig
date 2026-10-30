const std = @import("std");
const core = @import("stwo_core");
const W = @import("../resident_parent_direct_writers_v1.zig");
const Storage = @import("../../../frontends/riscv/recursion/air/blake3_parent_row_storage.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const IW = @import("../../../frontends/riscv/recursion/air/qm31_inv_witness.zig");
const LW = @import("../../../frontends/riscv/recursion/air/linear_ops_witness.zig");
fn input(comptime i: usize, seed: u32) [W.dynamicCount(i)]u32 {
    var d: [W.dynamicCount(i)]u32 = undefined;
    for (&d, 0..) |*x, j| x.* = @intCast((seed * 17 + @as(u32, @intCast(j)) * 31 + 1) % 251);
    switch (i) {
        3 => {},
        8, 9 => d[0] = 0xfedcba98 - seed,
        13 => {
            d[0] = seed % 2;
            d[1] = 0xfedcba98;
            d[2] = 0x12345678;
        },
        14 => {
            d[0] = seed % 2;
            d[1] = (seed / 2) % 2;
        },
        15 => {
            d[0] = 0xfffffff0 + seed;
            d[1] = 13;
            d[2] = 1;
        },
        16 => {
            d[0] = 30;
            d[1] = 2;
            d[2] = 35 + seed;
            d[3] = 17;
        },
        17 => d[0] = 0xabcdef00 + seed,
        else => {},
    }
    return d;
}
fn q(x: []const u32) Q {
    return Q.fromU32Unchecked(x[0], x[1], x[2], x[3]);
}
fn ms(comptime n: usize, x: []const u32) [n]M {
    var r: [n]M = undefined;
    for (&r, x[0..n]) |*v, w| v.* = M.fromCanonical(w);
    return r;
}
fn fixture(comptime i: usize, d: []const u32) !Storage.Airs[i].Row {
    const A = Storage.Airs[i];
    return switch (i) {
        2 => try A.privateCoordinates(7, 8, M.one().neg(), ms(4, d)),
        3 => try A.logicalRow(.{ .circuit = 7, .output = 12, .lhs = 3, .rhs = 4, .addend = 5, .uses = 2, .operation = .product_plus_addend }, q(d[0..4]), q(d[4..8]), q(d[8..12])),
        4 => blk: {
            const m = IW.CircuitMetadata{ .circuit_id = M.fromCanonical(7), .node_id = M.fromCanonical(12), .lhs_id = M.fromCanonical(3), .uses = M.one() };
            break :blk IW.logicalInputs(try IW.mainRow(.{ .a = q(d), .circuit = m }), IW.preprocessedRow(.{ .segment = m, .binary = .{ .circuit_id = M.fromCanonical(29), .node_id = M.fromCanonical(31), .lhs_id = M.fromCanonical(17), .uses = M.fromCanonical(3) }, .empty = m }), .segment_leaf);
        },
        5 => blk: {
            const m = LW.CircuitMetadata{ .circuit_id = M.fromCanonical(7), .node_id = M.fromCanonical(12), .lhs_id = M.fromCanonical(3), .rhs_id = M.fromCanonical(4), .uses = M.one() };
            break :blk LW.logicalInputs(try LW.mainRow(.{ .operation = .sub, .lhs = q(d[0..4]), .rhs = q(d[4..8]), .circuit = m }), LW.preprocessedRow(.{ .segment = .{ .operation = .sub, .circuit = m }, .binary = .{ .operation = .add, .circuit = m }, .empty = .{ .operation = .sub, .circuit = m } }), .segment_leaf);
        },
        6 => try A.logicalRow(.{ .source_circuit = 1, .source_first = 2, .destination_circuit = 3, .destination_first = 4, .uses = .{ 1, 2, 3, 4, 5, 6, 7, 8 }, .status_wire = 15, .status_uses = 2 }, d[0..8].*),
        7 => blk: {
            var schedule: A.AffineSchedule = .{ .sources = .{ .{ .circuit = 1, .wire = 2 }, .{ .circuit = 3, .wire = 4 } }, .destination = .{ .circuit = 5, .wire = 6 }, .uses = 2, .constants = .{ M.fromCanonical(300), M.one().neg(), M.zero(), M.one() } };
            schedule.coefficients[0][0] = M.fromCanonical(257);
            schedule.coefficients[0][7] = M.one().neg();
            schedule.coefficients[1][5] = M.fromCanonical(31);
            schedule.coefficients[2][3] = M.one();
            break :blk try A.logicalAffine(schedule, .{ ms(4, d[0..4]), ms(4, d[4..8]) });
        },
        8 => try A.logicalLowBitsRow(.{ .source_circuit = 1, .source_wire = 2, .destination_circuit = 3, .destination_wire = 4, .uses = 2, .log_domain_size = 32 }, d[0]),
        9 => try A.logicalRow(1, 2, 3, d[0]),
        10 => try A.logicalRow(.{ .source_circuit = 1, .source_wire = 2, .destination_circuit = 3, .destination_first = 4, .uses = .{ 1, 2, 3, 4 } }, q(d)),
        11 => try A.weightedLogicalRow(.{ .source_circuit = 1, .source_nodes = .{ 2, 3, 4, 5 }, .destination_circuit = 6, .destination_wire = 7 }, q(d), 3),
        12 => try A.routedRow(1, 2, 3, 4, 5, M.fromCanonical(d[0])),
        13 => try A.logicalRow(.{ .bit = .{ .circuit = 1, .wire = 2 }, .current = .{ .circuit = 3, .wire = 4 }, .sibling = .{ .circuit = 5, .wire = 6 }, .destination_circuit = 7, .left_wire = 8, .right_wire = 9, .left_uses = 1, .right_uses = 2 }, @intCast(d[0]), d[1], d[2]),
        14 => try A.logicalRow(.{ .pending = .{ .circuit = 1, .wire = 2 }, .status = .{ .circuit = 3, .wire = 4 }, .next_pending = .{ .circuit = 1, .wire = 5 }, .values = .{ .circuit = 6, .first_wire = 7 }, .destination = .{ .circuit = 8, .first_wire = 9 }, .count_wire = 20, .ordinal = 2, .words = 4 }, @intCast(d[0]), @intCast(d[1]), ms(8, d[2..10])),
        15 => try A.logicalRow(.{ .source = .{ .circuit = 1, .first_wire = 2 }, .increment = .{ .circuit = 3, .wire = 4 }, .destination = .{ .circuit = 5, .first_wire = 6 }, .uses = .{ 2, 3 } }, @as(u64, d[0]) | (@as(u64, d[1]) << 32), @intCast(d[2])),
        16 => try A.logicalRow(.{ .table = 1, .chain = 2, .rank = 3, .last = false }, .{ .index = d[0], .value = M.fromCanonical(d[1]) }, .{ .index = d[2], .value = M.fromCanonical(d[3]) }),
        17 => try A.logicalRow(.{ .index = .{ .circuit = 1, .wire = 2 }, .value = .{ .circuit = 3, .wire = 4 }, .table = 5 }, d[0], M.fromCanonical(d[1])),
        18 => blk: {
            var lhs: [4]Q = undefined;
            var rhs: [4]Q = undefined;
            for (0..4) |j| {
                lhs[j] = q(d[4 + j * 4 ..]);
                rhs[j] = q(d[20 + j * 4 ..]);
            }
            break :blk try A.logicalRow(.{ .circuit = 1, .accumulator = 2, .lhs = .{ 3, 4, 5, 6 }, .rhs = .{ 7, 8, 9, 10 }, .output = 11, .uses = 2 }, q(d), lhs, rhs, q(d[36..]));
        },
        19 => blk: {
            var weights: [4]Q = undefined;
            for (0..4) |j| weights[j] = q(d[8 + j * 4 ..]);
            break :blk try A.logicalRow(.{ .circuit = 1, .accumulator = 2, .queries = .{ 3, 4, 5, 6 }, .weights = .{ 7, 8, 9, 10 }, .output = 11, .uses = 2 }, q(d), ms(4, d[4..8]), weights, q(d[24..]));
        },
        else => unreachable,
    };
}
fn word(bytes: *std.ArrayList(u8), x: u32) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, x, .little);
    try bytes.appendSlice(std.testing.allocator, &b);
}
test "resident parent direct all original constructors and physical padding vectors" {
    const a = std.testing.allocator;
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(a);
    try word(&bytes, 0x50335257);
    try word(&bytes, W.indices.len);
    inline for (W.indices) |i| {
        const A = Storage.Airs[i];
        const count = 3;
        const rows = 8;
        const width = A.PHYSICAL_MAIN_COLUMN_COUNT;
        var pp: [count][W.fixedCount(i)]u32 = undefined;
        var dd: [count][W.dynamicCount(i)]u32 = undefined;
        var expected: [width * rows]u32 = @splat(0);
        var actual: [width * rows]u32 = @splat(0);
        for (0..count) |j| {
            dd[j] = input(i, @intCast(j));
            const original = try fixture(i, &dd[j]);
            for (original[width..], &pp[j]) |v, *out| out.* = v.toU32();
            try std.testing.expectEqualDeep(original, try W.row(i, &pp[j], &dd[j]));
            var logical: [A.LOGICAL_INPUT_COUNT]u32 = undefined;
            try std.testing.expectEqual(@as(u32, 0), W.Writer(i).logical(&pp[j], &dd[j], &logical));
            for (original, logical) |v, w| try std.testing.expectEqual(v.toU32(), w);
            const trusted = try W.fixedRow(i, &pp[j]);
            try std.testing.expectEqualSlices(M, original[width..], trusted[width..]);
            const at = @import("../../../frontends/riscv/recursion/air/framework_interaction.zig").committedRow(j, 3);
            for (original[0..width], 0..) |v, k| expected[k * rows + at] = v.toU32();
            try std.testing.expectEqual(@as(u32, 0), W.Writer(i).run(&pp[j], &dd[j], &actual, rows, j));
        }
        try std.testing.expectEqualSlices(u32, &expected, &actual);
        inline for (.{ i, rows, count, W.fixedCount(i), W.dynamicCount(i), width }) |n| try word(&bytes, @intCast(n));
        for (pp) |r| for (r) |x| {
            try word(&bytes, x);
        };
        for (dd) |r| for (r) |x| {
            try word(&bytes, x);
        };
        for (expected) |x| try word(&bytes, x);
        var hostile = pp[0];
        hostile[0] = core.fields.m31.Modulus;
        try std.testing.expectError(error.InvalidParentWriterInput, W.row(i, &hostile, &dd[0]));
    }
    const path = std.process.getEnvVarOwned(a, "STWO_PARENT_DIRECT_VECTORS") catch return;
    defer a.free(path);
    var f = try std.fs.cwd().createFile(path, .{});
    defer f.close();
    try f.writeAll(bytes.items);
}
