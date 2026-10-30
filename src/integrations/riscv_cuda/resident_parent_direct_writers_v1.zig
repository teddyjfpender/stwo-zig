//! Pure original parent row constructors lowered mechanically by Zig's C backend.
//! Fixed tails are independently admitted schedule metadata; dynamic words are
//! device wire values. Every decoded schedule round-trips through the original
//! constructor before any final MAIN store. No second AIR/witness arithmetic.
const std = @import("std");
const core = @import("stwo_core");
const Storage = @import("../../frontends/riscv/recursion/air/blake3_parent_row_storage.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const IW = @import("../../frontends/riscv/recursion/air/qm31_inv_witness.zig");
const LW = @import("../../frontends/riscv/recursion/air/linear_ops_witness.zig");
pub const indices = [_]usize{ 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19 };
pub fn dynamicCount(comptime i: usize) usize {
    return switch (i) {
        2, 4, 10, 11 => 4,
        3 => 12,
        5, 6, 7 => 8,
        8, 9, 12 => 1,
        13, 15 => 3,
        14 => 10,
        16 => 4,
        17 => 2,
        18 => 40,
        19 => 28,
        else => @compileError("unsupported parent writer"),
    };
}
pub fn fixedCount(comptime i: usize) usize {
    const A = Storage.Airs[i];
    return A.LOGICAL_INPUT_COUNT - A.PHYSICAL_MAIN_COLUMN_COUNT;
}
pub const supported_air_indices = indices;
pub const dynamicWordCount = dynamicCount;
/// Validate schedule by an original constructor with a legal neutral input;
/// no dynamic values are derived or returned as proving authority.
pub fn fixedRow(comptime i: usize, p: []const u32) !Storage.Airs[i].Row {
    if (p.len != fixedCount(i)) return error.InvalidParentWriterInput;
    var d: [dynamicCount(i)]u32 = @splat(0);
    if (i == 4) d[0] = 1;
    if (i == 2 and p[0] == 1) @memcpy(&d, p[4..8]);
    var r = try row(i, p, &d);
    @memset(r[0..Storage.Airs[i].PHYSICAL_MAIN_COLUMN_COUNT], M.zero());
    return r;
}
fn field(x: u32) !M {
    if (x >= core.fields.m31.Modulus) return error.InvalidParentWriterInput;
    return M.fromCanonical(x);
}
fn bit(x: u32) !u1 {
    if (x > 1) return error.InvalidParentWriterInput;
    return @intCast(x);
}
fn fields(comptime n: usize, x: []const u32) ![n]M {
    var r: [n]M = undefined;
    for (&r, x[0..n]) |*v, w| v.* = try field(w);
    return r;
}
fn q(x: []const u32) !Q {
    return Q.fromM31Array(try fields(4, x));
}
fn endpoint(comptime T: type, p: []const u32) T {
    return .{ .circuit = p[0], .wire = p[1] };
}
fn caller(comptime T: type, p: []const u32) T {
    return .{ .circuit = p[0], .first_wire = p[1] };
}
fn inversionSchedule(p: []const u32) !?IW.CircuitMetadata {
    if (try bit(p[0]) == 0) return null;
    return .{ .circuit_id = try field(p[1]), .node_id = try field(p[2]), .lhs_id = try field(p[3]), .uses = try field(p[4]) };
}
fn linearSchedule(p: []const u32) !?LW.ScheduleRow {
    if (try bit(p[0]) == 0) return null;
    if (@as(u32, try bit(p[3])) + try bit(p[4]) + try bit(p[5]) != 1) return error.InvalidParentWriterSchedule;
    const op: LW.Operation = if (p[3] == 1) .add else if (p[4] == 1) .sub else .neg;
    if (op == .neg and p[7] != 0) return error.InvalidParentWriterSchedule;
    return .{ .operation = op, .circuit = .{ .circuit_id = try field(p[1]), .node_id = try field(p[2]), .lhs_id = try field(p[6]), .rhs_id = try field(p[7]), .uses = try field(p[8]) } };
}
pub fn row(comptime i: usize, p: []const u32, d: []const u32) !Storage.Airs[i].Row {
    const A = Storage.Airs[i];
    if (p.len != fixedCount(i) or d.len != dynamicCount(i)) return error.InvalidParentWriterInput;
    for (p) |w| _ = try field(w);
    var result: A.Row = switch (i) {
        2 => if (try bit(p[0]) == 1) try A.logicalCoordinates(p[1], p[2], try field(p[3]), try fields(4, d)) else try A.privateCoordinates(p[1], p[2], try field(p[3]), try fields(4, d)),
        3 => blk: {
            const operation: A.Operation = if (p[7] == 0) .multiply else if (p[8] == core.fields.m31.Modulus - 1) .addend_minus_product else if (p[9] == core.fields.m31.Modulus - 1) .product_plus_addend else .product_minus_addend;
            break :blk try A.logicalRow(.{ .circuit = p[1], .output = p[2], .lhs = p[3], .rhs = p[4], .addend = p[5], .uses = p[6], .operation = operation }, try q(d[0..4]), try q(d[4..8]), try q(d[8..12]));
        },
        4 => blk: {
            const schedule = IW.PreprocessedRow{ .segment = try inversionSchedule(p[0..5]), .binary = try inversionSchedule(p[5..10]), .empty = try inversionSchedule(p[10..15]) };
            const selected = schedule.segment orelse return error.InvalidParentWriterSchedule;
            break :blk IW.logicalInputs(try IW.mainRow(.{ .a = try q(d), .circuit = selected }), IW.preprocessedRow(schedule), .segment_leaf);
        },
        5 => blk: {
            const schedule = LW.PreprocessedRow{ .segment = try linearSchedule(p[0..9]), .binary = try linearSchedule(p[9..18]), .empty = try linearSchedule(p[18..27]) };
            const selected = schedule.segment orelse return error.InvalidParentWriterSchedule;
            break :blk LW.logicalInputs(try LW.mainRow(.{ .operation = selected.operation, .lhs = try q(d[0..4]), .rhs = try q(d[4..8]), .circuit = selected.circuit }), LW.preprocessedRow(schedule), .segment_leaf);
        },
        6 => try A.logicalRow(.{ .source_circuit = p[1], .source_first = p[2], .destination_circuit = p[3], .destination_first = p[4], .uses = p[5..13].*, .status_wire = p[13], .status_uses = p[14] }, d[0..8].*),
        7 => blk: {
            var schedule: A.AffineSchedule = .{ .sources = .{ null, null }, .destination = .{ .circuit = p[6], .wire = p[7] }, .uses = p[8], .constants = try fields(4, p[9..13]) };
            for (0..2) |j| if (try bit(p[j]) == 1) {
                schedule.sources[j] = .{ .circuit = p[2 + 2 * j], .wire = p[3 + 2 * j] };
            };
            for (0..4) |j| schedule.coefficients[j] = try fields(8, p[13 + j * 8 ..][0..8]);
            break :blk try A.logicalAffine(schedule, .{ try fields(4, d[0..4]), try fields(4, d[4..8]) });
        },
        8 => blk: {
            var mask: u32 = 0;
            for (0..4) |j| {
                if (p[6 + j] > 255) return error.InvalidParentWriterInput;
                mask |= p[6 + j] << @as(u5, @intCast(8 * j));
            }
            var log: u32 = 0;
            var rest = mask;
            while (rest & 1 == 1) {
                log += 1;
                rest >>= 1;
            }
            if (rest != 0 or log > 32) return error.InvalidParentWriterInput;
            break :blk try A.logicalLowBitsRow(.{ .source_circuit = p[1], .source_wire = p[2], .destination_circuit = p[3], .destination_wire = p[4], .uses = p[5], .log_domain_size = log }, d[0]);
        },
        9 => try A.logicalRow(p[1], p[2], p[3], d[0]),
        10 => try A.logicalRow(.{ .source_circuit = p[1], .source_wire = p[2], .destination_circuit = p[3], .destination_first = p[4], .uses = p[5..9].* }, try q(d)),
        11 => try A.weightedLogicalRow(.{ .source_circuit = p[1], .source_nodes = p[2..6].*, .destination_circuit = p[6], .destination_wire = p[7] }, try q(d), p[0]),
        12 => if (try bit(p[5]) == 0) try A.logicalRow(p[0], p[1], p[2], try field(d[0])) else try A.routedRow(p[0], p[1], p[2], p[3], p[4], try field(d[0])),
        13 => try A.logicalRow(.{ .bit = endpoint(A.Endpoint, p[1..3]), .current = endpoint(A.Endpoint, p[3..5]), .sibling = endpoint(A.Endpoint, p[5..7]), .destination_circuit = p[7], .left_wire = p[8], .right_wire = p[9], .left_uses = p[10], .right_uses = p[11] }, try bit(d[0]), d[1], d[2]),
        14 => blk: {
            var n: u4 = 0;
            for (p[12..20]) |v| n += try bit(v);
            break :blk try A.logicalRow(.{ .pending = endpoint(A.Endpoint, p[1..3]), .status = endpoint(A.Endpoint, p[3..5]), .next_pending = endpoint(A.Endpoint, p[5..7]), .next_uses = p[7], .values = caller(A.Caller, p[8..10]), .destination = caller(A.Caller, p[10..12]), .count_wire = p[20], .ordinal = p[21], .words = n }, try bit(d[0]), try bit(d[1]), try fields(8, d[2..10]));
        },
        15 => try A.logicalRow(.{ .source = caller(A.Caller, p[1..3]), .increment = endpoint(A.Endpoint, p[3..5]), .destination = caller(A.Caller, p[5..7]), .uses = p[7..9].* }, @as(u64, d[0]) | (@as(u64, d[1]) << 32), try bit(d[2])),
        16 => try A.logicalRow(.{ .table = p[2], .chain = p[3], .rank = p[4], .last = try bit(p[5]) == 0 }, .{ .index = d[0], .value = try field(d[1]) }, .{ .index = d[2], .value = try field(d[3]) }),
        17 => try A.logicalRow(.{ .index = endpoint(A.Endpoint, p[1..3]), .value = endpoint(A.Endpoint, p[3..5]), .table = p[5] }, d[0], try field(d[1])),
        18 => blk: {
            var lhs: [4]Q = undefined;
            var rhs: [4]Q = undefined;
            for (0..4) |j| {
                lhs[j] = try q(d[4 + j * 4 ..][0..4]);
                rhs[j] = try q(d[20 + j * 4 ..][0..4]);
            }
            break :blk try A.logicalRow(.{ .circuit = p[1], .accumulator = p[2], .lhs = p[3..7].*, .rhs = p[7..11].*, .output = p[11], .uses = p[12] }, try q(d[0..4]), lhs, rhs, try q(d[36..40]));
        },
        19 => blk: {
            var weights: [4]Q = undefined;
            for (0..4) |j| weights[j] = try q(d[8 + j * 4 ..][0..4]);
            break :blk try A.logicalRow(.{ .circuit = p[1], .accumulator = p[2], .queries = p[3..7].*, .weights = p[7..11].*, .output = p[11], .uses = p[12] }, try q(d[0..4]), try fields(4, d[4..8]), weights, try q(d[24..28]));
        },
        else => @compileError("unsupported parent writer"),
    };
    // Namespace relocation can change inactive circuit identifiers. Their AIR
    // branch mask is zero; preserve the independently fixed bytes exactly while
    // the selected segment still round-trips through the original constructor.
    if (i == 4 or i == 5) {
        const stride: usize = if (i == 4) 5 else 9;
        for (1..3) |branch| if (p[branch * stride] == 0) {
            for (1..stride) |j| result[A.PHYSICAL_MAIN_COLUMN_COUNT + branch * stride + j] = try field(p[branch * stride + j]);
        };
    }
    for (result[A.PHYSICAL_MAIN_COLUMN_COUNT..], p) |actual, expected| if (actual.toU32() != expected) return error.InvalidParentWriterSchedule;
    return result;
}
pub fn Writer(comptime i: usize) type {
    return struct {
        pub fn input() callconv(.c) u32 {
            return @intCast(dynamicCount(i));
        }
        pub fn fixed() callconv(.c) u32 {
            return @intCast(fixedCount(i));
        }
        pub fn width() callconv(.c) u32 {
            return Storage.Airs[i].PHYSICAL_MAIN_COLUMN_COUNT;
        }
        pub fn logical(p: [*]const u32, d: [*]const u32, out: [*]u32) callconv(.c) u32 {
            const r = row(i, p[0..fixedCount(i)], d[0..dynamicCount(i)]) catch return 1;
            for (r, 0..) |v, j| out[j] = v.toU32();
            return 0;
        }
        pub fn run(p: [*]const u32, d: [*]const u32, out: [*]u32, stride: usize, index: usize) callconv(.c) u32 {
            if (stride < 2 or stride & (stride - 1) != 0 or index >= stride or stride > std.math.maxInt(usize) / Storage.Airs[i].PHYSICAL_MAIN_COLUMN_COUNT) return 3;
            const r = row(i, p[0..fixedCount(i)], d[0..dynamicCount(i)]) catch return 1;
            const physical = @import("../../frontends/riscv/recursion/air/framework_interaction.zig").committedRow(index, @intCast(@ctz(stride)));
            for (r[0..Storage.Airs[i].PHYSICAL_MAIN_COLUMN_COUNT], 0..) |value, column| out[column * stride + physical] = value.toU32();
            return 0;
        }
    };
}
pub fn exportDeviceWriters() void {
    comptime {
        for (indices, .{ "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19" }) |i, name| {
            @export(&Writer(i).run, .{ .name = "stwo_parent_direct_row_" ++ name ++ "_v1" });
            @export(&Writer(i).logical, .{ .name = "stwo_parent_direct_logical_" ++ name ++ "_v1" });
            @export(&Writer(i).input, .{ .name = "stwo_parent_direct_input_" ++ name ++ "_v1" });
            @export(&Writer(i).fixed, .{ .name = "stwo_parent_direct_fixed_" ++ name ++ "_v1" });
            @export(&Writer(i).width, .{ .name = "stwo_parent_direct_width_" ++ name ++ "_v1" });
        }
    }
}

test "resident direct inverse preserves relocated inactive namespace with exact active tail" {
    const p = [_]u32{ 1, 2, 787, 786, 2, 1, 3, 787, 786, 2, 0, 1, 0, 0, 0, 1, 0, 0 };
    const r = try row(4, &p, &.{ 1, 0, 0, 0 });
    for (r[Storage.Airs[4].PHYSICAL_MAIN_COLUMN_COUNT..], p) |v, w| try std.testing.expectEqual(w, v.v);
    var bad = p;
    bad[15] = 0;
    try std.testing.expectError(error.InvalidParentWriterSchedule, row(4, &bad, &.{ 1, 0, 0, 0 }));
}
