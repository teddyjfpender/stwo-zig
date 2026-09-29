//! Compare canonical operands, including all representation conversion costs.
const std = @import("std");
const felt = @import("felt252");
fn wide(lhs: u256, rhs: u256) u256 {
    return @intCast((@as(u512, lhs) * rhs) % @as(u512, felt.prime));
}

const Pair = struct { lhs: u256, rhs: u256 };
fn native(lhs: u256, rhs: u256) u256 {
    return felt.mul(lhs, rhs);
}
const Measurement = struct { ns: u64, checksum: u256 };
fn measure(comptime optimized: bool, values: []const Pair) !Measurement {
    var timer = try std.time.Timer.start();
    var checksum: u256 = 0;
    for (values) |pair| checksum ^= if (optimized) native(pair.lhs, pair.rhs) else wide(pair.lhs, pair.rhs);
    return .{ .ns = timer.read(), .checksum = checksum };
}

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const values = try allocator.alloc(Pair, 65536);
    defer allocator.free(values);
    var random = std.Random.DefaultPrng.init(0xca110);
    const boundaries = [_]u256{ 0, 1, 2, (1 << 64) - 1, 1 << 128, 1 << 192, felt.prime / 2, felt.prime - 1 };
    for (boundaries) |lhs| for (boundaries) |rhs| {
        if (native(lhs, rhs) != wide(lhs, rhs)) return error.ArithmeticMismatch;
    };
    for (values) |*pair| {
        pair.* = .{ .lhs = random.random().int(u256) % felt.prime, .rhs = random.random().int(u256) % felt.prime };
        if (native(pair.lhs, pair.rhs) != wide(pair.lhs, pair.rhs)) return error.ArithmeticMismatch;
    }
    const Trial = struct { wide_modulo_ns: u64, standard_field_ns: u64, checksum_match: bool };
    var trials: [5]Trial = undefined;
    for (&trials, 0..) |*trial, index| {
        const first = if (index & 1 == 0) try measure(false, values) else try measure(true, values);
        const second = if (index & 1 == 0) try measure(true, values) else try measure(false, values);
        const old = if (index & 1 == 0) first else second;
        const new = if (index & 1 == 0) second else first;
        if (old.checksum != new.checksum) return error.ArithmeticMismatch;
        trial.* = .{ .wide_modulo_ns = old.ns, .standard_field_ns = new.ns, .checksum_match = true };
    }
    var storage: [8192]u8 = undefined;
    var writer = std.fs.File.stdout().writer(&storage);
    try std.json.Stringify.value(.{ .schema = "cairo-felt-multiplication-pair-v1", .values_per_trial = values.len, .canonical_conversion_included = true, .trials = trials }, .{}, &writer.interface);
    try writer.interface.writeByte('\n');
    try writer.interface.flush();
}
