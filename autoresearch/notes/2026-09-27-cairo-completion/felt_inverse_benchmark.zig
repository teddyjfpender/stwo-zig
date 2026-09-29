const std = @import("std");
const felt = @import("felt252");

fn reference(value: u256) u256 {
    var exponent = felt.prime - 2;
    var factor = value;
    var result: u256 = 1;
    while (exponent != 0) : (exponent >>= 1) {
        if (exponent & 1 != 0) result = felt.mul(result, factor);
        factor = felt.mul(factor, factor);
    }
    return result;
}

const Measurement = struct { ns: u64, checksum: u256 };
fn measure(comptime optimized: bool, values: []const u256) !Measurement {
    const started = try std.time.Instant.now();
    var checksum: u256 = 0;
    for (values) |value| checksum ^= if (optimized) try felt.div(1, value) else reference(value);
    return .{ .ns = (try std.time.Instant.now()).since(started), .checksum = checksum };
}

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const values = try allocator.alloc(u256, 1024);
    defer allocator.free(values);
    var random = std.Random.DefaultPrng.init(0xca110);
    for (values) |*value| value.* = random.random().int(u256) % (felt.prime - 1) + 1;
    const Trial = struct { reference_ns: u64, optimized_ns: u64, checksum_match: bool };
    var trials: [5]Trial = undefined;
    for (&trials, 0..) |*trial, index| {
        const first = if (index & 1 == 0) try measure(false, values) else try measure(true, values);
        const second = if (index & 1 == 0) try measure(true, values) else try measure(false, values);
        const old = if (index & 1 == 0) first else second;
        const new = if (index & 1 == 0) second else first;
        if (old.checksum != new.checksum) return error.ArithmeticMismatch;
        trial.* = .{ .reference_ns = old.ns, .optimized_ns = new.ns, .checksum_match = true };
    }
    var storage: [8192]u8 = undefined;
    var writer = std.fs.File.stdout().writer(&storage);
    try std.json.Stringify.value(.{ .schema = "cairo-felt-inversion-pair-v1", .values_per_trial = values.len, .trials = trials }, .{}, &writer.interface);
    try writer.interface.writeByte('\n');
    try writer.interface.flush();
}
