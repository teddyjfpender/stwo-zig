//! Conservative admission for nonwrapping u64 table accumulation. Each original
//! signed M31 weight is accumulated as its canonical residue, then reduced once.
const std = @import("std");
const core = @import("stwo_core");
pub const MODULUS: u64 = core.fields.m31.Modulus;
pub const MAX_REQUESTS: u64 = std.math.maxInt(u64) / (MODULUS - 1);
pub fn admitted(requests: [2]u128) bool {
    for (requests) |count| if (count > MAX_REQUESTS) return false;
    return true;
}
pub fn reduce(value: u64) u32 {
    return @intCast(value % MODULUS);
}
pub fn requestBounds(programs: anytype, cohorts: anytype) [2]u128 {
    var out: [2]u128 = @splat(0);
    for (programs, cohorts) |p, c| for (p.entries) |e| {
        const index: usize = if (e.domain == 6) 0 else if (e.domain == 10) 1 else continue;
        out[index] += @as(u128, 1) << @intCast(c.trace_log);
    };
    return out;
}
test "resident wide counters exact signed modular sums and admission cliff" {
    const M = core.fields.m31.M31;
    var rng = std.Random.DefaultPrng.init(0x1239876654);
    var sums: [17]u64 = @splat(0);
    var scalar: [17]M = @splat(M.zero());
    for (0..50000) |i| {
        const index = rng.random().uintLessThan(usize, 17);
        const value: u32 = switch (i % 5) {
            0 => @intCast(MODULUS - 1),
            1 => 0,
            2 => 1,
            else => rng.random().uintLessThan(u32, @intCast(MODULUS)),
        };
        sums[index] += value;
        scalar[index] = scalar[index].add(M.fromCanonical(value));
    }
    for (sums, scalar) |wide, expected| try std.testing.expectEqual(expected.v, reduce(wide));
    try std.testing.expect(admitted(.{ MAX_REQUESTS, MAX_REQUESTS }));
    try std.testing.expect(!admitted(.{ @as(u128, MAX_REQUESTS) + 1, 0 }));
    try std.testing.expect(!admitted(.{ 0, @as(u128, MAX_REQUESTS) + 1 }));
    try std.testing.expectEqual(@as(u32, @intCast((@as(u128, std.math.maxInt(u64))) % @as(u128, MODULUS))), reduce(std.math.maxInt(u64)));
    const max_sum = MAX_REQUESTS * (MODULUS - 1);
    try std.testing.expectEqual(@as(u32, @intCast((@as(u128, MAX_REQUESTS) * @as(u128, MODULUS - 1)) % @as(u128, MODULUS))), reduce(max_sum));
}
