const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const H = core.vcs_lifted.poseidon2_profile.Om31V2.MerkleHasher;
const B = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
fn scalar(comptime Hasher: type, values: []M, n: usize) !u64 {
    var timer = try std.time.Timer.start();
    for (0..n) |i| {
        values[0] = M.fromCanonical(@intCast(i + 17));
        var h = Hasher.defaultWithInitialState();
        h.updateLeaf(values);
        std.mem.doNotOptimizeAway(h.finalize());
    }
    return timer.read();
}
pub fn main() !void {
    var storage: [497]M = undefined;
    for (&storage, 0..) |*x, i| x.* = M.fromCanonical(@intCast(i * 137 + 42));
    var bytes: [4][497 * 4]u8 = undefined;
    for (&bytes, 0..) |*row, lane| for (storage, 0..) |value, i| std.mem.writeInt(u32, row[4 * i ..][0..4], value.v + @as(u32, @intCast(lane)), .little);
    for ([_]usize{ 16, 53, 128, 497 }) |cols| {
        const b = try scalar(B, storage[0..cols], 4096);
        const p = try scalar(H, storage[0..cols], 4096);
        var messages: [4][]const u8 = undefined;
        for (&messages, 0..) |*m, lane| m.* = bytes[lane][0 .. 4 * cols];
        var timer = try std.time.Timer.start();
        for (0..1024) |i| {
            std.mem.writeInt(u32, bytes[0][0..4], @intCast(i + 17), .little);
            std.mem.doNotOptimizeAway(H.hashPackedLeavesWithSeed4(H.leafSeed(), &messages));
        }
        const packed_ns = timer.read();
        std.debug.print("columns={} blake_ns={} scalar_p2_ns={} packed4_p2_ns={} packed_gain={d:.2} vs_blake={d:.2}\n", .{ cols, b, p, packed_ns, @as(f64, @floatFromInt(p)) / @as(f64, @floatFromInt(packed_ns)), @as(f64, @floatFromInt(packed_ns)) / @as(f64, @floatFromInt(b)) });
    }
}
