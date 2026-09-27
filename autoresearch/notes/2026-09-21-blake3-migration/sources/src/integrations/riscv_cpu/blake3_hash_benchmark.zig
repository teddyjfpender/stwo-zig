//! Diagnostic native hash timings. These are not complete proof timings.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const Blake3 = core.vcs_lifted.blake3_merkle.MerkleHasher;
const Poseidon = @import("stwo_riscv_frontend").recursion.poseidon2_channel.MerkleHasher;
const iterations = 2048;
var checksum: u64 = 0;
fn leaves(comptime H: type, values: []M31) !u64 {
    var timer = try std.time.Timer.start();
    for (0..iterations) |i| {
        values[0] = M31.fromCanonical(@intCast(i));
        var h = H.defaultWithInitialState();
        h.updateLeaf(values);
        const digest = h.finalize();
        checksum +%= @intCast(digest[0]);
    }
    return timer.read();
}
fn nodes(comptime H: type) !u64 {
    var timer = try std.time.Timer.start();
    var left: H.Hash = @splat(0);
    const right: H.Hash = @splat(1);
    for (0..iterations) |_| left = H.hashChildren(.{ .left = left, .right = right });
    checksum +%= @intCast(left[0]);
    return timer.read();
}
pub fn main() !void {
    var values: [4096]M31 = @splat(M31.one());
    // Warm both paths before ABBA-order repeated samples.
    _ = try leaves(Blake3, values[0..16]);
    _ = try leaves(Poseidon, values[0..16]);
    for (0..6) |round| {
        for ([_]usize{ 16, 256, 4096 }) |len| {
            var blake_ns: u64 = undefined;
            var poseidon_ns: u64 = undefined;
            if (round % 2 == 0) {
                poseidon_ns = try leaves(Poseidon, values[0..len]);
                blake_ns = try leaves(Blake3, values[0..len]);
            } else {
                blake_ns = try leaves(Blake3, values[0..len]);
                poseidon_ns = try leaves(Poseidon, values[0..len]);
            }
            std.debug.print("{{\"kind\":\"leaf\",\"round\":{d},\"m31_words\":{d},\"iterations\":{d},\"poseidon_ns\":{d},\"blake3_ns\":{d}}}\n", .{ round, len, iterations, poseidon_ns, blake_ns });
        }
        var b: u64 = undefined;
        var p: u64 = undefined;
        if (round % 2 == 0) {
            p = try nodes(Poseidon);
            b = try nodes(Blake3);
        } else {
            b = try nodes(Blake3);
            p = try nodes(Poseidon);
        }
        std.debug.print("{{\"kind\":\"node\",\"round\":{d},\"iterations\":{d},\"poseidon_ns\":{d},\"blake3_ns\":{d}}}\n", .{ round, iterations, p, b });
    }
    std.debug.print("{{\"checksum\":{d}}}\n", .{checksum});
}
