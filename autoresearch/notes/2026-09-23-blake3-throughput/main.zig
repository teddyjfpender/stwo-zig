//! Isolated native hashing, not an E2E proving benchmark.
const std = @import("std");
const core = @import("stwo_core");
const batch = @import("batch.zig");
const H = core.vcs_lifted.blake3_merkle.MerkleHasher;
const M31 = core.fields.m31.M31;
const Column = struct { values: []const M31, log_size: u32 = 4 };
const Outcome = struct { ns: u64, checksum: u64 };
fn run(comptime vector: bool, comptime mode: enum { bytes, columns, nodes }, length: usize, iterations: usize) !Outcome {
    var payloads: [4][8192]u8 = undefined;
    for (&payloads, 0..) |*p, lane| for (p, 0..) |*b, i| {
        b.* = @truncate(i * 73 + lane * 101);
    };
    var storage: [1024][16]M31 = undefined;
    var columns: [1024]Column = undefined;
    for (&storage, &columns, 0..) |*row, *col, i| {
        for (row, 0..) |*v, j| v.* = M31.fromCanonical(@intCast(1 + i * 71 + j * 101));
        col.* = .{ .values = row };
    }
    var children: [8]H.Hash = undefined;
    for (&children, 0..) |*c, i| @memset(c, @intCast(i));
    var sum: u64 = 0;
    var timer = try std.time.Timer.start();
    for (0..iterations) |_| {
        var hashes: [4]H.Hash = undefined;
        if (mode == .nodes) {
            children[0][0] +%= 1;
            if (vector) hashes = batch.hashChildren4(&children) else {
                for (&hashes, 0..) |*digest, i| digest.* = H.hashChildren(.{ .left = children[2 * i], .right = children[2 * i + 1] });
            }
        } else if (mode == .columns) {
            storage[0][0].v +%= 1;
            if (vector) hashes = batch.hashLiftedLeaves4(columns[0..length], 4, 0) else {
                for (&hashes, 0..) |*digest, lane| {
                    var h = H.defaultWithInitialState();
                    for (columns[0..length]) |col| h.updateLeaf(col.values[lane..][0..1]);
                    digest.* = h.finalize();
                }
            }
        } else {
            payloads[0][0] +%= 1;
            var hashers = [_]H{H.defaultWithInitialState()} ** 4;
            var pos: usize = 0;
            while (pos < length) {
                const end = @min(length, pos + 256);
                var views: [4][]const u8 = undefined;
                for (&views, 0..) |*view, lane| view.* = payloads[lane][pos..end];
                if (vector) batch.updatePacked4(&hashers, &views) else {
                    for (&hashers, views) |*h, view| h.inner.update(view);
                }
                pos = end;
            }
            if (vector) hashes = batch.finalize4(&hashers) else {
                for (&hashes, &hashers) |*digest, *h| digest.* = h.finalize();
            }
        }
        std.mem.doNotOptimizeAway(hashes);
        for (hashes) |digest| sum +%= std.mem.readInt(u64, digest[0..8], .little);
    }
    return .{ .ns = timer.read(), .checksum = sum };
}
pub fn main() !void {
    const writer = std.fs.File.stdout().deprecatedWriter();
    inline for (.{ .bytes, .columns, .nodes }) |mode| {
        const lengths: []const usize = if (mode == .bytes) &.{ 64, 256, 1024, 8192 } else if (mode == .columns) &.{ 4, 64, 275, 1024 } else &.{64};
        for (lengths) |length| {
            const iterations = if (mode == .nodes) 20000 else @max(500, 1000000 / length);
            for (0..7) |sample| {
                var scalar: Outcome = undefined;
                var simd: Outcome = undefined;
                if (sample % 2 == 0) {
                    scalar = try run(false, mode, length, iterations);
                    simd = try run(true, mode, length, iterations);
                } else {
                    simd = try run(true, mode, length, iterations);
                    scalar = try run(false, mode, length, iterations);
                }
                if (scalar.checksum != simd.checksum) return error.DigestMismatch;
                try writer.print("{{\"mode\":\"{s}\",\"length\":{d},\"iterations\":{d},\"sample\":{d},\"warmup\":{},\"scalar_ns\":{d},\"simd_ns\":{d},\"checksum\":{d}}}\n", .{ @tagName(mode), length, iterations, sample, sample == 0, scalar.ns, simd.ns, scalar.checksum });
            }
        }
    }
}
