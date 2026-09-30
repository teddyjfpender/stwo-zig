//! Parent-layer hashing shared by the tiled commitments: one Merkle level
//! from the one below it, with the node hash `layers.zig` uses.

const std = @import("std");
const blake2_stream4 = @import("blake2_stream4.zig");
const work_pool = @import("../work_pool.zig");

/// `out[i] = node(prev[2i], prev[2i + 1])`, with the node hash
/// `vcs_lifted/layers.zig` uses, on the global pool for wide layers.
pub fn hashParents(comptime H: type, prev: []const H.Hash, out: []H.Hash) void {
    std.debug.assert(prev.len == 2 * out.len);
    const Range = struct {
        prev: []const H.Hash,
        out: []H.Hash,
        pub fn run(self: *@This()) void {
            hashParentsSerial(H, self.prev, self.out);
        }
    };
    const chunk: usize = 1 << 13;
    const pool = work_pool.getGlobalPool();
    if (pool == null or out.len <= chunk) {
        hashParentsSerial(H, prev, out);
        return;
    }
    var ranges: [256]Range = undefined;
    var start: usize = 0;
    while (start < out.len) {
        var count: usize = 0;
        while (count < ranges.len and start < out.len) : (count += 1) {
            const end = @min(out.len, start + chunk);
            ranges[count] = .{ .prev = prev[2 * start .. 2 * end], .out = out[start..end] };
            start = end;
        }
        var group: std.Thread.WaitGroup = .{};
        for (ranges[1..count]) |*range| pool.?.spawnWg(&group, Range.run, .{range});
        ranges[0].run();
        group.wait();
    }
}

pub fn hashParentsSerial(comptime H: type, prev: []const H.Hash, out: []H.Hash) void {
    if (comptime @hasDecl(H, "nodeSeed") and @hasDecl(H, "hashChildrenWithSeed")) {
        const seed = H.nodeSeed();
        var i: usize = 0;
        if (comptime blake2_stream4.supports(H)) {
            while (i + 8 <= out.len) : (i += 8) {
                const children: *const [16]H.Hash = @ptrCast(&prev[2 * i]);
                const hashes = blake2_stream4.hashChildren8(H, seed, children);
                inline for (0..8) |lane| out[i + lane] = hashes[lane];
            }
        }
        if (comptime @hasDecl(H, "hashChildrenWithSeed4")) {
            while (i + 4 <= out.len) : (i += 4) {
                const children: *const [8]H.Hash = @ptrCast(&prev[2 * i]);
                const hashes = H.hashChildrenWithSeed4(seed, children);
                inline for (0..4) |lane| out[i + lane] = hashes[lane];
            }
        }
        while (i < out.len) : (i += 1) {
            out[i] = H.hashChildrenWithSeed(seed, .{ .left = prev[2 * i], .right = prev[2 * i + 1] });
        }
        return;
    }
    for (out, 0..) |*node, i| node.* = H.hashChildren(.{ .left = prev[2 * i], .right = prev[2 * i + 1] });
}
