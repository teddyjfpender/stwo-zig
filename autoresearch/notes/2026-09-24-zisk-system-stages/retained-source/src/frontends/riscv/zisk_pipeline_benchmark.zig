const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const H = core.vcs_lifted.blake3_merkle.MerkleHasher;
const alloc = std.heap.page_allocator;
export fn local_pipeline(log: u32, width: u32, rounds: u32, constant: u32, times: *[2]u64, root: *[32]u8) u64 {
    const n = @as(usize, 1) << @intCast(log);
    const domain = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain();
    const ext = core.poly.circle.canonic.CanonicCoset.new(log + 1).circleDomain();
    var tw = engine.poly.twiddles.precomputeM31(alloc, ext.half_coset) catch unreachable;
    defer engine.poly.twiddles.deinitM31(alloc, &tw);
    const view: engine.poly.twiddles.TwiddleTree([]const M) = .{ .root_coset = tw.root_coset, .twiddles = tw.twiddles, .itwiddles = tw.itwiddles };
    const cols = alloc.alloc([]M, width) catch unreachable;
    defer alloc.free(cols);
    const base = alloc.alloc([]M, width) catch unreachable;
    defer alloc.free(base);
    const read = alloc.alloc([]const M, width) catch unreachable;
    defer alloc.free(read);
    for (cols, base, read) |*c, *b, *r| {
        c.* = alloc.alloc(M, 2 * n) catch unreachable;
        b.* = c.*[0..n];
        r.* = c.*;
    }
    defer for (cols) |c| alloc.free(c);
    times.* = .{ 0, 0 };
    var sum: u64 = 0;
    for (0..rounds) |_| {
        for (cols, 0..) |c, j| {
            for (c[0..n], 0..) |*v, i| v.* = M.fromCanonical(@intCast(if (constant != 0) 1 else i * width + j + 1));
            @memset(c[n..], M.zero());
        }
        var timer = std.time.Timer.start() catch unreachable;
        engine.poly.circle.poly.interpolateBuffersWithTwiddles(base, domain, view) catch unreachable;
        engine.poly.circle.poly.evaluateBuffersWithTwiddles(cols, ext, view) catch unreachable;
        times[0] += timer.read();
        if (constant != 0) {
            for (cols) |c| for (c) |v| {
                if (v.toU32() != 1) return std.math.maxInt(u64);
            };
        }
        timer.reset();
        var tree = engine.vcs_lifted.prover.MerkleProverLifted(H).commit(alloc, read) catch unreachable;
        root.* = tree.root();
        tree.deinit(alloc);
        times[1] += timer.read();
        for (0..4) |i| sum +%= std.mem.readInt(u64, root[i * 8 ..][0..8], .little);
    }
    return sum;
}
