//! Frozen algorithm comparison: identical scaled inverse planes, owned input
//! already available. Copy/setup and full output comparison are outside timing.
const std = @import("std");
const fields = @import("stwo_core").fields;
const Q = fields.qm31.QM31;
const M = fields.m31.M31;

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    var random = std.Random.DefaultPrng.init(20260928);
    const rng = random.random();
    for ([_]usize{ 1024, 32768, 262144, 1048576 }) |count| {
        const source = try allocator.alloc(Q, count);
        defer allocator.free(source);
        const owned = try allocator.alloc(Q, count);
        defer allocator.free(owned);
        const before = try allocator.alloc(Q, count);
        defer allocator.free(before);
        const after = try allocator.alloc(Q, count);
        defer allocator.free(after);
        const scalars = try allocator.alloc(M, count);
        defer allocator.free(scalars);
        for (source, scalars, 0..) |*value, *scale, index| {
            const q = Q.fromU32Unchecked(rng.int(u32) % 0x7fffffff, rng.int(u32) % 0x7fffffff, rng.int(u32) % 0x7fffffff, rng.int(u32) % 0x7fffffff);
            value.* = if (q.isZero()) Q.one() else q;
            scale.* = M.fromCanonical(@intCast(index % 17));
        }
        for (0..4) |trial| {
            @memcpy(owned, source);
            var baseline_ns: u64 = 0;
            var candidate_ns: u64 = 0;
            for (0..2) |position| {
                var timer = try std.time.Timer.start();
                if ((trial + position) % 2 == 0) {
                    try fields.batchInverseInPlace(Q, source, before);
                    for (before, scalars) |*value, scale| value.* = value.mulM31(scale);
                    baseline_ns = timer.read();
                } else {
                    try fields.qm31_norm_batch.invertScaledOwned(owned, after, scalars);
                    candidate_ns = timer.read();
                }
            }
            for (before, after) |want, got| if (!want.eql(got)) return error.InverseMismatch;
            std.debug.print("{{\"count\":{},\"trial\":{},\"before_ns\":{},\"after_ns\":{},\"equal\":true}}\n", .{ count, trial + 1, baseline_ns, candidate_ns });
        }
    }
}
