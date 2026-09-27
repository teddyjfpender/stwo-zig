//! Research comparison of field/transform stages with different field semantics.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const alloc = std.heap.page_allocator;
export fn local_field(op: u32, a: u64, b: u64) u64 {
    const x = M.fromCanonical(@intCast(a % core.fields.m31.Modulus));
    const y = M.fromCanonical(@intCast(b % core.fields.m31.Modulus));
    return (if (op == 0) x.add(y) else if (op == 1) x.mul(y) else x.inv() catch unreachable).toU32();
}
export fn local_field_batch(op: u32, rounds: u32) u64 {
    var x = M.fromCanonical(19);
    const y = M.fromCanonical(65537);
    var sum: u64 = 0;
    for (0..rounds) |i| {
        x = if (op == 0) x.add(y) else if (op == 1) x.mul(y) else M.fromCanonical(@intCast(i + 1)).inv() catch unreachable;
        sum +%= x.toU32();
    }
    return sum;
}
const Transform = struct {
    n: usize,
    domain: core.poly.circle.domain.CircleDomain,
    extended: core.poly.circle.domain.CircleDomain,
    twiddles: engine.poly.twiddles.TwiddleTree([]M),
    input: []M,
    a: []M,
    b: []M,
};
export fn local_transform_create(log: u32) *Transform {
    const self = alloc.create(Transform) catch unreachable;
    const n = @as(usize, 1) << @intCast(log);
    const domain = core.poly.circle.canonic.CanonicCoset.new(log).circleDomain();
    const extended = core.poly.circle.canonic.CanonicCoset.new(log + 1).circleDomain();
    self.* = .{ .n = n, .domain = domain, .extended = extended, .twiddles = engine.poly.twiddles.precomputeM31(alloc, extended.half_coset) catch unreachable, .input = alloc.alloc(M, n) catch unreachable, .a = alloc.alloc(M, n * 2) catch unreachable, .b = alloc.alloc(M, n * 2) catch unreachable };
    for (self.input, 0..) |*v, i| v.* = M.fromCanonical(@intCast(i + 1));
    return self;
}
export fn local_transform_destroy(t: *Transform) void {
    engine.poly.twiddles.deinitM31(alloc, &t.twiddles);
    alloc.free(t.input);
    alloc.free(t.a);
    alloc.free(t.b);
    alloc.destroy(t);
}
export fn local_transform_run(t: *Transform, op: u32, rounds: u32) u64 {
    const poly = engine.poly.circle.poly;
    var sum: u64 = 0;
    const tw: engine.poly.twiddles.TwiddleTree([]const M) = .{ .root_coset = t.twiddles.root_coset, .twiddles = @as([]const M, t.twiddles.twiddles), .itwiddles = @as([]const M, t.twiddles.itwiddles) };
    for (0..rounds) |_| {
        @memcpy(t.a[0..t.n], t.input);
        if (op == 0) poly.evaluateBuffersWithTwiddles(&.{t.a[0..t.n]}, t.domain, tw) catch unreachable else if (op == 1) poly.interpolateBuffersWithTwiddles(&.{t.a[0..t.n]}, t.domain, tw) catch unreachable else if (op == 2) {
            poly.evaluateBuffersWithTwiddles(&.{t.a[0..t.n]}, t.domain, tw) catch unreachable;
            poly.interpolateBuffersWithTwiddles(&.{t.a[0..t.n]}, t.domain, tw) catch unreachable;
            for (t.a[0..t.n], 0..) |v, i| if (v.toU32() != i + 1) return std.math.maxInt(u64);
        } else {
            poly.interpolateBuffersWithTwiddles(&.{t.a[0..t.n]}, t.domain, tw) catch unreachable;
            @memset(t.a[t.n..], M.zero());
            poly.evaluateBuffersWithTwiddles(&.{t.a}, t.extended, tw) catch unreachable;
        }
        for (t.a[0..if (op == 3) t.n * 2 else t.n]) |v| sum +%= v.toU32();
    }
    return sum;
}
