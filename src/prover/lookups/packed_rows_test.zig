const std = @import("std");
const core = @import("stwo_core");
const Kernels = @import("packed_rows.zig");
const M = core.fields.m31.M31;
const a = std.testing.allocator;
fn dense(comptime S: type, i: usize) S {
    var cs: [S.zero().toM31Array().len]M = undefined;
    for (&cs, 0..) |*v, j| v.* = M.fromCanonical(@intCast((i * 7919 + j * 977 + 3) % 1048573));
    return S.fromM31Array(cs);
}
fn scalarLogup(comptime S: type, comptime F: type, eq: []const S, n: []const F, d: []const S, terms: usize, lambda: S, first: usize, end: usize) [2]S {
    var out: [2]S = .{ S.zero(), S.zero() };
    for (first..end) |i| {
        const a0 = d[2 * i];
        const b0 = d[2 * i + 1];
        const a2 = d[2 * (terms + i)].add(d[2 * (terms + i)]).sub(a0);
        const b2 = d[2 * (terms + i) + 1].add(d[2 * (terms + i) + 1]).sub(b0);
        var n0: S = undefined;
        var n2: S = undefined;
        if (F == void) {
            n0 = a0.add(b0);
            n2 = a2.add(b2);
        } else {
            const na = n[2 * i];
            const nb = n[2 * i + 1];
            const na2 = n[2 * (terms + i)].add(n[2 * (terms + i)]).sub(na);
            const nb2 = n[2 * (terms + i) + 1].add(n[2 * (terms + i) + 1]).sub(nb);
            if (F == M) {
                n0 = b0.mulM31(na).add(a0.mulM31(nb));
                n2 = b2.mulM31(na2).add(a2.mulM31(nb2));
            } else {
                n0 = b0.mul(na).add(a0.mul(nb));
                n2 = b2.mul(na2).add(a2.mul(nb2));
            }
        }
        out[0] = out[0].add(eq[i].mul(n0.add(lambda.mul(a0.mul(b0)))));
        out[1] = out[1].add(eq[i].mul(n2.add(lambda.mul(a2.mul(b2)))));
    }
    return out;
}
fn check(comptime S: type) !void {
    const K = Kernels.ForField(S);
    const d = try a.alloc(S, 512);
    defer a.free(d);
    const n = try a.alloc(S, 512);
    defer a.free(n);
    const b = try a.alloc(M, 512);
    defer a.free(b);
    const eq = try a.alloc(S, 128);
    defer a.free(eq);
    const out = try a.alloc(S, 256);
    defer a.free(out);
    const nd = try a.alloc(S, 256);
    defer a.free(nd);
    for (d, n, b, 0..) |*dv, *nv, *bv, i| {
        dv.* = dense(S, i);
        nv.* = dense(S, i + 29);
        bv.* = if (i % 3 == 0) M.zero() else if (i % 3 == 1) M.one().neg() else M.fromCanonical(@intCast(i % 7));
    }
    for (eq, 0..) |*e, i| e.* = dense(S, i + 919);
    const r = dense(S, 97);
    for ([_]usize{ 0, 1, 3, 7 }) |first| for ([_]usize{ 0, 1, 3, 4, 5, 17, 31, 63 }) |count| {
        const end = first + count;
        inline for (.{ M, S }) |F| {
            const input = if (F == M) b else d;
            const tail = K.fold(F, input, out, r, first, end);
            for (first..tail) |i| {
                const lo = if (F == M) S.fromBase(input[i]) else input[i];
                const hi = if (F == M) S.fromBase(input[i + out.len]) else input[i + out.len];
                try std.testing.expectEqualDeep(lo.add(r.mul(hi.sub(lo))), out[i]);
            }
        }
        const product_tail = K.nextProduct(d, out, first, end);
        for (first..product_tail) |i| try std.testing.expectEqualDeep(d[2 * i].mul(d[2 * i + 1]), out[i]);
        inline for (.{ void, M, S }) |F| {
            const input: []const F = if (F == M) b else if (F == S) n else &.{};
            const tail = K.nextLogup(F, input, d, out, nd, first, end);
            for (first..tail) |i| {
                const expected = if (F == void) d[2 * i].add(d[2 * i + 1]) else if (F == M) d[2 * i + 1].mulM31(input[2 * i]).add(d[2 * i].mulM31(input[2 * i + 1])) else d[2 * i + 1].mul(input[2 * i]).add(d[2 * i].mul(input[2 * i + 1]));
                try std.testing.expectEqualDeep(expected, out[i]);
                try std.testing.expectEqualDeep(d[2 * i].mul(d[2 * i + 1]), nd[i]);
            }
            const got = K.sumLogup(F, eq, input, d, 128, r, first, end);
            try std.testing.expectEqualDeep(scalarLogup(S, F, eq, input, d, 128, r, first, got.end), got.values);
        }
        const got = K.sumProduct(eq, d, 128, first, end);
        var sums: [2]S = .{ S.zero(), S.zero() };
        for (first..got.end) |i| {
            const a0 = d[2 * i];
            const b0 = d[2 * i + 1];
            const a2 = d[2 * (128 + i)].add(d[2 * (128 + i)]).sub(a0);
            const b2 = d[2 * (128 + i) + 1].add(d[2 * (128 + i) + 1]).sub(b0);
            sums[0] = sums[0].add(eq[i].mul(a0.mul(b0)));
            sums[1] = sums[1].add(eq[i].mul(a2.mul(b2)));
        }
        try std.testing.expectEqualDeep(sums, got.values);
    };
}
test "packed Q GKR numerical kernels match independent scalar formulas at unaligned ranges and tails" {
    try check(core.fields.qm31.QM31);
}
test "packed OM GKR numerical kernels match independent scalar formulas at unaligned ranges and tails" {
    try check(core.fields.om31.OM31);
}
fn bench(comptime S: type) !void {
    const K = Kernels.ForField(S);
    const terms = 1 << 16;
    const d = try a.alloc(S, 4 * terms);
    defer a.free(d);
    const n = try a.alloc(M, 4 * terms);
    defer a.free(n);
    const eq = try a.alloc(S, terms);
    defer a.free(eq);
    for (d, n, 0..) |*dv, *nv, i| {
        dv.* = dense(S, i);
        nv.* = if (i % 3 == 0) M.zero() else if (i % 3 == 1) M.one().neg() else M.fromCanonical(@intCast(i % 7));
    }
    for (eq, 0..) |*v, i| v.* = dense(S, i + 91);
    const l = dense(S, 37);
    var timer = try std.time.Timer.start();
    var scalar_ns: u64 = 0;
    var packed_ns: u64 = 0;
    for (0..5) |_| {
        timer.reset();
        const reference = scalarLogup(S, M, eq, n, d, terms, l, 0, terms);
        scalar_ns += timer.read();
        std.mem.doNotOptimizeAway(reference);
        timer.reset();
        const result = K.sumLogup(M, eq, n, d, terms, l, 0, terms);
        packed_ns += timer.read();
        std.mem.doNotOptimizeAway(result);
        try std.testing.expectEqualDeep(reference, result.values);
    }
    std.debug.print("GKR_PACKED_KERNEL field={s} terms={d} rounds=5 scalar_ns={d} packed_ns={d} speedup={d:.3}\n", .{ @typeName(S), terms, scalar_ns, packed_ns, @as(f64, @floatFromInt(scalar_ns)) / @as(f64, @floatFromInt(packed_ns)) });
}
test "optional packed GKR kernel microbenchmark" {
    if (!std.process.hasEnvVarConstant("STWO_ZIG_BENCH_GKR_PACKED")) return;
    try bench(core.fields.qm31.QM31);
    try bench(core.fields.om31.OM31);
}
