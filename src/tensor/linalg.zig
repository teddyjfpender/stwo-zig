//! Integer-matrix x QM31-vector kernels (exact limb accumulation).
const std = @import("std");
const f = @import("field.zig");
const pcs = @import("pcs.zig");

const QM31 = f.QM31;

/// out[k] = sum_n m[k][n] * vec[n]   (row dots; the "fold columns" pass)
pub fn rowDots(comptime T: type, a: std.mem.Allocator, pool: *f.Pool, m: pcs.Matrix(T), vec: []const QM31, bound_log2: u32) ![]QM31 {
    const C = m.nCols();
    std.debug.assert(vec.len == C);
    const out = try a.alloc(QM31, m.nRows());
    const planes = try a.alloc(u32, f.N_LIMBS * C);
    defer a.free(planes);
    for (vec, 0..) |v, j| {
        const l = f.limbs(v);
        for (0..f.N_LIMBS) |k| planes[k * C + j] = l[k];
    }
    const Ctx = struct { m: pcs.Matrix(T), planes: []const u32, out: []QM31, C: usize, chunk: usize };
    const chunk: usize = @as(usize, 1) << @intCast(31 - @min(@as(u32, 30), bound_log2));
    const ctx = Ctx{ .m = m, .planes = planes, .out = out, .C = C, .chunk = chunk };
    pool.parallelFor(m.nRows(), 4, &ctx, struct {
        fn run(c: *const Ctx, s: usize, e: usize) void {
            for (s..e) |i| {
                const row = c.m.row(i);
                var tot: [f.N_LIMBS]i64 = @splat(0);
                var j: usize = 0;
                while (j < c.C) {
                    const end = @min(c.C, j + c.chunk);
                    inline for (0..f.N_LIMBS) |k| {
                        const pl = c.planes[k * c.C ..];
                        var acc: i64 = 0;
                        // vectorized inner loop
                        const V = 8;
                        var vacc: @Vector(V, i64) = @splat(0);
                        var jj = j;
                        while (jj + V <= end) : (jj += V) {
                            var rv: @Vector(V, i64) = undefined;
                            var pv: @Vector(V, i64) = undefined;
                            inline for (0..V) |t| {
                                rv[t] = row[jj + t];
                                pv[t] = pl[jj + t];
                            }
                            vacc += rv * pv;
                        }
                        acc += @reduce(.Add, vacc);
                        while (jj < end) : (jj += 1) acc += @as(i64, row[jj]) * @as(i64, pl[jj]);
                        tot[k] = @rem(tot[k] + @rem(acc, @as(i64, f.P)), @as(i64, f.P));
                    }
                    j = end;
                }
                var l: f.Limbs = undefined;
                for (&l, tot) |*x, tv| x.* = f.reduceI64(tv);
                c.out[i] = f.fromLimbs(l);
            }
        }
    }.run);
    return out;
}

/// out[n] = sum_k coeffs[k] * m[k][n]  (column combination; the "fold rows" pass)
pub fn colCombine(comptime T: type, a: std.mem.Allocator, pool: *f.Pool, m: pcs.Matrix(T), coeffs: []const QM31, bound_log2: u32) ![]QM31 {
    const rows = try pcs.combineRows(T, a, pool, m, &.{coeffs}, bound_log2);
    defer a.free(rows);
    return rows[0];
}

test "rowDots and colCombine match naive" {
    const a = std.testing.allocator;
    var pool: f.Pool = undefined;
    try pool.init(a, 3);
    defer pool.deinit();
    const R = 8;
    const C = 64;
    var data: [R * C]i8 = undefined;
    var prng = std.Random.DefaultPrng.init(3);
    for (&data) |*d| d.* = prng.random().int(i8);
    const m = pcs.Matrix(i8){ .data = &data, .log_rows = 3, .log_cols = 6 };
    var vec: [C]QM31 = undefined;
    for (&vec, 0..) |*v, i| v.* = QM31.fromU32Unchecked(@intCast(i * 1000003 % f.P), 7, @intCast(i), 0x7ffffffe);
    var co: [R]QM31 = undefined;
    for (&co, 0..) |*v, i| v.* = QM31.fromU32Unchecked(0x7ffffff0, @intCast(i), 1, 2);
    const rd = try rowDots(i8, a, &pool, m, &vec, 7);
    defer a.free(rd);
    for (0..R) |i| {
        var acc = QM31.zero();
        for (0..C) |j| acc = acc.add(vec[j].mulM31(f.fromI32(data[i * C + j])));
        try std.testing.expect(acc.eql(rd[i]));
    }
    const cc = try colCombine(i8, a, &pool, m, &co, 7);
    defer a.free(cc);
    for (0..C) |j| {
        var acc = QM31.zero();
        for (0..R) |i| acc = acc.add(co[i].mulM31(f.fromI32(data[i * C + j])));
        try std.testing.expect(acc.eql(cc[j]));
    }
}
