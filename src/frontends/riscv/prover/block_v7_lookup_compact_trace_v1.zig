const std = @import("std");
const R = @import("block_v7_memory_relations_v1.zig");
const A = @import("block_v7_lookup_compact_algebra_v1.zig");
const S = A.Schema;
const T = @import("block_v7_memory_trace_v1.zig");
const L = @import("block_v7_lookup_compact_layout_v1.zig");
const Counter = @import("../air/lookups/tables/counter.zig").Counter;
pub fn distinct(counter: *const Counter) !usize {
    if (counter.values.len != S.size(counter.kind)) return error.InvalidCompactLookupCounter;
    var n: usize = 0;
    for (counter.values) |v| {
        if (v.v >= @import("stwo_core").fields.m31.Modulus) return error.NonCanonicalM31;
        if (!v.isZero()) n += 1;
    }
    return n;
}
pub fn fixed(a: std.mem.Allocator, p: L.Part, max_bytes: usize) !T.Matrix {
    var out = try T.Matrix.init(a, p.log, p.width[0], max_bytes);
    errdefer out.deinit();
    for (0..out.size()) |row| {
        // Sparse activity is public geometry, not a prover-selected tuple count.
        // All rows are active; unused rows contain a valid tuple with m=0.
        out.set(0, row, R.M.one());
        if (p.mode == .dense) {
            const tuple = try S.tupleAt(p.kind, row);
            for (tuple.slice(), 0..) |v, j| out.set(j + 1, row, v);
        }
    }
    return out;
}
pub fn main(a: std.mem.Allocator, p: L.Part, counter: *const Counter, max_bytes: usize) !T.Matrix {
    if (counter.kind != p.kind) return error.InvalidCompactLookupCounter;
    const count = try distinct(counter);
    if (p.mode == .sparse and count > (@as(usize, 1) << @as(u6, @intCast(p.log)))) return error.CompactLookupCapacityExceeded;
    var out = try T.Matrix.init(a, p.log, p.width[1], max_bytes);
    errdefer out.deinit();
    inline for (0..6) |i| if (p.kind == @as(S.Kind, @enumFromInt(i))) {
        const Dense = A.For(@enumFromInt(i), .dense);
        const Sparse = A.For(@enumFromInt(i), .sparse);
        if (p.mode == .dense) {
            for (counter.values, 0..) |v, row| {
                const w = try Dense.witness(try S.tupleAt(p.kind, row), v);
                out.set(0, row, w[0]);
            }
        } else {
            const zero = try Sparse.witness(try S.tupleAt(p.kind, 0), R.M.zero());
            for (0..out.size()) |row| for (zero, 0..) |v, j| out.set(j, row, v);
            var next: usize = 0;
            for (counter.values, 0..) |v, row| if (!v.isZero()) {
                const w = try Sparse.witness(try S.tupleAt(p.kind, row), v);
                for (w, 0..) |x, j| out.set(j, next, x);
                next += 1;
            };
        }
    };
    return out;
}
