//! Explicit per-table encoding, with auditable work proxies (not timing claims).
const std = @import("std");
const core = @import("stwo_core");
const A = @import("block_v7_lookup_compact_algebra_v1.zig");
const S = A.Schema;
pub const VERSION: u32 = 1;
pub const Part = struct { kind: S.Kind, mode: A.Mode, log: u32, offset: [3]u32, width: [3]u32, claim_count: u32 = 1 };
pub const Cost = struct {
    raw_cells: u64,
    lde_cells: u64,
    quotient_cells: u64,
    ood_fields: u64,
    query_leaf_fields: u64,
    merkle_compression_upper: u64,
    pub fn forPart(placement: Part, blowup: u32, queries: u32) !Cost {
        if (placement.log > 24 or blowup > 8) return error.InvalidCompactLookupGeometry;
        const n = @as(u64, 1) << @as(u6, @intCast(placement.log));
        const width = @as(u64, placement.width[0]) + placement.width[1] + placement.width[2];
        const expansion: u32 = 2; // shared heterogeneous composition split
        const constraints: u64 = widthsConstraints(placement.kind, placement.mode);
        var hashes: u64 = 0;
        for (placement.width) |w| hashes += (@as(u64, w) * 4 + 63) / 64 + placement.log + blowup;
        return .{ .raw_cells = n * width, .lde_cells = (n * width) << @as(u6, @intCast(blowup)), .quotient_cells = (n << @as(u6, @intCast(expansion))) * constraints, .ood_fields = width + 4 + (@as(u64, 4) << @as(u6, @intCast(expansion))), .query_leaf_fields = width * queries, .merkle_compression_upper = hashes * queries };
    }
};
fn widthsConstraints(kind: S.Kind, mode: A.Mode) usize {
    inline for (0..6) |i| if (kind == @as(S.Kind, @enumFromInt(i))) {
        return if (mode == .dense) A.For(@enumFromInt(i), .dense).CONSTRAINT_COUNT else A.For(@enumFromInt(i), .sparse).CONSTRAINT_COUNT;
    };
    unreachable;
}
pub fn part(kind: S.Kind, mode: A.Mode, log: u32, offset: [3]u32) !Part {
    if (log < 4 or log > S.logSize(kind) or (mode == .dense and log != S.logSize(kind))) return error.InvalidCompactLookupGeometry;
    inline for (0..6) |i| if (kind == @as(S.Kind, @enumFromInt(i))) {
        const D = A.For(@enumFromInt(i), .dense);
        const C = A.For(@enumFromInt(i), .sparse);
        return .{ .kind = kind, .mode = mode, .log = log, .offset = offset, .width = if (mode == .dense) .{ D.FIXED_COUNT, D.MAIN_COUNT, 4 } else .{ C.FIXED_COUNT, C.MAIN_COUNT, 4 } };
    };
    unreachable;
}
pub fn choose(kind: S.Kind, distinct: usize, blowup: u32, queries: u32) !A.Mode {
    if (distinct > S.size(kind)) return error.InvalidCompactLookupCensus;
    const log = @max(@as(u32, 4), std.math.log2_int_ceil(usize, @max(1, distinct)));
    const dense = try Cost.forPart(try part(kind, .dense, S.logSize(kind), @splat(0)), blowup, queries);
    const sparse = try Cost.forPart(try part(kind, .sparse, log, @splat(0)), blowup, queries);
    // Conservatively charge 64 field operations per OODS/query field and
    // 512 per BLAKE3 compression. These are explicit selection weights, not
    // measured time predictions. A caller may pin a mode for differential runs.
    const ds = dense.lde_cells + dense.quotient_cells + 64 * (dense.ood_fields + dense.query_leaf_fields) + 512 * dense.merkle_compression_upper;
    const ss = sparse.lde_cells + sparse.quotient_cells + 64 * (sparse.ood_fields + sparse.query_leaf_fields) + 512 * sparse.merkle_compression_upper;
    return if (ss < ds and sparse.raw_cells < dense.raw_cells) .sparse else .dense;
}
pub const Layout = struct {
    parts: [6]Part,
    columns: [3]u32,
    digest: [32]u8,
    pub fn init(modes: [6]A.Mode, sizes: [6]u32) !Layout {
        var out: Layout = undefined;
        out.columns = @splat(0);
        var ch = core.proof_suites.Blake3.Channel{};
        ch.mixU32s(&.{ 0x4237434c, VERSION, 6 });
        for (&out.parts, modes, sizes, 0..) |*p, m, l, i| {
            p.* = try part(@enumFromInt(i), m, l, out.columns);
            ch.mixU32s(&.{ @intCast(i), @intFromEnum(m), l });
            ch.mixU32s(&p.width);
            for (&out.columns, p.width) |*count, w| count.* = try std.math.add(u32, count.*, w);
        }
        out.digest = ch.digestBytes();
        return out;
    }
    pub fn validate(self: Layout) !void {
        var modes: [6]A.Mode = undefined;
        var sizes: [6]u32 = undefined;
        for (self.parts, &modes, &sizes) |p, *m, *l| {
            m.* = p.mode;
            l.* = p.log;
        }
        if (!std.meta.eql(self, try init(modes, sizes))) return error.UntrustedCompactLookupLayout;
    }
    pub fn logs(self: Layout, a: std.mem.Allocator, tree: usize) ![]u32 {
        try self.validate();
        if (tree >= 3) return error.InvalidCompactLookupTree;
        const out = try a.alloc(u32, self.columns[tree]);
        for (self.parts) |p| @memset(out[p.offset[tree]..][0..p.width[tree]], p.log);
        return out;
    }
};
