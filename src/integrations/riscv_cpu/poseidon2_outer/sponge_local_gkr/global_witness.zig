//! Bounded batch inversions for classic global RAM/KIO. Local facts are handled
//! exclusively by the separately authenticated GKR child. No free global roots.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const R = @import("authority.zig");
const Src = @import("source.zig");
const Eq = @import("equations.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
pub const Witness = struct {
    allocator: std.mem.Allocator,
    data: []M,
    claims: [2]O,
    pub fn deinit(self: *Witness) void {
        self.allocator.free(self.data);
        self.* = undefined;
    }
};
fn put(data: []M, rows: usize, col: usize, p: usize, value: O) void {
    for (value.toM31Array(), 0..) |v, i| data[(col + i) * rows + p] = v;
}
pub fn View(comptime role: R.Role) type {
    return struct {
        f: [R.fixedWidth(role)]O,
        m: [R.mainWidth(role)]O,
        pub fn fixed(self: *const @This(), i: usize) O {
            return self.f[i];
        }
        pub fn main(self: *const @This(), i: usize) O {
            return self.m[i];
        }
        pub fn init(source: *const Src.Source, logical: usize) @This() {
            const g = source.geometry;
            const instance = (g.instances() catch unreachable)[Src.Source.index(role)];
            const row = source.row(role, logical);
            const f = Src.fixedRow(role, logical, instance.row_log);
            var out: @This() = undefined;
            for (row, &out.m) |v, *x| x.* = O.fromBase(v);
            for (f, &out.f) |v, *x| x.* = O.fromBase(v);
            return out;
        }
    };
}
pub fn generate(comptime role: R.Role, a: std.mem.Allocator, source: *const Src.Source, ch: Eq.GlobalFor(O), limit: usize) !Witness {
    const instance = (try source.geometry.instances())[Src.Source.index(role)];
    const rows = try instance.rows();
    const cols = R.interactionWidth(role) - 16;
    const bytes = try std.math.mul(usize, rows, cols * @sizeOf(M));
    if (try std.math.add(usize, bytes, (if (cols != 0) rows * @sizeOf(O) else 0) + 4 * 256 * @sizeOf(O)) > limit) return error.SpongeGlobalWitnessBudget;
    const data = try a.alloc(M, bytes / @sizeOf(M));
    errdefer a.free(data);
    @memset(data, M.zero());
    var claims: [2]O = @splat(O.zero());
    var column: usize = 0;
    const public = Eq.PublicFor(O){ .calls = source.geometry.calls, .permutations = source.geometry.permutations, .first_id = source.geometry.first_id };
    inline for (.{ false, true }, 0..) |io, claim_index| {
        const count = comptime Eq.globalCount(role, io);
        if (count != 0) {
            // Fill inverses group by group. The prefix contribution is summed
            // into a narrow temporary plane, then normalized once.
            const sums = try a.alloc(O, rows);
            defer a.free(sums);
            @memset(sums, O.zero());
            inline for (0..count / 2) |pair| {
                var start: usize = 0;
                while (start < rows) : (start += 256) {
                    const n = @min(256, rows - start);
                    var ds: [256]O = undefined;
                    var ns: [256]O = undefined;
                    var inv: [256]O = undefined;
                    for (0..n) |i| {
                        const view = View(role).init(source, start + i);
                        const f = Eq.globalFractions(role, O, io, &view, public, ch);
                        if (f.count != count) return error.SpongeGlobalFractionShape;
                        const k = 2 * pair;
                        ds[i] = f.d[k].mul(f.d[k + 1]);
                        ns[i] = f.d[k + 1].mul(f.n[k]).add(f.d[k].mul(f.n[k + 1]));
                    }
                    try core.fields.batchInverseInPlace(O, ds[0..n], inv[0..n]);
                    for (0..n) |i| {
                        const logical = start + i;
                        const physical = A.witness.physical(logical, instance.row_log);
                        put(data, rows, column + 8 * pair, physical, inv[i]);
                        sums[logical] = sums[logical].add(inv[i].mul(ns[i]));
                    }
                }
            }
            var total = O.zero();
            for (sums) |v| total = total.add(v);
            claims[claim_index] = total;
            var prefix = total.neg();
            for (sums, 0..) |v, logical| {
                prefix = prefix.add(v);
                put(data, rows, column + 8 * (count / 2), A.witness.physical(logical, instance.row_log), prefix);
            }
            column += 8 * (count / 2 + 1);
        }
    }
    if (column != cols) return error.SpongeGlobalFractionShape;
    return .{ .allocator = a, .data = data, .claims = claims };
}
