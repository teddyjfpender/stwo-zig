//! Interaction witness: per-slot inverses and six centered relation prefixes,
//! computed from the same `equations.fractions` the constraints evaluate.
const std = @import("std");
const core = @import("stwo_core");
const R = @import("../../memory/closed_ram/mod.zig");
const LS = @import("../../memory/load_store_v2/mod.zig");
const L = @import("layout.zig");
const T = @import("types.zig");
const Eq = @import("equations.zig");
const Src = @import("source.zig");
const physical = Src.physical;
const M = core.fields.m31.M31;
const Q = T.Q;
const CHUNK: usize = 512;

fn promote(comptime n: usize, row: [n]M) [n]Q {
    var out: [n]Q = undefined;
    for (row, &out) |v, *q| q.* = Q.fromBase(v);
    return out;
}
fn fixedRow(logical: usize, n: usize) [L.FIXED]Q {
    return .{ Q.fromBase(M.fromCanonical(@intCast(logical))), Q.fromBase(M.fromCanonical(@intFromBool(logical == 0))), Q.fromBase(M.fromCanonical(@intFromBool(logical == n - 1))) };
}
/// Slot products (denominators to invert) and the numerators that multiply the
/// inverse for each relation: sum_r += numerator_r * inverse.
fn Row(comptime kind: L.Kind) type {
    const slots = L.slots(kind);
    return struct {
        product: [slots]Q,
        numerator: [slots][T.RELATIONS]Q,
        fn init(self: *@This(), f: []const Q, m: []const Q, first_id: u32, ch: T.Challenges) void {
            const list = Eq.fractions(Q, kind, f, m, first_id, ch);
            for (0..slots) |j| {
                self.numerator[j] = @splat(Q.zero());
                const x = list[2 * j];
                if (2 * j + 1 < list.len) {
                    const y = list[2 * j + 1];
                    self.product[j] = x.d.mul(y.d);
                    self.numerator[j][x.relation] = self.numerator[j][x.relation].add(y.d.mul(x.w));
                    self.numerator[j][y.relation] = self.numerator[j][y.relation].add(x.d.mul(y.w));
                } else {
                    self.product[j] = x.d;
                    self.numerator[j][x.relation] = self.numerator[j][x.relation].add(x.w);
                }
            }
        }
    };
}
pub fn generate(s: *Src.Source, ch: T.Challenges, dict16: []const Q, dict8: []const Q) !T.Claims {
    if (s.interaction.len != 0) return error.InvalidKeccakSpongePhase;
    switch (s.kind) {
        inline else => |kind| {
            const Provider = struct {
                fn row(ctx: *const anyopaque, logical: usize) [L.main(kind)]M {
                    const source: *const Src.Source = @ptrCast(@alignCast(ctx));
                    return source.plan.row(kind, logical, source.first_id);
                }
            };
            const built = try generateRows(kind, s.allocator, s.log_size, s.rows, s.first_id, s, Provider.row, ch);
            errdefer s.allocator.free(built.interaction);
            if (dict16.len != 0) {
                try LS.interaction.validateDictionary(ch.range16, dict16, 65536);
                if (!(try LS.interaction.countDot(s.counts16, dict16)).eql(built.claims.range16)) return error.InvalidKeccakSpongeCounts;
            }
            if (dict8.len != 0) {
                try LS.interaction.validateDictionary(ch.range8, dict8, 256);
                if (!(try LS.interaction.countDot(s.counts8, dict8)).eql(built.claims.range8)) return error.InvalidKeccakSpongeCounts;
            }
            s.interaction = built.interaction;
            return built.claims;
        },
    }
}
pub const Built = struct { interaction: []M, claims: T.Claims };
/// Rows at logical index >= `active_rows` must equal the padding row
/// `rowFn(n-1)` (all zero). Tests pass `active_rows = n` to evaluate
/// arbitrary (forged) row sets.
pub fn generateRows(comptime kind: L.Kind, a: std.mem.Allocator, log: u32, active_rows: usize, first_id: u32, ctx: *const anyopaque, rowFn: *const fn (*const anyopaque, usize) [L.main(kind)]M, ch: T.Challenges) !Built {
    const slots = comptime L.slots(kind);
    const n = @as(usize, 1) << @intCast(log);
    const out = try a.alloc(M, L.interaction(kind) * n);
    errdefer a.free(out);
    // Padding rows differ only in the fixed row index, which enters perm IDs.
    const rows = try a.alloc(Row(kind), CHUNK);
    defer a.free(rows);
    const input = try a.alloc(Q, CHUNK * slots);
    defer a.free(input);
    const inverses = try a.alloc(Q, CHUNK * slots);
    defer a.free(inverses);
    var sums: [T.RELATIONS]Q = @splat(Q.zero());
    var begin: usize = 0;
    while (begin < n) : (begin += CHUNK) {
        const count = @min(CHUNK, n - begin);
        for (0..count) |i| {
            const logical = begin + i;
            const values = promote(L.main(kind), rowFn(ctx, if (logical < active_rows) logical else n - 1));
            rows[i].init(&fixedRow(logical, n), &values, first_id, ch);
            @memcpy(input[i * slots ..][0..slots], &rows[i].product);
        }
        try core.fields.batchInverseInPlace(Q, input[0 .. count * slots], inverses[0 .. count * slots]);
        for (0..count) |i| {
            const p = physical(begin + i, log);
            const inv = inverses[i * slots ..][0..slots];
            for (0..slots) |j| {
                R.trace.store(out, n, p, 4 * j, inv[j]);
                for (0..T.RELATIONS) |rel| sums[rel] = sums[rel].add(rows[i].numerator[j][rel].mul(inv[j]));
            }
            for (0..T.RELATIONS) |rel| R.trace.store(out, n, p, L.prefix(kind, rel), sums[rel]);
        }
    }
    for (0..T.RELATIONS) |rel| R.trace.center(out, n, L.prefix(kind, rel), sums[rel]);
    return .{ .interaction = out, .claims = T.Claims.fromValues(sums) };
}
