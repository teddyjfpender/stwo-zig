//! Interaction witness: per-slot inverses and three centered relation prefixes,
//! computed from the same `equations.fractions` the constraints evaluate.
const std = @import("std");
const core = @import("stwo_core");
const R = @import("../../memory/closed_ram/mod.zig");
const LS = @import("../../memory/load_store_v2/mod.zig");
const L = @import("layout.zig");
const T = @import("types.zig");
const Eq = @import("equations.zig");
const Source = @import("source.zig").Source;
const physical = @import("source.zig").physical;
const M = core.fields.m31.M31;
const Q = T.Q;
const CHUNK: usize = 2048;

fn promote(comptime n: usize, row: [n]M) [n]Q {
    var out: [n]Q = undefined;
    for (row, &out) |v, *q| q.* = Q.fromBase(v);
    return out;
}
/// Slot products (denominators to invert) and the numerators that multiply the
/// inverse for each relation: sum_r += numerator_r * inverse.
fn Row(comptime kind: L.Kind) type {
    const slots = L.slots(kind);
    return struct {
        product: [slots]Q,
        numerator: [slots][3]Q,
        fn init(m: []const Q, ch: T.Challenges) @This() {
            const list = Eq.fractions(Q, kind, m, ch);
            var out: @This() = undefined;
            for (0..slots) |j| {
                out.numerator[j] = @splat(Q.zero());
                const x = list[2 * j];
                if (2 * j + 1 < list.len) {
                    const y = list[2 * j + 1];
                    out.product[j] = x.d.mul(y.d);
                    out.numerator[j][x.relation] = out.numerator[j][x.relation].add(y.d.mul(x.w));
                    out.numerator[j][y.relation] = out.numerator[j][y.relation].add(x.d.mul(y.w));
                } else {
                    out.product[j] = x.d;
                    out.numerator[j][x.relation] = out.numerator[j][x.relation].add(x.w);
                }
            }
            return out;
        }
    };
}
pub fn generate(s: *Source, ch: T.Challenges, dict16: []const Q) !T.Claims {
    if (s.interaction.len != 0) return error.InvalidBulkMemoryPhase;
    switch (s.kind) {
        inline else => |kind| {
            const Provider = struct {
                fn row(ctx: *const anyopaque, logical: usize) [L.main(kind)]M {
                    const source: *const Source = @ptrCast(@alignCast(ctx));
                    return source.row(kind, logical);
                }
            };
            const built = try generateRows(kind, s.allocator, s.log_size, s.rows, s, Provider.row, ch);
            errdefer s.allocator.free(built.interaction);
            if (dict16.len != 0) {
                try LS.interaction.validateDictionary(ch.range16, dict16, 65536);
                if (!(try LS.interaction.countDot(s.counts16, dict16)).eql(built.claims.range16)) return error.InvalidBulkMemoryCounts;
            }
            s.interaction = built.interaction;
            return built.claims;
        },
    }
}
pub const Built = struct { interaction: []M, claims: T.Claims };
/// Rows at logical index >= `active` must equal the padding row `rowFn(n-1)`.
/// Tests pass `active = n` to evaluate arbitrary (forged) row sets.
pub fn generateRows(comptime kind: L.Kind, a: std.mem.Allocator, log: u32, active_rows: usize, ctx: *const anyopaque, rowFn: *const fn (*const anyopaque, usize) [L.main(kind)]M, ch: T.Challenges) !Built {
    const slots = comptime L.slots(kind);
    const n = @as(usize, 1) << @intCast(log);
    const out = try a.alloc(M, L.interaction(kind) * n);
    errdefer a.free(out);
    const padding = Row(kind).init(&promote(L.main(kind), rowFn(ctx, n - 1)), ch);
    var padding_inverse: [slots]Q = undefined;
    for (padding.product, &padding_inverse) |p, *i| i.* = try p.inv();
    var sums = [3]Q{ Q.zero(), Q.zero(), Q.zero() };
    const rows = try a.alloc(Row(kind), CHUNK);
    defer a.free(rows);
    const input = try a.alloc(Q, CHUNK * slots);
    defer a.free(input);
    const inverses = try a.alloc(Q, CHUNK * slots);
    defer a.free(inverses);
    var begin: usize = 0;
    while (begin < n) : (begin += CHUNK) {
        const count = @min(CHUNK, n - begin);
        const active: usize = if (begin < active_rows) @min(count, active_rows - begin) else 0;
        for (0..active) |i| {
            rows[i] = Row(kind).init(&promote(L.main(kind), rowFn(ctx, begin + i)), ch);
            @memcpy(input[i * slots ..][0..slots], &rows[i].product);
        }
        if (active != 0) try core.fields.batchInverseInPlace(Q, input[0 .. active * slots], inverses[0 .. active * slots]);
        for (0..count) |i| {
            const p = physical(begin + i, log);
            const r = if (i < active) &rows[i] else &padding;
            const inv: []const Q = if (i < active) inverses[i * slots ..][0..slots] else &padding_inverse;
            for (0..slots) |j| {
                R.trace.store(out, n, p, 4 * j, inv[j]);
                for (0..3) |rel| sums[rel] = sums[rel].add(r.numerator[j][rel].mul(inv[j]));
            }
            for (0..3) |rel| R.trace.store(out, n, p, L.prefix(kind, rel), sums[rel]);
        }
    }
    for (0..3) |rel| R.trace.center(out, n, L.prefix(kind, rel), sums[rel]);
    return .{ .interaction = out, .claims = .{ .ram = sums[Eq.RAM], .owner = sums[Eq.OWNER], .range16 = sums[Eq.RANGE16] } };
}
