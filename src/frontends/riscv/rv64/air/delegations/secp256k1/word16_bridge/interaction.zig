//! Private publication; all lookup values come from copied narrow native packet
//! metadata after MAIN release. Scalar recipe is the initial exact authority.
const core = @import("stwo_core");
const R = @import("../../../memory/closed_ram/mod.zig");
const LS = @import("../../../memory/load_store_v2/mod.zig");
const L = @import("layout.zig");
const T = @import("types.zig");
const Eq = @import("equations.zig");
const Src = @import("source.zig");
const Q = T.Q;
pub fn generate(s: *Src.Source, ch: T.Challenges, d16: []const Q, d8: []const Q) !T.Claims {
    if (s.interaction.len != 0) return error.InvalidWord16SecpPhase;
    const n = try T.validateGeometry(s.kind, s.calls.len, s.first_id, s.log_size);
    for (s.calls) |c| try Src.validate(s.kind, c);
    try LS.interaction.validateDictionary(ch.range16, d16, 65536);
    try LS.interaction.validateDictionary(ch.range8, d8, 256);
    const out = try s.allocator.alloc(core.fields.m31.M31, L.INTERACTION * n);
    errdefer s.allocator.free(out);
    var total = T.Claims.zero();
    total.range16 = try LS.interaction.countDot(s.counts16, d16);
    total.range8 = try LS.interaction.countDot(s.counts8, d8);
    var prefixes = [_]Q{ total.range16.neg(), total.range8.neg() };
    const coords = T.coordinates(s.kind);
    for (0..n) |row| {
        const p = R.trace.physical(row, s.log_size);
        const index = row / coords;
        const base = Src.nativeRow(s.kind, if (index < s.calls.len) s.calls[index] else null, row % coords, if (index < s.calls.len) s.first_id + @as(u32, @intCast(index)) else 0);
        var m: [L.MAIN]Q = undefined;
        for (base, &m) |v, *q| q.* = Q.fromBase(v);
        var f: [L.FIXED]Q = undefined;
        for (&f, 0..) |*q, c| q.* = Q.fromBase(s.fixed[c * n + p]);
        const active = m[L.ACTIVE];
        for (0..4) |lane| {
            const ramrow = Eq.ramRow(Q, &m, lane);
            const d = ch.ram.denominatorFor(Q, R.equations.ramTuple(Q, .transition, &ramrow, false));
            const e = ch.ram.denominatorFor(Q, R.equations.ramTuple(Q, .transition, &ramrow, true));
            const inv = try d.mul(e).inv();
            R.trace.store(out, n, p, L.RAM + 4 * lane, inv);
            total.ram = total.ram.add(e.sub(d).mul(inv).mul(active));
        }
        R.trace.store(out, n, p, 16, total.ram);
        const oi = try ch.owner.denominatorFor(Q, Eq.ownerTuple(Q, s.kind, &m)).inv();
        R.trace.store(out, n, p, L.OWNER, oi);
        total.owner = total.owner.sub(oi.mul(active).mul(f[4]));
        R.trace.store(out, n, p, L.OWNER + 4, total.owner);
        const d = ch.wire.denominator(&Eq.wireTuple(Q, s.kind, &f, &m, false));
        const e = ch.wire.denominator(&Eq.wireTuple(Q, s.kind, &f, &m, true));
        const wi = try d.mul(e).inv();
        R.trace.store(out, n, p, L.WIRE, wi);
        total.wire = total.wire.add(e.sub(d.mul(f[6])).mul(wi).mul(active));
        R.trace.store(out, n, p, L.WIRE + 4, total.wire);
        inline for (.{ L.U16, L.U8 }, 0..) |columns, k| {
            const dict = if (k == 0) d16 else d8;
            const start = if (k == 0) L.RANGE16 else L.RANGE8;
            for (0..(columns.len + 1) / 2) |batch| {
                const x = dict[base[columns[2 * batch]].v];
                var inv = x;
                prefixes[k] = prefixes[k].add(x);
                if (2 * batch + 1 < columns.len) {
                    const y = dict[base[columns[2 * batch + 1]].v];
                    inv = inv.mul(y);
                    prefixes[k] = prefixes[k].add(y);
                }
                R.trace.store(out, n, p, start + 4 * batch, inv);
            }
            R.trace.store(out, n, p, start + 4 * ((columns.len + 1) / 2), prefixes[k]);
        }
    }
    if (!prefixes[0].isZero() or !prefixes[1].isZero()) return error.InvalidWord16SecpCounts;
    R.trace.center(out, n, 16, total.ram);
    R.trace.center(out, n, L.OWNER + 4, total.owner);
    R.trace.center(out, n, L.WIRE + 4, total.wire);
    s.interaction = out;
    s.allocator.free(s.calls);
    s.calls = &.{};
    return total;
}
