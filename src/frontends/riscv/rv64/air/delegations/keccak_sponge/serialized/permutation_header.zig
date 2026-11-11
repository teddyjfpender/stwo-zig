//! Closed narrow permutation header: the old26-coordinate control prefix and
//!18 read flags. Full endpoint/slot tokens delegate data to source-owned rows.
const core = @import("stwo_core");
const E = @import("../../../evaluation.zig");
const Old = @import("../equations.zig");
const L = @import("../layout.zig");
const Lane = @import("permutation_lane.zig");
const Word = @import("message_word.zig");
const M = core.fields.m31.M31;
pub const MAIN = 44;
pub const FIXED = 3;
pub const LOCAL_QUERIES = 28;
pub const LOCAL_PADDED = 32;
pub const OM31_INTER = 16; // modeled local binding plus global relation columns
pub const READ = 26;
fn q(comptime F: type, n: u32) F {
    return E.qFor(F, n);
}
fn sum(comptime F: type, v: []const F) F {
    var s = F.zero();
    for (v) |x| s = s.add(x);
    return s;
}
pub fn row(old: *const [L.perm.MAIN]M) [MAIN]M {
    var out: [MAIN]M = undefined;
    @memcpy(out[0..26], old[0..26]);
    @memcpy(out[READ..], old[L.perm.read..][0..18]);
    return out;
}
pub fn emitRaw(comptime F: type, index: F, m: *const [MAIN]F, first_id: F, sink: anytype) void {
    const P = L.perm;
    const a = m[P.active];
    const id = first_id.add(index);
    const after = m[P.epoch..][0..3].*;
    var shift = F.zero();
    for (m[P.shift..][0..8], 0..) |v, i| shift = shift.add(v.mul(q(F, @intCast(i))));
    sink.emit(Old.OWNER, Old.tokenTuple(F, after, m[P.base..][0..4].*, m[P.rb], m[P.wr], m[P.fin], m[P.freshfirst], shift, id), m[P.first].neg());
    var lane: [Lane.MAIN]F = @splat(F.zero());
    lane[Lane.c.id] = id;
    lane[Lane.c.first] = m[P.first];
    lane[Lane.c.lastfin] = m[P.lastfin];
    lane[Lane.c.freshfirst] = m[P.freshfirst];
    lane[Lane.c.shift_value] = shift;
    lane[Lane.c.remaining] = m[P.lastfin].mul(m[P.rb]).add(a.sub(m[P.lastfin]).mul(q(F, 136)));
    lane[Lane.c.previous_mask] = a;
    sink.emit(Old.OWNER, Lane.chain(F, &lane, false), a);
    lane[Lane.c.lane] = q(F, 25);
    lane[Lane.c.remaining] = F.zero();
    lane[Lane.c.previous_mask] = a.sub(m[P.lastfin]);
    sink.emit(Old.OWNER, Lane.chain(F, &lane, false), a.neg());
    var word: [Word.MAIN]F = @splat(F.zero());
    word[Word.c.id] = id;
    word[Word.c.first] = m[P.first];
    word[Word.c.last] = m[P.last];
    @memcpy(word[Word.c.epoch..][0..3], &after);
    @memcpy(word[Word.c.base..][0..4], m[P.base..][0..4]);
    for (0..18) |slot| {
        word[Word.c.slot] = q(F, @intCast(slot));
        word[Word.c.read] = m[READ + slot];
        sink.emit(Old.OWNER, Word.token(F, &word), a);
    }
    for ([_]usize{ P.epoch, P.tick_low, P.base, P.base + 1, P.base + 2, P.base + 3 }) |col| sink.emit(Old.RANGE16, [1]F{m[col]}, F.one());
    sink.emit(Old.RANGE8, [1]F{m[P.tick_high]}, F.one());
}
pub fn emitMain(comptime F: type, f: *const [3]F, m: *const [MAIN]F, pm: *const [MAIN]F, rows: F, nonempty: F, sink: anytype) void {
    const P = L.perm;
    const one = F.one();
    const a = m[P.active];
    const first = m[P.first];
    const last = m[P.last];
    const cont = a.sub(first);
    for ([_]usize{ P.active, P.first, P.last, P.lastfin, P.freshfirst, P.fin }) |col| sink.emit(m[col].mul(m[col].sub(one)));
    for (m[P.shift..][0..8]) |v| sink.emit(v.mul(v.sub(one)));
    sink.emit(sum(F, m[P.shift..][0..8]).sub(a));
    for (m[P.bcarry..][0..3]) |v| sink.emit(v.mul(v.sub(one)));
    for (m[READ..]) |v| sink.emit(v.mul(v.sub(one)));
    sink.emit(f[1].mul(a.sub(nonempty)));
    sink.emit(f[2].mul(a));
    sink.emit(one.sub(f[1]).mul(a).mul(one.sub(pm[P.active])));
    sink.emit(one.sub(f[1]).mul(pm[P.active].sub(a)).mul(f[0].sub(rows)));
    sink.emit(first.mul(one.sub(a)));
    sink.emit(last.mul(one.sub(a)));
    sink.emit(m[P.freshfirst].mul(one.sub(first)));
    sink.emit(m[P.lastfin].sub(last.mul(m[P.fin])));
    sink.emit(cont.mul(one.sub(pm[P.active])));
    sink.emit(pm[P.active].mul(one.sub(pm[P.last])).mul(one.sub(cont)));
    sink.emit(pm[P.last].mul(cont));
    for ([_]usize{ P.epoch, P.tick_low, P.tick_high, P.fin }) |col| sink.emit(cont.mul(m[col].sub(pm[col])));
    for (0..8) |i| sink.emit(cont.mul(m[P.shift + i].sub(pm[P.shift + i])));
    const next = Old.advance(F, pm[P.base..][0..4].*, m[P.bcarry..][0..3], 136);
    for (0..4) |i| sink.emit(cont.mul(m[P.base + i].sub(next[i])));
    for (m[P.bcarry..][0..3]) |v| sink.emit(one.sub(cont).mul(v));
    sink.emit(cont.mul(m[P.rb].sub(pm[P.rb]).add(q(F, 136))));
    sink.emit(cont.mul(m[P.wr].sub(pm[P.wr]).add(sum(F, pm[READ..]))));
    sink.emit(last.mul(m[P.wr].sub(sum(F, m[READ..]))));
    sink.emit(m[READ].mul(one.sub(first)));
    for (1..17) |j| sink.emit(m[READ + j + 1].mul(one.sub(m[READ + j])));
    sink.emit(m[READ + 1].mul(one.sub(first.mul(m[READ])).sub(cont.mul(pm[READ + 17]))));
}
