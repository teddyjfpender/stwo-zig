//! Source-owned one-call public-packet arithmetic fixture authority.
//! This does not stand in for the pending production SSA/RAM/Wire joins.
const E = @import("../../evaluation.zig");
const R = @import("row.zig");
const S = @import("spec.zig");
pub const FIXED = 14;
pub const FIX_ACTIVE = 12;
pub const FIX_BYTE = 13;
inline fn k(comptime F: type, x: u32) F {
    return E.qFor(F, x);
}
pub fn query(comptime kind: S.Kind, comptime F: type, v: anytype, index: usize) F {
    return queryFor(S, kind, F, v, index);
}
pub fn queryFor(comptime Source: type, comptime kind: Source.Kind, comptime F: type, v: anytype, index: usize) F {
    const L = R.LayoutFor(Source, kind);
    const active = v.main(0);
    if (index < 32) return v.main(L.OUTPUT + index);
    var i = index - 32;
    if (i < L.G.q_bytes) return v.main(L.QUOTIENT + i);
    i -= L.G.q_bytes;
    if (i < L.G.carries * L.G.carry_bytes) return v.main(L.CARRY + i);
    i -= L.G.carries * L.G.carry_bytes;
    if (i < L.G.carries) return v.main(L.CARRY + i * L.G.carry_bytes + L.G.carry_bytes - 1).add(active.mul(k(F, 256 - (@as(u32, 1) << @intCast(L.G.top_bits)))));
    i -= L.G.carries;
    return v.main(L.DISTANCE + i);
}
pub fn constraints(comptime kind: S.Kind) usize {
    return constraintsFor(S, kind);
}
pub fn coordinates(comptime Source: type, comptime kind: Source.Kind) usize {
    return if (@hasDecl(Source, "rows")) Source.rows(kind) else Source.OUTPUTS;
}
pub fn fixedActive(comptime Source: type, comptime kind: Source.Kind) usize {
    return coordinates(Source, kind);
}
pub fn constraintsFor(comptime Source: type, comptime kind: Source.Kind) usize {
    const L = R.LayoutFor(Source, kind);
    return 1 + 32 * Source.inputs(kind) + (L.MULT - L.OUTPUT) + 15 + 16 + L.G.groups;
}
fn coeff(comptime Source: type, comptime kind: Source.Kind, comptime F: type, v: anytype, n: usize) F {
    const L = R.LayoutFor(Source, kind);
    var total = F.zero();
    inline for (0..comptime coordinates(Source, kind)) |coordinate| {
        var part = F.zero();
        inline for (comptime Source.terms(kind, coordinate)) |t| if (t.b) |b| {
            if (n < 63) {
                const first = if (n >= 32) n - 31 else 0;
                for (first..@min(n + 1, 32)) |i| {
                    const product = v.main(L.INPUT + 32 * @as(usize, t.a.in) + i).mul(v.main(L.INPUT + 32 * @as(usize, b.in) + n - i));
                    const scaled = product.mul(k(F, @intCast(@abs(t.coef))));
                    part = if (t.coef > 0) part.add(scaled) else part.sub(scaled);
                }
            }
        } else if (t.a == .in and n < 32) {
            const scaled = v.main(L.INPUT + 32 * @as(usize, t.a.in) + n).mul(k(F, @intCast(@abs(t.coef))));
            part = if (t.coef > 0) part.add(scaled) else part.sub(scaled);
        };
        total = total.add(v.fixed(coordinate).mul(part));
    }
    if (n < 32) total = total.sub(v.main(L.OUTPUT + n));
    total = total.add(v.main(0).mul(k(F, S.B.limbOf(L.G.kp, n))));
    const first = if (n >= 32) n - 31 else 0;
    var i = first;
    while (i < L.G.q_bytes and i <= n) : (i += 1) total = total.sub(v.main(L.QUOTIENT + i).mul(k(F, S.B.limbOf(S.B.BN254_P, n - i))));
    return total;
}
fn carry(comptime Source: type, comptime kind: Source.Kind, comptime F: type, v: anytype, index: usize) F {
    const L = R.LayoutFor(Source, kind);
    if (index >= L.G.carries) return F.zero();
    var value = F.zero();
    for (0..L.G.carry_bytes) |i| value = value.add(v.main(L.CARRY + index * L.G.carry_bytes + i).mul(k(F, @as(u32, 1) << @intCast(8 * i))));
    return value.sub(v.main(0).mul(k(F, @intCast(L.G.carry_offset))));
}
fn chunk(comptime F: type, v: anytype, start: usize, index: usize) F {
    return v.main(start + 2 * index).add(v.main(start + 2 * index + 1).mul(k(F, 256)));
}
pub fn emit(comptime kind: S.Kind, comptime F: type, v: anytype, input: *const [S.inputs(kind)]u256, sink: *E.SinkFor(F)) void {
    const L = R.Layout(kind);
    const active = v.main(0);
    // FIX_ACTIVE and all coordinate selectors belong to the independently rebuilt
    // immutable one-call ROM. The producer cannot choose an operation/coordinate.
    sink.emit(active.sub(v.fixed(FIX_ACTIVE)));
    for (input, 0..) |value, i| for (0..32) |b| sink.emit(v.main(L.INPUT + 32 * i + b).sub(active.mul(k(F, S.B.limbOf(value, b)))));
    emitBody(S, kind, F, v, sink);
}
/// Arithmetic rows consume input byte authority through an exact local SSA bus.
/// No public packet equality is inserted here. Inactive inputs are uniquely zero.
/// The caller must bind every active read to a source-owned canonical/raw writer.
pub fn emitInherited(comptime kind: S.Kind, comptime F: type, v: anytype, sink: *E.SinkFor(F)) void {
    emitInheritedFor(S, kind, F, v, sink);
}
pub fn emitInheritedFor(comptime Source: type, comptime kind: Source.Kind, comptime F: type, v: anytype, sink: *E.SinkFor(F)) void {
    const L = R.LayoutFor(Source, kind);
    const active = v.main(0);
    sink.emit(active.sub(v.fixed(fixedActive(Source, kind))));
    for (0..32 * Source.inputs(kind)) |i| sink.emit(F.one().sub(active).mul(v.main(L.INPUT + i)));
    emitBody(Source, kind, F, v, sink);
}
fn emitBody(comptime Source: type, comptime kind: Source.Kind, comptime F: type, v: anytype, sink: *E.SinkFor(F)) void {
    const L = R.LayoutFor(Source, kind);
    const active = v.main(0);
    for (L.OUTPUT..L.MULT) |c| sink.emit(F.one().sub(active).mul(v.main(c)));
    for (0..15) |i| E.booleanFor(F, sink, v.main(L.BORROW + i));
    for (0..16) |i| {
        var residual = chunk(F, v, L.OUTPUT, i).add(chunk(F, v, L.DISTANCE, i)).sub(active.mul(k(F, @intCast((S.B.BN254_P >> @intCast(16 * i)) & 0xffff))));
        if (i == 0) residual = residual.add(active);
        if (i > 0) residual = residual.add(v.main(L.BORROW + i - 1));
        if (i < 15) residual = residual.sub(v.main(L.BORROW + i).mul(k(F, 65536)));
        sink.emit(residual);
    }
    for (0..L.G.groups) |n| {
        var residual = coeff(Source, kind, F, v, n);
        if (n > 0) residual = residual.add(carry(Source, kind, F, v, n - 1));
        if (n < L.G.carries) residual = residual.sub(carry(Source, kind, F, v, n).mul(k(F, 256)));
        sink.emit(residual);
    }
}
