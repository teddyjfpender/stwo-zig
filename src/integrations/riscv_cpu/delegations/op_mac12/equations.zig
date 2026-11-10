//! Bounded public-input fixture: pending production SSA is deliberately absent.
const A = @import("stwo_riscv_frontend").rv64_air;
const core = @import("stwo_core");
const E = A.evaluation;
pub const S = A.crypto.bn254_mac12.source;
pub const W = A.crypto.bn254_mac12.witness;
pub const O = core.fields.om31.OM31;
pub const M = core.fields.m31.M31;
pub const FIX_BYTE = S.FIXED;
pub const FIXED = S.FIXED + 1;
pub const MULT = S.MAIN;
pub const MAIN = S.MAIN + 1;
pub const BATCHES = (S.BYTE_QUERIES + 2) / 2;
pub const INTER = 8 * BATCHES;
pub const LAST = INTER - 8;
pub const CONSTRAINTS = S.CONSTRAINTS + 25 * 32 + 32 + BATCHES;
fn secure(comptime F: type, v: anytype, start: usize, comptime shift: i32) E.SecureFor(F) {
    var coordinates: [8]F = undefined;
    for (&coordinates, 0..) |*x, i| x.* = v.interactionAt(start + i, shift);
    return E.secureFromCoordinatesForField(O, F, coordinates);
}
pub fn fraction(comptime F: type, v: anytype, beta: O, index: usize) struct { F, E.SecureFor(F) } {
    if (index < S.BYTE_QUERIES) return .{ v.main(S.ACTIVE), E.splatFor(F, beta).sub(E.liftFor(F, S.byteQuery(F, v, index))) };
    if (index == S.BYTE_QUERIES) return .{ v.main(MULT).neg(), E.splatFor(F, beta).sub(E.liftFor(F, v.fixed(FIX_BYTE))) };
    return .{ F.zero(), E.SecureFor(F).one() };
}
pub fn emit(comptime F: type, v: anytype, input: *const W.Inputs, output: u256, beta: O, sink: *E.SinkFor(F)) void {
    S.emit(F, v, sink);
    for (input, 0..) |x, i| for (0..32) |b| sink.emit(v.main(S.ACTIVE).mul(v.main(S.INPUT + 32 * i + b).sub(E.qFor(F, @intCast((x >> @intCast(8 * b)) & 255)))));
    for (0..32) |b| sink.emit(v.main(S.ACTIVE).mul(v.main(S.OUTPUT + b).sub(E.qFor(F, @intCast((output >> @intCast(8 * b)) & 255)))));
    for (0..BATCHES) |batch| {
        const delta = secure(F, v, 8 * batch, 0).sub(if (batch > 0) secure(F, v, 8 * (batch - 1), 0) else secure(F, v, LAST, -1));
        const l = fraction(F, v, beta, 2 * batch);
        const r = fraction(F, v, beta, 2 * batch + 1);
        sink.emit(delta.mul(l[1]).mul(r[1]).sub(E.mulBaseFor(F, r[1], l[0])).sub(E.mulBaseFor(F, l[1], r[0])));
    }
}
