//! OP-only packet source expression authority. Local OWNER/ranges use the
//! CPU's exact local GKR challenges. Global RAM/Wire remain explicit debts.
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const S = A.crypto.secp256k1.word16_bridge;
pub const KIND = S.types.Kind.bn254_sparse034;
pub const TAG = A.crypto.bn254_tower.execution.TAG;
pub const LOCAL_TERMS = 1 + S.layout.U16.len + S.layout.U8.len;
pub const MAIN_SHAPE = A.main_only.authority.Shape{ .fixed = S.layout.FIXED, .main = S.layout.MAIN, .constraints = 373 };
pub fn emitMainFor(comptime F: type, fixed: []const F, main: []const F, previous: []const F, span: E.CallSpanFor(E.ConstFor(F)), sink: *E.SinkFor(F)) void {
    S.equations.emitMainFor(F, KIND, fixed, main, previous, span, sink);
}
pub fn emitLocalFor(comptime F: type, fixed: []const F, main: []const F, sink: anytype) void {
    @import("fractions.zig").secpBridgeFor(F, KIND, fixed, main, sink);
}
pub fn emitGlobalFor(comptime F: type, fixed: []const F, main: []const F, sink: anytype) void {
    const R = A.memory.closed_ram;
    for (0..4) |lane| {
        const row = S.equations.ramRow(F, main, lane);
        sink.emit(.ram, R.equations.ramTuple(F, .transition, &row, false), main[0]);
        sink.emit(.ram, R.equations.ramTuple(F, .transition, &row, true), main[0].neg());
    }
    sink.emit(.wire, S.equations.wireTuple(F, KIND, fixed, main, false), main[0]);
    sink.emit(.wire, S.equations.wireTuple(F, KIND, fixed, main, true), main[0].mul(fixed[6]).neg());
}
