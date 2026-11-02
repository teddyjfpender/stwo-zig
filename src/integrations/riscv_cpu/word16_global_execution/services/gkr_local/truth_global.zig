//! Concrete OM8 truth-global pieces, composed under the SAME MAIN commitment
//! as direct arithmetic and authenticated truth-local GKR. No challenge draws.
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const K = A.crypto.keccak;
const S = A.crypto.secp256k1;
const G = A.main_only.global_classic;
pub const KECCAK_INTERACTION = 8 * (K.layout.IO_LANES + 1);
pub const SECP_INTERACTION = 8 * (3 + 1);
pub const KECCAK_CONSTRAINTS = K.layout.IO_LANES + 2;
pub const SECP_CONSTRAINTS = 3 + 2;
pub fn keccakFor(comptime F: type, row: K.equations.RowFor(F), current: []const F, previous: []const F, first: F, last: F, claim: E.ConstFor(F), ch: K.equations.IoFor(E.ConstFor(F)), out: *E.SinkFor(F)) !void {
    return keccakForPolicy(F, .triple_v2, row, current, previous, first, last, claim, ch, out);
}
pub fn keccakForPolicy(comptime F: type, policy: K.equations.BatchPolicy, row: K.equations.RowFor(F), current: []const F, previous: []const F, first: F, last: F, claim: E.ConstFor(F), ch: K.equations.IoFor(E.ConstFor(F)), out: *E.SinkFor(F)) !void {
    if (policy.geometry() == .pair27) {
        var denominators: [2 * K.layout.IO_LANES]E.SecureFor(F) = undefined;
        var weights: [2 * K.layout.IO_LANES]F = undefined;
        for (&denominators, &weights, 0..) |*d, *w, lane| {
            d.* = E.denominatorFor(F, ch.offset, &ch.coefficients, &K.equations.ioTupleR27For(F, row, lane), true);
            w.* = K.equations.ioActiveR27For(F, row, lane);
        }
        return G.singlesFor(F, &denominators, &weights, current, previous, first, last, claim, out);
    }
    var denominators: [K.layout.IO_LANES]E.SecureFor(F) = undefined;
    const weights: [K.layout.IO_LANES]F = @splat(K.equations.ioActiveFor(F, row));
    for (&denominators, 0..) |*d, lane| d.* = E.denominatorFor(F, ch.offset, &ch.coefficients, &K.equations.ioTupleFor(F, row, lane), true);
    try G.singlesFor(F, &denominators, &weights, current, previous, first, last, claim, out);
}
pub fn secpFor(comptime F: type, kind: S.layout.Kind, program: *const S.program.Program, row: S.equations.RowFor(F), current: []const F, previous: []const F, first: F, last: F, claim: E.ConstFor(F), ch: S.equations.WireFor(E.ConstFor(F)), out: *E.SinkFor(F)) !void {
    var denominators: [3]E.SecureFor(F) = undefined;
    var weights: [3]F = undefined;
    for (&denominators, &weights, 0..) |*d, *w, event| {
        d.* = E.denominatorFor(F, ch.offset, &ch.coefficients, &S.equations.wireTupleFor(F, kind, program, row, event), true);
        w.* = S.equations.wireCoefficientFor(F, row, event);
    }
    try G.singlesFor(F, &denominators, &weights, current, previous, first, last, claim, out);
}
