//! Physical type of each input to the existing hybrid CPU polynomial.
const IR = @import("stwo_prover_engine").air.secure_polynomial_program_v2;
const P = @import("profile.zig");
pub const Kind = enum { zero, base, secure };
pub fn expected(component: P.Component, input: IR.Input) Kind {
    if (P.gkrBound(component) and input.tree == 2 and input.column >= 18) return if (input.column == 18) .secure else .zero;
    return .base;
}
