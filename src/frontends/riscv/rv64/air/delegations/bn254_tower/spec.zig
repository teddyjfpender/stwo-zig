//! Exact sparse034 product in BN254 Fq12, i²=-1,u³=9+i,w²=u.
//! Candidate only: no legacy execution profile or service roster admits it.
const Base = @import("../curves/spec.zig");
pub const execution = @import("../../../ethereum_services/bn254_tower.zig");
pub const Kind = execution.Kind;
pub const ALL = [_]Kind{.mul034};
fn product(a: u8, b: u8, coefficient: i32) Base.Term {
    return .{ .a = .{ .in = a }, .b = .{ .in = b }, .coef = coefficient };
}
fn output(i: u8) Base.Term {
    return .{ .a = .{ .out = i }, .coef = -1 };
}
pub fn def(comptime kind: Kind) Base.Def {
    _ = kind;
    return .{
        .limbs = 32,
        .coords = execution.INPUTS,
        .written = execution.OUTPUTS,
        .inputs = execution.INPUTS,
        .outputs = execution.OUTPUTS,
        .witnesses = 0,
        .modulus = .{ .constant = Base.BN254_P },
        // Like bn254_fp2_mul, arbitrary byte-bounded input representatives are
        // admitted; canonical outputs are checked by the carried truth AIR.
        .relations = &.{
            &.{ product(0, 12, 1), product(1, 13, -1), product(8, 16, 9), product(8, 17, -1), product(9, 16, -1), product(9, 17, -9), product(10, 14, 9), product(10, 15, -1), product(11, 14, -1), product(11, 15, -9), output(0) },
            &.{ product(0, 13, 1), product(1, 12, 1), product(8, 16, 1), product(8, 17, 9), product(9, 16, 9), product(9, 17, -1), product(10, 14, 1), product(10, 15, 9), product(11, 14, 9), product(11, 15, -1), output(1) },
            &.{ product(2, 12, 1), product(3, 13, -1), product(6, 14, 1), product(7, 15, -1), product(10, 16, 9), product(10, 17, -1), product(11, 16, -1), product(11, 17, -9), output(2) },
            &.{ product(2, 13, 1), product(3, 12, 1), product(6, 15, 1), product(7, 14, 1), product(10, 16, 1), product(10, 17, 9), product(11, 16, 9), product(11, 17, -1), output(3) },
            &.{ product(4, 12, 1), product(5, 13, -1), product(6, 16, 1), product(7, 17, -1), product(8, 14, 1), product(9, 15, -1), output(4) },
            &.{ product(4, 13, 1), product(5, 12, 1), product(6, 17, 1), product(7, 16, 1), product(8, 15, 1), product(9, 14, 1), output(5) },
            &.{ product(0, 14, 1), product(1, 15, -1), product(4, 16, 9), product(4, 17, -1), product(5, 16, -1), product(5, 17, -9), product(6, 12, 1), product(7, 13, -1), output(6) },
            &.{ product(0, 15, 1), product(1, 14, 1), product(4, 16, 1), product(4, 17, 9), product(5, 16, 9), product(5, 17, -1), product(6, 13, 1), product(7, 12, 1), output(7) },
            &.{ product(0, 16, 1), product(1, 17, -1), product(2, 14, 1), product(3, 15, -1), product(8, 12, 1), product(9, 13, -1), output(8) },
            &.{ product(0, 17, 1), product(1, 16, 1), product(2, 15, 1), product(3, 14, 1), product(8, 13, 1), product(9, 12, 1), output(9) },
            &.{ product(2, 16, 1), product(3, 17, -1), product(4, 14, 1), product(5, 15, -1), product(10, 12, 1), product(11, 13, -1), output(10) },
            &.{ product(2, 17, 1), product(3, 16, 1), product(4, 15, 1), product(5, 14, 1), product(10, 13, 1), product(11, 12, 1), output(11) },
        },
    };
}
