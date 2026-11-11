//! Exact sparse034 product in BN254 Fq12, i²=-1,u³=9+i,w²=u.
//! Candidate only: no legacy execution profile or service roster admits it.
const Base = @import("../curves/spec.zig");
pub const execution = @import("../../../ethereum_services/bn254_tower.zig");
pub const Kind = execution.Kind;
pub const ALL = [_]Kind{.mul034};
fn product(a: Base.Vec, b: Base.Vec, coefficient: i32) Base.Term {
    return .{ .a = a, .b = b, .coef = coefficient };
}
fn linear(a: Base.Vec, coefficient: i32) Base.Term {
    return .{ .a = a, .coef = coefficient };
}
fn input(i: u8) Base.Vec {
    return .{ .in = i };
}
fn witness(i: u8) Base.Vec {
    return .{ .wit = i };
}
fn output(i: u8) Base.Vec {
    return .{ .out = i };
}
pub fn def(comptime kind: Kind) Base.Def {
    _ = kind;
    return .{
        .limbs = 32,
        .coords = execution.INPUTS,
        .written = execution.OUTPUTS,
        .inputs = execution.INPUTS,
        .outputs = execution.OUTPUTS,
        .witnesses = 14,
        .modulus = .{ .constant = Base.BN254_P },
        .asymmetric_carries = true,
        // Private residues are byte bounded, not assumed canonical. Their
        // carried identities plus final canonical outputs fix the field result.
        .relations = &.{
            &.{ product(input(12), input(19), 1), linear(witness(0), -1) },
            &.{ product(input(13), input(19), 1), linear(witness(1), -1) },
            &.{ product(input(14), input(18), 1), linear(witness(2), -1) },
            &.{ product(input(15), input(18), 1), linear(witness(3), -1) },
            &.{ linear(witness(2), 9), linear(witness(3), -1), linear(witness(4), -1) },
            &.{ linear(witness(2), 1), linear(witness(3), 9), linear(witness(5), -1) },
            &.{ linear(input(16), 9), linear(input(17), -1), linear(witness(6), -1) },
            &.{ linear(input(16), 1), linear(input(17), 9), linear(witness(7), -1) },
            &.{ product(input(0), witness(0), 1), product(input(1), witness(1), -1), product(input(8), witness(6), 1), product(input(9), witness(7), -1), product(input(10), witness(4), 1), product(input(11), witness(5), -1), linear(output(0), -1) },
            &.{ product(input(0), witness(1), 1), product(input(1), witness(0), 1), product(input(8), witness(7), 1), linear(witness(8), -1) },
            &.{ linear(witness(8), 1), product(input(9), witness(6), 1), product(input(10), witness(5), 1), product(input(11), witness(4), 1), linear(output(1), -1) },
            &.{ product(input(2), witness(0), 1), product(input(3), witness(1), -1), product(input(6), witness(2), 1), product(input(7), witness(3), -1), product(input(10), witness(6), 1), product(input(11), witness(7), -1), linear(output(2), -1) },
            &.{ product(input(2), witness(1), 1), product(input(3), witness(0), 1), product(input(6), witness(3), 1), linear(witness(9), -1) },
            &.{ linear(witness(9), 1), product(input(7), witness(2), 1), product(input(10), witness(7), 1), product(input(11), witness(6), 1), linear(output(3), -1) },
            &.{ product(input(4), witness(0), 1), product(input(5), witness(1), -1), product(input(6), input(16), 1), product(input(7), input(17), -1), product(input(8), witness(2), 1), product(input(9), witness(3), -1), linear(output(4), -1) },
            &.{ product(input(4), witness(1), 1), product(input(5), witness(0), 1), product(input(6), input(17), 1), linear(witness(10), -1) },
            &.{ linear(witness(10), 1), product(input(7), input(16), 1), product(input(8), witness(3), 1), product(input(9), witness(2), 1), linear(output(5), -1) },
            &.{ product(input(0), witness(2), 1), product(input(1), witness(3), -1), product(input(4), witness(6), 1), product(input(5), witness(7), -1), product(input(6), witness(0), 1), product(input(7), witness(1), -1), linear(output(6), -1) },
            &.{ product(input(0), witness(3), 1), product(input(1), witness(2), 1), product(input(4), witness(7), 1), linear(witness(11), -1) },
            &.{ linear(witness(11), 1), product(input(5), witness(6), 1), product(input(6), witness(1), 1), product(input(7), witness(0), 1), linear(output(7), -1) },
            &.{ product(input(0), input(16), 1), product(input(1), input(17), -1), product(input(2), witness(2), 1), product(input(3), witness(3), -1), product(input(8), witness(0), 1), product(input(9), witness(1), -1), linear(output(8), -1) },
            &.{ product(input(0), input(17), 1), product(input(1), input(16), 1), product(input(2), witness(3), 1), linear(witness(12), -1) },
            &.{ linear(witness(12), 1), product(input(3), witness(2), 1), product(input(8), witness(1), 1), product(input(9), witness(0), 1), linear(output(9), -1) },
            &.{ product(input(2), input(16), 1), product(input(3), input(17), -1), product(input(4), witness(2), 1), product(input(5), witness(3), -1), product(input(10), witness(0), 1), product(input(11), witness(1), -1), linear(output(10), -1) },
            &.{ product(input(2), input(17), 1), product(input(3), input(16), 1), product(input(4), witness(3), 1), linear(witness(13), -1) },
            &.{ linear(witness(13), 1), product(input(5), witness(2), 1), product(input(10), witness(1), 1), product(input(11), witness(0), 1), linear(output(11), -1) },
        },
    };
}
