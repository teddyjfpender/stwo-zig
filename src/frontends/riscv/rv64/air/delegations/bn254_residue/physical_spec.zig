//! Physical square-bank adapter:36 Frobenius rows use its existing padding.
//! All actual Frobenius terms fit the broader qualified square envelope.
const Logical = @import("spec.zig");
pub const B = Logical.B;
pub const Kind = enum { square, multiply };
pub fn inputs(kind: Kind) usize {
    return if (kind == .square) 12 else 24;
}
pub fn rows(kind: Kind) usize {
    return if (kind == .square) 48 else 12;
}
pub fn terms(comptime kind: Kind, comptime opcode: usize) []const B.Term {
    return if (kind == .multiply) Logical.terms(.multiply, opcode) else if (opcode < 12) Logical.terms(.square, opcode) else Logical.terms(.frobenius, opcode - 12);
}
pub fn commonGeometry(comptime kind: Kind) B.RelationGeometry {
    return if (kind == .square) Logical.commonGeometry(.square) else Logical.commonGeometry(.multiply);
}
