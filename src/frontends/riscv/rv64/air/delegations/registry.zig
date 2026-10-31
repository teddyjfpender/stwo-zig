//! Geometry inventory of implemented providers, not a protocol acceptance API.
//! Arithmetic FUNCTION identities are the actual decoded opcode coordinates.
const D = @import("division/layout.zig");
const M = @import("multiplication/layout.zig");
const K = @import("keccak/layout.zig");
const S = @import("secp256k1/layout.zig");
pub const Family = enum { division, multiplication, keccak, secp_product, secp_linear };
pub const Widths = struct { fixed: usize, main: usize, interaction: usize };
pub fn widths(family: Family) Widths {
    return switch (family) {
        .division => .{ .fixed = D.FIXED, .main = D.MAIN, .interaction = D.INTERACTION },
        .multiplication => .{ .fixed = M.FIXED, .main = M.MAIN, .interaction = M.INTERACTION },
        .keccak => .{ .fixed = K.FIXED, .main = K.MAIN, .interaction = K.INTERACTION },
        .secp_product => secpWidths(.product),
        .secp_linear => secpWidths(.linear),
    };
}
fn secpWidths(kind: S.Kind) Widths {
    return .{ .fixed = S.FIXED, .main = S.main(kind), .interaction = S.interaction(kind) };
}
/// Explicit immutable opcode sets avoid confusing interleaved MULW/DIVW IDs or
/// future opcode variants with a fictitious contiguous operation interval.
pub fn arithmeticFamily(raw: u8) ?Family {
    for (D.OPCODES) |op| if (@intFromEnum(op) == raw) return .division;
    for (M.OPCODES) |op| if (@intFromEnum(op) == raw) return .multiplication;
    return null;
}
