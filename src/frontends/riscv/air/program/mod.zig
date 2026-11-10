//! Decoded RV32IM program relation table.

pub const circuit_layout = @import("circuit_layout.zig");

pub const opcode = @import("opcode.zig");
pub const commitment = @import("commitment.zig");
pub const decode = @import("decode.zig");
pub const interaction = @import("interaction.zig");
pub const table = @import("table.zig");

test {
    @import("std").testing.refAllDeclsRecursive(@This());
}
