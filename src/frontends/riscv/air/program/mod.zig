//! Decoded RV32IM program relation table.

pub const opcode = @import("opcode.zig");
pub const commitment = @import("commitment.zig");
pub const decode = @import("decode.zig");
pub const interaction = @import("interaction.zig");
pub const table = @import("table.zig");

test {
    @import("std").testing.refAllDeclsRecursive(@This());
}

/// Explicit Ethereum fixed-program profile preparation; no default selection.
pub const fixed_table_v1 = @import("fixed_table_v1.zig");
