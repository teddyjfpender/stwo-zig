//! Pinned Stark-V relation placement before LogUp batching.

pub const entry = @import("stwo_riscv_air_lang").modules.shared_air_lookups_entry;
pub const opcode_component = @import("opcode_component.zig");
pub const opcode_entries = @import("opcode_entries.zig");
pub const opcode_interaction = @import("opcode_interaction.zig");
pub const tables = @import("tables/mod.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
