//! Exact bitwise and range-table schemas, counters, and interactions.

pub const counter = @import("stwo_riscv_air_lang").modules.shared_air_lookups_tables_counter;
pub const component = @import("component.zig");
pub const verifier = @import("verifier.zig");
pub const device_interaction = @import("device_interaction.zig");
pub const interaction = @import("interaction.zig");
pub const framework_export = @import("framework_export.zig");
pub const schema = @import("stwo_riscv_air_lang").modules.shared_air_lookups_tables_schema;
pub const source_ingest = @import("source_ingest.zig");

test {
    @import("std").testing.refAllDecls(@This());
}
