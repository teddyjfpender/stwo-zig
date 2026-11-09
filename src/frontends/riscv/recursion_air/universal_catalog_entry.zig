//! Shared type-level row descriptor; importing it does not import AIR owners.
const roster = @import("stwo_riscv_air_lang").modules.framework_universal_roster;

pub const Entry = struct {
    Air: type,
    row: roster.Component,
    /// The three arithmetic components retain an explicit source-location
    /// build selector; every other row has a location-independent builder.
    requires_location: bool = false,
};
