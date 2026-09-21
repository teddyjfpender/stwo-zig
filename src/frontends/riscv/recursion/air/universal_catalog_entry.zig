//! Shared type-level row descriptor; importing it does not import AIR owners.
const roster = @import("universal_roster.zig");

pub const Entry = struct {
    Air: type,
    row: roster.Component,
    /// The three arithmetic components retain an explicit source-location
    /// build selector; every other row has a location-independent builder.
    requires_location: bool = false,
};
