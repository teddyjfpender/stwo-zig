//! Canonical nineteen-component native-child BLAKE3 parent roster.
const Airs = @import("blake3_native_parent_rows.zig").Airs;
pub const Roster = @import("blake3_component_roster.zig").WithExtras(.{ Airs[3], Airs[4], Airs[5], Airs[6], Airs[7], Airs[8], Airs[9], Airs[10], Airs[11], Airs[12], Airs[13], Airs[14], Airs[15], Airs[16], Airs[17], Airs[18] });
