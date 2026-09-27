//! Canonical native-child BLAKE3 parent roster, shared with row ownership.
pub const Roster = @import("blake3_component_roster.zig").ForAirs(@import("blake3_native_parent_rows.zig").Airs);
