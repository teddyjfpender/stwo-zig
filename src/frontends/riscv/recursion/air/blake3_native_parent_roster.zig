//! Canonical native-child BLAKE3 parent roster, shared with row ownership.
pub const Roster = @import("stwo_riscv_air_lang").framework.blake3_component_roster.ForAirs(@import("blake3_native_parent_rows.zig").Airs);
