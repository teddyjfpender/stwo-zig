//! Distinct provider-leaf file domains; never a base proof or execution leaf.
pub const Family = enum(u32) { range16 = 1, ram_lanes = 2, program_table = 3, native_lookup = 4 };
