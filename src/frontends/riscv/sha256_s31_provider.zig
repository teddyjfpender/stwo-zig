//! Narrow module boundary for S31's SHA witness planner. The packed SHA AIR
//! stays owned by the RISC-V frontend until S31 has a proof-bound roster.
const rows = @import("air/guest_precompile/sha256_compression_rows.zig");
pub const compression = @import("air/guest_precompile/sha256_compression.zig");
pub const Call = rows.Call;
pub const Rows = rows.Rows;
pub const Geometry = rows.Geometry;
pub const prepare = rows.prepare;
