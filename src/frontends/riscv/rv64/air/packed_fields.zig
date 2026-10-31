//! RV64 aliases for the neutral sixteen-row field packet authority.
const fields = @import("../../air/packed_fields16.zig");
pub const LANES = fields.LANES;
pub const NATIVE_LANES = fields.NATIVE_LANES;
pub const PACKS = fields.PACKS;
pub const PackedBase = fields.PackedBase;
pub const PackedSecure = fields.PackedSecure;
