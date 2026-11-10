//! Explicit NEW physical-candidate namespace; logical source identities unchanged.
pub const source = @import("spec.zig");
pub const original_witness = @import("witness.zig");
pub const lowering = @import("lowering.zig");
pub const witness = @import("normalized_witness.zig");
pub fn sourceDigest() [32]u8 {
    return lowering.sourceDigest();
}
