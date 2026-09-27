//! Select the shared leaf continuation implementation by commitment hasher.
const core = @import("stwo_core");
const b2 = @import("blake2_stream4.zig");
const b3 = @import("blake3_stream4.zig");
pub fn supports(comptime H: type) bool {
    return b2.supports(H) or H == core.vcs_lifted.blake3_merkle.MerkleHasher;
}
pub fn Adapter(comptime H: type) type {
    if (H == core.vcs_lifted.blake3_merkle.MerkleHasher) return b3;
    if (b2.supports(H)) return b2;
    @compileError("unsupported leaf stream adapter");
}
