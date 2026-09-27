//! Closed type-to-profile mapping for authenticated execution captures.
pub fn isExtension(comptime Capture: type) bool {
    return Capture == @import("../../prover/blake3_ethereum_capture.zig").Verified or
        Capture == @import("../../prover/blake3_poseidon_proof.zig").Verified;
}
pub fn Extension(comptime Capture: type) type {
    if (Capture == @import("../../prover/blake3_ethereum_capture.zig").Verified) return @import("../../prover/blake3_ethereum_profile.zig");
    if (Capture == @import("../../prover/blake3_poseidon_proof.zig").Verified) return @import("../../prover/blake3_poseidon_profile.zig");
    @compileError("unsupported BLAKE3 extension capture");
}
