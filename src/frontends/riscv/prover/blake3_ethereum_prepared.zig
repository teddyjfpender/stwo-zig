//! Ethereum prepared-key specialization.
pub fn ForBackend(comptime Backend: type) type {
    return @import("blake3_extension_prepared.zig").ForBackend(@import("blake3_ethereum_profile.zig"), Backend);
}
