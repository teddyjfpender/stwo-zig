//! Explicit SHA-capable Ethereum specialization of the canonical leaf pipeline.
const Api = @import("blake3_extension_proof.zig").ForProfile(@import("blake3_ethereum_sha_profile.zig"));
pub const Proof = Api.Proof;
pub const Verified = Api.Verified;
pub const Proved = Api.Proved;
pub const codec = Api.codec;
pub const ForBackend = Api.ForBackend;
