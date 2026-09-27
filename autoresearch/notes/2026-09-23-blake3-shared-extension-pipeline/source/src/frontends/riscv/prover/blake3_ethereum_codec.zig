const Codec = @import("blake3_ethereum_proof.zig").codec;
pub const MAGIC = Codec.MAGIC;
pub const HEADER_BYTES = Codec.HEADER_BYTES;
pub const MAX_PROOF_BYTES = Codec.MAX_PROOF_BYTES;
pub const encode = Codec.encode;
pub const decode = Codec.decode;
