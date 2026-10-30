//! Terminal wire compatibility. Window proofs have distinct framing and schema.
pub const ForMode = @import("block_v7_multi_union_codec_family_v1.zig").ForMode;
const Default = ForMode(false);
pub const MAGIC = Default.MAGIC;
pub const HEADER_BYTES = Default.HEADER_BYTES;
pub const Limits = Default.Limits;
pub const Owned = Default.Owned;
pub const encode = Default.encode;
pub const decode = Default.decode;
pub const verifyBytes = Default.verifyBytes;
