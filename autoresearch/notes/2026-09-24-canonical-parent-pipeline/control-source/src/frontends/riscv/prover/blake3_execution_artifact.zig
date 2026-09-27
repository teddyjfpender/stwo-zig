//! Stable base facade over shared full-width profile artifact framing.
const Base = @import("blake3_profile_artifact.zig").ForProfile(false);
pub const MAGIC = Base.MAGIC;
pub const HEADER_BYTES = Base.HEADER_BYTES;
pub const Limits = Base.Limits;
pub const Encoded = Base.Encoded;
pub const Sections = Base.Sections;
pub const hasMagic = Base.hasMagic;
pub const split = Base.split;
pub const encode = Base.encode;
pub const ForBackend = Base.ForBackend;
