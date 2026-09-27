//! Explicit typed capacity complete-bundle transport.
const Impl = @import("block_v5_cpu_receiver_policy_file_v1.zig").ForCapacity(true);
pub const FILE = Impl.FILE;
pub const Limits = Impl.Limits;
pub const Identity = Impl.Identity;
pub const Owned = Impl.Owned;
pub const write = Impl.write;
pub const read = Impl.read;
pub const FORMAT = Impl.FORMAT;
pub const VERSION = Impl.VERSION;
pub const requireFormat = Impl.requireFormat;
