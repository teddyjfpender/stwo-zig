//! SHA-pinned independent public receiver policy, never proof authority. The
//! out-of-band digest and public identity are required before typed decoding.
pub const ForCapacity = @import("block_v5_cpu_receiver_policy_file_impl_v1.zig").ForCapacity;
const Default = ForCapacity(false);
pub const FILE = Default.FILE;
pub const Limits = Default.Limits;
pub const Identity = Default.Identity;
pub const Owned = Default.Owned;
pub const write = Default.write;
pub const read = Default.read;
pub const FORMAT = Default.FORMAT;
pub const VERSION = Default.VERSION;
pub const requireFormat = Default.requireFormat;
