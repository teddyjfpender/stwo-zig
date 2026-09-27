//! B5CT detached transport specialization. Canonical Wire/read/serializer are
//! shared; the typed capacity receiver independently reconstructs all authority.
const Common = @import("block_v5_open_forest_manifest_v1.zig");
const Stage = @import("block_v5_capacity_open_forest_stage_v1.zig");
const Receiver = @import("../recursion/block_v5_capacity_exact_forest_receiver_v1.zig");
const Impl = Common.ForExactReceiver(Receiver);
const std = @import("std");
pub const VERSION = Common.VERSION;
pub const FILE = Common.FILE;
pub const Wire = Common.Wire;
pub const Owned = Common.Owned;
pub const Limits = Common.Limits;
pub const writeWire = Common.writeWire;
pub const read = Common.read;
pub const verifyDetached = Impl.verifyDetached;
pub const verifyDetachedPinned = Impl.verifyDetachedPinned;
pub fn write(a: std.mem.Allocator, dir: std.fs.Dir, staged: *const Stage.Stage, leaves: []const Stage.LeafFile, profile: @import("../recursion/blake3_execution_parent_protocol.zig").Profile, limits: Limits) ![32]u8 {
    return Common.writeForStage(a, dir, staged, leaves, profile, limits);
}
