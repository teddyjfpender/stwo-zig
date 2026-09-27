//! Distinct B5Y authority for full native capacity fused recursion, sharing
//! one reusable parent implementation with the independently typed caller.
const Bus = @import("block_v5_native_capacity_fused_recursive_public_bus_v1.zig");
pub const API = @import("block_v5_reusable_fused_parent_protocol_v1.zig").ForBus(Bus, .{ .claim = 0x42355951, .key = 0x4235594b, .admission = 0x42355941, .proof = 0x42355950 });
pub const VERSION = API.VERSION;
pub const CLAIM_TAG = API.CLAIM_TAG;
pub const Profile = API.Profile;
pub const Context = API.Context;
pub const Key = API.Key;
pub const Admission = API.Admission;
