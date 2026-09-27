//! A caller B5CF recursive key cannot select a native fused verifier protocol.
const Bus = @import("block_v5_caller_fused_recursive_public_bus_v1.zig");
pub const API = @import("block_v5_reusable_fused_parent_protocol_v1.zig").ForBus(Bus, .{ .claim = 0x42354651, .key = 0x4235464b, .admission = 0x42354641, .proof = 0x42354650 });
pub const VERSION = API.VERSION;
pub const CLAIM_TAG = API.CLAIM_TAG;
pub const Profile = API.Profile;
pub const Context = API.Context;
pub const Key = API.Key;
pub const Admission = API.Admission;
