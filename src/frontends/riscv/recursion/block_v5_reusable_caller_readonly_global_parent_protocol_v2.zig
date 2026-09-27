//! A caller B5IC recursive key cannot select a native fused verifier protocol.
const Bus = @import("block_v5_caller_readonly_global_recursive_public_bus_v2.zig");
pub const API = @import("block_v5_reusable_fused_parent_protocol_v1.zig").ForBus(Bus, .{ .claim = 0x42354a51, .key = 0x42354a4b, .admission = 0x42354a41, .proof = 0x42354a50 });
pub const VERSION = API.VERSION;
pub const CLAIM_TAG = API.CLAIM_TAG;
pub const Profile = API.Profile;
pub const Context = API.Context;
pub const Key = API.Key;
pub const Admission = API.Admission;
