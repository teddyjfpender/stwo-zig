//! Domain-separated authority for the complete partitioned native verifier.
const Bus = @import("block_v6_partitioned_public_bus_v1.zig");
pub const API = @import("block_v5_reusable_fused_parent_protocol_v1.zig").ForBus(Bus, .{ .claim = 0x42365251, .key = 0x4236524b, .admission = 0x42365241, .proof = 0x42365250 });
pub const VERSION = API.VERSION;
pub const CLAIM_TAG = API.CLAIM_TAG;
pub const Profile = API.Profile;
pub const Context = API.Context;
pub const Key = API.Key;
pub const Admission = API.Admission;
