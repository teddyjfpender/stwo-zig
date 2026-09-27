//! Independently pinned B5IN2 recursive verifier protocol.
const Bus = @import("block_v5_readonly_provider_recursive_public_bus_v2.zig");
pub const API = @import("block_v5_reusable_fused_parent_protocol_v1.zig").ForBus(Bus, .{ .claim = 0x42355051, .key = 0x4235504b, .admission = 0x42355041, .proof = 0x42355050 });
pub const VERSION = API.VERSION;
pub const CLAIM_TAG = API.CLAIM_TAG;
pub const Profile = API.Profile;
pub const Context = API.Context;
pub const Key = API.Key;
pub const Admission = API.Admission;
