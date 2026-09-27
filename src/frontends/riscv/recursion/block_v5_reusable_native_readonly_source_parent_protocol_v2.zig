//! Independently pinned B5IN2 recursive verifier protocol.
const Bus = @import("block_v5_native_readonly_source_recursive_public_bus_v2.zig");
pub const API = @import("block_v5_reusable_fused_parent_protocol_v1.zig").ForBus(Bus, .{ .claim = 0x42354e51, .key = 0x42354e4b, .admission = 0x42354e41, .proof = 0x42354e50 });
pub const VERSION = API.VERSION;
pub const CLAIM_TAG = API.CLAIM_TAG;
pub const Profile = API.Profile;
pub const Context = API.Context;
pub const Key = API.Key;
pub const Admission = API.Admission;
