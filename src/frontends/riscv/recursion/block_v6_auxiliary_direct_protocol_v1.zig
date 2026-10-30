//! Caller/PAGE open-equation protocol, not complete-block root authority.
const API = @import("block_v6_direct_batch_protocol_v1.zig").ForBus(@import("block_v6_auxiliary_direct_public_v1.zig"), .{ .key = 0x4236414b, .public_input = 0x42364149, .proof = 0x42364150, .claims = 0x42364143 });
pub const VERSION = API.VERSION;
pub const CLAIM_TAG = API.CLAIM_TAG;
pub const Key = API.Key;
pub const Admission = API.Admission;
