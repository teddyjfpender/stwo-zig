//! One verifier STARK, no per-family intermediate wrappers. Global closure is
//! an independent receiver obligation over these exact authenticated values.
const API = @import("block_v6_direct_batch_protocol_v1.zig").ForBus(@import("block_v6_mixed_direct_public_v1.zig"), .{ .key = 0x42364d4b, .public_input = 0x42364d49, .proof = 0x42364d50, .claims = 0x42364d43 });
pub const VERSION = API.VERSION;
pub const CLAIM_TAG = API.CLAIM_TAG;
pub const Key = API.Key;
pub const Admission = API.Admission;
