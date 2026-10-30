//! One independently keyed verifier proof for a bounded typed original roster.
//! Global execution closure is mandatory in the complete receiver.
pub const Bus = @import("block_v7_mixed_public_v1.zig");
const API = @import("block_v6_direct_batch_protocol_v1.zig").ForBus(Bus, .{ .key = 0x4237534b, .public_input = 0x42375349, .proof = 0x42375350, .claims = 0x42375343 });
pub const VERSION = API.VERSION;
pub const CLAIM_TAG = API.CLAIM_TAG;
pub const Key = API.Key;
pub const Admission = API.Admission;
