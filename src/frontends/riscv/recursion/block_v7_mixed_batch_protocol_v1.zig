//! Original recursive verifier equation with typed mixed-batch public supply.
//! This authenticates ranges/frames; complete job coverage/global algebra are
//! independently checked by the eventual complete receiver.
const API = @import("block_v6_direct_batch_protocol_v1.zig").ForBus(@import("block_v7_mixed_batch_public_v1.zig"), .{ .key = 0x4237524b, .public_input = 0x42375249, .proof = 0x42375250, .claims = 0x42375243 });
pub const VERSION = API.VERSION;
pub const CLAIM_TAG = API.CLAIM_TAG;
pub const Key = API.Key;
pub const Admission = API.Admission;
