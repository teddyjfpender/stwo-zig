//! Direct original provider protocol; complete block closure remains external.
const API = @import("block_v6_direct_batch_protocol_v1.zig").ForBus(@import("block_v6_provider_batch_public_v1.zig"), .{ .key = 0x4236504b, .public_input = 0x42365049, .proof = 0x42365050, .claims = 0x42365043 });
pub const VERSION = API.VERSION;
pub const CLAIM_TAG = API.CLAIM_TAG;
pub const Key = API.Key;
pub const Admission = API.Admission;
