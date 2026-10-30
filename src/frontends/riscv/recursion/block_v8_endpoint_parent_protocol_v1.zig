//! Whole-window compatibility surface; implementation shared with Local11.
const API_ = @import("block_v8_endpoint_recursive_protocol_v1.zig").For(.whole_window);
pub const Bus = API_.Bus;
pub const VERSION = API_.VERSION;
pub const CLAIM_TAG = API_.CLAIM_TAG;
pub const Key = API_.Key;
pub const Admission = API_.Admission;
