//! Whole-window compatibility surface; implementation shared with Local11.
const API_ = @import("block_v8_endpoint_recursive_profile_v1.zig").For(.whole_window);
pub const TRACE_TREES = API_.TRACE_TREES;
pub const FIRST_ROOTS = API_.FIRST_ROOTS;
pub const RELATION_PAIRS = API_.RELATION_PAIRS;
pub const Limits = API_.Limits;
pub const Owned = API_.Owned;
