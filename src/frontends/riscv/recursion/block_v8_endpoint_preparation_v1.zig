//! Whole-window compatibility surface; implementation shared with Local11.
const API_ = @import("block_v8_endpoint_recursive_preparation_v1.zig").For(.whole_window);
pub const Limits = API_.Limits;
pub const Prepared = API_.Prepared;
pub const prepare = API_.prepare;
pub const plan = API_.plan;
