//! Whole-window compatibility surface; implementation shared with Local11.
const API_ = @import("block_v8_endpoint_recursive_pipeline_v1.zig").For(.whole_window);
pub const Limits = API_.Limits;
pub const Stats = API_.Stats;
pub const Artifact = API_.Artifact;
pub const produce = API_.produce;
pub const verify = API_.verify;
