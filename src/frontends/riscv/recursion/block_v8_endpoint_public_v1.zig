//! Whole-window compatibility surface; implementation shared with Local11.
const API_ = @import("block_v8_endpoint_recursive_public_v1.zig").For(.whole_window);
pub const API = API_.API;
pub const Wire = API_.Wire;
pub const Values = API_.Values;
pub const supply = API_.supply;
pub const scheduleDigest = API_.scheduleDigest;
pub const reconstruct = API_.reconstruct;
pub const collect = API_.collect;
