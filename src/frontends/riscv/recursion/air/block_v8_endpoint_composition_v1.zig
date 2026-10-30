//! Whole-window compatibility surface; implementation shared with Local11.
const API_ = @import("block_v8_endpoint_recursive_composition_v1.zig").For(.whole_window);
pub const Compiled = API_.Compiled;
pub const publicValues = API_.publicValues;
pub const compile = API_.compile;
pub const prepare = API_.prepare;
