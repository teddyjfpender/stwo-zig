//! Whole-window compatibility surface; implementation shared with Local11.
const API_ = @import("block_v8_endpoint_recursive_transcript_v1.zig").For(.whole_window);
pub const PUBLIC_CIRCUIT = API_.PUBLIC_CIRCUIT;
pub const statement = API_.statement;
pub const fixed = API_.fixed;
pub const replay = API_.replay;
