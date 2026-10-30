//! Whole-window census compatibility surface.
const API_ = @import("block_v8_endpoint_recursive_report_v1.zig").For(.whole_window);
pub const Cells = API_.Cells;
pub const Part = API_.Part;
pub const Tree = API_.Tree;
pub const Report = API_.Report;
pub const derive = API_.derive;
pub const SourcePin = API_.SourcePin;
pub const Manifest = API_.Manifest;
pub const manifest = API_.manifest;
