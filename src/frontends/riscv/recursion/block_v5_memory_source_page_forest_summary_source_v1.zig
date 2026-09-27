//! Summary-only fresh custody using the canonical original PAGE Source body.
//! Every admission/normalization/claim check remains in that implementation.
const Original = @import("block_v5_memory_source_page_forest_source_v1.zig");
const Impl = Original.ForReceiver(@import("block_v5_memory_source_page_forest_summary_receiver_v1.zig"));
pub const PUBLIC_CIRCUIT = Original.PUBLIC_CIRCUIT;
pub const Coordinate = Original.Coordinate;
pub const Source = Impl.Source;
pub const Admission = Impl.Admission;
