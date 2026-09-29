//! Protocol metadata for the pinned public fixed-column variants.
//!
//! The variant lives in `stwo_core.cairo_air_layout` so circuit recursion can
//! share it without importing this frontend.
pub const Variant = @import("stwo_core").cairo_air_layout.Variant;
