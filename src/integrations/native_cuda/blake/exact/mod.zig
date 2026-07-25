//! Exact upstream-compatible Native CUDA Blake proof structure.
//!
//! This namespace is intentionally separate from the retired provisional
//! three-tree Blake experiment. Product routing may depend only on this model.

pub const geometry = @import("geometry.zig");
pub const transcript = @import("transcript.zig");
pub const views = @import("views.zig");

test {
    _ = geometry;
    _ = transcript;
    _ = views;
}
