//! Exact upstream-compatible Native CUDA Blake proof structure.
//!
//! This namespace is intentionally separate from the retired provisional
//! three-tree Blake experiment. Product routing may depend only on this model.

pub const arena_plan = @import("arena_plan.zig");
pub const facades = @import("facades.zig");
pub const geometry = @import("geometry.zig");
pub const slots = @import("slots.zig");
pub const transcript = @import("transcript.zig");
pub const views = @import("views.zig");

test {
    _ = arena_plan;
    _ = facades;
    _ = geometry;
    _ = slots;
    _ = transcript;
    _ = views;
}
