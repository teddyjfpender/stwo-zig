//! Exact upstream-compatible Native CUDA Blake proof structure.
//!
//! This namespace is intentionally separate from the retired provisional
//! three-tree Blake experiment. Product routing may depend only on this model.

pub const activation = @import("activation.zig");
pub const arena_plan = @import("arena_plan.zig");
pub const executor = @import("executor.zig");
pub const facades = @import("facades.zig");
pub const geometry = @import("geometry.zig");
pub const oracle = @import("oracle.zig");
pub const slots = @import("slots.zig");
pub const terminal = @import("terminal.zig");
pub const topology = @import("topology.zig");
pub const transcript = @import("transcript.zig");
pub const trace_binding = @import("trace_binding.zig");
pub const views = @import("views.zig");

test {
    _ = activation;
    _ = arena_plan;
    _ = executor;
    _ = facades;
    _ = geometry;
    _ = oracle;
    _ = slots;
    _ = terminal;
    _ = topology;
    _ = transcript;
    _ = trace_binding;
    _ = views;
}
