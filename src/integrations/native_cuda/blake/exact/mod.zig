//! Exact upstream-compatible Native CUDA Blake proof structure.
//!
//! This namespace is intentionally separate from the retired provisional
//! three-tree Blake experiment. Product routing may depend only on this model.

pub const activation = @import("activation.zig");
pub const arena_plan = @import("arena_plan.zig");
pub const commitment = @import("commitment.zig");
pub const completion_plan = @import("completion_plan.zig");
pub const completion_bindings = @import("completion_bindings.zig");
pub const executor = @import("executor.zig");
pub const facades = @import("facades.zig");
pub const geometry = @import("geometry.zig");
pub const interaction_plan = @import("interaction_plan.zig");
pub const interaction_ingress = @import("interaction_ingress.zig");
pub const interaction_binding = @import("interaction_binding.zig");
pub const oracle = @import("oracle.zig");
pub const resident_bindings = @import("resident_bindings.zig");
pub const slots = @import("slots.zig");
pub const terminal = @import("terminal.zig");
pub const topology = @import("topology.zig");
pub const transcript = @import("transcript.zig");
pub const trace_binding = @import("trace_binding.zig");
pub const views = @import("views.zig");

test {
    _ = activation;
    _ = arena_plan;
    _ = commitment;
    _ = completion_plan;
    _ = completion_bindings;
    _ = executor;
    _ = facades;
    _ = geometry;
    _ = interaction_ingress;
    _ = interaction_binding;
    _ = oracle;
    _ = slots;
    _ = terminal;
    _ = topology;
    _ = transcript;
    _ = trace_binding;
    _ = views;
}
