//! Concrete permutation-only RV64 crypto provider. CPU/RAM service bridge is separate.
pub const layout = @import("layout.zig");
pub const equations = @import("equations.zig");
pub const trace = @import("trace.zig");
pub const interaction = @import("interaction.zig");
pub const component = @import("component.zig");
pub const parallel = @import("parallel.zig");
pub const tables = @import("tables.zig");
pub const bridge = struct {
    pub const layout = @import("bridge/layout.zig");
    pub const equations = @import("bridge/equations.zig");
    pub const trace = @import("bridge/trace.zig");
    pub const component = @import("bridge/component.zig");
};
pub const cpu_bus = @import("cpu_bus.zig");

/// Explicit inactive adapter; legacy component links only static triple kernels.
pub const quartet_component = @import("quartet_component.zig");
