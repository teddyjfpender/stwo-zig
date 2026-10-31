//! Exact homogeneous-projective k256 programs and independently sized arithmetic.
pub const program = @import("program.zig");
pub const layout = @import("layout.zig");
pub const equations = @import("equations.zig");
pub const trace = @import("trace.zig");
pub const component = @import("component.zig");
pub const batch = @import("batch.zig");
pub const bridge = struct {
    pub const layout = @import("bridge/layout.zig");
    pub const equations = @import("bridge/equations.zig");
    pub const trace = @import("bridge/trace.zig");
    pub const component = @import("bridge/component.zig");
};
pub const cpu_bus = @import("cpu_bus.zig");

pub const word16_bridge = struct {
    pub const layout = @import("word16_bridge/layout.zig");
    pub const types = @import("word16_bridge/types.zig");
    pub const equations = @import("word16_bridge/equations.zig");
    pub const source = @import("word16_bridge/source.zig");
    pub const component = @import("word16_bridge/component.zig");
};
