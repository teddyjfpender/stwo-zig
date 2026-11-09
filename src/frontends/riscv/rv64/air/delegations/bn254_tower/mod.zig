//! Closed-admission OP sparse tower candidate. This module is not a service
//! roster entry: VM, RAM/OWNER/Wire closure and receiver gates must admit it.
pub const spec = @import("spec.zig");
pub const execution = spec.execution;
const C = @import("../curves/mod.zig");
pub const Layout = C.Layout(execution.Kind.mul034);
pub const Native = C.Native(execution.Kind.mul034);
pub const Trace = C.Trace(execution.Kind.mul034);
pub const Component = C.Component(execution.Kind.mul034);
pub const Equations = C.Equations(execution.Kind.mul034);
pub const Challenges = C.equations.Challenges;
pub const narrow = struct {
    pub const dag = @import("dag.zig");
    pub const micro = @import("micro.zig");
    pub const source = @import("narrow_source.zig");
    pub const equations = @import("narrow_equations.zig");
    pub const trace = @import("narrow_trace.zig");
    pub const Component = @import("narrow_component.zig").Component;
};
