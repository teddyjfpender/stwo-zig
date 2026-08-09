pub const accumulation = @import("accumulation.zig");
pub const composition_execution = @import("composition_execution.zig");
pub const component_prover = @import("component_prover.zig");
pub const component_trace = @import("component_trace.zig");
pub const device_composition = @import("device_composition.zig");
pub const prepared_domain = @import("prepared_domain.zig");

test {
    _ = composition_execution;
    _ = device_composition;
    _ = component_trace;
    _ = prepared_domain;
    _ = @import("component_prepared_test.zig");
}
