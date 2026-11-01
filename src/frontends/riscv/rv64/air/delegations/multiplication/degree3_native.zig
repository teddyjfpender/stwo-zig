//! Concrete MUL adapter for the shared native2n SIMD/halo authority.
const E = @import("../../evaluation.zig");
const P = @import("degree3_provider.zig");
const Adapter = struct {
    pub const layout = @import("degree3_layout.zig");
    pub const Component = @import("degree3_component.zig").Component;
    pub const MAX_LOG = layout.MAX_LOG;
    pub const STACK_ERROR = error.InvalidRv64MultiplicationWorkerStack;
    pub const SHAPE_ERROR = error.InvalidRv64MultiplicationShape;
    pub fn emitFor(comptime F: type, self: *const Component, fixed: [layout.FIXED]F, main: *const [layout.MAIN]F, current: *const [layout.INTERACTION]F, previous_prefix: E.SecureFor(F), previous_count: F, count: F, sink: *E.SinkFor(F)) void {
        P.evaluateFor(F, fixed, main, current, previous_prefix, previous_count, count, self.challenges, self.byte_alpha, self.claim, sink);
    }
};
const Shared = @import("../../providers/degree3_domain.zig").Kernel(Adapter);
pub const MIN_STACK_BYTES = Shared.MIN_STACK_BYTES;
pub const evaluate = Shared.evaluate;
pub const testing = Shared.testing;
