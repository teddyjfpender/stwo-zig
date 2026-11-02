//! Concrete DIV product adapter for the shared native2n SIMD/halo authority.
const E = @import("../../../evaluation.zig");
const P = @import("lookup.zig");
const Adapter = struct {
    pub const layout = @import("layout.zig");
    pub const Component = @import("component.zig").Component;
    pub const MAX_LOG = 22;
    pub const STACK_ERROR = error.InvalidDivisionProductWorkerStack;
    pub const SHAPE_ERROR = error.InvalidDivisionProductShape;
    pub fn emitFor(comptime F: type, self: *const Component, fixed: [layout.FIXED]F, main: *const [layout.MAIN]F, current: *const [layout.INTERACTION]F, previous_prefix: E.SecureFor(F), previous_count: F, count: F, sink: *E.SinkFor(F)) void {
        P.emitFor(F, &fixed, main, previous_count, count, current, previous_prefix, self.claim, self.challenges, sink);
    }
};
const Shared = @import("../../../providers/degree3_domain.zig").Kernel(Adapter);
pub const MIN_STACK_BYTES = Shared.MIN_STACK_BYTES;
pub const evaluate = Shared.evaluate;
pub const testing = Shared.testing;
