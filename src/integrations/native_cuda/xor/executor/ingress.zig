//! Native XOR instantiation of shared canonical ingress.

const Executor = @import("../../common/native_ingress.zig").ExecutorFor(
    @import("../geometry.zig"),
    @import("../plan.zig"),
    @import("../canonical_ingress.zig"),
    @import("../slots.zig"),
);

pub const run = Executor.run;
