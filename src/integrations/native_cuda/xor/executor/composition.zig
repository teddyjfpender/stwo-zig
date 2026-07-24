//! Native XOR instantiation of shared resident composition stages.

const Executor = @import("../../common/native_composition.zig").ExecutorFor(
    @import("../plan.zig"),
    @import("../constraint.zig"),
    @import("../slots.zig"),
);

pub const run = Executor.run;
