//! Native state-machine instantiation of shared resident composition stages.

const Executor = @import(
    "../../common/native_composition.zig",
).ExecutorForWithPrelude(
    @import("../plan.zig"),
    @import("../constraint.zig"),
    @import("../slots.zig"),
    @import("statement.zig").ConstraintPrelude,
);

pub const run = Executor.run;
