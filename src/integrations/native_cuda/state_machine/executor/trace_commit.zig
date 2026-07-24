//! Native state-machine instantiation of shared resident trace stages.

const Executor = @import(
    "../../common/native_trace_commit.zig",
).ExecutorForWithStatement(
    @import("../plan.zig"),
    @import("../device_trace.zig"),
    @import("statement.zig").DeferredTraceMix,
);

pub const generate = Executor.generate;
pub const commit = Executor.commit;
