//! Native Plonk instantiation of shared resident trace stages.

const Executor = @import("../../common/native_trace_commit.zig").ExecutorFor(
    @import("../plan.zig"),
    @import("../device_trace.zig"),
);

pub const generate = Executor.generate;
pub const commit = Executor.commit;
