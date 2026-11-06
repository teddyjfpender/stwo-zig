//! M8 outer-job host tests (no GPU): class plan, enqueue-only trace commit
//! call sequence, per-class graph cache policy, staged image layout.
test {
    _ = @import("rv64/jobs/outer_plan.zig");
    _ = @import("rv64/jobs/outer_trace_commit.zig");
    _ = @import("rv64/jobs/outer_graph_cache.zig");
    _ = @import("rv64/jobs/outer_kernels.zig");
    _ = @import("rv64/jobs/outer_staged.zig");
    _ = @import("rv64/jobs/outer_composition.zig");
    _ = @import("rv64/jobs/outer_heap.zig");
    _ = @import("rv64/jobs/outer_fixed_job.zig");
    _ = @import("rv64/jobs/outer_env.zig");
    _ = @import("rv64/jobs/outer_window.zig");
    _ = @import("rv64/jobs/outer_device.zig");
    _ = @import("rv64/jobs/truth_job.zig");
}
