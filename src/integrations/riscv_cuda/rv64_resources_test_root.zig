//! Fast resource/arena contracts; no prover imports or GPU library.
test {
    _ = @import("rv64/jobs/resources.zig");
    _ = @import("rv64/jobs/arena.zig");
    _ = @import("rv64/jobs/job_timing.zig");
    _ = @import("rv64/jobs/memory_plan.zig");
    _ = @import("rv64/jobs/driver_memory.zig");
}
