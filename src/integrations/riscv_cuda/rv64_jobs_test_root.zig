//! M8 job runtime host tests (no GPU): contract, worker pipeline on the host
//! device model, channel parity on the model, slab layout, scheduler, lint.
test {
    _ = @import("rv64/jobs/api.zig");
    _ = @import("rv64/jobs/worker.zig");
    _ = @import("rv64/jobs/retained.zig");
    _ = @import("rv64/jobs/plan.zig");
    _ = @import("rv64/jobs/slab.zig");
    _ = @import("rv64/jobs/channel_parity.zig");
    _ = @import("rv64/jobs/lint.zig");
    _ = @import("rv64/jobs/scheduler.zig");
    _ = @import("rv64/jobs/mod.zig");
    _ = @import("rv64/jobs/gpu_native.zig");
    _ = @import("rv64/jobs/driver.zig");
    _ = @import("rv64/jobs/driver_request.zig");
    _ = @import("rv64/jobs/driver_dag.zig");
    _ = @import("rv64/jobs/driver_memory.zig");
    _ = @import("rv64/m8_capture_stream.zig");
    _ = @import("rv64/jobs/outer_device.zig");
}
