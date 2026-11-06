//! M8 job runtime host tests (no GPU): contract, worker pipeline on the host
//! device model, channel parity on the model, slab layout, scheduler, lint.
test {
    _ = @import("rv64/jobs/api.zig");
    _ = @import("rv64/jobs/worker.zig");
    _ = @import("rv64/jobs/slab.zig");
    _ = @import("rv64/jobs/channel_parity.zig");
    _ = @import("rv64/jobs/lint.zig");
    _ = @import("rv64/jobs/scheduler.zig");
    _ = @import("rv64/jobs/mod.zig");
}
