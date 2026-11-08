//! Node result/lifetime contracts; complete proof parity belongs to rv64_gate.
test {
    _ = @import("rv64/jobs/outer_result.zig");
    _ = @import("rv64/jobs/outer_job.zig");
    _ = @import("rv64/jobs/outer_encode_job.zig");
}
