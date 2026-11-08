//! Installed recursion classes and in-flight node jobs; no GPU or prover.
test {
    _ = @import("rv64/jobs/outer_device.zig");
    _ = @import("rv64/jobs/outer_node_job.zig");
}
