//! Retained distributed barrier, binary proof and open-debt rejection checks.
test {
    _ = @import("rv64_distributed/functional_test.zig");
    _ = @import("rv64_distributed/unified_test.zig");
    _ = @import("rv64_distributed/manifest_test.zig");
    _ = @import("rv64_distributed_execution/binary_worker_test.zig");
}
