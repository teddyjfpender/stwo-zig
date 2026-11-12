//! Owned partition of the original mixed execution contract.
test {
    _ = @import("tests/frequent_operations_test.zig");
    _ = @import("tests/compact_tape_test.zig");
    _ = @import("tests/access_census_test.zig");
    _ = @import("tests/execution_test.zig");
    _ = @import("tests/service_session_test.zig");
    _ = @import("tests/fast_execution_test.zig");
    _ = @import("tests/boundary_capture_test.zig");
    _ = @import("tests/zbb_binary_test.zig");
    _ = @import("isa_audit.zig");
    _ = @import("candidate_isa_test.zig");
}
