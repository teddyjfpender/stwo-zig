test {
    _ = @import("rv64/tests/gkr_test.zig");
    _ = @import("rv64/scoped_device_copy.zig");
    _ = @import("rv64/schedule_identity.zig");
    _ = @import("rv64/outer_assignment_pack.zig");
    _ = @import("rv64/assignment_suffix.zig");
    _ = @import("rv64/tests/assignment_suffix_generate_test.zig");
    _ = @import("rv64/projection_lifetime.zig");
}
