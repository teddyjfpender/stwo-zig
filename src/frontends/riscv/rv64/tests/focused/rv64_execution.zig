//! Owned partition of the original mixed execution contract.
test {
    _ = @import("../frequent_operations_test.zig");
    _ = @import("../access_census_test.zig");
    _ = @import("../execution_test.zig");
    _ = @import("../service_session_test.zig");
    _ = @import("../zbb_binary_test.zig");
    _ = @import("../../isa_audit.zig");
    _ = @import("../../candidate_isa_test.zig");
}
