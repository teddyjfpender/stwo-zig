test {
    _ = @import("rv64/tests/frequent_operations_test.zig");
    _ = @import("rv64/tests/ethereum_services_test.zig");
    _ = @import("rv64/tests/compact_tape_test.zig");
    _ = @import("rv64/tests/tape_wire_test.zig");
    _ = @import("rv64/tests/access_census_test.zig");
    _ = @import("rv64/tests/execution_test.zig");
    _ = @import("rv64/tests/foundations_test.zig");
    _ = @import("rv64/tests/ethereum_contract_test.zig");
    _ = @import("rv64/tests/service_session_test.zig");
    _ = @import("isa/decode.zig");
}
