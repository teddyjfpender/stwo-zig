//! Owned partition of the original mixed execution contract.
test {
    _ = @import("compat/product_tree/rv64/tests/ethereum_services_test.zig");
    _ = @import("compat/tests/rv64/tests/tape_wire_test.zig");
    _ = @import("compat/tests/rv64/tests/foundations_test.zig");
    _ = @import("compat/product_tree/rv64/tests/ethereum_contract_test.zig");
}
