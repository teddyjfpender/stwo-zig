//! Complete finite positive pairing MAC12 experiment. No VM/production admission.
test {
    _ = @import("delegations/op_pairing_mac12/physical_test.zig");
    _ = @import("delegations/op_pairing_mac12/column_test.zig");
}
