//! New universal signed MAC6 source/cost prototype, no production admission.
test {
    _ = @import("rv64/air/delegations/bn254_mac6/tests.zig");
    _ = @import("rv64/air/delegations/bn254_mac6/cost_test.zig");
}
