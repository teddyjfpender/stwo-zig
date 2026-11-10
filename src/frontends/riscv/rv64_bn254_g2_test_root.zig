//! Closed transition source/witness tests; no production profile admission.
test {
    _ = @import("rv64/air/delegations/bn254_g2/tests.zig");
}
test {
    _ = @import("rv64/air/delegations/bn254_dense/tests.zig");
}
