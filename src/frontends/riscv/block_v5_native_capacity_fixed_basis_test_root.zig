//! Explicit filter "capacity fixed admission" is pure/body-only.
//! "capacity fixed lease" commits tiny CPU fixed/main trees, no proof/guest.
test {
    _ = @import("prover/block_v5_native_capacity_fixed_basis_test.zig");
}
