//! Owner-local focused collection; selected by the maintained catalog.

test {
    _ = @import("air/tests/secp256k1_field_test.zig");
    _ = @import("air/tests/secp256k1_mul_direct_test.zig");
    _ = @import("air/tests/secp256k1_linear_direct_test.zig");
    _ = @import("air/tests/secp256k1_affine_test.zig");
    _ = @import("air/tests/secp256k1_point_direct_test.zig");
    _ = @import("air/tests/secp256k1_split_direct_test.zig");
    _ = @import("air/tests/secp256k1_scalar_direct_test.zig");
    _ = @import("air/tests/secp256k1_table_direct_test.zig");
    _ = @import("air/tests/secp256k1_ecdsa_direct_test.zig");
    _ = @import("air/tests/secp256k1_recovery_direct_test.zig");
}
