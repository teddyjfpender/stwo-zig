//! Fast edit-loop root for the secp256k1 precompile authority.

test {
    _ = @import("air/guest_precompile/secp256k1_field_test.zig");
    _ = @import("air/guest_precompile/secp256k1_mul_direct_test.zig");
    _ = @import("air/guest_precompile/secp256k1_linear_direct_test.zig");
    _ = @import("air/guest_precompile/secp256k1_affine_test.zig");
}
