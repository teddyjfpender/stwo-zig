//! Focused private gate for the RV32 `MUL` fixed-authority cutover.

const authority = @import("air/lang/typed_mul_authority.zig");

test {
    _ = authority;
    _ = @import("air/lang/typed_mul_authority_test.zig");
    _ = @import("runner/mul_retirement.zig");
    _ = @import("runner/mul_retirement_test.zig");
}
