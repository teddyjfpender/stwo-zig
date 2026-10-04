//! Focused private gate for the RV32 `MULH` fixed-authority cutover.

const authority = @import("air/lang/typed_mulh_authority.zig");

test {
    _ = authority;
    _ = @import("air/lang/tests/typed_mulh_authority_test.zig");
    _ = @import("runner/mulh_retirement.zig");
    _ = @import("runner/tests/mulh_retirement_test.zig");
}
