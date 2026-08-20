//! Focused private gate for the RV32 `DIV` fixed-authority cutover.

const authority = @import("air/lang/typed_div_authority.zig");

test {
    _ = authority;
    _ = @import("air/lang/typed_div_authority_test.zig");
    _ = @import("runner/div_retirement.zig");
    _ = @import("runner/div_retirement_test.zig");
}
