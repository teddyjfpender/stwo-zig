//! Focused private gate for the SLLI/SRLI/SRAI fixed-authority cutover.

const authority = @import("air/lang/typed_shifts_imm_authority.zig");

test {
    _ = authority;
    _ = @import("air/lang/typed_shifts_imm_authority_test.zig");
    _ = @import("runner/shifts_imm_retirement.zig");
    _ = @import("runner/shifts_imm_retirement_test.zig");
}
