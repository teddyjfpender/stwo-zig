//! Original B5WM/v1 input policy; generic ownership extraction changes no bytes.
const Input = @import("block_v5_wide_expected_input_owner_v1.zig");
pub const Owned = Input.Owned;
pub const Expected = Input.Expected;
pub const VERSION: u32 = 1;
pub const TAG: u32 = 0x4235574d;
pub fn retain(owner: *Owned) !*Owned {
    return owner.retain();
}
pub fn supplementCells(_: *const Owned) usize {
    return 0;
}
pub fn supplementWords(_: *const Owned) usize {
    return 0;
}
pub fn supplementOffset(_: *const Owned, _: u32) !u32 {
    return error.WideRawInputCellsNotExported;
}
pub fn supplementWord(_: *const Owned, _: u32) !u32 {
    return error.WideRawInputCellsNotExported;
}
pub fn supplementCell(_: *const Owned, _: u32) !u32 {
    return error.WideRawInputCellsNotExported;
}
pub fn mixSupplement(_: *const Owned, _: anytype) void {}
