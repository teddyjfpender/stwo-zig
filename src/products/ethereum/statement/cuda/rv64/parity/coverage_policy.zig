//! Private qualification mode owns its complete independent check set.
const std = @import("std");
pub const Mode = enum { all, composition, pcs };

test "full parity mode cannot omit composition or PCS comparisons" {
    try std.testing.expect(composition(.all));
    try std.testing.expect(pcs(.all));
    try std.testing.expect(composition(.composition));
    try std.testing.expect(!pcs(.composition));
    try std.testing.expect(!composition(.pcs));
    try std.testing.expect(pcs(.pcs));
}

pub fn composition(mode: Mode) bool {
    return mode != .pcs;
}
pub fn pcs(mode: Mode) bool {
    return mode != .composition;
}
