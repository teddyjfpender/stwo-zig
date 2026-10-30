//! Finite execution-only memory policy for compact DEEP contribution metadata.
//! The selected membership bitset and group/member arrays are all allocated
//! through the request allocator. These bytes are not a proof/security input.
const std = @import("std");
pub const Budget = enum(u32) {
    one_mib = 1,
    four_mib = 4,
    eight_mib = 8,
    pub fn bytes(self: Budget) usize {
        return @as(usize, @intFromEnum(self)) << 20;
    }
    pub fn parseMiB(mib: u32) !Budget {
        return switch (mib) {
            1 => .one_mib,
            4 => .four_mib,
            8 => .eight_mib,
            else => error.InvalidDeepGroupBudget,
        };
    }
};
test "DEEP compact group budget is finite and preserves one MiB default" {
    for ([_]Budget{ .one_mib, .four_mib, .eight_mib }) |budget| {
        try std.testing.expectEqual(budget, try Budget.parseMiB(@intFromEnum(budget)));
        try std.testing.expectEqual(@as(usize, @intFromEnum(budget)) * 1024 * 1024, budget.bytes());
    }
    for ([_]u32{ 0, 2, 3, 5, 16, std.math.maxInt(u32) }) |value|
        try std.testing.expectError(error.InvalidDeepGroupBudget, Budget.parseMiB(value));
}
