//! Explicit CPU-only diagnostic operational limits, separate from acceptance.
const std = @import("std");
pub const live_bytes: usize = 24 << 30;
pub const fixed_cache_bytes: usize = 12 << 30;
pub fn ordinal(args: anytype) !usize {
    if (args.len != 4 and args.len != 5) return error.ExpectedScheduleConfigProofDirectoryAndOptionalOrdinal;
    return if (args.len == 5) try std.fmt.parseUnsigned(usize, args[4], 10) else 0;
}
test "diagnostic ordinal form does not reuse fixed-budget argument parsing" {
    const a = [_][]const u8{ "driver", "inspect-recursion-schedule", "config", "proof" };
    try std.testing.expectEqual(@as(usize, 0), try ordinal(&a));
    try std.testing.expectEqual(@as(usize, 7), try ordinal(&(a ++ [_][]const u8{"7"})));
    try std.testing.expectError(error.ExpectedScheduleConfigProofDirectoryAndOptionalOrdinal, ordinal(&(a ++ [_][]const u8{ "7", "extra" })));
    try std.testing.expectError(error.InvalidCharacter, ordinal(&(a ++ [_][]const u8{"-1"})));
    try std.testing.expect(fixed_cache_bytes <= live_bytes);
}
