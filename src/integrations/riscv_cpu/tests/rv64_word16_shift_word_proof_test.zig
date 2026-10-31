const std = @import("std");
const F = @import("../word16/shift_word_fixture.zig");
test "inactive Word16 SHIFT D3 proves strict table U16 and FUNCTION closures with real modular-alias attacks" {
    const a = std.testing.allocator;
    const encoded = try F.produce(a, .none);
    defer a.free(encoded.bytes);
    try F.verify(a, encoded, false);
    if (F.verify(a, encoded, true)) |_| return error.ExpectedShiftPrefixRejection else |_| {}
    inline for (.{ .result, .table, .quotient_alias, .sign_alias }) |attack| {
        if (F.produce(a, attack)) |forged| {
            a.free(forged.bytes);
            return error.ExpectedShiftForgeryRejection;
        } else |err| try std.testing.expectEqual(error.ConstraintsNotSatisfied, err);
    }
}
