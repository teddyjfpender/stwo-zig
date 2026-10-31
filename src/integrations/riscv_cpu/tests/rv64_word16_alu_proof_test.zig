const std = @import("std");
const F = @import("../word16/alu_fixture.zig");
test "experimental Word16 ALU D3 proves complete paired U16/function closures in one PCS" {
    const a = std.testing.allocator;
    const encoded = try F.produce(a, .none);
    defer a.free(encoded.bytes);
    try F.verify(a, encoded, false);
    if (F.verify(a, encoded, true)) |_| return error.ExpectedPrefixRejection else |_| {}
    inline for (.{ .result, .carry, .sign_range }) |attack| {
        if (F.produce(a, attack)) |forged| {
            a.free(forged.bytes);
            return error.ExpectedAluForgeryRejection;
        } else |err| try std.testing.expectEqual(error.ConstraintsNotSatisfied, err);
    }
}
