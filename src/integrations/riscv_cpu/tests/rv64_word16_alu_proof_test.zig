const std = @import("std");
const F = @import("../word16/alu_fixture.zig");
test "experimental Word16 ALU D3 proves complete paired U16/function closures in one PCS" {
    const a = std.testing.allocator;
    const encoded = try F.produce(a, .none);
    defer a.free(encoded.bytes);
    try F.verify(a, encoded, false);
    if (F.verify(a, encoded, true)) |_| return error.ExpectedPrefixRejection else |_| {}
    // All two caller closures and the merged ALU total remain balanced, but
    // every physical claim is transcript-bound and the other prefixes bind
    // their own claims. Reusing the proof cannot redistribute their debts.
    var balanced = encoded;
    balanced.claims[0] = balanced.claims[0].add(@import("stwo_core").fields.qm31.QM31.one());
    balanced.claims[3] = balanced.claims[3].sub(@import("stwo_core").fields.qm31.QM31.one());
    balanced.claims[1] = balanced.claims[1].sub(@import("stwo_core").fields.qm31.QM31.one());
    balanced.claims[2] = balanced.claims[2].add(@import("stwo_core").fields.qm31.QM31.one());
    if (F.verify(a, balanced, false)) |_| return error.ExpectedBalancedClaimRejection else |_| {}
    inline for (.{ .result, .carry, .sign_range, .sum_zero_range }) |attack| {
        if (F.produce(a, attack)) |forged| {
            a.free(forged.bytes);
            return error.ExpectedAluForgeryRejection;
        } else |err| try std.testing.expectEqual(error.ConstraintsNotSatisfied, err);
    }
}
