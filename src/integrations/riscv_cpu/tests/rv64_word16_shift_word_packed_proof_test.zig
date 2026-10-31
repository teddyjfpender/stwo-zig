const std = @import("std");
const F = @import("../word16/shift_word_packed_fixture.zig");
test "inactive packed-table Word16 SHIFT D3 proves strict table U16 and FUNCTION closures with real modular-alias attacks" {
    const a = std.testing.allocator;
    const encoded = try F.produce(a, .none);
    defer a.free(encoded.bytes);
    try F.verify(a, encoded, false);
    var recorder = @import("stwo_prover_api").stage_profile.Recorder.initWithOptions(a, "cpu-simd16", "packed-word16-shift", .{ .capture_tasks = false, .capture_work = false });
    defer recorder.deinit();
    const recorded = try F.produceWithRecorder(a, .none, &recorder);
    defer a.free(recorded.bytes);
    try std.testing.expectEqualSlices(u8, encoded.bytes, recorded.bytes);
    try std.testing.expectEqual(@as(usize, 0), recorder.stack.items.len);
    if (F.verify(a, encoded, true)) |_| return error.ExpectedShiftPrefixRejection else |_| {}
    try std.testing.expectError(error.OodsNotMatching, F.verifyTablePrefixMutation(a, encoded));
    var balanced = encoded;
    balanced.claims[0] = balanced.claims[0].add(@import("stwo_core").fields.qm31.QM31.one());
    balanced.claims[4] = balanced.claims[4].sub(@import("stwo_core").fields.qm31.QM31.one());
    try std.testing.expectError(error.OodsNotMatching, F.verify(a, balanced, false));
    var noncanonical = encoded;
    noncanonical.claims[4].c0.a.v = @import("stwo_core").fields.m31.Modulus;
    try std.testing.expectError(error.NonCanonicalShiftClaim, F.verify(a, noncanonical, false));
    inline for (.{ .result, .table, .quotient_alias, .sign_alias }) |attack| {
        if (F.produce(a, attack)) |forged| {
            a.free(forged.bytes);
            return error.ExpectedShiftForgeryRejection;
        } else |err| try std.testing.expectEqual(error.ConstraintsNotSatisfied, err);
    }
}
