const std = @import("std");
const core = @import("stwo_core");
const suite = core.proof_suites.Blake3;
/// PCS capture records committed evaluation domains, whereas original typed
/// component manifests describe trace domains. Preserve exact column count and
/// independently require the configured FRI extension for every column.
pub fn requireExtendedLogs(comptime failure: anyerror, raw: []const u32, captured: []const u32, blowup: u32) !void {
    if (raw.len != captured.len) return failure;
    for (raw, captured) |trace_log, actual| {
        const extended = std.math.add(u32, trace_log, blowup) catch return failure;
        if (actual != extended) return failure;
    }
}
test "proof capture validates actual FRI extended PCS column geometry" {
    const a = std.testing.allocator;
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 2, 3) };
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel).init(a, config);
    defer verifier.deinit(a);
    var channel = suite.Channel{};
    const raw = [_]u32{ 3, 5 };
    try verifier.commit(a, @splat(7), &raw, &channel);
    var committed = try verifier.columnLogSizes(a);
    defer committed.deinitDeep(a);
    try requireExtendedLogs(error.InvalidProofCaptureGeometry, &raw, committed.items[0], config.fri_config.log_blowup_factor);
    try std.testing.expectError(error.InvalidProofCaptureGeometry, requireExtendedLogs(error.InvalidProofCaptureGeometry, &raw, &raw, 2));
    try std.testing.expectError(error.InvalidProofCaptureGeometry, requireExtendedLogs(error.InvalidProofCaptureGeometry, &raw, committed.items[0][0..1], 2));
    committed.items[0][1] += 1;
    try std.testing.expectError(error.InvalidProofCaptureGeometry, requireExtendedLogs(error.InvalidProofCaptureGeometry, &raw, committed.items[0], 2));
    try std.testing.expectError(error.InvalidProofCaptureGeometry, requireExtendedLogs(error.InvalidProofCaptureGeometry, &.{std.math.maxInt(u32)}, &.{1}, 2));
    try requireExtendedLogs(error.InvalidProofCaptureGeometry, &.{}, &.{}, 2);
}
