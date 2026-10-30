const std = @import("std");
const R = @import("block_v6_mixed_batch_ranges_v1.zig");
const Bus = @import("block_v6_mixed_direct_public_v1.zig");
const scope = R.Scope{ .sealed_digest = @splat(1), .profile = .diagnostic_q8_pow0, .public_input_identity = @splat(2) };
fn roster(out: []Bus.Expected) void {
    for (out, 0..) |*entry, i| entry.* = .{ .native = .{ .index = @intCast(i), .template = @splat(3) } };
}
test "mixed batch range metadata covers more than64 original children without padding" {
    const a = std.testing.allocator;
    var entries: [137]Bus.Expected = undefined;
    roster(&entries);
    const counts = [_]u32{ 64, 64, 9 };
    var plan = try R.create(a, scope, &entries, &counts, .{});
    defer plan.deinit();
    try std.testing.expectEqual(@as(u32, 137), plan.children);
    try std.testing.expectEqual(@as(u32, 128), plan.ranges[2].first);
    var proofs: [3]R.ExpectedProof = undefined;
    var batches: [3]R.Batch = undefined;
    for (plan.ranges, &proofs, &batches, 0..) |range, *proof, *batch, i| {
        proof.* = .{ .key_id = @splat(@intCast(i + 4)), .public_input_identity = @splat(@intCast(i + 8)) };
        batch.* = .{ .job_identity = plan.identity, .range = range, .sealed_digest = scope.sealed_digest, .config = scope.profile.config(), .public_input_identity = proof.public_input_identity, .key_id = proof.key_id };
    }
    try R.requireCoverage(a, scope, &entries, &counts, &batches, &proofs, .{});
    const saved = batches[1];
    batches[1].range.ordinal = 0;
    try std.testing.expectError(error.UntrustedMixedBatchRange, R.requireCoverage(a, scope, &entries, &counts, &batches, &proofs, .{}));
    batches[1] = saved;
    batches[1].range.first -= 1;
    try std.testing.expectError(error.UntrustedMixedBatchRange, R.requireCoverage(a, scope, &entries, &counts, &batches, &proofs, .{}));
    batches[1] = saved;
    batches[1].sealed_digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedMixedBatchScope, R.requireCoverage(a, scope, &entries, &counts, &batches, &proofs, .{}));
    batches[1] = saved;
    batches[1].config.pow_bits += 1;
    try std.testing.expectError(error.UntrustedMixedBatchScope, R.requireCoverage(a, scope, &entries, &counts, &batches, &proofs, .{}));
    batches[1] = saved;
    batches[1].public_input_identity[0] ^= 1;
    try std.testing.expectError(error.UntrustedMixedBatchProofPin, R.requireCoverage(a, scope, &entries, &counts, &batches, &proofs, .{}));
    batches[1] = saved;
    batches[1].key_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedMixedBatchProofPin, R.requireCoverage(a, scope, &entries, &counts, &batches, &proofs, .{}));
    batches[1] = saved;
    var other = scope;
    other.public_input_identity[0] ^= 1;
    try std.testing.expectError(error.UntrustedMixedBatchRange, R.requireCoverage(a, other, &entries, &counts, &batches, &proofs, .{}));
    try std.testing.expectError(error.InvalidMixedBatchCoverage, R.requireCoverage(a, scope, &entries, &counts, batches[0..2], proofs[0..2], .{}));
    try std.testing.expectError(error.MixedBatchResourceLimit, R.create(a, scope, &entries, &counts, .{ .max_children = 136 }));
    try std.testing.expectError(error.MixedBatchResourceLimit, R.create(a, scope, &entries, &counts, .{ .max_metadata_bytes = 1 }));
    try std.testing.expectError(error.InvalidMixedBatchCoverage, R.create(a, scope, &entries, &.{ 64, 64, 8 }, .{}));
    try std.testing.expectError(error.InvalidMixedBatchCoverage, R.create(a, scope, &entries, &.{ 65, 64, 8 }, .{}));
    try std.testing.expectError(error.InvalidMixedBatchCoverage, R.create(a, scope, &entries, &.{ 64, 0, 64, 9 }, .{}));
    entries[64] = entries[63];
    try std.testing.expectError(error.InvalidMixedDirectRoster, R.create(a, scope, &entries, &counts, .{}));
}
test "mixed batch ranges retain family boundaries and provider source seal" {
    const a = std.testing.allocator;
    var entries = [_]Bus.Expected{
        .{ .native = .{ .index = 0, .template = @splat(3) } },
        .{ .provider = .{ .family = .range16, .index = 0, .template = @splat(4), .sealed = scope.sealed_digest, .roots = @splat(@splat(5)) } },
        .{ .auxiliary = .{ .family = .source_raw, .index = 0, .template = @splat(6) } },
        .{ .auxiliary = .{ .family = .source_fold, .index = 0, .template = @splat(7) } },
    };
    var plan = try R.create(a, scope, &entries, &.{ 2, 2 }, .{});
    defer plan.deinit();
    entries[1].provider.sealed[0] ^= 1;
    try std.testing.expectError(error.UntrustedMixedBatchScope, R.create(a, scope, &entries, &.{ 2, 2 }, .{}));
    entries[1].provider.sealed = scope.sealed_digest;
    std.mem.swap(Bus.Expected, &entries[1], &entries[2]);
    try std.testing.expectError(error.InvalidMixedDirectRoster, R.create(a, scope, &entries, &.{ 2, 2 }, .{}));
}
