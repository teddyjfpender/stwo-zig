const std = @import("std");
const R = @import("block_v7_mixed_batch_ranges_v1.zig");
const E = @import("../prover/block_v7_execution_epoch_v1.zig");
const B = @import("block_v7_mixed_public_v1.zig");
const P = @import("blake3_execution_parent_protocol.zig");
fn fixture(entries: []E.Entry, expected: []B.Expected) !R.Scope {
    if (entries.len != expected.len or entries.len < 4) return error.InvalidTestFixture;
    var counts: E.Counts = @splat(0);
    counts[@intFromEnum(E.Family.native)] = @intCast(entries.len - 3);
    inline for ([_]E.Family{ .program, .lookup, .memory_joint }) |family| counts[@intFromEnum(family)] = 1;
    for (entries, 0..) |*entry, i| {
        const family: E.Family = if (i < entries.len - 3) .native else switch (i - (entries.len - 3)) {
            0 => .program,
            1 => .lookup,
            else => .memory_joint,
        };
        entry.* = try E.Entry.init(family, if (family == .native) @intCast(i) else 0, @splat(1), &.{@splat(2)});
    }
    const epoch = try E.Epoch.init(@splat(3), P.Profile.diagnostic_q8_pow0.config(), counts, entries, entries.len);
    for (entries, expected) |entry, *pin| pin.* = .{ .kind = @enumFromInt(@intFromEnum(entry.family)), .index = entry.index, .template = @splat(4), .epoch = epoch.digest, .entry = entry };
    return .{ .epoch = epoch, .profile = .diagnostic_q8_pow0, .public_input_identity = @splat(5) };
}
test "v7 batches cover137 originals with complete epoch and no padding" {
    const a = std.testing.allocator;
    var entries: [137]E.Entry = undefined;
    var roster: [137]B.Expected = undefined;
    const scope = try fixture(&entries, &roster);
    const counts = [_]u32{ 64, 64, 9 };
    var plan = try R.create(a, scope, &roster, &counts, .{});
    defer plan.deinit();
    try std.testing.expectEqual(@as(u32, 137), plan.children);
    try std.testing.expectEqual(@as(u32, 128), plan.ranges[2].first);
    var proofs: [3]R.ExpectedProof = undefined;
    var batches: [3]R.Batch = undefined;
    for (plan.ranges, &proofs, &batches, 0..) |range, *proof, *batch, i| {
        proof.* = .{ .key_id = @splat(@intCast(i + 6)), .public_input_identity = @splat(@intCast(i + 10)) };
        batch.* = .{ .job_identity = plan.identity, .range = range, .epoch = scope.epoch, .config = scope.profile.config(), .public_input_identity = proof.public_input_identity, .key_id = proof.key_id };
    }
    try R.requireCoverage(a, scope, &roster, &counts, &batches, &proofs, .{});
    const saved = batches[1];
    batches[1].range.ordinal = 0;
    try std.testing.expectError(error.UntrustedMixedBatchRange, R.requireCoverage(a, scope, &roster, &counts, &batches, &proofs, .{}));
    batches[1] = saved;
    batches[1].range.first -= 1;
    try std.testing.expectError(error.UntrustedMixedBatchRange, R.requireCoverage(a, scope, &roster, &counts, &batches, &proofs, .{}));
    batches[1] = saved;
    batches[1].epoch.digest[0] ^= 1;
    try std.testing.expectError(error.UntrustedMixedBatchScope, R.requireCoverage(a, scope, &roster, &counts, &batches, &proofs, .{}));
    batches[1] = saved;
    batches[1].key_id[0] ^= 1;
    try std.testing.expectError(error.UntrustedMixedBatchProofPin, R.requireCoverage(a, scope, &roster, &counts, &batches, &proofs, .{}));
    batches[1] = saved;
    try std.testing.expectError(error.InvalidMixedBatchCoverage, R.requireCoverage(a, scope, &roster, &counts, batches[0..2], proofs[0..2], .{}));
    try std.testing.expectError(error.InvalidMixedBatchCoverage, R.create(a, scope, &roster, &.{ 64, 64, 8 }, .{}));
    try std.testing.expectError(error.InvalidMixedBatchCoverage, R.create(a, scope, &roster, &.{ 65, 64, 8 }, .{}));
    try std.testing.expectError(error.InvalidMixedBatchCoverage, R.create(a, scope, &roster, &.{ 64, 0, 64, 9 }, .{}));
    try std.testing.expectError(error.MixedBatchResourceLimit, R.create(a, scope, &roster, &counts, .{ .max_children = 136 }));
    try std.testing.expectError(error.MixedBatchResourceLimit, R.create(a, scope, &roster, &counts, .{ .max_metadata_bytes = 1 }));
    roster[64] = roster[63];
    try std.testing.expectError(error.InvalidV7EpochRoster, R.create(a, scope, &roster, &counts, .{}));
}
test "v7 batches reject missing providers and separately pinned epoch mutation" {
    var entries: [65]E.Entry = undefined;
    var roster: [65]B.Expected = undefined;
    const scope = try fixture(&entries, &roster);
    var other = scope;
    other.epoch.counts[@intFromEnum(E.Family.memory_joint)] = 0;
    try std.testing.expectError(error.InvalidV7EpochRoster, R.create(std.testing.allocator, other, &roster, &.{ 64, 1 }, .{}));
    roster[63].entry.roots[0][0] ^= 1;
    try std.testing.expectError(error.UntrustedV7Epoch, R.create(std.testing.allocator, scope, &roster, &.{ 64, 1 }, .{}));
    roster[63].entry.roots[0][0] ^= 1;
    roster[64].epoch[0] ^= 1;
    try std.testing.expectError(error.MixedV7Epochs, R.create(std.testing.allocator, scope, &roster, &.{ 64, 1 }, .{}));
}
test "v7 batch independent setup is compiled from metadata" {
    std.mem.doNotOptimizeAway(&@import("block_v7_mixed_batch_fixed_v1.zig").Owned.derive);
    std.mem.doNotOptimizeAway(&@import("block_v7_mixed_batch_fixed_join_v1.zig").Owned.derive);
}
test "v7 whole admission preserves bounded direct entrypoint" {
    std.mem.doNotOptimizeAway(&@import("block_v7_mixed_inputs_v1.zig").Owned.initWhole);
    std.mem.doNotOptimizeAway(&@import("block_v7_mixed_inputs_v1.zig").Owned.window);
    std.mem.doNotOptimizeAway(&@import("../prover/block_v7_global_public_closure_v1.zig").closeWholePublic);
}
test "v7 final batch receiver codegen uses complete global closure" {
    std.mem.doNotOptimizeAway(&@import("block_v7_mixed_batch_receiver_v1.zig").Metadata.init);
    std.mem.doNotOptimizeAway(&@import("block_v7_mixed_batch_receiver_v1.zig").verify);
}
test "v7 bounded original window collection codegen" {
    std.mem.doNotOptimizeAway(&@import("block_v7_mixed_collection_v1.zig").prepareWindow);
    std.mem.doNotOptimizeAway(&@import("block_v7_mixed_fixed_v1.zig").Owned.deriveWindow);
}
