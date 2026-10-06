const std = @import("std");
const interval = @import("../temporal_interval_v3.zig");
const global = @import("../segment_leaf_local_authority_v3.zig");
const segment = @import("../segment_statement_v2.zig");
const span = @import("../span_statement.zig");
const channel = @import("../poseidon2_channel.zig");
const protocol = @import("../protocol.zig");

test "V3 interval carries an odd verified-child slot without an empty proof" {
    const metadata = try threeLeaves();
    var leaves: [3]interval.IntervalV3 = undefined;
    for (&leaves, &metadata) |*out, *leaf| out.* = try .fromLeaf(leaf);
    const reduced = try interval.reduce(std.testing.allocator, &leaves);
    try std.testing.expectEqual(@as(usize, 3), reduced.stats.leaves);
    try std.testing.expectEqual(@as(usize, 2), reduced.stats.pair_reductions);
    try std.testing.expectEqual(@as(usize, 2), reduced.stats.layers);
    try std.testing.expectEqual(@as(usize, 1), reduced.stats.odd_carries);
    try std.testing.expectError(error.ParentProofUnavailable, reduced.requireVerifiedParent());
    try std.testing.expectEqual(@as(u32, 3), reduced.root.executed.segment_count);
    try std.testing.expectEqualDeep(try metadata[0].identity(), reduced.root.first_leaf_id);
    try std.testing.expectEqualDeep(try metadata[2].identity(), reduced.root.last_leaf_id);
    _ = try reduced.root.rootWords();
    _ = try reduced.root.statementWords();
    try std.testing.expect(!interval.RECURSIVE_PARENT_PROOF_AVAILABLE);
    try std.testing.expect(!interval.PRODUCTION_ACTIVATION);
}

test "V3 interval rejects reordered children and a forged boundary" {
    const metadata = try threeLeaves();
    const a = try interval.IntervalV3.fromLeaf(&metadata[0]);
    const b = try interval.IntervalV3.fromLeaf(&metadata[1]);
    try std.testing.expectError(error.SegmentDiscontinuity, interval.IntervalV3.fold(&b, &a));
    var forged = b;
    forged.entry.snapshot_id = channel.hashBytes("forged", 0x5633_5052);
    try std.testing.expectError(error.MemoryBoundaryMismatch, interval.IntervalV3.fold(&a, &forged));
    try std.testing.expectError(error.InvalidLeaf, a.rootWords());
    const prepared = try interval.PairPreflightV3.init(&a, &b);
    try prepared.validateAgainst(&a, &b);
    try std.testing.expectError(error.ParentProofUnavailable, prepared.requireVerifiedParent());
    var changed = b;
    changed.first_leaf_id = channel.hashBytes("changed-first", 0x5633_5052);
    try std.testing.expectError(error.ParentChanged, prepared.validateAgainst(&a, &changed));
    changed = b;
    changed.family = .temporal_parent_v3;
    try std.testing.expectError(error.InvalidLeaf, prepared.validateAgainst(&a, &changed));
    var changed_preflight = prepared;
    changed_preflight.parent_statement_words[0] = @import("stwo_core").fields.m31.M31.fromCanonical(1);
    try std.testing.expectError(error.ParentChanged, changed_preflight.validateAgainst(&a, &b));
}

test "V3 interval rejects absent final completion" {
    var metadata = try threeLeaves();
    metadata[2].completion = null;
    try std.testing.expectError(error.CompletionMissing, interval.IntervalV3.fromLeaf(&metadata[2]));
}

test "V3 interval retains a global cycle beyond the V2 cap" {
    const cycles = [3]u32{ 8_388_608, 8_388_608, 2 };
    const metadata = try threeLeavesWithCycles(cycles);
    var leaves: [3]interval.IntervalV3 = undefined;
    for (&leaves, &metadata) |*out, *leaf| out.* = try .fromLeaf(leaf);
    const first_pair = try interval.PairPreflightV3.init(&leaves[0], &leaves[1]);
    try std.testing.expectEqual(@as(u64, cycles[0]), first_pair.global_join_cycle);
    const reduced = try interval.reduce(std.testing.allocator, &leaves);
    try std.testing.expectEqual(
        @as(u64, segment.MAX_GLOBAL_CYCLES) + 2,
        reduced.root.executed.endCycle(),
    );
}

fn threeLeaves() ![3]global.MetadataV3 {
    return threeLeavesWithCycles(.{ 3, 2, 2 });
}

fn threeLeavesWithCycles(cycles: [3]u32) ![3]global.MetadataV3 {
    const initial_id = digest("initial");
    const middle_1_id = digest("middle-1");
    const middle_2_id = digest("middle-2");
    const final_id = digest("final");
    const states = [4]span.MachineState{
        try state(0, initial_id),
        try state(1, middle_1_id),
        try state(2, middle_2_id),
        try state(3, final_id),
    };
    const snapshots = [4]span.Digest{ initial_id, middle_1_id, middle_2_id, final_id };
    const input = digest("input");
    const output = digest("output");
    const total_cycles: u64 = @as(u64, cycles[0]) + cycles[1] + cycles[2];
    const job = try span.JobContext.init(
        try span.CompleteExecution.init(
            protocol.PROTOCOL_ID_WORDS,
            digest("program"),
            states[0],
            states[3],
            input,
            output,
            total_cycles,
        ),
        3,
    );
    const starts = [3]u64{ 0, cycles[0], @as(u64, cycles[0]) + cycles[1] };
    var result: [3]global.MetadataV3 = undefined;
    for (&result, 0..) |*item, index| {
        const statement = try span.SpanStatement.segmentLeaf(
            job,
            @intCast(index),
            try span.ExecutedSpan.init(
                @intCast(index),
                1,
                starts[index],
                cycles[index],
                states[index],
                states[index + 1],
                if (index == 0) try span.EdgeClaim.present(input) else span.EdgeClaim.absent(),
                if (index == 2) try span.EdgeClaim.present(output) else span.EdgeClaim.absent(),
            ),
        );
        item.* = .{
            .base_statement_words = try statement.canonicalWords(),
            .segment_index = @intCast(index),
            .segment_count = 3,
            .global_cycle_start = starts[index],
            .global_cycle_end = starts[index] + cycles[index],
            .local_cycle_count = cycles[index],
            .entry = boundary(snapshots[index]),
            .exit = boundary(snapshots[index + 1]),
            .completion = if (index == 2) .{
                .kind = .halt_flag,
                .address = 0x100,
                .value = 1,
                .clock = cycles[index] - 1,
            } else null,
        };
        try item.validate();
    }
    return result;
}

fn boundary(snapshot: span.Digest) global.BoundaryV3 {
    return .{
        .snapshot_id = snapshot,
        .snapshot_count = 0,
        .continuation_root = 0,
        .register_clocks = .{0} ** 32,
        .memory_clock_id = segment.memoryClockIdentity(&.{}),
        .memory_clock_count = 0,
    };
}

fn state(seed: u32, rw: span.Digest) !span.MachineState {
    var regs = [_]u32{0} ** 32;
    regs[1] = seed;
    return span.MachineState.init(seed * 4, regs, rw, .{0} ** 8);
}

fn digest(label: []const u8) span.Digest {
    return channel.hashBytes(label, 0x5633_5052);
}
