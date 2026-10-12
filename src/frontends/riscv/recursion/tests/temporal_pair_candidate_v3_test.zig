const std = @import("std");
const candidate = @import("../temporal_pair_candidate_v3.zig");
const global = @import("../segment_leaf_local_authority_v3.zig");
const segment_v2 = @import("../segment_statement_v2.zig");
const span = @import("../span_statement.zig");
const channel = @import("../poseidon2_channel.zig");
const protocol = @import("../protocol.zig");

const Pair = struct {
    left: global.MetadataV3,
    right: global.MetadataV3,
    parent: span.StatementWords,
};

test "V3 temporal candidate folds adjacent leaves and retains exact preimages" {
    var pair = try fixture();
    const value = try candidate.CandidateV3.init(&pair.left, &pair.right, &pair.parent);
    try value.validateAgainst(&pair.left, &pair.right, &pair.parent);
    try std.testing.expectEqual(@as(usize, 608), value.child_metadata_words[0].len);
    try std.testing.expectEqual(@as(usize, 412), value.parent_statement_words.len);
    try std.testing.expectEqualDeep(try pair.left.identity(), value.child_metadata_ids[0]);
    try std.testing.expectEqualDeep(try pair.right.identity(), value.child_metadata_ids[1]);
    try std.testing.expect(!candidate.PARENT_PROOF_AVAILABLE);
    try std.testing.expect(!candidate.PRODUCTION_ACTIVATION);
}

test "V3 temporal candidate carries a global span beyond the V2 clock cap" {
    var pair = try fixtureAt(2, 4, @as(u64, segment_v2.MAX_GLOBAL_CYCLES) + 17);
    const value = try candidate.CandidateV3.init(&pair.left, &pair.right, &pair.parent);
    try value.validateAgainst(&pair.left, &pair.right, &pair.parent);
    try std.testing.expect(pair.left.global_cycle_start > segment_v2.MAX_GLOBAL_CYCLES);
    try std.testing.expectEqual(@as(u32, 3), pair.left.local_cycle_count);
    try std.testing.expectEqual(@as(u32, 2), pair.right.local_cycle_count);
}

test "V3 temporal candidate rejects position, boundary, completion and ordering changes" {
    var pair = try fixture();
    const original = try candidate.CandidateV3.init(&pair.left, &pair.right, &pair.parent);

    pair.right.global_cycle_start += 1;
    try std.testing.expectError(
        error.GlobalPositionMismatch,
        candidate.CandidateV3.init(&pair.left, &pair.right, &pair.parent),
    );
    pair.right.global_cycle_start -= 1;

    pair.right.entry.snapshot_id = digest("forged-shared-snapshot");
    try std.testing.expectError(
        error.MemorySnapshotMismatch,
        candidate.CandidateV3.init(&pair.left, &pair.right, &pair.parent),
    );
    pair.right.entry.snapshot_id = pair.left.exit.snapshot_id;

    const register_word = span.canonical_layout.entry_state_start +
        span.canonical_layout.machine_state_registers_start_offset + 2;
    pair.right.base_statement_words[register_word] =
        @import("stwo_core").fields.m31.M31.fromCanonical(2);
    try std.testing.expectError(
        error.GlobalPositionMismatch,
        candidate.CandidateV3.init(&pair.left, &pair.right, &pair.parent),
    );
    pair.right.base_statement_words[register_word] =
        @import("stwo_core").fields.m31.M31.fromCanonical(1);

    pair.right.completion = null;
    try std.testing.expectError(
        error.CompletionMissing,
        candidate.CandidateV3.init(&pair.left, &pair.right, &pair.parent),
    );
    pair.right.completion = .{
        .kind = .halt_flag,
        .address = 0x100,
        .value = 1,
        .clock = 1,
    };

    try std.testing.expectError(
        error.GlobalPositionMismatch,
        candidate.CandidateV3.init(&pair.right, &pair.left, &pair.parent),
    );

    var wrong_parent = pair.parent;
    wrong_parent[span.canonical_layout.executed_cycle_count_start] =
        @import("stwo_core").fields.m31.M31.fromCanonical(4);
    try std.testing.expectError(
        error.ParentStatementMismatch,
        candidate.CandidateV3.init(&pair.left, &pair.right, &wrong_parent),
    );

    pair.left.entry.continuation_root = 1;
    try std.testing.expectError(
        error.CandidateChanged,
        original.validateAgainst(&pair.left, &pair.right, &pair.parent),
    );
}

fn fixture() !Pair {
    return fixtureAt(0, 2, 0);
}

fn fixtureAt(first_segment: u32, total_segments: u32, global_start: u64) !Pair {
    const initial_snapshot = digest("initial-snapshot");
    const shared_snapshot = digest("shared-snapshot");
    const final_snapshot = digest("final-snapshot");
    const initial = try machine(0, initial_snapshot);
    const shared = try machine(1, shared_snapshot);
    const final = try machine(2, final_snapshot);
    const input = digest("input");
    const output = digest("output");
    const job = try span.JobContext.init(
        try span.CompleteExecution.init(
            protocol.PROTOCOL_ID_WORDS,
            digest("program"),
            initial,
            final,
            input,
            output,
            global_start + 5,
        ),
        total_segments,
    );
    const left_statement = try span.SpanStatement.segmentLeaf(
        job,
        first_segment,
        try span.ExecutedSpan.init(
            first_segment,
            1,
            global_start,
            3,
            initial,
            shared,
            if (first_segment == 0)
                try span.EdgeClaim.present(input)
            else
                span.EdgeClaim.absent(),
            span.EdgeClaim.absent(),
        ),
    );
    const right_statement = try span.SpanStatement.segmentLeaf(
        job,
        first_segment + 1,
        try span.ExecutedSpan.init(
            first_segment + 1,
            1,
            global_start + 3,
            2,
            shared,
            final,
            span.EdgeClaim.absent(),
            try span.EdgeClaim.present(output),
        ),
    );
    const empty_clocks = segment_v2.memoryClockIdentity(&.{});
    const initial_boundary = boundary(initial_snapshot, empty_clocks);
    const shared_boundary = boundary(shared_snapshot, empty_clocks);
    const final_boundary = boundary(final_snapshot, empty_clocks);
    return .{
        .left = .{
            .base_statement_words = try left_statement.canonicalWords(),
            .segment_index = first_segment,
            .segment_count = total_segments,
            .global_cycle_start = global_start,
            .global_cycle_end = global_start + 3,
            .local_cycle_count = 3,
            .entry = initial_boundary,
            .exit = shared_boundary,
            .completion = null,
        },
        .right = .{
            .base_statement_words = try right_statement.canonicalWords(),
            .segment_index = first_segment + 1,
            .segment_count = total_segments,
            .global_cycle_start = global_start + 3,
            .global_cycle_end = global_start + 5,
            .local_cycle_count = 2,
            .entry = shared_boundary,
            .exit = final_boundary,
            .completion = .{
                .kind = .halt_flag,
                .address = 0x100,
                .value = 1,
                .clock = 1,
            },
        },
        .parent = try (try span.SpanStatement.fold(left_statement, right_statement))
            .canonicalWords(),
    };
}

fn boundary(snapshot_id: span.Digest, clock_id: span.Digest) global.BoundaryV3 {
    return .{
        .snapshot_id = snapshot_id,
        .snapshot_count = 0,
        .continuation_root = 0,
        .register_clocks = .{0} ** 32,
        .memory_clock_id = clock_id,
        .memory_clock_count = 0,
    };
}

fn machine(seed: u32, rw: span.Digest) !span.MachineState {
    var regs = [_]u32{0} ** 32;
    regs[1] = seed;
    return span.MachineState.init(seed * 4, regs, rw, .{0} ** 8);
}

fn digest(label: []const u8) span.Digest {
    return channel.hashBytes(label, 0x5633_5052); // "V3PR"
}
