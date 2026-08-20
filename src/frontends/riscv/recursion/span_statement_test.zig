//! Canonical statement construction, row admission, and fold soundness gates.

const std = @import("std");
const stwo_core = @import("stwo_core");
const public_data_mod = @import("../air/public_data.zig");
const protocol = @import("protocol.zig");
const statement = @import("span_statement.zig");
const claim = @import("vm_public_claim.zig");
const row10 = @import("air/statement_input_witness.zig");
const row11 = @import("air/statement_semantics_input_witness.zig");

const M31 = stwo_core.fields.m31.M31;

test "R-012 one canonical VM claim owns the 412-word segment statement" {
    const data = testPublicData();
    var encoded_claim = try claim.encode(
        std.testing.allocator,
        &data,
        try claim.Shape.init(3, 3),
    );
    defer encoded_claim.deinit();
    var leaf = try statement.SegmentLeaf.init(
        &data,
        &encoded_claim,
        protocol.protocolId(),
    );
    try leaf.validateAgainst(&data, &encoded_claim);

    const decoded = try statement.SpanStatement.fromCanonicalWords(&leaf.words);
    try std.testing.expectEqual(leaf.root.statement, decoded);
    try std.testing.expectEqual(leaf.words, try decoded.canonicalWords());

    try std.testing.expectEqual(@as(usize, 412), leaf.words.len);
    try expectTag(&leaf.words, statement.canonical_layout.span_tag, .span_statement);
    try expectTag(&leaf.words, statement.canonical_layout.job_tag, .job_context);
    try expectTag(&leaf.words, statement.canonical_layout.complete_tag, .complete_execution);
    try expectTag(
        &leaf.words,
        statement.canonical_layout.initial_state_start,
        .machine_state,
    );
    try expectTag(&leaf.words, statement.canonical_layout.body_tag, .executed_body);
    try expectTag(&leaf.words, statement.canonical_layout.executed_tag, .executed_span);
    try expectTag(&leaf.words, statement.canonical_layout.input_edge_tag, .present_edge);
    try expectTag(&leaf.words, statement.canonical_layout.output_edge_tag, .present_edge);
    try expectDigest(
        &leaf.words,
        statement.canonical_layout.protocol_start,
        protocol.protocolId(),
    );
    try expectDigest(
        &leaf.words,
        statement.canonical_layout.public_input_start,
        encoded_claim.public_input_digest,
    );
    try expectDigest(
        &leaf.words,
        statement.canonical_layout.public_output_start,
        encoded_claim.public_output_digest,
    );
    try std.testing.expectEqual(
        @as(u64, data.clock),
        readU64(&leaf.words, statement.canonical_layout.total_cycles_start),
    );

    var row10_preprocessing = try row10.Preprocessed.init(std.testing.allocator);
    defer row10_preprocessing.deinit();
    const witness = row10.StatementWitness{ .segment_leaf = &leaf.words };
    try std.testing.expectEqual(
        leaf.words[0],
        (try row10.mainRow(row10_preprocessing.rows[0], witness))[1],
    );
    for (0..statement.SPAN_STATEMENT_CANONICAL_WORDS) |index| {
        try std.testing.expectEqual(
            statement.isIntegerWord(index),
            row11.isIntegerWord(index),
        );
    }

    leaf.words[statement.canonical_layout.public_input_start] = M31.zero();
    try std.testing.expectError(
        error.DigestMismatch,
        leaf.validateAgainst(&data, &encoded_claim),
    );
}

test "R-012 canonical statement decoder rejects every encoded vocabulary drift" {
    const data = testPublicData();
    var encoded_claim = try claim.encode(
        std.testing.allocator,
        &data,
        try claim.Shape.init(3, 3),
    );
    defer encoded_claim.deinit();
    const leaf = try statement.SegmentLeaf.init(
        &data,
        &encoded_claim,
        protocol.protocolId(),
    );

    const tag_indices = [_]usize{
        statement.canonical_layout.span_tag,
        statement.canonical_layout.job_tag,
        statement.canonical_layout.complete_tag,
        statement.canonical_layout.initial_state_start,
        statement.canonical_layout.final_state_start,
        statement.canonical_layout.slot_tag,
        statement.canonical_layout.body_tag,
        statement.canonical_layout.executed_tag,
        statement.canonical_layout.entry_state_start,
        statement.canonical_layout.exit_state_start,
        statement.canonical_layout.input_edge_tag,
        statement.canonical_layout.output_edge_tag,
    };
    for (tag_indices) |index| {
        var mutated = leaf.words;
        mutated[index] = M31.zero();
        try std.testing.expectError(
            error.CanonicalTagMismatch,
            statement.SpanStatement.fromCanonicalWords(&mutated),
        );
    }

    for (0..statement.SPAN_STATEMENT_CANONICAL_WORDS) |index| {
        if (!statement.isIntegerWord(index)) continue;
        var mutated = leaf.words;
        mutated[index] = M31.fromCanonical(1 << 16);
        try std.testing.expectError(
            error.CanonicalIntegerLimbOutOfRange,
            statement.SpanStatement.fromCanonicalWords(&mutated),
        );
    }

    var noncanonical = leaf.words;
    noncanonical[statement.canonical_layout.protocol_start] =
        M31.fromU32Unchecked(stwo_core.fields.m31.Modulus);
    try std.testing.expectError(
        error.CanonicalWordNonCanonical,
        statement.SpanStatement.fromCanonicalWords(&noncanonical),
    );

    const job = try statement.JobContext.init(leaf.root.statement.job.complete, 3);
    const empty = try statement.SpanStatement.emptyLeaf(job, 3);
    const empty_words = try empty.canonicalWords();
    for (empty_words[statement.canonical_layout.executed_start..], 0..) |_, offset| {
        var mutated = empty_words;
        mutated[statement.canonical_layout.executed_start + offset] = M31.one();
        try std.testing.expectError(
            error.CanonicalPaddingNonZero,
            statement.SpanStatement.fromCanonicalWords(&mutated),
        );
    }

    const s0 = try machineState(10);
    const s1 = try machineState(11);
    const s2 = try machineState(12);
    const input = digest(80);
    const output = digest(100);
    const pair_job = try statement.JobContext.init(
        try statement.CompleteExecution.init(
            protocol.protocolId(),
            digest(60),
            s0,
            s2,
            input,
            output,
            2,
        ),
        2,
    );
    const left = try statement.SpanStatement.segmentLeaf(
        pair_job,
        0,
        try statement.ExecutedSpan.init(
            0,
            1,
            0,
            1,
            s0,
            s1,
            try statement.EdgeClaim.present(input),
            statement.EdgeClaim.absent(),
        ),
    );
    const right = try statement.SpanStatement.segmentLeaf(
        pair_job,
        1,
        try statement.ExecutedSpan.init(
            1,
            1,
            1,
            1,
            s1,
            s2,
            statement.EdgeClaim.absent(),
            try statement.EdgeClaim.present(output),
        ),
    );
    const absent_cases = [_]struct {
        words: statement.StatementWords,
        digest_start: usize,
    }{
        .{
            .words = try left.canonicalWords(),
            .digest_start = statement.canonical_layout.output_edge_digest_start,
        },
        .{
            .words = try right.canonicalWords(),
            .digest_start = statement.canonical_layout.input_edge_digest_start,
        },
    };
    for (absent_cases) |case| {
        for (0..8) |offset| {
            var mutated = case.words;
            mutated[case.digest_start + offset] = M31.one();
            try std.testing.expectError(
                error.CanonicalPaddingNonZero,
                statement.SpanStatement.fromCanonicalWords(&mutated),
            );
        }
    }
}

test "R-012 statement fold enforces state cycle and edge continuity" {
    const s0 = try machineState(1);
    const s1 = try machineState(2);
    const s2 = try machineState(3);
    const input = digest(40);
    const output = digest(60);
    const complete = try statement.CompleteExecution.init(
        protocol.protocolId(),
        digest(20),
        s0,
        s2,
        input,
        output,
        10,
    );
    const job = try statement.JobContext.init(complete, 2);
    const left_span = try statement.ExecutedSpan.init(
        0,
        1,
        0,
        4,
        s0,
        s1,
        try statement.EdgeClaim.present(input),
        statement.EdgeClaim.absent(),
    );
    const right_span = try statement.ExecutedSpan.init(
        1,
        1,
        4,
        6,
        s1,
        s2,
        statement.EdgeClaim.absent(),
        try statement.EdgeClaim.present(output),
    );
    const left = try statement.SpanStatement.segmentLeaf(job, 0, left_span);
    const right = try statement.SpanStatement.segmentLeaf(job, 1, right_span);
    const parent = try statement.SpanStatement.fold(left, right);
    _ = try statement.RootStatement.init(parent);
    _ = try parent.canonicalWords();

    var broken_right = right;
    broken_right.body.executed.entry.pc +%= 4;
    try std.testing.expectError(
        error.StateDiscontinuity,
        statement.SpanStatement.fold(left, broken_right),
    );

    broken_right = right;
    broken_right.body.executed.first_cycle += 1;
    broken_right.body.executed.cycle_count -= 1;
    try std.testing.expectError(
        error.CycleDiscontinuity,
        statement.SpanStatement.fold(left, broken_right),
    );
}

fn expectTag(
    words: *const statement.StatementWords,
    index: usize,
    expected: statement.Tag,
) !void {
    try std.testing.expectEqual(@as(u32, @intFromEnum(expected)), words[index].toU32());
}

fn expectDigest(
    words: *const statement.StatementWords,
    start: usize,
    expected: statement.Digest,
) !void {
    for (words[start..][0..8], expected) |actual, value|
        try std.testing.expectEqual(value, actual.toU32());
}

fn readU64(words: *const statement.StatementWords, start: usize) u64 {
    var value: u64 = 0;
    inline for (0..4) |limb| value |= @as(u64, words[start + limb].toU32()) << (16 * limb);
    return value;
}

fn digest(seed: u32) statement.Digest {
    var result: statement.Digest = undefined;
    for (&result, 0..) |*word, index| word.* = seed + @as(u32, @intCast(index));
    return result;
}

fn machineState(seed: u32) !statement.MachineState {
    var registers = [_]u32{0} ** 32;
    registers[1] = seed;
    return statement.MachineState.init(seed * 4, registers, digest(seed + 10), digest(seed + 20));
}

const test_input_words = [_]u32{ 0x4433_2211, 0x55 };
const test_output_words = [_]public_data_mod.OutputWord{
    .{ .addr = 0x10_0004, .value = 4, .clock = 5 },
    .{ .addr = 0x10_0008, .value = 0x8877_6655, .clock = 6 },
};

fn testPublicData() public_data_mod.PublicData {
    var initial_regs = [_]u32{0} ** 32;
    initial_regs[1] = 0x8000_0001;
    var final_regs = initial_regs;
    final_regs[2] = 9;
    var reg_last_clock = [_]u32{0} ** 32;
    reg_last_clock[2] = 7;
    return .{
        .initial_pc = 0x1000,
        .final_pc = 0x1004,
        .clock = 8,
        .initial_regs = initial_regs,
        .final_regs = final_regs,
        .reg_last_clock = reg_last_clock,
        .program_root = 1,
        .initial_rw_root = 11,
        .final_rw_root = 21,
        .completion = public_data_mod.Completion.canonicalSelfLoop(0x1004),
        .io_entries = .{
            .input_start = 0x20_0000,
            .input_len = 5,
            .input_words = &test_input_words,
            .output_len = 4,
            .output_len_addr = 0x10_0004,
            .output_data_addr = 0x10_0008,
            .output_words = &test_output_words,
        },
    };
}
