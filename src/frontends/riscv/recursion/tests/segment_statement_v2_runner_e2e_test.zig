//! Real resumable-runner to canonical V2 statement custody.

const std = @import("std");

const runner = @import("../../runner/mod.zig");
const public_data_v2 = @import("../../air/public_data_v2.zig");
const channel = @import("../poseidon2_channel.zig");
const protocol = @import("../protocol.zig");
const span = @import("../span_statement.zig");
const segment_v2 = @import("../segment_statement_v2.zig");
const io_binding = @import("../segment_public_io_binding_v1.zig");

test "segment statement V2 real adjacent runner segments authenticate as one canonical span" {
    const allocator = std.testing.allocator;
    const instructions = [_]u32{
        0x0010_0093, // ADDI x1, x0, 1.
        0x0020_8113, // ADDI x2, x1, 2.
        0x0000_006f, // JAL  x0, 0: proof-bearing unretired self-loop.
    };
    const elf = runner.trace_dump.buildTestElf(instructions.len, instructions);

    var session = try runner.BaseExecutionSession.init(allocator, &elf, .{});
    defer session.deinit();
    var left_result = try session.startSegment(1);
    defer left_result.deinit();
    var right_result = try session.resumeSegment(
        left_result.continuation.?,
        16,
    );
    defer right_result.deinit();

    try std.testing.expect(!left_result.segment_role.is_last);
    try std.testing.expect(right_result.segment_role.is_last);
    try std.testing.expectEqual(
        runner.CompletionReason.self_loop,
        right_result.completion_reason.?,
    );
    try std.testing.expect(std.meta.eql(
        left_result.exit_cpu,
        right_result.entry_cpu,
    ));

    const public_input = digest("runner-input");
    const public_output = digest("runner-output");
    const initial_state = try machineState(
        left_result.entry_cpu,
        segment_v2.snapshotDigest(left_result.rw_memory.words, .initial_word).id,
        digest("runner-io-entry"),
    );
    const shared_state = try machineState(
        left_result.exit_cpu,
        segment_v2.snapshotDigest(left_result.rw_memory.words, .final_word).id,
        digest("runner-io-shared"),
    );
    const final_state = try machineState(
        right_result.exit_cpu,
        segment_v2.snapshotDigest(right_result.rw_memory.words, .final_word).id,
        digest("runner-io-exit"),
    );
    const total_cycles = try std.math.add(
        u64,
        @intCast(left_result.cycle_count),
        @intCast(right_result.cycle_count),
    );
    const job = try span.JobContext.init(
        try span.CompleteExecution.init(
            protocol.PROTOCOL_ID_WORDS,
            scalarDigest(17),
            initial_state,
            final_state,
            public_input,
            public_output,
            total_cycles,
        ),
        2,
    );
    const left_statement = try leafStatement(
        job,
        &left_result,
        initial_state,
        shared_state,
        try span.EdgeClaim.present(public_input),
        span.EdgeClaim.absent(),
    );
    const right_statement = try leafStatement(
        job,
        &right_result,
        shared_state,
        final_state,
        span.EdgeClaim.absent(),
        try span.EdgeClaim.present(public_output),
    );

    const session_id = digest("runner-session");
    const left_source = try segment_v2.SourceV2.fromSegmentResult(
        session_id,
        left_statement,
        &left_result,
    );
    const right_source = try segment_v2.SourceV2.fromSegmentResult(
        session_id,
        right_statement,
        &right_result,
    );
    try segment_v2.requireAdjacentSources(&left_source, &right_source);

    const left_words = try encode(allocator, &left_source);
    defer allocator.free(left_words);
    const right_words = try encode(allocator, &right_source);
    defer allocator.free(right_words);
    const left_public = try public_data_v2.PublicDataV2.authenticate(left_words);
    const right_public = try public_data_v2.PublicDataV2.authenticate(right_words);
    const adjacency = try public_data_v2.PublicDataV2.authenticateAdjacent(
        &left_public,
        &right_public,
    );
    const left_metadata = try left_public.metadata();
    const right_metadata = try right_public.metadata();

    try std.testing.expectEqual(left_public.wireId(), adjacency.left_wire_id);
    try std.testing.expectEqual(right_public.wireId(), adjacency.right_wire_id);
    try std.testing.expectEqual(
        left_metadata.exit_lineage_id,
        right_metadata.entry_lineage_id,
    );
    try std.testing.expectEqual(
        left_result.exit_access_clocks.register_clocks,
        right_result.entry_access_clocks.register_clocks,
    );
    try std.testing.expectEqualSlices(
        runner.result_mod.MemoryAccessClock,
        left_result.exit_access_clocks.memory_clocks,
        right_result.entry_access_clocks.memory_clocks,
    );
    try std.testing.expectEqual(@as(u32, 0), left_metadata.segment_index);
    try std.testing.expectEqual(@as(u32, 1), right_metadata.segment_index);
    try std.testing.expect(!left_metadata.is_final);
    try std.testing.expect(right_metadata.is_final);

    // Diagnostic of a known protocol limitation: these are the same runner
    // results, yet changing only the advertised public-I/O digests and the
    // otherwise unused public-I/O machine state still authenticates as a V2
    // wire. This exercises statement custody, not proof verification. The
    // verifier needs a versioned relation to actual input/output bytes before
    // these fields can be trusted as application claims.
    var changed_left = left_statement;
    changed_left.job.complete.public_input = digest("different-input-claim");
    changed_left.body.executed.input = try span.EdgeClaim.present(changed_left.job.complete.public_input);
    changed_left.job.complete.initial_state.public_io_state = digest("different-io-entry");
    changed_left.body.executed.entry.public_io_state = changed_left.job.complete.initial_state.public_io_state;
    const changed_left_source = try segment_v2.SourceV2.fromSegmentResult(
        session_id,
        changed_left,
        &left_result,
    );
    const changed_left_words = try encode(allocator, &changed_left_source);
    defer allocator.free(changed_left_words);
    const changed_left_public = try public_data_v2.PublicDataV2.authenticate(changed_left_words);
    const changed_left_metadata = try changed_left_public.metadata();
    try std.testing.expect(!std.meta.eql(left_metadata.public_input, changed_left_metadata.public_input));
    try std.testing.expect(!std.meta.eql(left_statement.body.executed.entry.public_io_state, changed_left.body.executed.entry.public_io_state));

    var changed_right = right_statement;
    changed_right.job.complete.public_output = digest("different-output-claim");
    changed_right.body.executed.output = try span.EdgeClaim.present(changed_right.job.complete.public_output);
    changed_right.job.complete.final_state.public_io_state = digest("different-io-exit");
    changed_right.body.executed.exit.public_io_state = changed_right.job.complete.final_state.public_io_state;
    const changed_right_source = try segment_v2.SourceV2.fromSegmentResult(
        session_id,
        changed_right,
        &right_result,
    );
    const changed_right_words = try encode(allocator, &changed_right_source);
    defer allocator.free(changed_right_words);
    const changed_right_public = try public_data_v2.PublicDataV2.authenticate(changed_right_words);
    const changed_right_metadata = try changed_right_public.metadata();
    try std.testing.expect(!std.meta.eql(right_metadata.public_output, changed_right_metadata.public_output));
    try std.testing.expect(!std.meta.eql(right_statement.body.executed.exit.public_io_state, changed_right.body.executed.exit.public_io_state));
}

test "segment statement V2 experimental public-I/O binding rejects changed claims and bytes" {
    const allocator = std.testing.allocator;
    const instructions = [_]u32{
        0x0010_00b7, // LUI x1, 0x100: output MMIO base.
        0x0040_0113, // ADDI x2, x0, 4.
        0x0020_a223, // SW x2, 4(x1): output length.
        0x02a0_0193, // ADDI x3, x0, 42.
        0x0030_a423, // SW x3, 8(x1): output data.
        0x0000_006f, // JAL x0, 0: self-loop completion.
    };
    var elf = @import("../../runner/guest_precompile/test_elf.zig").buildProgram(
        instructions.len,
        &instructions,
        8,
        .rv32im_zkvm_v1,
    );
    declareInput(&elf);
    const input = [_]u8{ 1, 2, 3, 4, 5 };
    var session = try runner.BaseExecutionSession.init(allocator, &elf, .{ .input = &input });
    defer session.deinit();
    var result = try session.startSegment(16);
    defer result.deinit();
    try std.testing.expect(result.segment_role.is_first and result.segment_role.is_last);
    try std.testing.expectEqualSlices(u8, &.{ 42, 0, 0, 0 }, result.output.?);

    const expected = io_binding.Expected{
        .input_start = result.input_start,
        .input = &input,
        .output_len_addr = result.output_len_addr,
        .output_data_addr = result.output_data_addr,
        .output = result.output orelse &.{},
    };
    try io_binding.validateRunner(&result, expected);
    const zero_io: span.Digest = .{0} ** 8;
    const entry = try machineState(
        result.entry_cpu,
        segment_v2.snapshotDigest(result.rw_memory.words, .initial_word).id,
        zero_io,
    );
    const exit = try machineState(
        result.exit_cpu,
        segment_v2.snapshotDigest(result.rw_memory.words, .final_word).id,
        zero_io,
    );
    const job = try span.JobContext.init(
        try span.CompleteExecution.init(
            protocol.PROTOCOL_ID_WORDS,
            scalarDigest(17),
            entry,
            exit,
            try io_binding.inputDigest(expected),
            try io_binding.outputDigest(expected),
            @intCast(result.cycle_count),
        ),
        1,
    );
    const statement = try leafStatement(
        job,
        &result,
        entry,
        exit,
        try span.EdgeClaim.present(job.complete.public_input),
        try span.EdgeClaim.present(job.complete.public_output),
    );
    const source = try segment_v2.SourceV2.fromSegmentResult(digest("bound-session"), statement, &result);
    const words = try encode(allocator, &source);
    defer allocator.free(words);
    const public = try public_data_v2.PublicDataV2.authenticate(words);
    const coverage = try io_binding.validateAuthenticatedWire(&public, expected);
    try std.testing.expect(coverage.input and coverage.output);
    try io_binding.requireComplete(&.{coverage});

    var changed_input = input;
    changed_input[0] ^= 0xff;
    var changed_expected = expected;
    changed_expected.input = &changed_input;
    try std.testing.expectError(error.RunnerIoMismatch, io_binding.validateRunner(&result, changed_expected));
    try std.testing.expectError(error.InputDigestMismatch, io_binding.validateAuthenticatedWire(&public, changed_expected));

    var changed_job = job;
    changed_job.complete.public_input = try io_binding.inputDigest(changed_expected);
    const changed_statement = try leafStatement(
        changed_job,
        &result,
        entry,
        exit,
        try span.EdgeClaim.present(changed_job.complete.public_input),
        try span.EdgeClaim.present(changed_job.complete.public_output),
    );
    const changed_source = try segment_v2.SourceV2.fromSegmentResult(digest("bound-session"), changed_statement, &result);
    const changed_words = try encode(allocator, &changed_source);
    defer allocator.free(changed_words);
    const changed_public = try public_data_v2.PublicDataV2.authenticate(changed_words);
    try std.testing.expectError(error.InputMemoryMismatch, io_binding.validateAuthenticatedWire(&changed_public, changed_expected));

    var changed_output = expected;
    changed_output.output = &.{9};
    changed_job = job;
    changed_job.complete.public_output = try io_binding.outputDigest(changed_output);
    const output_statement = try leafStatement(
        changed_job,
        &result,
        entry,
        exit,
        try span.EdgeClaim.present(changed_job.complete.public_input),
        try span.EdgeClaim.present(changed_job.complete.public_output),
    );
    const output_source = try segment_v2.SourceV2.fromSegmentResult(digest("bound-session"), output_statement, &result);
    const output_words = try encode(allocator, &output_source);
    defer allocator.free(output_words);
    const output_public = try public_data_v2.PublicDataV2.authenticate(output_words);
    try std.testing.expectError(error.OutputLengthMismatch, io_binding.validateAuthenticatedWire(&output_public, changed_output));

    const changed_output_bytes = [_]u8{ 43, 0, 0, 0 };
    changed_output.output = &changed_output_bytes;
    changed_job = job;
    changed_job.complete.public_output = try io_binding.outputDigest(changed_output);
    const changed_output_statement = try leafStatement(
        changed_job,
        &result,
        entry,
        exit,
        try span.EdgeClaim.present(changed_job.complete.public_input),
        try span.EdgeClaim.present(changed_job.complete.public_output),
    );
    const changed_output_source = try segment_v2.SourceV2.fromSegmentResult(digest("bound-session"), changed_output_statement, &result);
    const changed_output_words = try encode(allocator, &changed_output_source);
    defer allocator.free(changed_output_words);
    const changed_output_public = try public_data_v2.PublicDataV2.authenticate(changed_output_words);
    try std.testing.expectError(error.OutputMemoryMismatch, io_binding.validateAuthenticatedWire(&changed_output_public, changed_output));

    changed_job = job;
    changed_job.complete.initial_state.public_io_state = digest("not-zero-io-state");
    const state_statement = try leafStatement(
        changed_job,
        &result,
        changed_job.complete.initial_state,
        exit,
        try span.EdgeClaim.present(changed_job.complete.public_input),
        try span.EdgeClaim.present(changed_job.complete.public_output),
    );
    const state_source = try segment_v2.SourceV2.fromSegmentResult(digest("bound-session"), state_statement, &result);
    const state_words = try encode(allocator, &state_source);
    defer allocator.free(state_words);
    const state_public = try public_data_v2.PublicDataV2.authenticate(state_words);
    try std.testing.expectError(error.NonZeroPublicIoState, io_binding.validateAuthenticatedWire(&state_public, expected));
}

fn leafStatement(
    job: span.JobContext,
    result: *const runner.SegmentResult,
    entry: span.MachineState,
    exit: span.MachineState,
    input: span.EdgeClaim,
    output: span.EdgeClaim,
) !span.SpanStatement {
    if (result.global_first_cycle == 0) return error.InvalidGlobalCycle;
    return span.SpanStatement.segmentLeaf(
        job,
        result.segment_index,
        try span.ExecutedSpan.init(
            result.segment_index,
            1,
            result.global_first_cycle - 1,
            @intCast(result.cycle_count),
            entry,
            exit,
            input,
            output,
        ),
    );
}

fn machineState(
    cpu: runner.Cpu,
    rw_memory: span.Digest,
    public_io_state: span.Digest,
) !span.MachineState {
    return span.MachineState.init(
        cpu.pc,
        cpu.regs,
        rw_memory,
        public_io_state,
    );
}

fn encode(
    allocator: std.mem.Allocator,
    source: *const segment_v2.SourceV2,
) ![]@import("stwo_core").fields.m31.M31 {
    const words = try allocator.alloc(
        @import("stwo_core").fields.m31.M31,
        try source.canonicalWordCount(),
    );
    errdefer allocator.free(words);
    _ = try source.encodeCanonical(words);
    return words;
}

fn digest(label: []const u8) span.Digest {
    return channel.hashBytes(label, 0x5332_4532); // "S2E2"
}

fn scalarDigest(value: u32) span.Digest {
    var result: span.Digest = .{0} ** channel.RATE;
    result[0] = value;
    return result;
}

fn declareInput(elf: []u8) void {
    const names = "\x00__text_start\x00__text_len\x00__input_start\x00__input_end\x00";
    @memcpy(elf[480..][0..names.len], names);
    std.mem.writeInt(u32, elf[308..312], names.len, .little);
    std.mem.writeInt(u32, elf[268..272], 5 * 16, .little);
    std.mem.writeInt(u32, elf[608..612], @intCast(std.mem.indexOf(u8, names, "__input_start").?), .little);
    std.mem.writeInt(u32, elf[612..616], 0x00100100, .little);
    std.mem.writeInt(u32, elf[624..628], @intCast(std.mem.indexOf(u8, names, "__input_end").?), .little);
    std.mem.writeInt(u32, elf[628..632], 0x00100108, .little);
}
