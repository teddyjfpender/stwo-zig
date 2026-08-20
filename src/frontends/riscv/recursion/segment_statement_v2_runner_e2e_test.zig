//! Real resumable-runner to canonical V2 statement custody.

const std = @import("std");

const runner = @import("../runner/mod.zig");
const public_data_v2 = @import("../air/public_data_v2.zig");
const channel = @import("poseidon2_channel.zig");
const protocol = @import("protocol.zig");
const span = @import("span_statement.zig");
const segment_v2 = @import("segment_statement_v2.zig");

test "real adjacent runner segments authenticate as one canonical V2 span" {
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
        digest("runner-rw-entry"),
        digest("runner-io-entry"),
    );
    const shared_state = try machineState(
        left_result.exit_cpu,
        digest("runner-rw-shared"),
        digest("runner-io-shared"),
    );
    const final_state = try machineState(
        right_result.exit_cpu,
        digest("runner-rw-exit"),
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
