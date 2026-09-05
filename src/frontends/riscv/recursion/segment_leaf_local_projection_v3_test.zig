//! Existing-V2 proof projection for leaf-local large-execution segments.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;

const runner = @import("../runner/mod.zig");
const public_data_v2 = @import("../air/public_data_v2.zig");
const channel = @import("poseidon2_channel.zig");
const protocol = @import("protocol.zig");
const span = @import("span_statement.zig");
const segment_v2 = @import("segment_statement_v2.zig");
const global_v3 = @import("segment_leaf_local_authority_v3.zig");
const projection_v3 = @import("segment_leaf_local_projection_v3.zig");

test "leaf-local V3: deterministic local projection enters authenticated V2 custody" {
    const instructions = [_]u32{
        0x0010_0137,
        0x0550_0093,
        0x0011_2023,
        0x0001_2183,
        0x0010_8193,
        0x0000_006f,
    };
    const elf = runner.trace_dump.buildTestElf(instructions.len, instructions);
    var session = try runner.BaseExecutionSession.init(std.testing.allocator, &elf, .{
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
    });
    defer session.deinit();
    var left_result = try session.startSegment(3);
    defer left_result.deinit();
    var right_result = try session.resumeSegment(left_result.continuation.?, 16);
    defer right_result.deinit();

    const states = States{
        .entry = try machineFromCpu(left_result.entry_cpu, digest("rw-entry")),
        .shared = try machineFromCpu(left_result.exit_cpu, digest("rw-shared")),
        .exit = try machineFromCpu(right_result.exit_cpu, digest("rw-exit")),
    };
    const job = try span.JobContext.init(
        try span.CompleteExecution.init(
            protocol.PROTOCOL_ID_WORDS,
            digest("program"),
            states.entry,
            states.exit,
            digest("input"),
            digest("output"),
            5,
        ),
        2,
    );
    const left_statement = try leafStatement(
        job,
        &left_result,
        states.entry,
        states.shared,
        try span.EdgeClaim.present(job.complete.public_input),
        span.EdgeClaim.absent(),
    );
    const right_statement = try leafStatement(
        job,
        &right_result,
        states.shared,
        states.exit,
        span.EdgeClaim.absent(),
        try span.EdgeClaim.present(job.complete.public_output),
    );
    const left_global = try global_v3.SourceV3.fromSegmentResult(
        left_statement,
        &left_result,
    );
    const right_global = try global_v3.SourceV3.fromSegmentResult(
        right_statement,
        &right_result,
    );
    try global_v3.requireAdjacentSources(&left_global, &right_global);

    var left_projection = try projection_v3.ProjectionV3.init(&left_global);
    var right_projection = try projection_v3.ProjectionV3.init(&right_global);
    const session_id = digest("local-proof-session");
    const left_source = try left_projection.sourceV2(&left_global, session_id);
    const right_source = try right_projection.sourceV2(&right_global, session_id);

    const left_words = try encode(std.testing.allocator, &left_source);
    defer std.testing.allocator.free(left_words);
    const right_words = try encode(std.testing.allocator, &right_source);
    defer std.testing.allocator.free(right_words);
    const left_public = try public_data_v2.PublicDataV2.authenticate(left_words);
    const right_public = try public_data_v2.PublicDataV2.authenticate(right_words);
    const left_metadata = try left_public.metadata();
    const right_metadata = try right_public.metadata();
    try std.testing.expectEqual(@as(u32, 0), left_metadata.global_cycle_start);
    try std.testing.expectEqual(@as(u32, 3), left_metadata.global_cycle_end);
    try std.testing.expectEqual(@as(u32, 0), right_metadata.global_cycle_start);
    try std.testing.expectEqual(@as(u32, 2), right_metadata.global_cycle_end);
    try std.testing.expectEqual(@as(u32, 1), right_metadata.segment_index);
    try std.testing.expectError(
        error.JobMismatch,
        segment_v2.requireAdjacentSources(&left_source, &right_source),
    );

    left_projection.local_result.global_first_cycle = 2;
    try std.testing.expectError(
        error.LocalProjectionMismatch,
        left_projection.validateAgainst(&left_global),
    );
    left_projection.local_result.global_first_cycle = 1;
    right_projection.local_result.clock_frame = .leaf_local;
    try std.testing.expectError(
        error.LocalProjectionMismatch,
        right_projection.validateAgainst(&right_global),
    );
}

test "leaf-local V3: a globally positioned nonfinal leaf projects without a resume capability" {
    const instructions = [_]u32{
        0x0010_0137,
        0x0550_0093,
        0x0011_2023,
        0x0001_2183,
        0x0010_8193,
        0x0000_006f,
    };
    const elf = runner.trace_dump.buildTestElf(instructions.len, instructions);
    var session = try runner.BaseExecutionSession.init(std.testing.allocator, &elf, .{
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
    });
    defer session.deinit();
    var first = try session.startSegment(2);
    defer first.deinit();
    var middle = try session.resumeSegment(first.continuation.?, 2);
    defer middle.deinit();
    var final = try session.resumeSegment(middle.continuation.?, 16);
    defer final.deinit();

    const job = try span.JobContext.init(
        try span.CompleteExecution.init(
            protocol.PROTOCOL_ID_WORDS,
            digest("middle-program"),
            try machineFromCpu(first.entry_cpu, digest("middle-rw-entry")),
            try machineFromCpu(final.exit_cpu, digest("middle-rw-exit")),
            digest("middle-input"),
            digest("middle-output"),
            5,
        ),
        3,
    );
    const statement = try leafStatement(
        job,
        &middle,
        try machineFromCpu(middle.entry_cpu, digest("middle-rw-shared-entry")),
        try machineFromCpu(middle.exit_cpu, digest("middle-rw-shared-exit")),
        span.EdgeClaim.absent(),
        span.EdgeClaim.absent(),
    );
    const global = try global_v3.SourceV3.fromSegmentResult(statement, &middle);
    var projection = try projection_v3.ProjectionV3.init(&global);
    const local = try projection.sourceV2(&global, digest("middle-session"));
    try local.validate();
    try std.testing.expect(middle.global_first_cycle > 1);
    try std.testing.expect(middle.continuation != null);
    try std.testing.expect(projection.local_result.continuation != null);
    try std.testing.expectEqual(
        runner.SegmentClockFrame.global_continuous,
        projection.local_result.continuation.?.clock_frame,
    );
    try std.testing.expectEqual(@as(u64, 1), projection.local_result.global_first_cycle);
}

const States = struct {
    entry: span.MachineState,
    shared: span.MachineState,
    exit: span.MachineState,
};

fn leafStatement(
    job: span.JobContext,
    result: *const runner.SegmentResult,
    entry: span.MachineState,
    exit: span.MachineState,
    input: span.EdgeClaim,
    output: span.EdgeClaim,
) !span.SpanStatement {
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

fn machineFromCpu(cpu: runner.Cpu, rw: span.Digest) !span.MachineState {
    return span.MachineState.init(cpu.pc, cpu.regs, rw, .{0} ** 8);
}

fn encode(
    allocator: std.mem.Allocator,
    source: *const segment_v2.SourceV2,
) ![]M31 {
    const words = try allocator.alloc(M31, try source.canonicalWordCount());
    errdefer allocator.free(words);
    _ = try source.encodeCanonical(words);
    return words;
}

fn digest(label: []const u8) span.Digest {
    return channel.hashBytes(label, 0x4c50_5633); // "LPV3"
}
