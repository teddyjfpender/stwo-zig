//! Leaf-local/global-position authority and mutation fleet.

const std = @import("std");

const runner = @import("../runner/mod.zig");
const channel = @import("poseidon2_channel.zig");
const protocol = @import("protocol.zig");
const span = @import("span_statement.zig");
const segment_v2 = @import("segment_statement_v2.zig");
const authority = @import("segment_leaf_local_authority_v3.zig");

const BaseExecutionSession = runner.BaseExecutionSession;

test "leaf-local V3: adjacent native segments bind global order and exact state" {
    const instructions = [_]u32{
        0x0010_0137, // LUI  x2, 0x100: default halt-flag address.
        0x0550_0093, // ADDI x1, x0, 0x55.
        0x0011_2023, // SW   x1, 0(x2).
        0x0001_2183, // LW   x3, 0(x2), from the previous leaf.
        0x0010_8193, // ADDI x3, x1, 1.
        0x0000_006f, // JAL  x0, 0: proof-bearing completion.
    };
    const elf = runner.trace_dump.buildTestElf(instructions.len, instructions);
    var session = try BaseExecutionSession.init(std.testing.allocator, &elf, .{
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
    });
    defer session.deinit();
    var left_result = try session.startSegment(3);
    defer left_result.deinit();
    var right_result = try session.resumeSegment(left_result.continuation.?, 16);
    defer right_result.deinit();

    const states = try statesFor(&left_result, &right_result);
    const job = try jobFor(states, 5);
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
    const left = try authority.SourceV3.fromSegmentResult(
        left_statement,
        &left_result,
    );
    const right = try authority.SourceV3.fromSegmentResult(
        right_statement,
        &right_result,
    );
    try authority.requireAdjacentSources(&left, &right);

    const left_metadata = try left.metadata();
    const right_metadata = try right.metadata();
    try std.testing.expectEqual(@as(u64, 0), left_metadata.global_cycle_start);
    try std.testing.expectEqual(@as(u64, 3), left_metadata.global_cycle_end);
    try std.testing.expectEqual(@as(u64, 3), right_metadata.global_cycle_start);
    try std.testing.expectEqual(@as(u32, 2), right_metadata.local_cycle_count);
    try std.testing.expectEqual(
        left_metadata.exit.continuation_root,
        right_metadata.entry.continuation_root,
    );
    try std.testing.expect(!std.meta.eql(
        try left_metadata.identity(),
        try right_metadata.identity(),
    ));
    try std.testing.expectError(
        error.ClockFrameMismatch,
        segment_v2.SourceV2.fromSegmentResult(
            digest("v2-session"),
            left_statement,
            &left_result,
        ),
    );
}

test "leaf-local V3: source mutation fleet fails closed" {
    const instructions = [_]u32{
        0x0010_0137,
        0x0550_0093,
        0x0011_2023,
        0x0001_2183,
        0x0010_8193,
        0x0000_006f,
    };
    const elf = runner.trace_dump.buildTestElf(instructions.len, instructions);
    var session = try BaseExecutionSession.init(std.testing.allocator, &elf, .{
        .trace_retention = .segment_owned,
        .clock_frame = .leaf_local,
    });
    defer session.deinit();
    var left_result = try session.startSegment(3);
    defer left_result.deinit();
    var right_result = try session.resumeSegment(left_result.continuation.?, 16);
    defer right_result.deinit();
    const states = try statesFor(&left_result, &right_result);
    const job = try jobFor(states, 5);
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
    const left = try authority.SourceV3.fromSegmentResult(
        left_statement,
        &left_result,
    );
    const right = try authority.SourceV3.fromSegmentResult(
        right_statement,
        &right_result,
    );

    right_result.clock_frame = .global_continuous;
    try std.testing.expectError(error.ClockFrameMismatch, right.validate());
    right_result.clock_frame = .leaf_local;

    right_result.global_first_cycle += 1;
    try std.testing.expectError(error.GlobalPositionMismatch, right.validate());
    right_result.global_first_cycle -= 1;

    right_result.segment_index += 1;
    try std.testing.expectError(error.SegmentPositionMismatch, right.validate());
    right_result.segment_index -= 1;

    right_result.entry_cpu.regs[1] ^= 1;
    try std.testing.expectError(error.CpuBoundaryMismatch, right.validate());
    right_result.entry_cpu.regs[1] ^= 1;

    right_result.entry_access_clocks.register_clocks[1] = 1;
    try std.testing.expectError(error.BoundaryClockOutOfRange, right.validate());
    right_result.entry_access_clocks.register_clocks[1] = 0;

    right_result.execution_trace.rows.items[0].clk += 1;
    try std.testing.expectError(error.TraceClockMismatch, right.validate());
    right_result.execution_trace.rows.items[0].clk -= 1;

    const shared_addr = left_result.rw_memory.words[0].addr;
    const right_word = findWord(right_result.rw_memory.words, shared_addr) orelse
        return error.MissingSharedWord;
    const original = right_word.initial_word;
    right_word.initial_word ^= 1;
    try std.testing.expectError(
        error.MemorySnapshotMismatch,
        authority.requireAdjacentSources(&left, &right),
    );
    right_word.initial_word = original;
    try authority.requireAdjacentSources(&left, &right);
}

test "leaf-local V3: metadata admits global positions beyond V2 without widening a leaf" {
    const global_start = @as(u64, segment_v2.MAX_GLOBAL_CYCLES) + 17;
    const local_cycles: u32 = 3;
    const global_end = global_start + local_cycles;
    const entry = try machine(11, digest("large-entry"));
    const exit = try machine(12, digest("large-exit"));
    const complete = try span.CompleteExecution.init(
        protocol.PROTOCOL_ID_WORDS,
        digest("large-program"),
        try machine(1, digest("job-entry")),
        try machine(2, digest("job-exit")),
        digest("large-input"),
        digest("large-output"),
        global_end + 9,
    );
    const job = try span.JobContext.init(complete, 3);
    const statement = try span.SpanStatement.segmentLeaf(
        job,
        1,
        try span.ExecutedSpan.init(
            1,
            1,
            global_start,
            local_cycles,
            entry,
            exit,
            span.EdgeClaim.absent(),
            span.EdgeClaim.absent(),
        ),
    );
    const empty_clock_id = segment_v2.memoryClockIdentity(&.{});
    const metadata = authority.MetadataV3{
        .base_statement_words = try statement.canonicalWords(),
        .segment_index = 1,
        .segment_count = 3,
        .global_cycle_start = global_start,
        .global_cycle_end = global_end,
        .local_cycle_count = local_cycles,
        .entry = .{
            .snapshot_id = digest("large-snapshot"),
            .snapshot_count = 0,
            .continuation_root = 0,
            .register_clocks = .{0} ** 32,
            .memory_clock_id = empty_clock_id,
            .memory_clock_count = 0,
        },
        .exit = .{
            .snapshot_id = digest("large-snapshot-exit"),
            .snapshot_count = 0,
            .continuation_root = 0,
            .register_clocks = .{0} ** 32,
            .memory_clock_id = empty_clock_id,
            .memory_clock_count = 0,
        },
        .completion = null,
    };
    try metadata.validate();
    try std.testing.expect(metadata.global_cycle_start > segment_v2.MAX_GLOBAL_CYCLES);

    const metadata_id = try metadata.identity();
    var changed_boundary = metadata;
    changed_boundary.exit.continuation_root = 1;
    try changed_boundary.validate();
    try std.testing.expect(!std.meta.eql(
        metadata_id,
        try changed_boundary.identity(),
    ));

    var forged = metadata;
    forged.local_cycle_count = segment_v2.MAX_GLOBAL_CYCLES + 1;
    forged.global_cycle_end = forged.global_cycle_start + forged.local_cycle_count;
    try std.testing.expectError(
        error.LocalCycleRangeOutOfBounds,
        forged.validate(),
    );
}

const States = struct {
    entry: span.MachineState,
    shared: span.MachineState,
    exit: span.MachineState,
};

fn statesFor(
    left: *const runner.SegmentResult,
    right: *const runner.SegmentResult,
) !States {
    return .{
        .entry = try machineFromCpu(left.entry_cpu, digest("rw-entry")),
        .shared = try machineFromCpu(left.exit_cpu, digest("rw-shared")),
        .exit = try machineFromCpu(right.exit_cpu, digest("rw-exit")),
    };
}

fn jobFor(states: States, total_cycles: u64) !span.JobContext {
    return span.JobContext.init(
        try span.CompleteExecution.init(
            protocol.PROTOCOL_ID_WORDS,
            digest("program"),
            states.entry,
            states.exit,
            digest("input"),
            digest("output"),
            total_cycles,
        ),
        2,
    );
}

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

fn machine(seed: u32, rw: span.Digest) !span.MachineState {
    var registers = [_]u32{0} ** 32;
    registers[1] = seed;
    return span.MachineState.init(seed * 4, registers, rw, .{0} ** 8);
}

fn digest(label: []const u8) span.Digest {
    return channel.hashBytes(label, 0x4c33_5633); // "L3V3"
}

fn findWord(
    words: []memory_state.WordState,
    address: u32,
) ?*memory_state.WordState {
    for (words) |*word| if (word.addr == address) return word;
    return null;
}

const memory_state = @import("../runner/memory_state.zig");
