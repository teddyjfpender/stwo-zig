//! V2 resumed-segment public-boundary, canonical-wire, and continuity gates.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const memory_state = @import("../runner/memory_state.zig");
const runner_result = @import("../runner/result.zig");
const sparse_merkle = @import("../air/memory_commitment/sparse_merkle.zig");
const Cpu = @import("../runner/cpu.zig").Cpu;
const channel = @import("poseidon2_channel.zig");
const protocol = @import("protocol.zig");
const span = @import("span_statement.zig");
const temporal = @import("temporal_pair_node.zig");
const v2 = @import("segment_statement_v2.zig");

test "segment statement V2 retains an exact proof-consumable adjacent boundary" {
    var fixture = try Fixture.init();
    const left = fixture.leftSource();
    const right = fixture.rightSource();
    try left.validate();
    try right.validate();
    try v2.requireAdjacentSources(&left, &right);

    const left_words = try encode(std.testing.allocator, &left);
    defer std.testing.allocator.free(left_words);
    const right_words = try encode(std.testing.allocator, &right);
    defer std.testing.allocator.free(right_words);
    const left_view = try v2.authenticateCanonicalWire(left_words);
    const right_view = try v2.authenticateCanonicalWire(right_words);
    const receipt = try v2.authenticateAdjacentCanonicalWires(
        left_words,
        right_words,
    );

    try std.testing.expectEqual(@as(u32, 1), left_view.entry_snapshot.count);
    try std.testing.expectEqual(@as(u32, 1), left_view.exit_snapshot.count);
    try std.testing.expectEqual(@as(u32, 1), right_view.entry_snapshot.count);
    try std.testing.expectEqual(@as(u32, 2), right_view.exit_snapshot.count);
    try std.testing.expectEqual(
        v2.SparseEntryV2{ .address = 0x2000, .value = 12 },
        left_view.sparseEntry(left_view.exit_snapshot, 0),
    );
    try std.testing.expectEqual(
        v2.ClockEntryV2{ .address = 0x2000, .clock = 3 },
        right_view.clockEntry(right_view.entry_memory_clocks, 0),
    );
    try std.testing.expectEqual(
        left_view.statement.exit_lineage_id,
        right_view.statement.entry_lineage_id,
    );
    try std.testing.expectEqual(
        left_view.statement.exit_lineage_id,
        receipt.shared_boundary_lineage_id,
    );
    try std.testing.expectEqual(left_view.wire_id, receipt.left_wire_id);
    try std.testing.expectEqual(right_view.wire_id, receipt.right_wire_id);
    try std.testing.expect(v2.HOT_VALIDATION_HEAP_ALLOCATIONS == 0);
    try std.testing.expect(v2.ENCODING_FAILS_BEFORE_FIRST_WRITE);
}

test "segment statement V2 preserves the exact V1 projection and transcript identity" {
    var fixture = try Fixture.init();
    const source = fixture.leftSource();
    const expected_words = try fixture.statements[0].canonicalWords();
    const expected_id = baseStatementId(&expected_words);
    const words = try encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(words);
    const view = try v2.authenticateCanonicalWire(words);

    try std.testing.expectEqual(expected_words, view.statement.base_statement_words);
    try std.testing.expectEqual(expected_id, view.statement.base_statement_id);
    try std.testing.expectEqual(
        try temporal.jobId(&expected_words),
        view.statement.job_id,
    );
    try std.testing.expectEqual(@as(usize, 412), v2.V1_PROJECTION_WORD_COUNT);
    try std.testing.expectEqual(@as(u32, 1), protocol.LEAF_STATEMENT_VERSION);
    try std.testing.expectEqual(
        expected_words[0],
        words[v2.fixed_layout.base_statement],
    );

    var recording = RecordingChannel{};
    view.mixInto(&recording);
    try std.testing.expectEqual(@as(usize, 1), recording.calls);
    try std.testing.expectEqual(words.len, recording.word_count);
    try std.testing.expectEqual(view.wire_id, recording.identity);
}

test "segment statement V2 all-RW continuation roots match the pinned sparse Merkle tree" {
    var fixture = try Fixture.init();
    const left_statement = try fixture.leftSource().statement();
    const right_statement = try fixture.rightSource().statement();

    var left_entry_tree = try sparse_merkle.build(std.testing.allocator, &.{
        .{ .index = 0x2000, .value = 11 },
        .{ .index = 0x2001, .value = 0 },
        .{ .index = 0x2002, .value = 0 },
        .{ .index = 0x2003, .value = 0 },
    });
    defer left_entry_tree.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        left_entry_tree.root,
        left_statement.entry_continuation_root,
    );

    var right_exit_tree = try sparse_merkle.build(std.testing.allocator, &.{
        .{ .index = 0x2000, .value = 13 },
        .{ .index = 0x2001, .value = 0 },
        .{ .index = 0x2002, .value = 0 },
        .{ .index = 0x2003, .value = 0 },
        .{ .index = 0x2004, .value = 9 },
        .{ .index = 0x2005, .value = 0 },
        .{ .index = 0x2006, .value = 0 },
        .{ .index = 0x2007, .value = 0 },
    });
    defer right_exit_tree.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        right_exit_tree.root,
        right_statement.exit_continuation_root,
    );
}

test "segment statement V2 rejects swapped omitted duplicate and mutated retained sections" {
    var fixture = try Fixture.init();
    const right = fixture.rightSource();
    const canonical = try encode(std.testing.allocator, &right);
    defer std.testing.allocator.free(canonical);
    const view = try v2.authenticateCanonicalWire(canonical);

    var swapped = try std.testing.allocator.dupe(M31, canonical);
    defer std.testing.allocator.free(swapped);
    swapped[v2.FIXED_CANONICAL_WORDS] = M31.fromCanonical(
        @intFromEnum(v2.Tag.exit_memory_state),
    );
    try std.testing.expectError(
        error.CanonicalTagMismatch,
        v2.authenticateCanonicalWire(swapped),
    );

    try std.testing.expectError(
        error.CanonicalLengthMismatch,
        v2.authenticateCanonicalWire(canonical[0 .. canonical.len - 1]),
    );

    var duplicate = try std.testing.allocator.dupe(M31, canonical);
    defer std.testing.allocator.free(duplicate);
    const exit_start = view.exit_snapshot.payload_start;
    const first_addr = readU32(duplicate[exit_start..][0..2]);
    writeU32(duplicate[exit_start + v2.RETAINED_ENTRY_WORDS ..][0..2], first_addr);
    try std.testing.expectError(
        error.DuplicateBoundaryAddress,
        v2.authenticateCanonicalWire(duplicate),
    );

    var mutated = try std.testing.allocator.dupe(M31, canonical);
    defer std.testing.allocator.free(mutated);
    const value_start = view.entry_snapshot.payload_start + 2;
    writeU32(mutated[value_start..][0..2], 13);
    try std.testing.expectError(
        error.BoundaryIdentityMismatch,
        v2.authenticateCanonicalWire(mutated),
    );

    var sparse_zero = try std.testing.allocator.dupe(M31, canonical);
    defer std.testing.allocator.free(sparse_zero);
    writeU32(sparse_zero[value_start..][0..2], 0);
    try std.testing.expectError(
        error.NonCanonicalSparseZero,
        v2.authenticateCanonicalWire(sparse_zero),
    );
}

test "segment statement V2 rejects cross-session non-adjacent and mutated boundaries" {
    var fixture = try Fixture.init();
    const left = fixture.leftSource();
    var right = fixture.rightSource();

    var cross_session = right;
    cross_session.session_id = id("different-session");
    const left_words = try encode(std.testing.allocator, &left);
    defer std.testing.allocator.free(left_words);
    const cross_words = try encode(std.testing.allocator, &cross_session);
    defer std.testing.allocator.free(cross_words);
    try std.testing.expectError(
        error.CrossSession,
        v2.authenticateAdjacentCanonicalWires(left_words, cross_words),
    );

    const nonadjacent = try fixture.nonAdjacentRightSource();
    const nonadjacent_words = try encode(std.testing.allocator, &nonadjacent);
    defer std.testing.allocator.free(nonadjacent_words);
    try std.testing.expectError(
        error.CycleDiscontinuity,
        v2.authenticateAdjacentCanonicalWires(left_words, nonadjacent_words),
    );

    var changed_words = fixture.right_words;
    changed_words[0].initial_word ^= 1;
    right.memory_words = &changed_words;
    try std.testing.expectError(
        error.MemorySnapshotMismatch,
        v2.requireAdjacentSources(&left, &right),
    );

    right = fixture.rightSource();
    right.entry_register_clocks[1] = 1;
    try std.testing.expectError(
        error.BoundaryClockMismatch,
        v2.requireAdjacentSources(&left, &right),
    );
}

test "segment statement V2 makes completion a real final-only authority" {
    var fixture = try Fixture.init();
    var left = fixture.leftSource();
    var right = fixture.rightSource();

    left.completion = .{
        .kind = .unretired_self_loop,
        .address = left.exit_cpu.pc,
        .value = @import("../air/public_data.zig").CANONICAL_SELF_LOOP_WORD,
        .clock = 0,
    };
    try std.testing.expectError(error.CompletionForbidden, left.validate());

    right.completion = null;
    try std.testing.expectError(error.CompletionMissing, right.validate());

    right = fixture.rightSource();
    right.completion.?.value ^= 1;
    try std.testing.expectError(error.InvalidCompletionValue, right.validate());

    right = fixture.rightSource();
    right.public_output_custody = false;
    try std.testing.expectError(error.OutputCustodyMismatch, right.validate());

    left = fixture.leftSource();
    left.continuation_present = false;
    try std.testing.expectError(error.InvalidSegmentRole, left.validate());
}

test "segment statement V2 halt completion is linked to retained value and clock" {
    var fixture = try Fixture.init();
    var words = fixture.right_words;
    words[0].role.is_public_completion = true;
    var source = fixture.rightSource();
    source.memory_words = &words;
    source.completion = .{
        .kind = .halt_flag,
        .address = words[0].addr,
        .value = words[0].final_word,
        .clock = words[0].final_clock,
    };
    try source.validate();
    const canonical = try encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(canonical);
    _ = try v2.authenticateCanonicalWire(canonical);

    source.completion.?.value +%= 1;
    try std.testing.expectError(error.CompletionMismatch, source.validate());
    source.completion.?.value -%= 1;
    source.completion.?.clock = 5;
    try std.testing.expectError(error.CompletionMismatch, source.validate());
}

test "segment statement V2 encoding is bounded and failure atomic" {
    var fixture = try Fixture.init();
    var source = fixture.leftSource();
    const needed = try source.canonicalWordCount();
    const sentinel = M31.fromCanonical(0x1234);
    const too_short = try std.testing.allocator.alloc(M31, needed - 1);
    defer std.testing.allocator.free(too_short);
    @memset(too_short, sentinel);
    try std.testing.expectError(
        error.CanonicalLengthMismatch,
        source.encodeCanonical(too_short),
    );
    for (too_short) |word| try std.testing.expect(word.eql(sentinel));

    var duplicate_words = fixture.left_words;
    duplicate_words[1].addr = duplicate_words[0].addr;
    source.memory_words = &duplicate_words;
    const exact = try std.testing.allocator.alloc(M31, needed);
    defer std.testing.allocator.free(exact);
    @memset(exact, sentinel);
    try std.testing.expectError(
        error.DuplicateBoundaryAddress,
        source.encodeCanonical(exact),
    );
    for (exact) |word| try std.testing.expect(word.eql(sentinel));

    source = fixture.leftSource();
    const canonical = try encode(std.testing.allocator, &source);
    defer std.testing.allocator.free(canonical);
    var oversized = try std.testing.allocator.dupe(M31, canonical);
    defer std.testing.allocator.free(oversized);
    writeU32(
        oversized[v2.fixed_layout.entry_snapshot_count..][0..2],
        v2.MAX_SPARSE_BOUNDARY_ENTRIES + 1,
    );
    try std.testing.expectError(
        error.ExecutionRangeOutOfBounds,
        v2.authenticateCanonicalWire(oversized),
    );
}

test "segment statement V2 source rejects duplicate clocks and missing snapshot custody" {
    var fixture = try Fixture.init();
    var source = fixture.rightSource();
    const duplicate_clocks = [_]runner_result.MemoryAccessClock{
        .{ .addr = 0x2000, .clock = 3 },
        .{ .addr = 0x2000, .clock = 5 },
    };
    source.entry_memory_clocks = &duplicate_clocks;
    try std.testing.expectError(error.DuplicateBoundaryAddress, source.validate());

    source = fixture.rightSource();
    const missing_word_clock = [_]runner_result.MemoryAccessClock{
        .{ .addr = 0x2000, .clock = 7 },
        .{ .addr = 0x2004, .clock = 6 },
        .{ .addr = 0x2008, .clock = 5 },
    };
    source.exit_memory_clocks = &missing_word_clock;
    try std.testing.expectError(error.MemoryClockMissing, source.validate());
}

test "segment statement V2 runner adapter validates the captured boundary" {
    var fixture = try Fixture.init();
    var result: runner_result.SegmentResult = undefined;
    result.segment_index = 1;
    result.segment_role = .{ .is_first = false, .is_last = true };
    result.global_first_cycle = 3;
    result.cycle_count = 2;
    result.entry_cpu = cpuFromMachine(fixture.statements[1].body.executed.entry);
    result.exit_cpu = cpuFromMachine(fixture.job.complete.final_state);
    result.completion_reason = .self_loop;
    result.completion_address = fixture.job.complete.final_state.pc;
    result.completion_value = @import("../air/public_data.zig").CANONICAL_SELF_LOOP_WORD;
    result.completion_clock = 0;
    result.continuation = null;
    result.input = null;
    result.entry_access_clocks = .{
        .register_clocks = fixture.left_exit_register_clocks,
        .memory_clocks = &fixture.right_entry_memory_clocks,
    };
    result.exit_access_clocks = .{
        .register_clocks = fixture.right_exit_register_clocks,
        .memory_clocks = &fixture.right_exit_memory_clocks,
    };
    result.rw_memory.segment_role = result.segment_role;
    result.rw_memory.words = &fixture.right_words;

    const source = try v2.SourceV2.fromSegmentResult(
        id("session"),
        fixture.statements[1],
        &result,
    );
    try source.validate();
    try std.testing.expectEqual(result.segment_index, source.segment_index);
    try std.testing.expectEqual(
        result.exit_access_clocks.register_clocks,
        source.exit_register_clocks,
    );

    result.rw_memory.segment_role.is_last = false;
    try std.testing.expectError(
        error.InvalidSegmentRole,
        v2.SourceV2.fromSegmentResult(
            id("session"),
            fixture.statements[1],
            &result,
        ),
    );
}

const Fixture = struct {
    job: span.JobContext,
    statements: [2]span.SpanStatement,
    left_words: [2]memory_state.WordState,
    right_words: [2]memory_state.WordState,
    left_exit_memory_clocks: [1]runner_result.MemoryAccessClock,
    right_entry_memory_clocks: [1]runner_result.MemoryAccessClock,
    right_exit_memory_clocks: [2]runner_result.MemoryAccessClock,
    left_entry_register_clocks: [32]u32,
    left_exit_register_clocks: [32]u32,
    right_exit_register_clocks: [32]u32,

    fn init() !Fixture {
        const s0 = try machineState(0x1000, 0, "rw-0");
        const s1 = try machineState(0x1008, 1, "rw-1");
        const s2 = try machineState(0x1010, 2, "rw-2");
        const job = try span.JobContext.init(
            try span.CompleteExecution.init(
                protocol.PROTOCOL_ID_WORDS,
                id("program"),
                s0,
                s2,
                id("input"),
                id("output"),
                4,
            ),
            2,
        );
        const left_entry_register_clocks = [_]u32{0} ** 32;
        var left_exit_register_clocks = left_entry_register_clocks;
        left_exit_register_clocks[1] = 2;
        var right_exit_register_clocks = left_exit_register_clocks;
        right_exit_register_clocks[1] = 5;
        return .{
            .job = job,
            .statements = .{
                try span.SpanStatement.segmentLeaf(
                    job,
                    0,
                    try span.ExecutedSpan.init(
                        0,
                        1,
                        0,
                        2,
                        s0,
                        s1,
                        try span.EdgeClaim.present(id("input")),
                        span.EdgeClaim.absent(),
                    ),
                ),
                try span.SpanStatement.segmentLeaf(
                    job,
                    1,
                    try span.ExecutedSpan.init(
                        1,
                        1,
                        2,
                        2,
                        s1,
                        s2,
                        span.EdgeClaim.absent(),
                        try span.EdgeClaim.present(id("output")),
                    ),
                ),
            },
            .left_words = .{
                .{
                    .addr = 0x2000,
                    .initial_word = 11,
                    .final_word = 12,
                    .final_clock = 3,
                },
                .{
                    .addr = 0x2004,
                    .initial_word = 0,
                    .final_word = 0,
                    .final_clock = 0,
                },
            },
            .right_words = .{
                .{
                    .addr = 0x2000,
                    .initial_word = 12,
                    .final_word = 13,
                    .final_clock = 7,
                },
                .{
                    .addr = 0x2004,
                    .initial_word = 0,
                    .final_word = 9,
                    .final_clock = 6,
                },
            },
            .left_exit_memory_clocks = .{.{ .addr = 0x2000, .clock = 3 }},
            .right_entry_memory_clocks = .{.{ .addr = 0x2000, .clock = 3 }},
            .right_exit_memory_clocks = .{
                .{ .addr = 0x2000, .clock = 7 },
                .{ .addr = 0x2004, .clock = 6 },
            },
            .left_entry_register_clocks = left_entry_register_clocks,
            .left_exit_register_clocks = left_exit_register_clocks,
            .right_exit_register_clocks = right_exit_register_clocks,
        };
    }

    fn leftSource(self: *const Fixture) v2.SourceV2 {
        return .{
            .session_id = id("session"),
            .base_statement = self.statements[0],
            .segment_index = 0,
            .segment_role = .{ .is_first = true, .is_last = false },
            .global_first_cycle = 1,
            .cycle_count = 2,
            .entry_cpu = cpuFromMachine(self.job.complete.initial_state),
            .exit_cpu = cpuFromMachine(self.statements[0].body.executed.exit),
            .completion = null,
            .continuation_present = true,
            .public_input_custody = true,
            .public_output_custody = false,
            .memory_words = &self.left_words,
            .entry_register_clocks = self.left_entry_register_clocks,
            .exit_register_clocks = self.left_exit_register_clocks,
            .entry_memory_clocks = &.{},
            .exit_memory_clocks = &self.left_exit_memory_clocks,
        };
    }

    fn rightSource(self: *const Fixture) v2.SourceV2 {
        return .{
            .session_id = id("session"),
            .base_statement = self.statements[1],
            .segment_index = 1,
            .segment_role = .{ .is_first = false, .is_last = true },
            .global_first_cycle = 3,
            .cycle_count = 2,
            .entry_cpu = cpuFromMachine(self.statements[1].body.executed.entry),
            .exit_cpu = cpuFromMachine(self.job.complete.final_state),
            .completion = .{
                .kind = .unretired_self_loop,
                .address = self.job.complete.final_state.pc,
                .value = @import("../air/public_data.zig").CANONICAL_SELF_LOOP_WORD,
                .clock = 0,
            },
            .continuation_present = false,
            .public_input_custody = false,
            .public_output_custody = true,
            .memory_words = &self.right_words,
            .entry_register_clocks = self.left_exit_register_clocks,
            .exit_register_clocks = self.right_exit_register_clocks,
            .entry_memory_clocks = &self.right_entry_memory_clocks,
            .exit_memory_clocks = &self.right_exit_memory_clocks,
        };
    }

    fn nonAdjacentRightSource(self: *const Fixture) !v2.SourceV2 {
        var source = self.rightSource();
        source.base_statement = try span.SpanStatement.segmentLeaf(
            self.job,
            1,
            try span.ExecutedSpan.init(
                1,
                1,
                3,
                1,
                self.statements[1].body.executed.entry,
                self.statements[1].body.executed.exit,
                span.EdgeClaim.absent(),
                try span.EdgeClaim.present(id("output")),
            ),
        );
        source.global_first_cycle = 4;
        source.cycle_count = 1;
        return source;
    }
};

fn encode(allocator: std.mem.Allocator, source: *const v2.SourceV2) ![]M31 {
    const words = try allocator.alloc(M31, try source.canonicalWordCount());
    errdefer allocator.free(words);
    _ = try source.encodeCanonical(words);
    return words;
}

fn machineState(pc: u32, value: u32, rw_label: []const u8) !span.MachineState {
    var registers = [_]u32{0} ** 32;
    registers[1] = value;
    return span.MachineState.init(pc, registers, id(rw_label), .{0} ** 8);
}

fn cpuFromMachine(machine: span.MachineState) Cpu {
    return .{ .pc = machine.pc, .regs = machine.registers };
}

fn id(label: []const u8) v2.Digest {
    return channel.hashBytes(label, 0x5332_5453); // "S2TS"
}

fn baseStatementId(words: *const span.StatementWords) v2.Digest {
    var canonical: [span.SPAN_STATEMENT_CANONICAL_WORDS]u32 = undefined;
    for (&canonical, words) |*destination, word|
        destination.* = word.toU32();
    return protocol.statementId(&canonical);
}

fn readU32(words: *const [2]M31) u32 {
    return words[0].toU32() | (words[1].toU32() << 16);
}

fn writeU32(words: *[2]M31, value: u32) void {
    words[0] = M31.fromCanonical(value & 0xffff);
    words[1] = M31.fromCanonical(value >> 16);
}

const RecordingChannel = struct {
    calls: usize = 0,
    word_count: usize = 0,
    identity: v2.Digest = .{0} ** channel.RATE,

    pub fn mixCanonicalM31Words(self: *RecordingChannel, words: []const M31) void {
        self.calls += 1;
        self.word_count += words.len;
        self.identity = channel.hashCanonicalWords(words, v2.WIRE_ID_DOMAIN);
    }
};
