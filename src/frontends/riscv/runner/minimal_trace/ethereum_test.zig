const std = @import("std");
const execution_profile = @import("../../isa/execution_profile.zig");
const Cpu = @import("../cpu.zig").Cpu;
const result_mod = @import("../result.zig");
const segment_session = @import("../segment_session.zig");
const StateChainTracker = @import("../state_chain.zig").StateChainTracker;
const test_elf = @import("../guest_precompile/test_elf.zig");
const capture = @import("ethereum_capture.zig");
const ethereum_parallel = @import("ethereum_parallel_replay.zig");
const ethereum_replay = @import("ethereum_replay.zig");
const ethereum_semantic_capture = @import("ethereum_semantic_capture.zig");
const ethereum_types = @import("ethereum_types.zig");
const ethereum_wire = @import("ethereum_wire.zig");
const base_replay = @import("replay.zig");
const base_types = @import("types.zig");

const EthereumExecutionSession = segment_session.ExecutionSession(
    execution_profile.ExecutionProfile.rv32im_zkvm_ethereum_v1,
);

test "Ethereum minimal trace compacts and independently replays both native calls" {
    var elf = test_elf.buildEthereum();
    replaceTerminalEcallWithSelfLoop(&elf);
    var semantic_observation = ethereum_semantic_capture.SegmentObservationV1
        .init(std.testing.allocator);
    defer semantic_observation.deinit();
    var semantic_observer = CaptureObserver{ .capture = &semantic_observation };
    var session = try EthereumExecutionSession.init(
        std.testing.allocator,
        &elf,
        .{
            .trace_retention = .segment_owned,
            .clock_frame = .leaf_local,
            .retirement_observer = semantic_observer.interface(),
        },
    );
    defer session.deinit();
    var segment = try session.startSegment(16);
    defer segment.deinit();
    try std.testing.expectEqual(result_mod.CompletionReason.self_loop, segment.base.completion_reason.?);
    try std.testing.expectEqual(@as(usize, 1), segment.keccakf_calls.len());
    try std.testing.expectEqual(@as(usize, 1), segment.signer_recovery_calls.len());

    const program_words = try std.testing.allocator.alloc(
        base_replay.ProgramWord,
        segment.base.rw_memory.program_words.len,
    );
    defer std.testing.allocator.free(program_words);
    for (program_words, segment.base.rw_memory.program_words) |*destination, source| {
        destination.* = .{ .address = source.addr, .word = source.initial_word };
    }
    const program = try base_replay.SliceProgram.init(program_words);
    var captured = try capture.captureFromSegment(
        std.testing.allocator,
        .{
            .segment = &segment,
            .program = program.source(),
            .input_identity = base_types.digestBytes("ethereum-minimal-input"),
            .session_identity = base_types.digestBytes("ethereum-minimal-session"),
        },
    );
    defer captured.deinit();
    var semantic_captured = try semantic_observation.capture(
        std.testing.allocator,
        .{
            .segment = &segment,
            .program = program.source(),
            .input_identity = base_types.digestBytes("ethereum-minimal-input"),
            .session_identity = base_types.digestBytes("ethereum-minimal-session"),
        },
    );
    defer semantic_captured.deinit();
    const compatibility_bytes = try ethereum_wire.encodeAlloc(
        std.testing.allocator,
        &.{
            .leaf = captured.leaf,
            .boundary_words = captured.boundary_words,
            .allocator = std.testing.allocator,
        },
    );
    defer std.testing.allocator.free(compatibility_bytes);
    const semantic_bytes = try ethereum_wire.encodeAlloc(
        std.testing.allocator,
        &.{
            .leaf = semantic_captured.leaf,
            .boundary_words = semantic_captured.boundary_words,
            .allocator = std.testing.allocator,
        },
    );
    defer std.testing.allocator.free(semantic_bytes);
    try std.testing.expectEqualSlices(u8, compatibility_bytes, semantic_bytes);
    const expected_source = captured.leaf.source;
    const expected_entry_cpu_sha256 = ethereum_types.cpuIdentity(
        captured.leaf.entry_cpu,
    );
    const expected_exit_cpu_sha256 = ethereum_types.cpuIdentity(
        captured.leaf.exit_cpu,
    );
    const expected_completion = captured.leaf.completion;
    const entry_snapshot_identity = capture.snapshotIdentity(
        segment.base.rw_memory,
        .entry,
    );
    const exit_snapshot_identity = capture.snapshotIdentity(
        segment.base.rw_memory,
        .exit,
    );
    try std.testing.expectEqualSlices(
        u8,
        &entry_snapshot_identity,
        &captured.leaf.source.entry_memory,
    );
    try std.testing.expectEqualSlices(
        u8,
        &exit_snapshot_identity,
        &captured.leaf.source.exit_memory,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &captured.leaf.source.entry_memory,
        &captured.leaf.entry_boundary,
    ));
    const boundary = try captured.boundary();
    const encoded = try ethereum_wire.encodeAlloc(
        std.testing.allocator,
        &.{
            .leaf = captured.leaf,
            .boundary_words = captured.boundary_words,
            .allocator = std.testing.allocator,
        },
    );
    defer std.testing.allocator.free(encoded);
    var decoded = try ethereum_wire.decodeAlloc(std.testing.allocator, encoded);
    defer decoded.deinit();
    try std.testing.expectEqualSlices(u8, &captured.leaf.seal, &decoded.leaf.seal);
    try std.testing.expectEqualDeep(captured.boundary_words, decoded.boundary_words);
    const mutable_encoded = @constCast(encoded);
    mutable_encoded[ethereum_wire.MAGIC.len + 1] ^= 1;
    try std.testing.expectError(
        error.ArtifactChecksumMismatch,
        ethereum_wire.decodeAlloc(std.testing.allocator, encoded),
    );
    mutable_encoded[ethereum_wire.MAGIC.len + 1] ^= 1;
    var replayed = try ethereum_replay.replay(
        std.testing.allocator,
        .{
            .leaf = &captured.leaf,
            .program = program.source(),
            .boundary = boundary.source(),
            .expected_memory_layout = segment.base.rw_memory.layout,
            .expected_source = expected_source,
            .expected_entry_cpu_sha256 = expected_entry_cpu_sha256,
            .expected_exit_cpu_sha256 = expected_exit_cpu_sha256,
            .expected_completion = expected_completion,
        },
    );
    defer replayed.deinit();

    try expectCpuEqual(segment.base.exit_cpu, replayed.cpu);
    try std.testing.expectEqualDeep(
        segment.base.execution_trace.rows.items,
        replayed.execution_trace.rows.items,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        segment.base.state_chain_tracker.mem_initial.count(),
    );
    try expectTrackerEqual(
        &segment.base.state_chain_tracker,
        &replayed.state_chain_tracker,
    );
    try expectBoundaryReconstructed(
        captured.boundary_words,
        &replayed.state_chain_tracker,
        &replayed.touched_memory,
    );
    try std.testing.expectEqualDeep(
        segment.keccakf_calls.records(),
        replayed.keccakf_calls.records(),
    );
    try std.testing.expectEqualDeep(
        segment.keccakf_execution_rows.rows(),
        replayed.keccakf_execution_rows.rows(),
    );
    try std.testing.expectEqualDeep(
        segment.signer_recovery_calls.records(),
        replayed.signer_recovery_calls.records(),
    );
    try std.testing.expectEqualDeep(
        segment.signer_recovery_execution_rows.rows(),
        replayed.signer_recovery_execution_rows.rows(),
    );

    var sink = CountingSink{};
    const parallel_receipt = try ethereum_parallel.replayLeaves(
        std.testing.allocator,
        &.{.{
            .leaf = &captured.leaf,
            .program = program.source(),
            .boundary_words = captured.boundary_words,
            .expected_memory_layout = segment.base.rw_memory.layout,
            .expected_source = expected_source,
            .expected_entry_cpu_sha256 = expected_entry_cpu_sha256,
            .expected_exit_cpu_sha256 = expected_exit_cpu_sha256,
            .expected_completion = expected_completion,
        }},
        .{
            .worker_count = 4,
            .max_total_cycles = captured.leaf.cycle_count,
        },
        sink.interface(),
    );
    try std.testing.expectEqual(@as(u32, 1), parallel_receipt.leaf_count);
    try std.testing.expectEqual(
        @as(u64, captured.leaf.cycle_count),
        parallel_receipt.total_cycles,
    );
    try std.testing.expectEqual(
        @as(u64, captured.leaf.core_cycle_count),
        parallel_receipt.core_cycles,
    );
    try std.testing.expectEqual(@as(u64, 1), parallel_receipt.keccak_calls);
    try std.testing.expectEqual(@as(u64, 1), parallel_receipt.recovery_calls);
    try std.testing.expectEqual(@as(u16, 1), parallel_receipt.admitted_workers);
    try std.testing.expectEqual(@as(usize, 1), sink.consumed.load(.acquire));

    var first = captured.leaf;
    first.completion = null;
    first.reseal();
    var second = captured.leaf;
    second.segment_index += 1;
    second.global_first_cycle += first.cycle_count;
    second.entry_cpu = first.exit_cpu;
    second.source.entry_memory = first.source.exit_memory;
    second.reseal();
    var collection = [_]ethereum_parallel.RequestV1{
        .{
            .leaf = &first,
            .program = program.source(),
            .boundary_words = captured.boundary_words,
            .expected_memory_layout = segment.base.rw_memory.layout,
            .expected_source = first.source,
            .expected_entry_cpu_sha256 = ethereum_types.cpuIdentity(
                first.entry_cpu,
            ),
            .expected_exit_cpu_sha256 = ethereum_types.cpuIdentity(
                first.exit_cpu,
            ),
            .expected_completion = null,
        },
        .{
            .leaf = &second,
            .program = program.source(),
            .boundary_words = captured.boundary_words,
            .expected_memory_layout = segment.base.rw_memory.layout,
            .expected_source = second.source,
            .expected_entry_cpu_sha256 = ethereum_types.cpuIdentity(
                second.entry_cpu,
            ),
            .expected_exit_cpu_sha256 = ethereum_types.cpuIdentity(
                second.exit_cpu,
            ),
            .expected_completion = second.completion,
        },
    };
    const collection_receipt = try ethereum_parallel.validateCollection(
        &collection,
        @as(u64, first.cycle_count) + second.cycle_count,
    );
    try std.testing.expectEqual(@as(u32, 2), collection_receipt.leaf_count);
    second.source.entry_memory[0] ^= 1;
    second.reseal();
    try std.testing.expectError(
        error.SourceAuthorityMismatch,
        ethereum_parallel.validateCollection(
            &collection,
            @as(u64, first.cycle_count) + second.cycle_count,
        ),
    );
    collection[1].expected_source = second.source;
    try std.testing.expectError(
        error.MemoryContinuationMismatch,
        ethereum_parallel.validateCollection(
            &collection,
            @as(u64, first.cycle_count) + second.cycle_count,
        ),
    );
    second.source.entry_memory = first.source.exit_memory;
    second.reseal();
    collection[1].expected_source = second.source;

    first.exit_cpu.regs[14] ^= 1;
    second.entry_cpu = first.exit_cpu;
    first.reseal();
    second.reseal();
    try std.testing.expectError(
        error.ExitCpuAuthorityMismatch,
        ethereum_parallel.validateCollection(
            &collection,
            @as(u64, first.cycle_count) + second.cycle_count,
        ),
    );

    captured.leaf.completion.?.value ^= 1;
    captured.leaf.reseal();
    try std.testing.expectError(
        error.CompletionAuthorityMismatch,
        ethereum_replay.replay(
            std.testing.allocator,
            .{
                .leaf = &captured.leaf,
                .program = program.source(),
                .boundary = boundary.source(),
                .expected_memory_layout = segment.base.rw_memory.layout,
                .expected_source = expected_source,
                .expected_entry_cpu_sha256 = expected_entry_cpu_sha256,
                .expected_exit_cpu_sha256 = expected_exit_cpu_sha256,
                .expected_completion = expected_completion,
            },
        ),
    );
    captured.leaf.completion = expected_completion;
    captured.leaf.reseal();

    captured.leaf.source.input[0] ^= 1;
    captured.leaf.reseal();
    try std.testing.expectError(
        error.SourceAuthorityMismatch,
        ethereum_replay.replay(
            std.testing.allocator,
            .{
                .leaf = &captured.leaf,
                .program = program.source(),
                .boundary = boundary.source(),
                .expected_memory_layout = segment.base.rw_memory.layout,
                .expected_source = expected_source,
                .expected_entry_cpu_sha256 = expected_entry_cpu_sha256,
                .expected_exit_cpu_sha256 = expected_exit_cpu_sha256,
                .expected_completion = expected_completion,
            },
        ),
    );
    captured.leaf.source = expected_source;
    captured.leaf.reseal();

    captured.leaf.entry_cpu.pc +%= 4;
    captured.leaf.reseal();
    try std.testing.expectError(
        error.EntryCpuAuthorityMismatch,
        ethereum_replay.replay(
            std.testing.allocator,
            .{
                .leaf = &captured.leaf,
                .program = program.source(),
                .boundary = boundary.source(),
                .expected_memory_layout = segment.base.rw_memory.layout,
                .expected_source = expected_source,
                .expected_entry_cpu_sha256 = expected_entry_cpu_sha256,
                .expected_exit_cpu_sha256 = expected_exit_cpu_sha256,
                .expected_completion = expected_completion,
            },
        ),
    );
    captured.leaf.entry_cpu.pc -%= 4;
    captured.leaf.reseal();

    captured.leaf.keccak_records[0].output[0] ^= 1;
    captured.leaf.reseal();
    try std.testing.expectError(
        error.ExternalTapeMismatch,
        ethereum_replay.replay(
            std.testing.allocator,
            .{
                .leaf = &captured.leaf,
                .program = program.source(),
                .boundary = boundary.source(),
                .expected_memory_layout = segment.base.rw_memory.layout,
                .expected_source = expected_source,
                .expected_entry_cpu_sha256 = expected_entry_cpu_sha256,
                .expected_exit_cpu_sha256 = expected_exit_cpu_sha256,
                .expected_completion = expected_completion,
            },
        ),
    );
    captured.leaf.keccak_records[0].output[0] ^= 1;
    captured.leaf.reseal();

    captured.leaf.recovery_records[0].public_key_xy_big_endian[0] ^= 1;
    captured.leaf.reseal();
    try std.testing.expectError(
        error.ExternalTapeMismatch,
        ethereum_replay.replay(
            std.testing.allocator,
            .{
                .leaf = &captured.leaf,
                .program = program.source(),
                .boundary = boundary.source(),
                .expected_memory_layout = segment.base.rw_memory.layout,
                .expected_source = expected_source,
                .expected_entry_cpu_sha256 = expected_entry_cpu_sha256,
                .expected_exit_cpu_sha256 = expected_exit_cpu_sha256,
                .expected_completion = expected_completion,
            },
        ),
    );
    captured.leaf.recovery_records[0].public_key_xy_big_endian[0] ^= 1;
    captured.leaf.reseal();

    captured.leaf.keccak_records[0].execution_clock =
        captured.leaf.recovery_records[0].execution_clock;
    captured.leaf.reseal();
    try std.testing.expectError(
        error.InvalidExternalClockOrder,
        captured.leaf.validate(),
    );
}

const CountingSink = struct {
    consumed: std.atomic.Value(usize) = .init(0),

    fn interface(self: *CountingSink) ethereum_parallel.SinkV1 {
        return .{ .context = self, .consume_fn = consume };
    }

    fn consume(
        context: *anyopaque,
        _: usize,
        result: *ethereum_replay.ResultV1,
    ) !void {
        const self: *CountingSink = @ptrCast(@alignCast(context));
        if (result.keccakf_calls.len() != 1 or
            result.signer_recovery_calls.len() != 1)
        {
            return error.UnexpectedNativeCallCount;
        }
        _ = self.consumed.fetchAdd(1, .release);
    }
};

const CaptureObserver = struct {
    capture: *ethereum_semantic_capture.SegmentObservationV1,

    fn interface(self: *CaptureObserver) segment_session.RetirementObserverV1 {
        return .{
            .context = self,
            .begin_segment_fn = begin,
            .core_row_fn = observe,
        };
    }

    fn begin(context: *anyopaque, segment_index: u32) !void {
        const self: *CaptureObserver = @ptrCast(@alignCast(context));
        try self.capture.begin(segment_index);
    }

    fn observe(context: *anyopaque, row: @import("../trace.zig").TraceRow) !void {
        const self: *CaptureObserver = @ptrCast(@alignCast(context));
        try self.capture.observeCoreRow(row);
    }
};

fn replaceTerminalEcallWithSelfLoop(elf: []u8) void {
    var encoded: [test_elf.ethereum_instructions.len * 4]u8 = undefined;
    for (test_elf.ethereum_instructions, 0..) |word, index|
        std.mem.writeInt(u32, encoded[index * 4 ..][0..4], word, .little);
    const start = std.mem.indexOf(u8, elf, &encoded) orelse unreachable;
    std.mem.writeInt(
        u32,
        elf[start + encoded.len - 4 ..][0..4],
        0x0000_006f,
        .little,
    );
}

fn expectCpuEqual(expected: Cpu, actual: Cpu) !void {
    try std.testing.expectEqual(expected.pc, actual.pc);
    try std.testing.expectEqualSlices(u32, &expected.regs, &actual.regs);
}

fn expectTrackerEqual(
    expected: *const StateChainTracker,
    actual: *const StateChainTracker,
) !void {
    try std.testing.expectEqualSlices(
        u32,
        &expected.reg_last_clk,
        &actual.reg_last_clk,
    );
    try std.testing.expectEqualDeep(expected.accesses.items, actual.accesses.items);
    try std.testing.expectEqualDeep(
        expected.clock_updates_mem.items,
        actual.clock_updates_mem.items,
    );
    try std.testing.expectEqualDeep(
        expected.clock_updates_reg.items,
        actual.clock_updates_reg.items,
    );
    try expectMapEqual(&expected.mem_last_clk, &actual.mem_last_clk);
}

fn expectBoundaryReconstructed(
    words: []const base_replay.BoundaryWord,
    tracker: *const StateChainTracker,
    memory: anytype,
) !void {
    try std.testing.expectEqual(words.len, tracker.mem_initial.count());
    for (words) |word| {
        try std.testing.expectEqual(
            word.entry,
            tracker.mem_initial.get(word.address) orelse
                return error.MissingInitialMemoryWord,
        );
        try std.testing.expectEqual(word.exit, memory.readU32(word.address));
    }
}

fn expectMapEqual(expected: anytype, actual: @TypeOf(expected)) !void {
    try std.testing.expectEqual(expected.count(), actual.count());
    var iterator = expected.iterator();
    while (iterator.next()) |entry| {
        try std.testing.expectEqual(
            entry.value_ptr.*,
            actual.get(entry.key_ptr.*) orelse return error.MissingMapEntry,
        );
    }
}
