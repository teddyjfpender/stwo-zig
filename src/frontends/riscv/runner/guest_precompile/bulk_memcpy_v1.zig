//! Transactional runner for the nonproduction fixed-register bulk memcpy.
//!
//! Preparation snapshots every source/destination word and predecessor clock,
//! materializes the exact candidate rows, and completes all reservations.
//! Commit then performs only prepared word writes, assume-capacity state-chain
//! transitions, tape publication, PC retirement, and (optionally) external
//! clock publication.

const std = @import("std");

const access_clock = @import("../../access_clock.zig");
const caller = @import("../../air/guest_precompile/bulk_memcpy_caller_candidate_v1.zig");
const words = @import("../../air/guest_precompile/bulk_memcpy_word_candidate_v1.zig");
const abi = @import("../../isa/bulk_memcpy_candidate_v1.zig");
const Cpu = @import("../cpu.zig").Cpu;
const Memory = @import("../memory.zig").Memory;
const MemoryLayout = @import("../memory_state.zig").MemoryLayout;
const StateChainTracker = @import("../state_chain.zig").StateChainTracker;
const Trace = @import("../trace.zig").Trace;
const call_buffer = @import("bulk_memcpy_call_buffer_v1.zig");
const tape_mod = @import("bulk_memcpy_session_tape_v1.zig");

pub const Error = caller.Error || error{
    OutOfMemory,
    BulkMemcpyTapeLimitExceeded,
    BulkMemcpyClockOutOfRange,
    BulkMemcpySpanOutsideRwMemory,
    BulkMemcpyWordSpansOverlap,
    ProfileClockAuthorityMismatch,
};

const PreparedWord = struct {
    source_address: u32,
    destination_address: u32,
    source_before: u32,
    destination_before: u32,
    destination_after: u32,
};

const Prepared = struct {
    allocator: std.mem.Allocator,
    caller_record: caller.Record,
    inst_word: u32,
    register_clock: u32,
    memory_clock: u32,
    word_commits: []PreparedWord,
    word_rows: []words.Row,
    destination_addresses: []u32,

    fn deinit(self: *Prepared) void {
        self.allocator.free(self.destination_addresses);
        self.allocator.free(self.word_rows);
        self.allocator.free(self.word_commits);
        self.* = undefined;
    }
};

pub fn execute(
    inst_word: u32,
    execution_clock: u32,
    cpu: *Cpu,
    memory: *Memory,
    layout: MemoryLayout,
    tracker: *StateChainTracker,
    tape: *tape_mod.Builder,
) Error!void {
    var prepared = try prepareAndReserve(
        inst_word,
        execution_clock,
        cpu.*,
        memory,
        layout,
        tracker,
        tape,
    );
    defer prepared.deinit();
    commit(&prepared, cpu, memory, tracker, tape);
}

pub fn executeWithRecordedClock(
    inst_word: u32,
    execution_clock: u32,
    cpu: *Cpu,
    memory: *Memory,
    layout: MemoryLayout,
    tracker: *StateChainTracker,
    trace: *Trace,
    tape: *tape_mod.Builder,
) Error!void {
    return executeWithAggregateRecordedClock(
        inst_word,
        execution_clock,
        tape.external_step_origin,
        tape.len(),
        tape.rowLen(),
        cpu,
        memory,
        layout,
        tracker,
        trace,
        tape,
    );
}

/// Candidate overlays keep independent local call indices while sharing the
/// Ethereum extension's one external-retirement clock.
pub fn executeWithAggregateRecordedClock(
    inst_word: u32,
    execution_clock: u32,
    segment_external_origin: usize,
    aggregate_calls_before: usize,
    aggregate_rows_before: usize,
    cpu: *Cpu,
    memory: *Memory,
    layout: MemoryLayout,
    tracker: *StateChainTracker,
    trace: *Trace,
    tape: *tape_mod.Builder,
) Error!void {
    const clock_token = trace.prepareRecordedExternalRetirement(
        execution_clock,
        segment_external_origin,
        aggregate_calls_before,
        aggregate_rows_before,
    ) catch return error.ProfileClockAuthorityMismatch;
    var prepared = try prepareAndReserve(
        inst_word,
        execution_clock,
        cpu.*,
        memory,
        layout,
        tracker,
        tape,
    );
    defer prepared.deinit();
    if (!trace.externalRetirementTokenIsCurrent(
        clock_token,
        aggregate_calls_before,
        aggregate_rows_before,
    ) or !Trace.externalRetirementCommitIsValid(
        clock_token,
        aggregate_calls_before + 1,
        aggregate_rows_before + 1,
        prepared.caller_record.execution_clock,
        execution_clock,
    )) return error.ProfileClockAuthorityMismatch;
    commit(&prepared, cpu, memory, tracker, tape);
    trace.commitRecordedExternalRetirement(clock_token);
}

/// Candidate-only projection of one real architectural boundary into the
/// frozen proof tape. The CPU, memory, and predecessor-clock tracker are all
/// borrowed as const and therefore cannot be committed or advanced here.
/// Unlike `execute`, this does not reserve state transitions, write memory,
/// retire the PC, or publish an external execution step.
pub fn projectIntoTape(
    execution_clock: u32,
    cpu: Cpu,
    memory: *const Memory,
    layout: MemoryLayout,
    tracker: *const StateChainTracker,
    tape: *tape_mod.Builder,
) Error!void {
    var prepared = try prepare(
        abi.fixed_word,
        execution_clock,
        cpu,
        memory,
        layout,
        tracker,
        tape,
    );
    defer prepared.deinit();
    try tape.reserveOne(prepared.word_rows.len);
    tape.appendAssumeCapacity(
        prepared.inst_word,
        prepared.caller_record,
        prepared.word_rows,
    );
}

fn prepareAndReserve(
    inst_word: u32,
    execution_clock: u32,
    cpu: Cpu,
    memory: *Memory,
    layout: MemoryLayout,
    tracker: *StateChainTracker,
    tape: *tape_mod.Builder,
) Error!Prepared {
    var prepared = try prepare(
        inst_word,
        execution_clock,
        cpu,
        memory,
        layout,
        tracker,
        tape,
    );
    errdefer prepared.deinit();
    try tape.reserveOne(prepared.word_commits.len);

    var memory_gap_count: usize = 0;
    for (prepared.word_commits) |word| {
        memory_gap_count += StateChainTracker.clockGapCount(
            tracker.mem_last_clk.get(word.source_address) orelse 0,
            prepared.memory_clock,
        );
        memory_gap_count += StateChainTracker.clockGapCount(
            tracker.mem_last_clk.get(word.destination_address) orelse 0,
            prepared.memory_clock,
        );
    }
    var register_gap_count: usize = 0;
    inline for (.{
        abi.destination_register,
        abi.source_register,
        abi.length_register,
    }) |register| register_gap_count += StateChainTracker.clockGapCount(
        tracker.reg_last_clk[register],
        prepared.register_clock,
    );
    try tracker.reserveTransitions(.{
        .memory_address_count = 2 * prepared.word_commits.len,
        .access_count = 3 + 2 * prepared.word_commits.len,
        .memory_clock_update_count = memory_gap_count,
        .register_clock_update_count = register_gap_count,
    });
    try memory.prepareAlignedWordWrites(prepared.destination_addresses);
    return prepared;
}

fn prepare(
    inst_word: u32,
    execution_clock: u32,
    cpu: Cpu,
    memory: *const Memory,
    layout: MemoryLayout,
    tracker: *const StateChainTracker,
    tape: *const tape_mod.Builder,
) Error!Prepared {
    _ = abi.decode(inst_word) catch return error.InvalidCall;
    if (execution_clock == 0 or
        access_clock.maximum(execution_clock) > std.math.maxInt(u32))
    {
        return error.BulkMemcpyClockOutOfRange;
    }
    const call = words.Call{
        .execution_clock = execution_clock,
        .call_index = std.math.cast(u32, tape.len()) orelse
            return error.BulkMemcpyTapeLimitExceeded,
        .pc = cpu.pc,
        .source = cpu.readReg(abi.source_register),
        .destination = cpu.readReg(abi.destination_register),
        .length = cpu.readReg(abi.length_register),
    };
    try call_buffer.validateRunnerCall(call);
    const source_aligned = call.source & ~@as(u32, 3);
    const destination_aligned = call.destination & ~@as(u32, 3);
    const byte_count = std.math.mul(
        u32,
        call.expectedWordCount(),
        4,
    ) catch return error.InvalidCall;
    const source_aligned_end = std.math.add(
        u32,
        source_aligned,
        byte_count,
    ) catch return error.InvalidCall;
    const destination_aligned_end = std.math.add(
        u32,
        destination_aligned,
        byte_count,
    ) catch return error.InvalidCall;
    if (!(source_aligned_end <= destination_aligned or
        destination_aligned_end <= source_aligned))
    {
        return error.BulkMemcpyWordSpansOverlap;
    }
    if (!spanWithinOneRwInterval(layout, source_aligned, source_aligned_end) or
        !spanWithinOneRwInterval(
            layout,
            destination_aligned,
            destination_aligned_end,
        ))
    {
        return error.BulkMemcpySpanOutsideRwMemory;
    }

    const allocator = tape.allocator();
    const word_count: usize = call.expectedWordCount();
    const word_commits = try allocator.alloc(PreparedWord, word_count);
    errdefer allocator.free(word_commits);
    const word_rows = try allocator.alloc(words.Row, word_count);
    errdefer allocator.free(word_rows);
    const destination_addresses = try allocator.alloc(u32, word_count);
    errdefer allocator.free(destination_addresses);
    const memory_clock = access_clock.encode(execution_clock, .second);
    for (
        word_commits,
        word_rows,
        destination_addresses,
        0..,
    ) |*prepared_word, *row, *destination_address, index| {
        const byte_offset: u32 = @intCast(4 * index);
        const source_address = source_aligned + byte_offset;
        destination_address.* = destination_aligned + byte_offset;
        const source_before = memory.readU32(source_address);
        const destination_before = memory.readU32(destination_address.*);
        const source_raw_clock = tracker.mem_last_clk.get(source_address) orelse 0;
        const destination_raw_clock = tracker.mem_last_clk.get(
            destination_address.*,
        ) orelse 0;
        if (source_raw_clock >= memory_clock or
            destination_raw_clock >= memory_clock)
        {
            return error.InvalidRow;
        }
        row.* = try words.materializeRow(call, @intCast(index), .{
            .source_previous_clock = StateChainTracker.effectivePreviousClock(
                source_raw_clock,
                memory_clock,
            ),
            .destination_previous_clock = StateChainTracker.effectivePreviousClock(
                destination_raw_clock,
                memory_clock,
            ),
            .source_bytes = wordBytes(source_before),
            .destination_before = wordBytes(destination_before),
        });
        prepared_word.* = .{
            .source_address = source_address,
            .destination_address = destination_address.*,
            .source_before = source_before,
            .destination_before = destination_before,
            .destination_after = bytesWord(row.destination_after),
        };
    }
    const register_clock = access_clock.encode(execution_clock, .first);
    const caller_record = caller.Record{
        .execution_clock = execution_clock,
        .pc = cpu.pc,
        .destination_previous_clock = StateChainTracker.effectivePreviousClock(
            tracker.reg_last_clk[abi.destination_register],
            register_clock,
        ),
        .source_previous_clock = StateChainTracker.effectivePreviousClock(
            tracker.reg_last_clk[abi.source_register],
            register_clock,
        ),
        .length_previous_clock = StateChainTracker.effectivePreviousClock(
            tracker.reg_last_clk[abi.length_register],
            register_clock,
        ),
        .destination = call.destination,
        .source = call.source,
        .length = call.length,
        .call_index = call.call_index,
    };
    try caller_record.validate();
    return .{
        .allocator = allocator,
        .caller_record = caller_record,
        .inst_word = inst_word,
        .register_clock = register_clock,
        .memory_clock = memory_clock,
        .word_commits = word_commits,
        .word_rows = word_rows,
        .destination_addresses = destination_addresses,
    };
}

fn commit(
    prepared: *const Prepared,
    cpu: *Cpu,
    memory: *Memory,
    tracker: *StateChainTracker,
    tape: *tape_mod.Builder,
) void {
    inline for (.{
        .{ abi.destination_register, prepared.caller_record.destination },
        .{ abi.source_register, prepared.caller_record.source },
        .{ abi.length_register, prepared.caller_record.length },
    }) |register_value| tracker.recordRegTransitionAssumeCapacity(
        register_value[0],
        prepared.register_clock,
        register_value[1],
        register_value[1],
    );
    for (prepared.word_commits) |word| {
        tracker.recordMemTransitionAssumeCapacity(
            word.source_address,
            prepared.memory_clock,
            word.source_before,
            word.source_before,
        );
        memory.writeU32AssumePrepared(
            word.destination_address,
            word.destination_after,
        );
        tracker.recordMemTransitionAssumeCapacity(
            word.destination_address,
            prepared.memory_clock,
            word.destination_before,
            word.destination_after,
        );
    }
    tape.appendAssumeCapacity(
        prepared.inst_word,
        prepared.caller_record,
        prepared.word_rows,
    );
    cpu.pc +%= 4;
}

fn spanWithinOneRwInterval(layout: MemoryLayout, start: u32, end: u32) bool {
    const intervals = [_][2]u32{
        .{ layout.data_base, layout.data_end },
        .{ layout.stack_bottom, layout.stack_top },
        .{ layout.io_base, layout.io_end },
    };
    for (intervals) |interval| {
        if (interval[0] < interval[1] and
            start >= interval[0] and end <= interval[1])
        {
            return true;
        }
    }
    return false;
}

fn wordBytes(value: u32) [4]u8 {
    var result: [4]u8 = undefined;
    std.mem.writeInt(u32, &result, value, .little);
    return result;
}

fn bytesWord(value: [4]u8) u32 {
    return std.mem.readInt(u32, &value, .little);
}

comptime {
    if (abi.production_active or caller.production_active or words.production_active)
        @compileError("bulk memcpy runner is candidate-only");
}
