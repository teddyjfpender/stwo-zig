//! Transactional runner semantics for the non-production U256 swap opcode.
//!
//! Prepare performs every validation, snapshot, allocation, and reservation.
//! Commit then swaps sixteen prepared aligned words, publishes exact state
//! chains/tape custody, and retires the one external guest instruction.

const std = @import("std");
const access_clock = @import("../../access_clock.zig");
const abi = @import("../../isa/stack_swap_candidate_v1.zig");
const caller = @import("../../air/guest_precompile/stack_swap_caller_candidate_v1.zig");
const words = @import("../../air/guest_precompile/stack_swap_word_candidate_v1.zig");
const Cpu = @import("../cpu.zig").Cpu;
const Memory = @import("../memory.zig").Memory;
const MemoryLayout = @import("../memory_state.zig").MemoryLayout;
const StateChainTracker = @import("../state_chain.zig").StateChainTracker;
const Trace = @import("../trace.zig").Trace;
const tape_mod = @import("stack_swap_session_tape_v1.zig");

pub const Error = caller.Error || error{
    OutOfMemory,
    StackSwapTapeLimitExceeded,
    StackSwapClockOutOfRange,
    StackSwapSpanOutsideRwMemory,
    StackSwapProfileClockAuthorityMismatch,
};

const PreparedWord = struct {
    lhs_address: u32,
    rhs_address: u32,
    lhs_before: u32,
    rhs_before: u32,
};

const Prepared = struct {
    caller_record: caller.Record,
    inst_word: u32,
    register_clock: u32,
    memory_clock: u32,
    commits: [words.lane_count]PreparedWord,
    word_rows: [words.lane_count]words.Row,
    write_addresses: [2 * words.lane_count]u32,
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
    const prepared = try prepareAndReserve(
        inst_word,
        execution_clock,
        cpu.*,
        memory,
        layout,
        tracker,
        tape,
    );
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

/// Combined candidate profiles retain independent local call indices while
/// sharing the execution trace's single external-retirement clock.
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
    const token = trace.prepareRecordedExternalRetirement(
        execution_clock,
        segment_external_origin,
        aggregate_calls_before,
        aggregate_rows_before,
    ) catch return error.StackSwapProfileClockAuthorityMismatch;
    const prepared = try prepareAndReserve(
        inst_word,
        execution_clock,
        cpu.*,
        memory,
        layout,
        tracker,
        tape,
    );
    if (!trace.externalRetirementTokenIsCurrent(
        token,
        aggregate_calls_before,
        aggregate_rows_before,
    ) or
        !Trace.externalRetirementCommitIsValid(
            token,
            aggregate_calls_before + 1,
            aggregate_rows_before + 1,
            prepared.caller_record.execution_clock,
            execution_clock,
        ))
    {
        return error.StackSwapProfileClockAuthorityMismatch;
    }
    commit(&prepared, cpu, memory, tracker, tape);
    trace.commitRecordedExternalRetirement(token);
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
    const prepared = try prepare(
        inst_word,
        execution_clock,
        cpu,
        memory,
        layout,
        tracker,
        tape,
    );
    try tape.reserveOne();

    var memory_gap_count: usize = 0;
    for (prepared.commits) |word| {
        memory_gap_count += StateChainTracker.clockGapCount(
            tracker.mem_last_clk.get(word.lhs_address) orelse 0,
            prepared.memory_clock,
        );
        memory_gap_count += StateChainTracker.clockGapCount(
            tracker.mem_last_clk.get(word.rhs_address) orelse 0,
            prepared.memory_clock,
        );
    }
    var register_gap_count: usize = 0;
    inline for (.{ abi.lhs_pointer_register, abi.rhs_pointer_register }) |register|
        register_gap_count += StateChainTracker.clockGapCount(
            tracker.reg_last_clk[register],
            prepared.register_clock,
        );
    try tracker.reserveTransitions(.{
        .memory_address_count = 2 * words.lane_count,
        .access_count = 2 + 2 * words.lane_count,
        .memory_clock_update_count = memory_gap_count,
        .register_clock_update_count = register_gap_count,
    });
    try memory.prepareAlignedWordWrites(&prepared.write_addresses);
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
    _ = tape.authority.decode(inst_word) catch
        return error.InvalidStackSwapCallerRecord;
    if (execution_clock == 0 or
        access_clock.maximum(execution_clock) > std.math.maxInt(u32))
    {
        return error.StackSwapClockOutOfRange;
    }
    const lhs_pointer = cpu.readReg(abi.lhs_pointer_register);
    const rhs_pointer = cpu.readReg(abi.rhs_pointer_register);
    const lhs_end = std.math.add(u32, lhs_pointer, abi.u256_bytes) catch
        return error.InvalidStackSwapCallerRecord;
    const rhs_end = std.math.add(u32, rhs_pointer, abi.u256_bytes) catch
        return error.InvalidStackSwapCallerRecord;
    if (!spanWithinOneRwInterval(layout, lhs_pointer, lhs_end) or
        !spanWithinOneRwInterval(layout, rhs_pointer, rhs_end))
    {
        return error.StackSwapSpanOutsideRwMemory;
    }

    const memory_clock = access_clock.encode(execution_clock, .second);
    const call = words.Call{
        .execution_clock = execution_clock,
        .call_index = @intCast(tape.len()),
        .pc = cpu.pc,
        .lhs_first_word = lhs_pointer / abi.word_bytes,
        .rhs_first_word = rhs_pointer / abi.word_bytes,
    };
    try call.validate();
    var commits: [words.lane_count]PreparedWord = undefined;
    var word_rows: [words.lane_count]words.Row = undefined;
    var write_addresses: [2 * words.lane_count]u32 = undefined;
    for (0..words.lane_count) |index| {
        const byte_offset: u32 = @intCast(index * abi.word_bytes);
        const lhs_address = lhs_pointer + byte_offset;
        const rhs_address = rhs_pointer + byte_offset;
        const lhs_before = memory.readU32(lhs_address);
        const rhs_before = memory.readU32(rhs_address);
        const lhs_raw_clock = tracker.mem_last_clk.get(lhs_address) orelse 0;
        const rhs_raw_clock = tracker.mem_last_clk.get(rhs_address) orelse 0;
        if (lhs_raw_clock >= memory_clock or rhs_raw_clock >= memory_clock)
            return error.InvalidStackSwapWordRow;
        commits[index] = .{
            .lhs_address = lhs_address,
            .rhs_address = rhs_address,
            .lhs_before = lhs_before,
            .rhs_before = rhs_before,
        };
        word_rows[index] = try words.materializeRow(call, .at(@intCast(index)), .{
            .lhs_previous_clock = StateChainTracker.effectivePreviousClock(
                lhs_raw_clock,
                memory_clock,
            ),
            .rhs_previous_clock = StateChainTracker.effectivePreviousClock(
                rhs_raw_clock,
                memory_clock,
            ),
            .lhs_before = wordBytes(lhs_before),
            .rhs_before = wordBytes(rhs_before),
        });
        write_addresses[2 * index] = lhs_address;
        write_addresses[2 * index + 1] = rhs_address;
    }
    const register_clock = access_clock.encode(execution_clock, .first);
    const caller_record = caller.Record{
        .execution_clock = execution_clock,
        .pc = cpu.pc,
        .lhs_previous_clock = StateChainTracker.effectivePreviousClock(
            tracker.reg_last_clk[abi.lhs_pointer_register],
            register_clock,
        ),
        .rhs_previous_clock = StateChainTracker.effectivePreviousClock(
            tracker.reg_last_clk[abi.rhs_pointer_register],
            register_clock,
        ),
        .lhs_pointer = lhs_pointer,
        .rhs_pointer = rhs_pointer,
        .call_index = call.call_index,
    };
    try caller_record.validate();
    return .{
        .caller_record = caller_record,
        .inst_word = inst_word,
        .register_clock = register_clock,
        .memory_clock = memory_clock,
        .commits = commits,
        .word_rows = word_rows,
        .write_addresses = write_addresses,
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
        .{ abi.lhs_pointer_register, prepared.caller_record.lhs_pointer },
        .{ abi.rhs_pointer_register, prepared.caller_record.rhs_pointer },
    }) |register_value| tracker.recordRegTransitionAssumeCapacity(
        register_value[0],
        prepared.register_clock,
        register_value[1],
        register_value[1],
    );
    for (prepared.commits) |word| {
        memory.writeU32AssumePrepared(word.lhs_address, word.rhs_before);
        tracker.recordMemTransitionAssumeCapacity(
            word.lhs_address,
            prepared.memory_clock,
            word.lhs_before,
            word.rhs_before,
        );
        memory.writeU32AssumePrepared(word.rhs_address, word.lhs_before);
        tracker.recordMemTransitionAssumeCapacity(
            word.rhs_address,
            prepared.memory_clock,
            word.rhs_before,
            word.lhs_before,
        );
    }
    tape.appendAssumeCapacity(
        prepared.inst_word,
        prepared.caller_record,
        &prepared.word_rows,
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
        if (interval[0] < interval[1] and start >= interval[0] and end <= interval[1])
            return true;
    }
    return false;
}

fn wordBytes(value: u32) [4]u8 {
    var result: [4]u8 = undefined;
    std.mem.writeInt(u32, &result, value, .little);
    return result;
}

comptime {
    if (abi.production_active or caller.production_active or words.production_active)
        @compileError("stack-swap runner is candidate-only");
}
