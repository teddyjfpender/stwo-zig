//! Transactional execution of `stwo.keccakf.1600.v1`.
//!
//! Prepare performs every fallible action; commit publishes memory, state-chain,
//! call, row, and PC state without allocation.

const std = @import("std");
const access_clock = @import("../../access_clock.zig");
const authority = @import("../../air/guest_precompile/keccakf_authority.zig");
const custom0 = @import("../../isa/custom0.zig");
const execution_profile = @import("../../isa/execution_profile.zig");
const isa_profile = @import("../../isa/profile.zig");
const Cpu = @import("../cpu.zig").Cpu;
const Memory = @import("../memory.zig").Memory;
const MemoryLayout = @import("../memory_state.zig").MemoryLayout;
const Trace = @import("../trace.zig").Trace;
const StateChainTracker = @import("../state_chain.zig").StateChainTracker;
const call_buffer = @import("keccakf_call_buffer.zig");

pub const word_count = call_buffer.word_count;
pub const state_bytes = word_count * @sizeOf(u32);
pub const ExecutionProfile = execution_profile.ExecutionProfile;

pub const Error = custom0.DecodeError || error{
    OutOfMemory,
    PrecompileCallLimitExceeded,
    PrecompileClockOutOfRange,
    PrecompileAddressMisaligned,
    PrecompileSpanOutsideRwMemory,
};

pub const ExecutionRow = struct {
    execution_clock: u32,
    pc: u32,
    inst_word: u32,
    call_index: u32,
};

pub const FrozenExecutionRows = struct {
    storage: std.ArrayList(ExecutionRow),
    allocator: std.mem.Allocator,

    pub fn rows(self: *const FrozenExecutionRows) []const ExecutionRow {
        return self.storage.items;
    }

    pub fn capacity(self: *const FrozenExecutionRows) usize {
        return self.storage.capacity;
    }

    pub fn deinit(self: *FrozenExecutionRows) void {
        self.storage.deinit(self.allocator);
        self.* = undefined;
    }
};

pub const ExecutionRowsBuilder = struct {
    storage: std.ArrayList(ExecutionRow) = .empty,
    allocator: std.mem.Allocator,
    limit: usize,

    pub fn init(
        allocator: std.mem.Allocator,
        limit: usize,
    ) error{PrecompileCallLimitExceeded}!ExecutionRowsBuilder {
        if (limit > call_buffer.max_calls) return error.PrecompileCallLimitExceeded;
        return .{ .allocator = allocator, .limit = limit };
    }

    pub fn deinit(self: *ExecutionRowsBuilder) void {
        self.storage.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn len(self: *const ExecutionRowsBuilder) usize {
        return self.storage.items.len;
    }

    pub fn rows(self: *const ExecutionRowsBuilder) []const ExecutionRow {
        return self.storage.items;
    }

    pub fn reserveOne(self: *ExecutionRowsBuilder) Error!void {
        if (self.storage.items.len >= self.limit)
            return error.PrecompileCallLimitExceeded;
        try self.storage.ensureUnusedCapacity(self.allocator, 1);
    }

    fn appendAssumeCapacity(self: *ExecutionRowsBuilder, row: ExecutionRow) void {
        std.debug.assert(self.storage.items.len < self.limit);
        self.storage.appendAssumeCapacity(row);
    }

    pub fn freeze(self: *ExecutionRowsBuilder) FrozenExecutionRows {
        const result = FrozenExecutionRows{
            .storage = self.storage,
            .allocator = self.allocator,
        };
        self.storage = .empty;
        self.limit = 0;
        return result;
    }
};

const Prepared = struct {
    record: call_buffer.Record,
    row: ExecutionRow,
    addresses: [word_count]u32,
    pointer_clock: u32,
    memory_clock: u32,
};

pub fn execute(
    profile: ExecutionProfile,
    inst_word: u32,
    execution_clock: u32,
    cpu: *Cpu,
    memory: *Memory,
    layout: MemoryLayout,
    tracker: *StateChainTracker,
    calls: *call_buffer.Builder,
    execution_rows: *ExecutionRowsBuilder,
) Error!void {
    const prepared = try prepareAndReserve(
        profile,
        inst_word,
        execution_clock,
        cpu.*,
        memory,
        layout,
        tracker,
        calls,
        execution_rows,
    );
    commit(prepared, cpu, memory, tracker, calls, execution_rows);
}

/// Publish the Keccak call and the runner's external-retirement clock through
/// one allocation-free commit after every fallible check and reserve succeeds.
pub fn executeWithRecordedClock(
    profile: ExecutionProfile,
    inst_word: u32,
    execution_clock: u32,
    segment_external_origin: usize,
    cpu: *Cpu,
    memory: *Memory,
    layout: MemoryLayout,
    tracker: *StateChainTracker,
    trace: *Trace,
    calls: *call_buffer.Builder,
    execution_rows: *ExecutionRowsBuilder,
) !void {
    return executeWithAggregateRecordedClock(
        profile,
        inst_word,
        execution_clock,
        segment_external_origin,
        cpu,
        memory,
        layout,
        tracker,
        trace,
        calls.len(),
        execution_rows.len(),
        calls,
        execution_rows,
    );
}

/// Combined profiles keep independent typed tapes. Aggregate counts bind the
/// one shared external-retirement clock without weakening either tape's local
/// call-index authority.
pub fn executeWithAggregateRecordedClock(
    profile: ExecutionProfile,
    inst_word: u32,
    execution_clock: u32,
    segment_external_origin: usize,
    cpu: *Cpu,
    memory: *Memory,
    layout: MemoryLayout,
    tracker: *StateChainTracker,
    trace: *Trace,
    aggregate_calls_before: usize,
    aggregate_rows_before: usize,
    calls: *call_buffer.Builder,
    execution_rows: *ExecutionRowsBuilder,
) !void {
    const clock_token = try trace.prepareRecordedExternalRetirement(
        execution_clock,
        segment_external_origin,
        aggregate_calls_before,
        aggregate_rows_before,
    );
    const prepared = try prepareAndReserve(
        profile,
        inst_word,
        execution_clock,
        cpu.*,
        memory,
        layout,
        tracker,
        calls,
        execution_rows,
    );
    if (!trace.externalRetirementTokenIsCurrent(
        clock_token,
        aggregate_calls_before,
        aggregate_rows_before,
    )) return error.ProfileClockAuthorityMismatch;
    if (!Trace.externalRetirementCommitIsValid(
        clock_token,
        aggregate_calls_before + 1,
        aggregate_rows_before + 1,
        prepared.record.execution_clock,
        prepared.row.execution_clock,
    )) return error.ProfileClockAuthorityMismatch;
    commitWithRecordedClock(
        prepared,
        cpu,
        memory,
        tracker,
        trace,
        clock_token,
        calls,
        execution_rows,
    );
}

fn prepareAndReserve(
    profile: ExecutionProfile,
    inst_word: u32,
    execution_clock: u32,
    cpu: Cpu,
    memory: *Memory,
    layout: MemoryLayout,
    tracker: *StateChainTracker,
    calls: *call_buffer.Builder,
    execution_rows: *ExecutionRowsBuilder,
) Error!Prepared {
    const prepared = try prepare(
        profile,
        inst_word,
        execution_clock,
        cpu,
        memory,
        layout,
        tracker,
        calls,
    );
    try calls.reserveOne();
    try execution_rows.reserveOne();

    var memory_gap_count: usize = 0;
    for (prepared.addresses) |addr| {
        memory_gap_count += StateChainTracker.clockGapCount(
            tracker.mem_last_clk.get(addr) orelse 0,
            prepared.memory_clock,
        );
    }
    const register_gap_count = StateChainTracker.clockGapCount(
        tracker.reg_last_clk[prepared.record.pointer_register],
        prepared.pointer_clock,
    );
    try tracker.reserveTransitions(.{
        .memory_address_count = word_count,
        .access_count = word_count + 1,
        .memory_clock_update_count = memory_gap_count,
        .register_clock_update_count = register_gap_count,
    });
    try memory.prepareAlignedWordWrites(&prepared.addresses);
    return prepared;
}

fn prepare(
    profile: ExecutionProfile,
    inst_word: u32,
    execution_clock: u32,
    cpu: Cpu,
    memory: *const Memory,
    layout: MemoryLayout,
    tracker: *const StateChainTracker,
    calls: *const call_buffer.Builder,
) Error!Prepared {
    const decoded = try custom0.decode(profile, inst_word);
    if (decoded.opcode != .keccakf_1600_permute_in_place_v1)
        return error.InvalidPrecompileEncoding;
    if (execution_clock == 0 or
        access_clock.maximum(execution_clock) > std.math.maxInt(u32))
    {
        return error.PrecompileClockOutOfRange;
    }

    const state_ptr = cpu.readReg(decoded.rs1);
    if (state_ptr & 7 != 0) return error.PrecompileAddressMisaligned;
    const span_end = @as(u64, state_ptr) + state_bytes;
    if (span_end > isa_profile.program_commitment_size or
        !spanWithinOneRwInterval(layout, state_ptr, span_end))
    {
        return error.PrecompileSpanOutsideRwMemory;
    }

    const pointer_clock = access_clock.encode(execution_clock, .first);
    const memory_clock = access_clock.encode(execution_clock, .second);
    const pointer_previous_clock = StateChainTracker.effectivePreviousClock(
        tracker.reg_last_clk[decoded.rs1],
        pointer_clock,
    );

    var addresses: [word_count]u32 = undefined;
    var input: [word_count]u32 = undefined;
    var previous_clocks: [word_count]u32 = undefined;
    var state: authority.State = undefined;
    for (0..word_count) |index| {
        const addr = state_ptr + @as(u32, @intCast(index * @sizeOf(u32)));
        const word = memory.readU32(addr);
        addresses[index] = addr;
        input[index] = word;
        previous_clocks[index] = StateChainTracker.effectivePreviousClock(
            tracker.mem_last_clk.get(addr) orelse 0,
            memory_clock,
        );
    }
    for (&state, 0..) |*lane, index| {
        lane.* = input[2 * index] | (@as(u64, input[2 * index + 1]) << 32);
    }
    authority.permute(&state);
    var output: [word_count]u32 = undefined;
    for (state, 0..) |lane, index| {
        output[2 * index] = @truncate(lane);
        output[2 * index + 1] = @truncate(lane >> 32);
    }

    return .{
        .record = .{
            .execution_clock = execution_clock,
            .pc = cpu.pc,
            .state_ptr = state_ptr,
            .pointer_register = decoded.rs1,
            .pointer_previous_clock = pointer_previous_clock,
            .input = input,
            .output = output,
            .memory_previous_clocks = previous_clocks,
        },
        .row = .{
            .execution_clock = execution_clock,
            .pc = cpu.pc,
            .inst_word = inst_word,
            .call_index = @intCast(calls.len()),
        },
        .addresses = addresses,
        .pointer_clock = pointer_clock,
        .memory_clock = memory_clock,
    };
}

fn commit(
    prepared: Prepared,
    cpu: *Cpu,
    memory: *Memory,
    tracker: *StateChainTracker,
    calls: *call_buffer.Builder,
    execution_rows: *ExecutionRowsBuilder,
) void {
    tracker.recordRegTransitionAssumeCapacity(
        prepared.record.pointer_register,
        prepared.pointer_clock,
        prepared.record.state_ptr,
        prepared.record.state_ptr,
    );
    for (0..word_count) |index| {
        memory.writeU32AssumePrepared(prepared.addresses[index], prepared.record.output[index]);
        tracker.recordMemTransitionAssumeCapacity(
            prepared.addresses[index],
            prepared.memory_clock,
            prepared.record.input[index],
            prepared.record.output[index],
        );
    }
    execution_rows.appendAssumeCapacity(prepared.row);
    calls.appendAssumeCapacity(prepared.record);
    cpu.pc +%= 4;
}

fn commitWithRecordedClock(
    prepared: Prepared,
    cpu: *Cpu,
    memory: *Memory,
    tracker: *StateChainTracker,
    trace: *Trace,
    clock_token: Trace.ExternalRetirementToken,
    calls: *call_buffer.Builder,
    execution_rows: *ExecutionRowsBuilder,
) void {
    commit(prepared, cpu, memory, tracker, calls, execution_rows);
    trace.commitRecordedExternalRetirement(clock_token);
}

fn spanWithinOneRwInterval(layout: MemoryLayout, start: u32, end: u64) bool {
    const intervals = [_][2]u32{
        .{ layout.data_base, layout.data_end },
        .{ layout.stack_bottom, layout.stack_top },
        .{ layout.io_base, layout.io_end },
    };
    for (intervals) |interval| {
        if (interval[0] < interval[1] and
            start >= interval[0] and end <= @as(u64, interval[1]))
        {
            return true;
        }
    }
    return false;
}
