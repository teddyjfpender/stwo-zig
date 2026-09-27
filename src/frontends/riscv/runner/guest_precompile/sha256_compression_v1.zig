//! Transactional execution for general SHA compression. Combined-profile
//! dispatch is activated only together with the matching typed caller roster.
const std = @import("std");
const contract = @import("../../isa/sha256_compression_v1.zig");
const record = @import("../../air/guest_precompile/sha256_memory_record.zig");
const sha = @import("../../air/guest_precompile/sha256_compression.zig");
const access = @import("../../access_clock.zig");
const Cpu = @import("../cpu.zig").Cpu;
const Memory = @import("../memory.zig").Memory;
const Layout = @import("../memory_state.zig").MemoryLayout;
const Tracker = @import("../state_chain.zig").StateChainTracker;
const Trace = @import("../trace.zig").Trace;
pub const production_active = contract.production_active;

/// A single owner stores the exact caller record and instruction. The declared
/// program and SHA provider consume views of this same tape, avoiding duplicate
/// wide storage and a second independently mutable call-index authority.
pub const Entry = struct {
    call: record.Record,
    instruction: u32,
    /// Borrow the canonical call record rather than allocating fetch-only rows.
    pub fn programFetch(self: Entry) @import("../../air/program/table.zig").Fetch {
        return .{ .pc = self.call.pc, .word = self.instruction };
    }
};
pub const Frozen = struct {
    storage: std.ArrayList(Entry),
    allocator: std.mem.Allocator,
    pub fn records(self: *const Frozen) []const Entry {
        return self.storage.items;
    }
    pub fn len(self: *const Frozen) usize {
        return self.storage.items.len;
    }
    pub fn deinit(self: *Frozen) void {
        self.storage.deinit(self.allocator);
        self.* = undefined;
    }
};

pub const Tape = struct {
    allocator: std.mem.Allocator,
    limit: usize,
    entries: std.ArrayList(Entry) = .empty,
    pub fn deinit(self: *Tape) void {
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }
    pub fn len(self: *const Tape) usize {
        return self.entries.items.len;
    }
    pub fn freeze(self: *Tape) Frozen {
        const result = Frozen{ .storage = self.entries, .allocator = self.allocator };
        self.entries = .empty;
        self.limit = 0;
        return result;
    }
};

pub fn execute(word: u32, clock: u32, cpu: *Cpu, memory: *Memory, layout: Layout, tracker: *Tracker, tape: *Tape) !void {
    const prepared = try prepare(word, clock, cpu.*, memory, layout, tracker, tape);
    commit(prepared, cpu, memory, tracker, tape);
}

pub fn executeWithRecordedClock(word: u32, clock: u32, origin: usize, aggregate_calls: usize, aggregate_rows: usize, cpu: *Cpu, memory: *Memory, layout: Layout, tracker: *Tracker, trace: *Trace, tape: *Tape) !void {
    const token = try trace.prepareRecordedExternalRetirement(clock, origin, aggregate_calls, aggregate_rows);
    const prepared = try prepare(word, clock, cpu.*, memory, layout, tracker, tape);
    if (!trace.externalRetirementTokenIsCurrent(token, aggregate_calls, aggregate_rows) or
        !Trace.externalRetirementCommitIsValid(token, aggregate_calls + 1, aggregate_rows + 1, clock, clock)) return error.ProfileClockAuthorityMismatch;
    commit(prepared, cpu, memory, tracker, tape);
    trace.commitRecordedExternalRetirement(token);
}

fn within(layout: Layout, pointer: u32, size: u32) bool {
    const end = @as(u64, pointer) + size;
    for ([_][2]u32{ .{ layout.data_base, layout.data_end }, .{ layout.stack_bottom, layout.stack_top }, .{ layout.io_base, layout.io_end } }) |interval| {
        if (pointer >= interval[0] and end <= interval[1]) return true;
    }
    return false;
}

fn prepare(word: u32, clock: u32, cpu: Cpu, memory: *Memory, layout: Layout, tracker: *Tracker, tape: *Tape) !Entry {
    if (tape.len() >= tape.limit) return error.PrecompileCallLimitExceeded;
    if (tape.len() > 0 and clock <= tape.entries.items[tape.len() - 1].call.execution_clock) return error.InvalidShaCallOrder;
    const decoded = try contract.decode(word);
    if (clock == 0 or access.maximum(clock) >= @import("stwo_core").fields.m31.Modulus) return error.PrecompileClockOutOfRange;
    const state_ptr = cpu.readReg(decoded.state_register);
    const block_ptr = cpu.readReg(decoded.block_register);
    if (state_ptr & 3 != 0 or block_ptr & 3 != 0 or !within(layout, state_ptr, 32) or !within(layout, block_ptr, 64)) return error.InvalidShaSpan;
    if (state_ptr < @as(u64, block_ptr) + 64 and block_ptr < @as(u64, state_ptr) + 32) return error.OverlappingShaSpans;
    const reg_clock = access.encode(clock, .first);
    const mem_clock = access.encode(clock, .second);
    var call = record.Record{
        .execution_clock = clock,
        .pc = cpu.pc,
        .state_register = decoded.state_register,
        .block_register = decoded.block_register,
        .state_ptr = state_ptr,
        .block_ptr = block_ptr,
        .pointer_previous_clocks = .{ Tracker.effectivePreviousClock(tracker.reg_last_clk[decoded.state_register], reg_clock), Tracker.effectivePreviousClock(tracker.reg_last_clk[decoded.block_register], reg_clock) },
        .memory_previous_clocks = undefined,
        .state = undefined,
        .block = undefined,
        .output = undefined,
    };
    for (0..record.word_count) |i| {
        const address = call.address(i);
        const value = memory.readU32(address);
        if (i < 8) call.state[i] = value else std.mem.writeInt(u32, call.block[(i - 8) * 4 ..][0..4], value, .little);
        call.memory_previous_clocks[i] = Tracker.effectivePreviousClock(tracker.mem_last_clk.get(address) orelse 0, mem_clock);
    }
    call.output = sha.compress(call.state, call.block);
    try call.validate();
    var memory_gaps: usize = 0;
    for (0..record.word_count) |i| memory_gaps += Tracker.clockGapCount(tracker.mem_last_clk.get(call.address(i)) orelse 0, mem_clock);
    var register_gaps: usize = 0;
    for ([_]u5{ call.state_register, call.block_register }) |register| register_gaps += Tracker.clockGapCount(tracker.reg_last_clk[register], reg_clock);
    // All fallible allocation precedes logical mutation of memory, clocks,
    // registers, PC, the call tape and the external-retirement trace.
    try tape.entries.ensureUnusedCapacity(tape.allocator, 1);
    try tracker.reserveTransitions(.{ .memory_address_count = record.word_count, .access_count = record.word_count + 2, .memory_clock_update_count = memory_gaps, .register_clock_update_count = register_gaps });
    var writes: [8]u32 = undefined;
    for (&writes, 0..) |*address, i| address.* = call.address(i);
    try memory.prepareAlignedWordWrites(&writes);
    return .{ .call = call, .instruction = word };
}

fn commit(entry: Entry, cpu: *Cpu, memory: *Memory, tracker: *Tracker, tape: *Tape) void {
    const call = entry.call;
    const reg_clock = access.encode(call.execution_clock, .first);
    const mem_clock = access.encode(call.execution_clock, .second);
    tracker.recordRegTransitionAssumeCapacity(call.state_register, reg_clock, call.state_ptr, call.state_ptr);
    tracker.recordRegTransitionAssumeCapacity(call.block_register, reg_clock, call.block_ptr, call.block_ptr);
    for (0..record.word_count) |i| {
        const address = call.address(i);
        if (i < 8) memory.writeU32AssumePrepared(address, call.output[i]);
        tracker.recordMemTransitionAssumeCapacity(address, mem_clock, call.before(i), call.after(i));
    }
    tape.entries.appendAssumeCapacity(entry);
    cpu.pc +%= 4;
}
