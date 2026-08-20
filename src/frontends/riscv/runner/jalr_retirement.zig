//! Failure-atomic retirement for the typed RV32 JALR authority.
//!
//! The fixed authority owns source-plus-immediate target calculation, bit-zero
//! clearing, program-address admission, link result, x0, witness, roots, and
//! relations. This runner boundary owns exact I-type word admission, ordered
//! source/destination predecessor clocks, capacity preflight, and atomic CPU,
//! trace, and state-chain publication. The warm fused path allocates nothing.

const std = @import("std");
const builtin = @import("builtin");
const access_clock = @import("../access_clock.zig");
const typed_jalr = @import("../air/lang/typed_jalr.zig");
const typed_authority = @import("../air/lang/typed_jalr_authority.zig");
const Cpu = @import("cpu.zig").Cpu;
const state_chain = @import("state_chain.zig");
const trace_mod = @import("trace.zig");

pub const StateChainTracker = state_chain.StateChainTracker;
pub const Trace = trace_mod.Trace;
pub const TraceRow = trace_mod.TraceRow;
pub const DecodedInst = typed_authority.DecodedInst;
pub const Authority = typed_authority.Authority;

pub const StageError = typed_authority.ExecutionError || error{
    ClockOutOfRange,
    InstructionClockMismatch,
    InstructionWordMismatch,
    NonIncreasingClock,
    TraceInvariantViolation,
    ZeroRegisterValue,
};
pub const PrepareError = error{ OutOfMemory, StaleRetirement };
pub const CommitError = error{ AlreadyCommitted, StaleRetirement };
pub const RetireError = StageError || PrepareError;

// The current 64-bit layout is 88 bytes. Keep one eight-byte growth slot, but
// reject accidental cache-footprint creep at compile time.
pub const MAX_PLAN_BYTES: usize = 96;
pub const MAX_PREPARED_BYTES: usize = 16;

pub const PINNED_AUTHORITY = Authority.pinned();

pub fn authenticateCanonical(allocator: std.mem.Allocator) !Authority {
    var definition = try typed_jalr.build(allocator, .generated);
    defer definition.deinit();
    const binding = try typed_authority.Binding.canonical(&definition);
    return typed_authority.Authority.init(&definition, &binding);
}

/// Pointer-free two-register transaction. Raw clocks bind the live tracker;
/// effective clocks are the values committed after synthetic gap rows.
pub const Plan = struct {
    instruction: DecodedInst,
    instruction_clock: u32,
    pc_before: u32,
    next_pc: u32,
    inst_word: u32,
    rs1_value: u32,
    rs2_value: u32,
    rd_previous_value: u32,
    rd_next_value: u32,
    source_raw_previous_clock: u32,
    source_previous_clock: u32,
    destination_raw_previous_clock: u32,
    destination_previous_clock: u32,
    source_gap_count: usize,
    destination_gap_count: usize,
    expected_trace_len: usize,
    branch_taken: bool,

    pub inline fn traceRow(self: *const Plan) TraceRow {
        return canonicalRow(self);
    }

    pub inline fn reservation(self: *const Plan) StateChainTracker.Reservation {
        return .{
            .memory_address_count = 0,
            .access_count = 2,
            .memory_clock_update_count = 0,
            .register_clock_update_count = self.source_gap_count +
                self.destination_gap_count,
        };
    }

    pub fn isCurrentFor(
        self: *const Plan,
        cpu: *const Cpu,
        trace: *const Trace,
        tracker: *const StateChainTracker,
    ) bool {
        return self.isWellFormed() and
            self.runnerStateIsCurrent(cpu, trace) and
            self.accessStateIsCurrent(tracker);
    }

    pub fn prepare(
        self: *const Plan,
        cpu: *const Cpu,
        trace: *Trace,
        tracker: *StateChainTracker,
    ) PrepareError!Prepared {
        if (!self.isCurrentFor(cpu, trace, tracker))
            return error.StaleRetirement;
        try self.reserveAndRevalidate(cpu, trace, tracker);
        return .{ .plan = self };
    }

    pub fn commitAtomic(
        self: *const Plan,
        cpu: *Cpu,
        trace: *Trace,
        tracker: *StateChainTracker,
    ) PrepareError!void {
        if (!self.isCurrentFor(cpu, trace, tracker))
            return error.StaleRetirement;
        try self.reserveAndRevalidate(cpu, trace, tracker);
        self.publishAssumeCapacity(cpu, trace, tracker);
    }

    inline fn reserveAndRevalidate(
        self: *const Plan,
        cpu: *const Cpu,
        trace: *Trace,
        tracker: *StateChainTracker,
    ) PrepareError!void {
        const trace_needs_growth = trace.rows.capacity -
            trace.rows.items.len < 1;
        const required = self.reservation();
        const access_needs_growth = tracker.accesses.capacity -
            tracker.accesses.items.len < required.access_count;
        const gaps_need_growth = tracker.clock_updates_reg.capacity -
            tracker.clock_updates_reg.items.len <
            required.register_clock_update_count;
        if (trace_needs_growth) try trace.reserveOne();
        if (access_needs_growth or gaps_need_growth)
            try tracker.reserveTransitions(required);
        if ((trace_needs_growth or access_needs_growth or gaps_need_growth) and
            (!self.runnerStateIsCurrent(cpu, trace) or
                !self.accessStateIsCurrent(tracker)))
        {
            return error.StaleRetirement;
        }
    }

    inline fn publishAssumeCapacity(
        self: *const Plan,
        cpu: *Cpu,
        trace: *Trace,
        tracker: *StateChainTracker,
    ) void {
        publishEventsAssumeCapacity(
            self.instruction,
            self.instruction_clock,
            self.rs1_value,
            self.rd_previous_value,
            self.rd_next_value,
            self.source_previous_clock,
            self.destination_previous_clock,
            self.source_gap_count,
            self.destination_gap_count,
            tracker,
        );
        cpu.writeReg(self.instruction.rd, self.rd_next_value);
        cpu.pc = self.next_pc;
        trace.appendAssumeCapacity(self.traceRow());
    }

    inline fn runnerStateIsCurrent(
        self: *const Plan,
        cpu: *const Cpu,
        trace: *const Trace,
    ) bool {
        return cpu.pc == self.pc_before and
            cpu.readReg(self.instruction.rs1) == self.rs1_value and
            cpu.readReg(self.instruction.rs2) == self.rs2_value and
            cpu.readReg(self.instruction.rd) == self.rd_previous_value and
            trace.rows.items.len == self.expected_trace_len and
            trace.step_count == self.expected_trace_len;
    }

    inline fn accessStateIsCurrent(
        self: *const Plan,
        tracker: *const StateChainTracker,
    ) bool {
        if (tracker.reg_last_clk[self.instruction.rs1] !=
            self.source_raw_previous_clock) return false;
        return self.instruction.rd == self.instruction.rs1 or
            tracker.reg_last_clk[self.instruction.rd] ==
                self.destination_raw_previous_clock;
    }

    fn isWellFormed(self: *const Plan) bool {
        if (self.instruction_clock == 0 or
            access_clock.maximum(self.instruction_clock) >=
                state_chain.CLOCK_PREV_BOUND)
        {
            return false;
        }
        const source_clock = access_clock.encode(
            self.instruction_clock,
            .first,
        );
        const destination_clock = access_clock.encode(
            self.instruction_clock,
            .second,
        );
        if (self.source_raw_previous_clock >= source_clock or
            self.destination_raw_previous_clock >= destination_clock)
        {
            return false;
        }
        const source_gap = deriveClockGap(
            self.source_raw_previous_clock,
            source_clock,
        );
        const destination_gap = deriveClockGap(
            self.destination_raw_previous_clock,
            destination_clock,
        );
        const aliased = self.instruction.rd == self.instruction.rs1;
        return instructionMatchesWord(self.instruction, self.inst_word) and
            traceClockMatches(self.expected_trace_len, self.instruction_clock) and
            typed_authority.acceptsRetirement(
                self.instruction,
                self.pc_before,
                self.rs1_value,
                self.rd_next_value,
                self.next_pc,
                self.branch_taken,
            ) and
            (self.instruction.rs1 != 0 or self.rs1_value == 0) and
            (self.instruction.rs2 != 0 or self.rs2_value == 0) and
            (self.instruction.rd != 0 or
                (self.rd_previous_value == 0 and self.rd_next_value == 0)) and
            (!aliased or self.rd_previous_value == self.rs1_value) and
            self.destination_raw_previous_clock ==
                (if (aliased) source_clock else self.destination_raw_previous_clock) and
            self.source_previous_clock == source_gap.previous_clock and
            self.source_gap_count == source_gap.update_count and
            self.destination_previous_clock == destination_gap.previous_clock and
            self.destination_gap_count == destination_gap.update_count;
    }
};

pub const Prepared = struct {
    plan: *const Plan,
    consumed: bool = false,

    pub fn commit(
        self: *Prepared,
        cpu: *Cpu,
        trace: *Trace,
        tracker: *StateChainTracker,
    ) CommitError!void {
        if (self.consumed) return error.AlreadyCommitted;
        if (!self.plan.isCurrentFor(cpu, trace, tracker))
            return error.StaleRetirement;
        self.plan.publishAssumeCapacity(cpu, trace, tracker);
        self.consumed = true;
    }
};

pub inline fn stage(
    authority: *const Authority,
    cpu: *const Cpu,
    trace: *const Trace,
    tracker: *const StateChainTracker,
    instruction: DecodedInst,
    inst_word: u32,
    instruction_clock: u32,
) StageError!Plan {
    if (trace.step_count != trace.rows.items.len)
        return error.TraceInvariantViolation;
    if (!traceClockMatches(trace.rows.items.len, instruction_clock))
        return error.InstructionClockMismatch;
    if (!instructionMatchesWord(instruction, inst_word))
        return error.InstructionWordMismatch;
    if (instruction_clock == 0 or
        access_clock.maximum(instruction_clock) >=
            state_chain.CLOCK_PREV_BOUND)
    {
        return error.ClockOutOfRange;
    }

    const rs1_value = cpu.readReg(instruction.rs1);
    const rs2_value = cpu.readReg(instruction.rs2);
    const rd_previous = cpu.readReg(instruction.rd);
    const retirement = try authority.retire(
        instruction,
        cpu.pc,
        rs1_value,
    );
    if ((instruction.rs1 == 0 and rs1_value != 0) or
        (instruction.rs2 == 0 and rs2_value != 0) or
        (instruction.rd == 0 and
            (rd_previous != 0 or retirement.visible_value != 0)))
    {
        return error.ZeroRegisterValue;
    }

    const source_clock = access_clock.encode(instruction_clock, .first);
    const destination_clock = access_clock.encode(instruction_clock, .second);
    const source_raw = tracker.reg_last_clk[instruction.rs1];
    if (source_raw >= source_clock) return error.NonIncreasingClock;
    const aliased = instruction.rd == instruction.rs1;
    const destination_raw = if (aliased)
        source_clock
    else
        tracker.reg_last_clk[instruction.rd];
    if (destination_raw >= destination_clock)
        return error.NonIncreasingClock;
    const source_gap = deriveClockGap(source_raw, source_clock);
    const destination_gap = deriveClockGap(destination_raw, destination_clock);

    return .{
        .instruction = instruction,
        .instruction_clock = instruction_clock,
        .pc_before = cpu.pc,
        .next_pc = retirement.next_pc,
        .inst_word = inst_word,
        .rs1_value = rs1_value,
        .rs2_value = rs2_value,
        .rd_previous_value = rd_previous,
        .rd_next_value = retirement.visible_value,
        .source_raw_previous_clock = source_raw,
        .source_previous_clock = source_gap.previous_clock,
        .destination_raw_previous_clock = destination_raw,
        .destination_previous_clock = destination_gap.previous_clock,
        .source_gap_count = source_gap.update_count,
        .destination_gap_count = destination_gap.update_count,
        .expected_trace_len = trace.rows.items.len,
        .branch_taken = retirement.branch_taken,
    };
}

/// Fused production path. It keeps the compact transaction in scalar locals
/// and publishes directly, avoiding a reusable Plan copy on every hot row.
pub inline fn retireAtomic(
    authority: *const Authority,
    cpu: *Cpu,
    trace: *Trace,
    tracker: *StateChainTracker,
    instruction: DecodedInst,
    inst_word: u32,
    instruction_clock: u32,
) RetireError!void {
    const plan = try stage(
        authority,
        cpu,
        trace,
        tracker,
        instruction,
        inst_word,
        instruction_clock,
    );
    if (comptime builtin.mode == .Debug)
        std.debug.assert(plan.isCurrentFor(cpu, trace, tracker));
    try plan.reserveAndRevalidate(cpu, trace, tracker);
    plan.publishAssumeCapacity(cpu, trace, tracker);
}

pub inline fn instructionMatchesWord(
    instruction: DecodedInst,
    inst_word: u32,
) bool {
    if (instruction.opcode != .JALR or
        instruction.imm < -2048 or
        instruction.imm > 2047)
    {
        return false;
    }
    const immediate: u32 = @bitCast(instruction.imm);
    const immediate_12 = immediate & 0xfff;
    const reconstructed = (immediate_12 << 20) |
        (@as(u32, instruction.rs1) << 15) |
        (@as(u32, instruction.rd) << 7) |
        0b1100111;
    return inst_word == reconstructed and
        instruction.rs2 == @as(u5, @truncate(immediate_12));
}

inline fn traceClockMatches(trace_len: usize, instruction_clock: u32) bool {
    if (trace_len >= std.math.maxInt(u32)) return false;
    return instruction_clock == @as(u32, @intCast(trace_len)) + 1;
}

const ClockGap = struct {
    previous_clock: u32,
    update_count: usize,
};

inline fn deriveClockGap(previous_clock: u32, current_clock: u32) ClockGap {
    std.debug.assert(previous_clock < current_clock);
    const updates = (current_clock - previous_clock - 1) /
        state_chain.MAX_CLOCK_DIFF;
    return .{
        .previous_clock = previous_clock + updates *
            state_chain.MAX_CLOCK_DIFF,
        .update_count = updates,
    };
}

inline fn publishEventsAssumeCapacity(
    instruction: DecodedInst,
    instruction_clock: u32,
    rs1_value: u32,
    rd_previous_value: u32,
    rd_next_value: u32,
    source_previous_clock: u32,
    destination_previous_clock: u32,
    source_gap_count: usize,
    destination_gap_count: usize,
    tracker: *StateChainTracker,
) void {
    const source_clock = access_clock.encode(instruction_clock, .first);
    if (source_gap_count == 0) {
        tracker.accesses.appendAssumeCapacity(.{
            .addr_space = 0,
            .addr = instruction.rs1,
            .clk = source_clock,
            .value = rs1_value,
            .clk_prev = source_previous_clock,
        });
        tracker.reg_last_clk[instruction.rs1] = source_clock;
    } else {
        tracker.recordRegTransitionAssumeCapacity(
            instruction.rs1,
            source_clock,
            rs1_value,
            rs1_value,
        );
    }

    const destination_clock = access_clock.encode(
        instruction_clock,
        .second,
    );
    if (destination_gap_count == 0) {
        tracker.accesses.appendAssumeCapacity(.{
            .addr_space = 0,
            .addr = instruction.rd,
            .clk = destination_clock,
            .value = rd_next_value,
            .clk_prev = destination_previous_clock,
        });
        tracker.reg_last_clk[instruction.rd] = destination_clock;
    } else {
        tracker.recordRegTransitionAssumeCapacity(
            instruction.rd,
            destination_clock,
            rd_previous_value,
            rd_next_value,
        );
    }
}

inline fn canonicalRow(plan: *const Plan) TraceRow {
    return .{
        .clk = plan.instruction_clock,
        .pc = plan.pc_before,
        .opcode = plan.instruction.opcode,
        .rd = plan.instruction.rd,
        .rs1 = plan.instruction.rs1,
        .rs2 = plan.instruction.rs2,
        .imm = plan.instruction.imm,
        .rs1_val = plan.rs1_value,
        .rs2_val = plan.rs2_value,
        .rs1_prev_clk = plan.source_previous_clock,
        .rs2_prev_clk = 0,
        .rd_prev_val = plan.rd_previous_value,
        .rd_prev_clk = plan.destination_previous_clock,
        .rd_val = plan.rd_next_value,
        .mem_addr = 0,
        .mem_val = 0,
        .mem_prev_word = 0,
        .mem_next_word = 0,
        .mem_prev_clk = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = plan.branch_taken,
        .next_pc = plan.next_pc,
        .inst_word = plan.inst_word,
    };
}

comptime {
    if (@sizeOf(Plan) > MAX_PLAN_BYTES)
        @compileError("typed JALR retirement plan exceeded its stack budget");
    if (@sizeOf(Prepared) > MAX_PREPARED_BYTES)
        @compileError("typed JALR prepared token exceeded its stack budget");
}
