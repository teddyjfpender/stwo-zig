//! Failure-atomic retirement for the typed RV32 BRANCH_LT authority.
//!
//! The fixed authority owns signed/unsigned comparison, taken/not-taken target
//! selection, program-address admission, witness, roots, and relations. This
//! boundary owns exact B-type word admission, ordered two-source predecessor
//! clocks, capacity preflight, and atomic PC/trace/state-chain publication.
//! The warm fused path allocates nothing.

const std = @import("std");
const builtin = @import("builtin");
const access_clock = @import("../access_clock.zig");
const typed_branch_lt = @import("../air/lang/typed_branch_lt.zig");
const typed_authority = @import("../air/lang/typed_branch_lt_authority.zig");
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

// Keep one small growth slot while rejecting accidental cache-footprint creep.
pub const MAX_PLAN_BYTES: usize = 96;
pub const MAX_PREPARED_BYTES: usize = 16;

pub const PINNED_AUTHORITY = Authority.pinned();

pub fn authenticateCanonical(allocator: std.mem.Allocator) !Authority {
    var definition = try typed_branch_lt.build(allocator, .generated);
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
    diagnostic_rd_value: u32,
    source_1_raw_previous_clock: u32,
    source_1_previous_clock: u32,
    source_2_raw_previous_clock: u32,
    source_2_previous_clock: u32,
    source_1_gap_count: usize,
    source_2_gap_count: usize,
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
            .register_clock_update_count = self.source_1_gap_count +
                self.source_2_gap_count,
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
            self.rs2_value,
            self.source_1_previous_clock,
            self.source_2_previous_clock,
            self.source_1_gap_count,
            self.source_2_gap_count,
            tracker,
        );
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
            cpu.readReg(self.instruction.rd) == self.diagnostic_rd_value and
            trace.rows.items.len == self.expected_trace_len and
            trace.step_count == self.expected_trace_len and
            trace.expectsNextCoreRetirement(self.instruction_clock);
    }

    inline fn accessStateIsCurrent(
        self: *const Plan,
        tracker: *const StateChainTracker,
    ) bool {
        if (tracker.reg_last_clk[self.instruction.rs1] !=
            self.source_1_raw_previous_clock) return false;
        return self.instruction.rs2 == self.instruction.rs1 or
            tracker.reg_last_clk[self.instruction.rs2] ==
                self.source_2_raw_previous_clock;
    }

    fn isWellFormed(self: *const Plan) bool {
        if (self.instruction_clock == 0 or
            access_clock.maximum(self.instruction_clock) >=
                state_chain.CLOCK_PREV_BOUND)
        {
            return false;
        }
        const source_1_clock = access_clock.encode(
            self.instruction_clock,
            .first,
        );
        const source_2_clock = access_clock.encode(
            self.instruction_clock,
            .second,
        );
        if (self.source_1_raw_previous_clock >= source_1_clock or
            self.source_2_raw_previous_clock >= source_2_clock)
        {
            return false;
        }
        const source_1_gap = deriveClockGap(
            self.source_1_raw_previous_clock,
            source_1_clock,
        );
        const source_2_gap = deriveClockGap(
            self.source_2_raw_previous_clock,
            source_2_clock,
        );
        const aliased = self.instruction.rs2 == self.instruction.rs1;
        return instructionMatchesWord(self.instruction, self.inst_word) and
            typed_authority.acceptsRetirement(
                self.instruction,
                self.pc_before,
                self.rs1_value,
                self.rs2_value,
                self.next_pc,
                self.branch_taken,
            ) and
            (self.instruction.rs1 != 0 or self.rs1_value == 0) and
            (self.instruction.rs2 != 0 or self.rs2_value == 0) and
            (self.instruction.rd != 0 or self.diagnostic_rd_value == 0) and
            (self.instruction.rd != self.instruction.rs1 or
                self.diagnostic_rd_value == self.rs1_value) and
            (self.instruction.rd != self.instruction.rs2 or
                self.diagnostic_rd_value == self.rs2_value) and
            (!aliased or self.rs2_value == self.rs1_value) and
            self.source_2_raw_previous_clock ==
                (if (aliased) source_1_clock else self.source_2_raw_previous_clock) and
            self.source_1_previous_clock == source_1_gap.previous_clock and
            self.source_1_gap_count == source_1_gap.update_count and
            self.source_2_previous_clock == source_2_gap.previous_clock and
            self.source_2_gap_count == source_2_gap.update_count;
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
    if (!trace.expectsNextCoreRetirement(instruction_clock))
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
    const diagnostic_rd_value = cpu.readReg(instruction.rd);
    const retirement = try authority.retire(
        instruction,
        cpu.pc,
        rs1_value,
        rs2_value,
    );
    if ((instruction.rs1 == 0 and rs1_value != 0) or
        (instruction.rs2 == 0 and rs2_value != 0) or
        (instruction.rd == 0 and diagnostic_rd_value != 0))
    {
        return error.ZeroRegisterValue;
    }

    const source_1_clock = access_clock.encode(instruction_clock, .first);
    const source_2_clock = access_clock.encode(instruction_clock, .second);
    const source_1_raw = tracker.reg_last_clk[instruction.rs1];
    if (source_1_raw >= source_1_clock) return error.NonIncreasingClock;
    const aliased = instruction.rs2 == instruction.rs1;
    const source_2_raw = if (aliased)
        source_1_clock
    else
        tracker.reg_last_clk[instruction.rs2];
    if (source_2_raw >= source_2_clock)
        return error.NonIncreasingClock;
    const source_1_gap = deriveClockGap(source_1_raw, source_1_clock);
    const source_2_gap = deriveClockGap(source_2_raw, source_2_clock);

    return .{
        .instruction = instruction,
        .instruction_clock = instruction_clock,
        .pc_before = cpu.pc,
        .next_pc = retirement.next_pc,
        .inst_word = inst_word,
        .rs1_value = rs1_value,
        .rs2_value = rs2_value,
        .diagnostic_rd_value = diagnostic_rd_value,
        .source_1_raw_previous_clock = source_1_raw,
        .source_1_previous_clock = source_1_gap.previous_clock,
        .source_2_raw_previous_clock = source_2_raw,
        .source_2_previous_clock = source_2_gap.previous_clock,
        .source_1_gap_count = source_1_gap.update_count,
        .source_2_gap_count = source_2_gap.update_count,
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
    if (!typed_authority.isFamilyOpcode(instruction.opcode) or
        instruction.imm < -4096 or instruction.imm > 4094 or
        (@as(u32, @bitCast(instruction.imm)) & 1) != 0)
    {
        return false;
    }
    const immediate_13 = @as(u32, @bitCast(instruction.imm)) & 0x1fff;
    const funct3: u32 = switch (instruction.opcode) {
        .BLT => 0b100,
        .BGE => 0b101,
        .BLTU => 0b110,
        .BGEU => 0b111,
        else => unreachable,
    };
    const reconstructed = ((immediate_13 >> 12) & 1) << 31 |
        ((immediate_13 >> 5) & 0x3f) << 25 |
        (@as(u32, instruction.rs2) << 20) |
        (@as(u32, instruction.rs1) << 15) |
        (funct3 << 12) |
        ((immediate_13 >> 1) & 0xf) << 8 |
        ((immediate_13 >> 11) & 1) << 7 |
        0b1100011;
    return inst_word == reconstructed and
        instruction.rd == @as(u5, @truncate(inst_word >> 7));
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
    rs2_value: u32,
    source_1_previous_clock: u32,
    source_2_previous_clock: u32,
    source_1_gap_count: usize,
    source_2_gap_count: usize,
    tracker: *StateChainTracker,
) void {
    const source_1_clock = access_clock.encode(instruction_clock, .first);
    if (source_1_gap_count == 0) {
        tracker.accesses.appendAssumeCapacity(.{
            .addr_space = 0,
            .addr = instruction.rs1,
            .clk = source_1_clock,
            .value = rs1_value,
            .clk_prev = source_1_previous_clock,
        });
        tracker.reg_last_clk[instruction.rs1] = source_1_clock;
    } else {
        tracker.recordRegTransitionAssumeCapacity(
            instruction.rs1,
            source_1_clock,
            rs1_value,
            rs1_value,
        );
    }

    const source_2_clock = access_clock.encode(
        instruction_clock,
        .second,
    );
    if (source_2_gap_count == 0) {
        tracker.accesses.appendAssumeCapacity(.{
            .addr_space = 0,
            .addr = instruction.rs2,
            .clk = source_2_clock,
            .value = rs2_value,
            .clk_prev = source_2_previous_clock,
        });
        tracker.reg_last_clk[instruction.rs2] = source_2_clock;
    } else {
        tracker.recordRegTransitionAssumeCapacity(
            instruction.rs2,
            source_2_clock,
            rs2_value,
            rs2_value,
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
        .rs1_prev_clk = plan.source_1_previous_clock,
        .rs2_prev_clk = plan.source_2_previous_clock,
        .rd_prev_val = plan.diagnostic_rd_value,
        .rd_prev_clk = 0,
        .rd_val = plan.diagnostic_rd_value,
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

test "typed BRANCH_LT retirement closed-form gap geometry equals tracker authority" {
    const cases = [_]struct { previous: u32, current: u32 }{
        .{ .previous = 0, .current = 1 },
        .{ .previous = 0, .current = state_chain.MAX_CLOCK_DIFF },
        .{ .previous = 0, .current = state_chain.MAX_CLOCK_DIFF + 1 },
        .{ .previous = 7, .current = 7 + state_chain.MAX_CLOCK_DIFF * 3 + 1 },
        .{ .previous = 1, .current = state_chain.CLOCK_PREV_BOUND - 1 },
    };
    for (cases) |case| {
        const gap = deriveClockGap(case.previous, case.current);
        try std.testing.expectEqual(
            StateChainTracker.effectivePreviousClock(
                case.previous,
                case.current,
            ),
            gap.previous_clock,
        );
        try std.testing.expectEqual(
            StateChainTracker.clockGapCount(case.previous, case.current),
            gap.update_count,
        );
        try std.testing.expect(gap.previous_clock < case.current);
        try std.testing.expect(
            case.current - gap.previous_clock <= state_chain.MAX_CLOCK_DIFF,
        );
    }
}

comptime {
    if (@sizeOf(Plan) > MAX_PLAN_BYTES)
        @compileError("typed BRANCH_LT retirement plan exceeded its stack budget");
    if (@sizeOf(Prepared) > MAX_PREPARED_BYTES)
        @compileError("typed BRANCH_LT prepared token exceeded its stack budget");
}
