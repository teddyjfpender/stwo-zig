//! Failure-atomic retirement for the typed RV32 SLT/SLTU authority.
//!
//! The fixed authority is the sole comparison-result and x0 authority. This
//! family-local three-event compiler owns rs1/rs2/rd alias and predecessor-
//! clock geometry. Staging is allocation-free, preparation reserves every
//! fallible destination, and publication cannot expose a partial retirement.

const std = @import("std");
const builtin = @import("builtin");
const access_clock = @import("../access_clock.zig");
const typed = @import("../air/lang/typed_lt_reg.zig");
const typed_authority = @import("../air/lang/typed_lt_reg_authority.zig");
const Cpu = @import("cpu.zig").Cpu;
const state_chain = @import("state_chain.zig");
const trace_mod = @import("trace.zig");

pub const StateChainTracker = state_chain.StateChainTracker;
pub const Trace = trace_mod.Trace;
pub const TraceRow = trace_mod.TraceRow;
pub const DecodedInst = typed_authority.DecodedInst;
pub const Authority = typed_authority.Authority;

pub const CompileError = error{
    AliasedRegisterValueMismatch,
    ClockOutOfRange,
    InvalidLtRegImmediate,
    NonIncreasingClock,
    WrongLtRegOpcode,
    ZeroRegisterValue,
};
pub const StageError = CompileError || error{
    InstructionClockMismatch,
    InstructionWordMismatch,
    TraceInvariantViolation,
};
pub const PrepareError = error{ OutOfMemory, StaleRetirement };
pub const CommitError = error{ AlreadyCommitted, StaleRetirement };
pub const RetireError = StageError || PrepareError;

// One natural word of headroom catches accidental hot-stack footprint creep.
pub const MAX_TRANSACTION_BYTES: usize = 88;
pub const MAX_PLAN_BYTES: usize = 104;
pub const MAX_PREPARED_BYTES: usize = 16;

pub const PINNED_AUTHORITY = Authority.pinned();

pub fn authenticateCanonical(allocator: std.mem.Allocator) !Authority {
    var definition = try typed.build(allocator, .generated);
    defer definition.deinit();
    const binding = try typed_authority.Binding.canonical(&definition);
    return typed_authority.Authority.init(&definition, &binding);
}

/// Complete immutable projection of the three architectural accesses. Raw
/// clocks authenticate the tracker snapshot; effective clocks are committed to
/// the AIR row after any bounded synthetic gaps.
pub const CompactTransaction = struct {
    instruction: DecodedInst,
    instruction_clock: u32,
    rs1_value: u32,
    rs2_value: u32,
    rd_previous_value: u32,
    rd_next_value: u32,
    source_1_raw_previous_clock: u32,
    source_1_previous_clock: u32,
    source_2_raw_previous_clock: u32,
    source_2_previous_clock: u32,
    destination_raw_previous_clock: u32,
    destination_previous_clock: u32,
    source_1_gap_count: usize,
    source_2_gap_count: usize,
    destination_gap_count: usize,
};

pub const CompactInput = struct {
    instruction: DecodedInst,
    instruction_clock: u32,
    rs1_value: u32,
    rs2_value: u32,
    rd_previous_value: u32,
};

/// Compile semantic, alias, x0, and clock facts without allocation or mutation.
pub inline fn compileCompact(
    authority: *const Authority,
    tracker: *const StateChainTracker,
    input: CompactInput,
) CompileError!CompactTransaction {
    const retirement = authority.retire(
        input.instruction,
        input.rs1_value,
        input.rs2_value,
    ) catch |err| return switch (err) {
        error.WrongLtRegOpcode => error.WrongLtRegOpcode,
        error.InvalidImmediate => error.InvalidLtRegImmediate,
    };
    if (input.instruction_clock == 0 or
        access_clock.maximum(input.instruction_clock) >= state_chain.CLOCK_PREV_BOUND)
    {
        return error.ClockOutOfRange;
    }
    if ((input.instruction.rs1 == 0 and input.rs1_value != 0) or
        (input.instruction.rs2 == 0 and input.rs2_value != 0) or
        (input.instruction.rd == 0 and
            (input.rd_previous_value != 0 or retirement.visible_value != 0)))
    {
        return error.ZeroRegisterValue;
    }

    const source_1_clock = access_clock.encode(input.instruction_clock, .first);
    const source_1_raw = tracker.reg_last_clk[input.instruction.rs1];
    if (source_1_raw >= source_1_clock) return error.NonIncreasingClock;

    const sources_alias = input.instruction.rs2 == input.instruction.rs1;
    if (sources_alias and input.rs2_value != input.rs1_value)
        return error.AliasedRegisterValueMismatch;
    const source_2_clock = access_clock.encode(input.instruction_clock, .second);
    const source_2_raw = if (sources_alias)
        source_1_clock
    else
        tracker.reg_last_clk[input.instruction.rs2];
    if (source_2_raw >= source_2_clock) return error.NonIncreasingClock;

    const destination_aliases_source_2 = input.instruction.rd == input.instruction.rs2;
    const destination_aliases_source_1 = input.instruction.rd == input.instruction.rs1;
    const expected_destination_previous = if (destination_aliases_source_2)
        input.rs2_value
    else if (destination_aliases_source_1)
        input.rs1_value
    else
        input.rd_previous_value;
    if ((destination_aliases_source_1 or destination_aliases_source_2) and
        input.rd_previous_value != expected_destination_previous)
    {
        return error.AliasedRegisterValueMismatch;
    }
    const destination_clock = access_clock.encode(input.instruction_clock, .third);
    const destination_raw = if (destination_aliases_source_2)
        source_2_clock
    else if (destination_aliases_source_1)
        source_1_clock
    else
        tracker.reg_last_clk[input.instruction.rd];
    if (destination_raw >= destination_clock) return error.NonIncreasingClock;

    return .{
        .instruction = input.instruction,
        .instruction_clock = input.instruction_clock,
        .rs1_value = input.rs1_value,
        .rs2_value = input.rs2_value,
        .rd_previous_value = input.rd_previous_value,
        .rd_next_value = retirement.visible_value,
        .source_1_raw_previous_clock = source_1_raw,
        .source_1_previous_clock = StateChainTracker.effectivePreviousClock(
            source_1_raw,
            source_1_clock,
        ),
        .source_2_raw_previous_clock = source_2_raw,
        .source_2_previous_clock = StateChainTracker.effectivePreviousClock(
            source_2_raw,
            source_2_clock,
        ),
        .destination_raw_previous_clock = destination_raw,
        .destination_previous_clock = StateChainTracker.effectivePreviousClock(
            destination_raw,
            destination_clock,
        ),
        .source_1_gap_count = StateChainTracker.clockGapCount(
            source_1_raw,
            source_1_clock,
        ),
        .source_2_gap_count = StateChainTracker.clockGapCount(
            source_2_raw,
            source_2_clock,
        ),
        .destination_gap_count = StateChainTracker.clockGapCount(
            destination_raw,
            destination_clock,
        ),
    };
}

pub const Plan = struct {
    instruction: DecodedInst,
    instruction_clock: u32,
    pc_before: u32,
    inst_word: u32,
    rs1_value: u32,
    rs2_value: u32,
    rd_previous_value: u32,
    rd_next_value: u32,
    source_1_raw_previous_clock: u32,
    source_1_previous_clock: u32,
    source_2_raw_previous_clock: u32,
    source_2_previous_clock: u32,
    destination_raw_previous_clock: u32,
    destination_previous_clock: u32,
    source_1_gap_count: usize,
    source_2_gap_count: usize,
    destination_gap_count: usize,
    expected_trace_len: usize,

    pub inline fn traceRow(self: *const Plan) TraceRow {
        return canonicalRow(self);
    }

    pub inline fn reservation(self: *const Plan) StateChainTracker.Reservation {
        return .{
            .memory_address_count = 0,
            .access_count = 3,
            .memory_clock_update_count = 0,
            .register_clock_update_count = self.source_1_gap_count +
                self.source_2_gap_count + self.destination_gap_count,
        };
    }

    pub fn isCurrentFor(
        self: *const Plan,
        cpu: *const Cpu,
        exec_trace: *const Trace,
        tracker: *const StateChainTracker,
    ) bool {
        return self.isWellFormed() and self.runnerStateIsCurrent(cpu, exec_trace) and
            self.accessStateIsCurrent(tracker);
    }

    pub fn prepare(
        self: *const Plan,
        cpu: *const Cpu,
        exec_trace: *Trace,
        tracker: *StateChainTracker,
    ) PrepareError!Prepared {
        if (!self.isCurrentFor(cpu, exec_trace, tracker)) return error.StaleRetirement;
        try self.reserveAndRevalidate(cpu, exec_trace, tracker);
        return .{ .plan = self };
    }

    pub fn commitAtomic(
        self: *const Plan,
        cpu: *Cpu,
        exec_trace: *Trace,
        tracker: *StateChainTracker,
    ) PrepareError!void {
        if (!self.isCurrentFor(cpu, exec_trace, tracker)) return error.StaleRetirement;
        try self.reserveAndRevalidate(cpu, exec_trace, tracker);
        self.publishAssumeCapacity(cpu, exec_trace, tracker);
    }

    fn reserveAndRevalidate(
        self: *const Plan,
        cpu: *const Cpu,
        exec_trace: *Trace,
        tracker: *StateChainTracker,
    ) PrepareError!void {
        const trace_needs_growth = exec_trace.rows.capacity - exec_trace.rows.items.len < 1;
        const required = self.reservation();
        const access_needs_growth = tracker.accesses.capacity - tracker.accesses.items.len <
            required.access_count;
        const gaps_need_growth = tracker.clock_updates_reg.capacity -
            tracker.clock_updates_reg.items.len < required.register_clock_update_count;
        if (trace_needs_growth) try exec_trace.reserveOne();
        if (access_needs_growth or gaps_need_growth) try tracker.reserveTransitions(required);
        if ((trace_needs_growth or access_needs_growth or gaps_need_growth) and
            (!self.runnerStateIsCurrent(cpu, exec_trace) or
                !self.accessStateIsCurrent(tracker)))
        {
            return error.StaleRetirement;
        }
    }

    inline fn publishAssumeCapacity(
        self: *const Plan,
        cpu: *Cpu,
        exec_trace: *Trace,
        tracker: *StateChainTracker,
    ) void {
        tracker.recordRegTransitionAssumeCapacity(
            self.instruction.rs1,
            access_clock.encode(self.instruction_clock, .first),
            self.rs1_value,
            self.rs1_value,
        );
        tracker.recordRegTransitionAssumeCapacity(
            self.instruction.rs2,
            access_clock.encode(self.instruction_clock, .second),
            self.rs2_value,
            self.rs2_value,
        );
        tracker.recordRegTransitionAssumeCapacity(
            self.instruction.rd,
            access_clock.encode(self.instruction_clock, .third),
            self.rd_previous_value,
            self.rd_next_value,
        );
        cpu.writeReg(self.instruction.rd, self.rd_next_value);
        const row = self.traceRow();
        cpu.pc = row.next_pc;
        exec_trace.appendAssumeCapacity(row);
    }

    inline fn runnerStateIsCurrent(
        self: *const Plan,
        cpu: *const Cpu,
        exec_trace: *const Trace,
    ) bool {
        return cpu.pc == self.pc_before and
            cpu.readReg(self.instruction.rs1) == self.rs1_value and
            cpu.readReg(self.instruction.rs2) == self.rs2_value and
            cpu.readReg(self.instruction.rd) == self.rd_previous_value and
            exec_trace.rows.items.len == self.expected_trace_len and
            exec_trace.step_count == self.expected_trace_len and
            exec_trace.expectsNextCoreRetirement(self.instruction_clock);
    }

    inline fn accessStateIsCurrent(
        self: *const Plan,
        tracker: *const StateChainTracker,
    ) bool {
        if (tracker.reg_last_clk[self.instruction.rs1] !=
            self.source_1_raw_previous_clock) return false;
        if (self.instruction.rs2 != self.instruction.rs1 and
            tracker.reg_last_clk[self.instruction.rs2] !=
                self.source_2_raw_previous_clock) return false;
        return self.instruction.rd == self.instruction.rs1 or
            self.instruction.rd == self.instruction.rs2 or
            tracker.reg_last_clk[self.instruction.rd] ==
                self.destination_raw_previous_clock;
    }

    fn isWellFormed(self: *const Plan) bool {
        const source_1_clock = access_clock.encode(self.instruction_clock, .first);
        const source_2_clock = access_clock.encode(self.instruction_clock, .second);
        const destination_clock = access_clock.encode(self.instruction_clock, .third);
        const sources_alias = self.instruction.rs2 == self.instruction.rs1;
        const destination_aliases_source_2 = self.instruction.rd == self.instruction.rs2;
        const destination_aliases_source_1 = self.instruction.rd == self.instruction.rs1;
        const expected_destination_raw = if (destination_aliases_source_2)
            source_2_clock
        else if (destination_aliases_source_1)
            source_1_clock
        else
            self.destination_raw_previous_clock;
        const expected_destination_value = if (destination_aliases_source_2)
            self.rs2_value
        else if (destination_aliases_source_1)
            self.rs1_value
        else
            self.rd_previous_value;
        return instructionMatchesWord(self.instruction, self.inst_word) and
            self.instruction_clock != 0 and
            access_clock.maximum(self.instruction_clock) < state_chain.CLOCK_PREV_BOUND and
            typed_authority.acceptsRetirement(
                self.instruction,
                self.rs1_value,
                self.rs2_value,
                self.rd_next_value,
            ) and
            (self.instruction.rs1 != 0 or self.rs1_value == 0) and
            (self.instruction.rs2 != 0 or self.rs2_value == 0) and
            (self.instruction.rd != 0 or
                (self.rd_previous_value == 0 and self.rd_next_value == 0)) and
            self.source_1_raw_previous_clock < source_1_clock and
            self.source_1_previous_clock == StateChainTracker.effectivePreviousClock(
                self.source_1_raw_previous_clock,
                source_1_clock,
            ) and
            self.source_1_gap_count == StateChainTracker.clockGapCount(
                self.source_1_raw_previous_clock,
                source_1_clock,
            ) and
            (!sources_alias or
                (self.rs2_value == self.rs1_value and
                    self.source_2_raw_previous_clock == source_1_clock)) and
            self.source_2_raw_previous_clock < source_2_clock and
            self.source_2_previous_clock == StateChainTracker.effectivePreviousClock(
                self.source_2_raw_previous_clock,
                source_2_clock,
            ) and
            self.source_2_gap_count == StateChainTracker.clockGapCount(
                self.source_2_raw_previous_clock,
                source_2_clock,
            ) and
            self.destination_raw_previous_clock == expected_destination_raw and
            self.rd_previous_value == expected_destination_value and
            self.destination_raw_previous_clock < destination_clock and
            self.destination_previous_clock == StateChainTracker.effectivePreviousClock(
                self.destination_raw_previous_clock,
                destination_clock,
            ) and
            self.destination_gap_count == StateChainTracker.clockGapCount(
                self.destination_raw_previous_clock,
                destination_clock,
            );
    }
};

pub const Prepared = struct {
    plan: *const Plan,
    consumed: bool = false,

    pub fn commit(
        self: *Prepared,
        cpu: *Cpu,
        exec_trace: *Trace,
        tracker: *StateChainTracker,
    ) CommitError!void {
        if (self.consumed) return error.AlreadyCommitted;
        if (!self.plan.isCurrentFor(cpu, exec_trace, tracker))
            return error.StaleRetirement;
        self.plan.publishAssumeCapacity(cpu, exec_trace, tracker);
        self.consumed = true;
    }
};

pub fn stage(
    authority: *const Authority,
    cpu: *const Cpu,
    exec_trace: *const Trace,
    tracker: *const StateChainTracker,
    instruction: DecodedInst,
    inst_word: u32,
    instruction_clock: u32,
) StageError!Plan {
    if (exec_trace.step_count != exec_trace.rows.items.len)
        return error.TraceInvariantViolation;
    if (!exec_trace.expectsNextCoreRetirement(instruction_clock))
        return error.InstructionClockMismatch;
    if (!instructionMatchesWord(instruction, inst_word))
        return error.InstructionWordMismatch;
    const rs1_value = cpu.readReg(instruction.rs1);
    const rs2_value = cpu.readReg(instruction.rs2);
    const rd_previous_value = cpu.readReg(instruction.rd);
    const transaction = try compileCompact(authority, tracker, .{
        .instruction = instruction,
        .instruction_clock = instruction_clock,
        .rs1_value = rs1_value,
        .rs2_value = rs2_value,
        .rd_previous_value = rd_previous_value,
    });
    return .{
        .instruction = instruction,
        .instruction_clock = instruction_clock,
        .pc_before = cpu.pc,
        .inst_word = inst_word,
        .rs1_value = rs1_value,
        .rs2_value = rs2_value,
        .rd_previous_value = rd_previous_value,
        .rd_next_value = transaction.rd_next_value,
        .source_1_raw_previous_clock = transaction.source_1_raw_previous_clock,
        .source_1_previous_clock = transaction.source_1_previous_clock,
        .source_2_raw_previous_clock = transaction.source_2_raw_previous_clock,
        .source_2_previous_clock = transaction.source_2_previous_clock,
        .destination_raw_previous_clock = transaction.destination_raw_previous_clock,
        .destination_previous_clock = transaction.destination_previous_clock,
        .source_1_gap_count = transaction.source_1_gap_count,
        .source_2_gap_count = transaction.source_2_gap_count,
        .destination_gap_count = transaction.destination_gap_count,
        .expected_trace_len = exec_trace.rows.items.len,
    };
}

pub inline fn retireAtomic(
    authority: *const Authority,
    cpu: *Cpu,
    exec_trace: *Trace,
    tracker: *StateChainTracker,
    instruction: DecodedInst,
    inst_word: u32,
    instruction_clock: u32,
) RetireError!void {
    const plan = try stage(
        authority,
        cpu,
        exec_trace,
        tracker,
        instruction,
        inst_word,
        instruction_clock,
    );
    if (comptime builtin.mode == .Debug)
        std.debug.assert(plan.isCurrentFor(cpu, exec_trace, tracker));
    try plan.reserveAndRevalidate(cpu, exec_trace, tracker);
    plan.publishAssumeCapacity(cpu, exec_trace, tracker);
}

inline fn instructionMatchesWord(instruction: DecodedInst, inst_word: u32) bool {
    const funct3: u3 = switch (instruction.opcode) {
        .SLT => 0b010,
        .SLTU => 0b011,
        else => return false,
    };
    const reconstructed = (@as(u32, instruction.rs2) << 20) |
        (@as(u32, instruction.rs1) << 15) |
        (@as(u32, funct3) << 12) |
        (@as(u32, instruction.rd) << 7) |
        0b0110011;
    return instruction.imm == 0 and inst_word == reconstructed;
}

inline fn canonicalRow(plan: *const Plan) TraceRow {
    return .{
        .clk = plan.instruction_clock,
        .pc = plan.pc_before,
        .opcode = plan.instruction.opcode,
        .rd = plan.instruction.rd,
        .rs1 = plan.instruction.rs1,
        .rs2 = plan.instruction.rs2,
        .imm = 0,
        .rs1_val = plan.rs1_value,
        .rs2_val = plan.rs2_value,
        .rs1_prev_clk = plan.source_1_previous_clock,
        .rs2_prev_clk = plan.source_2_previous_clock,
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
        .branch_taken = false,
        .next_pc = plan.pc_before +% 4,
        .inst_word = plan.inst_word,
    };
}

comptime {
    if (@sizeOf(CompactTransaction) > MAX_TRANSACTION_BYTES)
        @compileError("typed LT_REG compact transaction exceeded its stack budget");
    if (@sizeOf(Plan) > MAX_PLAN_BYTES)
        @compileError("typed LT_REG retirement plan exceeded its stack budget");
    if (@sizeOf(Prepared) > MAX_PREPARED_BYTES)
        @compileError("typed LT_REG prepared token exceeded its stack budget");
}
