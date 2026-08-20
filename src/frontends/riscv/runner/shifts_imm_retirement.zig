//! Failure-atomic retirement for typed RV32 SLLI/SRLI/SRAI.
//!
//! The fixed typed authority owns shift semantics, x0 result visibility,
//! witness projection, roots, and ordered relations. This family-local
//! boundary owns exact shift-I word admission, ordered rs1/rd predecessor
//! clocks, capacity preflight, and atomic CPU/trace/state-chain publication.
//! Staging and the warm fused path allocate nothing.

const std = @import("std");
const builtin = @import("builtin");
const access_clock = @import("../access_clock.zig");
const typed = @import("../air/lang/typed_shifts_imm.zig");
const typed_authority = @import("../air/lang/typed_shifts_imm_authority.zig");
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
    InvalidShiftAmount,
    NonIncreasingClock,
    WrongShiftsImmOpcode,
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

// One natural word of growth budget catches accidental cache-footprint creep.
pub const MAX_TRANSACTION_BYTES: usize = 72;
pub const MAX_PLAN_BYTES: usize = 88;
pub const MAX_PREPARED_BYTES: usize = 16;

pub const PINNED_AUTHORITY = Authority.pinned();

pub fn authenticateCanonical(allocator: std.mem.Allocator) !Authority {
    var definition = try typed.build(allocator, .generated);
    defer definition.deinit();
    const binding = try typed_authority.Binding.canonical(&definition);
    return typed_authority.Authority.init(&definition, &binding);
}

pub const CompactInput = struct {
    instruction: DecodedInst,
    instruction_clock: u32,
    rs1_value: u32,
    rs2_diagnostic_value: u32,
    rd_previous_value: u32,
};

/// Pointer-free two-register transaction compiled without allocation or
/// mutation. Raw clocks authenticate the snapshot; effective clocks are the
/// values committed after any synthetic gap rows.
pub const CompactTransaction = struct {
    instruction: DecodedInst,
    instruction_clock: u32,
    rs1_value: u32,
    rs2_diagnostic_value: u32,
    rd_previous_value: u32,
    rd_next_value: u32,
    source_raw_previous_clock: u32,
    source_previous_clock: u32,
    destination_raw_previous_clock: u32,
    destination_previous_clock: u32,
    source_gap_count: usize,
    destination_gap_count: usize,
};

pub inline fn compileCompact(
    authority: *const Authority,
    tracker: *const StateChainTracker,
    input: CompactInput,
) CompileError!CompactTransaction {
    const retirement = authority.retire(
        input.instruction,
        input.rs1_value,
    ) catch |err| return switch (err) {
        error.WrongShiftsImmOpcode => error.WrongShiftsImmOpcode,
        error.InvalidShiftAmount => error.InvalidShiftAmount,
    };
    if (input.instruction_clock == 0 or
        access_clock.maximum(input.instruction_clock) >=
            state_chain.CLOCK_PREV_BOUND)
    {
        return error.ClockOutOfRange;
    }
    if ((input.instruction.rs1 == 0 and input.rs1_value != 0) or
        (input.instruction.rs2 == 0 and input.rs2_diagnostic_value != 0) or
        (input.instruction.rd == 0 and
            (input.rd_previous_value != 0 or retirement.visible_value != 0)))
    {
        return error.ZeroRegisterValue;
    }
    if ((input.instruction.rs2 == input.instruction.rs1 and
        input.rs2_diagnostic_value != input.rs1_value) or
        (input.instruction.rs2 == input.instruction.rd and
            input.rs2_diagnostic_value != input.rd_previous_value) or
        (input.instruction.rd == input.instruction.rs1 and
            input.rd_previous_value != input.rs1_value))
    {
        return error.AliasedRegisterValueMismatch;
    }

    const source_clock = access_clock.encode(input.instruction_clock, .first);
    const source_raw = tracker.reg_last_clk[input.instruction.rs1];
    if (source_raw >= source_clock) return error.NonIncreasingClock;
    const aliased = input.instruction.rd == input.instruction.rs1;
    const destination_clock = access_clock.encode(
        input.instruction_clock,
        .second,
    );
    const destination_raw = if (aliased)
        source_clock
    else
        tracker.reg_last_clk[input.instruction.rd];
    if (destination_raw >= destination_clock)
        return error.NonIncreasingClock;
    const source_gap = deriveClockGap(source_raw, source_clock);
    const destination_gap = deriveClockGap(destination_raw, destination_clock);

    return .{
        .instruction = input.instruction,
        .instruction_clock = input.instruction_clock,
        .rs1_value = input.rs1_value,
        .rs2_diagnostic_value = input.rs2_diagnostic_value,
        .rd_previous_value = input.rd_previous_value,
        .rd_next_value = retirement.visible_value,
        .source_raw_previous_clock = source_raw,
        .source_previous_clock = source_gap.previous_clock,
        .destination_raw_previous_clock = destination_raw,
        .destination_previous_clock = destination_gap.previous_clock,
        .source_gap_count = source_gap.update_count,
        .destination_gap_count = destination_gap.update_count,
    };
}

pub const Plan = struct {
    instruction: DecodedInst,
    instruction_clock: u32,
    pc_before: u32,
    inst_word: u32,
    rs1_value: u32,
    rs2_diagnostic_value: u32,
    rd_previous_value: u32,
    rd_next_value: u32,
    source_raw_previous_clock: u32,
    source_previous_clock: u32,
    destination_raw_previous_clock: u32,
    destination_previous_clock: u32,
    source_gap_count: usize,
    destination_gap_count: usize,
    expected_trace_len: usize,

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
        const trace_needs_growth = trace.rows.capacity - trace.rows.items.len < 1;
        const required = self.reservation();
        const access_needs_growth = tracker.accesses.capacity -
            tracker.accesses.items.len < required.access_count;
        const gaps_needs_growth = tracker.clock_updates_reg.capacity -
            tracker.clock_updates_reg.items.len <
            required.register_clock_update_count;
        if (trace_needs_growth) try trace.reserveOne();
        if (access_needs_growth or gaps_needs_growth)
            try tracker.reserveTransitions(required);
        if ((trace_needs_growth or access_needs_growth or gaps_needs_growth) and
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
        publishRegAssumeCapacity(
            self.instruction.rs1,
            access_clock.encode(self.instruction_clock, .first),
            self.rs1_value,
            self.rs1_value,
            self.source_previous_clock,
            self.source_gap_count,
            tracker,
        );
        publishRegAssumeCapacity(
            self.instruction.rd,
            access_clock.encode(self.instruction_clock, .second),
            self.rd_previous_value,
            self.rd_next_value,
            self.destination_previous_clock,
            self.destination_gap_count,
            tracker,
        );
        cpu.writeReg(self.instruction.rd, self.rd_next_value);
        cpu.pc = self.pc_before +% 4;
        trace.appendAssumeCapacity(self.traceRow());
    }

    inline fn runnerStateIsCurrent(
        self: *const Plan,
        cpu: *const Cpu,
        trace: *const Trace,
    ) bool {
        return cpu.pc == self.pc_before and
            cpu.readReg(self.instruction.rs1) == self.rs1_value and
            cpu.readReg(self.instruction.rs2) == self.rs2_diagnostic_value and
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
        const source_clock = access_clock.encode(self.instruction_clock, .first);
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
                self.rs1_value,
                self.rd_next_value,
            ) and
            (self.instruction.rs1 != 0 or self.rs1_value == 0) and
            (self.instruction.rs2 != 0 or self.rs2_diagnostic_value == 0) and
            (self.instruction.rd != 0 or
                (self.rd_previous_value == 0 and self.rd_next_value == 0)) and
            (self.instruction.rs2 != self.instruction.rs1 or
                self.rs2_diagnostic_value == self.rs1_value) and
            (self.instruction.rs2 != self.instruction.rd or
                self.rs2_diagnostic_value == self.rd_previous_value) and
            (!aliased or
                (self.rd_previous_value == self.rs1_value and
                    self.destination_raw_previous_clock == source_clock)) and
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

    const transaction = try compileCompact(authority, tracker, .{
        .instruction = instruction,
        .instruction_clock = instruction_clock,
        .rs1_value = cpu.readReg(instruction.rs1),
        .rs2_diagnostic_value = cpu.readReg(instruction.rs2),
        .rd_previous_value = cpu.readReg(instruction.rd),
    });
    return .{
        .instruction = transaction.instruction,
        .instruction_clock = transaction.instruction_clock,
        .pc_before = cpu.pc,
        .inst_word = inst_word,
        .rs1_value = transaction.rs1_value,
        .rs2_diagnostic_value = transaction.rs2_diagnostic_value,
        .rd_previous_value = transaction.rd_previous_value,
        .rd_next_value = transaction.rd_next_value,
        .source_raw_previous_clock = transaction.source_raw_previous_clock,
        .source_previous_clock = transaction.source_previous_clock,
        .destination_raw_previous_clock = transaction.destination_raw_previous_clock,
        .destination_previous_clock = transaction.destination_previous_clock,
        .source_gap_count = transaction.source_gap_count,
        .destination_gap_count = transaction.destination_gap_count,
        .expected_trace_len = trace.rows.items.len,
    };
}

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

/// Admit the funct7/funct3 pair and every generic decoder field. For shift-I,
/// both `imm` and the generic `rs2` diagnostic are the five-bit shift amount.
pub inline fn instructionMatchesWord(
    instruction: DecodedInst,
    inst_word: u32,
) bool {
    const shape = switch (instruction.opcode) {
        .SLLI => .{ @as(u32, 0b001), @as(u32, 0b0000000) },
        .SRLI => .{ @as(u32, 0b101), @as(u32, 0b0000000) },
        .SRAI => .{ @as(u32, 0b101), @as(u32, 0b0100000) },
        else => return false,
    };
    if (instruction.imm < 0 or instruction.imm > 31) return false;
    const amount: u32 = @intCast(instruction.imm);
    const reconstructed = (shape[1] << 25) |
        (amount << 20) |
        (@as(u32, instruction.rs1) << 15) |
        (shape[0] << 12) |
        (@as(u32, instruction.rd) << 7) |
        0b0010011;
    return instruction.rs2 == @as(u5, @intCast(amount)) and
        inst_word == reconstructed;
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

inline fn publishRegAssumeCapacity(
    register: u5,
    current_clock: u32,
    previous_value: u32,
    next_value: u32,
    previous_clock: u32,
    gap_count: usize,
    tracker: *StateChainTracker,
) void {
    if (gap_count == 0) {
        tracker.accesses.appendAssumeCapacity(.{
            .addr_space = 0,
            .addr = register,
            .clk = current_clock,
            .value = next_value,
            .clk_prev = previous_clock,
        });
        tracker.reg_last_clk[register] = current_clock;
    } else {
        tracker.recordRegTransitionAssumeCapacity(
            register,
            current_clock,
            previous_value,
            next_value,
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
        .rs2_val = plan.rs2_diagnostic_value,
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
        .branch_taken = false,
        .next_pc = plan.pc_before +% 4,
        .inst_word = plan.inst_word,
    };
}

test "SHIFTS_IMM closed-form clock gaps equal state-chain geometry" {
    const boundaries = [_][2]u32{
        .{ 0, 1 },
        .{ 0, state_chain.MAX_CLOCK_DIFF },
        .{ 0, state_chain.MAX_CLOCK_DIFF + 1 },
        .{ 7, 7 + state_chain.MAX_CLOCK_DIFF * 3 + 1 },
        .{ 1, state_chain.CLOCK_PREV_BOUND - 1 },
    };
    for (boundaries) |pair| {
        const actual = deriveClockGap(pair[0], pair[1]);
        try std.testing.expectEqual(
            StateChainTracker.effectivePreviousClock(pair[0], pair[1]),
            actual.previous_clock,
        );
        try std.testing.expectEqual(
            StateChainTracker.clockGapCount(pair[0], pair[1]),
            actual.update_count,
        );
    }
}

comptime {
    if (@sizeOf(CompactTransaction) > MAX_TRANSACTION_BYTES)
        @compileError("typed SHIFTS_IMM compact transaction exceeded its stack budget");
    if (@sizeOf(Plan) > MAX_PLAN_BYTES)
        @compileError("typed SHIFTS_IMM retirement plan exceeded its stack budget");
    if (@sizeOf(Prepared) > MAX_PREPARED_BYTES)
        @compileError("typed SHIFTS_IMM prepared token exceeded its stack budget");
}
