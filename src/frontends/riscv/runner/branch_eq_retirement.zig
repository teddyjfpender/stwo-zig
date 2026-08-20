//! Failure-atomic retirement for typed RV32 BEQ/BNE.
//!
//! The authenticated authority is the sole owner of comparison, branch
//! selection, target admission, witness projection, direct roots, and ordered
//! relations. This family-local boundary owns exact B-type word admission,
//! two read-only register predecessors, capacity preflight, and atomic CPU,
//! trace, and state-chain publication. The warm fused path allocates nothing.

const std = @import("std");
const builtin = @import("builtin");
const access_clock = @import("../access_clock.zig");
const typed = @import("../air/lang/typed_branch_eq.zig");
const typed_authority = @import("../air/lang/typed_branch_eq_authority.zig");
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
    InstructionAddressMisaligned,
    InvalidBranchEqImmediate,
    InvalidProgramCounter,
    NonIncreasingClock,
    TargetOutOfRange,
    WrongBranchEqOpcode,
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

// Current 64-bit layouts leave one natural word of explicit growth budget.
pub const MAX_TRANSACTION_BYTES: usize = 104;
pub const MAX_PLAN_BYTES: usize = 128;
pub const MAX_PREPARED_BYTES: usize = 16;

pub const PINNED_AUTHORITY = Authority.pinned();

pub fn authenticateCanonical(allocator: std.mem.Allocator) !Authority {
    var definition = try typed.build(allocator, .generated);
    defer definition.deinit();
    const binding = try typed_authority.Binding.canonical(&definition);
    return typed_authority.Authority.init(&definition, &binding);
}

/// Inputs captured before execution. `rd_metadata_value` is diagnostic only:
/// B-type bits 11:7 decode into the generic `rd` field, but branches never
/// publish a destination access. Retaining it makes stale trace metadata
/// detectable without pretending it is an architectural write.
pub const CompactInput = struct {
    instruction: DecodedInst,
    instruction_clock: u32,
    pc_before: u32,
    rs1_value: u32,
    rs2_value: u32,
    rd_metadata_value: u32,
};

/// Pointer-free transaction compiled from authority and live tracker state.
/// Raw clocks authenticate the snapshot; effective clocks are committed after
/// any synthetic gap records.
pub const CompactTransaction = struct {
    instruction: DecodedInst,
    instruction_clock: u32,
    pc_before: u32,
    next_pc: u32,
    rs1_value: u32,
    rs2_value: u32,
    rd_metadata_value: u32,
    source_1_raw_previous_clock: u32,
    source_1_previous_clock: u32,
    source_2_raw_previous_clock: u32,
    source_2_previous_clock: u32,
    source_1_gap_count: usize,
    source_2_gap_count: usize,
    branch_taken: bool,
};

/// Compile semantic, x0, alias, and clock facts without allocation or mutation.
pub inline fn compileCompact(
    authority: *const Authority,
    tracker: *const StateChainTracker,
    input: CompactInput,
) CompileError!CompactTransaction {
    const retirement = authority.retire(
        input.instruction,
        input.pc_before,
        input.rs1_value,
        input.rs2_value,
    ) catch |err| return switch (err) {
        error.WrongBranchEqOpcode => error.WrongBranchEqOpcode,
        error.InvalidImmediate => error.InvalidBranchEqImmediate,
        error.InvalidProgramCounter => error.InvalidProgramCounter,
        error.InstructionAddressMisaligned => error.InstructionAddressMisaligned,
        error.TargetOutOfRange => error.TargetOutOfRange,
    };
    if (input.instruction_clock == 0 or
        access_clock.maximum(input.instruction_clock) >=
            state_chain.CLOCK_PREV_BOUND)
    {
        return error.ClockOutOfRange;
    }
    if ((input.instruction.rs1 == 0 and input.rs1_value != 0) or
        (input.instruction.rs2 == 0 and input.rs2_value != 0) or
        (input.instruction.rd == 0 and input.rd_metadata_value != 0))
    {
        return error.ZeroRegisterValue;
    }
    if (input.instruction.rs1 == input.instruction.rs2 and
        input.rs1_value != input.rs2_value)
    {
        return error.AliasedRegisterValueMismatch;
    }
    if ((input.instruction.rd == input.instruction.rs1 and
        input.rd_metadata_value != input.rs1_value) or
        (input.instruction.rd == input.instruction.rs2 and
            input.rd_metadata_value != input.rs2_value))
    {
        return error.AliasedRegisterValueMismatch;
    }

    const source_1_clock = access_clock.encode(input.instruction_clock, .first);
    const source_1_raw = tracker.reg_last_clk[input.instruction.rs1];
    if (source_1_raw >= source_1_clock) return error.NonIncreasingClock;

    const sources_alias = input.instruction.rs2 == input.instruction.rs1;
    const source_2_clock = access_clock.encode(input.instruction_clock, .second);
    const source_2_raw = if (sources_alias)
        source_1_clock
    else
        tracker.reg_last_clk[input.instruction.rs2];
    if (source_2_raw >= source_2_clock) return error.NonIncreasingClock;
    const source_1_gap = deriveClockGap(source_1_raw, source_1_clock);
    const source_2_gap = deriveClockGap(source_2_raw, source_2_clock);

    return .{
        .instruction = input.instruction,
        .instruction_clock = input.instruction_clock,
        .pc_before = input.pc_before,
        .next_pc = retirement.next_pc,
        .rs1_value = input.rs1_value,
        .rs2_value = input.rs2_value,
        .rd_metadata_value = input.rd_metadata_value,
        .source_1_raw_previous_clock = source_1_raw,
        .source_1_previous_clock = source_1_gap.previous_clock,
        .source_2_raw_previous_clock = source_2_raw,
        .source_2_previous_clock = source_2_gap.previous_clock,
        .source_1_gap_count = source_1_gap.update_count,
        .source_2_gap_count = source_2_gap.update_count,
        .branch_taken = retirement.branch_taken,
    };
}

pub const Plan = struct {
    instruction: DecodedInst,
    instruction_clock: u32,
    pc_before: u32,
    next_pc: u32,
    inst_word: u32,
    rs1_value: u32,
    rs2_value: u32,
    rd_metadata_value: u32,
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
        const trace_needs_growth = trace.rows.capacity - trace.rows.items.len < 1;
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
        publishReadAssumeCapacity(
            self.instruction.rs1,
            access_clock.encode(self.instruction_clock, .first),
            self.rs1_value,
            self.source_1_previous_clock,
            self.source_1_gap_count,
            tracker,
        );
        publishReadAssumeCapacity(
            self.instruction.rs2,
            access_clock.encode(self.instruction_clock, .second),
            self.rs2_value,
            self.source_2_previous_clock,
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
            cpu.readReg(self.instruction.rd) == self.rd_metadata_value and
            trace.rows.items.len == self.expected_trace_len and
            trace.step_count == self.expected_trace_len;
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
        const source_1_clock = access_clock.encode(self.instruction_clock, .first);
        const source_2_clock = access_clock.encode(self.instruction_clock, .second);
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
        const sources_alias = self.instruction.rs1 == self.instruction.rs2;
        return instructionMatchesWord(self.instruction, self.inst_word) and
            traceClockMatches(self.expected_trace_len, self.instruction_clock) and
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
            (self.instruction.rd != 0 or self.rd_metadata_value == 0) and
            (!sources_alias or self.rs1_value == self.rs2_value) and
            (self.instruction.rd != self.instruction.rs1 or
                self.rd_metadata_value == self.rs1_value) and
            (self.instruction.rd != self.instruction.rs2 or
                self.rd_metadata_value == self.rs2_value) and
            (!sources_alias or
                self.source_2_raw_previous_clock == source_1_clock) and
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
    if (!traceClockMatches(trace.rows.items.len, instruction_clock))
        return error.InstructionClockMismatch;
    if (!instructionMatchesWord(instruction, inst_word))
        return error.InstructionWordMismatch;

    const transaction = try compileCompact(authority, tracker, .{
        .instruction = instruction,
        .instruction_clock = instruction_clock,
        .pc_before = cpu.pc,
        .rs1_value = cpu.readReg(instruction.rs1),
        .rs2_value = cpu.readReg(instruction.rs2),
        .rd_metadata_value = cpu.readReg(instruction.rd),
    });
    return .{
        .instruction = transaction.instruction,
        .instruction_clock = transaction.instruction_clock,
        .pc_before = transaction.pc_before,
        .next_pc = transaction.next_pc,
        .inst_word = inst_word,
        .rs1_value = transaction.rs1_value,
        .rs2_value = transaction.rs2_value,
        .rd_metadata_value = transaction.rd_metadata_value,
        .source_1_raw_previous_clock = transaction.source_1_raw_previous_clock,
        .source_1_previous_clock = transaction.source_1_previous_clock,
        .source_2_raw_previous_clock = transaction.source_2_raw_previous_clock,
        .source_2_previous_clock = transaction.source_2_previous_clock,
        .source_1_gap_count = transaction.source_1_gap_count,
        .source_2_gap_count = transaction.source_2_gap_count,
        .expected_trace_len = trace.rows.items.len,
        .branch_taken = transaction.branch_taken,
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

/// Admit every decoded field, including B-type encoding bits exposed through
/// the generic `rd` diagnostic field. This rejects forged decoded structs even
/// when their architectural branch behavior would happen to be unchanged.
pub inline fn instructionMatchesWord(
    instruction: DecodedInst,
    inst_word: u32,
) bool {
    const funct3: u3 = switch (instruction.opcode) {
        .BEQ => 0b000,
        .BNE => 0b001,
        else => return false,
    };
    if (instruction.imm < -4096 or instruction.imm > 4094) return false;
    const immediate: u32 = @bitCast(instruction.imm);
    if (immediate & 1 != 0) return false;
    const reconstructed = ((immediate >> 12) & 1) << 31 |
        ((immediate >> 5) & 0x3f) << 25 |
        (@as(u32, instruction.rs2) << 20) |
        (@as(u32, instruction.rs1) << 15) |
        (@as(u32, funct3) << 12) |
        ((immediate >> 1) & 0xf) << 8 |
        ((immediate >> 11) & 1) << 7 |
        0b1100011;
    return inst_word == reconstructed and
        instruction.rd == @as(u5, @truncate(inst_word >> 7));
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

test "BRANCH_EQ closed-form clock gaps equal the generic state-chain geometry" {
    const max = state_chain.MAX_CLOCK_DIFF;
    const boundaries = [_][2]u32{
        .{ 0, 1 },
        .{ 0, max },
        .{ 0, max + 1 },
        .{ 0, 2 * max },
        .{ 0, 2 * max + 1 },
        .{ max - 1, 2 * max - 1 },
        .{ max - 1, 2 * max },
        .{ state_chain.CLOCK_PREV_BOUND - 2, state_chain.CLOCK_PREV_BOUND - 1 },
    };
    for (boundaries) |pair| try expectClockGapEquivalent(pair[0], pair[1]);

    var prng = std.Random.DefaultPrng.init(0x4252_414e_4348_4551);
    const random = prng.random();
    for (0..16_384) |_| {
        const current = 1 + random.uintLessThan(
            u32,
            state_chain.CLOCK_PREV_BOUND - 1,
        );
        const previous = random.uintLessThan(u32, current);
        try expectClockGapEquivalent(previous, current);
    }
}

fn expectClockGapEquivalent(previous: u32, current: u32) !void {
    const actual = deriveClockGap(previous, current);
    try std.testing.expectEqual(
        StateChainTracker.effectivePreviousClock(previous, current),
        actual.previous_clock,
    );
    try std.testing.expectEqual(
        StateChainTracker.clockGapCount(previous, current),
        actual.update_count,
    );
}

inline fn publishReadAssumeCapacity(
    register: u5,
    current_clock: u32,
    value: u32,
    previous_clock: u32,
    gap_count: usize,
    tracker: *StateChainTracker,
) void {
    if (gap_count == 0) {
        tracker.accesses.appendAssumeCapacity(.{
            .addr_space = 0,
            .addr = register,
            .clk = current_clock,
            .value = value,
            .clk_prev = previous_clock,
        });
        tracker.reg_last_clk[register] = current_clock;
    } else {
        tracker.recordRegTransitionAssumeCapacity(
            register,
            current_clock,
            value,
            value,
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
        .rd_prev_val = plan.rd_metadata_value,
        .rd_prev_clk = 0,
        .rd_val = plan.rd_metadata_value,
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
    if (@sizeOf(CompactTransaction) > MAX_TRANSACTION_BYTES)
        @compileError("typed BRANCH_EQ compact transaction exceeded its stack budget");
    if (@sizeOf(Plan) > MAX_PLAN_BYTES)
        @compileError("typed BRANCH_EQ retirement plan exceeded its stack budget");
    if (@sizeOf(Prepared) > MAX_PREPARED_BYTES)
        @compileError("typed BRANCH_EQ prepared token exceeded its stack budget");
}
