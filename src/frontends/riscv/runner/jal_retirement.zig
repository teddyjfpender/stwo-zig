//! Failure-atomic retirement for the typed RV32 JAL authority.
//!
//! The authenticated authority is the sole owner of target, link, x0, witness,
//! direct-root, and relation semantics. This module adds only runner ownership:
//! exact instruction-word admission, one register-access predecessor, capacity
//! preflight, and atomic publication of CPU, trace, and state-chain state.
//! The warm fused path allocates nothing.

const std = @import("std");
const builtin = @import("builtin");
const access_clock = @import("../access_clock.zig");
const typed_jal = @import("../air/lang/typed_jal.zig");
const typed_authority = @import("../air/lang/typed_jal_authority.zig");
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

pub const MAX_PLAN_BYTES: usize = 96;
pub const MAX_PREPARED_BYTES: usize = 16;

/// Process-wide immutable capability for the compile-time-pinned definition.
pub const PINNED_AUTHORITY = Authority.pinned();

/// Independent cold admission gate for tests, tooling, and startup audits.
pub fn authenticateCanonical(allocator: std.mem.Allocator) !Authority {
    var definition = try typed_jal.build(allocator, .generated);
    defer definition.deinit();
    const binding = try typed_authority.Binding.canonical(&definition);
    return typed_authority.Authority.init(&definition, &binding);
}

/// Compact one-register transaction. Raw predecessor state authenticates the
/// live tracker; the effective predecessor is the value committed to the AIR
/// row after any required synthetic clock-gap records.
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
    raw_previous_clock: u32,
    previous_clock: u32,
    register_clock_update_count: usize,
    expected_trace_len: usize,
    branch_taken: bool,

    pub inline fn traceRow(self: *const Plan) TraceRow {
        return canonicalRow(self);
    }

    pub inline fn reservation(self: *const Plan) StateChainTracker.Reservation {
        return .{
            .memory_address_count = 0,
            .access_count = 1,
            .memory_clock_update_count = 0,
            .register_clock_update_count = self.register_clock_update_count,
        };
    }

    pub fn isCurrentFor(
        self: *const Plan,
        cpu: *const Cpu,
        exec_trace: *const Trace,
        tracker: *const StateChainTracker,
    ) bool {
        return self.isWellFormed() and
            self.runnerStateIsCurrent(cpu, exec_trace) and
            self.accessStateIsCurrent(tracker);
    }

    /// Reserve every fallible destination before publishing logical state.
    pub fn prepare(
        self: *const Plan,
        cpu: *const Cpu,
        exec_trace: *Trace,
        tracker: *StateChainTracker,
    ) PrepareError!Prepared {
        if (!self.isCurrentFor(cpu, exec_trace, tracker))
            return error.StaleRetirement;
        try self.reserveAndRevalidate(cpu, exec_trace, tracker);
        return .{ .plan = self };
    }

    /// Failure-atomic integration boundary for a caller retaining the plan.
    pub fn commitAtomic(
        self: *const Plan,
        cpu: *Cpu,
        exec_trace: *Trace,
        tracker: *StateChainTracker,
    ) PrepareError!void {
        if (!self.isCurrentFor(cpu, exec_trace, tracker))
            return error.StaleRetirement;
        try self.reserveAndRevalidate(cpu, exec_trace, tracker);
        self.publishAssumeCapacity(cpu, exec_trace, tracker);
    }

    inline fn reserveAndRevalidate(
        self: *const Plan,
        cpu: *const Cpu,
        exec_trace: *Trace,
        tracker: *StateChainTracker,
    ) PrepareError!void {
        const trace_needs_growth = exec_trace.rows.capacity -
            exec_trace.rows.items.len < 1;
        const required = self.reservation();
        const access_needs_growth = tracker.accesses.capacity -
            tracker.accesses.items.len < required.access_count;
        const gaps_need_growth = tracker.clock_updates_reg.capacity -
            tracker.clock_updates_reg.items.len <
            required.register_clock_update_count;

        if (trace_needs_growth) try exec_trace.reserveOne();
        if (access_needs_growth or gaps_need_growth)
            try tracker.reserveTransitions(required);

        // Only capacity growth can invoke external allocator code. Revalidate
        // the complete captured state after returning and before publication.
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
        const current_clock = access_clock.encode(
            self.instruction_clock,
            .first,
        );
        if (self.register_clock_update_count == 0) {
            // The overwhelmingly common path needs no synthetic predecessor.
            // Publish the already-authenticated compact event directly rather
            // than re-running the generic gap scanner during commit.
            tracker.accesses.appendAssumeCapacity(.{
                .addr_space = 0,
                .addr = @as(u32, self.instruction.rd),
                .clk = current_clock,
                .value = self.rd_next_value,
                .clk_prev = self.previous_clock,
            });
            tracker.reg_last_clk[self.instruction.rd] = current_clock;
        } else {
            tracker.recordRegTransitionAssumeCapacity(
                self.instruction.rd,
                current_clock,
                self.rd_previous_value,
                self.rd_next_value,
            );
        }
        cpu.writeReg(self.instruction.rd, self.rd_next_value);
        const row = self.traceRow();
        cpu.pc = self.next_pc;
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
        return tracker.reg_last_clk[self.instruction.rd] ==
            self.raw_previous_clock;
    }

    fn isWellFormed(self: *const Plan) bool {
        const current_clock = access_clock.encode(
            self.instruction_clock,
            .first,
        );
        if (self.raw_previous_clock >= current_clock) return false;
        const gap = deriveClockGap(self.raw_previous_clock, current_clock);
        return instructionMatchesWord(self.instruction, self.inst_word) and
            self.instruction_clock != 0 and
            access_clock.maximum(self.instruction_clock) <
                state_chain.CLOCK_PREV_BOUND and
            typed_authority.acceptsRetirement(
                self.instruction,
                self.pc_before,
                self.rd_next_value,
                self.next_pc,
                self.branch_taken,
            ) and
            (self.instruction.rs1 != 0 or self.rs1_value == 0) and
            (self.instruction.rs2 != 0 or self.rs2_value == 0) and
            (self.instruction.rd != 0 or
                (self.rd_previous_value == 0 and self.rd_next_value == 0)) and
            self.previous_clock == gap.previous_clock and
            self.register_clock_update_count == gap.update_count;
    }
};

/// Single-use capacity proof. Exclusive ownership of CPU, trace, and tracker
/// is required from `prepare` through `commit`.
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

/// Compile one JAL retirement against immutable live-state snapshots.
pub inline fn stage(
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
    if (instruction_clock == 0 or
        access_clock.maximum(instruction_clock) >=
            state_chain.CLOCK_PREV_BOUND)
    {
        return error.ClockOutOfRange;
    }

    const retirement = try authority.retire(instruction, cpu.pc);
    const rs1_value = cpu.readReg(instruction.rs1);
    const rs2_value = cpu.readReg(instruction.rs2);
    const rd_previous_value = cpu.readReg(instruction.rd);
    if ((instruction.rs1 == 0 and rs1_value != 0) or
        (instruction.rs2 == 0 and rs2_value != 0) or
        (instruction.rd == 0 and
            (rd_previous_value != 0 or retirement.visible_value != 0)))
    {
        return error.ZeroRegisterValue;
    }

    const current_clock = access_clock.encode(instruction_clock, .first);
    const raw_previous_clock = tracker.reg_last_clk[instruction.rd];
    if (raw_previous_clock >= current_clock)
        return error.NonIncreasingClock;
    const gap = deriveClockGap(raw_previous_clock, current_clock);

    return .{
        .instruction = instruction,
        .instruction_clock = instruction_clock,
        .pc_before = cpu.pc,
        .next_pc = retirement.next_pc,
        .inst_word = inst_word,
        .rs1_value = rs1_value,
        .rs2_value = rs2_value,
        .rd_previous_value = rd_previous_value,
        .rd_next_value = retirement.visible_value,
        .raw_previous_clock = raw_previous_clock,
        .previous_clock = gap.previous_clock,
        .register_clock_update_count = gap.update_count,
        .expected_trace_len = exec_trace.rows.items.len,
        .branch_taken = retirement.branch_taken,
    };
}

/// Fused production-shaped path. Warm retirement executes only fixed scalar
/// validation and infallible stores; cold allocation is followed by complete
/// snapshot revalidation.
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

pub inline fn instructionMatchesWord(
    instruction: DecodedInst,
    inst_word: u32,
) bool {
    if (instruction.opcode != .JAL or
        instruction.imm < -1_048_576 or
        instruction.imm > 1_048_574)
    {
        return false;
    }
    const immediate: u32 = @bitCast(instruction.imm);
    if ((immediate & 1) != 0) return false;
    const reconstructed = ((immediate >> 20) & 1) << 31 |
        ((immediate >> 1) & 0x3ff) << 21 |
        ((immediate >> 11) & 1) << 20 |
        ((immediate >> 12) & 0xff) << 12 |
        (@as(u32, instruction.rd) << 7) |
        0b1101111;
    return inst_word == reconstructed and
        instruction.rs1 == @as(u5, @truncate(inst_word >> 15)) and
        instruction.rs2 == @as(u5, @truncate(inst_word >> 20));
}

const ClockGap = struct {
    previous_clock: u32,
    update_count: usize,
};

/// Closed-form equivalent of the generic state-chain gap loop. One division
/// replaces two independent scans during staging; the divisor is compile-time
/// constant and the maximum quotient is bounded by the proof clock geometry.
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

test "JAL closed-form clock gap is exact across the proof clock domain" {
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

    var prng = std.Random.DefaultPrng.init(0x4a41_4c2d_4741_5031);
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
        .rs1_prev_clk = 0,
        .rs2_prev_clk = 0,
        .rd_prev_val = plan.rd_previous_value,
        .rd_prev_clk = plan.previous_clock,
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
        @compileError("typed JAL retirement plan exceeded its stack budget");
    if (@sizeOf(Prepared) > MAX_PREPARED_BYTES)
        @compileError("typed JAL prepared token exceeded its stack budget");
}
