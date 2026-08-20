//! Failure-atomic staged retirement for the typed RV32 AUIPC authority.
//!
//! AUIPC has one architectural register transition. Its result depends on the
//! pre-retirement program counter, so the staged plan authenticates that PC in
//! addition to the trace-visible U-type decode fields. All fallible capacity
//! work precedes publication; the warm production path allocates nothing.

const std = @import("std");
const builtin = @import("builtin");
const access_clock = @import("../access_clock.zig");
const typed_auipc = @import("../air/lang/typed_auipc.zig");
const typed_auipc_authority = @import("../air/lang/typed_auipc_authority.zig");
const Cpu = @import("cpu.zig").Cpu;
const state_chain = @import("state_chain.zig");
const trace_mod = @import("trace.zig");

pub const StateChainTracker = state_chain.StateChainTracker;
pub const Trace = trace_mod.Trace;
pub const TraceRow = trace_mod.TraceRow;
pub const DecodedInst = typed_auipc_authority.DecodedInst;
pub const Authority = typed_auipc_authority.Authority;

pub const StageError = typed_auipc_authority.ExecutionError || error{
    ClockOutOfRange,
    InstructionWordMismatch,
    NonIncreasingClock,
    TraceInvariantViolation,
    ZeroRegisterValue,
};
pub const PrepareError = error{ OutOfMemory, StaleRetirement };
pub const CommitError = error{ AlreadyCommitted, StaleRetirement };
pub const RetireError = StageError || PrepareError;

pub const MAX_PLAN_BYTES: usize = 64;
pub const MAX_PREPARED_BYTES: usize = 16;

/// Process-wide immutable executable capability. Cold graph authentication is
/// retained below as an independent admission gate.
pub const PINNED_AUTHORITY = Authority.pinned();

pub fn authenticateCanonical(allocator: std.mem.Allocator) !Authority {
    var definition = try typed_auipc.build(allocator, .generated);
    defer definition.deinit();
    const binding = try typed_auipc_authority.Binding.canonical(&definition);
    return typed_auipc_authority.Authority.init(&definition, &binding);
}

/// Pointer-free snapshot of one complete AUIPC retirement. It owns no
/// capacity token and cannot mutate architectural or proof state.
pub const Plan = struct {
    instruction: DecodedInst,
    instruction_clock: u32,
    rs1_value: u32,
    rs2_value: u32,
    rd_previous_value: u32,
    rd_next_value: u32,
    raw_previous_clock: u32,
    previous_clock: u32,
    register_clock_update_count: usize,
    pc_before: u32,
    inst_word: u32,
    expected_trace_len: usize,

    pub fn traceRow(self: *const Plan) TraceRow {
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

    pub fn prepare(
        self: *const Plan,
        cpu: *const Cpu,
        exec_trace: *Trace,
        tracker: *StateChainTracker,
    ) PrepareError!Prepared {
        try self.validateAndReserve(cpu, exec_trace, tracker);
        return .{ .plan = self };
    }

    pub fn commitAtomic(
        self: *const Plan,
        cpu: *Cpu,
        exec_trace: *Trace,
        tracker: *StateChainTracker,
    ) PrepareError!void {
        try self.validateAndReserve(cpu, exec_trace, tracker);
        self.publishAssumeCapacity(cpu, exec_trace, tracker);
    }

    fn validateAndReserve(
        self: *const Plan,
        cpu: *const Cpu,
        exec_trace: *Trace,
        tracker: *StateChainTracker,
    ) PrepareError!void {
        if (!self.isWellFormed() or
            !self.runnerStateIsCurrent(cpu, exec_trace) or
            !self.accessStateIsCurrent(tracker))
        {
            return error.StaleRetirement;
        }
        try self.reserveAndRevalidate(cpu, exec_trace, tracker);
    }

    fn reserveAndRevalidate(
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

        // Allocators may be re-entrant. A cold growth path therefore rechecks
        // every live value before the first logical write.
        if ((trace_needs_growth or access_needs_growth or gaps_need_growth) and
            (!self.runnerStateIsCurrent(cpu, exec_trace) or
                !self.accessStateIsCurrent(tracker)))
        {
            return error.StaleRetirement;
        }
    }

    fn reserveFreshAndRevalidateAfterGrowth(
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
            self.instruction.rd,
            access_clock.encode(self.instruction_clock, .first),
            self.rd_previous_value,
            self.rd_next_value,
        );
        cpu.writeReg(self.instruction.rd, self.rd_next_value);
        const row = self.traceRow();
        cpu.pc = row.next_pc;
        exec_trace.appendAssumeCapacity(row);
    }

    fn runnerStateIsCurrent(
        self: *const Plan,
        cpu: *const Cpu,
        exec_trace: *const Trace,
    ) bool {
        return cpu.pc == self.pc_before and
            cpu.readReg(self.instruction.rs1) == self.rs1_value and
            cpu.readReg(self.instruction.rs2) == self.rs2_value and
            cpu.readReg(self.instruction.rd) == self.rd_previous_value and
            exec_trace.rows.items.len == self.expected_trace_len and
            exec_trace.step_count == self.expected_trace_len;
    }

    fn isWellFormed(self: *const Plan) bool {
        if (self.instruction_clock == 0 or
            access_clock.maximum(self.instruction_clock) >=
                state_chain.CLOCK_PREV_BOUND)
        {
            return false;
        }
        const current_clock = access_clock.encode(
            self.instruction_clock,
            .first,
        );
        return self.instruction.opcode == .AUIPC and
            instructionMatchesWord(self.instruction, self.inst_word) and
            typed_auipc_authority.acceptsRetirement(
                self.instruction,
                self.pc_before,
                self.rd_next_value,
                self.pc_before +% 4,
            ) and
            (self.instruction.rd != 0 or self.rd_previous_value == 0) and
            self.raw_previous_clock < current_clock and
            self.previous_clock == StateChainTracker.effectivePreviousClock(
                self.raw_previous_clock,
                current_clock,
            ) and
            self.register_clock_update_count ==
                StateChainTracker.clockGapCount(
                    self.raw_previous_clock,
                    current_clock,
                );
    }

    inline fn accessStateIsCurrent(
        self: *const Plan,
        tracker: *const StateChainTracker,
    ) bool {
        return tracker.reg_last_clk[self.instruction.rd] ==
            self.raw_previous_clock;
    }
};

/// Single-use proof that every destination has sufficient capacity. Exclusive
/// ownership of CPU, trace, and tracker is required through `commit`.
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
        if (!self.plan.isWellFormed() or
            !self.plan.runnerStateIsCurrent(cpu, exec_trace) or
            !self.plan.accessStateIsCurrent(tracker))
        {
            return error.StaleRetirement;
        }
        self.plan.publishAssumeCapacity(cpu, exec_trace, tracker);
        self.consumed = true;
    }
};

/// Compile one AUIPC row against immutable runner snapshots. The authority
/// owns the PC-relative result and x0 visibility; this boundary owns exact
/// U-type encoding, predecessor-clock geometry, and alias snapshots.
pub fn stage(
    authority: *const Authority,
    cpu: Cpu,
    exec_trace: *const Trace,
    tracker: *const StateChainTracker,
    instruction: DecodedInst,
    inst_word: u32,
    instruction_clock: u32,
) StageError!Plan {
    if (exec_trace.step_count != exec_trace.rows.items.len)
        return error.TraceInvariantViolation;
    if (!instructionMatchesWord(instruction, inst_word))
        return error.InstructionWordMismatch;
    const retirement = try authority.retire(instruction, cpu.pc);
    if (instruction_clock == 0 or
        access_clock.maximum(instruction_clock) >=
            state_chain.CLOCK_PREV_BOUND)
    {
        return error.ClockOutOfRange;
    }
    const rd_previous = cpu.readReg(instruction.rd);
    if (instruction.rd == 0 and
        (rd_previous != 0 or retirement.visible_value != 0))
    {
        return error.ZeroRegisterValue;
    }
    const current_clock = access_clock.encode(instruction_clock, .first);
    const raw_previous = tracker.reg_last_clk[instruction.rd];
    if (raw_previous >= current_clock) return error.NonIncreasingClock;
    return .{
        .instruction = instruction,
        .instruction_clock = instruction_clock,
        .rs1_value = cpu.readReg(instruction.rs1),
        .rs2_value = cpu.readReg(instruction.rs2),
        .rd_previous_value = rd_previous,
        .rd_next_value = retirement.visible_value,
        .raw_previous_clock = raw_previous,
        .previous_clock = StateChainTracker.effectivePreviousClock(
            raw_previous,
            current_clock,
        ),
        .register_clock_update_count = StateChainTracker.clockGapCount(
            raw_previous,
            current_clock,
        ),
        .pc_before = cpu.pc,
        .inst_word = inst_word,
        .expected_trace_len = exec_trace.rows.items.len,
    };
}

/// Fused production path. With warm capacity no external code executes
/// between staging and publication; after a cold allocation the full snapshot
/// is revalidated.
pub fn retireAtomic(
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
        cpu.*,
        exec_trace,
        tracker,
        instruction,
        inst_word,
        instruction_clock,
    );
    if (comptime builtin.mode == .Debug)
        std.debug.assert(plan.isCurrentFor(cpu, exec_trace, tracker));
    try plan.reserveFreshAndRevalidateAfterGrowth(cpu, exec_trace, tracker);
    plan.publishAssumeCapacity(cpu, exec_trace, tracker);
}

inline fn instructionMatchesWord(
    instruction: DecodedInst,
    inst_word: u32,
) bool {
    const immediate_bits: u32 = @bitCast(instruction.imm);
    const reconstructed = (immediate_bits & 0xffff_f000) |
        (@as(u32, instruction.rd) << 7) | 0b0010111;
    const decoded_sources = @as(u10, instruction.rs1) |
        (@as(u10, instruction.rs2) << 5);
    return instruction.opcode == .AUIPC and
        inst_word == reconstructed and
        decoded_sources == @as(u10, @truncate(immediate_bits >> 15));
}

fn canonicalRow(plan: *const Plan) TraceRow {
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
        .branch_taken = false,
        .next_pc = plan.pc_before +% 4,
        .inst_word = plan.inst_word,
    };
}

comptime {
    if (@sizeOf(Plan) > MAX_PLAN_BYTES)
        @compileError("typed AUIPC runner plan exceeded its fixed stack budget");
    if (@sizeOf(Prepared) > MAX_PREPARED_BYTES)
        @compileError("typed AUIPC prepared token exceeded its fixed stack budget");
}
