//! Failure-atomic staged retirement for the typed RV32 FENCE authority.
//!
//! The production runner routes FENCE through `retireAtomic`. FENCE has no
//! register or memory effects in the single-hart zkVM, so the staged capability carries
//! only the trace-visible snapshot and reserves only one trace row. The state
//! chain is accepted through a const pointer and is never reserved or mutated.
//!
//! `stage` authenticates instruction/state-transition semantics and collapses
//! the generic access transaction after proving its geometry is exactly empty.
//! `prepare` completes the sole fallible operation. `Prepared.commit` then
//! performs a final staleness check and publishes with direct, infallible
//! writes. The fused path keeps the same boundary without an escaping plan.

const std = @import("std");
const builtin = @import("builtin");
const access_transaction = @import("../air/lang/access_transaction.zig");
const access_clock = @import("../access_clock.zig");
const typed_fence = @import("../air/lang/typed_fence.zig");
const typed_fence_authority = @import("../air/lang/typed_fence_authority.zig");
const Cpu = @import("cpu.zig").Cpu;
const state_chain = @import("state_chain.zig");
const trace_mod = @import("trace.zig");

pub const StateChainTracker = state_chain.StateChainTracker;
pub const Trace = trace_mod.Trace;
pub const TraceRow = trace_mod.TraceRow;
pub const DecodedInst = typed_fence_authority.DecodedInst;
pub const Authority = typed_fence_authority.Authority;

pub const StageError = access_transaction.CompileError || error{
    InstructionClockMismatch,
    InstructionWordMismatch,
    TraceInvariantViolation,
    TransactionInvariantViolation,
};
pub const PrepareError = error{ OutOfMemory, StaleRetirement };
pub const CommitError = error{ AlreadyCommitted, StaleRetirement };
pub const RetireError = StageError || PrepareError;

pub const MAX_PLAN_BYTES: usize = 48;
pub const MAX_PREPARED_BYTES: usize = 16;

/// Process-wide immutable production capability. This keeps compiler-arena
/// allocation and digest authentication out of the ELF execution path.
pub const PINNED_AUTHORITY = Authority.pinned();

/// Independent cold admission gate for the pinned fixed capability.
pub fn authenticateCanonical(allocator: std.mem.Allocator) !Authority {
    var definition = try typed_fence.build(allocator, .generated);
    defer definition.deinit();
    const binding = try typed_fence_authority.Binding.canonical(&definition);
    return typed_fence_authority.Authority.init(&definition, &binding);
}

/// Pointer-free FENCE capability. Empty effect geometry makes this 25% smaller
/// than the LUI plan: no predecessor clock, reservation, or transition value
/// survives staging.
pub const Plan = struct {
    instruction: DecodedInst,
    instruction_clock: u32,
    rs1_value: u32,
    rs2_value: u32,
    rd_value: u32,
    pc_before: u32,
    inst_word: u32,
    expected_trace_len: usize,

    pub inline fn traceRow(self: *const Plan) TraceRow {
        return canonicalRow(self);
    }

    /// True only while every value captured into the eventual trace row still
    /// names the live runner state. The tracker is const and irrelevant after
    /// staging because FENCE's authenticated transaction has no addresses.
    pub inline fn isCurrentFor(
        self: *const Plan,
        cpu: *const Cpu,
        exec_trace: *const Trace,
        _: *const StateChainTracker,
    ) bool {
        return self.isWellFormed() and
            self.runnerStateIsCurrent(cpu, exec_trace);
    }

    /// Reserve the sole fallible destination before publishing architectural
    /// or proof state. Capacity growth is not a logical trace mutation.
    pub fn prepare(
        self: *const Plan,
        cpu: *const Cpu,
        exec_trace: *Trace,
        tracker: *const StateChainTracker,
    ) PrepareError!Prepared {
        try self.validateAndReserve(cpu, exec_trace, tracker);
        return .{ .plan = self };
    }

    /// Failure-atomic integration boundary for a caller retaining the plan.
    pub fn commitAtomic(
        self: *const Plan,
        cpu: *Cpu,
        exec_trace: *Trace,
        tracker: *const StateChainTracker,
    ) PrepareError!void {
        try self.validateAndReserve(cpu, exec_trace, tracker);
        self.publishAssumeCapacity(cpu, exec_trace);
    }

    fn validateAndReserve(
        self: *const Plan,
        cpu: *const Cpu,
        exec_trace: *Trace,
        tracker: *const StateChainTracker,
    ) PrepareError!void {
        if (!self.isCurrentFor(cpu, exec_trace, tracker))
            return error.StaleRetirement;
        try self.reserveAndRevalidate(cpu, exec_trace);
    }

    inline fn reserveAndRevalidate(
        self: *const Plan,
        cpu: *const Cpu,
        exec_trace: *Trace,
    ) PrepareError!void {
        const trace_needs_growth = exec_trace.rows.capacity -
            exec_trace.rows.items.len < 1;
        if (trace_needs_growth) {
            try exec_trace.reserveOne();

            // Allocation can invoke external code. Revalidate every logical
            // source after returning and before the first published write.
            if (!self.runnerStateIsCurrent(cpu, exec_trace))
                return error.StaleRetirement;
        }
    }

    inline fn publishAssumeCapacity(
        self: *const Plan,
        cpu: *Cpu,
        exec_trace: *Trace,
    ) void {
        const row = self.traceRow();
        cpu.pc = row.next_pc;
        exec_trace.appendAssumeCapacity(row);
    }

    inline fn runnerStateIsCurrent(
        self: *const Plan,
        cpu: *const Cpu,
        exec_trace: *const Trace,
    ) bool {
        const instruction = self.instruction;
        return cpu.pc == self.pc_before and
            cpu.readReg(instruction.rs1) == self.rs1_value and
            cpu.readReg(instruction.rs2) == self.rs2_value and
            cpu.readReg(instruction.rd) == self.rd_value and
            exec_trace.rows.items.len == self.expected_trace_len and
            exec_trace.step_count == self.expected_trace_len and
            exec_trace.expectsNextCoreRetirement(self.instruction_clock);
    }

    inline fn isWellFormed(self: *const Plan) bool {
        const instruction = self.instruction;
        return instructionMatchesWord(instruction, self.inst_word) and
            self.instruction_clock != 0 and
            access_clock.maximum(self.instruction_clock) <
                state_chain.CLOCK_PREV_BOUND and
            typed_fence_authority.acceptsRetirement(
                instruction,
                self.pc_before,
                self.pc_before +% 4,
            ) and
            (instruction.rs1 != 0 or self.rs1_value == 0) and
            (instruction.rs2 != 0 or self.rs2_value == 0) and
            (instruction.rd != 0 or self.rd_value == 0);
    }
};

/// Single-use proof that one trace slot is available. Exclusive access to the
/// CPU and trace is required from `Plan.prepare` through `commit`; the state
/// tracker stays shared-read-only because this retirement cannot touch it.
pub const Prepared = struct {
    plan: *const Plan,
    consumed: bool = false,

    pub fn commit(
        self: *Prepared,
        cpu: *Cpu,
        exec_trace: *Trace,
        tracker: *const StateChainTracker,
    ) CommitError!void {
        if (self.consumed) return error.AlreadyCommitted;
        if (!self.plan.isCurrentFor(cpu, exec_trace, tracker))
            return error.StaleRetirement;

        self.plan.publishAssumeCapacity(cpu, exec_trace);
        self.consumed = true;
    }
};

/// Compile one FENCE retirement against immutable runner snapshots. The typed
/// authority owns sequential PC semantics; `access_transaction` proves that
/// reserved encoding fields induce no register or memory effects.
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

    const rs1_value = cpu.readReg(instruction.rs1);
    const rs2_value = cpu.readReg(instruction.rs2);
    const rd_value = cpu.readReg(instruction.rd);
    const transaction = try access_transaction.compileFence(authority, tracker, .{
        .instruction = instruction,
        .instruction_clock = instruction_clock,
        .pc_before = cpu.pc,
        .rs1_value = rs1_value,
        .rs2_value = rs2_value,
        .rd_previous_value = rd_value,
    });
    if (!transactionIsCanonicalEmpty(
        &transaction,
        instruction,
        instruction_clock,
        rs1_value,
        rs2_value,
        rd_value,
    )) return error.TransactionInvariantViolation;

    return .{
        .instruction = instruction,
        .instruction_clock = instruction_clock,
        .rs1_value = rs1_value,
        .rs2_value = rs2_value,
        .rd_value = rd_value,
        .pc_before = cpu.pc,
        .inst_word = inst_word,
        .expected_trace_len = exec_trace.rows.items.len,
    };
}

/// Fused production-shaped path. On warm trace capacity no external code runs
/// between the authenticated snapshot and publication; on a cold path the
/// allocator return is followed by complete live-state revalidation.
pub inline fn retireAtomic(
    authority: *const Authority,
    cpu: *Cpu,
    exec_trace: *Trace,
    tracker: *const StateChainTracker,
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
    try plan.reserveAndRevalidate(cpu, exec_trace);
    plan.publishAssumeCapacity(cpu, exec_trace);
}

inline fn instructionMatchesWord(
    instruction: DecodedInst,
    inst_word: u32,
) bool {
    const immediate_bits = @as(u32, @bitCast(instruction.imm)) & 0xfff;
    const reconstructed = (immediate_bits << 20) |
        (@as(u32, instruction.rs1) << 15) |
        (@as(u32, instruction.rd) << 7) |
        0b0001111;
    return instruction.opcode == .FENCE and
        instruction.imm >= -2048 and instruction.imm <= 2047 and
        instruction.rs2 == @as(u5, @truncate(immediate_bits)) and
        inst_word == reconstructed;
}

inline fn transactionIsCanonicalEmpty(
    transaction: *const access_transaction.Transaction,
    instruction: DecodedInst,
    instruction_clock: u32,
    rs1_value: u32,
    rs2_value: u32,
    rd_value: u32,
) bool {
    return transaction.format_version == access_transaction.FORMAT_VERSION and
        std.meta.eql(transaction.instruction, instruction) and
        transaction.instruction_clock == instruction_clock and
        !transaction.usage.reads_rs1 and
        !transaction.usage.reads_rs2 and
        !transaction.usage.writes_rd and
        transaction.rs1_value == rs1_value and
        transaction.rs2_value == rs2_value and
        transaction.rd_previous_value == rd_value and
        transaction.rd_next_value == rd_value and
        transaction.accessEvents().len == 0 and
        transaction.row_projection.rs1_previous_clock == 0 and
        transaction.row_projection.rs2_previous_clock == 0 and
        transaction.row_projection.rd_previous_clock == 0 and
        transaction.row_projection.memory == null and
        transaction.reservation.memory_address_count == 0 and
        transaction.reservation.access_count == 0 and
        transaction.reservation.memory_clock_update_count == 0 and
        transaction.reservation.register_clock_update_count == 0;
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
        .rd_prev_val = plan.rd_value,
        .rd_prev_clk = 0,
        .rd_val = plan.rd_value,
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
        @compileError("typed FENCE retirement plan exceeded its stack budget");
    if (@sizeOf(Prepared) > MAX_PREPARED_BYTES)
        @compileError("typed FENCE prepared token exceeded its stack budget");
}
