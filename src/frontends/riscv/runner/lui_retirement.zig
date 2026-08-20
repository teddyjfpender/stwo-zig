//! Failure-atomic staged retirement for the typed RV32 LUI authority.
//!
//! The production runner routes LUI through `retireAtomic`; the explicit
//! `stage`/`prepare` API remains available for adversarial and ownership tests.
//! `stage` snapshots and validates the complete row without allocation or
//! mutation. `prepare` reserves trace and state-chain capacity while logical
//! state remains untouched. `Prepared.commit` performs one final staleness
//! check and then publishes only through infallible assume-capacity/direct
//! operations, so no returned error can expose a partial retirement.

const std = @import("std");
const builtin = @import("builtin");
const access_transaction = @import("../air/lang/access_transaction.zig");
const access_clock = @import("../access_clock.zig");
const typed_lui = @import("../air/lang/typed_lui.zig");
const typed_lui_authority = @import("../air/lang/typed_lui_authority.zig");
const Cpu = @import("cpu.zig").Cpu;
const state_chain = @import("state_chain.zig");
const trace_mod = @import("trace.zig");

pub const StateChainTracker = state_chain.StateChainTracker;
pub const Trace = trace_mod.Trace;
pub const TraceRow = trace_mod.TraceRow;
pub const DecodedInst = typed_lui_authority.DecodedInst;
pub const Authority = typed_lui_authority.Authority;

pub const StageError = access_transaction.CompileError || error{
    InstructionWordMismatch,
    TraceInvariantViolation,
};
pub const PrepareError = error{ OutOfMemory, StaleRetirement };
pub const CommitError = error{ AlreadyCommitted, StaleRetirement };
pub const RetireError = StageError || PrepareError;

pub const MAX_PLAN_BYTES: usize = 64;
pub const MAX_PREPARED_BYTES: usize = 16;

/// Process-wide immutable production capability. Keeping this as static data
/// removes all compiler-arena allocation and authentication work from ELF
/// execution; `authenticateCanonical` below remains the independent cold gate
/// proving that this exact pinned value is admitted by the typed definition.
pub const PINNED_AUTHORITY = Authority.pinned();

/// Cold admission boundary for the fixed executable capability. The authored
/// arena is validated and released here; the returned authority is compact,
/// pointer-free, and safe to retain for the complete runner invocation.
pub fn authenticateCanonical(
    allocator: std.mem.Allocator,
) !Authority {
    var definition = try typed_lui.build(allocator, .generated);
    defer definition.deinit();
    const binding = typed_lui_authority.Binding.canonical(&definition);
    return typed_lui_authority.Authority.init(&definition, &binding);
}

/// Pointer-free staged retirement. The generic E-017 compiler is collapsed
/// here to LUI's one-transition projection so the hot path does not carry or
/// copy storage for the two impossible additional events and memory facts.
/// It owns no capacity token and therefore cannot mutate state.
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

    /// True only while every value captured into the eventual trace row and
    /// every predecessor clock still names the live runner state.
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

    /// Reserve every fallible destination before any architectural or proof
    /// state is published. Capacity growth after a later failure is allowed:
    /// it is not logical trace or state-chain content.
    pub fn prepare(
        self: *const Plan,
        cpu: *const Cpu,
        exec_trace: *Trace,
        tracker: *StateChainTracker,
    ) PrepareError!Prepared {
        try self.validateAndReserve(cpu, exec_trace, tracker);
        return .{ .plan = self };
    }

    /// Failure-atomic hot integration boundary. Validation and exact capacity
    /// preflight happen before publication, while keeping exclusive ownership
    /// continuously across the boundary. This avoids the duplicate staleness
    /// scan required by the externally held `Prepared` token.
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
        const required_capacity = self.reservation();
        const access_needs_growth = tracker.accesses.capacity -
            tracker.accesses.items.len < required_capacity.access_count;
        const register_gaps_need_growth = tracker.clock_updates_reg.capacity -
            tracker.clock_updates_reg.items.len <
            required_capacity.register_clock_update_count;
        if (trace_needs_growth) try exec_trace.reserveOne();
        if (access_needs_growth or register_gaps_need_growth)
            try tracker.reserveTransitions(required_capacity);

        // A warm pre-reserved row invokes no external code. Any allocator call
        // may be re-entrant, so the cold path revalidates the live snapshot.
        if ((trace_needs_growth or access_needs_growth or
            register_gaps_need_growth) and
            (!self.runnerStateIsCurrent(cpu, exec_trace) or
                !self.accessStateIsCurrent(tracker)))
        {
            return error.StaleRetirement;
        }
    }

    /// Fused-path capacity preflight for a just-compiled stack-local plan.
    /// `stage` already validated the immutable plan and observed the current
    /// state. A warm path calls no external code, so repeating those scans is
    /// redundant. If capacity growth invokes the allocator, the complete live
    /// snapshot is revalidated before publication exactly as before.
    fn reserveFreshAndRevalidateAfterGrowth(
        self: *const Plan,
        cpu: *const Cpu,
        exec_trace: *Trace,
        tracker: *StateChainTracker,
    ) PrepareError!void {
        const trace_needs_growth = exec_trace.rows.capacity -
            exec_trace.rows.items.len < 1;
        const required_capacity = self.reservation();
        const access_needs_growth = tracker.accesses.capacity -
            tracker.accesses.items.len < required_capacity.access_count;
        const register_gaps_need_growth = tracker.clock_updates_reg.capacity -
            tracker.clock_updates_reg.items.len <
            required_capacity.register_clock_update_count;
        if (trace_needs_growth) try exec_trace.reserveOne();
        if (access_needs_growth or register_gaps_need_growth)
            try tracker.reserveTransitions(required_capacity);

        if ((trace_needs_growth or access_needs_growth or
            register_gaps_need_growth) and
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
        const instruction = self.instruction;
        tracker.recordRegTransitionAssumeCapacity(
            instruction.rd,
            access_clock.encode(self.instruction_clock, .first),
            self.rd_previous_value,
            self.rd_next_value,
        );
        cpu.writeReg(instruction.rd, self.rd_next_value);
        const row = self.traceRow();
        cpu.pc = row.next_pc;
        exec_trace.appendAssumeCapacity(row);
    }

    fn runnerStateIsCurrent(
        self: *const Plan,
        cpu: *const Cpu,
        exec_trace: *const Trace,
    ) bool {
        const instruction = self.instruction;
        return cpu.pc == self.pc_before and
            cpu.readReg(instruction.rs1) == self.rs1_value and
            cpu.readReg(instruction.rs2) == self.rs2_value and
            cpu.readReg(instruction.rd) == self.rd_previous_value and
            exec_trace.rows.items.len == self.expected_trace_len and
            exec_trace.step_count == self.expected_trace_len;
    }

    fn isWellFormed(self: *const Plan) bool {
        const current_clock = access_clock.encode(
            self.instruction_clock,
            .first,
        );
        return self.instruction.opcode == .LUI and
            instructionMatchesWord(self.instruction, self.inst_word) and
            self.instruction_clock != 0 and
            access_clock.maximum(self.instruction_clock) <
                state_chain.CLOCK_PREV_BOUND and
            typed_lui_authority.acceptsVisibleRetirement(
                self.instruction,
                self.rd_next_value,
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

/// Single-use capacity proof. Exclusive access to all three destinations is
/// required from `Plan.prepare` through `commit`.
pub const Prepared = struct {
    // Borrowing the caller-owned plan keeps the hot hand-off fixed-size and
    // avoids copying the complete transaction into and out of the token.
    // The plan must outlive this token and stay immutable until `commit`.
    plan: *const Plan,
    consumed: bool = false,

    pub fn commit(
        self: *Prepared,
        cpu: *Cpu,
        exec_trace: *Trace,
        tracker: *StateChainTracker,
    ) CommitError!void {
        if (self.consumed) return error.AlreadyCommitted;
        if (!self.plan.runnerStateIsCurrent(cpu, exec_trace))
            return error.StaleRetirement;

        // This is the final fallible check. Everything following it is an
        // infallible direct write or assume-capacity append.
        if (!self.plan.accessStateIsCurrent(tracker))
            return error.StaleRetirement;
        self.plan.publishAssumeCapacity(cpu, exec_trace, tracker);
        self.consumed = true;
    }
};

/// Compile one LUI retirement against immutable runner snapshots. The typed
/// authority owns the architectural result; `access_transaction` owns aliases,
/// x0, predecessor clocks, and capacity geometry.
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
    const transaction = try access_transaction.compileLuiCompact(authority, tracker, .{
        .instruction = instruction,
        .instruction_clock = instruction_clock,
        .rs1_value = cpu.readReg(instruction.rs1),
        .rs2_value = cpu.readReg(instruction.rs2),
        .rd_previous_value = cpu.readReg(instruction.rd),
    });
    return .{
        .instruction = transaction.instruction,
        .instruction_clock = transaction.instruction_clock,
        .rs1_value = transaction.rs1_value,
        .rs2_value = transaction.rs2_value,
        .rd_previous_value = transaction.rd_previous_value,
        .rd_next_value = transaction.rd_next_value,
        .raw_previous_clock = transaction.raw_previous_clock,
        .previous_clock = transaction.previous_clock,
        .register_clock_update_count = transaction.register_clock_update_count,
        .pc_before = cpu.pc,
        .inst_word = inst_word,
        .expected_trace_len = exec_trace.rows.items.len,
    };
}

/// Fused production-shaped path: the authority-derived plan cannot escape or
/// be modified between staging and publication. With warm capacity there is
/// no external call in that interval; after cold allocation the complete live
/// snapshot is revalidated before the first logical write.
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
        (@as(u32, instruction.rd) << 7) | 0b0110111;
    const decoded_sources = @as(u10, instruction.rs1) |
        (@as(u10, instruction.rs2) << 5);
    return instruction.opcode == .LUI and
        inst_word == reconstructed and
        decoded_sources == @as(u10, @truncate(immediate_bits >> 15));
}

fn canonicalRow(
    plan: *const Plan,
) TraceRow {
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
        @compileError("typed LUI runner plan exceeded its fixed stack budget");
    if (@sizeOf(Prepared) > MAX_PREPARED_BYTES)
        @compileError("typed LUI prepared token exceeded its fixed stack budget");
}
