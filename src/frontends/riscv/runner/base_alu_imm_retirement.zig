//! Failure-atomic retirement for typed RV32 ADDI/XORI/ORI/ANDI.
//!
//! The typed authority is the sole architectural result/x0 authority. E-017's
//! generic access compiler is the sole rs1/rd alias and predecessor-clock
//! authority. Staging collapses its two-event transaction into a compact,
//! pointer-free plan; preparation reserves every fallible destination before
//! publication, and the warm fused path allocates nothing.

const std = @import("std");
const builtin = @import("builtin");
const access_clock = @import("../access_clock.zig");
const access_transaction = @import("../air/lang/access_transaction.zig");
const typed_addi = @import("../air/lang/typed_addi.zig");
const typed_authority = @import("../air/lang/typed_base_alu_imm_authority.zig");
const Cpu = @import("cpu.zig").Cpu;
const state_chain = @import("state_chain.zig");
const trace_mod = @import("trace.zig");

pub const StateChainTracker = state_chain.StateChainTracker;
pub const Trace = trace_mod.Trace;
pub const TraceRow = trace_mod.TraceRow;
pub const DecodedInst = typed_authority.DecodedInst;
pub const Authority = typed_authority.Authority;

pub const StageError = access_transaction.CompileError || error{
    InstructionClockMismatch,
    InstructionWordMismatch,
    TraceInvariantViolation,
};
pub const PrepareError = error{ OutOfMemory, StaleRetirement };
pub const CommitError = error{ AlreadyCommitted, StaleRetirement };
pub const RetireError = StageError || PrepareError;

pub const MAX_PLAN_BYTES: usize = 128;
pub const MAX_PREPARED_BYTES: usize = 16;

pub const PINNED_AUTHORITY = Authority.pinned();

pub fn authenticateCanonical(allocator: std.mem.Allocator) !Authority {
    var definition = try typed_addi.build(allocator, .generated);
    defer definition.deinit();
    const binding = try typed_authority.Binding.canonical(&definition);
    return typed_authority.Authority.init(&definition, &binding);
}

/// Compact two-register transaction. Raw predecessor clocks bind the live
/// tracker snapshot; effective predecessor clocks are the committed AIR row.
pub const Plan = struct {
    instruction: DecodedInst,
    instruction_clock: u32,
    pc_before: u32,
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
        if (!self.isCurrentFor(cpu, exec_trace, tracker))
            return error.StaleRetirement;
        try self.reserveAndRevalidate(cpu, exec_trace, tracker);
        return .{ .plan = self };
    }

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

        // Only allocator calls can re-enter external code. Warm retirement
        // proceeds directly from the already-authenticated stack-local plan.
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
        const source_clock = access_clock.encode(self.instruction_clock, .first);
        const destination_clock = access_clock.encode(self.instruction_clock, .second);
        tracker.recordRegTransitionAssumeCapacity(
            self.instruction.rs1,
            source_clock,
            self.rs1_value,
            self.rs1_value,
        );
        tracker.recordRegTransitionAssumeCapacity(
            self.instruction.rd,
            destination_clock,
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
            self.source_raw_previous_clock) return false;
        return self.instruction.rd == self.instruction.rs1 or
            tracker.reg_last_clk[self.instruction.rd] ==
                self.destination_raw_previous_clock;
    }

    fn isWellFormed(self: *const Plan) bool {
        const source_clock = access_clock.encode(self.instruction_clock, .first);
        const destination_clock = access_clock.encode(self.instruction_clock, .second);
        const aliased = self.instruction.rd == self.instruction.rs1;
        return instructionMatchesWord(self.instruction, self.inst_word) and
            self.instruction_clock != 0 and
            access_clock.maximum(self.instruction_clock) <
                state_chain.CLOCK_PREV_BOUND and
            typed_authority.acceptsRetirement(
                self.instruction,
                self.rs1_value,
                self.rd_next_value,
            ) and
            (self.instruction.rs1 != 0 or self.rs1_value == 0) and
            (self.instruction.rd != 0 or
                (self.rd_previous_value == 0 and self.rd_next_value == 0)) and
            self.source_raw_previous_clock < source_clock and
            self.source_previous_clock ==
                StateChainTracker.effectivePreviousClock(
                    self.source_raw_previous_clock,
                    source_clock,
                ) and
            self.source_gap_count == StateChainTracker.clockGapCount(
                self.source_raw_previous_clock,
                source_clock,
            ) and
            self.destination_raw_previous_clock ==
                (if (aliased) source_clock else self.destination_raw_previous_clock) and
            (!aliased or self.rd_previous_value == self.rs1_value) and
            self.destination_raw_previous_clock < destination_clock and
            self.destination_previous_clock ==
                StateChainTracker.effectivePreviousClock(
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
        if (!self.plan.isCurrentFor(cpu, exec_trace, tracker)) {
            return error.StaleRetirement;
        }
        self.plan.publishAssumeCapacity(cpu, exec_trace, tracker);
        self.consumed = true;
    }
};

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
    const rd_previous_value = cpu.readReg(instruction.rd);
    const transaction = try access_transaction.compileBaseAluImmCompact(authority, tracker, .{
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
        .source_raw_previous_clock = transaction.source_raw_previous_clock,
        .source_previous_clock = transaction.source_previous_clock,
        .destination_raw_previous_clock = transaction.destination_raw_previous_clock,
        .destination_previous_clock = transaction.destination_previous_clock,
        .source_gap_count = transaction.source_gap_count,
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
    if (exec_trace.step_count != exec_trace.rows.items.len)
        return error.TraceInvariantViolation;
    if (!exec_trace.expectsNextCoreRetirement(instruction_clock))
        return error.InstructionClockMismatch;
    if (!instructionMatchesWord(instruction, inst_word))
        return error.InstructionWordMismatch;

    // Keep the fused production path in the compact form. Materializing the
    // larger, independently reusable `Plan` here added avoidable stack traffic
    // to every warm retirement even though its fields are consumed once.
    const pc_before = cpu.pc;
    const rs1_value = cpu.readReg(instruction.rs1);
    const rs2_value = cpu.readReg(instruction.rs2);
    const rd_previous_value = cpu.readReg(instruction.rd);
    const transaction = try access_transaction.compileBaseAluImmCompact(
        authority,
        tracker,
        .{
            .instruction = instruction,
            .instruction_clock = instruction_clock,
            .rs1_value = rs1_value,
            .rs2_value = rs2_value,
            .rd_previous_value = rd_previous_value,
        },
    );
    const expected_trace_len = exec_trace.rows.items.len;
    const register_gap_count = transaction.source_gap_count +
        transaction.destination_gap_count;
    const trace_needs_growth = exec_trace.rows.capacity - expected_trace_len < 1;
    const access_needs_growth = tracker.accesses.capacity -
        tracker.accesses.items.len < 2;
    const gaps_need_growth = tracker.clock_updates_reg.capacity -
        tracker.clock_updates_reg.items.len < register_gap_count;
    if (trace_needs_growth) try exec_trace.reserveOne();
    if (access_needs_growth or gaps_need_growth) try tracker.reserveTransitions(.{
        .memory_address_count = 0,
        .access_count = 2,
        .memory_clock_update_count = 0,
        .register_clock_update_count = register_gap_count,
    });

    if (trace_needs_growth or access_needs_growth or gaps_need_growth) {
        if (cpu.pc != pc_before or
            cpu.readReg(instruction.rs1) != rs1_value or
            cpu.readReg(instruction.rs2) != rs2_value or
            cpu.readReg(instruction.rd) != rd_previous_value or
            exec_trace.rows.items.len != expected_trace_len or
            exec_trace.step_count != expected_trace_len or
            !exec_trace.expectsNextCoreRetirement(instruction_clock) or
            tracker.reg_last_clk[instruction.rs1] !=
                transaction.source_raw_previous_clock or
            (instruction.rd != instruction.rs1 and
                tracker.reg_last_clk[instruction.rd] !=
                    transaction.destination_raw_previous_clock))
        {
            return error.StaleRetirement;
        }
    }

    if (comptime builtin.mode == .Debug) {
        const plan = compactPlan(
            transaction,
            pc_before,
            inst_word,
            expected_trace_len,
        );
        std.debug.assert(plan.isCurrentFor(cpu, exec_trace, tracker));
    }
    publishCompactAssumeCapacity(
        &transaction,
        pc_before,
        inst_word,
        cpu,
        exec_trace,
        tracker,
    );
}

inline fn compactPlan(
    transaction: access_transaction.BaseAluImmTransaction,
    pc_before: u32,
    inst_word: u32,
    expected_trace_len: usize,
) Plan {
    return .{
        .instruction = transaction.instruction,
        .instruction_clock = transaction.instruction_clock,
        .pc_before = pc_before,
        .inst_word = inst_word,
        .rs1_value = transaction.rs1_value,
        .rs2_value = transaction.rs2_value,
        .rd_previous_value = transaction.rd_previous_value,
        .rd_next_value = transaction.rd_next_value,
        .source_raw_previous_clock = transaction.source_raw_previous_clock,
        .source_previous_clock = transaction.source_previous_clock,
        .destination_raw_previous_clock = transaction.destination_raw_previous_clock,
        .destination_previous_clock = transaction.destination_previous_clock,
        .source_gap_count = transaction.source_gap_count,
        .destination_gap_count = transaction.destination_gap_count,
        .expected_trace_len = expected_trace_len,
    };
}

inline fn publishCompactAssumeCapacity(
    transaction: *const access_transaction.BaseAluImmTransaction,
    pc_before: u32,
    inst_word: u32,
    cpu: *Cpu,
    exec_trace: *Trace,
    tracker: *StateChainTracker,
) void {
    tracker.recordRegTransitionAssumeCapacity(
        transaction.instruction.rs1,
        access_clock.encode(transaction.instruction_clock, .first),
        transaction.rs1_value,
        transaction.rs1_value,
    );
    tracker.recordRegTransitionAssumeCapacity(
        transaction.instruction.rd,
        access_clock.encode(transaction.instruction_clock, .second),
        transaction.rd_previous_value,
        transaction.rd_next_value,
    );
    cpu.writeReg(transaction.instruction.rd, transaction.rd_next_value);
    cpu.pc = pc_before +% 4;
    exec_trace.appendAssumeCapacity(.{
        .clk = transaction.instruction_clock,
        .pc = pc_before,
        .opcode = transaction.instruction.opcode,
        .rd = transaction.instruction.rd,
        .rs1 = transaction.instruction.rs1,
        .rs2 = transaction.instruction.rs2,
        .imm = transaction.instruction.imm,
        .rs1_val = transaction.rs1_value,
        .rs2_val = transaction.rs2_value,
        .rs1_prev_clk = transaction.source_previous_clock,
        .rs2_prev_clk = 0,
        .rd_prev_val = transaction.rd_previous_value,
        .rd_prev_clk = transaction.destination_previous_clock,
        .rd_val = transaction.rd_next_value,
        .mem_addr = 0,
        .mem_val = 0,
        .mem_prev_word = 0,
        .mem_next_word = 0,
        .mem_prev_clk = 0,
        .is_load = false,
        .is_store = false,
        .branch_taken = false,
        .next_pc = pc_before +% 4,
        .inst_word = inst_word,
    });
}

inline fn instructionMatchesWord(instruction: DecodedInst, inst_word: u32) bool {
    const funct3: u3 = switch (instruction.opcode) {
        .ADDI => 0b000,
        .XORI => 0b100,
        .ORI => 0b110,
        .ANDI => 0b111,
        else => return false,
    };
    if (instruction.imm < -2048 or instruction.imm > 2047) return false;
    const immediate_bits = @as(u32, @bitCast(instruction.imm)) & 0xfff;
    const reconstructed = (immediate_bits << 20) |
        (@as(u32, instruction.rs1) << 15) |
        (@as(u32, funct3) << 12) |
        (@as(u32, instruction.rd) << 7) |
        0b0010011;
    return instruction.rs2 == @as(u5, @truncate(immediate_bits)) and
        inst_word == reconstructed;
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
        .branch_taken = false,
        .next_pc = plan.pc_before +% 4,
        .inst_word = plan.inst_word,
    };
}

comptime {
    if (@sizeOf(Plan) > MAX_PLAN_BYTES)
        @compileError("typed BASE_ALU_IMM retirement plan exceeded its stack budget");
    if (@sizeOf(Prepared) > MAX_PREPARED_BYTES)
        @compileError("typed BASE_ALU_IMM prepared token exceeded its stack budget");
}
