//! Failure-atomic retirement for the typed RV32 load/store authority.
//!
//! The fixed authority is the single source of architectural addressing,
//! alignment, sign extension, partial-word stores, x0 discard, witness, roots,
//! and ordered relations. This family-private boundary owns exact I/S word
//! admission, three protocol-ordered accesses, sparse-memory preflight, stale
//! transaction rejection, and atomic CPU/memory/trace/state-chain publication.
//! Staging and the prepared warm path allocate nothing.

const std = @import("std");
const builtin = @import("builtin");
const access_clock = @import("../access_clock.zig");
const typed = @import("../air/lang/typed_load_store.zig");
const typed_authority = @import("../air/lang/typed_load_store_authority.zig");
const Cpu = @import("cpu.zig").Cpu;
const Opcode = @import("decode.zig").Opcode;
const Memory = @import("memory.zig").Memory;
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
    StateChainInvariantViolation,
    TraceInvariantViolation,
    ZeroRegisterValue,
};
pub const PrepareError = error{ OutOfMemory, StaleRetirement };
pub const CommitError = error{ AlreadyCommitted, StaleRetirement };
pub const RetireError = StageError || PrepareError;

// One natural word of headroom catches accidental hot-stack footprint creep.
pub const MAX_PLAN_BYTES: usize = 96;
pub const MAX_PREPARED_BYTES: usize = 16;

pub const PINNED_AUTHORITY = Authority.pinned();

pub fn authenticateCanonical(allocator: std.mem.Allocator) !Authority {
    var definition = try typed.build(allocator, .generated);
    defer definition.deinit();
    const binding = try typed_authority.Binding.canonical(&definition);
    return typed_authority.Authority.init(&definition, &binding);
}

/// Pointer-free snapshot of one load/store retirement. Only raw predecessor
/// clocks are retained: effective predecessors and gap counts are cheap scalar
/// derivations, avoiding six redundant words in every staged transaction.
pub const Plan = struct {
    instruction: DecodedInst,
    instruction_clock: u32,
    pc_before: u32,
    inst_word: u32,
    rs1_value: u32,
    rs2_value: u32,
    rd_previous_value: u32,
    rd_next_value: u32,
    memory_address: u32,
    memory_previous_word: u32,
    memory_next_word: u32,
    first_raw_previous_clock: u32,
    second_raw_previous_clock: u32,
    memory_raw_previous_clock: u32,
    memory_initial_value: u32,
    expected_access_len: u32,
    expected_memory_gap_len: u32,
    expected_register_gap_len: u32,
    expected_trace_len: usize,
    memory_last_was_present: bool,
    memory_initial_was_present: bool,
    memory_word_was_initialized: bool,

    pub inline fn traceRow(self: *const Plan) TraceRow {
        return canonicalRow(self);
    }

    pub inline fn alignedAddress(self: *const Plan) u32 {
        return self.memory_address & ~@as(u32, 3);
    }

    pub inline fn isLoad(self: *const Plan) bool {
        return typed_authority.isLoadOpcode(self.instruction.opcode);
    }

    pub inline fn reservation(self: *const Plan) StateChainTracker.Reservation {
        const first = access_clock.encode(self.instruction_clock, .first);
        const second = access_clock.encode(self.instruction_clock, .second);
        const third = access_clock.encode(self.instruction_clock, .third);
        return .{
            .memory_address_count = @intFromBool(
                !self.memory_last_was_present or
                    !self.memory_initial_was_present,
            ),
            .access_count = 3,
            .memory_clock_update_count = state_chain.StateChainTracker.clockGapCount(
                self.memory_raw_previous_clock,
                third,
            ),
            .register_clock_update_count = state_chain.StateChainTracker.clockGapCount(
                self.first_raw_previous_clock,
                first,
            ) + state_chain.StateChainTracker.clockGapCount(
                self.second_raw_previous_clock,
                second,
            ),
        };
    }

    pub fn isCurrentFor(
        self: *const Plan,
        cpu: *const Cpu,
        memory: *const Memory,
        trace: *const Trace,
        tracker: *const StateChainTracker,
    ) bool {
        return self.isWellFormed() and
            self.runnerStateIsCurrent(cpu, memory, trace) and
            self.accessStateIsCurrent(tracker);
    }

    pub fn prepare(
        self: *const Plan,
        cpu: *const Cpu,
        memory: *Memory,
        trace: *Trace,
        tracker: *StateChainTracker,
    ) PrepareError!Prepared {
        if (!self.isCurrentFor(cpu, memory, trace, tracker))
            return error.StaleRetirement;
        try self.reserveAndRevalidate(cpu, memory, trace, tracker);
        return .{ .plan = self };
    }

    pub fn commitAtomic(
        self: *const Plan,
        cpu: *Cpu,
        memory: *Memory,
        trace: *Trace,
        tracker: *StateChainTracker,
    ) PrepareError!void {
        if (!self.isCurrentFor(cpu, memory, trace, tracker))
            return error.StaleRetirement;
        try self.reserveAndRevalidate(cpu, memory, trace, tracker);
        self.publishAssumeCapacity(cpu, memory, trace, tracker);
    }

    inline fn reserveAndRevalidate(
        self: *const Plan,
        cpu: *const Cpu,
        memory: *Memory,
        trace: *Trace,
        tracker: *StateChainTracker,
    ) PrepareError!void {
        const required = self.reservation();
        const trace_needs_growth = trace.rows.capacity -
            trace.rows.items.len < 1;
        const tracker_needs_growth = !trackerHasCapacity(tracker, required);
        const memory_needs_preparation = !self.isLoad() and
            !memory.alignedWordWriteIsPrepared(self.alignedAddress());

        if (trace_needs_growth) try trace.reserveOne();
        if (tracker_needs_growth) try tracker.reserveTransitions(required);
        if (memory_needs_preparation)
            try memory.prepareAlignedWordWrites(&.{self.alignedAddress()});

        if ((trace_needs_growth or tracker_needs_growth or
            memory_needs_preparation) and
            (!self.isCurrentFor(cpu, memory, trace, tracker) or
                !self.hasPreparedCapacity(memory, trace, tracker)))
        {
            return error.StaleRetirement;
        }
    }

    inline fn hasPreparedCapacity(
        self: *const Plan,
        memory: *const Memory,
        trace: *const Trace,
        tracker: *const StateChainTracker,
    ) bool {
        return trace.rows.capacity - trace.rows.items.len >= 1 and
            trackerHasCapacity(tracker, self.reservation()) and
            (self.isLoad() or
                memory.alignedWordWriteIsPrepared(self.alignedAddress()));
    }

    inline fn publishAssumeCapacity(
        self: *const Plan,
        cpu: *Cpu,
        memory: *Memory,
        trace: *Trace,
        tracker: *StateChainTracker,
    ) void {
        publishEventsAssumeCapacity(self, tracker);
        if (self.isLoad()) {
            cpu.writeReg(self.instruction.rd, self.rd_next_value);
        } else {
            memory.writeU32AssumePrepared(
                self.alignedAddress(),
                self.memory_next_word,
            );
        }
        cpu.pc +%= 4;
        trace.appendAssumeCapacity(self.traceRow());
    }

    inline fn runnerStateIsCurrent(
        self: *const Plan,
        cpu: *const Cpu,
        memory: *const Memory,
        trace: *const Trace,
    ) bool {
        return cpu.pc == self.pc_before and
            cpu.readReg(self.instruction.rs1) == self.rs1_value and
            (if (self.isLoad())
                cpu.readReg(self.instruction.rd) == self.rd_previous_value
            else
                cpu.readReg(self.instruction.rs2) == self.rs2_value) and
            memory.readU32(self.alignedAddress()) ==
                self.memory_previous_word and
            memory.initialized_words.contains(self.alignedAddress()) ==
                self.memory_word_was_initialized and
            trace.rows.items.len == self.expected_trace_len and
            trace.step_count == self.expected_trace_len;
    }

    inline fn accessStateIsCurrent(
        self: *const Plan,
        tracker: *const StateChainTracker,
    ) bool {
        if (tracker.reg_last_clk[self.instruction.rs1] !=
            self.first_raw_previous_clock)
        {
            return false;
        }
        const second_register = if (self.isLoad())
            self.instruction.rd
        else
            self.instruction.rs2;
        if (second_register != self.instruction.rs1 and
            tracker.reg_last_clk[second_register] !=
                self.second_raw_previous_clock)
        {
            return false;
        }

        const aligned = self.alignedAddress();
        const last = tracker.mem_last_clk.get(aligned);
        if ((last != null) != self.memory_last_was_present or
            (last orelse 0) != self.memory_raw_previous_clock)
        {
            return false;
        }
        const initial = tracker.mem_initial.get(aligned);
        return (initial != null) == self.memory_initial_was_present and
            (initial orelse 0) == self.memory_initial_value and
            tracker.accesses.items.len == self.expected_access_len and
            tracker.clock_updates_mem.items.len == self.expected_memory_gap_len and
            tracker.clock_updates_reg.items.len == self.expected_register_gap_len;
    }

    fn isWellFormed(self: *const Plan) bool {
        if (self.instruction_clock == 0 or
            access_clock.maximum(self.instruction_clock) >=
                state_chain.CLOCK_PREV_BOUND or
            !traceClockMatches(self.expected_trace_len, self.instruction_clock) or
            !instructionMatchesWord(self.instruction, self.inst_word))
        {
            return false;
        }
        const first = access_clock.encode(self.instruction_clock, .first);
        const second = access_clock.encode(self.instruction_clock, .second);
        const third = access_clock.encode(self.instruction_clock, .third);
        if (self.first_raw_previous_clock >= first or
            self.second_raw_previous_clock >= second or
            self.memory_raw_previous_clock >= third)
        {
            return false;
        }

        const is_load = self.isLoad();
        const second_register = if (is_load)
            self.instruction.rd
        else
            self.instruction.rs2;
        const second_value = if (is_load)
            self.rd_previous_value
        else
            self.rs2_value;
        if ((self.instruction.rs1 == 0 and self.rs1_value != 0) or
            (self.instruction.rs2 == 0 and self.rs2_value != 0) or
            (self.instruction.rd == 0 and
                (self.rd_previous_value != 0 or self.rd_next_value != 0)) or
            (second_register == self.instruction.rs1 and
                (second_value != self.rs1_value or
                    self.second_raw_previous_clock != first)) or
            (self.memory_last_was_present !=
                self.memory_initial_was_present) or
            (!self.memory_last_was_present and
                self.memory_raw_previous_clock != 0) or
            (!self.memory_initial_was_present and
                self.memory_initial_value != 0))
        {
            return false;
        }

        const retired = typed_authority.canonicalRetirement(
            self.instruction,
            self.rs1_value,
            self.rs2_value,
            self.memory_previous_word,
        ) catch return false;
        return retired.is_load == is_load and
            retired.address == self.memory_address and
            retired.aligned_address == self.alignedAddress() and
            retired.write_register == (is_load and self.instruction.rd != 0) and
            retired.write_memory == !is_load and
            (!is_load or retired.register_value == self.rd_next_value) and
            retired.memory_next_word == self.memory_next_word and
            (is_load or self.rd_next_value == self.rd_previous_value) and
            (!is_load or self.memory_next_word == self.memory_previous_word);
    }
};

pub const Prepared = struct {
    plan: *const Plan,
    consumed: bool = false,

    pub fn commit(
        self: *Prepared,
        cpu: *Cpu,
        memory: *Memory,
        trace: *Trace,
        tracker: *StateChainTracker,
    ) CommitError!void {
        if (self.consumed) return error.AlreadyCommitted;
        if (!self.plan.isCurrentFor(cpu, memory, trace, tracker) or
            !self.plan.hasPreparedCapacity(memory, trace, tracker))
        {
            return error.StaleRetirement;
        }
        self.plan.publishAssumeCapacity(cpu, memory, trace, tracker);
        self.consumed = true;
    }
};

pub inline fn stage(
    authority: *const Authority,
    cpu: *const Cpu,
    memory: *const Memory,
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

    const is_load = typed_authority.isLoadOpcode(instruction.opcode);
    const rs1_value = cpu.readReg(instruction.rs1);
    // Decoder overlap fields (`rs2` for I-type loads and `rd` for S-type
    // stores) are encoding evidence, not architectural register operands.
    // Keep their unused value dimensions canonical instead of snapshotting
    // unrelated register state into the retirement plan and trace row.
    const rs2_value = if (is_load) 0 else cpu.readReg(instruction.rs2);
    const rd_previous = if (is_load) cpu.readReg(instruction.rd) else 0;
    const provisional_address = rs1_value +%
        @as(u32, @bitCast(instruction.imm));
    const aligned_address = provisional_address & ~@as(u32, 3);
    const memory_previous = memory.readU32(aligned_address);
    const retirement = try authority.retire(
        instruction,
        rs1_value,
        rs2_value,
        memory_previous,
    );
    const rd_next = if (retirement.is_load)
        retirement.register_value
    else
        rd_previous;
    if ((instruction.rs1 == 0 and rs1_value != 0) or
        (instruction.rs2 == 0 and rs2_value != 0) or
        (instruction.rd == 0 and (rd_previous != 0 or rd_next != 0)))
    {
        return error.ZeroRegisterValue;
    }

    const first = access_clock.encode(instruction_clock, .first);
    const second = access_clock.encode(instruction_clock, .second);
    const third = access_clock.encode(instruction_clock, .third);
    const first_raw = tracker.reg_last_clk[instruction.rs1];
    if (first_raw >= first) return error.NonIncreasingClock;
    const second_register = if (is_load)
        instruction.rd
    else
        instruction.rs2;
    const second_raw = if (second_register == instruction.rs1)
        first
    else
        tracker.reg_last_clk[second_register];
    if (second_raw >= second) return error.NonIncreasingClock;

    const memory_last = tracker.mem_last_clk.get(retirement.aligned_address);
    const memory_initial = tracker.mem_initial.get(retirement.aligned_address);
    if ((memory_last != null) != (memory_initial != null) or
        (memory_last != null and memory_last.? == 0))
    {
        return error.StateChainInvariantViolation;
    }
    const memory_raw = memory_last orelse 0;
    if (memory_raw >= third) return error.NonIncreasingClock;

    return .{
        .instruction = instruction,
        .instruction_clock = instruction_clock,
        .pc_before = cpu.pc,
        .inst_word = inst_word,
        .rs1_value = rs1_value,
        .rs2_value = rs2_value,
        .rd_previous_value = rd_previous,
        .rd_next_value = rd_next,
        .memory_address = retirement.address,
        .memory_previous_word = memory_previous,
        .memory_next_word = retirement.memory_next_word,
        .first_raw_previous_clock = first_raw,
        .second_raw_previous_clock = second_raw,
        .memory_raw_previous_clock = memory_raw,
        .memory_initial_value = memory_initial orelse 0,
        .expected_access_len = std.math.cast(u32, tracker.accesses.items.len) orelse
            return error.StateChainInvariantViolation,
        .expected_memory_gap_len = std.math.cast(
            u32,
            tracker.clock_updates_mem.items.len,
        ) orelse return error.StateChainInvariantViolation,
        .expected_register_gap_len = std.math.cast(
            u32,
            tracker.clock_updates_reg.items.len,
        ) orelse return error.StateChainInvariantViolation,
        .expected_trace_len = trace.rows.items.len,
        .memory_last_was_present = memory_last != null,
        .memory_initial_was_present = memory_initial != null,
        .memory_word_was_initialized = memory.initialized_words.contains(retirement.aligned_address),
    };
}

/// Fused production path. The scalar transaction stays on the stack and skips
/// every reserve helper once trace, tracker, and sparse memory are warm.
pub inline fn retireAtomic(
    authority: *const Authority,
    cpu: *Cpu,
    memory: *Memory,
    trace: *Trace,
    tracker: *StateChainTracker,
    instruction: DecodedInst,
    inst_word: u32,
    instruction_clock: u32,
) RetireError!void {
    const plan = try stage(
        authority,
        cpu,
        memory,
        trace,
        tracker,
        instruction,
        inst_word,
        instruction_clock,
    );
    if (comptime builtin.mode == .Debug)
        std.debug.assert(plan.isCurrentFor(cpu, memory, trace, tracker));
    try plan.reserveAndRevalidate(cpu, memory, trace, tracker);
    plan.publishAssumeCapacity(cpu, memory, trace, tracker);
}

pub inline fn instructionMatchesWord(
    instruction: DecodedInst,
    inst_word: u32,
) bool {
    return typed_authority.instructionMatchesWord(instruction, inst_word);
}

inline fn traceClockMatches(trace_len: usize, instruction_clock: u32) bool {
    if (trace_len >= std.math.maxInt(u32)) return false;
    return instruction_clock == @as(u32, @intCast(trace_len)) + 1;
}

inline fn trackerHasCapacity(
    tracker: *const StateChainTracker,
    required: StateChainTracker.Reservation,
) bool {
    return hashMapUnusedCapacity(tracker.mem_initial) >=
        required.memory_address_count and
        hashMapUnusedCapacity(tracker.mem_last_clk) >=
            required.memory_address_count and
        tracker.accesses.capacity - tracker.accesses.items.len >=
            required.access_count and
        tracker.clock_updates_mem.capacity -
            tracker.clock_updates_mem.items.len >=
            required.memory_clock_update_count and
        tracker.clock_updates_reg.capacity -
            tracker.clock_updates_reg.items.len >=
            required.register_clock_update_count;
}

inline fn hashMapUnusedCapacity(map: anytype) usize {
    const maximum_entries = map.capacity() *
        std.hash_map.default_max_load_percentage / 100;
    return maximum_entries - map.count();
}

inline fn publishEventsAssumeCapacity(
    plan: *const Plan,
    tracker: *StateChainTracker,
) void {
    const first = access_clock.encode(plan.instruction_clock, .first);
    const second = access_clock.encode(plan.instruction_clock, .second);
    const third = access_clock.encode(plan.instruction_clock, .third);
    publishRegisterAssumeCapacity(
        tracker,
        plan.instruction.rs1,
        first,
        plan.rs1_value,
        plan.rs1_value,
        plan.first_raw_previous_clock,
    );
    if (plan.isLoad()) {
        publishRegisterAssumeCapacity(
            tracker,
            plan.instruction.rd,
            second,
            plan.rd_previous_value,
            plan.rd_next_value,
            plan.second_raw_previous_clock,
        );
    } else {
        publishRegisterAssumeCapacity(
            tracker,
            plan.instruction.rs2,
            second,
            plan.rs2_value,
            plan.rs2_value,
            plan.second_raw_previous_clock,
        );
    }
    publishMemoryAssumeCapacity(
        tracker,
        plan.alignedAddress(),
        third,
        plan.memory_previous_word,
        plan.memory_next_word,
        plan.memory_raw_previous_clock,
    );
}

inline fn publishRegisterAssumeCapacity(
    tracker: *StateChainTracker,
    register: u5,
    current_clock: u32,
    previous_value: u32,
    next_value: u32,
    raw_previous_clock: u32,
) void {
    const gap_count = StateChainTracker.clockGapCount(
        raw_previous_clock,
        current_clock,
    );
    if (gap_count != 0) {
        tracker.recordRegTransitionAssumeCapacity(
            register,
            current_clock,
            previous_value,
            next_value,
        );
        return;
    }
    tracker.accesses.appendAssumeCapacity(.{
        .addr_space = 0,
        .addr = register,
        .clk = current_clock,
        .value = next_value,
        .clk_prev = raw_previous_clock,
    });
    tracker.reg_last_clk[register] = current_clock;
}

inline fn publishMemoryAssumeCapacity(
    tracker: *StateChainTracker,
    address: u32,
    current_clock: u32,
    previous_value: u32,
    next_value: u32,
    raw_previous_clock: u32,
) void {
    const gap_count = StateChainTracker.clockGapCount(
        raw_previous_clock,
        current_clock,
    );
    if (gap_count != 0) {
        tracker.recordMemTransitionAssumeCapacity(
            address,
            current_clock,
            previous_value,
            next_value,
        );
        return;
    }
    const initial = tracker.mem_initial.getOrPutAssumeCapacity(address);
    if (!initial.found_existing) initial.value_ptr.* = previous_value;
    tracker.accesses.appendAssumeCapacity(.{
        .addr_space = 1,
        .addr = address,
        .clk = current_clock,
        .value = next_value,
        .clk_prev = raw_previous_clock,
    });
    tracker.mem_last_clk.putAssumeCapacity(address, current_clock);
}

inline fn canonicalRow(plan: *const Plan) TraceRow {
    const first = access_clock.encode(plan.instruction_clock, .first);
    const second = access_clock.encode(plan.instruction_clock, .second);
    const third = access_clock.encode(plan.instruction_clock, .third);
    const first_previous = StateChainTracker.effectivePreviousClock(
        plan.first_raw_previous_clock,
        first,
    );
    const second_previous = StateChainTracker.effectivePreviousClock(
        plan.second_raw_previous_clock,
        second,
    );
    const memory_previous = StateChainTracker.effectivePreviousClock(
        plan.memory_raw_previous_clock,
        third,
    );
    const is_load = plan.isLoad();
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
        .rs1_prev_clk = first_previous,
        .rs2_prev_clk = if (is_load) 0 else second_previous,
        .rd_prev_val = plan.rd_previous_value,
        .rd_prev_clk = if (is_load) second_previous else 0,
        .rd_val = plan.rd_next_value,
        .mem_addr = plan.memory_address,
        .mem_val = if (is_load)
            rawLoadValue(
                plan.instruction.opcode,
                plan.memory_previous_word,
                plan.memory_address,
            )
        else
            plan.rs2_value,
        .mem_prev_word = plan.memory_previous_word,
        .mem_next_word = plan.memory_next_word,
        .mem_prev_clk = memory_previous,
        .is_load = is_load,
        .is_store = !is_load,
        .branch_taken = false,
        .next_pc = plan.pc_before +% 4,
        .inst_word = plan.inst_word,
    };
}

inline fn rawLoadValue(opcode: Opcode, word: u32, address: u32) u32 {
    const amount: u5 = @intCast((address & 3) * 8);
    return switch (opcode) {
        .LB, .LBU => @as(u8, @truncate(word >> amount)),
        .LH, .LHU => @as(u16, @truncate(word >> amount)),
        .LW => word,
        else => unreachable,
    };
}

comptime {
    if (@sizeOf(Plan) > MAX_PLAN_BYTES)
        @compileError("typed LOAD_STORE retirement plan exceeded its stack budget");
    if (@sizeOf(Prepared) > MAX_PREPARED_BYTES)
        @compileError("typed LOAD_STORE prepared token exceeded its stack budget");
}
