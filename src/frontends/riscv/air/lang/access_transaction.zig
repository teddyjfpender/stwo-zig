//! Failure-atomic runtime access transactions for generated typed rows.
//!
//! This module compiles one completed architectural retirement into a
//! fixed-size, numeric transaction before a
//! trace row is published. Compilation resolves register aliases, x0, physical
//! subclocks, predecessor clocks, synthetic clock gaps, and load/store word
//! transitions without allocating. Capacity reservation is a separate cold
//! step; the prepared commit performs no allocation and cannot partially fail.
//! BASE_ALU_IMM and LUI consume fixed projections of this authority in
//! production; the generic transaction is also the executable oracle for later
//! family cutovers.
//!
//! Loads retain Stark-V compatibility's nontrivial split:
//!
//!   logical order:  rs1(1), memory source(2), rd destination(3)
//!   physical phase: rs1(1), rd destination(2), memory source(3)
//!
//! Events are stored in physical-clock order so committing them is monotonic.

const std = @import("std");
const access_clock = @import("../../access_clock.zig");
const decode = @import("../../isa/decode.zig");
const state_chain = @import("../../runner/state_chain.zig");
const trace_row = @import("../../runner/trace_row.zig");
const typed_fence_authority = @import("typed_fence_authority.zig");
const typed_base_alu_imm_authority = @import("typed_base_alu_imm_authority.zig");
const typed_lui_authority = @import("typed_lui_authority.zig");
const types = @import("types.zig");
const transaction_support = @import("access_transaction_support.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const MAX_EVENTS: usize = 3;
pub const MAX_TRANSACTION_BYTES: usize = 256;

/// Recursive segment statements already bind read/write addresses below 2^30.
/// The load/store AIR now proves the same bound with a low20/high8 word-index
/// decomposition, so execution and proof admission share one exact ceiling.
pub const MAX_ALIGNED_DATA_ADDRESS: u32 = (@as(u32, 1) << 30) - 4;
/// `range_check_m31` admits the canonical integers below the M31 modulus.
pub const M31_MODULUS: u32 = 0x7fff_ffff;

pub const DecodedInst = decode.DecodedInst;
pub const TraceRow = trace_row.TraceRow;
pub const StateChainTracker = state_chain.StateChainTracker;

pub const CompileError = error{
    AliasedRegisterValueMismatch,
    ClockOutOfRange,
    LoadResultMismatch,
    MemoryAddressMisaligned,
    MemoryAddressOutOfRange,
    MemoryBaseOutOfRange,
    MemoryTransitionMismatch,
    MissingMemoryWords,
    NonIncreasingClock,
    UnexpectedMemoryWords,
    InvalidFenceImmediate,
    InvalidBaseAluImmImmediate,
    WrongBaseAluImmOpcode,
    WrongFenceOpcode,
    WrongLuiOpcode,
    ZeroRegisterValue,
};

pub const ProjectionError = error{RowProjectionMismatch};
pub const PrepareError = error{ OutOfMemory, StaleTransaction };
pub const CommitError = error{ AlreadyCommitted, StaleTransaction };

pub const EventKind = enum(u8) {
    register_read,
    register_write,
    memory_read,
    memory_write,
};

/// One state-chain transition. Memory masks are relative to the aligned word,
/// not to the effective byte address. Register transitions always cover all
/// four bytes.
pub const Event = struct {
    kind: EventKind,
    logical_ordinal: types.AccessOrdinal,
    physical_phase: types.AccessPhase,
    address: u32,
    raw_previous_clock: u32,
    previous_clock: u32,
    current_clock: u32,
    previous_value: u32,
    next_value: u32,
    read_mask: u4,
    write_mask: u4,

    pub inline fn addressSpace(self: Event) u1 {
        return switch (self.kind) {
            .register_read, .register_write => 0,
            .memory_read, .memory_write => 1,
        };
    }
};

/// Memory state sampled immediately before and after successful execution.
/// The compiler derives the address, transfer value, and masks itself.
pub const MemoryWords = struct {
    previous: u32,
    next: u32,
};

pub const Input = struct {
    instruction: DecodedInst,
    instruction_clock: u32,
    rs1_value: u32,
    rs2_value: u32,
    rd_previous_value: u32,
    rd_next_value: u32,
    memory_words: ?MemoryWords = null,
};

/// LUI's runner snapshot. Encoding-only `rs1`/`rs2` fields are retained
/// because the canonical execution trace records their pre-retirement values
/// even though they are not architectural operands.
pub const LuiInput = struct {
    instruction: DecodedInst,
    instruction_clock: u32,
    rs1_value: u32,
    rs2_value: u32,
    rd_previous_value: u32,
};

pub const BaseAluImmInput = struct {
    instruction: DecodedInst,
    instruction_clock: u32,
    rs1_value: u32,
    rs2_value: u32,
    rd_previous_value: u32,
};

/// Minimal two-register projection for BASE_ALU_IMM's fixed source/destination
/// geometry. It is authenticated against the generic transaction compiler in
/// tests, but avoids carrying an impossible third event and memory facts in
/// the production runner hot loop.
pub const BaseAluImmTransaction = struct {
    instruction: DecodedInst,
    instruction_clock: u32,
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
};

/// Minimal, pointer-free LUI projection used by the fused runner hot path.
/// The generic `Transaction` remains the cross-family compiler form; carrying
/// its three-event/memory capacity through a one-register instruction measured
/// as avoidable bandwidth after the semantic boundary was already closed.
pub const LuiTransaction = struct {
    instruction: DecodedInst,
    instruction_clock: u32,
    rs1_value: u32,
    rs2_value: u32,
    rd_previous_value: u32,
    rd_next_value: u32,
    raw_previous_clock: u32,
    previous_clock: u32,
    register_clock_update_count: usize,
};

/// FENCE's runner snapshot. Reserved register fields are trace-visible but
/// have no architectural access semantics. `pc_before` binds the typed
/// authority's sequential retirement result even though the access
/// transaction itself owns only state-chain geometry.
pub const FenceInput = struct {
    instruction: DecodedInst,
    instruction_clock: u32,
    pc_before: u32,
    rs1_value: u32,
    rs2_value: u32,
    rd_previous_value: u32,
};

pub const MemoryFacts = struct {
    effective_address: u32,
    aligned_address: u32,
    width_bytes: u3,
    byte_offset: u2,
    /// Low `width_bytes` bits, relative to the effective byte address. This is
    /// the convention used by the RVFI-compatible trace dump.
    addressed_mask: u4,
    /// Masks relative to `aligned_address`, used by the word transition.
    word_read_mask: u4,
    word_write_mask: u4,
    transferred_value: u32,
    previous_word: u32,
    next_word: u32,
    previous_clock: u32,
    current_clock: u32,
};

pub const RowProjection = struct {
    rs1_previous_clock: u32,
    rs2_previous_clock: u32,
    rd_previous_clock: u32,
    memory: ?MemoryFacts,
};

/// Fixed-size compiled boundary. It contains no pointers, allocator, strings,
/// or runtime dispatch table and can be copied into a prepared batch.
pub const Transaction = struct {
    format_version: u16,
    instruction: DecodedInst,
    instruction_clock: u32,
    usage: decode.OperandUsage,
    rs1_value: u32,
    rs2_value: u32,
    rd_previous_value: u32,
    rd_next_value: u32,
    events: [MAX_EVENTS]Event,
    event_count: u2,
    row_projection: RowProjection,
    reservation: StateChainTracker.Reservation,

    pub inline fn accessEvents(self: *const Transaction) []const Event {
        return self.events[0..@as(usize, self.event_count)];
    }

    /// Verify that no state-chain address observed during compilation changed.
    /// This check is allocation-free and includes same-row register aliases.
    pub fn isCurrentFor(
        self: *const Transaction,
        tracker: *const StateChainTracker,
    ) bool {
        if (self.format_version != FORMAT_VERSION or
            !std.meta.eql(self.usage, decode.operandUsage(self.instruction.opcode)))
        {
            return false;
        }
        if (self.instruction_clock == 0 or
            access_clock.maximum(self.instruction_clock) >=
                state_chain.CLOCK_PREV_BOUND)
        {
            return false;
        }
        const has_memory = decode.isLoad(self.instruction.opcode) or
            decode.isStore(self.instruction.opcode);
        const expected_event_count: usize =
            @as(usize, @intFromBool(self.usage.reads_rs1)) +
            @as(usize, @intFromBool(self.usage.reads_rs2)) +
            @as(usize, @intFromBool(self.usage.writes_rd)) +
            @as(usize, @intFromBool(has_memory));
        if (self.accessEvents().len != expected_event_count or
            (self.row_projection.memory != null) != has_memory)
        {
            return false;
        }
        var expected_reservation = StateChainTracker.Reservation{
            .memory_address_count = 0,
            .access_count = 0,
            .memory_clock_update_count = 0,
            .register_clock_update_count = 0,
        };
        for (self.accessEvents(), 0..) |event, index| {
            if (event.current_clock != phaseClock(
                self.instruction_clock,
                event.physical_phase,
            ) or (index != 0 and
                event.current_clock <= self.events[index - 1].current_clock))
            {
                return false;
            }
            const raw_previous_clock = switch (event.kind) {
                .register_read, .register_write => blk: {
                    if (event.address >= 32) return false;
                    var raw = tracker.reg_last_clk[@as(u5, @intCast(event.address))];
                    var prior_index = index;
                    while (prior_index > 0) {
                        prior_index -= 1;
                        const prior = self.events[prior_index];
                        if (prior.addressSpace() == 0 and
                            prior.address == event.address)
                        {
                            raw = prior.current_clock;
                            break;
                        }
                    }
                    break :blk raw;
                },
                .memory_read, .memory_write => blk: {
                    if (event.address & 3 != 0) return false;
                    var raw = tracker.mem_last_clk.get(event.address) orelse 0;
                    var has_same_row_predecessor = false;
                    var prior_index = index;
                    while (prior_index > 0) {
                        prior_index -= 1;
                        const prior = self.events[prior_index];
                        if (prior.addressSpace() == 1 and
                            prior.address == event.address)
                        {
                            raw = prior.current_clock;
                            has_same_row_predecessor = true;
                            break;
                        }
                    }
                    if (!has_same_row_predecessor and
                        (!tracker.mem_initial.contains(event.address) or
                            !tracker.mem_last_clk.contains(event.address)))
                    {
                        expected_reservation.memory_address_count += 1;
                    }
                    break :blk raw;
                },
            };
            if (raw_previous_clock != event.raw_previous_clock or
                raw_previous_clock >= event.current_clock or
                StateChainTracker.effectivePreviousClock(
                    raw_previous_clock,
                    event.current_clock,
                ) != event.previous_clock)
            {
                return false;
            }
            expected_reservation.access_count += 1;
            const gaps = StateChainTracker.clockGapCount(
                raw_previous_clock,
                event.current_clock,
            );
            if (event.addressSpace() == 0) {
                expected_reservation.register_clock_update_count += gaps;
            } else {
                expected_reservation.memory_clock_update_count += gaps;
            }
        }
        return std.meta.eql(expected_reservation, self.reservation);
    }

    /// Apply only derived access facts to a candidate runner row. Every stable
    /// identity/value check happens before the first write, so rejection leaves
    /// the row byte-for-byte unchanged.
    pub fn applyToRow(
        self: *const Transaction,
        row: *TraceRow,
    ) ProjectionError!void {
        if (row.clk != self.instruction_clock or
            row.opcode != self.instruction.opcode or
            row.rd != self.instruction.rd or
            row.rs1 != self.instruction.rs1 or
            row.rs2 != self.instruction.rs2 or
            row.imm != self.instruction.imm or
            (self.usage.reads_rs1 and row.rs1_val != self.rs1_value) or
            (self.usage.reads_rs2 and row.rs2_val != self.rs2_value) or
            (self.usage.writes_rd and
                (row.rd_prev_val != self.rd_previous_value or
                    row.rd_val != self.rd_next_value)))
        {
            return error.RowProjectionMismatch;
        }

        const projection = self.row_projection;
        row.rs1_prev_clk = projection.rs1_previous_clock;
        row.rs2_prev_clk = projection.rs2_previous_clock;
        row.rd_prev_clk = projection.rd_previous_clock;
        if (projection.memory) |memory| {
            row.mem_addr = memory.effective_address;
            row.mem_val = memory.transferred_value;
            row.mem_prev_word = memory.previous_word;
            row.mem_next_word = memory.next_word;
            row.mem_prev_clk = memory.previous_clock;
            row.is_load = decode.isLoad(self.instruction.opcode);
            row.is_store = decode.isStore(self.instruction.opcode);
        } else {
            row.mem_addr = 0;
            row.mem_val = 0;
            row.mem_prev_word = 0;
            row.mem_next_word = 0;
            row.mem_prev_clk = 0;
            row.is_load = false;
            row.is_store = false;
        }
    }

    /// Cold reservation boundary. Capacity growth may occur, but no logical
    /// tracker state is published. The returned token commits allocation-free.
    pub fn prepareCommit(
        self: Transaction,
        tracker: *StateChainTracker,
    ) PrepareError!PreparedCommit {
        if (!self.isCurrentFor(tracker)) return error.StaleTransaction;
        try tracker.reserveTransitions(self.reservation);
        if (!self.isCurrentFor(tracker)) return error.StaleTransaction;
        return .{ .transaction = self };
    }

    /// Publish the compiled transitions after an owning integration layer has
    /// reserved `reservation` and revalidated `isCurrentFor`. This is public
    /// only for fixed prepared-transaction adapters; ordinary callers should
    /// use `prepareCommit` and `PreparedCommit.commit`.
    pub fn commitAssumeCapacity(
        self: *const Transaction,
        tracker: *StateChainTracker,
    ) void {
        for (self.accessEvents()) |event| switch (event.kind) {
            .register_read, .register_write => tracker.recordRegTransitionAssumeCapacity(
                @intCast(event.address),
                event.current_clock,
                event.previous_value,
                event.next_value,
            ),
            .memory_read, .memory_write => tracker.recordMemTransitionAssumeCapacity(
                event.address,
                event.current_clock,
                event.previous_value,
                event.next_value,
            ),
        };
    }
};

/// Single-use proof that all transaction collections were reserved. Exclusive
/// access to the tracker is required between `prepareCommit` and `commit`.
pub const PreparedCommit = struct {
    transaction: Transaction,
    consumed: bool = false,

    pub fn commit(
        self: *PreparedCommit,
        tracker: *StateChainTracker,
    ) CommitError!void {
        if (self.consumed) return error.AlreadyCommitted;
        if (!self.transaction.isCurrentFor(tracker))
            return error.StaleTransaction;
        self.transaction.commitAssumeCapacity(tracker);
        self.consumed = true;
    }
};

/// Compile a complete architectural access set without allocation or mutation.
pub fn compile(
    tracker: *const StateChainTracker,
    input: Input,
) CompileError!Transaction {
    if (input.instruction_clock == 0 or
        access_clock.maximum(input.instruction_clock) >=
            state_chain.CLOCK_PREV_BOUND)
    {
        return error.ClockOutOfRange;
    }

    const usage = decode.operandUsage(input.instruction.opcode);
    const is_load = decode.isLoad(input.instruction.opcode);
    const is_store = decode.isStore(input.instruction.opcode);
    if ((is_load or is_store) != (input.memory_words != null)) {
        return if (input.memory_words == null)
            error.MissingMemoryWords
        else
            error.UnexpectedMemoryWords;
    }

    // State-only instructions have no address dependency. Return their fixed
    // transaction before entering register/memory compilation; this is both
    // the generic SSOT and the allocation-free FENCE fast geometry.
    if (!usage.reads_rs1 and !usage.reads_rs2 and !usage.writes_rd and
        !is_load and !is_store)
    {
        return baseTransaction(input, usage);
    }

    var transaction = baseTransaction(input, usage);

    if (is_load) {
        try appendRegister(
            &transaction,
            tracker,
            .register_read,
            .first,
            .first,
            input.instruction.rs1,
            input.rs1_value,
            input.rs1_value,
            .rs1,
        );
        try appendRegister(
            &transaction,
            tracker,
            .register_write,
            .third,
            .second,
            input.instruction.rd,
            input.rd_previous_value,
            input.rd_next_value,
            .rd,
        );
        try appendMemory(&transaction, tracker, input, input.memory_words.?);
    } else if (is_store) {
        try appendRegister(
            &transaction,
            tracker,
            .register_read,
            .first,
            .first,
            input.instruction.rs1,
            input.rs1_value,
            input.rs1_value,
            .rs1,
        );
        try appendRegister(
            &transaction,
            tracker,
            .register_read,
            .second,
            .second,
            input.instruction.rs2,
            input.rs2_value,
            input.rs2_value,
            .rs2,
        );
        try appendMemory(&transaction, tracker, input, input.memory_words.?);
    } else {
        var ordinal: u8 = 1;
        if (usage.reads_rs1) {
            try appendRegister(
                &transaction,
                tracker,
                .register_read,
                @enumFromInt(ordinal),
                @enumFromInt(ordinal),
                input.instruction.rs1,
                input.rs1_value,
                input.rs1_value,
                .rs1,
            );
            ordinal += 1;
        }
        if (usage.reads_rs2) {
            try appendRegister(
                &transaction,
                tracker,
                .register_read,
                @enumFromInt(ordinal),
                @enumFromInt(ordinal),
                input.instruction.rs2,
                input.rs2_value,
                input.rs2_value,
                .rs2,
            );
            ordinal += 1;
        }
        if (usage.writes_rd) {
            try appendRegister(
                &transaction,
                tracker,
                .register_write,
                @enumFromInt(ordinal),
                @enumFromInt(ordinal),
                input.instruction.rd,
                input.rd_previous_value,
                input.rd_next_value,
                .rd,
            );
        }
    }

    return transaction;
}

inline fn baseTransaction(input: Input, usage: decode.OperandUsage) Transaction {
    return .{
        .format_version = FORMAT_VERSION,
        .instruction = input.instruction,
        .instruction_clock = input.instruction_clock,
        .usage = usage,
        .rs1_value = input.rs1_value,
        .rs2_value = input.rs2_value,
        .rd_previous_value = input.rd_previous_value,
        .rd_next_value = input.rd_next_value,
        // Slots beyond event_count are intentionally unspecified. Initializing
        // impossible events costs measurable hot-loop bandwidth; accessEvents
        // is the sole semantic view and never exposes inactive storage.
        .events = undefined,
        .event_count = 0,
        .row_projection = .{
            .rs1_previous_clock = 0,
            .rs2_previous_clock = 0,
            .rd_previous_clock = 0,
            .memory = null,
        },
        .reservation = .{
            .memory_address_count = 0,
            .access_count = 0,
            .memory_clock_update_count = 0,
            .register_clock_update_count = 0,
        },
    };
}

/// Narrow E-018 seam: the authenticated typed facade is the sole owner of
/// LUI's result and x0 behavior, while the generic compiler remains the sole
/// clock/alias authority. This function performs no allocation or mutation.
pub inline fn compileLui(
    authority: *const typed_lui_authority.Authority,
    tracker: *const StateChainTracker,
    input: LuiInput,
) CompileError!Transaction {
    const compact = try compileLuiCompact(authority, tracker, input);
    const current_clock = access_clock.encode(
        compact.instruction_clock,
        .first,
    );
    var transaction = Transaction{
        .format_version = FORMAT_VERSION,
        .instruction = compact.instruction,
        .instruction_clock = compact.instruction_clock,
        .usage = .{
            .reads_rs1 = false,
            .reads_rs2 = false,
            .writes_rd = true,
        },
        .rs1_value = compact.rs1_value,
        .rs2_value = compact.rs2_value,
        .rd_previous_value = compact.rd_previous_value,
        .rd_next_value = compact.rd_next_value,
        .events = undefined,
        .event_count = 1,
        .row_projection = .{
            .rs1_previous_clock = 0,
            .rs2_previous_clock = 0,
            .rd_previous_clock = compact.previous_clock,
            .memory = null,
        },
        .reservation = .{
            .memory_address_count = 0,
            .access_count = 1,
            .memory_clock_update_count = 0,
            .register_clock_update_count = compact.register_clock_update_count,
        },
    };
    transaction.events[0] = .{
        .kind = .register_write,
        .logical_ordinal = .first,
        .physical_phase = .first,
        .address = compact.instruction.rd,
        .raw_previous_clock = compact.raw_previous_clock,
        .previous_clock = compact.previous_clock,
        .current_clock = current_clock,
        .previous_value = compact.rd_previous_value,
        .next_value = compact.rd_next_value,
        .read_mask = 0,
        .write_mask = 0b1111,
    };
    return transaction;
}

/// Fixed BASE_ALU_IMM compiler. The typed authority owns result/x0 semantics;
/// this function owns the same source-before-destination alias and clock rules
/// as `compile` while returning only the family's possible state.
pub inline fn compileBaseAluImmCompact(
    authority: *const typed_base_alu_imm_authority.Authority,
    tracker: *const StateChainTracker,
    input: BaseAluImmInput,
) CompileError!BaseAluImmTransaction {
    const retirement = authority.retire(
        input.instruction,
        input.rs1_value,
    ) catch |err| return switch (err) {
        error.WrongBaseAluImmOpcode => error.WrongBaseAluImmOpcode,
        error.InvalidImmediate => error.InvalidBaseAluImmImmediate,
    };
    if (input.instruction_clock == 0 or
        access_clock.maximum(input.instruction_clock) >=
            state_chain.CLOCK_PREV_BOUND)
    {
        return error.ClockOutOfRange;
    }
    if (input.instruction.rs1 == 0 and input.rs1_value != 0)
        return error.ZeroRegisterValue;
    if (input.instruction.rd == 0 and
        (input.rd_previous_value != 0 or retirement.visible_value != 0))
    {
        return error.ZeroRegisterValue;
    }

    const source_clock = access_clock.encode(input.instruction_clock, .first);
    const source_raw = tracker.reg_last_clk[input.instruction.rs1];
    if (source_raw >= source_clock) return error.NonIncreasingClock;
    const aliased = input.instruction.rd == input.instruction.rs1;
    if (aliased and input.rd_previous_value != input.rs1_value)
        return error.AliasedRegisterValueMismatch;
    const destination_clock = access_clock.encode(input.instruction_clock, .second);
    const destination_raw = if (aliased)
        source_clock
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
        .source_raw_previous_clock = source_raw,
        .source_previous_clock = StateChainTracker.effectivePreviousClock(
            source_raw,
            source_clock,
        ),
        .destination_raw_previous_clock = destination_raw,
        .destination_previous_clock = StateChainTracker.effectivePreviousClock(
            destination_raw,
            destination_clock,
        ),
        .source_gap_count = StateChainTracker.clockGapCount(
            source_raw,
            source_clock,
        ),
        .destination_gap_count = StateChainTracker.clockGapCount(
            destination_raw,
            destination_clock,
        ),
    };
}

/// Same semantic/access compiler authority as `compileLui`, specialized to
/// the only event LUI can produce. It performs no allocation or mutation.
pub inline fn compileLuiCompact(
    authority: *const typed_lui_authority.Authority,
    tracker: *const StateChainTracker,
    input: LuiInput,
) CompileError!LuiTransaction {
    const retirement = authority.retire(input.instruction) catch
        return error.WrongLuiOpcode;
    if (input.instruction_clock == 0 or
        access_clock.maximum(input.instruction_clock) >=
            state_chain.CLOCK_PREV_BOUND)
    {
        return error.ClockOutOfRange;
    }

    if (input.instruction.rd == 0 and
        (input.rd_previous_value != 0 or retirement.visible_value != 0))
    {
        return error.ZeroRegisterValue;
    }
    const current_clock = access_clock.encode(input.instruction_clock, .first);
    const raw_previous_clock = tracker.reg_last_clk[input.instruction.rd];
    if (raw_previous_clock >= current_clock)
        return error.NonIncreasingClock;
    return .{
        .instruction = input.instruction,
        .instruction_clock = input.instruction_clock,
        .rs1_value = input.rs1_value,
        .rs2_value = input.rs2_value,
        .rd_previous_value = input.rd_previous_value,
        .rd_next_value = retirement.visible_value,
        .raw_previous_clock = raw_previous_clock,
        .previous_clock = StateChainTracker.effectivePreviousClock(
            raw_previous_clock,
            current_clock,
        ),
        .register_clock_update_count = StateChainTracker.clockGapCount(
            raw_previous_clock,
            current_clock,
        ),
    };
}

/// Narrow E-019 seam: authenticate FENCE's sequential state-only retirement,
/// then delegate its empty access geometry to the generic compiler. This is
/// allocation-free and mutation-free; the returned transaction has no events
/// or capacity reservation by construction.
pub inline fn compileFence(
    authority: *const typed_fence_authority.Authority,
    tracker: *const StateChainTracker,
    input: FenceInput,
) CompileError!Transaction {
    _ = authority.retire(input.instruction, input.pc_before) catch |err|
        return switch (err) {
            error.WrongFenceOpcode => error.WrongFenceOpcode,
            error.InvalidFenceImmediate => error.InvalidFenceImmediate,
        };
    if (input.instruction_clock == 0 or
        access_clock.maximum(input.instruction_clock) >=
            state_chain.CLOCK_PREV_BOUND)
    {
        return error.ClockOutOfRange;
    }
    _ = tracker;
    return baseTransaction(.{
        .instruction = input.instruction,
        .instruction_clock = input.instruction_clock,
        .rs1_value = input.rs1_value,
        .rs2_value = input.rs2_value,
        .rd_previous_value = input.rd_previous_value,
        .rd_next_value = input.rd_previous_value,
    }, .{
        .reads_rs1 = false,
        .reads_rs2 = false,
        .writes_rd = false,
    });
}

const appendRegister = transaction_support.appendRegister;
const appendMemory = transaction_support.appendMemory;
const phaseClock = transaction_support.phaseClock;
comptime {
    if (MAX_EVENTS != access_clock.MAX_ACCESSES_PER_INSTRUCTION)
        @compileError("transaction event bound drifted from protocol subclocks");
    if (@intFromEnum(types.AccessPhase.first) != 1 or
        @intFromEnum(types.AccessPhase.third) != 3)
    {
        @compileError("typed physical phases drifted from access-clock encoding");
    }
    if (@sizeOf(Transaction) > MAX_TRANSACTION_BYTES)
        @compileError("access transaction exceeded its fixed hot-row stack budget");
}
