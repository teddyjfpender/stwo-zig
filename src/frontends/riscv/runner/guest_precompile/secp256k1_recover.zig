//! Transactional successful-only Ethereum secp256k1 signer recovery.
//!
//! Prepare validates the complete input and performs all allocation. Commit is
//! infallible and publishes memory, state-chain, call, execution-row, PC, and
//! external-clock state as one retirement.

const std = @import("std");
const access_clock = @import("../../access_clock.zig");
const custom0 = @import("../../isa/custom0.zig");
const abi = @import("../../isa/ethereum_signer_recovery.zig");
const execution_profile = @import("../../isa/execution_profile.zig");
const isa_profile = @import("../../isa/profile.zig");
const Cpu = @import("../cpu.zig").Cpu;
const Memory = @import("../memory.zig").Memory;
const MemoryLayout = @import("../memory_state.zig").MemoryLayout;
const Trace = @import("../trace.zig").Trace;
const StateChainTracker = @import("../state_chain.zig").StateChainTracker;
const call_buffer = @import("secp256k1_recover_call_buffer.zig");

const Secp256k1 = std.crypto.ecc.Secp256k1;

pub const ExecutionProfile = execution_profile.ExecutionProfile;
pub const Record = call_buffer.Record;
pub const input_word_count = abi.input_word_count;
pub const output_word_count = abi.output_word_count;

pub const Error = custom0.DecodeError || error{
    OutOfMemory,
    PrecompileCallLimitExceeded,
    PrecompileClockOutOfRange,
    PrecompileAddressMisaligned,
    PrecompileSpanOutsideRwMemory,
    InvalidRecoveryId,
    InvalidSignatureScalar,
    InvalidRecoveryPoint,
    InvalidRecoveredPublicKey,
};

pub const ExecutionRow = struct {
    execution_clock: u32,
    pc: u32,
    inst_word: u32,
    call_index: u32,
};

pub const FrozenExecutionRows = struct {
    storage: std.ArrayList(ExecutionRow),
    allocator: std.mem.Allocator,

    pub fn rows(self: *const FrozenExecutionRows) []const ExecutionRow {
        return self.storage.items;
    }

    pub fn capacity(self: *const FrozenExecutionRows) usize {
        return self.storage.capacity;
    }

    pub fn deinit(self: *FrozenExecutionRows) void {
        self.storage.deinit(self.allocator);
        self.* = undefined;
    }
};

pub const ExecutionRowsBuilder = struct {
    storage: std.ArrayList(ExecutionRow) = .empty,
    allocator: std.mem.Allocator,
    limit: usize,

    pub fn init(
        allocator: std.mem.Allocator,
        limit: usize,
    ) error{PrecompileCallLimitExceeded}!ExecutionRowsBuilder {
        if (limit > call_buffer.max_calls) return error.PrecompileCallLimitExceeded;
        return .{ .allocator = allocator, .limit = limit };
    }

    pub fn deinit(self: *ExecutionRowsBuilder) void {
        self.storage.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn len(self: *const ExecutionRowsBuilder) usize {
        return self.storage.items.len;
    }

    pub fn rows(self: *const ExecutionRowsBuilder) []const ExecutionRow {
        return self.storage.items;
    }

    pub fn reserveOne(self: *ExecutionRowsBuilder) Error!void {
        if (self.storage.items.len >= self.limit)
            return error.PrecompileCallLimitExceeded;
        try self.storage.ensureUnusedCapacity(self.allocator, 1);
    }

    fn appendAssumeCapacity(self: *ExecutionRowsBuilder, row: ExecutionRow) void {
        std.debug.assert(self.storage.items.len < self.limit);
        self.storage.appendAssumeCapacity(row);
    }

    pub fn freeze(self: *ExecutionRowsBuilder) FrozenExecutionRows {
        const frozen = FrozenExecutionRows{
            .storage = self.storage,
            .allocator = self.allocator,
        };
        self.storage = .empty;
        self.limit = 0;
        return frozen;
    }
};

const Prepared = struct {
    record: Record,
    row: ExecutionRow,
    input_addresses: [input_word_count]u32,
    input_words: [input_word_count]u32,
    output_addresses: [output_word_count]u32,
    output_previous_words: [output_word_count]u32,
    output_words: [output_word_count]u32,
    pointer_clock: u32,
    memory_clock: u32,
};

pub fn execute(
    profile: ExecutionProfile,
    inst_word: u32,
    execution_clock: u32,
    cpu: *Cpu,
    memory: *Memory,
    layout: MemoryLayout,
    tracker: *StateChainTracker,
    calls: *call_buffer.Builder,
    execution_rows: *ExecutionRowsBuilder,
) Error!void {
    const prepared = try prepareAndReserve(
        profile,
        inst_word,
        execution_clock,
        cpu.*,
        memory,
        layout,
        tracker,
        calls,
        execution_rows,
    );
    commit(prepared, cpu, memory, tracker, calls, execution_rows);
}

pub fn executeWithRecordedClock(
    profile: ExecutionProfile,
    inst_word: u32,
    execution_clock: u32,
    segment_external_origin: usize,
    cpu: *Cpu,
    memory: *Memory,
    layout: MemoryLayout,
    tracker: *StateChainTracker,
    trace: *Trace,
    aggregate_calls_before: usize,
    aggregate_rows_before: usize,
    calls: *call_buffer.Builder,
    execution_rows: *ExecutionRowsBuilder,
) !void {
    const clock_token = try trace.prepareRecordedExternalRetirement(
        execution_clock,
        segment_external_origin,
        aggregate_calls_before,
        aggregate_rows_before,
    );
    const prepared = try prepareAndReserve(
        profile,
        inst_word,
        execution_clock,
        cpu.*,
        memory,
        layout,
        tracker,
        calls,
        execution_rows,
    );
    if (!trace.externalRetirementTokenIsCurrent(
        clock_token,
        aggregate_calls_before,
        aggregate_rows_before,
    )) return error.ProfileClockAuthorityMismatch;
    if (!Trace.externalRetirementCommitIsValid(
        clock_token,
        aggregate_calls_before + 1,
        aggregate_rows_before + 1,
        prepared.record.execution_clock,
        prepared.row.execution_clock,
    )) return error.ProfileClockAuthorityMismatch;
    commit(prepared, cpu, memory, tracker, calls, execution_rows);
    trace.commitRecordedExternalRetirement(clock_token);
}

fn prepareAndReserve(
    profile: ExecutionProfile,
    inst_word: u32,
    execution_clock: u32,
    cpu: Cpu,
    memory: *Memory,
    layout: MemoryLayout,
    tracker: *StateChainTracker,
    calls: *call_buffer.Builder,
    execution_rows: *ExecutionRowsBuilder,
) Error!Prepared {
    const prepared = try prepare(
        profile,
        inst_word,
        execution_clock,
        cpu,
        memory,
        layout,
        tracker,
        calls,
    );
    try calls.reserveOne();
    try execution_rows.reserveOne();

    var memory_gap_count: usize = 0;
    for (prepared.input_addresses) |address| {
        memory_gap_count += StateChainTracker.clockGapCount(
            tracker.mem_last_clk.get(address) orelse 0,
            prepared.memory_clock,
        );
    }
    for (prepared.output_addresses) |address| {
        memory_gap_count += StateChainTracker.clockGapCount(
            tracker.mem_last_clk.get(address) orelse 0,
            prepared.memory_clock,
        );
    }
    const register_gap_count = StateChainTracker.clockGapCount(
        tracker.reg_last_clk[prepared.record.pointer_register],
        prepared.pointer_clock,
    );
    try tracker.reserveTransitions(.{
        .memory_address_count = abi.memory_word_count,
        .access_count = abi.memory_word_count + 1,
        .memory_clock_update_count = memory_gap_count,
        .register_clock_update_count = register_gap_count,
    });
    try memory.prepareAlignedWordWrites(&prepared.output_addresses);
    return prepared;
}

fn prepare(
    profile: ExecutionProfile,
    inst_word: u32,
    execution_clock: u32,
    cpu: Cpu,
    memory: *const Memory,
    layout: MemoryLayout,
    tracker: *const StateChainTracker,
    calls: *const call_buffer.Builder,
) Error!Prepared {
    const decoded = try custom0.decode(profile, inst_word);
    if (decoded.opcode != .secp256k1_recover_signer_v1)
        return error.InvalidPrecompileEncoding;
    if (execution_clock == 0 or
        access_clock.maximum(execution_clock) > std.math.maxInt(u32))
    {
        return error.PrecompileClockOutOfRange;
    }

    const io_ptr = cpu.readReg(decoded.rs1);
    if (io_ptr & (abi.alignment - 1) != 0)
        return error.PrecompileAddressMisaligned;
    const span_end = @as(u64, io_ptr) + abi.record_size;
    if (span_end > isa_profile.program_commitment_size or
        !spanWithinOneRwInterval(layout, io_ptr, span_end))
    {
        return error.PrecompileSpanOutsideRwMemory;
    }

    const pointer_clock = access_clock.encode(execution_clock, .first);
    const memory_clock = access_clock.encode(execution_clock, .second);
    const pointer_previous_clock = StateChainTracker.effectivePreviousClock(
        tracker.reg_last_clk[decoded.rs1],
        pointer_clock,
    );

    var input_addresses: [input_word_count]u32 = undefined;
    var input_words: [input_word_count]u32 = undefined;
    var input_previous_clocks: [input_word_count]u32 = undefined;
    var input_bytes: [input_word_count * @sizeOf(u32)]u8 = undefined;
    for (0..input_word_count) |index| {
        const address = abi.inputWordAddress(io_ptr, index);
        const word = memory.readU32(address);
        input_addresses[index] = address;
        input_words[index] = word;
        input_previous_clocks[index] = StateChainTracker.effectivePreviousClock(
            tracker.mem_last_clk.get(address) orelse 0,
            memory_clock,
        );
        input_bytes[index * 4 ..][0..4].* = abi.bytesFromWord(word);
    }

    const digest = input_bytes[abi.digest_offset..][0..abi.digest_size].*;
    const r = input_bytes[abi.r_offset..][0..abi.scalar_size].*;
    const s = input_bytes[abi.s_offset..][0..abi.scalar_size].*;
    const recovery_id = input_words[input_word_count - 1];
    const public_key = try recoverSigner(digest, r, s, recovery_id);

    var output_bytes: [output_word_count * @sizeOf(u32)]u8 = undefined;
    output_bytes[0..abi.public_key_size].* = public_key;
    output_bytes[abi.public_key_size..][0..4].* =
        abi.bytesFromWord(abi.success_status);
    var output_addresses: [output_word_count]u32 = undefined;
    var output_previous_words: [output_word_count]u32 = undefined;
    var output_words: [output_word_count]u32 = undefined;
    var output_previous_clocks: [output_word_count]u32 = undefined;
    for (0..output_word_count) |index| {
        const address = abi.outputWordAddress(io_ptr, index);
        output_addresses[index] = address;
        output_previous_words[index] = memory.readU32(address);
        output_words[index] = abi.wordFromBytes(output_bytes[index * 4 ..][0..4]);
        output_previous_clocks[index] = StateChainTracker.effectivePreviousClock(
            tracker.mem_last_clk.get(address) orelse 0,
            memory_clock,
        );
    }

    return .{
        .record = .{
            .execution_clock = execution_clock,
            .pc = cpu.pc,
            .io_ptr = io_ptr,
            .pointer_register = decoded.rs1,
            .pointer_previous_clock = pointer_previous_clock,
            .digest_big_endian = digest,
            .r_big_endian = r,
            .s_big_endian = s,
            .recovery_id = recovery_id,
            .public_key_xy_big_endian = public_key,
            .status = abi.success_status,
            .input_previous_clocks = input_previous_clocks,
            .output_previous_words = output_previous_words,
            .output_previous_clocks = output_previous_clocks,
        },
        .row = .{
            .execution_clock = execution_clock,
            .pc = cpu.pc,
            .inst_word = inst_word,
            .call_index = @intCast(calls.len()),
        },
        .input_addresses = input_addresses,
        .input_words = input_words,
        .output_addresses = output_addresses,
        .output_previous_words = output_previous_words,
        .output_words = output_words,
        .pointer_clock = pointer_clock,
        .memory_clock = memory_clock,
    };
}

fn commit(
    prepared: Prepared,
    cpu: *Cpu,
    memory: *Memory,
    tracker: *StateChainTracker,
    calls: *call_buffer.Builder,
    execution_rows: *ExecutionRowsBuilder,
) void {
    tracker.recordRegTransitionAssumeCapacity(
        prepared.record.pointer_register,
        prepared.pointer_clock,
        prepared.record.io_ptr,
        prepared.record.io_ptr,
    );
    for (0..input_word_count) |index| {
        tracker.recordMemTransitionAssumeCapacity(
            prepared.input_addresses[index],
            prepared.memory_clock,
            prepared.input_words[index],
            prepared.input_words[index],
        );
    }
    for (0..output_word_count) |index| {
        memory.writeU32AssumePrepared(
            prepared.output_addresses[index],
            prepared.output_words[index],
        );
        tracker.recordMemTransitionAssumeCapacity(
            prepared.output_addresses[index],
            prepared.memory_clock,
            prepared.output_previous_words[index],
            prepared.output_words[index],
        );
    }
    execution_rows.appendAssumeCapacity(prepared.row);
    calls.appendAssumeCapacity(prepared.record);
    cpu.pc +%= 4;
}

/// Recover one Ethereum-compatible signer key from a successful signature.
pub fn recoverSigner(
    digest_big_endian: [abi.digest_size]u8,
    r_big_endian: [abi.scalar_size]u8,
    s_big_endian: [abi.scalar_size]u8,
    recovery_id: u32,
) Error![abi.public_key_size]u8 {
    if (recovery_id > 1) return error.InvalidRecoveryId;
    const r = Secp256k1.scalar.Scalar.fromBytes(r_big_endian, .big) catch
        return error.InvalidSignatureScalar;
    const s = Secp256k1.scalar.Scalar.fromBytes(s_big_endian, .big) catch
        return error.InvalidSignatureScalar;
    if (r.isZero() or s.isZero()) return error.InvalidSignatureScalar;

    const x = Secp256k1.Fe.fromBytes(r_big_endian, .big) catch
        return error.InvalidRecoveryPoint;
    const y = Secp256k1.recoverY(x, recovery_id == 1) catch
        return error.InvalidRecoveryPoint;
    const recovery_point = Secp256k1.fromAffineCoordinates(.{ .x = x, .y = y }) catch
        return error.InvalidRecoveryPoint;

    const z_integer = std.mem.readInt(u256, &digest_big_endian, .big) %
        Secp256k1.scalar.field_order;
    var z_bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &z_bytes, z_integer, .big);
    const z = Secp256k1.scalar.Scalar.fromBytes(z_bytes, .big) catch unreachable;
    const r_inverse = r.invert();
    const generator_scalar = z.neg().mul(r_inverse).toBytes(.big);
    const recovery_scalar = s.mul(r_inverse).toBytes(.big);
    const public_key = Secp256k1.mulDoubleBasePublic(
        Secp256k1.basePoint,
        generator_scalar,
        recovery_point,
        recovery_scalar,
        .big,
    ) catch return error.InvalidRecoveredPublicKey;
    // Rearranging the construction yields sR = zG + rQ. Since R is a valid
    // curve point with x(R)=r and Q is non-identity, this is exactly successful
    // ECDSA verification; repeating another double-scalar multiplication here
    // would add no input validation and would nearly double host work.
    const sec1 = public_key.toUncompressedSec1();
    return sec1[1..65].*;
}

fn spanWithinOneRwInterval(layout: MemoryLayout, start: u32, end: u64) bool {
    const intervals = [_][2]u32{
        .{ layout.data_base, layout.data_end },
        .{ layout.stack_bottom, layout.stack_top },
        .{ layout.io_base, layout.io_end },
    };
    for (intervals) |interval| {
        if (interval[0] < interval[1] and
            start >= interval[0] and end <= @as(u64, interval[1]))
        {
            return true;
        }
    }
    return false;
}
