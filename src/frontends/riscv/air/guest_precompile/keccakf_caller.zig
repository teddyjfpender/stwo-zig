//! Compact RISC-V caller authority embedded in the Keccak-f shard.
//!
//! The caller occupies only the input row of each operation (row groups zero
//! and one of a paired slot).  It reuses the provider's already-boolean state
//! cells as the memory-relation byte source, so arbitrary `u32` words need no
//! second bit decomposition, byte materialization, or standalone component.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const access_clock = @import("../../access_clock.zig");
const logup = @import("../logup.zig");
const call_buffer = @import("../../runner/guest_precompile/keccakf_call_buffer.zig");
const custom0 = @import("../../isa/custom0.zig");
const runner = @import("../../runner/guest_precompile/keccakf_v1.zig");
const relations_mod = @import("keccakf_relations.zig");
const witness = @import("keccakf_witness.zig");

pub const word_count: usize = call_buffer.word_count;
pub const word_bytes: usize = @sizeOf(u32);
pub const opcode_id: u32 = 46;

pub const Layout = struct {
    pub const enabler: usize = 0;
    pub const execution_clock: usize = 1;
    pub const pc: usize = 2;
    pub const pointer_register: usize = 3;
    pub const pointer_previous_clock: usize = 4;
    pub const pointer_bytes: usize = 5;
    pub const pointer_double_word_index: usize = pointer_bytes + word_bytes;
    pub const span_end_limbs: usize = pointer_double_word_index + 1;
    pub const memory_previous_clocks: usize = span_end_limbs + 4;
    pub const main_columns: usize = memory_previous_clocks + word_count;

    pub fn previousClock(word: usize) usize {
        return memory_previous_clocks + word;
    }
};

pub const padding_constraint_count: usize = Layout.main_columns - 1;
pub const direct_constraint_count: usize = 2 + padding_constraint_count + 2;

pub const core_event_count: usize = 6 + 3 * word_count + 2;
pub const io_event_count: usize = 2;
pub const event_count: usize = core_event_count + io_event_count;
pub const batch_count: usize = event_count / 2;

pub const Error = error{InvalidTraceShape};
pub const BoundaryError = Error || error{ZeroDenominator};

pub const PreflightError = custom0.DecodeError || error{
    CallIndexMismatch,
    ExecutionClockMismatch,
    ExecutionClockOutOfRange,
    ExecutionOrderMismatch,
    PointerMismatch,
    PointerRegisterMismatch,
    ProgramMismatch,
};

/// Binds the independently retained execution-row tape to the caller records
/// before either may reach a commitment. The paired Keccak trace consumes the
/// records; the declared-program commitment consumes the rows, so this seam is
/// what makes those two witnesses one transaction.
pub fn preflight(
    records: []const call_buffer.Record,
    rows: []const runner.ExecutionRow,
    total_steps: u32,
) PreflightError!void {
    if (records.len != rows.len) return error.CallIndexMismatch;
    var previous_clock: u32 = 0;
    for (records, rows, 0..) |record, row, index| {
        if (row.call_index != index) return error.CallIndexMismatch;
        if (record.execution_clock != row.execution_clock)
            return error.ExecutionClockMismatch;
        if (record.pc != row.pc) return error.ProgramMismatch;
        if (record.execution_clock == 0 or record.execution_clock > total_steps or
            access_clock.maximum(record.execution_clock) > std.math.maxInt(u32))
        {
            return error.ExecutionClockOutOfRange;
        }
        if (index != 0 and record.execution_clock <= previous_clock)
            return error.ExecutionOrderMismatch;
        previous_clock = record.execution_clock;
        const decoded = try custom0.decode(.rv32im_zkvm_ethereum_v1, row.inst_word);
        if (decoded.opcode != .keccakf_1600_permute_in_place_v1)
            return error.ProgramMismatch;
        if (decoded.rs1 != record.pointer_register)
            return error.PointerRegisterMismatch;
        if (record.state_ptr & 7 != 0) return error.PointerMismatch;
    }
}

pub fn fill(record: call_buffer.Record) [Layout.main_columns]M31 {
    var row = [_]M31{M31.zero()} ** Layout.main_columns;
    row[Layout.enabler] = M31.one();
    row[Layout.execution_clock] = M31.fromCanonical(record.execution_clock);
    row[Layout.pc] = M31.fromCanonical(record.pc);
    row[Layout.pointer_register] = M31.fromCanonical(record.pointer_register);
    row[Layout.pointer_previous_clock] = M31.fromCanonical(
        record.pointer_previous_clock,
    );
    writeBytes(&row, Layout.pointer_bytes, record.state_ptr);
    row[Layout.pointer_double_word_index] = M31.fromCanonical(record.state_ptr / 8);

    const last_word_index: u32 = record.state_ptr / @as(u32, word_bytes) +
        @as(u32, word_count - 1);
    row[Layout.span_end_limbs] = byteFelt(last_word_index, 0);
    row[Layout.span_end_limbs + 1] = byteFelt(last_word_index, 8);
    row[Layout.span_end_limbs + 2] = byteFelt(last_word_index, 16);
    row[Layout.span_end_limbs + 3] = M31.fromCanonical(
        @intCast((last_word_index >> 24) & 0x0f),
    );
    for (record.memory_previous_clocks, 0..) |clock, index| {
        row[Layout.previousClock(index)] = M31.fromCanonical(clock);
    }
    return row;
}

pub fn evaluateDirect(
    comptime S: type,
    caller: []const S,
    active: S,
    sink: anytype,
) Error!void {
    if (caller.len != Layout.main_columns) return error.InvalidTraceShape;
    const one = S.one();
    const enabler = caller[Layout.enabler];
    sink.add(enabler.mul(one.sub(enabler)), 2);
    sink.add(enabler.sub(active), 2);

    const padding = one.sub(active);
    for (caller[1..]) |value| sink.add(padding.mul(value), 3);

    const pointer = composeLittleEndian(
        S,
        caller[Layout.pointer_bytes..][0..4].*,
    );
    sink.add(pointer.sub(mulSmall(
        S,
        caller[Layout.pointer_double_word_index],
        8,
    )), 1);
    sink.add(mulSmall(
        S,
        caller[Layout.pointer_double_word_index],
        2,
    ).add(mulSmall(S, enabler, word_count - 1)).sub(composeLittleEndian(
        S,
        caller[Layout.span_end_limbs..][0..4].*,
    )), 1);
}

pub fn rowPairs(
    comptime S: type,
    caller: []const S,
    input_state: []const S,
    output_state: []const S,
    io_a: []const S,
    io_b: []const S,
    selector_a: S,
    selector_b: S,
    in_use_b: S,
    relations: anytype,
) Error![batch_count]logup.RowPairFor(InteractionScalar(S)) {
    if (caller.len != Layout.main_columns or
        input_state.len != witness.state_cell_count or
        output_state.len != witness.state_cell_count or
        io_a.len != relations_mod.io_arity or
        io_b.len != relations_mod.io_arity)
    {
        return error.InvalidTraceShape;
    }
    var events = coreEvents(S, caller, input_state, output_state, relations);
    events[core_event_count] = emit(
        S,
        selector_a,
        combine(S, io_a[0..relations_mod.io_arity].*, relations.io),
    );
    events[core_event_count + 1] = emit(
        S,
        selector_b.mul(in_use_b),
        combine(S, io_b[0..relations_mod.io_arity].*, relations.io),
    );
    return pairEvents(S, events);
}

/// Opposite-sign public boundary for the isolated proof gate. Production
/// proofs cancel these exact events against the base program/state/memory and
/// fixed-table components instead.
pub fn publicCoreCounterpart(
    caller: []const M31,
    input_state: []const M31,
    output_state: []const M31,
    relations: *const relations_mod.Relations,
) BoundaryError!QM31 {
    if (caller.len != Layout.main_columns or
        input_state.len != witness.state_cell_count or
        output_state.len != witness.state_cell_count)
    {
        return error.InvalidTraceShape;
    }
    const events = coreEvents(M31, caller, input_state, output_state, relations);
    var result = QM31.zero();
    for (events[0..core_event_count]) |event| {
        if (event.n1.isZero()) continue;
        result = result.sub(event.n1.mul(event.d1.inv() catch
            return error.ZeroDenominator));
    }
    return result;
}

pub fn publicCoreCounterpartForRecord(
    record: call_buffer.Record,
    relations: *const relations_mod.Relations,
) BoundaryError!QM31 {
    const row = fill(record);
    const input_state = stateBits(record.input);
    const output_state = stateBits(record.output);
    return publicCoreCounterpart(&row, &input_state, &output_state, relations);
}

fn coreEvents(
    comptime S: type,
    caller: []const S,
    input_state: []const S,
    output_state: []const S,
    relations: anytype,
) [event_count]logup.RowPairFor(InteractionScalar(S)) {
    const active = caller[Layout.enabler];
    const clock = caller[Layout.execution_clock];
    const pointer_bytes = caller[Layout.pointer_bytes..][0..4].*;
    var events: [event_count]logup.RowPairFor(InteractionScalar(S)) = undefined;
    var index: usize = 0;
    events[index] = request(S, active, combine(S, .{
        caller[Layout.pc],
        scalar(S, opcode_id),
        scalar(S, 0),
        caller[Layout.pointer_register],
        scalar(S, 0),
    }, relations.base.program_access));
    index += 1;
    events[index] = request(S, active, combine(S, .{
        caller[Layout.pc], clock,
    }, relations.base.registers_state));
    index += 1;
    events[index] = emit(S, active, combine(S, .{
        caller[Layout.pc].add(scalar(S, 4)), clock.add(scalar(S, 1)),
    }, relations.base.registers_state));
    index += 1;
    events[index] = request(S, active, memoryDenominator(
        S,
        scalar(S, 0),
        caller[Layout.pointer_register],
        caller[Layout.pointer_previous_clock],
        pointer_bytes,
        relations,
    ));
    index += 1;
    events[index] = emit(S, active, memoryDenominator(
        S,
        scalar(S, 0),
        caller[Layout.pointer_register],
        accessClock(S, clock, 1),
        pointer_bytes,
        relations,
    ));
    index += 1;
    events[index] = request(S, active, combine(S, .{
        accessClock(S, clock, 1)
            .sub(caller[Layout.pointer_previous_clock]).sub(scalar(S, 1)),
    }, relations.base.range_check_20));
    index += 1;

    for (0..word_count) |word| {
        const address = stateWordAddress(
            S,
            caller[Layout.pointer_double_word_index],
            word,
        );
        events[index] = request(S, active, memoryDenominator(
            S,
            scalar(S, 1),
            address,
            caller[Layout.previousClock(word)],
            stateWordBytes(S, input_state, word),
            relations,
        ));
        index += 1;
        events[index] = emit(S, active, memoryDenominator(
            S,
            scalar(S, 1),
            address,
            accessClock(S, clock, 2),
            stateWordBytes(S, output_state, word),
            relations,
        ));
        index += 1;
        events[index] = request(S, active, combine(S, .{
            accessClock(S, clock, 2)
                .sub(caller[Layout.previousClock(word)]).sub(scalar(S, 1)),
        }, relations.base.range_check_20));
        index += 1;
    }
    events[index] = request(S, active, combine(S, .{
        caller[Layout.span_end_limbs], caller[Layout.span_end_limbs + 1],
    }, relations.base.range_check_8_8));
    index += 1;
    events[index] = request(S, active, combine(S, .{
        caller[Layout.span_end_limbs + 2],
        mulSmall(S, caller[Layout.pointer_bytes + 3], 4),
        caller[Layout.span_end_limbs + 3],
    }, relations.base.range_check_8_8_4));
    index += 1;
    while (index < events.len) : (index += 1) {
        events[index] = logup.RowPairFor(InteractionScalar(S)).single(
            InteractionScalar(S).zero(),
            InteractionScalar(S).one(),
        );
    }
    return events;
}

fn pairEvents(
    comptime S: type,
    events: [event_count]logup.RowPairFor(InteractionScalar(S)),
) [batch_count]logup.RowPairFor(InteractionScalar(S)) {
    var result: [batch_count]logup.RowPairFor(InteractionScalar(S)) = undefined;
    for (&result, 0..) |*pair, batch| {
        const first = events[2 * batch];
        const second = events[2 * batch + 1];
        pair.* = .{
            .n1 = first.n1,
            .d1 = first.d1,
            .n2 = second.n1,
            .d2 = second.d1,
        };
    }
    return result;
}

fn request(comptime S: type, active: S, denominator: InteractionScalar(S)) logup.RowPairFor(InteractionScalar(S)) {
    return logup.RowPairFor(InteractionScalar(S)).single(
        lift(S, active).neg(),
        denominator,
    );
}

fn emit(comptime S: type, active: S, denominator: InteractionScalar(S)) logup.RowPairFor(InteractionScalar(S)) {
    return logup.RowPairFor(InteractionScalar(S)).single(
        lift(S, active),
        denominator,
    );
}

fn memoryDenominator(
    comptime S: type,
    address_space: S,
    address: S,
    clock: S,
    limbs: [4]S,
    relations: anytype,
) InteractionScalar(S) {
    return combine(S, .{
        address_space, address,  clock,
        limbs[0],      limbs[1], limbs[2],
        limbs[3],
    }, relations.base.memory_access);
}

fn packedByte(
    comptime S: type,
    state: []const S,
    word: usize,
    byte: usize,
) S {
    var result = S.zero();
    for (0..8) |bit| result = result.add(mulSmall(
        S,
        state[word * 32 + byte * 8 + bit],
        @as(u32, 1) << @as(u5, @intCast(bit)),
    ));
    return result;
}

fn stateWordBytes(
    comptime S: type,
    state: []const S,
    word: usize,
) [word_bytes]S {
    var result: [word_bytes]S = undefined;
    for (&result, 0..) |*value, byte| value.* = packedByte(S, state, word, byte);
    return result;
}

fn stateBits(words: [word_count]u32) [witness.state_cell_count]M31 {
    var result: [witness.state_cell_count]M31 = undefined;
    for (words, 0..) |word, word_index| for (0..32) |bit| {
        result[word_index * 32 + bit] = M31.fromCanonical(
            (word >> @as(u5, @intCast(bit))) & 1,
        );
    };
    return result;
}

fn composeLittleEndian(comptime S: type, limbs: [4]S) S {
    return limbs[0]
        .add(mulSmall(S, limbs[1], 1 << 8))
        .add(mulSmall(S, limbs[2], 1 << 16))
        .add(mulSmall(S, limbs[3], 1 << 24));
}

fn stateWordAddress(comptime S: type, double_word: S, word: usize) S {
    return mulSmall(S, double_word, 8)
        .add(scalar(S, @as(u32, @intCast(word * word_bytes))));
}

fn accessClock(comptime S: type, clock: S, ordinal: u32) S {
    return mulSmall(S, clock.sub(scalar(S, 1)), 4).add(scalar(S, ordinal));
}

fn combine(comptime S: type, tuple: anytype, relation: anytype) InteractionScalar(S) {
    if (comptime S == M31) return relation.combineBase(tuple);
    if (comptime S == QM31) return relation.combineSecure(tuple);
    return relation.combine(tuple);
}

fn lift(comptime S: type, value: S) InteractionScalar(S) {
    if (comptime S == M31) return QM31.fromBase(value);
    if (comptime S == QM31) return value;
    return value;
}

fn InteractionScalar(comptime S: type) type {
    return if (S == M31) QM31 else S;
}

fn scalar(comptime S: type, value: u32) S {
    if (comptime S == M31) return M31.fromCanonical(value);
    if (comptime S == QM31) return QM31.fromBase(M31.fromCanonical(value));
    return S.fromBase(M31.fromCanonical(value));
}

fn mulSmall(comptime S: type, value: S, coefficient: anytype) S {
    const canonical: u32 = @intCast(coefficient);
    if (comptime S == M31) return value.mul(M31.fromCanonical(canonical));
    if (comptime S == QM31) return value.mulM31(M31.fromCanonical(canonical));
    return value.mul(S.fromBase(M31.fromCanonical(canonical)));
}

fn writeBytes(row: *[Layout.main_columns]M31, start: usize, word: u32) void {
    inline for (0..word_bytes) |byte| {
        row[start + byte] = byteFelt(word, @intCast(byte * 8));
    }
}

fn byteFelt(word: u32, shift: u5) M31 {
    return M31.fromCanonical(@intCast((word >> shift) & 0xff));
}

comptime {
    if (Layout.main_columns != 64 or direct_constraint_count != 67 or
        core_event_count != 158 or event_count != 160 or batch_count != 80)
    {
        @compileError("Keccak caller geometry drifted");
    }
}
