//! CPU, program, memory, and arithmetic boundary for signer recovery.
//!
//! One row consumes the exact committed CUSTOM-0 signer instruction, advances
//! the CPU state, authenticates every register/memory transition, and requests
//! the same versioned recovery tuple emitted by the secp256k1 arithmetic row.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const access_clock = @import("../../access_clock.zig");
const program_decode = @import("../program/decode.zig");
const custom0 = @import("../../isa/custom0.zig");
const abi = @import("../../isa/ethereum_signer_recovery.zig");
const call_buffer = @import("../../runner/guest_precompile/secp256k1_recover_call_buffer.zig");
const runner = @import("../../runner/guest_precompile/secp256k1_recover_v1.zig");
const logup = @import("../logup.zig");
const recovery_direct = @import("secp256k1_recovery_direct.zig");
const relations_mod = @import("secp256k1_relations.zig");

pub const opcode_id = program_decode.secp256k1_recover_v1_program_opcode_id;
pub const input_word_count = abi.input_word_count;
pub const output_word_count = abi.output_word_count;
pub const memory_word_count = abi.memory_word_count;

pub const Layout = struct {
    pub const is_active: usize = 0;
    pub const execution_clock: usize = 1;
    pub const pc: usize = 2;
    pub const pointer_register: usize = 3;
    pub const pointer_previous_clock: usize = 4;
    pub const pointer_bytes: usize = 5;
    pub const pointer_word_index: usize = pointer_bytes + 4;
    pub const span_end_limbs: usize = pointer_word_index + 1;
    pub const digest_big_endian: usize = span_end_limbs + 4;
    pub const r_big_endian: usize = digest_big_endian + abi.digest_size;
    pub const s_big_endian: usize = r_big_endian + abi.scalar_size;
    pub const recovery_id_bytes: usize = s_big_endian + abi.scalar_size;
    pub const public_key_big_endian: usize = recovery_id_bytes + 4;
    pub const status_bytes: usize = public_key_big_endian + abi.public_key_size;
    pub const output_previous_bytes: usize = status_bytes + 4;
    pub const input_previous_clocks: usize =
        output_previous_bytes + output_word_count * 4;
    pub const output_previous_clocks: usize =
        input_previous_clocks + input_word_count;
    pub const main_columns: usize = output_previous_clocks + output_word_count;

    pub fn inputPreviousClock(word: usize) usize {
        std.debug.assert(word < input_word_count);
        return input_previous_clocks + word;
    }

    pub fn outputPreviousClock(word: usize) usize {
        std.debug.assert(word < output_word_count);
        return output_previous_clocks + word;
    }

    pub fn outputPreviousByte(word: usize, byte: usize) usize {
        std.debug.assert(word < output_word_count and byte < 4);
        return output_previous_bytes + 4 * word + byte;
    }
};

pub const event_count: usize = 136;
pub const batch_count: usize = event_count / 2;
pub const range_pair_count: usize = 0;
pub const padding_constraint_count: usize = Layout.main_columns - 1;
pub const constraint_count: usize = 1 + padding_constraint_count + 9;
pub const maximum_constraint_degree: u8 = 3;

pub const Error = error{
    CallIndexMismatch,
    ExecutionClockMismatch,
    ExecutionClockOutOfRange,
    ExecutionOrderMismatch,
    InvalidRecoveryId,
    InvalidStatus,
    PointerMismatch,
    PointerRegisterMismatch,
    ProgramMismatch,
};

comptime {
    if (Layout.main_columns != 292 or event_count != 136 or batch_count != 68)
        @compileError("secp256k1 recovery caller geometry drifted");
}

pub fn preflight(
    records: []const call_buffer.Record,
    rows: []const runner.ExecutionRow,
    total_steps: u32,
) (Error || custom0.DecodeError)!void {
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
        if (decoded.opcode != .secp256k1_recover_signer_v1)
            return error.ProgramMismatch;
        if (decoded.rs1 != record.pointer_register)
            return error.PointerRegisterMismatch;
        if (record.io_ptr & (abi.alignment - 1) != 0)
            return error.PointerMismatch;
        if (record.recovery_id > 1) return error.InvalidRecoveryId;
        if (record.status != abi.success_status) return error.InvalidStatus;
    }
}

pub fn rowFromRecord(record: call_buffer.Record) [Layout.main_columns]M31 {
    var row: [Layout.main_columns]M31 = @splat(M31.zero());
    row[Layout.is_active] = M31.one();
    row[Layout.execution_clock] = M31.fromCanonical(record.execution_clock);
    row[Layout.pc] = M31.fromCanonical(record.pc);
    row[Layout.pointer_register] = M31.fromCanonical(record.pointer_register);
    row[Layout.pointer_previous_clock] =
        M31.fromCanonical(record.pointer_previous_clock);
    writeWord(&row, Layout.pointer_bytes, record.io_ptr);
    const word_index = record.io_ptr / 4;
    row[Layout.pointer_word_index] = M31.fromCanonical(word_index);
    writeWord(
        &row,
        Layout.span_end_limbs,
        word_index + @as(u32, memory_word_count - 1),
    );
    writeBytes(&row, Layout.digest_big_endian, &record.digest_big_endian);
    writeBytes(&row, Layout.r_big_endian, &record.r_big_endian);
    writeBytes(&row, Layout.s_big_endian, &record.s_big_endian);
    writeWord(&row, Layout.recovery_id_bytes, record.recovery_id);
    writeBytes(
        &row,
        Layout.public_key_big_endian,
        &record.public_key_xy_big_endian,
    );
    writeWord(&row, Layout.status_bytes, record.status);
    for (record.output_previous_words, 0..) |word, index| {
        writeWord(&row, Layout.outputPreviousByte(index, 0), word);
    }
    for (record.input_previous_clocks, 0..) |clock, index| {
        row[Layout.inputPreviousClock(index)] = M31.fromCanonical(clock);
    }
    for (record.output_previous_clocks, 0..) |clock, index| {
        row[Layout.outputPreviousClock(index)] = M31.fromCanonical(clock);
    }
    return row;
}

pub fn evaluateDirect(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    sink: anytype,
) void {
    comptime requireSupportedField(S);
    const active = main[Layout.is_active];
    sink.add(active.mul(active.sub(scalar(S, 1))), 2);
    const padding = scalar(S, 1).sub(active);
    for (main[1..]) |value| sink.add(padding.mul(value), 2);
    sink.add(composeWord(S, main[Layout.pointer_bytes..][0..4].*)
        .sub(main[Layout.pointer_word_index].mul(scalar(S, 4))), 1);
    sink.add(composeWord(S, main[Layout.span_end_limbs..][0..4].*)
        .sub(main[Layout.pointer_word_index])
        .sub(active.mul(scalar(S, memory_word_count - 1))), 1);
    for (1..4) |byte| sink.add(
        active.mul(main[Layout.recovery_id_bytes + byte]),
        2,
    );
    sink.add(active.mul(main[Layout.status_bytes].sub(scalar(S, 1))), 2);
    for (1..4) |byte| sink.add(
        active.mul(main[Layout.status_bytes + byte]),
        2,
    );
}

pub fn rowPairs(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    relations: anytype,
) [batch_count]logup.RowPairFor(relations_mod.InteractionScalar(S)) {
    comptime requireSupportedField(S);
    const active = main[Layout.is_active];
    const clock = main[Layout.execution_clock];
    const pointer = main[Layout.pointer_bytes..][0..4].*;
    var events: [event_count]logup.RowPairFor(relations_mod.InteractionScalar(S)) = undefined;
    var cursor: usize = 0;
    events[cursor] = request(S, active, relations_mod.combineAny(S, relations.base.program_access, .{
        liftValue(S, main[Layout.pc]),
        secureScalar(S, opcode_id),
        relations_mod.InteractionScalar(S).zero(),
        liftValue(S, main[Layout.pointer_register]),
        relations_mod.InteractionScalar(S).zero(),
    }));
    cursor += 1;
    events[cursor] = request(S, active, relations_mod.combineAny(S, relations.base.registers_state, .{
        liftValue(S, main[Layout.pc]), liftValue(S, clock),
    }));
    cursor += 1;
    events[cursor] = emit(S, active, relations_mod.combineAny(S, relations.base.registers_state, .{
        liftValue(S, main[Layout.pc].add(scalar(S, 4))),
        liftValue(S, clock.add(scalar(S, 1))),
    }));
    cursor += 1;
    events[cursor] = request(S, active, memoryDenominator(
        S,
        scalar(S, 0),
        main[Layout.pointer_register],
        main[Layout.pointer_previous_clock],
        pointer,
        relations,
    ));
    cursor += 1;
    events[cursor] = emit(S, active, memoryDenominator(
        S,
        scalar(S, 0),
        main[Layout.pointer_register],
        accessClock(S, clock, 1),
        pointer,
        relations,
    ));
    cursor += 1;
    events[cursor] = request(S, active, relations_mod.combineAny(S, relations.base.range_check_20, .{
        liftValue(S, accessClock(S, clock, 1)
            .sub(main[Layout.pointer_previous_clock])
            .sub(scalar(S, 1))),
    }));
    cursor += 1;

    for (0..input_word_count) |word| {
        const bytes = inputWordBytes(S, main, word);
        appendMemoryTransition(
            S,
            &events,
            &cursor,
            active,
            clock,
            wordAddress(S, main[Layout.pointer_word_index], word),
            main[Layout.inputPreviousClock(word)],
            bytes,
            bytes,
            relations,
        );
    }
    for (0..output_word_count) |word| appendMemoryTransition(
        S,
        &events,
        &cursor,
        active,
        clock,
        wordAddress(S, main[Layout.pointer_word_index], input_word_count + word),
        main[Layout.outputPreviousClock(word)],
        main[Layout.outputPreviousByte(word, 0)..][0..4].*,
        outputWordBytes(S, main, word),
        relations,
    );
    events[cursor] = request(S, active, relations_mod.combineAny(S, relations.base.range_check_8_8, .{
        liftValue(S, main[Layout.span_end_limbs]),
        liftValue(S, main[Layout.span_end_limbs + 1]),
    }));
    cursor += 1;
    events[cursor] = request(S, active, relations_mod.combineAny(S, relations.base.range_check_8_8_4, .{
        liftValue(S, main[Layout.span_end_limbs + 2]),
        liftValue(S, main[Layout.pointer_bytes + 3].mul(scalar(S, 4))),
        liftValue(S, main[Layout.span_end_limbs + 3]),
    }));
    cursor += 1;

    const digest = main[Layout.digest_big_endian..][0..32].*;
    const r = main[Layout.r_big_endian..][0..32].*;
    const s = main[Layout.s_big_endian..][0..32].*;
    const public_key_big_endian =
        main[Layout.public_key_big_endian..][0 .. 2 * 32].*;
    events[cursor] = request(S, active, relations_mod.combineRecovery(
        S,
        relations.recovery,
        relations_mod.recoveryTuple(
            S,
            scalar(S, recovery_direct.relation_version),
            main[Layout.status_bytes],
            &digest,
            &r,
            &s,
            main[Layout.recovery_id_bytes],
            &public_key_big_endian,
        ),
    ));
    cursor += 1;
    while (cursor < events.len) : (cursor += 1) {
        events[cursor] = logup.RowPairFor(relations_mod.InteractionScalar(S)).single(
            relations_mod.InteractionScalar(S).zero(),
            relations_mod.InteractionScalar(S).one(),
        );
    }

    var pairs: [batch_count]logup.RowPairFor(relations_mod.InteractionScalar(S)) = undefined;
    for (&pairs, 0..) |*pair, index| pair.* = .{
        .n1 = events[2 * index].n1,
        .d1 = events[2 * index].d1,
        .n2 = events[2 * index + 1].n1,
        .d2 = events[2 * index + 1].d1,
    };
    return pairs;
}

pub fn rangePairs(
    comptime S: type,
    main: *const [Layout.main_columns]S,
) [0][2]S {
    _ = main;
    return .{};
}

fn appendMemoryTransition(comptime S: type, events: *[event_count]logup.RowPairFor(relations_mod.InteractionScalar(S)), cursor: *usize, active: S, clock: S, address: S, previous_clock: S, previous_bytes: [4]S, current_bytes: [4]S, relations: anytype) void {
    events[cursor.*] = request(S, active, memoryDenominator(
        S,
        scalar(S, 1),
        address,
        previous_clock,
        previous_bytes,
        relations,
    ));
    cursor.* += 1;
    events[cursor.*] = emit(S, active, memoryDenominator(
        S,
        scalar(S, 1),
        address,
        accessClock(S, clock, 2),
        current_bytes,
        relations,
    ));
    cursor.* += 1;
    events[cursor.*] = request(S, active, relations_mod.combineAny(S, relations.base.range_check_20, .{
        liftValue(S, accessClock(S, clock, 2)
            .sub(previous_clock)
            .sub(scalar(S, 1))),
    }));
    cursor.* += 1;
}

fn inputWordBytes(comptime S: type, main: *const [Layout.main_columns]S, word: usize) [4]S {
    if (word < 8) return main[Layout.digest_big_endian + 4 * word ..][0..4].*;
    if (word < 16) return main[Layout.r_big_endian + 4 * (word - 8) ..][0..4].*;
    if (word < 24) return main[Layout.s_big_endian + 4 * (word - 16) ..][0..4].*;
    return main[Layout.recovery_id_bytes..][0..4].*;
}

fn outputWordBytes(comptime S: type, main: *const [Layout.main_columns]S, word: usize) [4]S {
    if (word < 16) return main[Layout.public_key_big_endian + 4 * word ..][0..4].*;
    return main[Layout.status_bytes..][0..4].*;
}

fn memoryDenominator(comptime S: type, address_space: S, address: S, clock: S, limbs: [4]S, relations: anytype) relations_mod.InteractionScalar(S) {
    return relations_mod.combineAny(S, relations.base.memory_access, .{
        liftValue(S, address_space), liftValue(S, address),
        liftValue(S, clock),         liftValue(S, limbs[0]),
        liftValue(S, limbs[1]),      liftValue(S, limbs[2]),
        liftValue(S, limbs[3]),
    });
}

fn wordAddress(comptime S: type, pointer_word_index: S, word: usize) S {
    return pointer_word_index.mul(scalar(S, 4)).add(scalar(S, 4 * word));
}

fn accessClock(comptime S: type, clock: S, ordinal: u8) S {
    return clock.sub(scalar(S, 1)).mul(scalar(S, 4)).add(scalar(S, ordinal));
}

fn composeWord(comptime S: type, bytes: [4]S) S {
    return bytes[0]
        .add(bytes[1].mul(scalar(S, 1 << 8)))
        .add(bytes[2].mul(scalar(S, 1 << 16)))
        .add(bytes[3].mul(scalar(S, 1 << 24)));
}

fn request(comptime S: type, coefficient: S, denominator: relations_mod.InteractionScalar(S)) logup.RowPairFor(relations_mod.InteractionScalar(S)) {
    return logup.RowPairFor(relations_mod.InteractionScalar(S)).single(
        liftValue(S, coefficient).neg(),
        denominator,
    );
}

fn emit(comptime S: type, coefficient: S, denominator: relations_mod.InteractionScalar(S)) logup.RowPairFor(relations_mod.InteractionScalar(S)) {
    return logup.RowPairFor(relations_mod.InteractionScalar(S)).single(
        liftValue(S, coefficient),
        denominator,
    );
}

fn liftValue(comptime S: type, value: S) relations_mod.InteractionScalar(S) {
    if (S == M31) return QM31.fromBase(value);
    if (S == QM31) return value;
    return value;
}

fn secureScalar(comptime S: type, value: anytype) relations_mod.InteractionScalar(S) {
    const base = M31.fromU64(@intCast(value));
    if (S == M31 or S == QM31) return QM31.fromBase(base);
    return S.fromBase(base);
}

fn scalar(comptime S: type, value: anytype) S {
    if (S == M31) return M31.fromU64(@intCast(value));
    if (S == QM31) return QM31.fromBase(M31.fromU64(@intCast(value)));
    if (@hasDecl(S, "fromBase")) return S.fromBase(M31.fromU64(@intCast(value)));
    @compileError("recovery caller requires a base-field lift");
}

fn writeWord(row: *[Layout.main_columns]M31, offset: usize, word: u32) void {
    writeBytes(row, offset, &abi.bytesFromWord(word));
}

fn writeBytes(row: *[Layout.main_columns]M31, offset: usize, bytes: []const u8) void {
    for (bytes, 0..) |byte, index| row[offset + index] = M31.fromU64(byte);
}

fn requireSupportedField(comptime S: type) void {
    if (S != M31 and S != QM31 and !@hasDecl(S, "fromBase"))
        @compileError("recovery caller requires a base-field lift");
}
