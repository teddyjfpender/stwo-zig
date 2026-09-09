//! Streaming field-native block evaluator for the non-production sponge.
//!
//! One active row represents one 136-byte absorption block.  It derives the
//! exact Keccak-f input tuple from prior-state bits, raw input bits and the
//! Ethereum padding law, and links the returned state through the existing
//! Keccak-f I/O relation.  Guest-memory reads/writes remain intentionally
//! unavailable, so this is not yet an admissible component.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const relations = @import("keccakf_relations.zig");
const sponge = @import("keccak256_sponge_candidate_v1.zig");

pub const production_active = false;
pub const memory_relation_ready = false;
pub const maximum_constraint_degree: u8 = 2;
pub const state_bits: usize = 1600;
pub const rate_bits: usize = sponge.rate_bytes * 8;
pub const main_column_count: usize = 5 + sponge.rate_bytes + rate_bits + 2 * state_bits;
pub const constraint_count: usize = 13_416;
pub const Digest = [32]u8;

pub fn Row(comptime S: type) type {
    return struct {
        active: S,
        is_first: S,
        is_final: S,
        call_index: S,
        permutation_index: S,
        input_mask: [sponge.rate_bytes]S,
        input_bits: [rate_bits]S,
        state_before: [state_bits]S,
        state_after: [state_bits]S,
    };
}

pub fn fill(
    call_index: u32,
    permutation_index: u32,
    block: sponge.BlockV1,
) Row(M31) {
    var result = zeroRow(M31);
    result.active = M31.one();
    result.is_first = M31.fromCanonical(@intFromBool(block.block_index == 0));
    result.is_final = M31.fromCanonical(@intFromBool(block.is_final));
    result.call_index = M31.fromCanonical(call_index);
    result.permutation_index = M31.fromCanonical(permutation_index);
    for (&result.input_mask, 0..) |*mask, byte|
        mask.* = M31.fromCanonical(@intFromBool(byte < block.input_count));
    for (&result.input_bits, 0..) |*bit, position| {
        const byte = position / 8;
        const offset: u3 = @intCast(position % 8);
        bit.* = M31.fromCanonical(@truncate(block.input_rate[byte] >> offset));
    }
    writeStateBits(M31, &result.state_before, block.state_before);
    writeStateBits(M31, &result.state_after, block.permutation_output);
    return result;
}

pub fn zeroRow(comptime S: type) Row(S) {
    return .{
        .active = S.zero(),
        .is_first = S.zero(),
        .is_final = S.zero(),
        .call_index = S.zero(),
        .permutation_index = S.zero(),
        .input_mask = @splat(S.zero()),
        .input_bits = @splat(S.zero()),
        .state_before = @splat(S.zero()),
        .state_after = @splat(S.zero()),
    };
}

pub fn evaluateGeneric(
    comptime S: type,
    row: *const Row(S),
    next_state_before: *const [state_bits]S,
    is_active: S,
    sink: anytype,
) void {
    const one = S.one();
    const padding = one.sub(row.active);
    sink.add(row.active.mul(one.sub(row.active)), 2);
    sink.add(row.is_first.mul(one.sub(row.is_first)), 2);
    sink.add(row.is_final.mul(one.sub(row.is_final)), 2);
    sink.add(row.is_first.mul(one.sub(row.active)), 2);
    sink.add(row.is_final.mul(one.sub(row.active)), 2);
    sink.add(row.active.sub(is_active), 1);

    sink.add(padding.mul(row.call_index), 2);
    sink.add(padding.mul(row.permutation_index), 2);
    for (row.input_mask) |mask| sink.add(padding.mul(mask), 2);
    for (row.input_bits) |bit| sink.add(padding.mul(bit), 2);
    for (row.state_before) |bit| sink.add(padding.mul(bit), 2);
    for (row.state_after) |bit| sink.add(padding.mul(bit), 2);

    for (row.input_mask, 0..) |mask, byte| {
        sink.add(mask.mul(one.sub(mask)), 2);
        if (byte != 0) sink.add(
            mask.mul(one.sub(row.input_mask[byte - 1])),
            2,
        );
        const nonfinal = row.active.sub(row.is_final);
        sink.add(nonfinal.mul(one.sub(mask)), 2);
    }
    sink.add(row.is_final.mul(row.input_mask[sponge.rate_bytes - 1]), 2);

    for (row.input_bits, 0..) |bit, position| {
        const mask = row.input_mask[position / 8];
        sink.add(bit.mul(one.sub(bit)), 2);
        sink.add(bit.mul(one.sub(mask)), 2);
    }
    for (row.state_before) |bit| sink.add(bit.mul(one.sub(bit)), 2);
    for (row.state_after) |bit| sink.add(bit.mul(one.sub(bit)), 2);

    const continuation = row.active.sub(row.is_final);
    for (0..state_bits) |bit| {
        sink.add(row.is_first.mul(row.state_before[bit]), 2);
        sink.add(continuation.mul(
            next_state_before[bit].sub(row.state_after[bit]),
        ), 2);
    }
}

pub fn permutationIoTuple(
    comptime S: type,
    row: *const Row(S),
) relations.IoTupleFor(S) {
    var result: relations.IoTupleFor(S) = undefined;
    result[0] = row.permutation_index;
    for (0..relations.state_chunk_count) |chunk| {
        result[1 + chunk] = packInputChunk(S, row, chunk);
        result[1 + relations.state_chunk_count + chunk] = packBits(
            S,
            &row.state_after,
            chunk,
        );
    }
    return result;
}

pub fn outputBytes(
    comptime S: type,
    row: *const Row(S),
) [sponge.output_bytes]S {
    var result: [sponge.output_bytes]S = undefined;
    for (&result, 0..) |*byte, byte_index| {
        var value = S.zero();
        inline for (0..8) |bit| value = value.add(mulSmall(
            S,
            row.state_after[8 * byte_index + bit],
            @as(u32, 1) << bit,
        ));
        byte.* = value;
    }
    return result;
}

pub fn airProgramIdentity() Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.keccak256-sponge-block-air-program.v1\x00");
    const sponge_identity = sponge.verifierProgramIdentity();
    hash.update(&sponge_identity);
    hashInt(&hash, main_column_count);
    hashInt(&hash, constraint_count);
    hashInt(&hash, maximum_constraint_degree);
    hashInt(&hash, relations.io_schema_numeric_id);
    hashInt(&hash, relations.io_schema.version);
    hashInt(&hash, relations.io_arity);
    var result: Digest = undefined;
    hash.final(&result);
    return result;
}

fn paddedInputBit(
    comptime S: type,
    row: *const Row(S),
    position: usize,
) S {
    const byte = position / 8;
    const bit = position % 8;
    const previous_mask = if (byte == 0) row.active else row.input_mask[byte - 1];
    const first_padding = previous_mask.sub(row.input_mask[byte]);
    var result = row.input_bits[position];
    if (bit == 0) result = result.add(first_padding);
    if (byte + 1 == sponge.rate_bytes and bit == 7)
        result = result.add(row.is_final);
    return result;
}

fn permutationInputBit(
    comptime S: type,
    row: *const Row(S),
    position: usize,
) S {
    if (position >= rate_bits) return row.state_before[position];
    const message = paddedInputBit(S, row, position);
    const state = row.state_before[position];
    return state.add(message).sub(mulSmall(S, state.mul(message), 2));
}

fn packInputChunk(
    comptime S: type,
    row: *const Row(S),
    chunk: usize,
) S {
    const first = chunk * relations.state_chunk_bits;
    const count = @min(relations.state_chunk_bits, state_bits - first);
    var result = S.zero();
    var coefficient: u32 = 1;
    for (0..count) |offset| {
        result = result.add(mulSmall(
            S,
            permutationInputBit(S, row, first + offset),
            coefficient,
        ));
        coefficient <<= 1;
    }
    return result;
}

fn packBits(
    comptime S: type,
    bits: *const [state_bits]S,
    chunk: usize,
) S {
    const first = chunk * relations.state_chunk_bits;
    const count = @min(relations.state_chunk_bits, state_bits - first);
    var result = S.zero();
    var coefficient: u32 = 1;
    for (0..count) |offset| {
        result = result.add(mulSmall(S, bits[first + offset], coefficient));
        coefficient <<= 1;
    }
    return result;
}

fn writeStateBits(
    comptime S: type,
    destination: *[state_bits]S,
    state: sponge.State,
) void {
    for (destination, 0..) |*bit, position| {
        const lane = position / 64;
        const offset: u6 = @intCast(position % 64);
        bit.* = fromU32(S, @truncate((state[lane] >> offset) & 1));
    }
}

fn fromU32(comptime S: type, value: u32) S {
    if (comptime S == M31) return M31.fromCanonical(value);
    if (comptime S == QM31) return QM31.fromBase(M31.fromCanonical(value));
    return S.fromBase(M31.fromCanonical(value));
}

fn mulSmall(comptime S: type, value: S, coefficient: u32) S {
    if (comptime S == M31) return value.mul(M31.fromCanonical(coefficient));
    if (comptime S == QM31) return value.mulM31(M31.fromCanonical(coefficient));
    return value.mul(S.fromBase(M31.fromCanonical(coefficient)));
}

fn hashInt(hash: anytype, value: anytype) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (state_bits != 1600 or rate_bits != 1088 or
        main_column_count != 4429 or constraint_count != 13_416 or
        maximum_constraint_degree != 2 or production_active or
        memory_relation_ready)
    {
        @compileError("Keccak-256 sponge block AIR candidate geometry drifted");
    }
}
