//! Field-native round AIR candidate for fixed-64-byte SHA-256 pair hashing.
//!
//! One call occupies exactly 128 active rows: 64 rounds for the raw pair and
//! 64 rounds for the fixed padding block. Every 32-bit value is decomposed to
//! bits and every modular addition carries its own range-constrained carry
//! chain. The caller and output relations are field-native, but CPU dispatch,
//! memory linkage and production registration intentionally remain absent.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const sha = @import("sha256_pair_candidate_v1.zig");

pub const production_active = false;
pub const cpu_dispatch_ready = false;
pub const memory_relation_ready = false;
pub const maximum_constraint_degree: u8 = 4;
pub const word_bits: usize = 32;
pub const ring_word_count: usize = 16;
pub const rows_per_call: usize = sha.block_count * sha.round_count;
pub const relation_schema_numeric_id: u32 = 0x5348_5031;
pub const input_relation_arity: usize = 2 + sha.input_bytes;
pub const output_relation_arity: usize = 2 + sha.output_bytes;
pub const main_column_count: usize = 2_162;
pub const constraint_count: usize = 7_168;
pub const Digest = sha.Digest;

pub const Error = error{InvalidPosition};

pub const Position = struct {
    block: u1,
    round: u6,

    pub fn init(block: usize, round: usize) Error!Position {
        if (block >= sha.block_count or round >= sha.round_count)
            return error.InvalidPosition;
        return .{ .block = @intCast(block), .round = @intCast(round) };
    }

    pub fn isCallFirst(self: Position) bool {
        return self.block == 0 and self.round == 0;
    }

    pub fn isBlockFirst(self: Position) bool {
        return self.round == 0;
    }

    pub fn isBlockLast(self: Position) bool {
        return self.round == sha.round_count - 1;
    }

    pub fn isCallLast(self: Position) bool {
        return self.block == sha.block_count - 1 and self.isBlockLast();
    }
};

pub fn Bits(comptime S: type) type {
    return [word_bits]S;
}

pub fn Row(comptime S: type) type {
    return struct {
        active: S,
        call_index: S,
        base_state: [sha.state_word_count]Bits(S),
        state_before: [sha.state_word_count]Bits(S),
        state_after: [sha.state_word_count]Bits(S),
        schedule_ring: [ring_word_count]Bits(S),
        schedule_append: Bits(S),
        schedule_carry: [word_bits + 1][2]S,
        t1: Bits(S),
        t1_carry: [word_bits + 1][3]S,
        t2: Bits(S),
        t2_carry: [word_bits + 1]S,
        a_carry: [word_bits + 1]S,
        e_carry: [word_bits + 1]S,
        digest: [sha.state_word_count]Bits(S),
        digest_carry: [sha.state_word_count][word_bits + 1]S,
    };
}

pub fn zeroRow(comptime S: type) Row(S) {
    return .{
        .active = S.zero(),
        .call_index = S.zero(),
        .base_state = @splat(@splat(S.zero())),
        .state_before = @splat(@splat(S.zero())),
        .state_after = @splat(@splat(S.zero())),
        .schedule_ring = @splat(@splat(S.zero())),
        .schedule_append = @splat(S.zero()),
        .schedule_carry = @splat(@splat(S.zero())),
        .t1 = @splat(S.zero()),
        .t1_carry = @splat(@splat(S.zero())),
        .t2 = @splat(S.zero()),
        .t2_carry = @splat(S.zero()),
        .a_carry = @splat(S.zero()),
        .e_carry = @splat(S.zero()),
        .digest = @splat(@splat(S.zero())),
        .digest_carry = @splat(@splat(S.zero())),
    };
}

pub fn fill(
    call_index: u32,
    witness: *const sha.WitnessV1,
    position: Position,
) Row(M31) {
    var result = zeroRow(M31);
    result.active = M31.one();
    result.call_index = M31.fromCanonical(call_index);
    const block: usize = position.block;
    const round: usize = position.round;
    const trace = witness.blocks[block];
    const base = if (block == 0)
        sha.initial_state
    else
        witness.blocks[block - 1].output_state;
    writeStateBits(&result.base_state, base);
    writeStateBits(&result.state_before, trace.states[round]);
    writeStateBits(&result.state_after, trace.states[round + 1]);
    for (&result.schedule_ring, 0..) |*destination, offset| {
        const index = round + offset;
        writeWordBits(destination, if (index < sha.schedule_word_count)
            trace.schedule[index]
        else
            0);
    }
    const append = if (round + ring_word_count < sha.schedule_word_count)
        trace.schedule[round + ring_word_count]
    else
        0;
    writeWordBits(&result.schedule_append, append);
    if (round < 48) {
        result.schedule_carry = fillCarryBits(4, 2, .{
            sha.sigmaSmall1(trace.schedule[round + 14]),
            trace.schedule[round + 9],
            sha.sigmaSmall0(trace.schedule[round + 1]),
            trace.schedule[round],
        }, append);
    }

    const state = trace.states[round];
    const t1 = state[7] +% sha.sigmaBig1(state[4]) +%
        sha.choose(state[4], state[5], state[6]) +%
        sha.round_constants[round] +% trace.schedule[round];
    const t2 = sha.sigmaBig0(state[0]) +%
        sha.majority(state[0], state[1], state[2]);
    writeWordBits(&result.t1, t1);
    writeWordBits(&result.t2, t2);
    result.t1_carry = fillCarryBits(5, 3, .{
        state[7],
        sha.sigmaBig1(state[4]),
        sha.choose(state[4], state[5], state[6]),
        sha.round_constants[round],
        trace.schedule[round],
    }, t1);
    result.t2_carry = fillSingleCarry(.{
        sha.sigmaBig0(state[0]),
        sha.majority(state[0], state[1], state[2]),
    }, t2);
    result.a_carry = fillSingleCarry(.{ t1, t2 }, trace.states[round + 1][0]);
    result.e_carry = fillSingleCarry(
        .{ state[3], t1 },
        trace.states[round + 1][4],
    );
    if (position.isBlockLast()) {
        writeStateBits(&result.digest, trace.output_state);
        for (0..sha.state_word_count) |word| {
            result.digest_carry[word] = fillSingleCarry(
                .{ base[word], trace.states[round + 1][word] },
                trace.output_state[word],
            );
        }
    }
    return result;
}

pub fn evaluateGeneric(
    comptime S: type,
    row: *const Row(S),
    next: *const Row(S),
    position: Position,
    expected_active: S,
    sink: anytype,
) void {
    const one = S.one();
    const active = row.active;
    const padding = one.sub(active);
    sink.add(active.mul(one.sub(active)), 2);
    sink.add(active.sub(expected_active), 1);
    constrainBits(S, row, sink);
    constrainPadding(S, row, padding, sink);

    const schedule_gate = active.mul(boolScalar(S, position.round < 48));
    const no_schedule_gate = active.mul(boolScalar(S, position.round >= 48));
    constrainSchedule(S, row, schedule_gate, no_schedule_gate, sink);
    constrainRound(S, row, position, active, sink);

    const last_gate = active.mul(boolScalar(S, position.isBlockLast()));
    const nonlast_gate = active.mul(boolScalar(S, !position.isBlockLast()));
    constrainDigest(S, row, last_gate, nonlast_gate, sink);
    constrainInitialState(S, row, position, active, sink);
    constrainTransition(S, row, next, position, active, sink);
}

pub fn inputRelationTuple(
    comptime S: type,
    row: *const Row(S),
) [input_relation_arity]S {
    var result: [input_relation_arity]S = undefined;
    result[0] = fromU32(S, relation_schema_numeric_id);
    result[1] = row.call_index;
    for (0..sha.input_bytes) |byte| {
        const word = byte / 4;
        const within_word = byte % 4;
        result[2 + byte] = bigEndianByte(
            S,
            &row.schedule_ring[word],
            within_word,
        );
    }
    return result;
}

pub fn outputRelationTuple(
    comptime S: type,
    row: *const Row(S),
) [output_relation_arity]S {
    var result: [output_relation_arity]S = undefined;
    result[0] = fromU32(S, relation_schema_numeric_id);
    result[1] = row.call_index;
    for (0..sha.output_bytes) |byte| {
        const word = byte / 4;
        const within_word = byte % 4;
        result[2 + byte] = bigEndianByte(S, &row.digest[word], within_word);
    }
    return result;
}

pub fn airProgramIdentity() Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.sha256-pair-64-round-air-program.v1\x00");
    const semantic_identity = sha.verifierProgramIdentity();
    hash.update(&semantic_identity);
    hashInt(&hash, main_column_count);
    hashInt(&hash, constraint_count);
    hashInt(&hash, maximum_constraint_degree);
    hashInt(&hash, rows_per_call);
    hashInt(&hash, relation_schema_numeric_id);
    hashInt(&hash, input_relation_arity);
    hashInt(&hash, output_relation_arity);
    var result: Digest = undefined;
    hash.final(&result);
    return result;
}

fn constrainBits(comptime S: type, row: *const Row(S), sink: anytype) void {
    for (row.base_state) |word| constrainBitSlice(S, &word, sink);
    for (row.state_before) |word| constrainBitSlice(S, &word, sink);
    for (row.state_after) |word| constrainBitSlice(S, &word, sink);
    for (row.schedule_ring) |word| constrainBitSlice(S, &word, sink);
    constrainBitSlice(S, &row.schedule_append, sink);
    for (row.schedule_carry) |carry| constrainBitSlice(S, &carry, sink);
    constrainBitSlice(S, &row.t1, sink);
    for (row.t1_carry) |carry| constrainBitSlice(S, &carry, sink);
    constrainBitSlice(S, &row.t2, sink);
    constrainBitSlice(S, &row.t2_carry, sink);
    constrainBitSlice(S, &row.a_carry, sink);
    constrainBitSlice(S, &row.e_carry, sink);
    for (row.digest) |word| constrainBitSlice(S, &word, sink);
    for (row.digest_carry) |carry| constrainBitSlice(S, &carry, sink);
    for (row.t1_carry) |carry| {
        sink.add(carry[2].mul(carry[0]), 2);
        sink.add(carry[2].mul(carry[1]), 2);
    }
}

fn constrainPadding(
    comptime S: type,
    row: *const Row(S),
    padding: S,
    sink: anytype,
) void {
    sink.add(padding.mul(row.call_index), 2);
    for (row.base_state) |word| constrainZeroSlice(S, &word, padding, sink);
    for (row.state_before) |word| constrainZeroSlice(S, &word, padding, sink);
    for (row.state_after) |word| constrainZeroSlice(S, &word, padding, sink);
    for (row.schedule_ring) |word| constrainZeroSlice(S, &word, padding, sink);
    constrainZeroSlice(S, &row.schedule_append, padding, sink);
    for (row.schedule_carry) |carry| constrainZeroSlice(S, &carry, padding, sink);
    constrainZeroSlice(S, &row.t1, padding, sink);
    for (row.t1_carry) |carry| constrainZeroSlice(S, &carry, padding, sink);
    constrainZeroSlice(S, &row.t2, padding, sink);
    constrainZeroSlice(S, &row.t2_carry, padding, sink);
    constrainZeroSlice(S, &row.a_carry, padding, sink);
    constrainZeroSlice(S, &row.e_carry, padding, sink);
    for (row.digest) |word| constrainZeroSlice(S, &word, padding, sink);
    for (row.digest_carry) |carry| constrainZeroSlice(S, &carry, padding, sink);
}

fn constrainSchedule(
    comptime S: type,
    row: *const Row(S),
    schedule_gate: S,
    no_schedule_gate: S,
    sink: anytype,
) void {
    sink.add(row.schedule_carry[0][0], 1);
    sink.add(row.schedule_carry[0][1], 1);
    for (0..word_bits) |bit| {
        const sum = sigmaSmall1Bits(S, &row.schedule_ring[14], bit)
            .add(row.schedule_ring[9][bit])
            .add(sigmaSmall0Bits(S, &row.schedule_ring[1], bit))
            .add(row.schedule_ring[0][bit])
            .add(twoBitValue(S, row.schedule_carry[bit]));
        const equality = sum.sub(row.schedule_append[bit]).sub(mulSmall(
            S,
            twoBitValue(S, row.schedule_carry[bit + 1]),
            2,
        ));
        sink.add(schedule_gate.mul(equality), 4);
        sink.add(no_schedule_gate.mul(row.schedule_append[bit]), 2);
    }
    for (row.schedule_carry) |carry| {
        sink.add(no_schedule_gate.mul(carry[0]), 2);
        sink.add(no_schedule_gate.mul(carry[1]), 2);
    }
}

fn constrainRound(
    comptime S: type,
    row: *const Row(S),
    position: Position,
    active: S,
    sink: anytype,
) void {
    for (row.t1_carry[0]) |bit| sink.add(bit, 1);
    sink.add(row.t2_carry[0], 1);
    sink.add(row.a_carry[0], 1);
    sink.add(row.e_carry[0], 1);
    const constant = sha.round_constants[position.round];
    for (0..word_bits) |bit| {
        const t1_sum = row.state_before[7][bit]
            .add(sigmaBig1Bits(S, &row.state_before[4], bit))
            .add(chooseBit(S, row.state_before[4][bit], row.state_before[5][bit], row.state_before[6][bit]))
            .add(boolScalar(S, constant >> @intCast(bit) & 1 != 0))
            .add(row.schedule_ring[0][bit])
            .add(threeBitValue(S, row.t1_carry[bit]));
        sink.add(active.mul(t1_sum.sub(row.t1[bit]).sub(mulSmall(
            S,
            threeBitValue(S, row.t1_carry[bit + 1]),
            2,
        ))), 4);

        const t2_sum = sigmaBig0Bits(S, &row.state_before[0], bit)
            .add(majorityBit(S, row.state_before[0][bit], row.state_before[1][bit], row.state_before[2][bit]))
            .add(row.t2_carry[bit]);
        sink.add(active.mul(t2_sum.sub(row.t2[bit]).sub(mulSmall(
            S,
            row.t2_carry[bit + 1],
            2,
        ))), 4);

        const a_sum = row.t1[bit].add(row.t2[bit]).add(row.a_carry[bit]);
        sink.add(active.mul(a_sum.sub(row.state_after[0][bit]).sub(mulSmall(
            S,
            row.a_carry[bit + 1],
            2,
        ))), 2);
        const e_sum = row.state_before[3][bit].add(row.t1[bit]).add(row.e_carry[bit]);
        sink.add(active.mul(e_sum.sub(row.state_after[4][bit]).sub(mulSmall(
            S,
            row.e_carry[bit + 1],
            2,
        ))), 2);
    }
    const shifted_lanes = [_]struct { after: usize, before: usize }{
        .{ .after = 1, .before = 0 }, .{ .after = 2, .before = 1 },
        .{ .after = 3, .before = 2 }, .{ .after = 5, .before = 4 },
        .{ .after = 6, .before = 5 }, .{ .after = 7, .before = 6 },
    };
    for (shifted_lanes) |lane| {
        for (0..word_bits) |bit| sink.add(active.mul(
            row.state_after[lane.after][bit].sub(row.state_before[lane.before][bit]),
        ), 2);
    }
}

fn constrainDigest(
    comptime S: type,
    row: *const Row(S),
    last_gate: S,
    nonlast_gate: S,
    sink: anytype,
) void {
    for (0..sha.state_word_count) |word| {
        sink.add(row.digest_carry[word][0], 1);
        for (0..word_bits) |bit| {
            const sum = row.base_state[word][bit]
                .add(row.state_after[word][bit])
                .add(row.digest_carry[word][bit]);
            sink.add(last_gate.mul(sum.sub(row.digest[word][bit]).sub(mulSmall(
                S,
                row.digest_carry[word][bit + 1],
                2,
            ))), 2);
            sink.add(nonlast_gate.mul(row.digest[word][bit]), 2);
        }
        for (row.digest_carry[word]) |carry|
            sink.add(nonlast_gate.mul(carry), 2);
    }
}

fn constrainInitialState(
    comptime S: type,
    row: *const Row(S),
    position: Position,
    active: S,
    sink: anytype,
) void {
    const call_first = active.mul(boolScalar(S, position.isCallFirst()));
    const block_first = active.mul(boolScalar(S, position.isBlockFirst()));
    for (0..sha.state_word_count) |word| {
        for (0..word_bits) |bit| {
            const expected = boolScalar(
                S,
                sha.initial_state[word] >> @intCast(bit) & 1 != 0,
            );
            sink.add(call_first.mul(row.base_state[word][bit].sub(expected)), 2);
            sink.add(block_first.mul(
                row.state_before[word][bit].sub(row.base_state[word][bit]),
            ), 2);
        }
    }
}

fn constrainTransition(
    comptime S: type,
    row: *const Row(S),
    next: *const Row(S),
    position: Position,
    active: S,
    sink: anytype,
) void {
    const has_next = !position.isCallLast();
    const gate = active.mul(boolScalar(S, has_next));
    sink.add(gate.mul(next.call_index.sub(row.call_index)), 2);
    for (0..sha.state_word_count) |word| {
        for (0..word_bits) |bit| {
            const expected_base = if (!position.isBlockLast())
                row.base_state[word][bit]
            else
                row.digest[word][bit];
            const expected_state = if (!position.isBlockLast())
                row.state_after[word][bit]
            else
                row.digest[word][bit];
            sink.add(gate.mul(next.base_state[word][bit].sub(expected_base)), 2);
            sink.add(gate.mul(next.state_before[word][bit].sub(expected_state)), 2);
        }
    }
    const padding = sha.paddingBlock();
    for (0..ring_word_count) |word| {
        const padding_word = std.mem.readInt(
            u32,
            padding[word * 4 ..][0..4],
            .big,
        );
        for (0..word_bits) |bit| {
            const expected = if (!position.isBlockLast())
                (if (word + 1 < ring_word_count)
                    row.schedule_ring[word + 1][bit]
                else
                    row.schedule_append[bit])
            else
                boolScalar(S, padding_word >> @intCast(bit) & 1 != 0);
            sink.add(gate.mul(next.schedule_ring[word][bit].sub(expected)), 2);
        }
    }
}

fn constrainBitSlice(comptime S: type, values: anytype, sink: anytype) void {
    const one = S.one();
    for (values) |value| sink.add(value.mul(one.sub(value)), 2);
}

fn constrainZeroSlice(
    comptime S: type,
    values: anytype,
    gate: S,
    sink: anytype,
) void {
    for (values) |value| sink.add(gate.mul(value), 2);
}

fn sigmaSmall0Bits(comptime S: type, bits: *const Bits(S), bit: usize) S {
    return xor3(
        S,
        bits[(bit + 7) % word_bits],
        bits[(bit + 18) % word_bits],
        if (bit + 3 < word_bits) bits[bit + 3] else S.zero(),
    );
}

fn sigmaSmall1Bits(comptime S: type, bits: *const Bits(S), bit: usize) S {
    return xor3(
        S,
        bits[(bit + 17) % word_bits],
        bits[(bit + 19) % word_bits],
        if (bit + 10 < word_bits) bits[bit + 10] else S.zero(),
    );
}

fn sigmaBig0Bits(comptime S: type, bits: *const Bits(S), bit: usize) S {
    return xor3(
        S,
        bits[(bit + 2) % word_bits],
        bits[(bit + 13) % word_bits],
        bits[(bit + 22) % word_bits],
    );
}

fn sigmaBig1Bits(comptime S: type, bits: *const Bits(S), bit: usize) S {
    return xor3(
        S,
        bits[(bit + 6) % word_bits],
        bits[(bit + 11) % word_bits],
        bits[(bit + 25) % word_bits],
    );
}

fn xor3(comptime S: type, a: S, b: S, c: S) S {
    const ab = a.mul(b);
    const ac = a.mul(c);
    const bc = b.mul(c);
    return a.add(b).add(c)
        .sub(mulSmall(S, ab.add(ac).add(bc), 2))
        .add(mulSmall(S, ab.mul(c), 4));
}

fn chooseBit(comptime S: type, e: S, f: S, g: S) S {
    return e.mul(f).add(S.one().sub(e).mul(g));
}

fn majorityBit(comptime S: type, a: S, b: S, c: S) S {
    return a.mul(b).add(a.mul(c)).add(b.mul(c)).sub(mulSmall(
        S,
        a.mul(b).mul(c),
        2,
    ));
}

fn twoBitValue(comptime S: type, bits: [2]S) S {
    return bits[0].add(mulSmall(S, bits[1], 2));
}

fn threeBitValue(comptime S: type, bits: [3]S) S {
    return bits[0]
        .add(mulSmall(S, bits[1], 2))
        .add(mulSmall(S, bits[2], 4));
}

fn bigEndianByte(
    comptime S: type,
    bits: *const Bits(S),
    byte_index: usize,
) S {
    var result = S.zero();
    const first = (3 - byte_index) * 8;
    for (0..8) |bit|
        result = result.add(mulSmall(S, bits[first + bit], @as(u32, 1) << @intCast(bit)));
    return result;
}

fn writeStateBits(destination: *[sha.state_word_count]Bits(M31), state: sha.State) void {
    for (destination, state) |*bits, word| writeWordBits(bits, word);
}

fn writeWordBits(destination: *Bits(M31), word: u32) void {
    for (destination, 0..) |*bit, index|
        bit.* = M31.fromCanonical(word >> @intCast(index) & 1);
}

fn fillCarryBits(
    comptime term_count: usize,
    comptime carry_bit_count: usize,
    terms: [term_count]u32,
    output: u32,
) [word_bits + 1][carry_bit_count]M31 {
    var result = [_][carry_bit_count]M31{
        [_]M31{M31.zero()} ** carry_bit_count,
    } ** (word_bits + 1);
    var carry: u32 = 0;
    for (0..word_bits) |bit| {
        writeCarryBits(carry_bit_count, &result[bit], carry);
        var sum = carry;
        for (terms) |term| sum += term >> @intCast(bit) & 1;
        std.debug.assert(sum & 1 == output >> @intCast(bit) & 1);
        carry = sum >> 1;
    }
    writeCarryBits(carry_bit_count, &result[word_bits], carry);
    return result;
}

fn fillSingleCarry(terms: [2]u32, output: u32) [word_bits + 1]M31 {
    const expanded = fillCarryBits(2, 1, terms, output);
    var result: [word_bits + 1]M31 = undefined;
    for (&result, expanded) |*destination, source| destination.* = source[0];
    return result;
}

fn writeCarryBits(
    comptime carry_bit_count: usize,
    destination: *[carry_bit_count]M31,
    carry: u32,
) void {
    std.debug.assert(carry < @as(u32, 1) << carry_bit_count);
    for (destination, 0..) |*bit, index|
        bit.* = M31.fromCanonical(carry >> @intCast(index) & 1);
}

fn boolScalar(comptime S: type, value: bool) S {
    return fromU32(S, @intFromBool(value));
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
    if (rows_per_call != 128 or main_column_count != 2_162 or
        constraint_count != 7_168 or maximum_constraint_degree != 4 or
        production_active or cpu_dispatch_ready or memory_relation_ready)
    {
        @compileError("fixed SHA-256 pair round AIR candidate geometry drifted");
    }
}
