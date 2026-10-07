//! Table-free, 80-row private Bitcoin SHA256d caller equations.
//!
//! Local equations bind 56 circuit u16 Gate values to header/digest SHA words
//! with 32 Boolean bits per boundary word. The word events still need a joint
//! lookup bus with the schedule, round and feed-forward AIRs. This file alone
//! is neither an AIR proof nor authority for private header bytes.
const std = @import("std");
const core = @import("stwo_core");
const plan_mod = @import("sha_chip_plan.zig");
const sha = @import("s31_sha_provider").compression;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const modulus = core.fields.m31.Modulus;

pub const row_count: usize = 80;
pub const gate_count: usize = 56;
pub const word_count: usize = 96;
pub const constraint_count: usize = 38;

pub fn Row(comptime F: type) type {
    return struct {
        gate_limbs: [2]F,
        words: [2][2]F, // Low and high u16 of each SHA big-endian word.
        serialized_bits: [32]F, // Only header/digest rows use these bits.
    };
}

pub fn GateEvent(comptime F: type) type {
    return struct { address: u32, value: F };
}
pub fn WordEvent(comptime F: type) type {
    return struct { call_id: u32, word_id: u32, lo: F, hi: F, direction: enum { emit_input, consume_output } };
}

pub const Config = struct {
    gate_addresses: [gate_count]u32,
    first_call_id: u32,

    pub fn validate(self: Config) !void {
        if (self.first_call_id == 0 or self.first_call_id > modulus - 3) return error.InvalidShaCallId;
        for (self.gate_addresses, 0..) |address, index| {
            if (address <= 2 or address >= modulus) return error.InvalidShaGateAddress;
            for (self.gate_addresses[0..index]) |earlier| if (address == earlier) return error.DuplicateShaGateAddress;
        }
    }
};

const Kind = enum { header, digest, chain_state, chain_digest, iv_first, iv_third, pad_second, pad_third };
fn kind(index: usize) Kind {
    std.debug.assert(index < row_count);
    if (index < 20) return .header;
    if (index < 28) return .digest;
    if (index < 36) return .chain_state;
    if (index < 44) return .chain_digest;
    if (index < 52) return .iv_first;
    if (index < 60) return .iv_third;
    if (index < 72) return .pad_second;
    return .pad_third;
}

fn fixed(comptime F: type, value: u32) F {
    const base = M31.fromCanonical(value);
    return if (F == M31) base else if (F == QM31) QM31.fromBase(base) else @compileError("SHA caller requires M31 or QM31");
}
fn packBits(comptime F: type, bits: [32]F, start: usize) F {
    var result = fixed(F, 0);
    for (0..16) |i| result = result.add(bits[start + i].mul(fixed(F, @as(u32, 1) << @intCast(i))));
    return result;
}
fn swappedHalf(comptime F: type, bits: [32]F, low_byte: usize, high_byte: usize) F {
    var result = fixed(F, 0);
    for (0..8) |i| {
        result = result.add(bits[8 * low_byte + i].mul(fixed(F, @as(u32, 1) << @intCast(i))));
        result = result.add(bits[8 * high_byte + i].mul(fixed(F, @as(u32, 1) << @intCast(i + 8))));
    }
    return result;
}

fn constantWord(index: usize) u32 {
    return switch (kind(index)) {
        .iv_first => sha.initial_state[index - 44],
        .iv_third => sha.initial_state[index - 52],
        .pad_second => if (index == 60) 0x80000000 else if (index == 71) 640 else 0,
        .pad_third => if (index == 72) 0x80000000 else if (index == 79) 256 else 0,
        else => unreachable,
    };
}

/// All unused row fields are fixed to zero, so they cannot become free bus
/// values later. Header/digest byte swaps are computed from Boolean bits,
/// avoiding the field-linear packing alias between two independent u16s.
pub fn evaluate(comptime F: type, row: Row(F), index: usize) [constraint_count]F {
    var out: [constraint_count]F = @splat(fixed(F, 0));
    var at: usize = 0;
    switch (kind(index)) {
        .header, .digest => {
            for (row.serialized_bits) |value| {
                out[at] = value.mul(value.sub(fixed(F, 1)));
                at += 1;
            }
            out[at] = row.gate_limbs[0].sub(packBits(F, row.serialized_bits, 0));
            at += 1;
            out[at] = row.gate_limbs[1].sub(packBits(F, row.serialized_bits, 16));
            at += 1;
            out[at] = row.words[0][0].sub(swappedHalf(F, row.serialized_bits, 3, 2));
            at += 1;
            out[at] = row.words[0][1].sub(swappedHalf(F, row.serialized_bits, 1, 0));
            at += 1;
            out[at] = row.words[1][0];
            at += 1;
            out[at] = row.words[1][1];
            at += 1;
        },
        .chain_state, .chain_digest => {
            for (row.gate_limbs) |value| {
                out[at] = value;
                at += 1;
            }
            for (row.serialized_bits) |value| {
                out[at] = value;
                at += 1;
            }
            for (0..2) |i| {
                out[at] = row.words[0][i].sub(row.words[1][i]);
                at += 1;
            }
        },
        .iv_first, .iv_third, .pad_second, .pad_third => {
            for (row.gate_limbs) |value| {
                out[at] = value;
                at += 1;
            }
            for (row.serialized_bits) |value| {
                out[at] = value;
                at += 1;
            }
            const expected = constantWord(index);
            out[at] = row.words[0][0].sub(fixed(F, expected & 0xffff));
            at += 1;
            out[at] = row.words[0][1].sub(fixed(F, expected >> 16));
            at += 1;
            out[at] = row.words[1][0];
            at += 1;
            out[at] = row.words[1][1];
            at += 1;
        },
    }
    std.debug.assert(at <= constraint_count);
    return out;
}

fn halves(comptime F: type, word: u32) [2]F {
    return .{ fixed(F, word & 0xffff), fixed(F, word >> 16) };
}
fn planWord(plan: plan_mod.Plan, call_index: usize, word_id: usize) u32 {
    const call = plan.calls[call_index];
    if (word_id < 8) return call.state[word_id];
    if (word_id < 24) return std.mem.readInt(u32, call.block[4 * (word_id - 8) ..][0..4], .big);
    return call.output[word_id - 24];
}

fn serializedWordBytes(header: [80]u8, digest: [32]u8, index: usize) [4]u8 {
    const source = if (index < 16) header[4 * index ..][0..4] else if (index < 20)
        header[64 + 4 * (index - 16) ..][0..4]
    else
        digest[4 * (index - 20) ..][0..4];
    return .{ source[0], source[1], source[2], source[3] };
}

pub fn witness(header: [80]u8) [row_count]Row(M31) {
    const plan = plan_mod.prepare(header);
    var rows: [row_count]Row(M31) = undefined;
    for (&rows, 0..) |*row, index| {
        row.* = .{
            .gate_limbs = @splat(M31.zero()),
            .words = @splat(@splat(M31.zero())),
            .serialized_bits = @splat(M31.zero()),
        };
        switch (kind(index)) {
            .header, .digest => {
                const bytes = serializedWordBytes(header, plan.digest, index);
                row.gate_limbs = .{
                    M31.fromCanonical(std.mem.readInt(u16, bytes[0..2], .little)),
                    M31.fromCanonical(std.mem.readInt(u16, bytes[2..4], .little)),
                };
                for (0..32) |i| row.serialized_bits[i] = M31.fromCanonical((bytes[i / 8] >> @intCast(i % 8)) & 1);
                row.words[0] = if (index < 16)
                    halves(M31, planWord(plan, 0, 8 + index))
                else if (index < 20)
                    halves(M31, planWord(plan, 1, 8 + index - 16))
                else
                    halves(M31, planWord(plan, 2, 24 + index - 20));
            },
            .chain_state => {
                row.words[0] = halves(M31, planWord(plan, 0, 24 + index - 28));
                row.words[1] = halves(M31, planWord(plan, 1, index - 28));
            },
            .chain_digest => {
                row.words[0] = halves(M31, planWord(plan, 1, 24 + index - 36));
                row.words[1] = halves(M31, planWord(plan, 2, 8 + index - 36));
            },
            .iv_first, .iv_third, .pad_second, .pad_third => row.words[0] = halves(M31, constantWord(index)),
        }
    }
    return rows;
}

pub fn lift(rows: [row_count]Row(M31)) [row_count]Row(QM31) {
    var secure: [row_count]Row(QM31) = undefined;
    for (rows, &secure) |row, *target| {
        for (row.gate_limbs, &target.gate_limbs) |value, *slot| slot.* = QM31.fromBase(value);
        for (row.words, &target.words) |word, *target_word| for (word, target_word) |value, *slot| {
            slot.* = QM31.fromBase(value);
        };
        for (row.serialized_bits, &target.serialized_bits) |value, *slot| slot.* = QM31.fromBase(value);
    }
    return secure;
}

pub fn gateEvents(comptime F: type, row: Row(F), index: usize, addresses: [gate_count]u32) [2]?GateEvent(F) {
    if (index >= 28) return .{ null, null };
    return .{
        .{ .address = addresses[2 * index], .value = row.gate_limbs[0] },
        .{ .address = addresses[2 * index + 1], .value = row.gate_limbs[1] },
    };
}

fn event(comptime F: type, row: Row(F), slot: usize, first_call_id: u32, call_index: u32, word_id: u32) WordEvent(F) {
    return .{
        .call_id = first_call_id + call_index,
        .word_id = word_id,
        .lo = row.words[slot][0],
        .hi = row.words[slot][1],
        .direction = if (word_id < 24) .emit_input else .consume_output,
    };
}

/// Fixed row metadata supplies the complete three-call boundary roster.
/// Direction is determined by word ID, never by witness data.
pub fn wordEvents(comptime F: type, row: Row(F), index: usize, first_call_id: u32) [2]?WordEvent(F) {
    return switch (kind(index)) {
        .header => if (index < 16)
            .{ event(F, row, 0, first_call_id, 0, @intCast(8 + index)), null }
        else
            .{ event(F, row, 0, first_call_id, 1, @intCast(8 + index - 16)), null },
        .digest => .{ event(F, row, 0, first_call_id, 2, @intCast(24 + index - 20)), null },
        .chain_state => .{
            event(F, row, 0, first_call_id, 0, @intCast(24 + index - 28)),
            event(F, row, 1, first_call_id, 1, @intCast(index - 28)),
        },
        .chain_digest => .{
            event(F, row, 0, first_call_id, 1, @intCast(24 + index - 36)),
            event(F, row, 1, first_call_id, 2, @intCast(8 + index - 36)),
        },
        .iv_first => .{ event(F, row, 0, first_call_id, 0, @intCast(index - 44)), null },
        .iv_third => .{ event(F, row, 0, first_call_id, 2, @intCast(index - 52)), null },
        .pad_second => .{ event(F, row, 0, first_call_id, 1, @intCast(8 + index - 60 + 4)), null },
        .pad_third => .{ event(F, row, 0, first_call_id, 2, @intCast(8 + index - 72 + 8)), null },
    };
}

fn valid(comptime F: type, rows: *const [row_count]Row(F)) bool {
    for (rows, 0..) |row, index| for (evaluate(F, row, index)) |constraint| {
        if (!constraint.isZero()) return false;
    };
    return true;
}

test "80-row caller binds endian conversion, chaining, padding, and every SHA boundary word" {
    var random = std.Random.DefaultPrng.init(0x4341_4c4c_4552_3830);
    for (0..4) |_| {
        var header: [80]u8 = undefined;
        random.random().bytes(&header);
        const plan = plan_mod.prepare(header);
        const graph_words = try plan_mod.boundaryWords(header, plan, 7);
        const rows = witness(header);
        try std.testing.expect(valid(M31, &rows));
        const secure = lift(rows);
        try std.testing.expect(valid(QM31, &secure));
        var addresses: [gate_count]u32 = undefined;
        for (&addresses, 0..) |*address, i| address.* = @intCast(i + 3);
        const config = Config{ .gate_addresses = addresses, .first_call_id = 7 };
        try config.validate();
        var seen: [3][32]bool = @splat(@splat(false));
        var n_words: usize = 0;
        var n_gates: usize = 0;
        for (rows, 0..) |row, index| {
            for (gateEvents(M31, row, index, addresses)) |maybe_gate| if (maybe_gate) |gate| {
                try std.testing.expectEqual(addresses[n_gates], gate.address);
                n_gates += 1;
            };
            for (wordEvents(M31, row, index, config.first_call_id)) |maybe_word| if (maybe_word) |word| {
                const call_index = word.call_id - config.first_call_id;
                const word_id = word.word_id;
                try std.testing.expect(!seen[call_index][word_id]);
                seen[call_index][word_id] = true;
                const expected = planWord(plan, call_index, word_id);
                try std.testing.expectEqual(expected & 0xffff, word.lo.toU32());
                try std.testing.expectEqual(expected >> 16, word.hi.toU32());
                try std.testing.expectEqual(word_id < 24, word.direction == .emit_input);
                const graph_word = graph_words[call_index * 32 + word_id];
                try std.testing.expectEqualDeep([4]u8{
                    @truncate(word.lo.toU32()),
                    @truncate(word.lo.toU32() >> 8),
                    @truncate(word.hi.toU32()),
                    @truncate(word.hi.toU32() >> 8),
                }, graph_word.bytes);
                n_words += 1;
            };
        }
        try std.testing.expectEqual(gate_count, n_gates);
        try std.testing.expectEqual(word_count, n_words);
        for (seen) |call| for (call) |present| try std.testing.expect(present);
    }
}

test "streamed caller rejects byte alias, chain, padding, and unused-column changes" {
    const header = [_]u8{0x39} ** 80;
    const honest = witness(header);
    try std.testing.expect(valid(M31, &honest));
    var changed = honest;
    // Keep the Gate limb and all four packing equations valid while changing
    // the SHA high half by one. The field-linear byte witnesses can solve
    // this alias unless their individual bits are Boolean constrained.
    const inverse = try M31.fromCanonical(65535).inv();
    changed[0].serialized_bits[0] = changed[0].serialized_bits[0].add(inverse.mul(M31.fromCanonical(256)));
    changed[0].serialized_bits[8] = changed[0].serialized_bits[8].sub(inverse);
    changed[0].words[0][1] = changed[0].words[0][1].add(M31.one());
    const aliased = evaluate(M31, changed[0], 0);
    for (aliased[32..]) |packing_constraint| try std.testing.expect(packing_constraint.isZero());
    try std.testing.expect(!aliased[0].isZero());
    try std.testing.expect(!valid(M31, &changed));
    changed = honest;
    changed[20].gate_limbs[0] = changed[20].gate_limbs[0].add(M31.one());
    try std.testing.expect(!valid(M31, &changed));
    changed = honest;
    changed[28].words[1][0] = changed[28].words[1][0].add(M31.one());
    try std.testing.expect(!valid(M31, &changed));
    changed = honest;
    changed[60].words[0][1] = changed[60].words[0][1].add(M31.one());
    try std.testing.expect(!valid(M31, &changed));
    changed = honest;
    changed[60].serialized_bits[0] = M31.one();
    try std.testing.expect(!valid(M31, &changed));
}
