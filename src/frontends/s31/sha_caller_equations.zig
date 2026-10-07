//! Algebraic row contract for the S31 private Bitcoin-header SHA caller.
//!
//! Each row owns 56 circuit limbs and the 96 boundary words of three SHA
//! compressions. The linear equations below are intended to be evaluated over
//! both M31 prover rows and QM31 verifier openings by a future joined AIR
//! component. Lookup tuples alone are not an authenticated circuit boundary.
const std = @import("std");
const core = @import("stwo_core");
const provider = @import("s31_sha_provider");
const plan_mod = @import("sha_chip_plan.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
pub const header_limb_count: usize = 40;
pub const digest_limb_count: usize = 16;
pub const gate_limb_count: usize = header_limb_count + digest_limb_count;
pub const word_count_per_call: usize = 32;
pub const constraint_count: usize = 264;

pub fn Call(comptime F: type) type {
    return struct {
        state: [8][4]F,
        block: [16][4]F,
        output: [8][4]F,
    };
}

pub fn Row(comptime F: type) type {
    return struct {
        limbs: [gate_limb_count]F,
        calls: [3]Call(F),
    };
}

pub const Direction = enum { emit_input, consume_output };
pub fn ShaTuple(comptime F: type) type {
    return struct { call_id: u32, wire_id: u32, bytes: [4]F, direction: Direction };
}
pub fn GateTuple(comptime F: type) type {
    return struct { address: u32, value: F };
}

fn wordM31(value: u32) [4]M31 {
    return .{
        M31.fromCanonical(value & 0xff),
        M31.fromCanonical((value >> 8) & 0xff),
        M31.fromCanonical((value >> 16) & 0xff),
        M31.fromCanonical(value >> 24),
    };
}

/// Witness generation only. The verifier must enforce `evaluate` and the
/// joined Gate/SHA lookup closure; host SHA computation grants no authority.
pub fn witness(header: [80]u8, plan: plan_mod.Plan) !Row(M31) {
    _ = try plan_mod.providerCalls(header, plan, 1);
    var row: Row(M31) = undefined;
    for (0..header_limb_count) |i| row.limbs[i] = M31.fromCanonical(std.mem.readInt(u16, header[2 * i ..][0..2], .little));
    for (0..digest_limb_count) |i| row.limbs[header_limb_count + i] = M31.fromCanonical(std.mem.readInt(u16, plan.digest[2 * i ..][0..2], .little));
    for (plan.calls, &row.calls) |call, *target| {
        for (call.state, &target.state) |word, *bytes| bytes.* = wordM31(word);
        for (&target.block, 0..) |*bytes, i| bytes.* = wordM31(std.mem.readInt(u32, call.block[4 * i ..][0..4], .big));
        for (call.output, &target.output) |word, *bytes| bytes.* = wordM31(word);
    }
    return row;
}

/// The same degree-one equations are evaluated on opened QM31 coordinates
/// by the native verifier. This helper also makes field-parity tests explicit.
pub fn lift(row: Row(M31)) Row(QM31) {
    var secure: Row(QM31) = undefined;
    for (row.limbs, &secure.limbs) |value, *slot| slot.* = QM31.fromBase(value);
    for (row.calls, &secure.calls) |call, *target| {
        for (call.state, &target.state) |word, *bytes| for (word, bytes) |value, *slot| {
            slot.* = QM31.fromBase(value);
        };
        for (call.block, &target.block) |word, *bytes| for (word, bytes) |value, *slot| {
            slot.* = QM31.fromBase(value);
        };
        for (call.output, &target.output) |word, *bytes| for (word, bytes) |value, *slot| {
            slot.* = QM31.fromBase(value);
        };
    }
    return secure;
}

fn fixed(comptime F: type, value: u32) F {
    const base = M31.fromCanonical(value);
    return if (F == M31) base else if (F == QM31) QM31.fromBase(base) else @compileError("SHA caller equations require M31 or QM31");
}

fn push(comptime F: type, out: *[constraint_count]F, at: *usize, value: F) void {
    out[at.*] = value;
    at.* += 1;
}

/// All equations are degree one. Byte range is supplied by the SHA chip's
/// authenticated byte/bitwise lookups after these coordinates are joined to
/// its graph. `u16 = byte0 + 256*byte1` is integer-sound since the right side
/// is at most 65535 and the M31 modulus is much larger.
pub fn evaluate(comptime F: type, row: Row(F)) [constraint_count]F {
    var out: [constraint_count]F = undefined;
    var at: usize = 0;
    const k256 = fixed(F, 256);

    // SHA reads serialized header bytes in big-endian four-byte words. The
    // lookup tuple coordinates are low-to-high, hence the reversed indices.
    for (0..header_limb_count) |i| {
        const word = if (i < 32) row.calls[0].block[i / 2] else row.calls[1].block[(i - 32) / 2];
        const lo = if (i % 2 == 0) word[3] else word[1];
        const hi = if (i % 2 == 0) word[2] else word[0];
        push(F, &out, &at, row.limbs[i].sub(lo.add(hi.mul(k256))));
    }
    for (0..digest_limb_count) |i| {
        const word = row.calls[2].output[i / 2];
        const lo = if (i % 2 == 0) word[3] else word[1];
        const hi = if (i % 2 == 0) word[2] else word[0];
        push(F, &out, &at, row.limbs[header_limb_count + i].sub(lo.add(hi.mul(k256))));
    }

    for ([_]usize{ 0, 2 }) |call_index| for (provider.compression.initial_state, 0..) |value, word_index| {
        const expected = wordM31(value);
        for (expected, 0..) |byte, byte_index|
            push(F, &out, &at, row.calls[call_index].state[word_index][byte_index].sub(if (F == M31) byte else QM31.fromBase(byte)));
    };
    for (0..8) |word_index| for (0..4) |byte_index|
        push(F, &out, &at, row.calls[1].state[word_index][byte_index].sub(row.calls[0].output[word_index][byte_index]));

    // Block two has 16 header bytes, 0x80, 39 zero bytes and a big-endian
    // 64-bit bit length of 640. Its first four words are the remaining header.
    for (4..16) |word_index| for (0..4) |byte_index| {
        const expected: u32 = if (word_index == 4 and byte_index == 3) 0x80 else if (word_index == 15 and byte_index == 0) 0x80 else if (word_index == 15 and byte_index == 1) 0x02 else 0;
        push(F, &out, &at, row.calls[1].block[word_index][byte_index].sub(fixed(F, expected)));
    };

    // SHA's first-pass digest becomes the first eight words of block three.
    for (0..8) |word_index| for (0..4) |byte_index|
        push(F, &out, &at, row.calls[2].block[word_index][byte_index].sub(row.calls[1].output[word_index][byte_index]));
    // Block three ends with SHA-256 padding for a 32-byte (256-bit) digest.
    for (8..16) |word_index| for (0..4) |byte_index| {
        const expected: u32 = if (word_index == 8 and byte_index == 3) 0x80 else if (word_index == 15 and byte_index == 1) 0x01 else 0;
        push(F, &out, &at, row.calls[2].block[word_index][byte_index].sub(fixed(F, expected)));
    };
    std.debug.assert(at == constraint_count);
    return out;
}

pub fn gateTuples(comptime F: type, row: Row(F), addresses: [gate_limb_count]u32) ![gate_limb_count]GateTuple(F) {
    var tuples: [gate_limb_count]GateTuple(F) = undefined;
    for (addresses, row.limbs, &tuples) |address, value, *tuple| {
        if (address >= core.fields.m31.Modulus) return error.InvalidShaGateAddress;
        tuple.* = .{ .address = address, .value = value };
    }
    return tuples;
}

pub fn shaTuples(comptime F: type, row: Row(F), first_call_id: u32) ![3 * word_count_per_call]ShaTuple(F) {
    if (first_call_id == 0 or first_call_id > core.fields.m31.Modulus - 3) return error.InvalidShaCallId;
    var tuples: [3 * word_count_per_call]ShaTuple(F) = undefined;
    for (row.calls, 0..) |call, call_index| {
        const id = first_call_id + @as(u32, @intCast(call_index));
        for (0..24) |i| tuples[call_index * word_count_per_call + i] = .{
            .call_id = id,
            .wire_id = provider.graph.input_boundary_offset + @as(u32, @intCast(i)),
            .bytes = if (i < 8) call.state[i] else call.block[i - 8],
            .direction = .emit_input,
        };
        for (0..8) |i| tuples[call_index * word_count_per_call + 24 + i] = .{
            .call_id = id,
            .wire_id = provider.topology.output[i],
            .bytes = call.output[i],
            .direction = .consume_output,
        };
    }
    return tuples;
}

fn valid(comptime F: type, row: Row(F)) bool {
    for (evaluate(F, row)) |constraint| if (!constraint.isZero()) return false;
    return true;
}

test "SHA caller equations tie every header and digest limb to chip words" {
    var random = std.Random.DefaultPrng.init(0x5343_414c_4c45_52);
    for (0..8) |_| {
        var header: [80]u8 = undefined;
        random.random().bytes(&header);
        const plan = plan_mod.prepare(header);
        const row = try witness(header, plan);
        try std.testing.expect(valid(M31, row));
        try std.testing.expect(valid(QM31, lift(row)));
        const canonical = try plan_mod.boundaryWords(header, plan, 1);
        const tuples = try shaTuples(M31, row, 1);
        for (canonical, tuples) |expected, actual| {
            try std.testing.expectEqual(expected.call_id, actual.call_id);
            try std.testing.expectEqual(expected.wire_id, actual.wire_id);
            for (expected.bytes, actual.bytes) |a, b| try std.testing.expectEqual(@as(u32, a), b.toU32());
        }
        var changed = row;
        changed.limbs[0] = changed.limbs[0].add(M31.one());
        try std.testing.expect(!valid(M31, changed));
        changed = row;
        changed.limbs[55] = changed.limbs[55].add(M31.one());
        try std.testing.expect(!valid(M31, changed));
        changed = row;
        changed.calls[1].state[3][2] = changed.calls[1].state[3][2].add(M31.one());
        try std.testing.expect(!valid(M31, changed));
        changed = row;
        changed.calls[1].block[15][0] = changed.calls[1].block[15][0].add(M31.one());
        try std.testing.expect(!valid(M31, changed));
        changed = row;
        changed.calls[2].block[0][3] = changed.calls[2].block[0][3].add(M31.one());
        try std.testing.expect(!valid(M31, changed));
        changed = row;
        changed.calls[2].output[7][0] = changed.calls[2].output[7][0].add(M31.one());
        try std.testing.expect(!valid(M31, changed));
    }
    var addresses: [gate_limb_count]u32 = undefined;
    for (&addresses, 0..) |*address, i| address.* = @intCast(i + 1);
    const header: [80]u8 = @splat(0);
    const row = try witness(header, plan_mod.prepare(header));
    const gate = try gateTuples(M31, row, addresses);
    try std.testing.expectEqual(@as(u32, 1), gate[0].address);
    try std.testing.expectEqual(@as(u32, 56), gate[55].address);
    addresses[0] = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidShaGateAddress, gateTuples(M31, row, addresses));
}

test "nonbyte split satisfies local limb equation but fails SHA range lookup closure" {
    const allocator = std.testing.allocator;
    var header: [80]u8 = @splat(0);
    header[0] = 7;
    header[1] = 3;
    const plan = plan_mod.prepare(header);
    const row = try witness(header, plan);
    var changed = row;
    const shift = M31.fromCanonical(256);
    changed.calls[0].block[0][3] = changed.calls[0].block[0][3].add(shift);
    changed.calls[0].block[0][2] = changed.calls[0].block[0][2].sub(M31.one());
    // 7 + 256*3 = (7+256) + 256*(3-1) in M31. Local linear
    // equations alone cannot assert that both coordinates are bytes.
    try std.testing.expect(valid(M31, changed));
    try std.testing.expect(changed.calls[0].block[0][3].toU32() > 255);

    const records = try plan_mod.providerCalls(header, plan, 1);
    var prepared = try provider.prepare(allocator, &records);
    defer prepared.deinit();
    var boundary_rows = try plan_mod.privateBoundaryRows(header, plan, 1);
    try std.testing.expectEqual(@as(usize, 0), try plan_mod.wireImbalanceCount(allocator, &prepared, &boundary_rows));
    // The boundary row uses exactly the same first message-word coordinates.
    boundary_rows[8][3] = changed.calls[0].block[0][3];
    boundary_rows[8][2] = changed.calls[0].block[0][2];
    try std.testing.expect((try plan_mod.wireImbalanceCount(allocator, &prepared, &boundary_rows)) != 0);
}
