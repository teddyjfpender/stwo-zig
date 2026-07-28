//! Independent scalar deductions used by the recorded-witness CUDA fixtures.

const std = @import("std");
const pedersen_rows = @import("pedersen_fixture_rows.zig");
const program = @import("stwo_cairo_frontend").witness.program;
const cuda_backend = @import("stwo_cuda_backend");

const key_source = cuda_backend.upstream_sources.poseidon_witness_round_keys;
const expected_key_source_sha256 =
    "a606868540f59a8e257f3d1b60220d12f0a878f54a2d324f56b9f12ef3b8d34b";
const pedersen_source = cuda_backend.upstream_sources.pedersen_table_init;

const key_rounds = 35;
const keys_per_round = 30;
const key_word_count = key_rounds * keys_per_round;

const Felt = struct {
    limbs: [16]u16 = @splat(0),

    const modulus = [16]u16{
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0, 0, 0x0800,
    };
    const r2 = [16]u16{
        0x0401, 0x7e00, 0xfd73, 0xffff,
        0xffff, 0x330f, 0x0001, 0x0000,
        0x8000, 0xff6f, 0xffff, 0xffff,
        0x8810, 0x5e00, 0xd4ab, 0x07ff,
    };

    fn fromM31Words(words: []const u32) Felt {
        var words32: [8]u32 = @splat(0);
        for (words[0..28], 0..) |word, index| {
            const bit: u32 = @intCast(index * 9);
            const limb = bit >> 5;
            const shift: u5 = @intCast(bit & 31);
            words32[limb] |= word << shift;
            if (shift > 23 and limb + 1 < words32.len) {
                words32[limb + 1] |= word >> @intCast(32 - @as(u6, shift));
            }
        }
        var result = Felt{};
        for (words32, 0..) |word, index| {
            result.limbs[index * 2] = @truncate(word);
            result.limbs[index * 2 + 1] = @truncate(word >> 16);
        }
        return result;
    }

    fn toM31Words(self: Felt, words: []u32) void {
        var words32: [8]u32 = undefined;
        for (&words32, 0..) |*word, index| {
            word.* = self.limbs[index * 2] |
                (@as(u32, self.limbs[index * 2 + 1]) << 16);
        }
        for (words[0..28], 0..) |*word, index| {
            const bit: u32 = @intCast(index * 9);
            const limb = bit >> 5;
            const shift: u5 = @intCast(bit & 31);
            var value = words32[limb] >> shift;
            if (shift > 23 and limb + 1 < words32.len) {
                value |= words32[limb + 1] <<
                    @intCast(32 - @as(u6, shift));
            }
            word.* = value & 0x1ff;
        }
    }

    fn fromW27(words: []const u32) Felt {
        var limbs: [28]u32 = undefined;
        for (0..9) |index| {
            limbs[index * 3] = words[index] & 0x1ff;
            limbs[index * 3 + 1] = (words[index] >> 9) & 0x1ff;
            limbs[index * 3 + 2] = (words[index] >> 18) & 0x1ff;
        }
        limbs[27] = words[9] & 0x1ff;
        return fromM31Words(&limbs);
    }

    fn toW27(self: Felt, words: []u32) void {
        var limbs: [28]u32 = undefined;
        self.toM31Words(&limbs);
        for (0..9) |index| {
            words[index] = limbs[index * 3] |
                (limbs[index * 3 + 1] << 9) |
                (limbs[index * 3 + 2] << 18);
        }
        words[9] = limbs[27];
    }

    fn add(left: Felt, right: Felt) Felt {
        var result = Felt{};
        var carry: u32 = 0;
        for (&result.limbs, left.limbs, right.limbs) |*out, lhs, rhs| {
            const sum = @as(u32, lhs) + rhs + carry;
            out.* = @truncate(sum);
            carry = sum >> 16;
        }
        if (carry != 0 or result.greaterOrEqualModulus()) {
            result.subtractModulus();
        }
        return result;
    }

    fn sub(left: Felt, right: Felt) Felt {
        var result = Felt{};
        var borrow: i32 = 0;
        for (&result.limbs, left.limbs, right.limbs) |*out, lhs, rhs| {
            const difference = @as(i32, lhs) - @as(i32, rhs) - borrow;
            out.* = @truncate(@as(u32, @bitCast(difference)));
            borrow = @intFromBool(difference < 0);
        }
        if (borrow != 0) {
            var carry: u32 = 0;
            for (&result.limbs, modulus) |*out, limb| {
                const sum = @as(u32, out.*) + limb + carry;
                out.* = @truncate(sum);
                carry = sum >> 16;
            }
        }
        return result;
    }

    fn mul(left: Felt, right: Felt) Felt {
        return fromMontgomery(montMul(
            toMontgomery(left),
            toMontgomery(right),
        ));
    }

    fn cube(self: Felt) Felt {
        return self.mul(self).mul(self);
    }

    fn inverse(self: Felt) Felt {
        const value = self.toMontgomery();
        var one = Felt{};
        one.limbs[0] = 1;
        var result = one.toMontgomery();
        var bit: i32 = 251;
        while (bit >= 0) : (bit -= 1) {
            result = montMul(result, result);
            if (bit < 192 or bit == 196 or bit == 251) {
                result = montMul(result, value);
            }
        }
        return result.fromMontgomery();
    }

    fn toMontgomery(self: Felt) Felt {
        return montMul(self, .{ .limbs = r2 });
    }

    fn fromMontgomery(self: Felt) Felt {
        var one = Felt{};
        one.limbs[0] = 1;
        return montMul(self, one);
    }

    fn montMul(left: Felt, right: Felt) Felt {
        var temporary: [33]u32 = @splat(0);
        for (0..16) |i| {
            var carry: u64 = 0;
            for (0..16) |j| {
                const product = @as(u64, temporary[i + j]) +
                    @as(u64, left.limbs[i]) * right.limbs[j] + carry;
                temporary[i + j] = @truncate(product & 0xffff);
                carry = product >> 16;
            }
            var cursor = i + 16;
            while (carry != 0) : (cursor += 1) {
                const sum = @as(u64, temporary[cursor]) + carry;
                temporary[cursor] = @truncate(sum & 0xffff);
                carry = sum >> 16;
            }
        }
        for (0..16) |i| {
            const multiplier = (temporary[i] *% 0xffff) & 0xffff;
            var carry: u64 = 0;
            for (0..16) |j| {
                const sum = @as(u64, temporary[i + j]) +
                    @as(u64, multiplier) * modulus[j] + carry;
                temporary[i + j] = @truncate(sum & 0xffff);
                carry = sum >> 16;
            }
            var cursor = i + 16;
            while (carry != 0) : (cursor += 1) {
                const sum = @as(u64, temporary[cursor]) + carry;
                temporary[cursor] = @truncate(sum & 0xffff);
                carry = sum >> 16;
            }
        }
        var result = Felt{};
        for (&result.limbs, temporary[16..32]) |*out, limb| {
            out.* = @truncate(limb);
        }
        if (temporary[32] != 0 or result.greaterOrEqualModulus()) {
            result.subtractModulus();
        }
        return result;
    }

    fn greaterOrEqualModulus(self: Felt) bool {
        var index: usize = 16;
        while (index != 0) {
            index -= 1;
            if (self.limbs[index] != modulus[index]) {
                return self.limbs[index] > modulus[index];
            }
        }
        return true;
    }

    fn subtractModulus(self: *Felt) void {
        var borrow: i32 = 0;
        for (&self.limbs, modulus) |*out, limb| {
            const difference = @as(i32, out.*) - @as(i32, limb) - borrow;
            out.* = @truncate(@as(u32, @bitCast(difference)));
            borrow = @intFromBool(difference < 0);
        }
    }
};

pub const Oracle = struct {
    keys: [key_word_count]u32,

    pub fn init() !Oracle {
        var source_digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(key_source, &source_digest, .{});
        var expected_digest: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(
            &expected_digest,
            expected_key_source_sha256,
        );
        if (!std.mem.eql(u8, &source_digest, &expected_digest)) {
            return error.PoseidonKeyAuthorityDrift;
        }
        std.crypto.hash.sha2.Sha256.hash(
            pedersen_source,
            &source_digest,
            .{},
        );
        _ = try std.fmt.hexToBytes(
            &expected_digest,
            pedersen_rows.source_sha256,
        );
        if (!std.mem.eql(u8, &source_digest, &expected_digest)) {
            return error.PedersenTableAuthorityDrift;
        }
        var result: Oracle = undefined;
        var count: usize = 0;
        var cursor: usize = 0;
        while (cursor < key_source.len) {
            if (!std.ascii.isDigit(key_source[cursor])) {
                cursor += 1;
                continue;
            }
            const start = cursor;
            while (cursor < key_source.len and
                std.ascii.isDigit(key_source[cursor])) : (cursor += 1)
            {}
            if (cursor >= key_source.len or key_source[cursor] != 'u') {
                continue;
            }
            if (count >= result.keys.len) return error.InvalidPoseidonKeys;
            result.keys[count] = try std.fmt.parseUnsigned(
                u32,
                key_source[start..cursor],
                10,
            );
            count += 1;
        }
        if (count != result.keys.len) return error.InvalidPoseidonKeys;
        return result;
    }

    pub fn context(self: *Oracle) program.DeduceContext {
        return .{ .context = self, .call_fn = callOpaque };
    }

    fn callOpaque(
        erased: *anyopaque,
        selector: u32,
        inputs: []const u32,
        outputs: []u32,
    ) !void {
        const self: *Oracle = @ptrCast(@alignCast(erased));
        return switch (selector) {
            0 => deduceBlakeG(inputs, outputs),
            1 => deduceBlakeSigma(inputs, outputs),
            2 => deducePedersenAdd(inputs, outputs),
            3 => deducePedersenRow(inputs, outputs),
            4 => deduceFeltBinary(inputs, outputs, .add),
            5 => deduceFeltBinary(inputs, outputs, .sub),
            6 => deduceFeltBinary(inputs, outputs, .mul),
            7 => deduceFeltBinary(inputs, outputs, .div),
            8 => self.deducePoseidonKeys(inputs, outputs),
            9 => deduceCube(inputs, outputs),
            10 => self.deducePoseidonFull(inputs, outputs),
            11 => self.deducePoseidonPartial(inputs, outputs),
            else => return error.UnsupportedFixtureDeduction,
        };
    }

    fn key(self: Oracle, round: u32, index: usize) Felt {
        const safe_round = if (round < key_rounds) round else 0;
        const base = @as(usize, safe_round) * keys_per_round + index * 10;
        return Felt.fromW27(self.keys[base .. base + 10]);
    }

    fn deducePoseidonKeys(
        self: Oracle,
        inputs: []const u32,
        outputs: []u32,
    ) !void {
        if (inputs.len < 1 or outputs.len != 30) return error.InvalidDeduction;
        const safe_round = if (inputs[0] < key_rounds) inputs[0] else 0;
        const base = @as(usize, safe_round) * keys_per_round;
        @memcpy(outputs, self.keys[base .. base + keys_per_round]);
    }

    fn deducePoseidonFull(
        self: Oracle,
        inputs: []const u32,
        outputs: []u32,
    ) !void {
        if (inputs.len < 32 or outputs.len != 32) return error.InvalidDeduction;
        const x = Felt.fromW27(inputs[2..12]).cube();
        const y = Felt.fromW27(inputs[12..22]).cube();
        const z = Felt.fromW27(inputs[22..32]).cube();
        const y_minus_z = y.sub(z);
        const x_minus_yz = x.sub(y_minus_z);
        const x_plus_yz = x.add(y_minus_z);
        const twice_xy = x.add(y).add(x.add(y));
        outputs[0] = inputs[0];
        outputs[1] = inputs[1] +% 1;
        twice_xy.add(x_minus_yz).add(self.key(inputs[1], 0))
            .toW27(outputs[2..12]);
        x_minus_yz.add(self.key(inputs[1], 1))
            .toW27(outputs[12..22]);
        x_plus_yz.sub(z).add(self.key(inputs[1], 2))
            .toW27(outputs[22..32]);
    }

    fn deducePoseidonPartial(
        self: Oracle,
        inputs: []const u32,
        outputs: []u32,
    ) !void {
        if (inputs.len < 42 or outputs.len != 42) return error.InvalidDeduction;
        var state = [4]Felt{
            Felt.fromW27(inputs[2..12]),
            Felt.fromW27(inputs[12..22]),
            Felt.fromW27(inputs[22..32]),
            Felt.fromW27(inputs[32..42]),
        };
        for (0..3) |key_index| {
            const z23 = state[3].cube();
            const z03z13 = state[0].add(state[2]);
            const z03z13z1 = z03z13.add(state[1]);
            const long_sum = z03z13z1.add(state[3]).sub(z23)
                .add(self.key(inputs[1], key_index));
            const half_z3 = long_sum.add(z03z13z1).add(z03z13)
                .add(state[0]);
            state = .{ state[2], state[3], z23, half_z3.add(half_z3) };
        }
        outputs[0] = inputs[0];
        outputs[1] = inputs[1] +% 1;
        for (state, 0..) |value, index| {
            value.toW27(outputs[2 + index * 10 ..][0..10]);
        }
    }
};

pub fn pedersenFixtureIdentity() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/cairo/pedersen-w18-matrix-table/v2\x00");
    hash.update(pedersen_rows.source_sha256);
    for (0..28) |round| {
        const row: u32 = @intCast(round * pedersen_rows.row_stride);
        const words = pedersen_rows.find(row).?;
        var encoded: [4]u8 = undefined;
        std.mem.writeInt(u32, &encoded, row, .little);
        hash.update(&encoded);
        for (words) |word| {
            std.mem.writeInt(u32, &encoded, word, .little);
            hash.update(&encoded);
        }
    }
    return hash.finalResult();
}

const FeltBinary = enum { add, sub, mul, div };

fn deduceFeltBinary(
    inputs: []const u32,
    outputs: []u32,
    operation: FeltBinary,
) !void {
    if (inputs.len < 56 or outputs.len != 28) return error.InvalidDeduction;
    const left = Felt.fromM31Words(inputs[0..28]);
    const right = Felt.fromM31Words(inputs[28..56]);
    const result = switch (operation) {
        .add => left.add(right),
        .sub => left.sub(right),
        .mul => left.mul(right),
        .div => left.mul(right.inverse()),
    };
    result.toM31Words(outputs);
}

fn deducePedersenRow(inputs: []const u32, outputs: []u32) !void {
    if (inputs.len < 1 or outputs.len != pedersen_rows.row_zero.len)
        return error.InvalidFixturePedersenRow;
    const words = pedersen_rows.find(inputs[0]) orelse
        return error.InvalidFixturePedersenRow;
    @memcpy(outputs, words);
}

fn deducePedersenAdd(inputs: []const u32, outputs: []u32) !void {
    if (inputs.len < 72 or outputs.len != 72)
        return error.InvalidFixturePedersenRow;
    const row = inputs[1] *% pedersen_rows.row_stride +% inputs[2];
    const point = pedersen_rows.find(row) orelse
        return error.InvalidFixturePedersenRow;
    const accumulator_x = Felt.fromM31Words(inputs[16..44]);
    const accumulator_y = Felt.fromM31Words(inputs[44..72]);
    const point_x = Felt.fromM31Words(point[0..28]);
    const point_y = Felt.fromM31Words(point[28..56]);
    const slope = point_y.sub(accumulator_y)
        .mul(point_x.sub(accumulator_x).inverse());
    const result_x = slope.mul(slope).sub(accumulator_x).sub(point_x);
    const result_y = slope.mul(accumulator_x.sub(result_x))
        .sub(accumulator_y);
    outputs[0] = inputs[0];
    outputs[1] = inputs[1] +% 1;
    @memcpy(outputs[2..15], inputs[3..16]);
    outputs[15] = 0;
    result_x.toM31Words(outputs[16..44]);
    result_y.toM31Words(outputs[44..72]);
}

fn deduceCube(inputs: []const u32, outputs: []u32) !void {
    if (inputs.len < 10 or outputs.len != 10) return error.InvalidDeduction;
    Felt.fromW27(inputs[0..10]).cube().toW27(outputs);
}

fn rotateRight(value: u32, shift: u5) u32 {
    return (value >> shift) | (value << @intCast(32 - @as(u6, shift)));
}

fn deduceBlakeG(inputs: []const u32, outputs: []u32) !void {
    if (inputs.len < 6 or outputs.len != 4) return error.InvalidDeduction;
    var a = inputs[0];
    var b = inputs[1];
    var c = inputs[2];
    var d = inputs[3];
    a +%= b +% inputs[4];
    d = rotateRight(d ^ a, 16);
    c +%= d;
    b = rotateRight(b ^ c, 12);
    a +%= b +% inputs[5];
    d = rotateRight(d ^ a, 8);
    c +%= d;
    b = rotateRight(b ^ c, 7);
    outputs[0..4].* = .{ a, b, c, d };
}

const blake_sigma = [160]u32{
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
    14, 10, 4,  8,  9,  15, 13, 6,  1,  12, 0,  2,  11, 7,  5,  3,
    11, 8,  12, 0,  5,  2,  15, 13, 10, 14, 3,  6,  7,  1,  9,  4,
    7,  9,  3,  1,  13, 12, 11, 14, 2,  6,  5,  10, 4,  0,  15, 8,
    9,  0,  5,  7,  2,  4,  10, 15, 14, 1,  11, 12, 6,  8,  3,  13,
    2,  12, 6,  10, 0,  11, 8,  3,  4,  13, 7,  5,  15, 14, 1,  9,
    12, 5,  1,  15, 14, 13, 4,  10, 0,  7,  6,  3,  9,  2,  8,  11,
    13, 11, 7,  14, 12, 1,  3,  9,  5,  0,  15, 4,  8,  6,  2,  10,
    6,  15, 14, 9,  11, 3,  0,  8,  12, 2,  13, 7,  1,  4,  10, 5,
    10, 2,  8,  4,  7,  6,  1,  5,  15, 11, 9,  14, 3,  12, 13, 0,
};

fn deduceBlakeSigma(inputs: []const u32, outputs: []u32) !void {
    if (inputs.len < 1 or outputs.len != 16) return error.InvalidDeduction;
    const round = if (inputs[0] < 10) inputs[0] else 0;
    const base = @as(usize, round) * 16;
    @memcpy(outputs, blake_sigma[base .. base + 16]);
}

test "recorded CUDA oracle pins key authority and basic deductions" {
    var oracle = try Oracle.init();
    var sigma: [16]u32 = undefined;
    try oracle.context().call(1, &.{1}, &sigma);
    try std.testing.expectEqualSlices(
        u32,
        blake_sigma[16..32],
        &sigma,
    );
    var cube: [10]u32 = undefined;
    try oracle.context().call(9, &([_]u32{0} ** 10), &cube);
    try std.testing.expect(std.mem.allEqual(u32, &cube, 0));
}
