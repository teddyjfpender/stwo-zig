const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const affine = @import("../secp256k1_affine.zig");
const ecdsa = @import("../secp256k1_ecdsa.zig");
const fixture = @import("secp256k1_affine_test.zig").csp_input;
const direct = @import("../secp256k1_ecdsa_direct.zig");
const relations_mod = @import("../secp256k1_relations.zig");

const Sink = struct {
    failures: usize = 0,
    maximum_degree: u8 = 0,

    pub fn add(self: *Sink, value: anytype, degree: u8) void {
        const lifted = if (@TypeOf(value) == M31) QM31.fromBase(value) else value;
        self.failures += @intFromBool(!lifted.isZero());
        self.maximum_degree = @max(self.maximum_degree, degree);
    }
};

test "secp256k1 ECDSA AIR: CSP transaction vanishes and covers every byte" {
    var tape = try cspTape();
    defer tape.deinit();
    const row = try direct.rowFromRecord(&tape, &tape.ecdsa.items[0]);
    var sink = Sink{};
    direct.evaluateDirect(M31, &row, &sink);
    try std.testing.expectEqual(@as(usize, 0), sink.failures);
    try std.testing.expect(sink.maximum_degree <= direct.maximum_constraint_degree);
    try std.testing.expectEqual(@as(usize, 80), direct.rangePairs(M31, &row).len);
}

test "secp256k1 ECDSA AIR: high-level requests cancel exact tape authorities" {
    var tape = try cspTape();
    defer tape.deinit();
    const record = &tape.ecdsa.items[0];
    const row = try direct.rowFromRecord(&tape, record);
    const relations = relations_mod.Relations.dummy();
    var sum = try pairSum(&direct.rowPairs(M31, &row, &relations));
    for (tape.products.items[record.product_start..][0..6]) |*product| {
        sum = sum.add(relations_mod.combineProduct(
            M31,
            relations.product,
            relations_mod.productTupleForRecord(product),
        ).inv() catch unreachable);
    }
    const linears = tape.linears.items[record.linear_start..][0..record.linear_count];
    for ([_]usize{ 0, 1, 2, linears.len - 1 }) |index| {
        sum = sum.add(relations_mod.combineLinear(
            M31,
            relations.linear,
            relations_mod.linearTupleForRecord(&linears[index]),
        ).inv() catch unreachable);
    }
    const program = &tape.scalar_programs.items[record.program_index];
    sum = sum.add(relations_mod.combineProgram(
        M31,
        relations.program,
        relations_mod.programTupleForRecord(program),
    ).inv() catch unreachable);
    sum = sum.sub(relations_mod.combineEcdsa(
        M31,
        relations.ecdsa,
        relations_mod.ecdsaTupleForRecord(record),
    ).inv() catch unreachable);
    try std.testing.expect(sum.isZero());
}

test "secp256k1 ECDSA AIR: tape and public-input mutations fail closed" {
    var tape = try cspTape();
    defer tape.deinit();
    const record = &tape.ecdsa.items[0];
    const row = try direct.rowFromRecord(&tape, record);
    const relations = relations_mod.Relations.dummy();
    var forged = row;
    forged[direct.Layout.digest_big_endian + 3] =
        forged[direct.Layout.digest_big_endian + 3].add(M31.one());
    try std.testing.expect(!(try pairSum(&direct.rowPairs(
        M31,
        &row,
        &relations,
    ))).eql(try pairSum(&direct.rowPairs(M31, &forged, &relations))));

    tape.products.items[record.product_start].witness.result[0] ^= 1;
    try std.testing.expectError(
        error.InvalidLinearSequence,
        direct.rowFromRecord(&tape, record),
    );
}

test "secp256k1 ECDSA AIR: s is bound below the group order" {
    const field = @import("../secp256k1_field.zig");
    const linear_direct = @import("../secp256k1_linear_direct.zig");
    var tape = try cspTape();
    defer tape.deinit();
    const record = &tape.ecdsa.items[0];
    const row = try direct.rowFromRecord(&tape, record);
    const relations = relations_mod.Relations.dummy();
    const order = field.scalar_modulus.integer();

    // The honest row requests `reduce_once(s, n) == s` from the linear bus.
    const linears = tape.linears.items[record.linear_start..][0..record.linear_count];
    try std.testing.expectEqual(affine.LinearKind.reduce_once, linears[2].kind);
    try std.testing.expectEqualSlices(u8, &record.s, &linears[2].lhs);
    try std.testing.expectEqualSlices(u8, &record.s, &linears[2].result);
    const expected_request = relations_mod.combineLinear(
        M31,
        relations.linear,
        relations_mod.linearTupleForRecord(&linears[2]),
    );
    const pairs = direct.rowPairs(M31, &row, &relations);
    try std.testing.expect(pairs[direct.batch_count - 1].d2.eql(expected_request));
    try std.testing.expect(pairs[direct.batch_count - 1].n2.eql(QM31.one().neg()));

    // A non-canonical representative `v in [n, 2^256)` passes every direct
    // constraint and every modular product request; only the canonical
    // reduction request distinguishes it, and no linear row can serve it.
    const representative = field.bytesFromInteger(order + 7);
    var forged = row;
    for (representative, 0..) |byte, index| forged[direct.Layout.s + index] = M31.fromU64(byte);
    var sink = Sink{};
    direct.evaluateDirect(M31, &forged, &sink);
    try std.testing.expectEqual(@as(usize, 0), sink.failures);
    const honest = try pairSum(&pairs);
    try std.testing.expect(!honest.eql(try pairSum(&direct.rowPairs(M31, &forged, &relations))));
    const non_canonical = affine.LinearRecord{
        .kind = .reduce_once,
        .modulus = .scalar,
        .lhs = representative,
        .rhs = field.scalar_modulus.bytes,
        .result = representative,
    };
    try std.testing.expectError(
        error.NonCanonicalOperand,
        linear_direct.rowFromRecord(&non_canonical),
    );

    // The witness generator rejects `s = n` outright.
    var big_s: [32]u8 = undefined;
    std.mem.writeInt(u256, &big_s, order, .big);
    var scratch = affine.Tape.init(std.testing.allocator);
    defer scratch.deinit();
    try std.testing.expect(!try ecdsa.verify(
        &scratch,
        fixture[0..32].*,
        fixture[32..97].*,
        fixture[97..129].*,
        big_s,
    ));
}

test "secp256k1 ECDSA AIR: infinity flags and out-of-range bytes reject" {
    var tape = try cspTape();
    defer tape.deinit();
    var row = try direct.rowFromRecord(&tape, &tape.ecdsa.items[0]);
    row[direct.Layout.public_key] = M31.one();
    var sink = Sink{};
    direct.evaluateDirect(M31, &row, &sink);
    try std.testing.expect(sink.failures != 0);

    row = try direct.rowFromRecord(&tape, &tape.ecdsa.items[0]);
    row[direct.Layout.digest_big_endian + 17] = M31.fromU64(256);
    var rejected = false;
    for (direct.rangePairs(M31, &row)) |pair| rejected = rejected or
        pair[0].toU32() > 255 or pair[1].toU32() > 255;
    try std.testing.expect(rejected);
}

fn cspTape() !affine.Tape {
    var tape = affine.Tape.init(std.testing.allocator);
    errdefer tape.deinit();
    if (!try ecdsa.verify(
        &tape,
        fixture[0..32].*,
        fixture[32..97].*,
        fixture[97..129].*,
        fixture[129..161].*,
    )) return error.InvalidFixture;
    return tape;
}

fn pairSum(pairs: *const [direct.batch_count]@import("../../logup.zig").RowPair) !QM31 {
    var result = QM31.zero();
    for (pairs) |pair| {
        result = result.add(pair.n1.mul(try pair.d1.inv()));
        result = result.add(pair.n2.mul(try pair.d2.inv()));
    }
    return result;
}
