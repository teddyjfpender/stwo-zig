const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const affine = @import("secp256k1_affine.zig");
const direct = @import("secp256k1_split_direct.zig");
const field = @import("secp256k1_field.zig");
const relations_mod = @import("secp256k1_relations.zig");

const Sink = struct {
    failures: usize = 0,
    maximum_degree: u8 = 0,

    pub fn add(self: *Sink, value: anytype, degree: u8) void {
        const lifted = if (@TypeOf(value) == M31) QM31.fromBase(value) else value;
        self.failures += @intFromBool(!lifted.isZero());
        self.maximum_degree = @max(self.maximum_degree, degree);
    }
};

test "secp256k1 GLV split AIR: bounded decompositions vanish and link" {
    var tape = affine.Tape.init(std.testing.allocator);
    defer tape.deinit();
    const scalars = [_]u256{
        1,
        0x123456789abcdef,
        field.scalar_modulus.integer() - 1,
    };
    for (scalars) |value| _ = try tape.splitScalar(field.bytesFromInteger(value));
    const relations = relations_mod.Relations.dummy();

    for (tape.scalar_splits.items) |*record| {
        const row = try direct.rowFromRecord(&tape, record);
        var sink = Sink{};
        direct.evaluateDirect(M31, &row, &sink);
        try std.testing.expectEqual(@as(usize, 0), sink.failures);
        try std.testing.expect(sink.maximum_degree <= direct.maximum_constraint_degree);

        var sum = try pairSum(&direct.rowPairs(M31, &row, &relations));
        const product_end = record.product_start + record.product_count;
        for (tape.products.items[record.product_start..product_end]) |*product| {
            sum = sum.add(relations_mod.combineProduct(
                M31,
                relations.product,
                relations_mod.productTupleForRecord(product),
            ).inv() catch unreachable);
        }
        const linear_end = record.linear_start + record.linear_count;
        for (tape.linears.items[record.linear_start..linear_end]) |*linear| {
            sum = sum.add(relations_mod.combineLinear(
                M31,
                relations.linear,
                relations_mod.linearTupleForRecord(linear),
            ).inv() catch unreachable);
        }
        sum = sum.sub(relations_mod.combineSplit(
            M31,
            relations.split,
            relations_mod.splitTupleForRecord(record),
        ).inv() catch unreachable);
        try std.testing.expect(sum.isZero());
    }
}

test "secp256k1 GLV split AIR: magnitude and relation mutations reject" {
    var tape = affine.Tape.init(std.testing.allocator);
    defer tape.deinit();
    _ = try tape.splitScalar(field.bytesFromInteger(
        0x123456789abcdef0011223344556677,
    ));
    const record = &tape.scalar_splits.items[0];
    const honest = try direct.rowFromRecord(&tape, record);

    var forged = honest;
    forged[direct.Layout.magnitude_1 + 20] = M31.one();
    var sink = Sink{};
    direct.evaluateDirect(M31, &forged, &sink);
    try std.testing.expect(sink.failures != 0);

    const relations = relations_mod.Relations.dummy();
    const honest_sum = try pairSum(&direct.rowPairs(M31, &honest, &relations));
    forged = honest;
    forged[direct.Layout.lambda_product + 3] =
        forged[direct.Layout.lambda_product + 3].add(M31.one());
    const forged_sum = try pairSum(&direct.rowPairs(M31, &forged, &relations));
    try std.testing.expect(!honest_sum.eql(forged_sum));
}

test "secp256k1 GLV split AIR: byte custody is delegated to scalar primitives" {
    var tape = affine.Tape.init(std.testing.allocator);
    defer tape.deinit();
    _ = try tape.splitScalar(field.bytesFromInteger(42));
    var row = try direct.rowFromRecord(&tape, &tape.scalar_splits.items[0]);
    const pairs = direct.rangePairs(M31, &row);
    try std.testing.expectEqual(@as(usize, 0), pairs.len);
    _ = &row;
}

fn pairSum(pairs: *const [direct.batch_count]@import("../logup.zig").RowPair) !QM31 {
    var result = QM31.zero();
    for (pairs) |pair| {
        result = result.add(pair.n1.mul(try pair.d1.inv()));
        result = result.add(pair.n2.mul(try pair.d2.inv()));
    }
    return result;
}
