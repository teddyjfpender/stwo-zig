const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const affine = @import("secp256k1_affine.zig");
const direct = @import("secp256k1_point_direct.zig");
const field = @import("secp256k1_field.zig");
const relations_mod = @import("secp256k1_relations.zig");

const Sink = struct {
    count: usize = 0,
    failures: usize = 0,
    maximum_degree: u8 = 0,

    pub fn add(self: *Sink, value: anytype, degree: u8) void {
        const lifted = if (@TypeOf(value) == M31) QM31.fromBase(value) else value;
        self.count += 1;
        self.failures += @intFromBool(!lifted.isZero());
        self.maximum_degree = @max(self.maximum_degree, degree);
    }
};

test "secp256k1 point AIR: every complete affine branch vanishes" {
    var tape = affine.Tape.init(std.testing.allocator);
    defer tape.deinit();
    const generator = affine.basePoint();
    const doubled = try affine.double(&tape, generator);
    _ = try affine.addPoints(&tape, generator, doubled);
    _ = try affine.addPoints(&tape, .{}, generator);
    _ = try affine.addPoints(&tape, generator, .{});
    const inverse = affine.Point{
        .x = generator.x,
        .y = field.bytesFromInteger(
            field.base_modulus.integer() - integer(generator.y),
        ),
        .infinity = false,
    };
    _ = try affine.addPoints(&tape, generator, inverse);
    _ = try affine.double(&tape, .{});
    _ = try affine.double(&tape, .{
        .x = field.bytesFromInteger(7),
        .y = @splat(0),
        .infinity = false,
    });

    for (tape.points.items) |*record| {
        const row = try direct.rowFromRecord(&tape, record);
        var sink = Sink{};
        direct.evaluateDirect(M31, &row, &sink);
        try std.testing.expectEqual(@as(usize, 0), sink.failures);
        try std.testing.expect(sink.maximum_degree <= direct.maximum_constraint_degree);
    }
    try std.testing.expectEqual(@as(usize, 7), tape.points.items.len);
}

test "secp256k1 point AIR: primitive requests and point emission cancel exactly" {
    var tape = affine.Tape.init(std.testing.allocator);
    defer tape.deinit();
    const generator = affine.basePoint();
    const doubled = try affine.double(&tape, generator);
    _ = try affine.addPoints(&tape, generator, doubled);
    const relations = relations_mod.Relations.dummy();

    for (tape.points.items) |*record| {
        const row = try direct.rowFromRecord(&tape, record);
        const pairs = direct.rowPairs(M31, &row, &relations);
        var sum = try pairSum(&pairs);
        const product_end = record.product_start + record.product_count;
        for (tape.products.items[record.product_start..product_end]) |*product| {
            const tuple = relations_mod.productTupleForRecord(product);
            sum = sum.add(relations_mod.combineProduct(
                M31,
                relations.product,
                tuple,
            ).inv() catch unreachable);
        }
        const linear_end = record.linear_start + record.linear_count;
        for (tape.linears.items[record.linear_start..linear_end]) |*linear| {
            const tuple = relations_mod.linearTupleForRecord(linear);
            sum = sum.add(relations_mod.combineLinear(
                M31,
                relations.linear,
                tuple,
            ).inv() catch unreachable);
        }
        const point_tuple = relations_mod.pointTupleForRecord(record);
        sum = sum.sub(relations_mod.combinePoint(
            M31,
            relations.point,
            point_tuple,
        ).inv() catch unreachable);
        try std.testing.expect(sum.isZero());
    }
}

test "secp256k1 point AIR: direct and linked mutations reject" {
    var tape = affine.Tape.init(std.testing.allocator);
    defer tape.deinit();
    _ = try affine.double(&tape, affine.basePoint());
    const record = &tape.points.items[0];
    const honest = try direct.rowFromRecord(&tape, record);

    var direct_mutation = honest;
    direct_mutation[direct.Layout.result] = M31.one();
    var sink = Sink{};
    direct.evaluateDirect(M31, &direct_mutation, &sink);
    try std.testing.expect(sink.failures != 0);

    const relations = relations_mod.Relations.dummy();
    const honest_sum = try pairSum(&direct.rowPairs(M31, &honest, &relations));
    var linked_mutation = honest;
    linked_mutation[direct.Layout.auxiliaryValue(4) + 7] =
        linked_mutation[direct.Layout.auxiliaryValue(4) + 7].add(M31.one());
    const forged_sum = try pairSum(&direct.rowPairs(M31, &linked_mutation, &relations));
    try std.testing.expect(!honest_sum.eql(forged_sum));
}

test "secp256k1 point AIR: byte custody is delegated to primitive relations" {
    var tape = affine.Tape.init(std.testing.allocator);
    defer tape.deinit();
    _ = try affine.double(&tape, affine.basePoint());
    var row = try direct.rowFromRecord(&tape, &tape.points.items[0]);
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

fn integer(value: affine.Value) u256 {
    return std.mem.readInt(u256, &value, .little);
}
