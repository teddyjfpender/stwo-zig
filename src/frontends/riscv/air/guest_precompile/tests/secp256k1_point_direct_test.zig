const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const affine = @import("../secp256k1_affine.zig");
const direct = @import("../secp256k1_point_direct.zig");
const field = @import("../secp256k1_field.zig");
const relations_mod = @import("../secp256k1_relations.zig");

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
    const equal_sum = try affine.addPoints(&tape, generator, generator);
    try std.testing.expect(affine.Point.eql(equal_sum, doubled));

    var seen: [direct.kind_count]bool = @splat(false);
    for (tape.points.items) |*record| {
        seen[@intFromEnum(record.kind)] = true;
        const row = try direct.rowFromRecord(&tape, record);
        var sink = Sink{};
        direct.evaluateDirect(M31, &row, &sink);
        try std.testing.expectEqual(@as(usize, 0), sink.failures);
        try std.testing.expectEqual(direct.constraint_count, sink.count);
        try std.testing.expect(sink.maximum_degree <= direct.maximum_constraint_degree);
    }
    try std.testing.expectEqual(@as(usize, 8), tape.points.items.len);
    for (seen) |kind_seen| try std.testing.expect(kind_seen);

    const equal = &tape.points.items[7];
    try std.testing.expectEqual(affine.PointKind.add_equal, equal.kind);
    try std.testing.expect(affine.Point.eql(equal.lhs, generator));
    try std.testing.expect(affine.Point.eql(equal.rhs, generator));
    try std.testing.expect(affine.Point.eql(equal.result, doubled));
}

test "secp256k1 point AIR: add_equal shares the doubling authority with rhs = lhs" {
    var tape = affine.Tape.init(std.testing.allocator);
    defer tape.deinit();
    const generator = affine.basePoint();
    const doubled = try affine.double(&tape, generator);
    _ = try affine.addPoints(&tape, generator, generator);
    const double_record = &tape.points.items[0];
    const equal_record = &tape.points.items[1];
    try std.testing.expectEqual(affine.PointKind.double, double_record.kind);
    try std.testing.expectEqual(affine.PointKind.add_equal, equal_record.kind);
    try std.testing.expectEqual(double_record.product_count, equal_record.product_count);
    try std.testing.expectEqual(double_record.linear_count, equal_record.linear_count);
    try std.testing.expect(affine.Point.eql(equal_record.result, doubled));

    const relations = relations_mod.Relations.dummy();
    const row = try direct.rowFromRecord(&tape, equal_record);
    try std.testing.expect(row[direct.Layout.selector(.add_equal)].isOne());
    try std.testing.expect(row[direct.Layout.selector(.double)].isZero());
    try std.testing.expect((try authoritySum(&tape, equal_record, &row, &relations)).isZero());

    // The emitted tuple is the add-slot request shape: rhs is the finite
    // operand, not infinity.
    const tuple = relations_mod.pointTupleForRecord(equal_record);
    try std.testing.expectEqual(
        M31.fromU64(@intFromEnum(affine.PointKind.add_equal)),
        tuple[0],
    );
    try std.testing.expect(tuple[1 + relations_mod.encoded_point_size].isZero());
}

test "secp256k1 point AIR: add_equal rejects unequal, infinite, and wrong-result operands" {
    var tape = affine.Tape.init(std.testing.allocator);
    defer tape.deinit();
    const generator = affine.basePoint();
    _ = try affine.addPoints(&tape, generator, generator);
    const record = &tape.points.items[0];
    try std.testing.expectEqual(affine.PointKind.add_equal, record.kind);
    const honest = try direct.rowFromRecord(&tape, record);
    const relations = relations_mod.Relations.dummy();

    // lhs != rhs: the coordinate pin fails directly.
    var unequal = honest;
    unequal[direct.Layout.rhs + 1] = unequal[direct.Layout.rhs + 1].add(M31.one());
    var sink = Sink{};
    direct.evaluateDirect(M31, &unequal, &sink);
    try std.testing.expect(sink.failures != 0);

    // rhs = infinity: a doubling disguised as an add-slot transition.
    var infinite_rhs = honest;
    @memset(
        infinite_rhs[direct.Layout.rhs..][0..relations_mod.encoded_point_size],
        M31.zero(),
    );
    infinite_rhs[direct.Layout.rhs] = M31.one();
    sink = .{};
    direct.evaluateDirect(M31, &infinite_rhs, &sink);
    try std.testing.expect(sink.failures != 0);

    // lhs = rhs = infinity with a finite result.
    var infinite_both = infinite_rhs;
    @memset(
        infinite_both[direct.Layout.lhs..][0..relations_mod.encoded_point_size],
        M31.zero(),
    );
    infinite_both[direct.Layout.lhs] = M31.one();
    sink = .{};
    direct.evaluateDirect(M31, &infinite_both, &sink);
    try std.testing.expect(sink.failures != 0);

    // result != 2 * lhs: the direct constraints pass (the formula lives in the
    // primitive requests) but the doubling authority no longer cancels.
    var wrong_result = honest;
    wrong_result[direct.Layout.result + 1] =
        wrong_result[direct.Layout.result + 1].add(M31.one());
    sink = .{};
    direct.evaluateDirect(M31, &wrong_result, &sink);
    try std.testing.expectEqual(@as(usize, 0), sink.failures);
    try std.testing.expect(!(try authoritySum(&tape, record, &wrong_result, &relations)).isZero());

    // The witness recorder refuses an add_equal record whose operands differ
    // or are infinite.
    var forged_record = record.*;
    forged_record.rhs.x[0] +%= 1;
    try std.testing.expectError(error.InvalidPointRecord, direct.rowFromRecord(&tape, &forged_record));
    forged_record = record.*;
    forged_record.rhs = .{};
    try std.testing.expectError(error.InvalidPointRecord, direct.rowFromRecord(&tape, &forged_record));
    forged_record = record.*;
    forged_record.lhs = .{};
    forged_record.rhs = .{};
    try std.testing.expectError(error.InvalidPointRecord, direct.rowFromRecord(&tape, &forged_record));
}

/// Row requests plus the record's primitive authorities, minus the row's own
/// point emission read back from the row: zero exactly when the row's
/// requests are the record's product/linear rows.
fn authoritySum(
    tape: *const affine.Tape,
    record: *const affine.PointRecord,
    row: *const [direct.Layout.main_columns]M31,
    relations: *const relations_mod.Relations,
) !QM31 {
    var sum = try pairSum(&direct.rowPairs(M31, row, relations));
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
    var kind = M31.zero();
    inline for (@typeInfo(affine.PointKind).@"enum".fields) |field_info| {
        const point_kind: affine.PointKind = @enumFromInt(field_info.value);
        kind = kind.add(row[direct.Layout.selector(point_kind)].mul(M31.fromU64(field_info.value)));
    }
    const lhs = row[direct.Layout.lhs..][0..relations_mod.encoded_point_size];
    const rhs = row[direct.Layout.rhs..][0..relations_mod.encoded_point_size];
    const result = row[direct.Layout.result..][0..relations_mod.encoded_point_size];
    sum = sum.sub(relations_mod.combinePoint(
        M31,
        relations.point,
        relations_mod.pointTuple(M31, kind, lhs, rhs, result),
    ).inv() catch unreachable);
    return sum;
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

fn pairSum(pairs: *const [direct.batch_count]@import("../../logup.zig").RowPair) !QM31 {
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
