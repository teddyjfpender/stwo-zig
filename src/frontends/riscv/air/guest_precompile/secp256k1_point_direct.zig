//! Compact affine-transition AIR for secp256k1.
//!
//! A point row does not repeat non-native multiplication constraints. Instead
//! it requests the exact product and linear tuples emitted by the primitive
//! components, then emits one complete point-transition tuple for the scalar
//! program. This keeps point constraints degree two while preserving complete
//! exceptional-branch semantics.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const affine = @import("secp256k1_affine.zig");
const field = @import("secp256k1_field.zig");
const logup = @import("../logup.zig");
const relations_mod = @import("secp256k1_relations.zig");

pub const auxiliary_count: usize = 8;
pub const kind_count: usize = 7;
const point_kinds = [_]affine.PointKind{
    .double,
    .add,
    .left_identity,
    .right_identity,
    .inverse_pair,
    .double_identity,
    .double_to_infinity,
};

pub const Layout = struct {
    pub const is_active: usize = 0;
    pub const selectors: usize = 1;
    pub const lhs: usize = selectors + kind_count;
    pub const rhs: usize = lhs + relations_mod.encoded_point_size;
    pub const result: usize = rhs + relations_mod.encoded_point_size;
    pub const slope: usize = result + relations_mod.encoded_point_size;
    pub const denominator_inverse: usize = slope + field.limb_count;
    pub const auxiliary: usize = denominator_inverse + field.limb_count;
    pub const main_columns: usize = auxiliary + auxiliary_count * field.limb_count;

    pub fn selector(kind: affine.PointKind) usize {
        return selectors + @intFromEnum(kind);
    }

    pub fn auxiliaryValue(index: usize) usize {
        std.debug.assert(index < auxiliary_count);
        return auxiliary + index * field.limb_count;
    }
};

pub const product_event_count: usize = 9;
pub const linear_event_count: usize = 14;
pub const event_count: usize = product_event_count + linear_event_count + 1;
pub const batch_count: usize = event_count / 2;
pub const maximum_constraint_degree: u8 = 2;
pub const constraint_count: usize = 416;
/// Every point-row value is authenticated by a range-checked product/linear
/// row or by a caller/table root. Repeating those byte lookups here adds no
/// authority and would dominate the interaction commitment.
pub const range_pair_count: usize = 0;

pub const Error = error{
    InvalidPointRecord,
    InvalidTapeRange,
    InvalidProductSequence,
    InvalidLinearSequence,
};

comptime {
    if (Layout.main_columns != 523 or range_pair_count != 0 or
        event_count != 24 or batch_count != 12)
    {
        @compileError("secp256k1 point-row geometry drifted");
    }
}

pub fn rowFromRecord(
    tape: *const affine.Tape,
    record: *const affine.PointRecord,
) Error![Layout.main_columns]M31 {
    const product_end = std.math.add(
        usize,
        record.product_start,
        record.product_count,
    ) catch return error.InvalidTapeRange;
    const linear_end = std.math.add(
        usize,
        record.linear_start,
        record.linear_count,
    ) catch return error.InvalidTapeRange;
    if (product_end > tape.products.items.len or linear_end > tape.linears.items.len)
        return error.InvalidTapeRange;
    const products = tape.products.items[record.product_start..product_end];
    const linears = tape.linears.items[record.linear_start..linear_end];

    var row: [Layout.main_columns]M31 = @splat(M31.zero());
    row[Layout.is_active] = M31.one();
    row[Layout.selector(record.kind)] = M31.one();
    writePoint(&row, Layout.lhs, record.lhs);
    writePoint(&row, Layout.rhs, record.rhs);
    writePoint(&row, Layout.result, record.result);
    writeValue(&row, Layout.slope, record.slope);
    writeValue(&row, Layout.denominator_inverse, record.denominator_inverse);

    switch (record.kind) {
        .double => try materializeDouble(&row, record, products, linears),
        .add => try materializeAdd(&row, record, products, linears),
        .inverse_pair => try materializeInverse(&row, record, products, linears),
        .left_identity,
        .right_identity,
        .double_identity,
        .double_to_infinity,
        => if (products.len != 0 or linears.len != 0)
            return error.InvalidPointRecord,
    }
    return row;
}

pub fn evaluateDirect(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    sink: anytype,
) void {
    comptime requireSupportedField(S);
    const one = scalar(S, 1);
    const active = main[Layout.is_active];
    sink.add(active.mul(active.sub(one)), 2);

    var selector_sum = S.zero();
    inline for (point_kinds) |kind| {
        const selector = main[Layout.selector(kind)];
        sink.add(selector.mul(selector.sub(active)), 2);
        selector_sum = selector_sum.add(selector);
    }
    sink.add(selector_sum.sub(active), 1);

    const lhs = pointView(S, main, Layout.lhs);
    const rhs = pointView(S, main, Layout.rhs);
    const result = pointView(S, main, Layout.result);
    const points = [3][relations_mod.encoded_point_size]S{ lhs, rhs, result };
    for (points) |point| {
        const infinity = point[0];
        sink.add(infinity.mul(infinity.sub(active)), 2);
        for (point[1..]) |coordinate| sink.add(infinity.mul(coordinate), 2);
    }

    const left = main[Layout.selector(.left_identity)];
    sink.add(left.mul(lhs[0].sub(one)), 2);
    sink.add(left.mul(result[0].sub(rhs[0])), 2);
    constrainPointCoordinates(S, left, &result, &rhs, sink);

    const right = main[Layout.selector(.right_identity)];
    sink.add(right.mul(lhs[0]), 2);
    sink.add(right.mul(rhs[0].sub(one)), 2);
    sink.add(right.mul(result[0].sub(lhs[0])), 2);
    constrainPointCoordinates(S, right, &result, &lhs, sink);

    const inverse = main[Layout.selector(.inverse_pair)];
    sink.add(inverse.mul(lhs[0]), 2);
    sink.add(inverse.mul(rhs[0]), 2);
    sink.add(inverse.mul(result[0].sub(one)), 2);
    for (0..field.limb_count) |index| {
        sink.add(inverse.mul(lhs[1 + index].sub(rhs[1 + index])), 2);
    }

    const double_identity = main[Layout.selector(.double_identity)];
    sink.add(double_identity.mul(lhs[0].sub(one)), 2);
    sink.add(double_identity.mul(rhs[0].sub(one)), 2);
    sink.add(double_identity.mul(result[0].sub(one)), 2);

    const double_infinity = main[Layout.selector(.double_to_infinity)];
    sink.add(double_infinity.mul(lhs[0]), 2);
    sink.add(double_infinity.mul(rhs[0].sub(one)), 2);
    sink.add(double_infinity.mul(result[0].sub(one)), 2);
    for (0..field.limb_count) |index| {
        sink.add(double_infinity.mul(lhs[1 + field.limb_count + index]), 2);
    }

    const double = main[Layout.selector(.double)];
    sink.add(double.mul(lhs[0]), 2);
    sink.add(double.mul(rhs[0].sub(one)), 2);
    sink.add(double.mul(result[0]), 2);

    const add = main[Layout.selector(.add)];
    sink.add(add.mul(lhs[0]), 2);
    sink.add(add.mul(rhs[0]), 2);
    sink.add(add.mul(result[0]), 2);
}

pub fn rowPairs(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    relations: *const relations_mod.Relations,
) [batch_count]logup.RowPair {
    comptime requireSupportedField(S);
    const double = main[Layout.selector(.double)];
    const add = main[Layout.selector(.add)];
    const inverse = main[Layout.selector(.inverse_pair)];
    const lhs = pointView(S, main, Layout.lhs);
    const rhs = pointView(S, main, Layout.rhs);
    const result = pointView(S, main, Layout.result);
    const slope = valueView(S, main, Layout.slope);
    const denominator_inverse = valueView(S, main, Layout.denominator_inverse);
    var auxiliary: [auxiliary_count][field.limb_count]S = undefined;
    for (&auxiliary, 0..) |*value, index| value.* =
        valueView(S, main, Layout.auxiliaryValue(index));
    const zero: [field.limb_count]S = @splat(S.zero());
    var one: [field.limb_count]S = @splat(S.zero());
    one[0] = scalar(S, 1);

    var events: [event_count]logup.RowPair = undefined;
    var event: usize = 0;
    // Doubling: five products, seven linears.
    events[event] = productRequest(S, double, lhsX(S, &lhs), lhsX(S, &lhs), &auxiliary[0], relations);
    event += 1;
    events[event] = productRequest(S, double, &auxiliary[3], &denominator_inverse, &one, relations);
    event += 1;
    events[event] = productRequest(S, double, &auxiliary[2], &denominator_inverse, &slope, relations);
    event += 1;
    events[event] = productRequest(S, double, &slope, &slope, &auxiliary[4], relations);
    event += 1;
    events[event] = productRequest(S, double, &slope, &auxiliary[6], &auxiliary[7], relations);
    event += 1;
    events[event] = linearRequest(S, double, .add, &auxiliary[0], &auxiliary[0], &auxiliary[1], relations);
    event += 1;
    events[event] = linearRequest(S, double, .add, &auxiliary[1], &auxiliary[0], &auxiliary[2], relations);
    event += 1;
    events[event] = linearRequest(S, double, .add, lhsY(S, &lhs), lhsY(S, &lhs), &auxiliary[3], relations);
    event += 1;
    events[event] = linearRequest(S, double, .subtract, &auxiliary[4], lhsX(S, &lhs), &auxiliary[5], relations);
    event += 1;
    events[event] = linearRequest(S, double, .subtract, &auxiliary[5], lhsX(S, &lhs), pointX(S, &result), relations);
    event += 1;
    events[event] = linearRequest(S, double, .subtract, lhsX(S, &lhs), pointX(S, &result), &auxiliary[6], relations);
    event += 1;
    events[event] = linearRequest(S, double, .subtract, &auxiliary[7], lhsY(S, &lhs), pointY(S, &result), relations);
    event += 1;

    // General addition: four products, six linears.
    events[event] = productRequest(S, add, &auxiliary[0], &denominator_inverse, &one, relations);
    event += 1;
    events[event] = productRequest(S, add, &auxiliary[1], &denominator_inverse, &slope, relations);
    event += 1;
    events[event] = productRequest(S, add, &slope, &slope, &auxiliary[2], relations);
    event += 1;
    events[event] = productRequest(S, add, &slope, &auxiliary[4], &auxiliary[5], relations);
    event += 1;
    events[event] = linearRequest(S, add, .subtract, pointX(S, &rhs), pointX(S, &lhs), &auxiliary[0], relations);
    event += 1;
    events[event] = linearRequest(S, add, .subtract, pointY(S, &rhs), pointY(S, &lhs), &auxiliary[1], relations);
    event += 1;
    events[event] = linearRequest(S, add, .subtract, &auxiliary[2], pointX(S, &lhs), &auxiliary[3], relations);
    event += 1;
    events[event] = linearRequest(S, add, .subtract, &auxiliary[3], pointX(S, &rhs), pointX(S, &result), relations);
    event += 1;
    events[event] = linearRequest(S, add, .subtract, pointX(S, &lhs), pointX(S, &result), &auxiliary[4], relations);
    event += 1;
    events[event] = linearRequest(S, add, .subtract, &auxiliary[5], pointY(S, &lhs), pointY(S, &result), relations);
    event += 1;

    events[event] = linearRequest(S, inverse, .add, pointY(S, &lhs), pointY(S, &rhs), &zero, relations);
    event += 1;
    const kind = kindValue(S, main);
    const point_denominator = relations_mod.combinePoint(
        S,
        relations.point,
        relations_mod.pointTuple(S, kind, &lhs, &rhs, &result),
    );
    events[event] = emit(S, main[Layout.is_active], point_denominator);
    event += 1;
    std.debug.assert(event == events.len);

    var pairs: [batch_count]logup.RowPair = undefined;
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
) [range_pair_count][2]S {
    comptime requireSupportedField(S);
    _ = main;
    return .{};
}

fn materializeDouble(
    row: *[Layout.main_columns]M31,
    record: *const affine.PointRecord,
    products: []const affine.ProductRecord,
    linears: []const affine.LinearRecord,
) Error!void {
    if (products.len != 5 or linears.len != 7) return error.InvalidPointRecord;
    const one = field.bytesFromInteger(1);
    try expectProduct(&products[0], record.lhs.x, record.lhs.x, products[0].witness.result);
    const xx = products[0].witness.result;
    try expectLinear(&linears[0], .add, xx, xx, linears[0].result);
    const two_xx = linears[0].result;
    try expectLinear(&linears[1], .add, two_xx, xx, linears[1].result);
    const numerator = linears[1].result;
    try expectLinear(&linears[2], .add, record.lhs.y, record.lhs.y, linears[2].result);
    const denominator = linears[2].result;
    try expectProduct(&products[1], denominator, record.denominator_inverse, one);
    try expectProduct(&products[2], numerator, record.denominator_inverse, record.slope);
    try expectProduct(&products[3], record.slope, record.slope, products[3].witness.result);
    const slope_squared = products[3].witness.result;
    try expectLinear(&linears[3], .subtract, slope_squared, record.lhs.x, linears[3].result);
    const x_after = linears[3].result;
    try expectLinear(&linears[4], .subtract, x_after, record.lhs.x, record.result.x);
    try expectLinear(&linears[5], .subtract, record.lhs.x, record.result.x, linears[5].result);
    const x_delta = linears[5].result;
    try expectProduct(&products[4], record.slope, x_delta, products[4].witness.result);
    const y_product = products[4].witness.result;
    try expectLinear(&linears[6], .subtract, y_product, record.lhs.y, record.result.y);
    for ([_]affine.Value{ xx, two_xx, numerator, denominator, slope_squared, x_after, x_delta, y_product }, 0..) |value, index| {
        writeValue(row, Layout.auxiliaryValue(index), value);
    }
}

fn materializeAdd(
    row: *[Layout.main_columns]M31,
    record: *const affine.PointRecord,
    products: []const affine.ProductRecord,
    linears: []const affine.LinearRecord,
) Error!void {
    if (products.len != 4 or linears.len != 6) return error.InvalidPointRecord;
    const one = field.bytesFromInteger(1);
    try expectLinear(&linears[0], .subtract, record.rhs.x, record.lhs.x, linears[0].result);
    const denominator = linears[0].result;
    try expectLinear(&linears[1], .subtract, record.rhs.y, record.lhs.y, linears[1].result);
    const numerator = linears[1].result;
    try expectProduct(&products[0], denominator, record.denominator_inverse, one);
    try expectProduct(&products[1], numerator, record.denominator_inverse, record.slope);
    try expectProduct(&products[2], record.slope, record.slope, products[2].witness.result);
    const slope_squared = products[2].witness.result;
    try expectLinear(&linears[2], .subtract, slope_squared, record.lhs.x, linears[2].result);
    const x_after = linears[2].result;
    try expectLinear(&linears[3], .subtract, x_after, record.rhs.x, record.result.x);
    try expectLinear(&linears[4], .subtract, record.lhs.x, record.result.x, linears[4].result);
    const x_delta = linears[4].result;
    try expectProduct(&products[3], record.slope, x_delta, products[3].witness.result);
    const y_product = products[3].witness.result;
    try expectLinear(&linears[5], .subtract, y_product, record.lhs.y, record.result.y);
    for ([_]affine.Value{ denominator, numerator, slope_squared, x_after, x_delta, y_product }, 0..) |value, index| {
        writeValue(row, Layout.auxiliaryValue(index), value);
    }
}

fn materializeInverse(
    row: *[Layout.main_columns]M31,
    record: *const affine.PointRecord,
    products: []const affine.ProductRecord,
    linears: []const affine.LinearRecord,
) Error!void {
    if (products.len != 0 or linears.len != 1) return error.InvalidPointRecord;
    const zero: affine.Value = @splat(0);
    try expectLinear(&linears[0], .add, record.lhs.y, record.rhs.y, zero);
    writeValue(row, Layout.auxiliaryValue(0), linears[0].result);
}

fn expectProduct(
    record: *const affine.ProductRecord,
    lhs: affine.Value,
    rhs: affine.Value,
    result: affine.Value,
) Error!void {
    if (record.modulus != .base or
        !std.mem.eql(u8, &record.witness.lhs, &lhs) or
        !std.mem.eql(u8, &record.witness.rhs, &rhs) or
        !std.mem.eql(u8, &record.witness.result, &result))
    {
        return error.InvalidProductSequence;
    }
}

fn expectLinear(
    record: *const affine.LinearRecord,
    kind: affine.LinearKind,
    lhs: affine.Value,
    rhs: affine.Value,
    result: affine.Value,
) Error!void {
    if (record.kind != kind or record.modulus != .base or
        !std.mem.eql(u8, &record.lhs, &lhs) or
        !std.mem.eql(u8, &record.rhs, &rhs) or
        !std.mem.eql(u8, &record.result, &result))
    {
        return error.InvalidLinearSequence;
    }
}

fn productRequest(
    comptime S: type,
    coefficient: S,
    lhs: *const [field.limb_count]S,
    rhs: *const [field.limb_count]S,
    result: *const [field.limb_count]S,
    relations: *const relations_mod.Relations,
) logup.RowPair {
    const tuple = relations_mod.productTuple(S, scalar(S, @intFromEnum(affine.ModulusKind.base)), lhs, rhs, result);
    return request(S, coefficient, relations_mod.combineProduct(S, relations.product, tuple));
}

fn linearRequest(
    comptime S: type,
    coefficient: S,
    kind: affine.LinearKind,
    lhs: *const [field.limb_count]S,
    rhs: *const [field.limb_count]S,
    result: *const [field.limb_count]S,
    relations: *const relations_mod.Relations,
) logup.RowPair {
    const tuple = relations_mod.linearTuple(
        S,
        scalar(S, @intFromEnum(kind)),
        scalar(S, @intFromEnum(affine.ModulusKind.base)),
        lhs,
        rhs,
        result,
    );
    return request(S, coefficient, relations_mod.combineLinear(S, relations.linear, tuple));
}

fn pointView(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    offset: usize,
) [relations_mod.encoded_point_size]S {
    return main[offset..][0..relations_mod.encoded_point_size].*;
}

fn valueView(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    offset: usize,
) [field.limb_count]S {
    return main[offset..][0..field.limb_count].*;
}

fn pointX(comptime S: type, point: *const [relations_mod.encoded_point_size]S) *const [field.limb_count]S {
    return point[1..][0..field.limb_count];
}

fn lhsX(comptime S: type, point: *const [relations_mod.encoded_point_size]S) *const [field.limb_count]S {
    return pointX(S, point);
}

fn pointY(comptime S: type, point: *const [relations_mod.encoded_point_size]S) *const [field.limb_count]S {
    return point[1 + field.limb_count ..][0..field.limb_count];
}

fn lhsY(comptime S: type, point: *const [relations_mod.encoded_point_size]S) *const [field.limb_count]S {
    return pointY(S, point);
}

fn kindValue(comptime S: type, main: *const [Layout.main_columns]S) S {
    var result = S.zero();
    inline for (point_kinds) |kind| {
        result = result.add(main[Layout.selector(kind)].mul(
            scalar(S, @intFromEnum(kind)),
        ));
    }
    return result;
}

fn constrainPointCoordinates(
    comptime S: type,
    selector: S,
    lhs: *const [relations_mod.encoded_point_size]S,
    rhs: *const [relations_mod.encoded_point_size]S,
    sink: anytype,
) void {
    for (1..relations_mod.encoded_point_size) |index| {
        sink.add(selector.mul(lhs[index].sub(rhs[index])), 2);
    }
}

fn request(comptime S: type, coefficient: S, denominator: QM31) logup.RowPair {
    return logup.RowPair.single(lift(S, coefficient).neg(), denominator);
}

fn emit(comptime S: type, coefficient: S, denominator: QM31) logup.RowPair {
    return logup.RowPair.single(lift(S, coefficient), denominator);
}

fn lift(comptime S: type, value: S) QM31 {
    if (S == M31) return QM31.fromBase(value);
    if (S == QM31) return value;
    @compileError("secp256k1 point AIR supports only M31 and QM31");
}

fn scalar(comptime S: type, value: anytype) S {
    const canonical: u64 = @intCast(value);
    if (S == M31) return M31.fromU64(canonical);
    if (S == QM31) return QM31.fromBase(M31.fromU64(canonical));
    @compileError("secp256k1 point AIR supports only M31 and QM31");
}

fn writePoint(row: *[Layout.main_columns]M31, offset: usize, point: affine.Point) void {
    row[offset] = M31.fromU64(@intFromBool(point.infinity));
    writeValue(row, offset + 1, point.x);
    writeValue(row, offset + 1 + field.limb_count, point.y);
}

fn writeValue(row: *[Layout.main_columns]M31, offset: usize, value: affine.Value) void {
    for (value, 0..) |byte, index| row[offset + index] = M31.fromU64(byte);
}

fn requireSupportedField(comptime S: type) void {
    if (S != M31 and S != QM31)
        @compileError("secp256k1 point AIR supports only M31 and QM31");
}
