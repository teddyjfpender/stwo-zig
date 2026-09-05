//! Degree-two GLV scalar-split AIR.
//!
//! The row proves a bounded signed decomposition
//! `k = sign(k1)·k1 + lambda·sign(k2)·k2 (mod n)` by consuming one scalar
//! multiplication and up to three scalar linear-operation tuples.  Both
//! magnitudes are restricted to 128 bits, which is the only property the wNAF
//! schedule needs; the host lattice algorithm itself is not trusted.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const affine = @import("secp256k1_affine.zig");
const field = @import("secp256k1_field.zig");
const logup = @import("../logup.zig");
const relations_mod = @import("secp256k1_relations.zig");

pub const Layout = struct {
    pub const is_active: usize = 0;
    pub const negative_1: usize = 1;
    pub const negative_2: usize = 2;
    pub const original: usize = 3;
    pub const magnitude_1: usize = original + field.limb_count;
    pub const magnitude_2: usize = magnitude_1 + field.limb_count;
    pub const lambda_product: usize = magnitude_2 + field.limb_count;
    pub const signed_1: usize = lambda_product + field.limb_count;
    pub const signed_2: usize = signed_1 + field.limb_count;
    pub const reconstructed: usize = signed_2 + field.limb_count;
    pub const main_columns: usize = reconstructed + field.limb_count;
};

pub const event_count: usize = 6;
pub const batch_count: usize = event_count / 2;
/// Split limbs are all re-used by the range-checked scalar product/linear
/// providers; the split bus transfers that custody into the scalar program.
pub const range_pair_count: usize = 0;
pub const maximum_constraint_degree: u8 = 2;
pub const constraint_count: usize = 131;

pub const Error = error{
    InvalidTapeRange,
    InvalidProductSequence,
    InvalidLinearSequence,
};

comptime {
    if (Layout.main_columns != 227 or range_pair_count != 0 or batch_count != 3)
        @compileError("secp256k1 scalar-split geometry drifted");
}

pub fn rowFromRecord(
    tape: *const affine.Tape,
    record: *const affine.ScalarSplitRecord,
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
    if (products.len != 1 or linears.len !=
        1 + @as(usize, @intFromBool(record.negative_1)) +
            @as(usize, @intFromBool(record.negative_2)))
    {
        return error.InvalidTapeRange;
    }

    const lambda = field.bytesFromInteger(affine.endomorphism_lambda);
    const lambda_product = products[0].witness.result;
    try expectProduct(&products[0], record.magnitude_2, lambda, lambda_product);
    var cursor: usize = 0;
    const zero: affine.Value = @splat(0);
    const signed_1 = if (record.negative_1) blk: {
        const result = linears[cursor].result;
        try expectLinear(&linears[cursor], .subtract, zero, record.magnitude_1, result);
        cursor += 1;
        break :blk result;
    } else record.magnitude_1;
    const signed_2 = if (record.negative_2) blk: {
        const result = linears[cursor].result;
        try expectLinear(&linears[cursor], .subtract, zero, lambda_product, result);
        cursor += 1;
        break :blk result;
    } else lambda_product;
    try expectLinear(
        &linears[cursor],
        .add,
        signed_1,
        signed_2,
        record.original,
    );

    var row: [Layout.main_columns]M31 = @splat(M31.zero());
    row[Layout.is_active] = M31.one();
    row[Layout.negative_1] = M31.fromU64(@intFromBool(record.negative_1));
    row[Layout.negative_2] = M31.fromU64(@intFromBool(record.negative_2));
    writeValue(&row, Layout.original, record.original);
    writeValue(&row, Layout.magnitude_1, record.magnitude_1);
    writeValue(&row, Layout.magnitude_2, record.magnitude_2);
    writeValue(&row, Layout.lambda_product, lambda_product);
    writeValue(&row, Layout.signed_1, signed_1);
    writeValue(&row, Layout.signed_2, signed_2);
    writeValue(&row, Layout.reconstructed, record.original);
    return row;
}

pub fn evaluateDirect(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    sink: anytype,
) void {
    comptime requireSupportedField(S);
    const active = main[Layout.is_active];
    const negative_1 = main[Layout.negative_1];
    const negative_2 = main[Layout.negative_2];
    sink.add(active.mul(active.sub(scalar(S, 1))), 2);
    sink.add(negative_1.mul(negative_1.sub(active)), 2);
    sink.add(negative_2.mul(negative_2.sub(active)), 2);
    for (0..field.limb_count) |index| {
        sink.add(active.mul(
            main[Layout.reconstructed + index].sub(main[Layout.original + index]),
        ), 2);
        sink.add(active.sub(negative_1).mul(
            main[Layout.signed_1 + index].sub(main[Layout.magnitude_1 + index]),
        ), 2);
        sink.add(active.sub(negative_2).mul(
            main[Layout.signed_2 + index].sub(main[Layout.lambda_product + index]),
        ), 2);
    }
    for (field.limb_count / 2..field.limb_count) |index| {
        sink.add(active.mul(main[Layout.magnitude_1 + index]), 2);
        sink.add(active.mul(main[Layout.magnitude_2 + index]), 2);
    }
}

pub fn rowPairs(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    relations: anytype,
) [batch_count]logup.RowPairFor(relations_mod.InteractionScalar(S)) {
    comptime requireSupportedField(S);
    const active = main[Layout.is_active];
    const negative_1 = main[Layout.negative_1];
    const negative_2 = main[Layout.negative_2];
    const original = valueView(S, main, Layout.original);
    const magnitude_1 = valueView(S, main, Layout.magnitude_1);
    const magnitude_2 = valueView(S, main, Layout.magnitude_2);
    const lambda_product = valueView(S, main, Layout.lambda_product);
    const signed_1 = valueView(S, main, Layout.signed_1);
    const signed_2 = valueView(S, main, Layout.signed_2);
    const reconstructed = valueView(S, main, Layout.reconstructed);
    const zero: [field.limb_count]S = @splat(S.zero());
    const lambda = constantValue(S, affine.endomorphism_lambda);

    var events: [event_count]logup.RowPairFor(relations_mod.InteractionScalar(S)) = undefined;
    events[0] = productRequest(S, active, &magnitude_2, &lambda, &lambda_product, relations);
    events[1] = linearRequest(S, negative_1, .subtract, &zero, &magnitude_1, &signed_1, relations);
    events[2] = linearRequest(S, negative_2, .subtract, &zero, &lambda_product, &signed_2, relations);
    events[3] = linearRequest(S, active, .add, &signed_1, &signed_2, &reconstructed, relations);
    const split_tuple = relations_mod.splitTuple(
        S,
        negative_1,
        negative_2,
        &original,
        &magnitude_1,
        &magnitude_2,
    );
    events[4] = emit(
        S,
        active,
        relations_mod.combineSplit(S, relations.split, split_tuple),
    );
    events[5] = logup.RowPairFor(relations_mod.InteractionScalar(S)).single(
        relations_mod.InteractionScalar(S).zero(),
        relations_mod.InteractionScalar(S).one(),
    );

    var pairs: [batch_count]logup.RowPairFor(relations_mod.InteractionScalar(S)) = undefined;
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

fn productRequest(
    comptime S: type,
    coefficient: S,
    lhs: *const [field.limb_count]S,
    rhs: *const [field.limb_count]S,
    result: *const [field.limb_count]S,
    relations: anytype,
) logup.RowPairFor(relations_mod.InteractionScalar(S)) {
    const tuple = relations_mod.productTuple(
        S,
        scalar(S, @intFromEnum(affine.ModulusKind.scalar)),
        lhs,
        rhs,
        result,
    );
    return request(S, coefficient, relations_mod.combineProduct(S, relations.product, tuple));
}

fn linearRequest(
    comptime S: type,
    coefficient: S,
    kind: affine.LinearKind,
    lhs: *const [field.limb_count]S,
    rhs: *const [field.limb_count]S,
    result: *const [field.limb_count]S,
    relations: anytype,
) logup.RowPairFor(relations_mod.InteractionScalar(S)) {
    const tuple = relations_mod.linearTuple(
        S,
        scalar(S, @intFromEnum(kind)),
        scalar(S, @intFromEnum(affine.ModulusKind.scalar)),
        lhs,
        rhs,
        result,
    );
    return request(S, coefficient, relations_mod.combineLinear(S, relations.linear, tuple));
}

fn expectProduct(
    record: *const affine.ProductRecord,
    lhs: affine.Value,
    rhs: affine.Value,
    result: affine.Value,
) Error!void {
    if (record.modulus != .scalar or
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
    if (record.kind != kind or record.modulus != .scalar or
        !std.mem.eql(u8, &record.lhs, &lhs) or
        !std.mem.eql(u8, &record.rhs, &rhs) or
        !std.mem.eql(u8, &record.result, &result))
    {
        return error.InvalidLinearSequence;
    }
}

fn valueView(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    offset: usize,
) [field.limb_count]S {
    return main[offset..][0..field.limb_count].*;
}

fn constantValue(comptime S: type, value: u256) [field.limb_count]S {
    const encoded = field.bytesFromInteger(value);
    var result: [field.limb_count]S = undefined;
    for (encoded, 0..) |byte, index| result[index] = scalar(S, byte);
    return result;
}

fn request(
    comptime S: type,
    coefficient: S,
    denominator: relations_mod.InteractionScalar(S),
) logup.RowPairFor(relations_mod.InteractionScalar(S)) {
    return logup.RowPairFor(relations_mod.InteractionScalar(S)).single(
        lift(S, coefficient).neg(),
        denominator,
    );
}

fn emit(
    comptime S: type,
    coefficient: S,
    denominator: relations_mod.InteractionScalar(S),
) logup.RowPairFor(relations_mod.InteractionScalar(S)) {
    return logup.RowPairFor(relations_mod.InteractionScalar(S)).single(
        lift(S, coefficient),
        denominator,
    );
}

fn lift(comptime S: type, value: S) relations_mod.InteractionScalar(S) {
    if (S == M31) return QM31.fromBase(value);
    if (S == QM31) return value;
    return value;
}

fn scalar(comptime S: type, value: anytype) S {
    const canonical: u64 = @intCast(value);
    if (S == M31) return M31.fromU64(canonical);
    if (S == QM31) return QM31.fromBase(M31.fromU64(canonical));
    if (@hasDecl(S, "fromBase")) return S.fromBase(M31.fromU64(canonical));
    @compileError("secp256k1 split AIR requires a base-field lift");
}

fn writeValue(row: *[Layout.main_columns]M31, offset: usize, value: affine.Value) void {
    for (value, 0..) |byte, index| row[offset + index] = M31.fromU64(byte);
}

fn requireSupportedField(comptime S: type) void {
    if (S != M31 and S != QM31 and !@hasDecl(S, "fromBase"))
        @compileError("secp256k1 split AIR requires a base-field lift");
}
