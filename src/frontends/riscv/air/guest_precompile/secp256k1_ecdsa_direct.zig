//! One-row typed AIR for a successful secp256k1 ECDSA transaction.
//!
//! The row links the public request to the curve-membership check, scalar
//! inverse/products, the complete GLV scalar program, and `result.x mod n = r`.
//! Expensive arithmetic stays in shared product/linear/point components.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const affine = @import("secp256k1_affine.zig");
const field = @import("secp256k1_field.zig");
const logup = @import("../logup.zig");
const relations_mod = @import("secp256k1_relations.zig");

pub const Layout = struct {
    pub const is_active: usize = 0;
    pub const digest_big_endian: usize = 1;
    pub const public_key: usize = digest_big_endian + field.limb_count;
    pub const r: usize = public_key + relations_mod.encoded_point_size;
    pub const s: usize = r + field.limb_count;
    pub const reduced_digest: usize = s + field.limb_count;
    pub const inverse_s: usize = reduced_digest + field.limb_count;
    pub const generator_scalar: usize = inverse_s + field.limb_count;
    pub const public_key_scalar: usize = generator_scalar + field.limb_count;
    pub const result: usize = public_key_scalar + field.limb_count;
    pub const y_squared: usize = result + relations_mod.encoded_point_size;
    pub const x_squared: usize = y_squared + field.limb_count;
    pub const x_cubed: usize = x_squared + field.limb_count;
    pub const main_columns: usize = x_cubed + field.limb_count;
};

pub const event_count: usize = 12;
pub const batch_count: usize = event_count / 2;
/// Only the public digest/key/signature bytes originate outside the typed
/// arithmetic graph. Derived scalars and points inherit byte custody through
/// the range-checked primitive and scalar-program relations.
pub const range_pair_count: usize = 80;
pub const maximum_constraint_degree: u8 = 2;
pub const constraint_count: usize = 3;

pub const Error = error{
    InvalidTapeRange,
    InvalidProductSequence,
    InvalidLinearSequence,
    InvalidProgramSequence,
};

comptime {
    if (Layout.main_columns != 451 or range_pair_count != 80 or batch_count != 6)
        @compileError("secp256k1 ECDSA row geometry drifted");
}

pub fn rowFromRecord(
    tape: *const affine.Tape,
    record: *const affine.EcdsaRecord,
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
    if (product_end > tape.products.items.len or
        linear_end > tape.linears.items.len or
        record.program_index >= tape.scalar_programs.items.len or
        record.product_count < 6 or record.linear_count < 3)
    {
        return error.InvalidTapeRange;
    }
    const products = tape.products.items[record.product_start..product_end];
    const linears = tape.linears.items[record.linear_start..linear_end];
    const y_squared = products[0].witness.result;
    const x_squared = products[1].witness.result;
    const x_cubed = products[2].witness.result;
    try expectProduct(&products[0], .base, record.public_key.y, record.public_key.y, y_squared);
    try expectProduct(&products[1], .base, record.public_key.x, record.public_key.x, x_squared);
    try expectProduct(&products[2], .base, x_squared, record.public_key.x, x_cubed);
    try expectLinear(
        &linears[0],
        .add,
        .base,
        x_cubed,
        field.bytesFromInteger(7),
        y_squared,
    );
    try expectLinear(
        &linears[1],
        .reduce_once,
        .scalar,
        reverse(record.digest_big_endian),
        field.scalar_modulus.bytes,
        record.reduced_digest,
    );
    const one = field.bytesFromInteger(1);
    try expectProduct(&products[3], .scalar, record.s, record.inverse_s, one);
    try expectProduct(
        &products[4],
        .scalar,
        record.reduced_digest,
        record.inverse_s,
        record.generator_scalar,
    );
    try expectProduct(
        &products[5],
        .scalar,
        record.r,
        record.inverse_s,
        record.public_key_scalar,
    );
    try expectLinear(
        &linears[linears.len - 1],
        .reduce_once,
        .scalar,
        record.result.x,
        field.scalar_modulus.bytes,
        record.r,
    );
    const program = &tape.scalar_programs.items[record.program_index];
    if (!std.mem.eql(u8, &program.generator_scalar, &record.generator_scalar) or
        !affine.Point.eql(program.point, record.public_key) or
        !std.mem.eql(u8, &program.point_scalar, &record.public_key_scalar) or
        !affine.Point.eql(program.result, record.result) or
        program.split_start != record.split_start or record.split_count != 2)
    {
        return error.InvalidProgramSequence;
    }

    var row: [Layout.main_columns]M31 = @splat(M31.zero());
    row[Layout.is_active] = M31.one();
    writeBytes(&row, Layout.digest_big_endian, &record.digest_big_endian);
    writePoint(&row, Layout.public_key, record.public_key);
    writeValue(&row, Layout.r, record.r);
    writeValue(&row, Layout.s, record.s);
    writeValue(&row, Layout.reduced_digest, record.reduced_digest);
    writeValue(&row, Layout.inverse_s, record.inverse_s);
    writeValue(&row, Layout.generator_scalar, record.generator_scalar);
    writeValue(&row, Layout.public_key_scalar, record.public_key_scalar);
    writePoint(&row, Layout.result, record.result);
    writeValue(&row, Layout.y_squared, y_squared);
    writeValue(&row, Layout.x_squared, x_squared);
    writeValue(&row, Layout.x_cubed, x_cubed);
    return row;
}

pub fn evaluateDirect(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    sink: anytype,
) void {
    comptime requireSupportedField(S);
    const active = main[Layout.is_active];
    sink.add(active.mul(active.sub(scalar(S, 1))), 2);
    sink.add(active.mul(main[Layout.public_key]), 2);
    sink.add(active.mul(main[Layout.result]), 2);
}

pub fn rowPairs(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    relations: *const relations_mod.Relations,
) [batch_count]logup.RowPair {
    comptime requireSupportedField(S);
    const active = main[Layout.is_active];
    const digest_big_endian = valueView(S, main, Layout.digest_big_endian);
    const digest_little_endian = reverseField(S, digest_big_endian);
    const public_key = pointView(S, main, Layout.public_key);
    const r = valueView(S, main, Layout.r);
    const s = valueView(S, main, Layout.s);
    const reduced_digest = valueView(S, main, Layout.reduced_digest);
    const inverse_s = valueView(S, main, Layout.inverse_s);
    const generator_scalar = valueView(S, main, Layout.generator_scalar);
    const public_key_scalar = valueView(S, main, Layout.public_key_scalar);
    const result = pointView(S, main, Layout.result);
    const y_squared = valueView(S, main, Layout.y_squared);
    const x_squared = valueView(S, main, Layout.x_squared);
    const x_cubed = valueView(S, main, Layout.x_cubed);
    const seven = constantValue(S, 7);
    const one = constantValue(S, 1);
    const scalar_modulus = constantBytes(S, field.scalar_modulus.bytes);

    var events: [event_count]logup.RowPair = undefined;
    events[0] = productRequest(S, active, .base, pointY(S, &public_key), pointY(S, &public_key), &y_squared, relations);
    events[1] = productRequest(S, active, .base, pointX(S, &public_key), pointX(S, &public_key), &x_squared, relations);
    events[2] = productRequest(S, active, .base, &x_squared, pointX(S, &public_key), &x_cubed, relations);
    events[3] = linearRequest(S, active, .add, .base, &x_cubed, &seven, &y_squared, relations);
    events[4] = linearRequest(S, active, .reduce_once, .scalar, &digest_little_endian, &scalar_modulus, &reduced_digest, relations);
    events[5] = productRequest(S, active, .scalar, &s, &inverse_s, &one, relations);
    events[6] = productRequest(S, active, .scalar, &reduced_digest, &inverse_s, &generator_scalar, relations);
    events[7] = productRequest(S, active, .scalar, &r, &inverse_s, &public_key_scalar, relations);
    const program = relations_mod.programTuple(
        S,
        &generator_scalar,
        &public_key,
        &public_key_scalar,
        &result,
    );
    events[8] = request(S, active, relations_mod.combineProgram(S, relations.program, program));
    events[9] = linearRequest(
        S,
        active,
        .reduce_once,
        .scalar,
        pointX(S, &result),
        &scalar_modulus,
        &r,
        relations,
    );
    const call = relations_mod.ecdsaTuple(
        S,
        active,
        &digest_big_endian,
        &public_key,
        &r,
        &s,
    );
    events[10] = emit(S, active, relations_mod.combineEcdsa(S, relations.ecdsa, call));
    events[11] = logup.RowPair.single(QM31.zero(), QM31.one());

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
    var bytes: [2 * range_pair_count]S = undefined;
    var cursor: usize = 0;
    copyBytes(S, &bytes, &cursor, main[Layout.digest_big_endian..][0..field.limb_count]);
    copyBytes(S, &bytes, &cursor, main[Layout.public_key + 1 ..][0 .. 2 * field.limb_count]);
    inline for (.{ Layout.r, Layout.s }) |offset| {
        copyBytes(S, &bytes, &cursor, main[offset..][0..field.limb_count]);
    }
    std.debug.assert(cursor == bytes.len);
    var result_pairs: [range_pair_count][2]S = undefined;
    for (&result_pairs, 0..) |*pair, index| {
        pair.* = .{ bytes[2 * index], bytes[2 * index + 1] };
    }
    return result_pairs;
}

fn expectProduct(
    record: *const affine.ProductRecord,
    modulus: affine.ModulusKind,
    lhs: affine.Value,
    rhs: affine.Value,
    result: affine.Value,
) Error!void {
    if (record.modulus != modulus or
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
    modulus: affine.ModulusKind,
    lhs: affine.Value,
    rhs: affine.Value,
    result: affine.Value,
) Error!void {
    if (record.kind != kind or record.modulus != modulus or
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
    modulus: affine.ModulusKind,
    lhs: *const [field.limb_count]S,
    rhs: *const [field.limb_count]S,
    result: *const [field.limb_count]S,
    relations: *const relations_mod.Relations,
) logup.RowPair {
    const tuple = relations_mod.productTuple(
        S,
        scalar(S, @intFromEnum(modulus)),
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
    modulus: affine.ModulusKind,
    lhs: *const [field.limb_count]S,
    rhs: *const [field.limb_count]S,
    result: *const [field.limb_count]S,
    relations: *const relations_mod.Relations,
) logup.RowPair {
    const tuple = relations_mod.linearTuple(
        S,
        scalar(S, @intFromEnum(kind)),
        scalar(S, @intFromEnum(modulus)),
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

fn pointY(comptime S: type, point: *const [relations_mod.encoded_point_size]S) *const [field.limb_count]S {
    return point[1 + field.limb_count ..][0..field.limb_count];
}

fn constantValue(comptime S: type, value: u256) [field.limb_count]S {
    return constantBytes(S, field.bytesFromInteger(value));
}

fn constantBytes(comptime S: type, bytes: affine.Value) [field.limb_count]S {
    var result: [field.limb_count]S = undefined;
    for (bytes, 0..) |byte, index| result[index] = scalar(S, byte);
    return result;
}

fn reverseField(comptime S: type, value: [field.limb_count]S) [field.limb_count]S {
    var result: [field.limb_count]S = undefined;
    for (value, 0..) |item, index| result[value.len - 1 - index] = item;
    return result;
}

fn reverse(value: affine.Value) affine.Value {
    var result: affine.Value = undefined;
    for (value, 0..) |byte, index| result[value.len - 1 - index] = byte;
    return result;
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
    @compileError("secp256k1 ECDSA AIR supports only M31 and QM31");
}

fn scalar(comptime S: type, value: anytype) S {
    const canonical: u64 = @intCast(value);
    if (S == M31) return M31.fromU64(canonical);
    if (S == QM31) return QM31.fromBase(M31.fromU64(canonical));
    @compileError("secp256k1 ECDSA AIR supports only M31 and QM31");
}

fn writePoint(row: *[Layout.main_columns]M31, offset: usize, point: affine.Point) void {
    row[offset] = M31.fromU64(@intFromBool(point.infinity));
    writeValue(row, offset + 1, point.x);
    writeValue(row, offset + 1 + field.limb_count, point.y);
}

fn writeValue(row: *[Layout.main_columns]M31, offset: usize, value: affine.Value) void {
    writeBytes(row, offset, &value);
}

fn writeBytes(row: *[Layout.main_columns]M31, offset: usize, bytes: []const u8) void {
    for (bytes, 0..) |byte, index| row[offset + index] = M31.fromU64(byte);
}

fn copyBytes(
    comptime S: type,
    destination: []S,
    cursor: *usize,
    source: []const S,
) void {
    @memcpy(destination[cursor.*..][0..source.len], source);
    cursor.* += source.len;
}

fn requireSupportedField(comptime S: type) void {
    if (S != M31 and S != QM31)
        @compileError("secp256k1 ECDSA AIR supports only M31 and QM31");
}
