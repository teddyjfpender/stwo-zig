//! One-row typed AIR for parity-bound secp256k1 public-key recovery.
//!
//! The row links a versioned successful recovery call to `R.x = r`, the
//! selected parity of `R.y`, curve membership, scalar inversion, and the
//! complete GLV program proving `Q = r^-1(sR - zG)`.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const affine = @import("secp256k1_affine.zig");
const field = @import("secp256k1_field.zig");
const logup = @import("../logup.zig");
const relations_mod = @import("secp256k1_relations.zig");

pub const relation_version: u16 = 1;

pub const Layout = struct {
    pub const is_active: usize = 0;
    pub const digest_big_endian: usize = 1;
    pub const r: usize = digest_big_endian + field.limb_count;
    pub const s: usize = r + field.limb_count;
    pub const recovery_id: usize = s + field.limb_count;
    pub const recovery_point: usize = recovery_id + 1;
    pub const public_key: usize = recovery_point + relations_mod.encoded_point_size;
    pub const reduced_digest: usize = public_key + relations_mod.encoded_point_size;
    pub const inverse_r: usize = reduced_digest + field.limb_count;
    pub const inverse_s: usize = inverse_r + field.limb_count;
    pub const negative_digest: usize = inverse_s + field.limb_count;
    pub const generator_scalar: usize = negative_digest + field.limb_count;
    pub const recovery_point_scalar: usize = generator_scalar + field.limb_count;
    pub const y_squared: usize = recovery_point_scalar + field.limb_count;
    pub const x_squared: usize = y_squared + field.limb_count;
    pub const x_cubed: usize = x_squared + field.limb_count;
    pub const y_half: usize = x_cubed + field.limb_count;
    pub const main_columns: usize = y_half + 1;
};

pub const event_count: usize = 12;
pub const batch_count: usize = event_count / 2;
/// 32-byte digest/r/s, 64-byte output, plus recovery-id and parity half.
pub const range_pair_count: usize = 81;
pub const maximum_constraint_degree: u8 = 2;
pub const constraint_count: usize = 5 + field.limb_count;

pub const Error = error{
    InvalidLinearSequence,
    InvalidProductSequence,
    InvalidProgramSequence,
    InvalidTapeRange,
};

comptime {
    if (Layout.main_columns != 517 or batch_count != 6 or range_pair_count != 81)
        @compileError("secp256k1 recovery row geometry drifted");
}

pub fn rowFromRecord(
    tape: *const affine.Tape,
    record: *const affine.RecoveryRecord,
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
        record.product_count < 7 or record.linear_count < 3)
    {
        return error.InvalidTapeRange;
    }
    const products = tape.products.items[record.product_start..product_end];
    const linears = tape.linears.items[record.linear_start..linear_end];
    const y_squared = products[0].witness.result;
    const x_squared = products[1].witness.result;
    const x_cubed = products[2].witness.result;
    try expectProduct(&products[0], .base, record.recovery_point.y, record.recovery_point.y, y_squared);
    try expectProduct(&products[1], .base, record.recovery_point.x, record.recovery_point.x, x_squared);
    try expectProduct(&products[2], .base, x_squared, record.recovery_point.x, x_cubed);
    try expectLinear(&linears[0], .add, .base, x_cubed, field.bytesFromInteger(7), y_squared);
    try expectLinear(
        &linears[1],
        .reduce_once,
        .scalar,
        reverse(record.digest_big_endian),
        field.scalar_modulus.bytes,
        record.reduced_digest,
    );
    const one = field.bytesFromInteger(1);
    try expectProduct(&products[3], .scalar, record.r, record.inverse_r, one);
    try expectProduct(&products[4], .scalar, record.s, record.inverse_s, one);
    try expectLinear(
        &linears[2],
        .subtract,
        .scalar,
        @splat(0),
        record.reduced_digest,
        record.negative_digest,
    );
    try expectProduct(
        &products[5],
        .scalar,
        record.negative_digest,
        record.inverse_r,
        record.generator_scalar,
    );
    try expectProduct(
        &products[6],
        .scalar,
        record.s,
        record.inverse_r,
        record.recovery_point_scalar,
    );
    if (!std.mem.eql(u8, &record.recovery_point.x, &record.r))
        return error.InvalidProgramSequence;
    const program = &tape.scalar_programs.items[record.program_index];
    if (!std.mem.eql(u8, &program.generator_scalar, &record.generator_scalar) or
        !affine.Point.eql(program.point, record.recovery_point) or
        !std.mem.eql(u8, &program.point_scalar, &record.recovery_point_scalar) or
        !affine.Point.eql(program.result, record.public_key) or
        program.split_start != record.split_start or record.split_count != 2)
    {
        return error.InvalidProgramSequence;
    }

    var row: [Layout.main_columns]M31 = @splat(M31.zero());
    row[Layout.is_active] = M31.one();
    writeBytes(&row, Layout.digest_big_endian, &record.digest_big_endian);
    writeValue(&row, Layout.r, record.r);
    writeValue(&row, Layout.s, record.s);
    row[Layout.recovery_id] = M31.fromU64(record.recovery_id);
    writePoint(&row, Layout.recovery_point, record.recovery_point);
    writePoint(&row, Layout.public_key, record.public_key);
    writeValue(&row, Layout.reduced_digest, record.reduced_digest);
    writeValue(&row, Layout.inverse_r, record.inverse_r);
    writeValue(&row, Layout.inverse_s, record.inverse_s);
    writeValue(&row, Layout.negative_digest, record.negative_digest);
    writeValue(&row, Layout.generator_scalar, record.generator_scalar);
    writeValue(&row, Layout.recovery_point_scalar, record.recovery_point_scalar);
    writeValue(&row, Layout.y_squared, y_squared);
    writeValue(&row, Layout.x_squared, x_squared);
    writeValue(&row, Layout.x_cubed, x_cubed);
    row[Layout.y_half] = M31.fromU64(record.recovery_point.y[0] / 2);
    return row;
}

pub fn evaluateDirect(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    sink: anytype,
) void {
    comptime requireSupportedField(S);
    const active = main[Layout.is_active];
    const recovery_id = main[Layout.recovery_id];
    sink.add(active.mul(active.sub(scalar(S, 1))), 2);
    sink.add(active.mul(main[Layout.recovery_point]), 2);
    sink.add(active.mul(main[Layout.public_key]), 2);
    sink.add(recovery_id.mul(recovery_id.sub(active)), 2);
    sink.add(active.mul(
        main[Layout.recovery_point + 1 + field.limb_count]
            .sub(recovery_id)
            .sub(main[Layout.y_half].mul(scalar(S, 2))),
    ), 2);
    for (0..field.limb_count) |byte| sink.add(active.mul(
        main[Layout.recovery_point + 1 + byte]
            .sub(main[Layout.r + byte]),
    ), 2);
}

pub fn rowPairs(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    relations: anytype,
) [batch_count]logup.RowPairFor(relations_mod.InteractionScalar(S)) {
    comptime requireSupportedField(S);
    const active = main[Layout.is_active];
    const digest = valueView(S, main, Layout.digest_big_endian);
    const digest_little_endian = reverseField(S, digest);
    const r = valueView(S, main, Layout.r);
    const s = valueView(S, main, Layout.s);
    const r_big_endian = reverseField(S, r);
    const s_big_endian = reverseField(S, s);
    const recovery_point = pointView(S, main, Layout.recovery_point);
    const public_key = pointView(S, main, Layout.public_key);
    var public_key_big_endian: [2 * field.limb_count]S = undefined;
    for (0..field.limb_count) |byte| {
        public_key_big_endian[byte] =
            public_key[1 + field.limb_count - 1 - byte];
        public_key_big_endian[field.limb_count + byte] =
            public_key[1 + 2 * field.limb_count - 1 - byte];
    }
    const reduced_digest = valueView(S, main, Layout.reduced_digest);
    const inverse_r = valueView(S, main, Layout.inverse_r);
    const inverse_s = valueView(S, main, Layout.inverse_s);
    const negative_digest = valueView(S, main, Layout.negative_digest);
    const generator_scalar = valueView(S, main, Layout.generator_scalar);
    const recovery_point_scalar = valueView(S, main, Layout.recovery_point_scalar);
    const y_squared = valueView(S, main, Layout.y_squared);
    const x_squared = valueView(S, main, Layout.x_squared);
    const x_cubed = valueView(S, main, Layout.x_cubed);
    const seven = constantValue(S, 7);
    const one = constantValue(S, 1);
    const zero = constantValue(S, 0);
    const scalar_modulus = constantBytes(S, field.scalar_modulus.bytes);

    var events: [event_count]logup.RowPairFor(relations_mod.InteractionScalar(S)) = undefined;
    events[0] = productRequest(S, active, .base, pointY(S, &recovery_point), pointY(S, &recovery_point), &y_squared, relations);
    events[1] = productRequest(S, active, .base, pointX(S, &recovery_point), pointX(S, &recovery_point), &x_squared, relations);
    events[2] = productRequest(S, active, .base, &x_squared, pointX(S, &recovery_point), &x_cubed, relations);
    events[3] = linearRequest(S, active, .add, .base, &x_cubed, &seven, &y_squared, relations);
    events[4] = linearRequest(S, active, .reduce_once, .scalar, &digest_little_endian, &scalar_modulus, &reduced_digest, relations);
    events[5] = productRequest(S, active, .scalar, &r, &inverse_r, &one, relations);
    events[6] = productRequest(S, active, .scalar, &s, &inverse_s, &one, relations);
    events[7] = linearRequest(S, active, .subtract, .scalar, &zero, &reduced_digest, &negative_digest, relations);
    events[8] = productRequest(S, active, .scalar, &negative_digest, &inverse_r, &generator_scalar, relations);
    events[9] = productRequest(S, active, .scalar, &s, &inverse_r, &recovery_point_scalar, relations);
    events[10] = request(S, active, relations_mod.combineProgram(S, relations.program, relations_mod.programTuple(
        S,
        &generator_scalar,
        &recovery_point,
        &recovery_point_scalar,
        &public_key,
    )));
    events[11] = emit(S, active, relations_mod.combineRecovery(
        S,
        relations.recovery,
        relations_mod.recoveryTuple(
            S,
            scalar(S, relation_version),
            active,
            &digest,
            &r_big_endian,
            &s_big_endian,
            main[Layout.recovery_id],
            &public_key_big_endian,
        ),
    ));

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
    var bytes: [2 * range_pair_count]S = undefined;
    var cursor: usize = 0;
    inline for (.{ Layout.digest_big_endian, Layout.r, Layout.s }) |offset| {
        copyBytes(S, &bytes, &cursor, main[offset..][0..field.limb_count]);
    }
    copyBytes(
        S,
        &bytes,
        &cursor,
        main[Layout.public_key + 1 ..][0 .. 2 * field.limb_count],
    );
    bytes[cursor] = main[Layout.recovery_id];
    bytes[cursor + 1] = main[Layout.y_half];
    cursor += 2;
    std.debug.assert(cursor == bytes.len);
    var result: [range_pair_count][2]S = undefined;
    for (&result, 0..) |*pair, index| pair.* =
        .{ bytes[2 * index], bytes[2 * index + 1] };
    return result;
}

fn expectProduct(record: *const affine.ProductRecord, modulus: affine.ModulusKind, lhs: affine.Value, rhs: affine.Value, result: affine.Value) Error!void {
    if (record.modulus != modulus or
        !std.mem.eql(u8, &record.witness.lhs, &lhs) or
        !std.mem.eql(u8, &record.witness.rhs, &rhs) or
        !std.mem.eql(u8, &record.witness.result, &result))
        return error.InvalidProductSequence;
}

fn expectLinear(record: *const affine.LinearRecord, kind: affine.LinearKind, modulus: affine.ModulusKind, lhs: affine.Value, rhs: affine.Value, result: affine.Value) Error!void {
    if (record.kind != kind or record.modulus != modulus or
        !std.mem.eql(u8, &record.lhs, &lhs) or
        !std.mem.eql(u8, &record.rhs, &rhs) or
        !std.mem.eql(u8, &record.result, &result))
        return error.InvalidLinearSequence;
}

fn productRequest(comptime S: type, coefficient: S, modulus: affine.ModulusKind, lhs: *const [field.limb_count]S, rhs: *const [field.limb_count]S, result: *const [field.limb_count]S, relations: anytype) logup.RowPairFor(relations_mod.InteractionScalar(S)) {
    return request(S, coefficient, relations_mod.combineProduct(S, relations.product, relations_mod.productTuple(
        S,
        scalar(S, @intFromEnum(modulus)),
        lhs,
        rhs,
        result,
    )));
}

fn linearRequest(comptime S: type, coefficient: S, kind: affine.LinearKind, modulus: affine.ModulusKind, lhs: *const [field.limb_count]S, rhs: *const [field.limb_count]S, result: *const [field.limb_count]S, relations: anytype) logup.RowPairFor(relations_mod.InteractionScalar(S)) {
    return request(S, coefficient, relations_mod.combineLinear(S, relations.linear, relations_mod.linearTuple(
        S,
        scalar(S, @intFromEnum(kind)),
        scalar(S, @intFromEnum(modulus)),
        lhs,
        rhs,
        result,
    )));
}

fn pointView(comptime S: type, main: *const [Layout.main_columns]S, offset: usize) [relations_mod.encoded_point_size]S {
    return main[offset..][0..relations_mod.encoded_point_size].*;
}

fn valueView(comptime S: type, main: *const [Layout.main_columns]S, offset: usize) [field.limb_count]S {
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

fn request(comptime S: type, coefficient: S, denominator: relations_mod.InteractionScalar(S)) logup.RowPairFor(relations_mod.InteractionScalar(S)) {
    return logup.RowPairFor(relations_mod.InteractionScalar(S)).single(
        lift(S, coefficient).neg(),
        denominator,
    );
}

fn emit(comptime S: type, coefficient: S, denominator: relations_mod.InteractionScalar(S)) logup.RowPairFor(relations_mod.InteractionScalar(S)) {
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
    @compileError("secp256k1 recovery AIR requires a base-field lift");
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

fn copyBytes(comptime S: type, destination: []S, cursor: *usize, source: []const S) void {
    @memcpy(destination[cursor.*..][0..source.len], source);
    cursor.* += source.len;
}

fn requireSupportedField(comptime S: type) void {
    if (S != M31 and S != QM31 and !@hasDecl(S, "fromBase"))
        @compileError("secp256k1 recovery AIR requires a base-field lift");
}
