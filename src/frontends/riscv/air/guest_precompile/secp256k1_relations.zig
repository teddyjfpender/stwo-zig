//! Typed buses joining compact secp256k1 arithmetic and scalar-program rows.
//!
//! Product and linear rows emit primitive operation tuples. Point rows consume
//! those tuples and emit complete affine transitions; the scalar program then
//! consumes the point transitions in execution order.  The modulus and
//! operation tags are inside each tuple, so base-field and scalar-field work
//! cannot cancel across otherwise identical byte strings.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const challenges = @import("../relation_challenges.zig");
const affine = @import("secp256k1_affine.zig");
const field = @import("secp256k1_field.zig");

pub const product_arity: usize = 1 + 3 * field.limb_count;
pub const linear_arity: usize = 2 + 3 * field.limb_count;
pub const encoded_point_size: usize = 1 + 2 * field.limb_count;
pub const point_arity: usize = 1 + 3 * encoded_point_size;
pub const split_arity: usize = 2 + 3 * field.limb_count;
pub const table_arity: usize = 2 + encoded_point_size;
pub const program_arity: usize = 2 * field.limb_count + 2 * encoded_point_size;
pub const table_root_arity: usize = 1 + encoded_point_size;
pub const ecdsa_arity: usize = 1 + field.limb_count + encoded_point_size +
    2 * field.limb_count;
pub const byte_arity: usize = 1;
/// Version, successful status, digest/r/s, recovery-id, affine x/y bytes.
pub const recovery_arity: usize = 3 + 5 * field.limb_count;

pub fn ProductTuple(comptime S: type) type {
    return [product_arity]S;
}

pub fn LinearTuple(comptime S: type) type {
    return [linear_arity]S;
}

pub fn PointTuple(comptime S: type) type {
    return [point_arity]S;
}

pub fn SplitTuple(comptime S: type) type {
    return [split_arity]S;
}

pub fn TableTuple(comptime S: type) type {
    return [table_arity]S;
}

pub fn ProgramTuple(comptime S: type) type {
    return [program_arity]S;
}

pub fn TableRootTuple(comptime S: type) type {
    return [table_root_arity]S;
}

pub fn EcdsaTuple(comptime S: type) type {
    return [ecdsa_arity]S;
}

pub fn ByteTuple(comptime S: type) type {
    return [byte_arity]S;
}

pub fn RecoveryTuple(comptime S: type) type {
    return [recovery_arity]S;
}

/// Interaction scalars are secure-field values for native base rows and the
/// recording scalar itself for recursive compiler replay.
pub fn InteractionScalar(comptime S: type) type {
    return if (S == M31) QM31 else S;
}

pub const Relations = struct {
    /// Base buses are drawn first so recovery caller rows and ordinary CPU,
    /// program, and state-chain components share one challenge authority.
    base: challenges.Relations,
    product: challenges.RelationElements(product_arity),
    linear: challenges.RelationElements(linear_arity),
    point: challenges.RelationElements(point_arity),
    split: challenges.RelationElements(split_arity),
    table: challenges.RelationElements(table_arity),
    program: challenges.RelationElements(program_arity),
    table_root: challenges.RelationElements(table_root_arity),
    ecdsa: challenges.RelationElements(ecdsa_arity),
    byte: challenges.RelationElements(byte_arity),
    recovery: challenges.RelationElements(recovery_arity),

    pub fn draw(allocator: std.mem.Allocator, channel: anytype) !Relations {
        const base = try challenges.Relations.draw(allocator, channel);
        const values = try channel.drawSecureFelts(allocator, 20);
        defer allocator.free(values);
        if (values.len != 20) return error.InvalidChallengeDraw;
        return .{
            .base = base,
            .product = .init(values[0], values[1]),
            .linear = .init(values[2], values[3]),
            .point = .init(values[4], values[5]),
            .split = .init(values[6], values[7]),
            .table = .init(values[8], values[9]),
            .program = .init(values[10], values[11]),
            .table_root = .init(values[12], values[13]),
            .ecdsa = .init(values[14], values[15]),
            .byte = .init(values[16], values[17]),
            .recovery = .init(values[18], values[19]),
        };
    }

    pub fn dummy() Relations {
        return .{
            .base = .dummy(),
            .product = .dummy(),
            .linear = .dummy(),
            .point = .dummy(),
            .split = .dummy(),
            .table = .dummy(),
            .program = .dummy(),
            .table_root = .dummy(),
            .ecdsa = .dummy(),
            .byte = .dummy(),
            .recovery = .dummy(),
        };
    }
};

pub fn productTuple(
    comptime S: type,
    modulus: S,
    lhs: *const [field.limb_count]S,
    rhs: *const [field.limb_count]S,
    result: *const [field.limb_count]S,
) ProductTuple(S) {
    var tuple: ProductTuple(S) = undefined;
    tuple[0] = modulus;
    @memcpy(tuple[1..][0..field.limb_count], lhs);
    @memcpy(tuple[1 + field.limb_count ..][0..field.limb_count], rhs);
    @memcpy(tuple[1 + 2 * field.limb_count ..][0..field.limb_count], result);
    return tuple;
}

pub fn linearTuple(
    comptime S: type,
    kind: S,
    modulus: S,
    lhs: *const [field.limb_count]S,
    rhs: *const [field.limb_count]S,
    result: *const [field.limb_count]S,
) LinearTuple(S) {
    var tuple: LinearTuple(S) = undefined;
    tuple[0] = kind;
    tuple[1] = modulus;
    @memcpy(tuple[2..][0..field.limb_count], lhs);
    @memcpy(tuple[2 + field.limb_count ..][0..field.limb_count], rhs);
    @memcpy(tuple[2 + 2 * field.limb_count ..][0..field.limb_count], result);
    return tuple;
}

pub fn pointTuple(
    comptime S: type,
    kind: S,
    lhs: *const [encoded_point_size]S,
    rhs: *const [encoded_point_size]S,
    result: *const [encoded_point_size]S,
) PointTuple(S) {
    var tuple: PointTuple(S) = undefined;
    tuple[0] = kind;
    @memcpy(tuple[1..][0..encoded_point_size], lhs);
    @memcpy(tuple[1 + encoded_point_size ..][0..encoded_point_size], rhs);
    @memcpy(tuple[1 + 2 * encoded_point_size ..][0..encoded_point_size], result);
    return tuple;
}

pub fn splitTuple(
    comptime S: type,
    negative_1: S,
    negative_2: S,
    original: *const [field.limb_count]S,
    magnitude_1: *const [field.limb_count]S,
    magnitude_2: *const [field.limb_count]S,
) SplitTuple(S) {
    var tuple: SplitTuple(S) = undefined;
    tuple[0] = negative_1;
    tuple[1] = negative_2;
    @memcpy(tuple[2..][0..field.limb_count], original);
    @memcpy(tuple[2 + field.limb_count ..][0..field.limb_count], magnitude_1);
    @memcpy(tuple[2 + 2 * field.limb_count ..][0..field.limb_count], magnitude_2);
    return tuple;
}

pub fn tableTuple(
    comptime S: type,
    table_kind: S,
    digit_code: S,
    point: *const [encoded_point_size]S,
) TableTuple(S) {
    var tuple: TableTuple(S) = undefined;
    tuple[0] = table_kind;
    tuple[1] = digit_code;
    @memcpy(tuple[2..], point);
    return tuple;
}

pub fn programTuple(
    comptime S: type,
    generator_scalar: *const [field.limb_count]S,
    point: *const [encoded_point_size]S,
    point_scalar: *const [field.limb_count]S,
    result: *const [encoded_point_size]S,
) ProgramTuple(S) {
    var tuple: ProgramTuple(S) = undefined;
    @memcpy(tuple[0..field.limb_count], generator_scalar);
    @memcpy(tuple[field.limb_count..][0..encoded_point_size], point);
    @memcpy(tuple[field.limb_count + encoded_point_size ..][0..field.limb_count], point_scalar);
    @memcpy(tuple[field.limb_count + encoded_point_size + field.limb_count ..], result);
    return tuple;
}

pub fn tableRootTuple(
    comptime S: type,
    table_kind: S,
    point: *const [encoded_point_size]S,
) TableRootTuple(S) {
    var tuple: TableRootTuple(S) = undefined;
    tuple[0] = table_kind;
    @memcpy(tuple[1..], point);
    return tuple;
}

pub fn ecdsaTuple(
    comptime S: type,
    success: S,
    digest_big_endian: *const [field.limb_count]S,
    public_key: *const [encoded_point_size]S,
    r: *const [field.limb_count]S,
    s: *const [field.limb_count]S,
) EcdsaTuple(S) {
    var tuple: EcdsaTuple(S) = undefined;
    tuple[0] = success;
    @memcpy(tuple[1..][0..field.limb_count], digest_big_endian);
    @memcpy(tuple[1 + field.limb_count ..][0..encoded_point_size], public_key);
    @memcpy(tuple[1 + field.limb_count + encoded_point_size ..][0..field.limb_count], r);
    @memcpy(tuple[1 + 2 * field.limb_count + encoded_point_size ..], s);
    return tuple;
}

/// Canonical successful-recovery relation. The point at `public_key` must be
/// affine; callers supply only its x/y bytes and the arithmetic row proves its
/// infinity marker is zero independently.
pub fn recoveryTuple(
    comptime S: type,
    version: S,
    status: S,
    digest_big_endian: *const [field.limb_count]S,
    r: *const [field.limb_count]S,
    s: *const [field.limb_count]S,
    recovery_id: S,
    public_key_xy_big_endian: *const [2 * field.limb_count]S,
) RecoveryTuple(S) {
    var tuple: RecoveryTuple(S) = undefined;
    tuple[0] = version;
    tuple[1] = status;
    @memcpy(tuple[2..][0..field.limb_count], digest_big_endian);
    @memcpy(tuple[2 + field.limb_count ..][0..field.limb_count], r);
    @memcpy(tuple[2 + 2 * field.limb_count ..][0..field.limb_count], s);
    tuple[2 + 3 * field.limb_count] = recovery_id;
    @memcpy(
        tuple[3 + 3 * field.limb_count ..][0 .. 2 * field.limb_count],
        public_key_xy_big_endian,
    );
    return tuple;
}

pub fn productTupleForRecord(record: *const affine.ProductRecord) ProductTuple(M31) {
    const lhs = feltBytes(record.witness.lhs);
    const rhs = feltBytes(record.witness.rhs);
    const result = feltBytes(record.witness.result);
    return productTuple(
        M31,
        scalar(M31, @intFromEnum(record.modulus)),
        &lhs,
        &rhs,
        &result,
    );
}

pub fn linearTupleForRecord(record: *const affine.LinearRecord) LinearTuple(M31) {
    const lhs = feltBytes(record.lhs);
    const rhs = feltBytes(record.rhs);
    const result = feltBytes(record.result);
    return linearTuple(
        M31,
        scalar(M31, @intFromEnum(record.kind)),
        scalar(M31, @intFromEnum(record.modulus)),
        &lhs,
        &rhs,
        &result,
    );
}

pub fn encodePoint(point: affine.Point) [encoded_point_size]M31 {
    var result: [encoded_point_size]M31 = undefined;
    result[0] = scalar(M31, @intFromBool(point.infinity));
    for (point.x, 0..) |value, index| result[1 + index] = scalar(M31, value);
    for (point.y, 0..) |value, index| {
        result[1 + field.limb_count + index] = scalar(M31, value);
    }
    return result;
}

pub fn pointTupleForRecord(record: *const affine.PointRecord) PointTuple(M31) {
    const lhs = encodePoint(record.lhs);
    const rhs = encodePoint(record.rhs);
    const result = encodePoint(record.result);
    return pointTuple(
        M31,
        scalar(M31, @intFromEnum(record.kind)),
        &lhs,
        &rhs,
        &result,
    );
}

pub fn splitTupleForRecord(record: *const affine.ScalarSplitRecord) SplitTuple(M31) {
    const original = feltBytes(record.original);
    const magnitude_1 = feltBytes(record.magnitude_1);
    const magnitude_2 = feltBytes(record.magnitude_2);
    return splitTuple(
        M31,
        scalar(M31, @intFromBool(record.negative_1)),
        scalar(M31, @intFromBool(record.negative_2)),
        &original,
        &magnitude_1,
        &magnitude_2,
    );
}

pub fn tableTupleForEntry(
    kind: affine.TableKind,
    digit_code: usize,
    point: affine.Point,
) TableTuple(M31) {
    const encoded = encodePoint(point);
    return tableTuple(
        M31,
        scalar(M31, @intFromEnum(kind)),
        scalar(M31, digit_code),
        &encoded,
    );
}

pub fn programTupleForRecord(record: *const affine.ScalarProgramRecord) ProgramTuple(M31) {
    const generator_scalar = feltBytes(record.generator_scalar);
    const point = encodePoint(record.point);
    const point_scalar = feltBytes(record.point_scalar);
    const result = encodePoint(record.result);
    return programTuple(
        M31,
        &generator_scalar,
        &point,
        &point_scalar,
        &result,
    );
}

pub fn ecdsaTupleForRecord(record: *const affine.EcdsaRecord) EcdsaTuple(M31) {
    const digest = feltBytes(record.digest_big_endian);
    const public_key = encodePoint(record.public_key);
    const r = feltBytes(record.r);
    const s = feltBytes(record.s);
    return ecdsaTuple(M31, M31.one(), &digest, &public_key, &r, &s);
}

pub fn recoveryTupleForRecord(
    record: *const affine.RecoveryRecord,
) RecoveryTuple(M31) {
    const digest = feltBytes(record.digest_big_endian);
    const r = feltBytesReversed(record.r);
    const s = feltBytesReversed(record.s);
    var public_key_big_endian: [2 * field.limb_count]M31 = undefined;
    for (record.public_key.x, 0..) |byte, index| {
        public_key_big_endian[field.limb_count - 1 - index] = M31.fromU64(byte);
    }
    for (record.public_key.y, 0..) |byte, index| {
        public_key_big_endian[2 * field.limb_count - 1 - index] = M31.fromU64(byte);
    }
    return recoveryTuple(
        M31,
        M31.one(),
        M31.one(),
        &digest,
        &r,
        &s,
        M31.fromU64(record.recovery_id),
        &public_key_big_endian,
    );
}

fn feltBytesReversed(value: affine.Value) [field.limb_count]M31 {
    var result: [field.limb_count]M31 = undefined;
    for (value, 0..) |byte, index| {
        result[value.len - 1 - index] = M31.fromU64(byte);
    }
    return result;
}

pub fn combineProduct(
    comptime S: type,
    relation: anytype,
    tuple: ProductTuple(S),
) InteractionScalar(S) {
    return combine(S, product_arity, relation, tuple);
}

pub fn combineLinear(
    comptime S: type,
    relation: anytype,
    tuple: LinearTuple(S),
) InteractionScalar(S) {
    return combine(S, linear_arity, relation, tuple);
}

pub fn combinePoint(
    comptime S: type,
    relation: anytype,
    tuple: PointTuple(S),
) InteractionScalar(S) {
    return combine(S, point_arity, relation, tuple);
}

pub fn combineSplit(
    comptime S: type,
    relation: anytype,
    tuple: SplitTuple(S),
) InteractionScalar(S) {
    return combine(S, split_arity, relation, tuple);
}

pub fn combineTable(
    comptime S: type,
    relation: anytype,
    tuple: TableTuple(S),
) InteractionScalar(S) {
    return combine(S, table_arity, relation, tuple);
}

pub fn combineProgram(
    comptime S: type,
    relation: anytype,
    tuple: ProgramTuple(S),
) InteractionScalar(S) {
    return combine(S, program_arity, relation, tuple);
}

pub fn combineTableRoot(
    comptime S: type,
    relation: anytype,
    tuple: TableRootTuple(S),
) InteractionScalar(S) {
    return combine(S, table_root_arity, relation, tuple);
}

pub fn combineEcdsa(
    comptime S: type,
    relation: anytype,
    tuple: EcdsaTuple(S),
) InteractionScalar(S) {
    return combine(S, ecdsa_arity, relation, tuple);
}

pub fn combineByte(
    comptime S: type,
    relation: anytype,
    tuple: ByteTuple(S),
) InteractionScalar(S) {
    return combine(S, byte_arity, relation, tuple);
}

pub fn combineRecovery(
    comptime S: type,
    relation: anytype,
    tuple: RecoveryTuple(S),
) InteractionScalar(S) {
    return combine(S, recovery_arity, relation, tuple);
}

fn combine(
    comptime S: type,
    comptime arity: usize,
    relation: anytype,
    tuple: [arity]S,
) InteractionScalar(S) {
    return combineAny(S, relation, tuple);
}

/// Combines either a native relation challenge or the recursion compiler's
/// graph relation without changing the native M31/QM31 call surface.
pub fn combineAny(
    comptime S: type,
    relation: anytype,
    tuple: anytype,
) InteractionScalar(S) {
    const Value = @TypeOf(tuple[0]);
    if (comptime Value == M31) return relation.combineBase(tuple);
    if (comptime Value == QM31) return relation.combineSecure(tuple);
    return relation.combine(tuple);
}

fn feltBytes(value: affine.Value) [field.limb_count]M31 {
    var result: [field.limb_count]M31 = undefined;
    for (value, 0..) |byte, index| result[index] = M31.fromU64(byte);
    return result;
}

fn scalar(comptime S: type, value: anytype) S {
    const canonical: u64 = @intCast(value);
    if (S == M31) return M31.fromU64(canonical);
    if (S == QM31) return QM31.fromBase(M31.fromU64(canonical));
    if (@hasDecl(S, "fromBase")) return S.fromBase(M31.fromU64(canonical));
    @compileError("secp256k1 relations require a base-field lift");
}

comptime {
    if (product_arity != 97 or linear_arity != 98 or point_arity != 196 or
        split_arity != 98 or table_arity != 67 or program_arity != 194 or
        table_root_arity != 66 or ecdsa_arity != 162 or recovery_arity != 163)
        @compileError("secp256k1 relation geometry drifted");
}
