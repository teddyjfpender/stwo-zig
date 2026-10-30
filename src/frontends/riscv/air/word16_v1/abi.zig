//! NEW, INACTIVE word16 semantic namespace. No released AIR imports this file.
//! A Word is a pair of field expressions, NOT an implicit range proof.
const core = @import("stwo_core");
pub const M = core.fields.m31.M31;
pub const Q = core.fields.qm31.QM31;
pub const VERSION: u32 = 1;
pub const production_active = false;
pub const qualification = .local_m31_algebra_only;

pub fn c(comptime S: type, value: u32) S {
    const base = M.fromCanonical(value);
    if (S == M) return base;
    const secure = Q.fromBase(base);
    if (S == Q) return secure;
    return S.splat(secure);
}
pub fn signed(comptime S: type, value: i32) S {
    return if (value < 0) S.zero().sub(c(S, @intCast(-@as(i64, value)))) else c(S, @intCast(value));
}
pub fn Word(comptime S: type) type {
    return struct {
        lo: S,
        hi: S,
        pub fn zero() @This() {
            return .{ .lo = S.zero(), .hi = S.zero() };
        }
        pub fn fromU32(value: u32) @This() {
            return .{ .lo = c(S, value & 0xffff), .hi = c(S, value >> 16) };
        }
        pub fn packedBytes(bytes: [4]S) @This() {
            return .{ .lo = bytes[0].add(bytes[1].mul(c(S, 256))), .hi = bytes[2].add(bytes[3].mul(c(S, 256))) };
        }
    };
}
pub fn Read(comptime S: type) type {
    return struct { address: S, previous_clock: S, value: Word(S) };
}
pub fn Write(comptime S: type) type {
    return struct { address: S, previous_clock: S, before: Word(S), after: Word(S) };
}
pub fn ByteView(comptime S: type) type {
    return struct { bytes: [4]S, word: Word(S) };
}
/// These are the only two conversion equalities. Bounds must come from the
/// source byte AIR or from explicit byte-pair/bitwise table requests.
pub fn byteViewConstraints(comptime S: type, view: ByteView(S)) [2]S {
    const packed_word = Word(S).packedBytes(view.bytes);
    return .{ packed_word.lo.sub(view.word.lo), packed_word.hi.sub(view.word.hi) };
}
pub fn boolResidual(comptime S: type, value: S) S {
    return value.mul(value.sub(S.one()));
}
pub fn ternaryResidual(comptime S: type, value: S) S {
    return value.mul(value.sub(S.one())).mul(value.add(S.one()));
}
pub fn accessClock(comptime S: type, instruction_clock: S, comptime ordinal: u2) S {
    if (ordinal > 2) @compileError("the fourth subclock is not an access");
    return instruction_clock.sub(S.one()).mul(c(S, 4)).add(c(S, @as(u32, ordinal) + 1));
}
/// Inverse powers are constants. This never treats an arbitrary u32 as M31.
pub fn divide65536(comptime S: type, value: S) S {
    const inverse = M.fromCanonical(65536).inv() catch unreachable;
    return value.mul(c(S, inverse.v));
}
/// A sink implements add(residual, exact_total_degree). `active` MUST be an
/// independently derived fixed prefix, not an untrusted witness selector.
pub fn enforce(comptime S: type, sink: anytype, active: S, value: S, comptime degree: u8) void {
    sink.add(active.mul(value), degree + 1);
}
pub fn equalWord(comptime S: type, sink: anytype, active: S, left: Word(S), right: Word(S)) void {
    enforce(S, sink, active, left.lo.sub(right.lo), 1);
    enforce(S, sink, active, left.hi.sub(right.hi), 1);
}
/// Canonical x0 WRITE. Read correctness follows only from a fully closed
/// register relation whose initial x0 producer is zero and all writes use this.
pub fn destination(comptime S: type, sink: anytype, active: S, write: Write(S), result: Word(S), nonzero: S, inverse: S) void {
    enforce(S, sink, active, boolResidual(S, nonzero), 2);
    enforce(S, sink, active, write.address.mul(S.one().sub(nonzero)), 2);
    enforce(S, sink, active, write.address.mul(inverse).sub(nonzero), 2);
    enforce(S, sink, active, S.one().sub(nonzero).mul(write.before.lo), 2);
    enforce(S, sink, active, S.one().sub(nonzero).mul(write.before.hi), 2);
    enforce(S, sink, active, write.after.lo.sub(nonzero.mul(result.lo)), 2);
    enforce(S, sink, active, write.after.hi.sub(nonzero.mul(result.hi)), 2);
}
/// Zero every inactive semantic field. This is intentionally conservative;
/// physical lowering may alias fields only after proving equivalent equations.
pub fn padding(comptime S: type, sink: anytype, active: S, row: anytype) void {
    paddingValue(S, sink, S.one().sub(active), row);
}
fn paddingValue(comptime S: type, sink: anytype, inactive: S, value: anytype) void {
    const T = @TypeOf(value);
    if (T == S) {
        sink.add(inactive.mul(value), 2);
        return;
    }
    switch (@typeInfo(T)) {
        .@"struct" => |info| inline for (info.fields) |field| paddingValue(S, sink, inactive, @field(value, field.name)),
        .array => for (value) |item| paddingValue(S, sink, inactive, item),
        else => @compileError("non-scalar field in word16 semantic row"),
    }
}
