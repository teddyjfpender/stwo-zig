//! The value carried by a circuit wire: a concrete `QM31`, or `NoValue` when
//! only the topology is built.
//!
//! Port of `crates/circuits/src/ivalue.rs` (https://github.com/starkware-libs/proving
//! at 5a7c5ede4299c91a61df19a07cba4f7502c14230). Upstream expresses the
//! surface as the `IValue` trait; here every operation takes the value type as
//! a comptime parameter and dispatches on it, so value mode and topology mode
//! run the same builder code, as in Rust. `NoValue` is zero-sized: topology
//! mode stores no values and computes nothing.
//!
//! Parity notes:
//! - `fromU32s` reduces each word modulo P (`qm31_from_u32s`, `M31::from(u32)`).
//! - `div` panics on a zero divisor, like upstream's `QM31 / QM31` (whose
//!   `inverse` asserts a non-zero element).
//! - `unpackU32` panics on a value that is not `(u16, u16, 0, 0)`, as upstream.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const pointwise = stwo_core.fields.qm31_pointwise;
const Blake2s256 = std.crypto.hash.blake2.Blake2s256;

/// The topology-mode value: carries nothing.
pub const NoValue = struct {};

/// Rejects every value type other than `QM31` and `NoValue` at compile time.
pub fn assertValueType(comptime V: type) void {
    if (V != QM31 and V != NoValue) @compileError("circuit values are QM31 or NoValue, got " ++ @typeName(V));
}

/// `qm31_from_u32s`: four words, each reduced modulo P.
pub fn qm31FromU32s(a: u32, b: u32, c: u32, d: u32) QM31 {
    return pointwise.fromU32s(a, b, c, d);
}

/// The four canonical M31 limbs `[a, b, c, d]` of `(a + b·i) + (c + d·i)·u`.
pub fn limbs(value: QM31) [4]u32 {
    const m = value.toM31Array();
    return .{ m[0].v, m[1].v, m[2].v, m[3].v };
}

/// `IValue::from_qm31`.
pub fn fromQm31(comptime V: type, value: QM31) V {
    assertValueType(V);
    return if (V == QM31) value else .{};
}

/// `IValue::placeholder`: the dummy value of a reserved variable.
pub fn placeholder(comptime V: type) V {
    return fromQm31(V, QM31.fromU32Unchecked(0xabcdef, 0xabcdef, 0xabcdef, 0xabcdef));
}

pub fn add(comptime V: type, a: V, b: V) V {
    return if (V == QM31) a.add(b) else .{};
}

pub fn sub(comptime V: type, a: V, b: V) V {
    return if (V == QM31) a.sub(b) else .{};
}

pub fn mul(comptime V: type, a: V, b: V) V {
    return if (V == QM31) a.mul(b) else .{};
}

/// Field division. Panics when `b` is zero, as upstream does.
pub fn div(comptime V: type, a: V, b: V) V {
    if (V != QM31) return .{};
    return a.div(b) catch @panic("0 has no inverse");
}

/// `IValue::pointwise_mul`: `(x0·y0) + (x1·y1)·i + (x2·y2)·u + (x3·y3)·iu`.
pub fn pointwiseMul(comptime V: type, a: V, b: V) V {
    return if (V == QM31) pointwise.pointwiseMul(a, b) else .{};
}

/// `IValue::pointwise_inv_or_zero`: each coordinate `x` becomes `1/x`, or 0.
pub fn pointwiseInvOrZero(comptime V: type, a: V) V {
    return if (V == QM31) pointwise.pointwiseInvOrZero(a) else .{};
}

/// `IValue::pointwise_lsb`: the least significant bit of each coordinate.
pub fn pointwiseLsb(comptime V: type, a: V) V {
    return if (V == QM31) pointwise.pointwiseLsb(a) else .{};
}

/// `IValue::m31_to_u32`: `(x, _, _, _)` becomes `(x & 0xFFFF, x >> 16, 0, 0)`.
pub fn m31ToU32(comptime V: type, a: V) V {
    if (V != QM31) return .{};
    const x = a.c0.a.v;
    return QM31.fromU32Unchecked(x & 0xFFFF, x >> 16, 0, 0);
}

/// `IValue::pack_u32`: the limb form `(low_u16, high_u16, 0, 0)` of a `u32`.
pub fn packU32(comptime V: type, value: u32) V {
    return fromQm31(V, QM31.fromU32Unchecked(value & 0xFFFF, value >> 16, 0, 0));
}

/// `IValue::unpack_u32`: the inverse of `packU32` (0 in topology mode).
pub fn unpackU32(comptime V: type, value: V) u32 {
    if (V != QM31) return 0;
    const l = limbs(value);
    if (l[2] != 0 or l[3] != 0) @panic("value does not have zeroes in the last two coordinates as expected");
    if (l[0] > 0xFFFF or l[1] > 0xFFFF) @panic("low and high coordinates must be u16 values");
    return l[0] | (l[1] << 16);
}

/// Value equality (always true in topology mode).
pub fn eql(comptime V: type, a: V, b: V) bool {
    return if (V == QM31) a.eql(b) else true;
}

/// `IValue::sort_by_u_coordinate`: a stable sort by the `c` limb (the real
/// part of the `u` coordinate), as a permutation for `Context.permute`.
/// Topology mode keeps the input order.
pub fn sortByUCoordinate(comptime V: type) fn ([]const V, []V) void {
    return struct {
        fn apply(input: []const V, output: []V) void {
            std.debug.assert(input.len == output.len);
            @memcpy(output, input);
            if (V != QM31) return;
            // `std.mem.sort` is the stable block sort, matching `sorted_by_key`.
            std.mem.sort(QM31, output, {}, lessByU);
        }

        fn lessByU(_: void, lhs: QM31, rhs: QM31) bool {
            return lhs.c1.a.v < rhs.c1.a.v;
        }
    }.apply;
}

/// `IValue::blake2s`: Blake2s over the first `n_bytes` of the little-endian
/// limbs of `input`, returned as eight packed `u32` words (no reduction).
/// Topology mode returns eight placeholders.
pub fn blake2s(comptime V: type, input: []const V, n_bytes: usize) [8]V {
    std.debug.assert(input.len == std.math.divCeil(usize, n_bytes, 16) catch unreachable);
    if (V != QM31) return @splat(.{});
    var hasher = Blake2s256.init(.{});
    var remaining = n_bytes;
    for (input) |value| {
        for (limbs(value)) |limb| {
            if (remaining == 0) break;
            const bytes = std.mem.toBytes(std.mem.nativeToLittle(u32, limb));
            const take = @min(remaining, bytes.len);
            hasher.update(bytes[0..take]);
            remaining -= take;
        }
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    var words: [8]QM31 = undefined;
    for (&words, stwo_core.vcs.blake2_hash.digestToU32s(digest)) |*word, value| word.* = packU32(QM31, value);
    return words;
}

test "ivalue: pointwise_inv_or_zero matches upstream ivalue_test" {
    // `test_pointwise_inv_or_zero`, crates/circuits/src/ivalue_test.rs.
    const inverse = pointwiseInvOrZero(QM31, qm31FromU32s(2, 0, 3, 4));
    const one = M31.one();
    const expected = QM31.fromM31(try one.div(M31.fromCanonical(2)), M31.zero(), try one.div(M31.fromCanonical(3)), try one.div(M31.fromCanonical(4)));
    try std.testing.expect(inverse.eql(expected));
}

test "ivalue: u32 packing round-trips every boundary" {
    for ([_]u32{ 0, 1, 0xFFFF, 0x1_0000, 0xDEAD_BEEF, 0xFFFF_FFFF }) |word| {
        const packed_value = packU32(QM31, word);
        try std.testing.expectEqual(word, unpackU32(QM31, packed_value));
        try std.testing.expectEqual(@as(u32, 0), unpackU32(NoValue, packU32(NoValue, word)));
    }
    // `m31_to_u32` of an M31 is its limb form.
    try std.testing.expect(m31ToU32(QM31, qm31FromU32s(0x7FFF_FFFE, 0, 0, 0)).eql(packU32(QM31, 0x7FFF_FFFE)));
}

test "ivalue: sort_by_u_coordinate is stable and keyed on the u limb" {
    const input = [_]QM31{ qm31FromU32s(1, 0, 9, 0), qm31FromU32s(2, 0, 3, 0), qm31FromU32s(3, 0, 7, 0), qm31FromU32s(4, 0, 3, 0), qm31FromU32s(5, 0, 0, 0) };
    var output: [5]QM31 = undefined;
    sortByUCoordinate(QM31)(&input, &output);
    const order = [_]u32{ 5, 2, 4, 3, 1 };
    for (output, order) |value, a| try std.testing.expectEqual(a, value.c0.a.v);
}

test "ivalue: blake2s hashes the little-endian limbs up to n_bytes" {
    // `test_blake2s`, crates/circuits/src/blake_test.rs, cross-checked with std Blake2s.
    const message = [16]u32{
        930933030,  1766240503, 3660871006, 388409270, 1948594622, 3119396969, 3924579183, 2089920034,
        3857888532, 929304360,  1810891574, 860971754, 1822893775, 2008495810, 2958962335, 2340515744,
    };
    var input: [4]QM31 = undefined;
    for (&input, 0..) |*value, i| value.* = qm31FromU32s(message[4 * i], message[4 * i + 1], message[4 * i + 2], message[4 * i + 3]);
    const words = blake2s(QM31, &input, 64);
    var bytes: [64]u8 = undefined;
    for (input, 0..) |value, i| {
        for (limbs(value), 0..) |limb, j| std.mem.writeInt(u32, bytes[16 * i + 4 * j ..][0..4], limb, .little);
    }
    var digest: [32]u8 = undefined;
    Blake2s256.hash(&bytes, &digest, .{});
    for (words, 0..) |word, i| try std.testing.expectEqual(std.mem.readInt(u32, digest[4 * i ..][0..4], .little), unpackU32(QM31, word));
}
