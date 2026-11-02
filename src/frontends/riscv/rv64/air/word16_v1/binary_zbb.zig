//! Word16 Zbb BINARY chip arithmetic (profile ethereum_services_v3_zbb):
//! andn, orn, xnor, rev8, sext.b, sext.h. zext.h needs no chip: it is the
//! existing BINARY AND with ROM immediate 0xffff (a decode-level mapping).
//!
//! The row reuses the BINARY chip's byte decomposition and its eight canonical
//! byte-AND requests (a_i, b_i, T_i) against the SAME fixed AND table, so it is
//! not an accepting component by itself either. It adds six selectors; every
//! output byte is affine in (a, b, T) per selector, so the derived C limbs are
//! degree 2, exactly as in binary.zig.
//!
//! Soundness (integer statement). Let a row be active with selector s_k = 1.
//!  1. Selector booleanity, sum(s) = active and active booleanity make exactly
//!     one op selected; payload[0] = 19 + k is then the op's GLOBAL FUNCTION id
//!     (19..24, disjoint from ALU 0..10, BINARY 16..18, SHIFT 32..37 and the
//!     raw MUL/DIV 49..61), so no other family's fact can satisfy this tuple.
//!  2. Each AND membership authenticates a_i, b_i in [0,255] and T_i = a_i & b_i
//!     (the table has exactly 2^16 rows). Hence A_k = a_2k + 256 a_2k+1 and B_k
//!     are canonical u16 limbs that recompose the bus A and B, and no field
//!     wrap is possible: every byte expression below lies in [0,255] and every
//!     limb in [0,65535], far below p = 2^31 - 1.
//!  3. Per byte, with T = a & b:  a & ~b = a - T;  a | ~b = 255 - b + T;
//!     ~(a ^ b) = 255 - (a + b - 2T). These are the integer identities of the
//!     bitwise ops on bytes, so C = andn/orn/xnor(A, B) exactly.
//!  4. rev8: c_i = a_{7-i}, a permutation of authenticated bytes; B is ignored
//!     (the CPU ROM pins it to the immediate 0).
//!  5. sext.b: the chip REQUIRES B = 0x80 (constraint s_sb * (B_k - [128,0,0,0]_k)).
//!     Then T_0 = a_0 & 0x80 is 0 or 128, sign = T_0 / 128 is a bit equal to
//!     A bit 7, c_0 = a_0 and c_i = 255 sign for i >= 1, i.e. sext.b(A).
//!     sext.h: B = 0x8000 is required, sign = T_1 / 128 is A bit 15, c_0 = a_0,
//!     c_1 = a_1, c_i = 255 sign for i >= 2.
//!  6. Inactive rows force every byte column to zero, so padding emits the
//!     (0,0,0) AND request (admitted in the AND mass like BINARY padding).
const E = @import("../evaluation.zig");
const std = @import("std");
pub const PAYLOAD = 13;
pub const OPS = 6;
/// Global FUNCTION ids: andn 19, orn 20, xnor 21, rev8 22, sext.b 23, sext.h 24.
pub const FIRST_ID = 19;
pub const Op = enum(u8) { andn = 0, orn = 1, xnor = 2, rev8 = 3, sext_b = 4, sext_h = 5 };
pub fn busId(op: Op) u8 {
    return FIRST_ID + @intFromEnum(op);
}
pub const LOCAL_MAIN = 1 + OPS + 24; // active, selectors, a/b/ab bytes; payload derived.
pub const columns = struct {
    pub const active = 0;
    pub const selectors = 1;
    pub const a = 1 + OPS;
    pub const b = a + 8;
    pub const ab = b + 8;
    pub const multiplicity = LOCAL_MAIN;
};
pub const SELECTOR_CONSTRAINTS = OPS + 2;
pub const PIN_CONSTRAINTS = 8; // B pinned for sext.b / sext.h (4 limbs each).
pub const PADDING_CONSTRAINTS = 24;
pub const CONSTRAINTS = SELECTOR_CONSTRAINTS + PAYLOAD + PIN_CONSTRAINTS + PADDING_CONSTRAINTS;
pub const PROJECTED_CONSTRAINTS = CONSTRAINTS - PAYLOAD;
pub const AND_REQUESTS = 8;
/// 255 * 128^-1 mod (2^31 - 1): maps T in {0, 128} to a sign fill byte {0, 255}.
pub const SIGN_FILL: u32 = 2130706433;
comptime {
    std.debug.assert((@as(u64, SIGN_FILL) * 128) % 2147483647 == 255);
}

pub fn RowFor(comptime F: type) type {
    return struct {
        payload: [PAYLOAD]F, // op, A[4], B[4], C[4], little-endian u16 limbs.
        active: F,
        selectors: [OPS]F,
        a: [8]F,
        b: [8]F,
        ab: [8]F,
    };
}

/// Output byte i of op k, affine in (a, b, T). Shared by constraints and witness.
fn byteFor(comptime F: type, row: *const RowFor(F), op: Op, i: usize) F {
    const c255 = E.qFor(F, 255);
    // 255 / 128 in M31: 128^-1 = 2^24 since 2^31 = 1 (mod 2^31 - 1).
    const fill = E.qFor(F, SIGN_FILL);
    return switch (op) {
        .andn => row.a[i].sub(row.ab[i]),
        .orn => c255.sub(row.b[i]).add(row.ab[i]),
        .xnor => c255.sub(row.a[i].add(row.b[i]).sub(row.ab[i].mul(E.qFor(F, 2)))),
        .rev8 => row.a[7 - i],
        .sext_b => if (i == 0) row.a[0] else row.ab[0].mul(fill),
        .sext_h => if (i < 2) row.a[i] else row.ab[1].mul(fill),
    };
}

pub fn derivePayloadFor(comptime F: type, row: *RowFor(F)) void {
    const radix = E.qFor(F, 256);
    var op = row.active.mul(E.qFor(F, FIRST_ID));
    for (row.selectors, 0..) |s, k| op = op.add(s.mul(E.qFor(F, @intCast(k))));
    row.payload[0] = op;
    for (0..4) |limb| {
        row.payload[1 + limb] = row.a[2 * limb].add(row.a[2 * limb + 1].mul(radix));
        row.payload[5 + limb] = row.b[2 * limb].add(row.b[2 * limb + 1].mul(radix));
        var expected = F.zero();
        inline for (std.meta.fields(Op)) |field| {
            const k: Op = @enumFromInt(field.value);
            const lo = byteFor(F, row, k, 2 * limb);
            const hi = byteFor(F, row, k, 2 * limb + 1);
            expected = expected.add(row.selectors[field.value].mul(lo.add(hi.mul(radix))));
        }
        row.payload[9 + limb] = expected;
    }
}

fn emitSelectorsFor(comptime F: type, row: *const RowFor(F), sink: anytype) void {
    const one = F.one();
    var selected = F.zero();
    for (row.selectors) |s| {
        sink.emit(s.mul(s.sub(one)));
        selected = selected.add(s);
    }
    sink.emit(selected.sub(row.active));
    sink.emit(row.active.mul(row.active.sub(one)));
}
fn emitPinsFor(comptime F: type, row: *const RowFor(F), sink: anytype) void {
    var r = row.*;
    derivePayloadFor(F, &r);
    const pins = [2][4]u32{ .{ 0x80, 0, 0, 0 }, .{ 0x8000, 0, 0, 0 } };
    for ([_]Op{ .sext_b, .sext_h }, pins) |op, pin| for (0..4) |limb| {
        sink.emit(row.selectors[@intFromEnum(op)].mul(r.payload[5 + limb].sub(E.qFor(F, pin[limb]))));
    };
}
fn emitPaddingFor(comptime F: type, row: *const RowFor(F), sink: anytype) void {
    const inactive = F.one().sub(row.active);
    for (row.a) |value| sink.emit(inactive.mul(value));
    for (row.b) |value| sink.emit(inactive.mul(value));
    for (row.ab) |value| sink.emit(inactive.mul(value));
}

/// Logical authority including the payload equalities (diagnostics/tests).
pub fn emitFor(comptime F: type, row: *const RowFor(F), sink: anytype) void {
    emitSelectorsFor(F, row, sink);
    var derived = row.*;
    derivePayloadFor(F, &derived);
    for (0..PAYLOAD) |i| sink.emit(row.payload[i].sub(derived.payload[i]));
    emitPinsFor(F, row, sink);
    emitPaddingFor(F, row, sink);
}
/// Physical rows: payload is substituted, its residuals are identically zero.
pub fn emitProjectedFor(comptime F: type, row: *const RowFor(F), sink: anytype) void {
    emitSelectorsFor(F, row, sink);
    emitPinsFor(F, row, sink);
    emitPaddingFor(F, row, sink);
}
pub fn andTupleFor(comptime F: type, row: *const RowFor(F), index: usize) [3]F {
    return .{ row.a[index], row.b[index], row.ab[index] };
}

/// Reference semantics (RISC-V Bit-Manipulation v1.0.0), independent of the row.
pub fn result(op: Op, a: u64, b: u64) u64 {
    return switch (op) {
        .andn => a & ~b,
        .orn => a | ~b,
        .xnor => ~(a ^ b),
        .rev8 => @byteSwap(a),
        .sext_b => @bitCast(@as(i64, @as(i8, @bitCast(@as(u8, @truncate(a)))))),
        .sext_h => @bitCast(@as(i64, @as(i16, @bitCast(@as(u16, @truncate(a)))))),
    };
}
/// The B operand the CPU ROM supplies (register for binary ops, immediate otherwise).
pub fn canonicalB(op: Op, rs2: u64) u64 {
    return switch (op) {
        .andn, .orn, .xnor => rs2,
        .rev8 => 0,
        .sext_b => 0x80,
        .sext_h => 0x8000,
    };
}

/// Native witness helper, not an alternative constraint evaluator.
pub fn witness(op: Op, a: u64, b: u64) RowFor(E.Q) {
    const c = result(op, a, b);
    var row: RowFor(E.Q) = undefined;
    row.payload[0] = E.q(busId(op));
    row.active = E.Q.one();
    for (&row.selectors, 0..) |*s, i| s.* = E.q(@intFromBool(i == @intFromEnum(op)));
    for (0..4) |i| {
        const shift: u6 = @intCast(16 * i);
        row.payload[1 + i] = E.q(@as(u16, @truncate(a >> shift)));
        row.payload[5 + i] = E.q(@as(u16, @truncate(b >> shift)));
        row.payload[9 + i] = E.q(@as(u16, @truncate(c >> shift)));
    }
    for (0..8) |i| {
        const shift: u6 = @intCast(8 * i);
        row.a[i] = E.q(@as(u8, @truncate(a >> shift)));
        row.b[i] = E.q(@as(u8, @truncate(b >> shift)));
        row.ab[i] = E.q(@as(u8, @truncate((a & b) >> shift)));
    }
    return row;
}
