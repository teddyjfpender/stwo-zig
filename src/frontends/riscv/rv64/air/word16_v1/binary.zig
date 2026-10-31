//! Concrete Word16 binary chip arithmetic. This is deliberately not an
//! accepting component by itself: each of its eight AND requests must close
//! against the fixed canonical byte-AND provider in the shared proof.
const E = @import("../evaluation.zig");
const operations = @import("operations.zig");
pub const PAYLOAD = 13;
pub const LOCAL_MAIN = 41; // payload13, active1, selectors3, byte auxiliaries24.
pub const CONSTRAINTS = 42;
pub const AND_REQUESTS = 8;

pub fn RowFor(comptime F: type) type {
    return struct {
        payload: [PAYLOAD]F, // op, A[4], B[4], C[4], little-endian u16 limbs.
        active: F,
        selectors: [3]F, // AND, OR, XOR.
        a: [8]F,
        b: [8]F,
        ab: [8]F,
    };
}

/// One authority for arbitrary secure OODS points and native packed lanes.
/// Integer soundness additionally requires all andTuple memberships. Their
/// three coordinates separately authenticate A/B/AND bytes, avoiding an
/// unbounded packed-byte alias. All reconstructed limbs are then <=65535;
/// the largest intermediate a+b is 131070, well below the M31 modulus.
pub fn emitFor(comptime F: type, row: *const RowFor(F), sink: anytype) void {
    const one = F.one();
    const two = E.qFor(F, 2);
    const radix = E.qFor(F, 256);
    var selected = F.zero();
    for (row.selectors) |s| {
        sink.emit(s.mul(s.sub(one)));
        selected = selected.add(s);
    }
    sink.emit(selected.sub(row.active));
    sink.emit(row.active.mul(row.active.sub(one)));
    sink.emit(row.payload[0].sub(row.active.mul(E.qFor(F, 16))).sub(row.selectors[1]).sub(row.selectors[2].mul(two)));
    for (0..4) |limb| {
        sink.emit(row.payload[1 + limb].sub(row.a[2 * limb]).sub(row.a[2 * limb + 1].mul(radix)));
        sink.emit(row.payload[5 + limb].sub(row.b[2 * limb]).sub(row.b[2 * limb + 1].mul(radix)));
    }
    for (0..4) |limb| {
        var expected = F.zero();
        for (0..2) |j| {
            const i = 2 * limb + j;
            const sum = row.a[i].add(row.b[i]);
            const byte = row.selectors[0].mul(row.ab[i])
                .add(row.selectors[1].mul(sum.sub(row.ab[i])))
                .add(row.selectors[2].mul(sum.sub(row.ab[i].mul(two))));
            expected = expected.add(if (j == 0) byte else byte.mul(radix));
        }
        sink.emit(row.payload[9 + limb].sub(expected));
    }
    // Unconditional padding requests are (0,0,0). Including them in the
    // admitted AND mass avoids an extra active factor in degree4 batching.
    const inactive = one.sub(row.active);
    for (row.a) |value| sink.emit(inactive.mul(value));
    for (row.b) |value| sink.emit(inactive.mul(value));
    for (row.ab) |value| sink.emit(inactive.mul(value));
}
pub fn andTupleFor(comptime F: type, row: *const RowFor(F), index: usize) [3]F {
    return .{ row.a[index], row.b[index], row.ab[index] };
}

/// Native witness helper, not an alternative constraint evaluator.
pub fn witness(op: operations.Binary, a: u64, b: u64) RowFor(E.Q) {
    const c = switch (op) {
        .and_ => a & b,
        .or_ => a | b,
        .xor => a ^ b,
    };
    var row: RowFor(E.Q) = undefined;
    row.payload[0] = E.q(operations.busIdFor(.binary, @intFromEnum(op)));
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
