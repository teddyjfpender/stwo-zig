//! Adversarial tests for the Zbb BINARY chip (binary_zbb.zig): honest rows
//! close; forged results, selectors, op ids, pinned operands and non-canonical
//! byte decompositions are rejected (by a row constraint or by the canonical
//! byte-AND table membership); every residual is degree <= 2.
const std = @import("std");
const E = @import("../evaluation.zig");
const Z = @import("binary_zbb.zig");
const B = @import("binary.zig");
const Ops = @import("operations.zig");
const Q = E.Q;
const t = std.testing;

const Sink = struct {
    values: [Z.CONSTRAINTS]Q = undefined,
    count: usize = 0,
    pub fn emit(self: *@This(), value: Q) void {
        self.values[self.count] = value;
        self.count += 1;
    }
};
fn residuals(row: *const Z.RowFor(Q)) Sink {
    var sink = Sink{};
    Z.emitFor(Q, row, &sink);
    return sink;
}
fn rowClean(row: *const Z.RowFor(Q)) bool {
    const sink = residuals(row);
    if (sink.count != Z.CONSTRAINTS) return false;
    for (sink.values) |v| if (!v.isZero()) return false;
    return true;
}
fn m31(v: Q) u32 {
    return v.toM31Array()[0].v;
}
/// Membership in the fixed canonical byte-AND table (x, y < 256, z = x & y).
fn inAndTable(tuple: [3]Q) bool {
    for (tuple) |c| {
        const arr = c.toM31Array();
        if (arr[1].v != 0 or arr[2].v != 0 or arr[3].v != 0) return false;
    }
    const x = m31(tuple[0]);
    const y = m31(tuple[1]);
    return x < 256 and y < 256 and m31(tuple[2]) == (x & y);
}
/// A row is accepted iff its constraints vanish and all 8 AND requests are table rows.
fn accepted(row: *const Z.RowFor(Q)) bool {
    if (!rowClean(row)) return false;
    for (0..8) |i| if (!inAndTable(Z.andTupleFor(Q, row, i))) return false;
    return true;
}
fn limbs(row: *const Z.RowFor(Q), at: usize) u64 {
    var v: u64 = 0;
    for (0..4) |i| v |= @as(u64, m31(row.payload[at + i])) << @intCast(16 * i);
    return v;
}

const WORDS = [_]u64{ 0, 1, 0x7f, 0x80, 0xff, 0x7fff, 0x8000, 0xffff, 0xffff_ffff, 0x8000_0000_0000_0000, ~@as(u64, 0), 0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210, 0x7fff_8000_ffff_0080 };

test "honest rows close for every op and the payload is the reference result" {
    var prng = std.Random.DefaultPrng.init(19);
    const r = prng.random();
    inline for (std.meta.fields(Z.Op)) |f| {
        const op: Z.Op = @enumFromInt(f.value);
        for (0..400) |i| {
            const a = if (i < WORDS.len) WORDS[i] else r.int(u64);
            const rs2 = if (i < WORDS.len) WORDS[WORDS.len - 1 - i] else r.int(u64);
            const b = Z.canonicalB(op, rs2);
            const row = Z.witness(op, a, b);
            try t.expect(accepted(&row));
            try t.expectEqual(@as(u32, Z.busId(op)), m31(row.payload[0]));
            try t.expectEqual(a, limbs(&row, 1));
            try t.expectEqual(b, limbs(&row, 5));
            try t.expectEqual(Z.result(op, a, b), limbs(&row, 9));
        }
    }
}

test "reference semantics agree with the executor's independent definitions" {
    const cisa = @import("../../candidate_isa.zig");
    const pairs = [_]struct { Z.Op, cisa.Op }{ .{ .andn, .andn }, .{ .orn, .orn }, .{ .xnor, .xnor }, .{ .rev8, .rev8 }, .{ .sext_b, .sext_b }, .{ .sext_h, .sext_h } };
    for (pairs) |p| for (WORDS) |a| for (WORDS) |b| {
        try t.expectEqual(cisa.execute(.{ .op = p[1], .rd = 1, .rs1 = 2, .rs2 = 3 }, a, b), Z.result(p[0], a, Z.canonicalB(p[0], b)));
    };
}

test "forged result limbs are rejected" {
    inline for (std.meta.fields(Z.Op)) |f| {
        const op: Z.Op = @enumFromInt(f.value);
        for (WORDS) |a| {
            const row = Z.witness(op, a, Z.canonicalB(op, 0x0f0f_f0f0_1234_8765));
            for (0..4) |limb| {
                var bad = row;
                bad.payload[9 + limb] = bad.payload[9 + limb].add(Q.one());
                try t.expect(!accepted(&bad));
            }
            // A result that is correct for a DIFFERENT op is still rejected.
            inline for (std.meta.fields(Z.Op)) |g| {
                const other: Z.Op = @enumFromInt(g.value);
                const want = Z.result(op, a, limbs(&row, 5));
                const forged = Z.result(other, a, limbs(&row, 5));
                if (forged != want) {
                    var bad = row;
                    for (0..4) |i| bad.payload[9 + i] = E.q(@as(u16, @truncate(forged >> @intCast(16 * i))));
                    try t.expect(!accepted(&bad));
                }
            }
        }
    }
}

test "wrong selector, double selection, non-boolean selector and foreign op id are rejected" {
    const a: u64 = 0x0123_4567_89ab_cdef;
    inline for (std.meta.fields(Z.Op)) |f| {
        const op: Z.Op = @enumFromInt(f.value);
        const row = Z.witness(op, a, Z.canonicalB(op, 0x00ff_00ff_f0f0_0f0f));
        for (0..Z.OPS) |k| if (k != f.value) {
            // Move the selector to another op, keeping the committed payload.
            var bad = row;
            bad.selectors[f.value] = Q.zero();
            bad.selectors[k] = Q.one();
            try t.expect(!accepted(&bad));
            // Two selectors.
            bad = row;
            bad.selectors[k] = Q.one();
            try t.expect(!accepted(&bad));
        };
        var bad = row;
        bad.selectors[f.value] = E.q(2);
        try t.expect(!accepted(&bad));
        // Claiming a BINARY (16..18), ALU or SHIFT id for a Zbb fact.
        for ([_]u8{ Ops.busIdFor(.binary, 0), Ops.busIdFor(.binary, 1), Ops.busIdFor(.binary, 2), Ops.busIdFor(.alu, 0), Ops.busIdFor(.shift, 0) }) |id| {
            bad = row;
            bad.payload[0] = E.q(id);
            try t.expect(!accepted(&bad));
        }
        // An inactive row cannot carry a fact.
        bad = row;
        bad.active = Q.zero();
        try t.expect(!accepted(&bad));
    }
    // Op ids are disjoint from every other Word16 family's global ids.
    for (std.enums.values(Z.Op)) |op| {
        const id = Z.busId(op);
        try t.expect(id >= 19 and id <= 24);
        for (0..10) |i| try t.expect(id != Ops.busIdFor(.alu, @intCast(i)));
        for (0..3) |i| try t.expect(id != Ops.busIdFor(.binary, @intCast(i)));
        for (0..6) |i| try t.expect(id != Ops.busIdFor(.shift, @intCast(i)));
        try t.expect(id != 10 and (id < 49 or id > 61));
    }
}

test "sext.b / sext.h require the pinned B immediate" {
    for ([_]Z.Op{ .sext_b, .sext_h }) |op| for ([_]u64{ 0x80, 0x8000, 0, 0x8080, 0xff, 0x1_0000_0080 }) |b| {
        const row = Z.witness(op, 0xffff_ffff_ffff_ff80, b);
        try t.expectEqual(b == Z.canonicalB(op, 0), accepted(&row));
    };
    // With B = 0x81 the AND would give T_0 = 128 | (a & 1): a forged "sign" fill
    // would not even be a byte. The pin rejects B before that matters.
    var row = Z.witness(.sext_b, 0x81, 0x81);
    try t.expect(!accepted(&row));
}

test "non-canonical byte decompositions with the same limb value are rejected by the AND table" {
    // a_0 = x + 256, a_1 = y - 1 recomposes the same A limb but is not a byte pair.
    inline for (std.meta.fields(Z.Op)) |f| {
        const op: Z.Op = @enumFromInt(f.value);
        const a: u64 = 0x0000_0000_0000_0234;
        const row = Z.witness(op, a, Z.canonicalB(op, 0x0102));
        var bad = row;
        bad.a[0] = bad.a[0].add(E.q(256));
        bad.a[1] = bad.a[1].sub(Q.one());
        try t.expectEqual(m31(row.payload[1]), m31(bad.a[0].add(bad.a[1].mul(E.q(256)))));
        var derived0 = bad;
        Z.derivePayloadFor(Q, &derived0);
        bad.payload = derived0.payload;
        try t.expect(rowClean(&bad)); // the row algebra alone cannot see it ...
        try t.expect(!accepted(&bad)); // ... the canonical AND table does.
        // Field-wrapped byte a_7 = p - 1: not a table row either.
        bad = row;
        bad.a[7] = Q.zero().sub(Q.one());
        derived0 = bad;
        Z.derivePayloadFor(Q, &derived0);
        bad.payload = derived0.payload;
        try t.expect(rowClean(&bad));
        try t.expect(!accepted(&bad));
        // Wrong AND witness T with a consistent payload: T is table-bound.
        bad = row;
        bad.ab[0] = bad.ab[0].add(Q.one());
        var derived = bad;
        Z.derivePayloadFor(Q, &derived);
        bad.payload = derived.payload;
        try t.expect(rowClean(&bad));
        try t.expect(!accepted(&bad));
    }
}

test "rev8 forged permutation is rejected" {
    const row = Z.witness(.rev8, 0x0102_0304_0506_0708, 0);
    var bad = row;
    // Claim the identity instead of the byte reversal.
    for (0..4) |i| bad.payload[9 + i] = row.payload[1 + i];
    try t.expect(!accepted(&bad));
}

test "padding rows close only when all byte columns are zero" {
    var pad = Z.witness(.andn, 0, 0);
    pad.active = Q.zero();
    pad.selectors = @splat(Q.zero());
    Z.derivePayloadFor(Q, &pad);
    try t.expect(accepted(&pad));
    for (pad.payload) |v| try t.expect(v.isZero());
    pad.b[3] = Q.one();
    try t.expect(!rowClean(&pad));
}

test "every residual is degree <= 2 in the committed columns" {
    // Along a random line row(x) = r0 + x r1 each residual is a polynomial in x;
    // degree <= 2 iff its third finite difference vanishes.
    var prng = std.Random.DefaultPrng.init(3);
    const r = prng.random();
    const Row = Z.RowFor(Q);
    var r0: Row = undefined;
    var r1: Row = undefined;
    inline for (std.meta.fields(Row)) |f| {
        if (@typeInfo(f.type) == .array) {
            for (&@field(r0, f.name), &@field(r1, f.name)) |*x, *y| {
                x.* = E.q(r.uintLessThan(u32, 1 << 30));
                y.* = E.q(r.uintLessThan(u32, 1 << 30));
            }
        } else {
            @field(r0, f.name) = E.q(r.uintLessThan(u32, 1 << 30));
            @field(r1, f.name) = E.q(r.uintLessThan(u32, 1 << 30));
        }
    }
    var vals: [4]Sink = undefined;
    for (0..4) |x| {
        var row: Row = undefined;
        inline for (std.meta.fields(Row)) |f| {
            if (@typeInfo(f.type) == .array) {
                for (&@field(row, f.name), @field(r0, f.name), @field(r1, f.name)) |*o, p, q| o.* = p.add(q.mul(E.q(@intCast(x))));
            } else @field(row, f.name) = @field(r0, f.name).add(@field(r1, f.name).mul(E.q(@intCast(x))));
        }
        vals[x] = residuals(&row);
    }
    for (0..Z.CONSTRAINTS) |c| {
        const d3 = vals[3].values[c].sub(vals[2].values[c].mul(E.q(3))).add(vals[1].values[c].mul(E.q(3))).sub(vals[0].values[c]);
        try t.expect(d3.isZero());
    }
}

test "the Zbb chip reuses the BINARY byte geometry and AND request shape" {
    try t.expectEqual(B.AND_REQUESTS, Z.AND_REQUESTS);
    try t.expectEqual(B.PAYLOAD, Z.PAYLOAD);
    try t.expectEqual(@as(usize, B.LOCAL_MAIN + 3), Z.LOCAL_MAIN);
}
