const std = @import("std");
const Core = @import("stwo_core");
const Row = @import("row.zig");
const Authority = @import("authority.zig");
const Witness = @import("witness.zig");
const M = Core.fields.m31.M31;
const Q = Core.fields.qm31.QM31;
const O = Core.fields.om31.OM31;
const a = std.testing.allocator;
fn q(v: [4]u32) Q {
    var out: [4]M = undefined;
    for (&out, v) |*d, n| d.* = M.fromCanonical(n);
    return Q.fromM31Array(out);
}
fn zero(values: anytype) bool {
    for (values) |v| if (!v.isZero()) return false;
    return true;
}
const Fixture = struct {
    terms0: [2]Authority.Term = .{ .{ .weight = .{ 1, 2 }, .scalar = 3 }, .{ .weight = .{ 1, 2 }, .scalar = 4 } },
    terms2: [1]Authority.Term = .{.{ .weight = .{ 8, 9 }, .scalar = 4 }},
    values: [14]Q = @splat(Q.zero()),
    uses: [14]u32 = @splat(0),
    fn init() Fixture {
        var f = Fixture{};
        f.values[1] = q(.{ 2, 3, 5, 7 });
        f.values[2] = q(.{ 11, 13, 17, 19 });
        f.values[3] = Q.fromBase(M.fromCanonical(3));
        f.values[4] = Q.fromBase(M.fromCanonical(5));
        const w = O{ .c0 = f.values[1], .c1 = f.values[2] };
        const first = w.mulM31(M.fromCanonical(8));
        f.values[8] = first.c0;
        f.values[9] = first.c1;
        const last = first.mulM31(M.fromCanonical(5));
        f.values[12] = last.c0;
        f.values[13] = last.c1;
        f.uses[8] = 1;
        f.uses[9] = 1;
        f.uses[12] = 1;
        f.uses[13] = 1;
        return f;
    }
    fn calls(f: *const Fixture) [3]Authority.Call {
        return .{ .{ .terms = &f.terms0, .outputs = .{ 8, 9 } }, .{ .terms = &.{}, .outputs = .{ 10, 11 } }, .{ .terms = &f.terms2, .outputs = .{ 12, 13 } } };
    }
};
test "OP native dot isolated authority inclusive sums resets empty call and output mutations" {
    var f = Fixture.init();
    var source = try Authority.Source.compile(a, &f.calls(), &f.uses);
    defer source.deinit();
    try std.testing.expectEqual(@as(usize, 4), source.raw_rows);
    try std.testing.expectEqual(@as(usize, 3), source.logical_terms);
    const rows = try Witness.main(a, &source, &f.values);
    defer a.free(rows);
    var previous: [8]M = @splat(M.zero());
    for (rows, source.fixed) |row, fixed| {
        try std.testing.expect(zero(&Row.arithmeticFor(M, &row, &previous, &fixed)));
        previous = row[Row.ACC..][0..8].*;
    }
    // The zero dot has explicit first/last row and two fresh zero outputs.
    try std.testing.expect(source.fixed[2][Row.FIRST].eql(M.one()));
    try std.testing.expect(source.fixed[2][Row.LAST].eql(M.one()));
    try std.testing.expect(zero(rows[2][Row.ACC..][0..8]));
    var no_reset = source.fixed[2];
    no_reset[Row.FIRST] = M.zero();
    try std.testing.expect(!zero(&Row.arithmeticFor(M, &rows[2], rows[1][Row.ACC..][0..8], &no_reset)));
    for (0..8) |i| {
        var corrupt = rows[1];
        corrupt[Row.ACC + i] = corrupt[Row.ACC + i].add(M.one());
        try std.testing.expect(!zero(&Row.arithmeticFor(M, &corrupt, rows[0][Row.ACC..][0..8], &source.fixed[1])));
    }
    f.values[3] = q(.{ 3, 1, 0, 0 });
    try std.testing.expectError(error.NativeDotScalarNotBase, Witness.main(a, &source, &f.values));
    f.values[3] = Q.fromBase(M.fromCanonical(3));
    f.values[12] = f.values[12].add(Q.one());
    try std.testing.expectError(error.NativeDotOutputMismatch, Witness.main(a, &source, &f.values));
    f.values[12] = f.values[12].sub(Q.one());
    f.values[0] = Q.one();
    try std.testing.expectError(error.NativeDotZeroAuthority, Witness.main(a, &source, &f.values));
}

test "OP native dot isolated source authority rejects cycles alias producers fanout and pins complete ports" {
    var f = Fixture.init();
    var source = try Authority.Source.compile(a, &f.calls(), &f.uses);
    defer source.deinit();
    f.uses[12] += 1;
    var changed = try Authority.Source.compile(a, &f.calls(), &f.uses);
    defer changed.deinit();
    try std.testing.expect(!std.mem.eql(u8, &source.identity, &changed.identity));
    f.uses[12] -= 1;
    var bad_calls = f.calls();
    bad_calls[2].outputs = .{ 8, 9 };
    try std.testing.expectError(error.DuplicateNativeDotProducer, Authority.Source.compile(a, &bad_calls, &f.uses));
    const cyclic = [_]Authority.Term{.{ .weight = .{ 12, 1 }, .scalar = 3 }};
    bad_calls = f.calls();
    bad_calls[0].terms = &cyclic;
    try std.testing.expectError(error.CyclicNativeDotSource, Authority.Source.compile(a, &bad_calls, &f.uses));
    f.uses[12] = Core.fields.m31.Modulus;
    try std.testing.expectError(error.NativeDotCharacteristic, Authority.Source.compile(a, &f.calls(), &f.uses));
    f.uses[12] = 1;
    const rows = try Witness.main(a, &source, &f.values);
    defer a.free(rows);
    const input = Row.portsFor(M, &rows[0], &source.fixed[0]);
    for (0..8) |i| try std.testing.expectEqual(rows[0][i].v, input[i / 4].tuple[2 + i % 4].v);
    try std.testing.expectEqual(M.fromCanonical(3).v, input[2].tuple[2].v);
    try std.testing.expect(zero(input[2].tuple[3..6]));
    const output = Row.portsFor(M, &rows[1], &source.fixed[1]);
    for (0..8) |i| try std.testing.expectEqual(rows[1][Row.ACC + i].v, output[3 + i / 4].tuple[2 + i % 4].v);
    try std.testing.expect(output[3].numerator.eql(M.one().neg()));
    try std.testing.expect(Row.portsFor(M, &rows[0], &source.fixed[0])[3].numerator.isZero());
}

test "OP native dot isolated arithmetic and five fraction pairing stay degree three" {
    var samples: [5][Row.ROOTS]M = undefined;
    for (&samples, 0..) |*roots, t| {
        const x = M.fromCanonical(@intCast(t));
        var main: [Row.MAIN]M = undefined;
        var fixed: [Row.FIXED]M = undefined;
        var previous: [8]M = undefined;
        var current: [3]M = undefined;
        for (&main, 0..) |*v, i| v.* = M.fromCanonical(@intCast(i * 23 + 7)).add(x.mul(M.fromCanonical(@intCast(i * 7 + 2))));
        for (&fixed, 0..) |*v, i| v.* = M.fromCanonical(@intCast(i * 17 + 3)).add(x.mul(M.fromCanonical(@intCast(i * 11 + 1))));
        for (&previous, 0..) |*v, i| v.* = M.fromCanonical(@intCast(i * 13 + 5)).add(x.mul(M.fromCanonical(@intCast(i * 2 + 1))));
        for (&current, 0..) |*v, i| v.* = M.fromCanonical(@intCast(i * 37 + 11)).add(x.mul(M.fromCanonical(@intCast(i * 3 + 7))));
        roots.* = Row.rootsFor(M, &main, &previous, &fixed, &current, x.add(M.fromCanonical(41)), M.fromCanonical(991), .{ M.one(), M.fromCanonical(3), M.fromCanonical(7), M.fromCanonical(11), M.fromCanonical(13), M.fromCanonical(17) }, M.fromCanonical(47));
    }
    var n: usize = samples.len;
    for (0..4) |_| {
        for (0..n - 1) |i| for (0..Row.ROOTS) |j| {
            samples[i][j] = samples[i + 1][j].sub(samples[i][j]);
        };
        n -= 1;
    }
    try std.testing.expect(zero(&samples[0]));
}

const Bag = std.AutoHashMap([6]u32, i64);
fn addPort(multiset: *Bag, tuple: [6]M, count: i64) !void {
    if (count == 0) return;
    var key: [6]u32 = undefined;
    for (&key, tuple) |*v, x| v.* = x.v;
    const slot = try multiset.getOrPut(key);
    if (!slot.found_existing) slot.value_ptr.* = 0;
    slot.value_ptr.* += count;
}
fn signed(value: M) i64 {
    return if (value.v > Core.fields.m31.Modulus / 2) @as(i64, value.v) - Core.fields.m31.Modulus else value.v;
}
fn bag(source: *const Authority.Source, rows: []const [Row.MAIN]M) !Bag {
    var out = Bag.init(a);
    errdefer out.deinit();
    for (rows, source.fixed) |r, f| for (Row.portsFor(M, &r, &f)) |port| try addPort(&out, port.tuple, signed(port.numerator));
    return out;
}
fn sameBag(x: *Bag, y: *Bag) bool {
    var it = x.iterator();
    while (it.next()) |entry| if ((y.get(entry.key_ptr.*) orelse 0) != entry.value_ptr.*) return false;
    it = y.iterator();
    while (it.next()) |entry| if ((x.get(entry.key_ptr.*) orelse 0) != entry.value_ptr.*) return false;
    return true;
}
fn expectedBag(values: []const Q) !Bag {
    var out = Bag.init(a);
    errdefer out.deinit();
    const ids = [_]u32{ 0, 1, 2, 3, 4, 12, 13 };
    const counts = [_]i64{ 3, 2, 2, 1, 2, -1, -1 };
    for (ids, counts) |id, count| {
        const coords = values[id].toM31Array();
        try addPort(&out, .{ M.fromCanonical(@import("stwo_circuit_frontend").common.component_list.GATE_RELATION_ID), M.fromCanonical(id), coords[0], coords[1], coords[2], coords[3] }, count);
    }
    return out;
}
test "OP native dot isolated full Var multiset closes internal sums and rejects hidden scalar coordinates" {
    var f = Fixture.init();
    var source = try Authority.Source.compile(a, &f.calls(), &f.uses);
    defer source.deinit();
    const rows = try Witness.main(a, &source, &f.values);
    defer a.free(rows);
    var actual = try bag(&source, rows);
    defer actual.deinit();
    var expected = try expectedBag(&f.values);
    defer expected.deinit();
    try std.testing.expect(sameBag(&actual, &expected));
    for (1..4) |i| {
        var scalar = f.values[3].toM31Array();
        scalar[i] = M.one();
        f.values[3] = Q.fromM31Array(scalar);
        var hidden = try expectedBag(&f.values);
        defer hidden.deinit();
        try std.testing.expect(!sameBag(&actual, &hidden));
        f.values[3] = Q.fromBase(M.fromCanonical(3));
    }
    rows[0][6] = rows[0][6].add(M.one());
    var changed = try bag(&source, rows);
    defer changed.deinit();
    try std.testing.expect(!sameBag(&changed, &expected));
}
fn frac(port: Row.PortFor(M), z: O, powers: [6]O) !O {
    var d = z.neg();
    for (port.tuple, powers) |v, p| d = d.add(p.mulM31(v));
    return O.fromBase(port.numerator).mul(try d.inv());
}
test "OP native dot isolated paired prefix witness closes cyclic sum and rejects interaction mutation" {
    var f = Fixture.init();
    var source = try Authority.Source.compile(a, &f.calls(), &f.uses);
    defer source.deinit();
    const rows = try Witness.main(a, &source, &f.values);
    defer a.free(rows);
    const prefix = try a.alloc([3]O, rows.len);
    defer a.free(prefix);
    const z = O.fromBase(M.fromCanonical(991));
    const powers = [6]O{ O.one(), O.fromBase(M.fromCanonical(3)), O.fromBase(M.fromCanonical(7)), O.fromBase(M.fromCanonical(11)), O.fromBase(M.fromCanonical(13)), O.fromBase(M.fromCanonical(17)) };
    var claim = O.zero();
    for (rows, source.fixed) |r, fixed| for (Row.portsFor(M, &r, &fixed)) |port| {
        claim = claim.add(try frac(port, z, powers));
    };
    const shift = claim.mulM31(try M.fromCanonical(@intCast(rows.len)).inv());
    var previous = O.zero();
    for (rows, source.fixed, prefix) |r, fixed, *dst| {
        const ports = Row.portsFor(M, &r, &fixed);
        var local = O.zero();
        for (0..3) |i| {
            local = local.add(try frac(ports[2 * i], z, powers)).add(try frac(ports[2 * i + 1], z, powers));
            dst[i] = if (i == 2) previous.add(local).sub(shift) else local;
        }
        previous = dst[2];
    }
    try std.testing.expect(previous.isZero());
    for (rows, source.fixed, 0..) |r, fixed, i| {
        var lifted: [Row.MAIN]O = undefined;
        var lf: [Row.FIXED]O = undefined;
        var pm: [8]O = undefined;
        for (&lifted, r) |*d, v| d.* = O.fromBase(v);
        for (&lf, fixed) |*d, v| d.* = O.fromBase(v);
        const prior = (i + rows.len - 1) % rows.len;
        for (&pm, rows[prior][Row.ACC..][0..8]) |*d, v| d.* = O.fromBase(v);
        try std.testing.expect(zero(&Row.rootsFor(O, &lifted, &pm, &lf, &prefix[i], prefix[prior][2], z, powers, shift)));
        if (i == 0) {
            var bad = prefix[i];
            bad[0] = bad[0].add(O.one());
            try std.testing.expect(!zero(&Row.rootsFor(O, &lifted, &pm, &lf, &bad, prefix[prior][2], z, powers, shift)));
        }
    }
}

test {
    _ = @import("cost.zig");
}
