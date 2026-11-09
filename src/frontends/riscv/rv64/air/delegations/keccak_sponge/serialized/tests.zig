//! Closed source gates; no permutation, execution or proof acceptance claim.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const S = @import("state_word.zig");
const D = @import("descriptor.zig");
const T = @import("../types.zig");
const Old = @import("../equations.zig");
const Source = @import("../source.zig");
const L = @import("../layout.zig");
const Term = struct { relation: usize, len: usize, tuple: [19]M, weight: M };
const Capture = struct {
    terms: [2048]Term = undefined,
    n: usize = 0,
    pub fn emit(self: *@This(), relation: usize, tuple: anytype, weight: M) void {
        var t = Term{ .relation = relation, .len = tuple.len, .tuple = @splat(M.zero()), .weight = weight };
        @memcpy(t.tuple[0..tuple.len], &tuple);
        self.terms[self.n] = t;
        self.n += 1;
    }
};
fn less(_: void, a: Term, b: Term) bool {
    if (a.relation != b.relation) return a.relation < b.relation;
    if (a.len != b.len) return a.len < b.len;
    for (a.tuple, b.tuple) |x, y| {
        if (x.v != y.v) return x.v < y.v;
    }
    return a.weight.v < b.weight.v;
}
fn selected(a: std.mem.Allocator, cap: *const Capture, relation: usize) ![]Term {
    var list: std.ArrayList(Term) = .empty;
    errdefer list.deinit(a);
    for (cap.terms[0..cap.n]) |t| if (t.relation == relation) try list.append(a, t);
    std.mem.sort(Term, list.items, {}, less);
    return list.toOwnedSlice(a);
}
const Roots = struct {
    values: [128]M = undefined,
    n: usize = 0,
    pub fn emit(self: *@This(), x: M) void {
        self.values[self.n] = x;
        self.n += 1;
    }
};
fn allZero(values: []const M) bool {
    for (values) |v| if (!v.isZero()) return false;
    return true;
}
fn fixture(fresh: bool, same: bool) T.Call {
    var call: T.Call = .{ .pointer = 0x4000, .epoch = 3, .tick = 400, .packet = undefined, .state = undefined };
    const values = [4]u64{ 0x12345678fff8, 0x9000, 0, T.Native.FINALIZE | if (fresh) T.Native.FRESH else 0 };
    for (&call.packet, values) |*s, v| s.* = .{ .value = v, .epoch = if (same) 3 else 2, .tick = 10, .rights = 3 };
    for (&call.state, 0..) |*s, i| s.* = .{ .value = 0xfedcba9876543210 + @as(u64, @intCast(i)), .epoch = if (same) 3 else 2, .tick = 10, .rights = 3 };
    return call;
}
fn lastState() [25]u64 {
    var out: [25]u64 = undefined;
    for (&out, 0..) |*x, i| x.* = 0x0123456789abcdef ^ @as(u64, @intCast(i));
    return out;
}
test "serialized sponge descriptor and state rows preserve every complete global tuple" {
    const a = std.testing.allocator;
    for ([2]bool{ false, true }) |fresh| for ([2]bool{ false, true }) |same| {
        const call = fixture(fresh, same);
        try T.validateCall(call, &.{});
        const output = lastState();
        const old = Source.callRow(call, 17, output);
        const desc = try D.row(call, &.{}, 17);
        var reference: Capture = .{};
        Old.emitRawFor(M, .call, &.{ M.zero(), M.one(), M.zero() }, &old, 17, &reference);
        var projected: Capture = .{};
        D.emitRaw(M, &desc, &projected);
        var provider: Capture = .{};
        D.emitStateTokens(M, &desc, &provider);
        var consumers: Capture = .{};
        for (0..25) |lane| {
            const row = try S.row(call, 17, output, @intCast(lane));
            var roots: Roots = .{};
            S.emitMain(M, &.{ M.fromCanonical(@intCast(lane)), if (lane == 0) M.one() else M.zero(), M.zero() }, &row, if (lane == 0) M.zero() else M.one(), M.fromCanonical(25), M.one(), &roots);
            try std.testing.expectEqual(S.CONSTRAINTS, roots.n);
            try std.testing.expect(allZero(roots.values[0..roots.n]));
            S.emitRaw(M, &row, &projected);
            consumers.emit(Old.OWNER, S.token(M, &row), M.one());
        }
        for ([2]usize{ Old.RAM, Old.IO }) |relation| {
            const expected = try selected(a, &reference, relation);
            defer a.free(expected);
            const actual = try selected(a, &projected, relation);
            defer a.free(actual);
            try std.testing.expectEqualDeep(expected, actual);
        }
        const p = try selected(a, &provider, Old.OWNER);
        defer a.free(p);
        const r = try selected(a, &consumers, Old.OWNER);
        defer a.free(r);
        try std.testing.expectEqualDeep(p, r);
        var descRoots: Roots = .{};
        D.emitMain(M, &.{ M.zero(), M.one(), M.zero() }, &desc, M.zero(), M.one(), M.one(), &descRoots);
        try std.testing.expectEqual(D.CONSTRAINTS, descRoots.n);
        try std.testing.expect(allZero(descRoots.values[0..descRoots.n]));
    };
}
test "serialized sponge state binds upper words metadata and strict predecessors" {
    const call = fixture(false, true);
    var row = try S.row(call, 17, lastState(), 24);
    const token = S.token(M, &row);
    var forged = row;
    forged[S.c.state + 3] = forged[S.c.state + 3].add(M.one());
    forged[S.c.address + 3] = forged[S.c.address + 3].add(M.one());
    try std.testing.expect(!std.meta.eql(token, S.token(M, &forged)));
    for ([_]usize{ S.c.carry, S.c.address, S.c.clock, S.c.clock + 1, S.c.clock + 4, S.c.fresh }) |col| {
        forged = row;
        forged[col] = forged[col].add(M.one());
        var roots: Roots = .{};
        S.emitMain(M, &.{ M.one(), M.zero(), M.zero() }, &forged, M.one(), M.fromCanonical(25), M.one(), &roots);
        // Changing fresh preserves an otherwise legal Boolean but changes the
        // authenticated metadata token; other mutations break address/clock AIR.
        if (col == S.c.fresh) try std.testing.expect(!std.meta.eql(token, S.token(M, &forged))) else try std.testing.expect(!allZero(roots.values[0..roots.n]));
    }
    var terms: Capture = .{};
    S.emitRaw(M, &row, &terms);
    const before = terms.terms[1];
    const link = terms.terms[3];
    row[S.c.old + 7] = row[S.c.old + 7].add(M.one());
    var changed: Capture = .{};
    S.emitRaw(M, &row, &changed);
    try std.testing.expect(!std.meta.eql(before, changed.terms[1]));
    try std.testing.expect(!std.meta.eql(link, changed.terms[3]));
    var invalid = call;
    invalid.state[0].tick = call.tick;
    try std.testing.expectError(error.InvalidSerializedStatePredecessor, S.row(invalid, 17, lastState(), 0));
    try std.testing.expectError(error.InvalidSerializedStateRow, S.row(call, 17, lastState(), 25));
}
fn degree(comptime N: usize, comptime Main: usize, comptime emit: anytype) !void {
    var values: [5][N]M = undefined;
    for (&values, 0..) |*out, t| {
        const x = M.fromCanonical(@intCast(t));
        var m: [Main]M = undefined;
        var f: [3]M = undefined;
        for (&m, 0..) |*v, i| v.* = M.fromCanonical(@intCast(31 * i + 7)).add(x.mul(M.fromCanonical(@intCast(11 * i + 3))));
        for (&f, 0..) |*v, i| v.* = M.fromCanonical(@intCast(13 * i + 11)).add(x.mul(M.fromCanonical(@intCast(17 * i + 2))));
        var roots: Roots = .{};
        emit(M, &f, &m, M.fromCanonical(7).add(x), M.fromCanonical(17).add(x), M.one().add(x), &roots);
        try std.testing.expectEqual(N, roots.n);
        @memcpy(out, roots.values[0..N]);
    }
    var n: usize = 5;
    for (0..4) |_| {
        for (0..n - 1) |i| for (0..N) |j| {
            values[i][j] = values[i + 1][j].sub(values[i][j]);
        };
        n -= 1;
    }
    try std.testing.expect(allZero(&values[0]));
}
test "serialized sponge source constraints stay degree3 with arbitrary fixed columns" {
    try degree(S.CONSTRAINTS, S.MAIN, S.emitMain);
    try degree(D.CONSTRAINTS, D.MAIN, D.emitMain);
}

fn rangesValid(cap: *const Capture) bool {
    for (cap.terms[0..cap.n]) |t| {
        if (t.relation == Old.RANGE8 and t.tuple[0].v >= 256) return false;
        if (t.relation == Old.RANGE16 and t.tuple[0].v >= 65536) return false;
    }
    return true;
}
test "serialized sponge explicit ranges reject byte aliases and clock overflow" {
    const call = fixture(true, true);
    const row = try S.row(call, 17, lastState(), 0);
    var honest: Capture = .{};
    S.emitRaw(M, &row, &honest);
    try std.testing.expect(rangesValid(&honest));
    var alias = row;
    alias[S.c.old] = alias[S.c.old].add(M.fromCanonical(256));
    alias[S.c.old + 1] = alias[S.c.old + 1].sub(M.one());
    var changed: Capture = .{};
    S.emitRaw(M, &alias, &changed);
    // The same complete RAM word can have a non-byte decomposition; explicit
    // BYTE membership must reject it, even when fresh suppresses the old IO link.
    try std.testing.expectEqualDeep(honest.terms[1], changed.terms[1]);
    try std.testing.expect(!rangesValid(&changed));
    alias = row;
    alias[S.c.tick_high] = M.fromCanonical(256);
    changed = .{};
    S.emitRaw(M, &alias, &changed);
    try std.testing.expect(!rangesValid(&changed));
}
