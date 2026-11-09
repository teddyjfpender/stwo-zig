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
const Term = struct { relation: usize, len: usize, tuple: [35]M, weight: M };
const Capture = struct {
    terms: [2048]Term = undefined,
    n: usize = 0,
    globals_only: bool = false,
    pub fn emit(self: *@This(), relation: usize, tuple: anytype, weight: M) void {
        if (self.globals_only and relation != Old.RAM and relation != Old.IO) return;
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

test "serialized permutation lanes preserve all IO and exact padding across byte alignments" {
    const Lane = @import("permutation_lane.zig");
    const Header = @import("permutation_header.zig");
    const a = std.testing.allocator;
    for ([2]bool{ false, true }) |fresh| for ([_]u64{ 0, 1, 7, 8, 135, 136, 137, 272 }) |len| for (0..8) |alignment| {
        var call = fixture(fresh, true);
        call.packet[1].value = 0x9000 + alignment;
        call.packet[2].value = len;
        const words = try a.alloc(T.State, call.words());
        defer a.free(words);
        for (words, 0..) |*word, i| word.* = .{ .value = 0xfedcba9876543210 ^ @as(u64, @intCast(i)), .epoch = 3, .tick = 10, .rights = 3 };
        try T.validateCall(call, words);
        const perms = try T.permutations(a, call, words);
        defer a.free(perms);
        var previous_header: [Header.MAIN]M = @splat(M.zero());
        var carries: Capture = .{};
        for (perms, 0..) |_, k| {
            const old = Source.permRow(call, words, @intCast(k), perms);
            const header = Header.row(&old);
            var header_roots: Roots = .{};
            Header.emitMain(M, &.{ M.fromCanonical(@intCast(k)), if (k == 0) M.one() else M.zero(), M.zero() }, &header, &previous_header, M.fromCanonical(@intCast(perms.len)), M.one(), &header_roots);
            try std.testing.expect(allZero(header_roots.values[0..header_roots.n]));
            previous_header = header;

            var reference: Capture = .{};
            Old.emitRawFor(M, .perm, &.{ M.fromCanonical(@intCast(k)), M.zero(), M.zero() }, &old, 17, &reference);
            var projected: Capture = .{};
            var previous: [19]M = undefined;
            for (0..25) |lane| {
                const row = try Lane.row(&old, 17 + @as(u32, @intCast(k)), @intCast(lane));
                var roots: Roots = .{};
                Lane.emitMain(M, &.{ M.fromCanonical(@intCast(lane)), M.fromCanonical(@intFromBool(lane < 17)), M.fromCanonical(@intFromBool(lane == 16)) }, &row, &roots);
                try std.testing.expect(allZero(roots.values[0..roots.n]));
                if (lane != 0) try std.testing.expectEqualDeep(previous, Lane.chain(M, &row, false));
                previous = Lane.chain(M, &row, true);
                Lane.emitRaw(M, &row, &projected);
            }
            try std.testing.expectEqual(@as(u32, 25), previous[6].v);
            try std.testing.expectEqual(@as(u32, 0), previous[7].v);
            try std.testing.expectEqual(@as(u32, 1) - old[L.perm.lastfin].v, previous[8].v);
            const Word = @import("message_word.zig");
            var word_facts: Capture = .{};
            for (0..18) |slot| {
                const word = try Word.row(&old, 17 + @as(u32, @intCast(k)), @intCast(slot));
                var roots: Roots = .{};
                Word.emitMain(M, &wordFixed(slot), &word, &roots);
                try std.testing.expect(allZero(roots.values[0..roots.n]));
                Word.emitRaw(M, &wordFixed(slot), &word, &word_facts);
            }
            for (word_facts.terms[0..word_facts.n]) |fact| if (fact.relation == Old.OWNER and fact.tuple[0].v == Word.TOKEN_CARRY) {
                carries.terms[carries.n] = fact;
                carries.n += 1;
            };
            const ram_expected = try selected(a, &reference, Old.RAM);
            defer a.free(ram_expected);
            const ram_actual = try selected(a, &word_facts, Old.RAM);
            defer a.free(ram_actual);
            try std.testing.expectEqualDeep(ram_expected, ram_actual);
            var joined: Capture = projected;
            for (word_facts.terms[0..word_facts.n]) |fact| {
                joined.terms[joined.n] = fact;
                joined.n += 1;
            }
            Header.emitRaw(M, M.fromCanonical(@intCast(k)), &header, M.fromCanonical(17), &joined);
            const residual = try ownerResidual(a, &joined);
            defer a.free(residual);
            var old_owner: Capture = .{};
            for (reference.terms[0..reference.n]) |fact| if (fact.relation == Old.OWNER) {
                old_owner.terms[old_owner.n] = fact;
                old_owner.n += 1;
            };
            const expected_owner = try ownerResidual(a, &old_owner);
            defer a.free(expected_owner);
            try std.testing.expectEqualDeep(expected_owner, residual);
            const window_provider = try units(a, &word_facts, Lane.TOKEN_WINDOW, false);
            defer a.free(window_provider);
            const window_consumer = try units(a, &projected, Lane.TOKEN_WINDOW, true);
            defer a.free(window_consumer);
            try std.testing.expectEqualDeep(window_provider, window_consumer);
            const expected = try selected(a, &reference, Old.IO);
            defer a.free(expected);
            const actual = try selected(a, &projected, Old.IO);
            defer a.free(actual);
            try std.testing.expectEqualDeep(expected, actual);
        }
        const carry_residual = try ownerResidualAll(a, &carries, false);
        defer a.free(carry_residual);
        try std.testing.expectEqual(@as(usize, 0), carry_residual.len);
        if (perms.len > 1) {
            var forged = carries;
            // Each independent forged tuple must leave physical local debt.
            var changed = false;
            for (forged.terms[0..forged.n]) |*term| if (!term.weight.isZero()) {
                term.tuple[9] = term.tuple[9].add(M.one());
                changed = true;
                break;
            };
            try std.testing.expect(changed);
            const debt = try ownerResidualAll(a, &forged, false);
            defer a.free(debt);
            try std.testing.expect(debt.len != 0);
        }
    };
}

fn units(a: std.mem.Allocator, cap: *const Capture, tag: u32, negative: bool) ![]Term {
    var list: std.ArrayList(Term) = .empty;
    errdefer list.deinit(a);
    for (cap.terms[0..cap.n]) |t| if (t.relation == Old.OWNER and t.tuple[0].v == tag) {
        const n = if (negative) t.weight.neg().v else t.weight.v;
        if (n > 2) return error.InvalidUnitFactWeight;
        var unit = t;
        unit.weight = M.one();
        for (0..n) |_| try list.append(a, unit);
    };
    std.mem.sort(Term, list.items, {}, less);
    return list.toOwnedSlice(a);
}

fn ownerResidual(a: std.mem.Allocator, cap: *const Capture) ![]Term {
    return ownerResidualAll(a, cap, true);
}
fn ownerResidualAll(a: std.mem.Allocator, cap: *const Capture, skip_carry: bool) ![]Term {
    const Word = @import("message_word.zig");
    var list: std.ArrayList(Term) = .empty;
    errdefer list.deinit(a);
    for (cap.terms[0..cap.n]) |t| if (t.relation == Old.OWNER and (!skip_carry or t.tuple[0].v != Word.TOKEN_CARRY) and !t.weight.isZero()) try list.append(a, t);
    std.mem.sort(Term, list.items, {}, less);
    var out: std.ArrayList(Term) = .empty;
    errdefer out.deinit(a);
    var i: usize = 0;
    while (i < list.items.len) {
        var t = list.items[i];
        var j = i + 1;
        while (j < list.items.len and std.meta.eql(t.tuple, list.items[j].tuple)) : (j += 1) t.weight = t.weight.add(list.items[j].weight);
        if (!t.weight.isZero()) try out.append(a, t);
        i = j;
    }
    list.deinit(a);
    return out.toOwnedSlice(a);
}

fn projectCall(call: T.Call, words: []const T.State, perms: []const [2][25]u64, first_id: u32, reference: *Capture, projected: *Capture) !void {
    const Lane = @import("permutation_lane.zig");
    const Word = @import("message_word.zig");
    const old = Source.callRow(call, first_id, perms[perms.len - 1][1]);
    Old.emitRawFor(M, .call, &.{ M.zero(), M.one(), M.zero() }, &old, first_id, reference);
    const desc = try D.row(call, words, first_id);
    D.emitRaw(M, &desc, projected);
    for (0..25) |lane| {
        const state = try S.row(call, first_id, perms[perms.len - 1][1], @intCast(lane));
        S.emitRaw(M, &state, projected);
    }
    for (perms, 0..) |_, k| {
        const perm = Source.permRow(call, words, @intCast(k), perms);
        Old.emitRawFor(M, .perm, &.{ M.fromCanonical(@intCast(k)), M.zero(), M.zero() }, &perm, first_id, reference);
        for (0..25) |lane| {
            const state = try Lane.row(&perm, first_id + @as(u32, @intCast(k)), @intCast(lane));
            Lane.emitRaw(M, &state, projected);
        }
        for (0..18) |slot| {
            const word = try Word.row(&perm, first_id + @as(u32, @intCast(k)), @intCast(slot));
            Word.emitRaw(M, &wordFixed(slot), &word, projected);
        }
    }
}
test "serialized sponge overlap rejection and adjacent reused-address global tuples match legacy" {
    const a = std.testing.allocator;
    for ([2]bool{ false, true }) |fresh| {
        const original = fixture(fresh, true);
        var overlap = original;
        overlap.packet[0].value = overlap.pointer;
        try std.testing.expectError(error.InvalidKeccakSpongePacket, T.validateCall(overlap, &.{}));
        try std.testing.expectError(error.InvalidKeccakSpongePacket, D.row(overlap, &.{}, 1));
        overlap = original;
        overlap.packet[1].value = overlap.packet[0].value;
        overlap.packet[2].value = 1;
        const word = [_]T.State{.{ .value = 7, .epoch = 3, .tick = 10, .rights = 3 }};
        try std.testing.expectError(error.InvalidKeccakSpongePacket, T.validateCall(overlap, &word));
        overlap = original;
        overlap.packet[1].value = overlap.pointer;
        overlap.packet[2].value = 1;
        try std.testing.expectError(error.InvalidKeccakSpongePacket, T.validateCall(overlap, &word));
        for ([2]bool{ false, true }) |same_clock| {
            var reference: Capture = .{ .globals_only = true };
            var projected: Capture = .{ .globals_only = true };
            var call = original;
            call.packet[2].value = 1;
            const perms = try T.permutations(a, call, &word);
            defer a.free(perms);
            try projectCall(call, &word, perms, 17, &reference, &projected);
            if (!same_clock) call.tick += 4;
            // Deliberate identical-before address reuse remains the SAME global
            // consistency debt as legacy, not a locally accepted RAM execution.
            try projectCall(call, &word, perms, 18, &reference, &projected);
            for ([_]usize{ Old.RAM, Old.IO }) |relation| {
                const expected = try selected(a, &reference, relation);
                defer a.free(expected);
                const actual = try selected(a, &projected, relation);
                defer a.free(actual);
                try std.testing.expectEqualDeep(expected, actual);
            }
        }
    }
}

test "serialized permutation word and header constraints stay degree3" {
    const Lane = @import("permutation_lane.zig");
    const Word = @import("message_word.zig");
    const Header = @import("permutation_header.zig");
    for (0..3) |kind| {
        var values: [5][128]M = undefined;
        var count: usize = 0;
        for (0..5) |t| {
            const x = M.fromCanonical(@intCast(t));
            var m: [128]M = undefined;
            var pm: [128]M = undefined;
            var fixed: [3]M = undefined;
            for (&m, &pm, 0..) |*v, *p, i| {
                v.* = M.fromCanonical(@intCast(31 * i + 7)).add(x.mul(M.fromCanonical(@intCast(11 * i + 3))));
                p.* = M.fromCanonical(@intCast(17 * i + 5)).add(x.mul(M.fromCanonical(@intCast(19 * i + 1))));
            }
            for (&fixed, 0..) |*v, i| v.* = M.fromCanonical(@intCast(13 * i + 11)).add(x.mul(M.fromCanonical(@intCast(17 * i + 2))));
            var roots: Roots = .{};
            switch (kind) {
                0 => Lane.emitMain(M, &fixed, m[0..Lane.MAIN], &roots),
                1 => Word.emitMain(M, &fixed, m[0..Word.MAIN], &roots),
                else => Header.emitMain(M, &fixed, m[0..Header.MAIN], pm[0..Header.MAIN], M.fromCanonical(17).add(x), M.one().add(x), &roots),
            }
            if (t == 0) count = roots.n else try std.testing.expectEqual(count, roots.n);
            @memcpy(values[t][0..count], roots.values[0..count]);
        }
        var n: usize = 5;
        for (0..4) |_| {
            for (0..n - 1) |i| for (0..count) |j| {
                values[i][j] = values[i + 1][j].sub(values[i][j]);
            };
            n -= 1;
        }
        try std.testing.expect(allZero(values[0][0..count]));
    }
}
test "serialized message and lane mutations break ranges padding or authenticated chains" {
    const Lane = @import("permutation_lane.zig");
    const Word = @import("message_word.zig");
    const a = std.testing.allocator;
    var call = fixture(false, true);
    call.packet[2].value = 137;
    const words = try a.alloc(T.State, call.words());
    defer a.free(words);
    for (words) |*w| w.* = .{ .value = 0x123456789abcdef0, .epoch = 3, .tick = 10, .rights = 3 };
    const perms = try T.permutations(a, call, words);
    defer a.free(perms);
    const old = Source.permRow(call, words, 0, perms);
    const word = try Word.row(&old, 17, 0);
    for ([_]usize{ Word.c.address + 3, Word.c.clock, Word.c.clock + 4, Word.c.read, Word.c.carry }) |col| {
        var forged = word;
        forged[col] = forged[col].add(M.one());
        var roots: Roots = .{};
        Word.emitMain(M, &wordFixed(0), &forged, &roots);
        try std.testing.expect(!allZero(roots.values[0..roots.n]));
    }
    var alias = word;
    alias[Word.c.value] = alias[Word.c.value].add(M.fromCanonical(256));
    alias[Word.c.value + 1] = alias[Word.c.value + 1].sub(M.one());
    var raw: Capture = .{};
    Word.emitRaw(M, &wordFixed(0), &alias, &raw);
    try std.testing.expect(!rangesValid(&raw));
    const lane = try Lane.row(&old, 17, 0);
    for ([_]usize{ Lane.c.msg, Lane.c.mask, Lane.c.lane, Lane.c.shift_value }) |col| {
        var forged = lane;
        forged[col] = forged[col].add(M.one());
        var roots: Roots = .{};
        Lane.emitMain(M, &.{ M.zero(), M.one(), M.zero() }, &forged, &roots);
        try std.testing.expect(!allZero(roots.values[0..roots.n]));
    }
    var shifted = lane;
    shifted[Lane.c.remaining] = shifted[Lane.c.remaining].add(M.one());
    shifted[Lane.c.next_remaining] = shifted[Lane.c.next_remaining].add(M.one());
    try std.testing.expect(!std.meta.eql(Lane.chain(M, &lane, false), Lane.chain(M, &shifted, false)));
}

fn wordFixed(slot: usize) [3]M {
    return .{ M.fromCanonical(@intCast(slot)), M.fromCanonical(@intFromBool(slot == 0)), M.fromCanonical(@intFromBool(slot == 17)) };
}

fn localCount(cap: *const Capture) usize {
    var n: usize = 0;
    for (cap.terms[0..cap.n]) |t| if (t.relation != Old.RAM and t.relation != Old.IO) {
        n += 1;
    };
    return n;
}
test "serialized sponge source query budgets match emitters" {
    const Lane = @import("permutation_lane.zig");
    const Word = @import("message_word.zig");
    const Header = @import("permutation_header.zig");
    const a = std.testing.allocator;
    const call = fixture(true, true);
    const perms = try T.permutations(a, call, &.{});
    defer a.free(perms);
    const old = Source.permRow(call, &.{}, 0, perms);
    var cap: Capture = .{};
    const header = Header.row(&old);
    Header.emitRaw(M, M.zero(), &header, M.one(), &cap);
    try std.testing.expectEqual(Header.LOCAL_QUERIES, localCount(&cap));
    cap = .{};
    const word = try Word.row(&old, 1, 0);
    Word.emitRaw(M, &wordFixed(0), &word, &cap);
    try std.testing.expectEqual(Word.LOCAL_QUERIES, localCount(&cap));
    cap = .{};
    const lane = try Lane.row(&old, 1, 0);
    Lane.emitRaw(M, &lane, &cap);
    try std.testing.expectEqual(Lane.LOCAL_QUERIES, localCount(&cap));
}
test "serialized sponge frontier is a unit whole OWNER19 to injective Wire35 adapter" {
    const F = @import("frontier.zig");
    const call = fixture(false, true);
    const row = try F.row(call.pointer, call.epoch, call.tick, call.epoch);
    const old = Source.callRow(call, 17, lastState());
    const expected = Old.ecallTuple(M, &old);
    try std.testing.expectEqualDeep(expected, F.owner(M, &row));
    try std.testing.expectEqualDeep(F.wireTuple(M, M.fromCanonical(call.epoch - 1), expected), F.fromDescriptor(M, &old));
    const wire = F.wireTuple(M, M.fromCanonical(call.epoch - 1), expected);
    try std.testing.expectEqual(@as(u32, F.WIRE_KIND), wire[0].v);
    try std.testing.expectEqual(@as(u32, call.epoch - 1), wire[1].v);
    try std.testing.expectEqualDeep(expected, wire[2..21].*);
    for (wire[21..]) |v| try std.testing.expect(v.isZero());
    for (0..19) |i| {
        var changed = expected;
        changed[i] = changed[i].add(M.one());
        try std.testing.expect(!std.meta.eql(wire, F.wireTuple(M, M.fromCanonical(call.epoch - 1), changed)));
    }
    try std.testing.expect(!std.meta.eql(wire, F.wireTuple(M, M.fromCanonical(call.epoch), expected)));
    var raw: Capture = .{};
    F.emitRaw(M, &row, M.fromCanonical(call.epoch - 1), &raw);
    try std.testing.expectEqual(@as(usize, 4), raw.n);
    try std.testing.expectEqual(Old.OWNER, raw.terms[0].relation);
    try std.testing.expectEqual(M.one().neg().v, raw.terms[0].weight.v);
    try std.testing.expectEqual(F.WIRE, raw.terms[3].relation);
    try std.testing.expectEqual(M.one().v, raw.terms[3].weight.v);
    var roots: Roots = .{};
    F.emitMain(M, &.{ M.zero(), M.one(), M.zero() }, &row, M.zero(), M.one(), M.one(), M.fromCanonical(call.epoch), M.fromCanonical(call.epoch - 1), &roots);
    try std.testing.expectEqual(F.MAIN_CONSTRAINTS, roots.n);
    try std.testing.expect(allZero(roots.values[0..roots.n]));
    var bad = row;
    bad[F.c.epoch] = bad[F.c.epoch].add(M.one());
    roots = .{};
    F.emitMain(M, &.{ M.zero(), M.one(), M.zero() }, &bad, M.zero(), M.one(), M.one(), M.fromCanonical(call.epoch), M.fromCanonical(call.epoch - 1), &roots);
    try std.testing.expect(!allZero(roots.values[0..roots.n]));
    try std.testing.expectError(error.SpongeFrontierRecord, F.row(call.pointer, call.epoch, call.tick, call.epoch + 1));
}

test "serialized sponge frontier Wire prefixes bind both directions and reject balanced lies" {
    const F = @import("frontier.zig");
    const O = core.fields.om31.OM31;
    const E = @import("../../../evaluation.zig");
    var channel = core.channel.poseidon2_m31.Om31ChannelV2.init();
    const Wire = @import("../../secp256k1/equations.zig").WireFor(O);
    const ch = Wire.draw(&channel);
    const native = try F.row(0x123456789abc0000, 3, 65936, 3);
    var row: [F.MAIN]O = undefined;
    for (native, &row) |v, *out| out.* = O.fromBase(v);
    const ordinal = O.fromBase(M.fromCanonical(2));
    const tuple = F.wireTuple(O, ordinal, F.owner(O, &row));
    const denominator = E.denominatorFor(O, ch.offset, &ch.coefficients, &tuple, true);
    const claim = try denominator.inv();
    var values: [1]O = undefined;
    var sink = E.SinkFor(O){ .values = &values };
    F.emitWireFor(false, O, &row, ordinal, O.one(), O.zero(), O.zero(), claim, ch, &sink);
    try std.testing.expect(values[0].isZero());
    sink = .{ .values = &values };
    F.emitWireFor(true, O, &row, ordinal, O.one(), O.zero(), O.zero(), claim.neg(), ch, &sink);
    try std.testing.expect(values[0].isZero());
    sink = .{ .values = &values };
    F.emitWireFor(false, O, &row, ordinal, O.one(), O.zero(), O.zero(), claim.add(O.one()), ch, &sink);
    try std.testing.expect(!values[0].isZero());
    sink = .{ .values = &values };
    F.emitWireFor(true, O, &row, ordinal, O.one(), O.zero(), O.zero(), claim.add(O.one()).neg(), ch, &sink);
    try std.testing.expect(!values[0].isZero());
    var alias = native;
    alias[F.c.low] = alias[F.c.low].add(M.fromCanonical(65536));
    alias[F.c.high] = alias[F.c.high].sub(M.one());
    try std.testing.expectEqualDeep(F.owner(M, &native), F.owner(M, &alias));
    var raw: Capture = .{};
    F.emitRaw(M, &alias, M.fromCanonical(19), &raw);
    try std.testing.expect(!rangesValid(&raw));
    try F.validatePublic(31, 5, 256, 255);
    try std.testing.expectError(error.SpongeFrontierGeometry, F.validatePublic(32, 5, 3, 0));
    try std.testing.expectError(error.SpongeFrontierGeometry, F.validatePublic(1, 5, 3, 256));
    try std.testing.expectError(error.SpongeFrontierGeometry, F.validatePublic(1, 5, 65536, 0));
    try std.testing.expectError(error.SpongeFrontierGeometry, F.validatePublic(1, 5, 3, 19));
}

test "serialized sponge detached source removes only the fixed full CPU retirement slot" {
    const call = fixture(false, true);
    const m = try D.row(call, &.{}, 1);
    var full: Capture = .{};
    var internal: Capture = .{};
    D.emitRaw(M, &m, &full);
    D.emitInternalRaw(M, &m, &internal);
    try std.testing.expectEqual(full.n - 1, internal.n);
    try std.testing.expectEqual(Old.OWNER, full.terms[0].relation);
    try std.testing.expectEqual(@as(usize, 19), full.terms[0].len);
    try std.testing.expectEqual(M.one().neg().v, full.terms[0].weight.v);
    const expected = Old.ecallTuple(M, &m);
    try std.testing.expectEqualDeep(expected, full.terms[0].tuple[0..19].*);
    try std.testing.expectEqual(@as(u32, @as(u16, @truncate(T.TAG))), expected[9].v);
    try std.testing.expectEqual(@as(u32, @as(u16, @truncate(T.TAG >> 16))), expected[10].v);
    try std.testing.expectEqualDeep(full.terms[1..full.n], internal.terms[0..internal.n]);
}
