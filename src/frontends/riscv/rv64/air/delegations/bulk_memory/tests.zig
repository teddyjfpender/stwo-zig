//! Known-answer and adversarial tests for the bulk-memory AIR.
//!
//! A forged witness is accepted only if every local residual is zero, every
//! U16 lookup value lies in the table, RAM14 closes against the honest memory
//! chain endpoints (INIT/TERM of every touched word) and OWNER19 closes
//! against the honest CPU ECALL tuples. Each adversarial case names the check
//! that rejects it.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../../evaluation.zig");
const Decode = @import("../../../decode.zig");
const B = @import("mod.zig");
const T = B.types;
const L = B.layout;
const Eq = B.equations;
const Src = B.source;
const M = core.fields.m31.M31;
const Q = T.Q;
const testing = std.testing;

fn q(n: u32) Q {
    const h = n *% 0x9E3779B1;
    return Q.fromU32Unchecked((h % 0x7fff0000) + 1, ((h >> 3) % 0x7fff0000) + 3, ((h >> 7) % 0x7fff0000) + 7, ((h >> 11) % 0x7fff0000) + 11);
}
fn challenges() T.Challenges {
    var ch: T.Challenges = undefined;
    ch.ram.offset = q(1);
    for (&ch.ram.coefficients, 0..) |*c, i| c.* = q(@intCast(10 + i));
    ch.owner.offset = q(2);
    for (&ch.owner.coefficients, 0..) |*c, i| c.* = q(@intCast(40 + i));
    ch.range16 = .{ .offset = q(3), .coefficient = q(4) };
    return ch;
}

const RW: u2 = 3;
const RO: u2 = 1;
fn rightsAt(address: u64) u2 {
    return if (address >= 0x5000 and address < 0x6000) RO else if (address >= 0x7000 and address < 0x7100) RO else RW;
}

/// Honest chronological memory ledger producing calls, words and the
/// environment's RAM endpoint sum.
const World = struct {
    a: std.mem.Allocator,
    states: std.AutoHashMap(u64, T.State),
    initial: std.AutoHashMap(u64, T.State),
    calls: std.ArrayList(T.Call) = .{},
    words: std.ArrayList(T.Word) = .{},
    fn init(a: std.mem.Allocator) World {
        return .{ .a = a, .states = std.AutoHashMap(u64, T.State).init(a), .initial = std.AutoHashMap(u64, T.State).init(a) };
    }
    fn deinit(self: *World) void {
        self.states.deinit();
        self.initial.deinit();
        self.calls.deinit(self.a);
        self.words.deinit(self.a);
    }
    fn image(self: *World, address: u64, value: u64) !void {
        const s = T.State{ .value = value, .rights = rightsAt(address) };
        try self.states.put(address, s);
        try self.initial.put(address, s);
    }
    fn get(self: *World, address: u64) !T.State {
        if (self.states.get(address)) |s| return s;
        try self.image(address, address *% 0x9E3779B97F4A7C15);
        return self.states.get(address).?;
    }
    fn call(self: *World, op: T.Op, pointer: u64, epoch: u16, tick: u24, dst: u64, word1: u64, len: u64) !void {
        const pw: usize = if (op == .cmp) 4 else 3;
        for ([_]u64{ dst, word1, len, 0x5EED }, 0..) |v, k| if (k < pw and !self.states.contains(pointer + 8 * k)) try self.image(pointer + 8 * k, v);
        var c = T.Call{ .op = op, .pointer = pointer, .epoch = epoch, .tick = tick, .dst = dst, .word1 = word1, .len = len, .packet = @splat(.{ .value = 0, .rights = 0 }) };
        for (0..pw) |k| c.packet[k] = try self.get(pointer + 8 * k);
        var fresh: std.ArrayList(T.Word) = .{};
        defer fresh.deinit(self.a);
        const n = c.count();
        switch (op) {
            .set => for (0..n) |j| try fresh.append(self.a, .{ .dst = try self.get(dst + 8 * j) }),
            .copy => if (c.shift() == 0) {
                for (0..n) |j| try fresh.append(self.a, .{ .dst = try self.get(dst + 8 * j), .src = try self.get(word1 + 8 * j) });
            } else {
                const base = word1 & ~@as(u64, 7);
                for (0..n + 1) |r| try fresh.append(self.a, .{ .dst = if (r == 0) .{ .value = 0, .rights = 0 } else try self.get(dst + 8 * (r - 1)), .src = try self.get(base + 8 * r) });
            },
            .cmp => {
                var j: usize = 0;
                while (j < n) : (j += 1) {
                    const w = T.Word{ .dst = try self.get(dst + 8 * j), .src = try self.get(word1 + 8 * j) };
                    try fresh.append(self.a, w);
                    c.result = T.compareWords(w.dst.value, w.src.value);
                    if (c.result != 0) break;
                }
                c.examined = @intCast(fresh.items.len);
            },
        }
        // Every access of the call moves to the call's clock.
        for (0..pw) |k| {
            const after: u64 = if (k == 3) @bitCast(@as(i64, c.result)) else c.packet[k].value;
            try self.states.put(pointer + 8 * k, .{ .value = after, .epoch = epoch, .tick = tick, .rights = c.packet[k].rights });
        }
        for (fresh.items, 0..) |w, r| switch (op) {
            .set => try self.states.put(dst + 8 * r, .{ .value = @as(u64, c.fill()) * 0x0101010101010101, .epoch = epoch, .tick = tick, .rights = w.dst.rights }),
            .copy => if (c.shift() == 0) {
                try self.states.put(word1 + 8 * r, .{ .value = w.src.value, .epoch = epoch, .tick = tick, .rights = w.src.rights });
                try self.states.put(dst + 8 * r, .{ .value = w.src.value, .epoch = epoch, .tick = tick, .rights = w.dst.rights });
            } else {
                const base = word1 & ~@as(u64, 7);
                try self.states.put(base + 8 * r, .{ .value = w.src.value, .epoch = epoch, .tick = tick, .rights = w.src.rights });
                if (r != 0) try self.states.put(dst + 8 * (r - 1), .{ .value = T.shifted(fresh.items[r - 1].src.value, w.src.value, c.shift()), .epoch = epoch, .tick = tick, .rights = w.dst.rights });
            },
            .cmp => {
                try self.states.put(dst + 8 * r, .{ .value = w.dst.value, .epoch = epoch, .tick = tick, .rights = w.dst.rights });
                try self.states.put(word1 + 8 * r, .{ .value = w.src.value, .epoch = epoch, .tick = tick, .rights = w.src.rights });
            },
        };
        try self.calls.append(self.a, c);
        try self.words.appendSlice(self.a, fresh.items);
    }
    fn ramEnvironment(self: *World, ch: T.Challenges) !Q {
        var sum = Q.zero();
        var it = self.initial.iterator();
        while (it.next()) |entry| {
            const address = entry.key_ptr.*;
            sum = sum.sub(try den(ch, address, entry.value_ptr.*).inv());
            sum = sum.add(try den(ch, address, self.states.get(address).?).inv());
        }
        return sum;
    }
    fn cpuOwner(self: *World, ch: T.Challenges) !Q {
        var sum = Q.zero();
        for (self.calls.items) |c| {
            var t: [19]Q = @splat(Q.zero());
            t[0] = E.q(@intFromEnum(Decode.Opcode.ECALL));
            for (0..4) |i| t[1 + i] = E.q(@as(u16, @truncate(c.pointer >> @as(u6, @intCast(16 * i)))));
            for (0..4) |i| t[9 + i] = E.q(@as(u16, @truncate(c.tag() >> @as(u6, @intCast(16 * i)))));
            t[17] = E.q(c.epoch);
            t[18] = E.q(c.tick);
            sum = sum.add(try ch.owner.denominatorFor(Q, t).inv());
        }
        return sum;
    }
};
fn den(ch: T.Challenges, address: u64, s: T.State) Q {
    var addr: [4]Q = undefined;
    var value: [4]Q = undefined;
    for (0..4) |i| {
        addr[i] = E.q(@as(u16, @truncate(address >> @as(u6, @intCast(16 * i)))));
        value[i] = E.q(@as(u16, @truncate(s.value >> @as(u6, @intCast(16 * i)))));
    }
    return ch.ram.denominatorFor(Q, Eq.ramTuple(Q, addr, E.q(s.epoch), E.q(@as(u16, @truncate(s.tick))), E.q(s.tick >> 16), value, E.q(s.rights & 1), E.q(s.rights >> 1)));
}

/// Standard scenario: memset, memcpy reading the memset output, an adjacent
/// cross-epoch copy, a read-only packet memset and a read-only-source copy.
fn scenario(w: *World) !void {
    try w.call(.set, 0x1000, 1, 8, 0x2000, 0xAB, 24);
    try w.call(.copy, 0x1018, 1, 16, 0x3000, 0x2000, 32);
    try w.call(.copy, 0x1030, 2, 4, 0x3010, 0x3000, 16); // adjacent: dst = src + len
    try w.call(.set, 0x7000, 2, 12, 0x4000, 0xFFFF_1234, 8);
    try w.call(.copy, 0x1048, 2, 20, 0x6000, 0x5000, 16);
}

fn Rows(comptime kind: L.Kind) type {
    return struct {
        items: [][L.main(kind)]M,
        fn get(ctx: *const anyopaque, logical: usize) [L.main(kind)]M {
            const self: *const @This() = @ptrCast(@alignCast(ctx));
            return self.items[logical];
        }
    };
}
const LOG: u32 = 6;
const N: usize = 1 << LOG;
/// Every row of one kind (honest from the source, then possibly forged).
const Witness = struct {
    desc: [N][L.desc.MAIN]M,
    copy: [N][L.copy.MAIN]M,
    set: [N][L.set.MAIN]M,
    ucopy: [N][L.ucopy.MAIN]M,
    cdesc: [N][L.cdesc.MAIN]M,
    cmp: [N][L.cmp.MAIN]M,
    rows: [6]u32,
};
/// All rows padding (zero) and no active rows.
fn emptyWitness(wit: *Witness) void {
    inline for (L.kinds) |kind| for (&@field(wit, @tagName(kind))) |*r| {
        r.* = @splat(M.zero());
    };
    wit.rows = @splat(0);
}
fn honest(a: std.mem.Allocator, w: *World) !Witness {
    var out: Witness = undefined;
    inline for (L.kinds, 0..) |kind, k| {
        var s = try Src.Source.init(a, kind, w.calls.items, w.words.items, LOG);
        defer s.deinit();
        out.rows[k] = s.rows;
        const target = &@field(out, @tagName(kind));
        for (target, 0..) |*r, i| r.* = s.row(kind, i);
    }
    return out;
}
const Verdict = struct { local: usize = 0, ranges: bool = true, ram: bool = true, owner: bool = true };
fn verdict(a: std.mem.Allocator, w: *World, wit: *Witness) !Verdict {
    const ch = challenges();
    var out = Verdict{};
    var ram = try w.ramEnvironment(ch);
    var owner = try w.cpuOwner(ch);
    var f: [N][3]M = undefined;
    for (&f, 0..) |*r, i| r.* = .{ M.fromCanonical(@intCast(i)), M.fromCanonical(@intFromBool(i == 0)), M.fromCanonical(@intFromBool(i == N - 1)) };
    inline for (L.kinds, 0..) |kind, k| {
        const rows = &@field(wit, @tagName(kind));
        var provider = Rows(kind){ .items = rows };
        const built = try B.interaction.generateRows(kind, a, LOG, N, &provider, Rows(kind).get, ch);
        defer a.free(built.interaction);
        ram = ram.add(built.claims.ram);
        owner = owner.add(built.claims.owner);
        const width = L.interaction(kind);
        var residuals: [192]Q = undefined;
        for (0..N) |r| {
            const prev = (r + N - 1) % N;
            var fq: [3]Q = undefined;
            var m: [L.main(kind)]Q = undefined;
            var pm: [L.main(kind)]Q = undefined;
            var i: [L.interaction(kind)]Q = undefined;
            var pi: [L.interaction(kind)]Q = undefined;
            for (&fq, f[r]) |*x, v| x.* = Q.fromBase(v);
            for (&m, rows[r]) |*x, v| x.* = Q.fromBase(v);
            for (&pm, rows[prev]) |*x, v| x.* = Q.fromBase(v);
            for (0..width) |c| {
                i[c] = Q.fromBase(built.interaction[c * N + Src.physical(r, LOG)]);
                pi[c] = Q.fromBase(built.interaction[c * N + Src.physical(prev, LOG)]);
            }
            var sink = E.Sink{ .values = &residuals };
            Eq.emitFor(Q, kind, &fq, &m, &pm, &i, &pi, wit.rows[k], built.claims, ch, &sink);
            if (sink.count != L.constraints(kind)) return error.ConstraintCountDrift;
            for (residuals[0..sink.count]) |v| out.local += @intFromBool(!v.isZero());
            // Every U16 lookup value (computed in the field) must lie in the table.
            for (Eq.fractions(Q, kind, &m, ch)) |fr| if (fr.relation == Eq.RANGE16) {
                // Recover the looked-up value from the affine denominator.
                const value = ch.range16.offset.sub(fr.d).div(ch.range16.coefficient) catch unreachable;
                const base = value.tryIntoM31() catch unreachable;
                if (base.v >= 65536) out.ranges = false;
            };
        }
    }
    out.ram = ram.isZero();
    out.owner = owner.isZero();
    return out;
}
fn accepted(v: Verdict) bool {
    return v.local == 0 and v.ranges and v.ram and v.owner;
}

fn setup(a: std.mem.Allocator) !struct { world: World, wit: *Witness } {
    var w = World.init(a);
    errdefer w.deinit();
    try scenario(&w);
    const wit = try a.create(Witness);
    wit.* = try honest(a, &w);
    return .{ .world = w, .wit = wit };
}

test "bulk memory: honest scenario satisfies every constraint and closes every relation" {
    const a = testing.allocator;
    var s = try setup(a);
    defer s.world.deinit();
    defer a.destroy(s.wit);
    try testing.expectEqual(@as(u32, 5), s.wit.rows[0]);
    try testing.expectEqual(@as(u32, 4 + 2 + 2), s.wit.rows[1]); // copy words
    try testing.expectEqual(@as(u32, 3 + 1), s.wit.rows[2]); // set words
    const v = try verdict(a, &s.world, s.wit);
    try testing.expectEqual(Verdict{}, v);
}

test "bulk memory: known answers for copied and filled words" {
    const a = testing.allocator;
    var s = try setup(a);
    defer s.world.deinit();
    defer a.destroy(s.wit);
    // memset 0xAB over 0x2000..0x2018, then memcpy 0x2000.. -> 0x3000..
    for (0..3) |j| try testing.expectEqual(@as(u64, 0xABABABABABABABAB), s.world.states.get(0x2000 + 8 * j).?.value);
    for (0..3) |j| try testing.expectEqual(@as(u64, 0xABABABABABABABAB), s.world.states.get(0x3000 + 8 * j).?.value);
    // Adjacent copy 0x3000..0x3010 -> 0x3010..0x3020 overwrote the word copied from 0x2018.
    try testing.expectEqual(@as(u64, 0xABABABABABABABAB), s.world.states.get(0x3018).?.value);
    try testing.expectEqual(@as(u64, 0x5008) *% 0x9E3779B97F4A7C15, s.world.states.get(0x6008).?.value);
    try testing.expectEqual(@as(u64, 0x3434343434343434), s.world.states.get(0x4000).?.value);
    // AIR rows: the copy row of word 0 carries limb 0xABAB as both src value and dst after.
    try testing.expectEqual(@as(u32, 0xABAB), s.wit.copy[0][L.copy.value].v);
    try testing.expectEqual(@as(u32, 0x34), s.wit.set[3][L.set.fill].v);
    try testing.expectEqual(@as(u32, 1), s.wit.set[3][L.set.remaining].v);
    try testing.expectEqual(@as(u32, 4), s.wit.copy[0][L.copy.remaining].v);
}

// ---------------------------------------------------------------------------
// Adversarial cases. Row map of the standard scenario:
// desc 0..4 = calls A..E; copy 0..3 = B, 4..5 = C, 6..7 = E; set 0..2 = A, 3 = D.

const Fixture = struct {
    a: std.mem.Allocator,
    world: World,
    wit: *Witness,
    fn init(a: std.mem.Allocator) !Fixture {
        const s = try setup(a);
        return .{ .a = a, .world = s.world, .wit = s.wit };
    }
    fn deinit(self: *Fixture) void {
        self.world.deinit();
        self.a.destroy(self.wit);
    }
    fn check(self: *Fixture) !Verdict {
        return verdict(self.a, &self.world, self.wit);
    }
};
fn mm(v: u32) M {
    return M.fromCanonical(v);
}
fn neg(v: u32) M {
    return M.zero().sub(M.fromCanonical(v));
}

test "bulk memory adversarial: wrong copied word is rejected by RAM closure" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    // The copied value column is shared by the src read and the dst write, so a
    // wrong dst value is also a wrong src read: no produced token matches it.
    fx.wit.copy[1][L.copy.value] = fx.wit.copy[1][L.copy.value].add(M.one());
    const v = try fx.check();
    try testing.expect(!accepted(v));
    try testing.expectEqual(@as(usize, 0), v.local);
    try testing.expect(!v.ram);
    try testing.expect(v.owner);
}

test "bulk memory adversarial: wrong memset fill is rejected by the call token and RAM" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    for (0..3) |r| fx.wit.set[r][L.set.fill] = mm(0xAC);
    const v = try fx.check();
    try testing.expectEqual(@as(usize, 0), v.local);
    try testing.expect(!v.owner and !v.ram);
}

test "bulk memory adversarial: skipped word fails the chain end or the token length" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    const honest_copy = fx.wit.copy;
    // (a) Drop call B's last word: the chain ends at remaining = 2.
    for (3..N - 1) |r| fx.wit.copy[r] = honest_copy[r + 1];
    fx.wit.rows[1] -= 1;
    const a = try fx.check();
    try testing.expect(!accepted(a) and a.local != 0);
    // (b) Also relabel remaining 3, 2, 1 so the chain is locally valid: the
    // token still says 4 words and word 3 is never written.
    for (0..3) |r| fx.wit.copy[r][L.copy.remaining] = mm(@intCast(3 - r));
    const b = try fx.check();
    try testing.expectEqual(@as(usize, 0), b.local);
    try testing.expect(!b.owner and !b.ram);
}

test "bulk memory adversarial: extra write fails the chain end or has no token" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    const honest_copy = fx.wit.copy;
    // (a) Continue call B with a fifth word (remaining 0): the chain must end at 1.
    for (5..N) |r| fx.wit.copy[r] = honest_copy[r - 1];
    fx.wit.copy[4] = Src.copyRow(fx.world.calls.items[1], 4, .{ .dst = .{ .value = 0, .rights = 3 }, .src = .{ .value = 0, .rights = 3 } });
    fx.wit.copy[4][L.copy.remaining] = mm(0);
    fx.wit.rows[1] += 1;
    const a = try fx.check();
    try testing.expect(!accepted(a) and a.local != 0);
    // (b) A standalone one-word chain (start row) with a claimed public count:
    // locally valid, but no descriptor emitted its token and memory changed.
    fx.wit.copy = honest_copy;
    var extra = Src.copyRow(fx.world.calls.items[4], 0, .{ .dst = .{ .value = 0, .rights = 3 }, .src = .{ .value = 0, .rights = 1 } });
    extra[L.copy.remaining] = mm(1);
    fx.wit.copy[8] = extra;
    fx.wit.rows[1] = 9;
    const b = try fx.check();
    try testing.expectEqual(@as(usize, 0), b.local);
    try testing.expect(!b.owner and !b.ram);
}

test "bulk memory adversarial: stale read before a prior write is rejected by RAM closure" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    // Call C (epoch 2) reads 0x3000, written by call B at (1, 16). Forge the
    // read to observe the initial image instead (a clock-valid cross-epoch gap).
    const r = 4;
    const k = L.copy.src_clock;
    fx.wit.copy[r][k + L.clock.epoch] = mm(0);
    fx.wit.copy[r][k + L.clock.low] = mm(0);
    fx.wit.copy[r][k + L.clock.same] = mm(0);
    fx.wit.copy[r][k + L.clock.gap16] = mm(1);
    const stale = fx.world.initial.get(0x3000).?.value;
    for (0..4) |i| fx.wit.copy[r][L.copy.value + i] = mm(@as(u16, @truncate(stale >> @as(u6, @intCast(16 * i)))));
    const v = try fx.check();
    try testing.expectEqual(@as(usize, 0), v.local);
    try testing.expect(v.ranges and v.owner and !v.ram);
}

test "bulk memory adversarial: wrong clock order needs an out-of-range gap or breaks OWNER" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    // (a) Predecessor at the call's own tick: the gap would be -1.
    const r = 0;
    const k = L.copy.dst_clock;
    fx.wit.copy[r][k + L.clock.epoch] = fx.wit.copy[r][L.copy.epoch];
    fx.wit.copy[r][k + L.clock.low] = fx.wit.copy[r][L.copy.tick_low];
    fx.wit.copy[r][k + L.clock.high] = fx.wit.copy[r][L.copy.tick_high];
    fx.wit.copy[r][k + L.clock.same] = mm(1);
    fx.wit.copy[r][k + L.clock.gap16] = neg(1);
    fx.wit.copy[r][k + L.clock.gap8] = mm(0);
    const a = try fx.check();
    try testing.expectEqual(@as(usize, 0), a.local);
    try testing.expect(!a.ranges and !a.ram);
    // (b) Move call B's accesses to a later CPU tick: the token/ECALL tick differs.
    fx.wit.* = try honest(fx.a, &fx.world);
    for (0..4) |row| {
        fx.wit.copy[row][L.copy.tick_low] = mm(40);
        if (fx.wit.copy[row][L.copy.dst_clock + L.clock.same].v == 1) fx.wit.copy[row][L.copy.dst_clock + L.clock.gap16] = fx.wit.copy[row][L.copy.dst_clock + L.clock.gap16].add(mm(24));
        if (fx.wit.copy[row][L.copy.src_clock + L.clock.same].v == 1) fx.wit.copy[row][L.copy.src_clock + L.clock.gap16] = fx.wit.copy[row][L.copy.src_clock + L.clock.gap16].add(mm(24));
    }
    const b = try fx.check();
    try testing.expectEqual(@as(usize, 0), b.local);
    try testing.expect(!b.owner and !b.ram);
}

test "bulk memory adversarial: length that is not a multiple of eight needs an out-of-range quotient" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    // Make call B's packet say len = 36 and forge q0 = 36/8 in the field.
    const inv8 = try M.fromCanonical(8).inv();
    fx.wit.desc[1][L.desc.len_q0] = M.fromCanonical(36).mul(inv8);
    _ = try fx.world.states.put(0x1018 + 16, .{ .value = 36, .epoch = 1, .tick = 16, .rights = 3 });
    _ = try fx.world.initial.put(0x1018 + 16, .{ .value = 36, .rights = 3 });
    const v = try fx.check();
    try testing.expect(!v.ranges);
    // A len with a nonzero limb 2 cannot even be read: limbs 2 and 3 are constants 0.
    try testing.expect(!accepted(v));
}

test "bulk memory adversarial: non-canonical limbs are rejected" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    // (a) Copied value limb0 + 2^16, limb1 - 1: same integer, different tuple.
    fx.wit.copy[6][L.copy.value] = fx.wit.copy[6][L.copy.value].add(mm(65536));
    fx.wit.copy[6][L.copy.value + 1] = fx.wit.copy[6][L.copy.value + 1].sub(M.one());
    const a = try fx.check();
    try testing.expectEqual(@as(usize, 0), a.local);
    try testing.expect(!a.ram);
    // (b) memset fill byte 0x1AB (non-canonical byte split of limb0 0x1234 is
    // impossible with both bytes < 256): the fill ranges fail.
    fx.wit.* = try honest(fx.a, &fx.world);
    const inv256 = try M.fromCanonical(256).inv();
    fx.wit.desc[3][L.desc.fill_low] = mm(0x134);
    fx.wit.desc[3][L.desc.fill_high] = M.fromCanonical(0x1234 - 0x134).mul(inv256);
    fx.wit.set[3][L.set.fill] = mm(0x134);
    const b = try fx.check();
    try testing.expectEqual(@as(usize, 0), b.local);
    try testing.expect(!b.ranges);
}

test "bulk memory adversarial: forged tag or packet field breaks OWNER or RAM" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    // memcpy executed as memset (set bit flipped): a7 limb mismatch.
    fx.wit.desc[1][L.desc.set] = mm(1);
    const a = try fx.check();
    try testing.expect(!a.owner);
    fx.wit.* = try honest(fx.a, &fx.world);
    // Packet dst forged on the descriptor and every body row of call B.
    fx.wit.desc[1][L.desc.dst + 1] = fx.wit.desc[1][L.desc.dst + 1].add(M.one());
    for (0..4) |r| fx.wit.copy[r][L.copy.dst + 1] = fx.wit.copy[r][L.copy.dst + 1].add(M.one());
    const b = try fx.check();
    try testing.expectEqual(@as(usize, 0), b.local);
    try testing.expect(b.owner and !b.ram);
}

test "bulk memory adversarial: overlapping memcpy is rejected natively and by RAM order" {
    const a = testing.allocator;
    // Native admission refuses any alias among packet, src and dst words.
    var w = World.init(a);
    defer w.deinit();
    try w.call(.copy, 0x1000, 1, 8, 0x2008, 0x2000, 16);
    try testing.expectError(error.BulkMemoryOverlap, T.validateCall(w.calls.items[0], w.words.items));
    // AIR: build the rows anyway. Both 0x2008 accesses share tick 8.
    const wit = try a.create(Witness);
    defer a.destroy(wit);
    emptyWitness(wit);
    const call = w.calls.items[0];
    for (&wit.desc, 0..) |*r, i| r.* = Src.descRow(if (i == 0) call else null);
    for (&wit.copy, 0..) |*r, i| r.* = Src.copyRow(if (i < 2) call else null, i, if (i < 2) w.words.items[i] else .{ .dst = undefined });
    wit.rows[0] = 1;
    wit.rows[1] = 2;
    // (a) Snapshot semantics: the 0x2008 read and write consume the same token.
    const snapshot = try verdict(a, &w, wit);
    try testing.expectEqual(@as(usize, 0), snapshot.local);
    try testing.expect(!snapshot.ram);
    // (b) Chain the write after the read at the same tick: gap -1 is out of range.
    const k = L.copy.dst_clock;
    wit.copy[0][k + L.clock.epoch] = mm(1);
    wit.copy[0][k + L.clock.low] = mm(8);
    wit.copy[0][k + L.clock.high] = mm(0);
    wit.copy[0][k + L.clock.same] = mm(1);
    wit.copy[0][k + L.clock.gap16] = neg(1);
    const chained = try verdict(a, &w, wit);
    try testing.expect(!chained.ranges and !accepted(chained));
}

test "bulk memory: constraint degrees are at most three" {
    // Evaluate the residuals of a random point by polynomial-degree probing:
    // each constraint restricted to a line t -> x + t*y must have degree <= 3.
    const a = testing.allocator;
    var fx = try Fixture.init(a);
    defer fx.deinit();
    const ch = challenges();
    inline for (L.kinds) |kind| {
        const W = comptime L.main(kind);
        const I = comptime L.interaction(kind);
        var samples: [5][192]Q = undefined;
        var x: [3 + 2 * W + 2 * I]Q = undefined;
        var y: [3 + 2 * W + 2 * I]Q = undefined;
        for (&x, &y, 0..) |*xi, *yi, i| {
            xi.* = q(@intCast(1000 + i));
            yi.* = q(@intCast(5000 + i));
        }
        for (0..5) |t| {
            var z: [3 + 2 * W + 2 * I]Q = undefined;
            for (&z, x, y) |*zi, xi, yi| zi.* = xi.add(yi.mul(E.q(@intCast(t))));
            var sink = E.Sink{ .values = &samples[t] };
            Eq.emitFor(Q, kind, z[0..3], z[3..][0..W], z[3 + W ..][0..W], z[3 + 2 * W ..][0..I], z[3 + 2 * W + I ..][0..I], 7, .{ .ram = q(1), .owner = q(2), .range16 = q(3) }, ch, &sink);
        }
        // Fourth finite difference vanishes for degree <= 3.
        for (0..L.constraints(kind)) |c| {
            var d: [5]Q = undefined;
            for (0..5) |t| d[t] = samples[t][c];
            var level: usize = 5;
            while (level > 1) : (level -= 1) for (0..level - 1) |i| {
                d[i] = d[i + 1].sub(d[i]);
            };
            try testing.expect(d[0].isZero());
        }
    }
}

// ---------------------------------------------------------------------------
// Unaligned memcpy (`ucopy`) and memcmp (`cdesc` + `cmp`). Scenario 2 row map:
// desc 0..2 = B, C, G; ucopy 0..3 = B (shift 3, 3 words), 4..6 = C (shift 5,
// 2 words, reads B's output), 7..8 = G (shift 7, read-only source);
// cdesc 0..2 = D, E, F; cmp 0..1 = D (equal, 2 words), 2..3 = E (first
// difference in word 1, byte 5: limb 2 high byte, a < b), 4 = F (word 0,
// byte 0, a > b).

fn scenario2(w: *World) !void {
    for (0..2) |j| {
        const v = 0x1122_3344_5566_7788 +% 0x0101_0101_0101_0101 * @as(u64, j);
        try w.image(0x4000 + 8 * j, v);
        try w.image(0x4100 + 8 * j, v);
    }
    for (0..3) |j| {
        const v = 0x0F1E_2D3C_4B5A_6978 *% (@as(u64, j) + 3);
        try w.image(0x4200 + 8 * j, v);
        try w.image(0x4300 + 8 * j, if (j == 1) v +% (@as(u64, 1) << 40) & ~@as(u64, 0) else v ^ (if (j == 2) @as(u64, 0xFF) else 0));
    }
    try w.image(0x4400, 0x0000_0000_0000_00F0);
    try w.image(0x4500, 0xFFFF_FFFF_FFFF_FF0F);
    try w.call(.copy, 0x1000, 1, 8, 0x3000, 0x2003, 24);
    try w.call(.copy, 0x1040, 1, 12, 0x3100, 0x3005, 16);
    try w.call(.cmp, 0x1080, 1, 16, 0x4000, 0x4100, 16);
    try w.call(.cmp, 0x10C0, 1, 20, 0x4200, 0x4300, 24);
    try w.call(.cmp, 0x1100, 2, 4, 0x4400, 0x4500, 8);
    try w.call(.copy, 0x1140, 2, 8, 0x6100, 0x5007, 8);
}
const Fixture2 = struct {
    a: std.mem.Allocator,
    world: World,
    wit: *Witness,
    fn init(a: std.mem.Allocator) !Fixture2 {
        var w = World.init(a);
        errdefer w.deinit();
        try scenario2(&w);
        const wit = try a.create(Witness);
        wit.* = try honest(a, &w);
        return .{ .a = a, .world = w, .wit = wit };
    }
    fn deinit(self: *Fixture2) void {
        self.world.deinit();
        self.a.destroy(self.wit);
    }
    fn check(self: *Fixture2) !Verdict {
        return verdict(self.a, &self.world, self.wit);
    }
    fn reset(self: *Fixture2) !void {
        self.wit.* = try honest(self.a, &self.world);
    }
};

test "bulk memory: unaligned copy and memcmp scenario satisfies every constraint and closes every relation" {
    var fx = try Fixture2.init(testing.allocator);
    defer fx.deinit();
    try testing.expectEqual([6]u32{ 3, 0, 0, 4 + 3 + 2, 3, 2 + 2 + 1 }, fx.wit.rows);
    try testing.expectEqual(Verdict{}, try fx.check());
}

test "bulk memory: known answers for unaligned copies and memcmp results" {
    var fx = try Fixture2.init(testing.allocator);
    defer fx.deinit();
    const w = &fx.world;
    // Byte-level reference of B: dst[i] = initial byte at 0x2003 + i.
    for (0..24) |i| {
        const s = w.initial.get((0x2003 + i) & ~@as(u64, 7)).?.value;
        const d = w.states.get((0x3000 + i) & ~@as(u64, 7)).?.value;
        try testing.expectEqual(@as(u8, @truncate(s >> @intCast(8 * ((0x2003 + i) & 7)))), @as(u8, @truncate(d >> @intCast(8 * (i & 7)))));
    }
    // C copies B's output: byte i of 0x3100.. = byte 5 + i of 0x3000..
    for (0..16) |i| {
        const s = w.states.get((0x3005 + i) & ~@as(u64, 7)).?.value;
        const d = w.states.get((0x3100 + i) & ~@as(u64, 7)).?.value;
        try testing.expectEqual(@as(u8, @truncate(s >> @intCast(8 * ((0x3005 + i) & 7)))), @as(u8, @truncate(d >> @intCast(8 * (i & 7)))));
    }
    const calls = w.calls.items;
    try testing.expectEqual(@as(i2, 0), calls[2].result);
    try testing.expectEqual(@as(u32, 2), calls[2].examined);
    try testing.expectEqual(@as(i2, -1), calls[3].result);
    try testing.expectEqual(@as(u32, 2), calls[3].examined);
    try testing.expectEqual(@as(i2, 1), calls[4].result);
    try testing.expectEqual(@as(u64, std.math.maxInt(u64)), w.states.get(0x10C0 + 24).?.value);
    try testing.expectEqual(@as(u64, 1), w.states.get(0x1100 + 24).?.value);
    try testing.expectEqual(@as(u64, 0), w.states.get(0x1080 + 24).?.value);
    // AIR rows: E's differing row selects limb 2, high byte, lt.
    const e = fx.wit.cmp[3];
    try testing.expectEqual(@as(u32, 1), e[L.cmp.limbsel + 2].v);
    try testing.expectEqual(@as(u32, 1), e[L.cmp.hb].v);
    try testing.expectEqual(@as(u32, 1), e[L.cmp.lt].v);
    try testing.expectEqual(@as(u32, 1), fx.wit.ucopy[0][L.ucopy.sel + 2].v);
    try testing.expectEqual(@as(u32, 1), fx.wit.ucopy[7][L.ucopy.sel + 6].v);
}

test "bulk memory adversarial: unaligned copy with a wrong shift breaks the call token" {
    var fx = try Fixture2.init(testing.allocator);
    defer fx.deinit();
    // Run B re-executed at shift 4 (locally consistent: sel and every written
    // limb recomputed): the token src = aligned + 4 differs from the packet's.
    for (0..4) |r| {
        fx.wit.ucopy[r][L.ucopy.sel + 2] = M.zero();
        fx.wit.ucopy[r][L.ucopy.sel + 3] = M.one();
    }
    for (1..4) |r| {
        const prev = fx.world.words.items[r - 1].src.value;
        const cur = fx.world.words.items[r].src.value;
        const v = T.shifted(prev, cur, 4);
        for (0..4) |i| fx.wit.ucopy[r][L.ucopy.out + i] = mm(@as(u16, @truncate(v >> @intCast(16 * i))));
    }
    const v = try fx.check();
    try testing.expectEqual(@as(usize, 0), v.local);
    try testing.expect(v.ranges and !v.owner and !v.ram);
    // Shift changed on one continuation row only: local selector continuity.
    try fx.reset();
    fx.wit.ucopy[2][L.ucopy.sel + 2] = M.zero();
    fx.wit.ucopy[2][L.ucopy.sel + 3] = M.one();
    try testing.expect((try fx.check()).local != 0);
}

test "bulk memory adversarial: unaligned copy with a wrong byte is rejected" {
    var fx = try Fixture2.init(testing.allocator);
    defer fx.deinit();
    // (a) Wrong written limb only: the shift equation fails locally.
    fx.wit.ucopy[2][L.ucopy.out + 1] = fx.wit.ucopy[2][L.ucopy.out + 1].add(M.one());
    const a = try fx.check();
    try testing.expect(a.local != 0);
    // (b) Wrong source byte with a consistent written word: the source read
    // matches no produced token.
    try fx.reset();
    fx.wit.ucopy[2][L.ucopy.bytes + 6] = fx.wit.ucopy[2][L.ucopy.bytes + 6].add(M.one());
    fx.wit.ucopy[2][L.ucopy.bytes + 6] = M.fromCanonical(fx.wit.ucopy[2][L.ucopy.bytes + 6].v & 0xff);
    for ([_]usize{ 2, 3 }) |r| {
        const sh: u3 = 3;
        var bytes_prev: u64 = 0;
        var bytes_cur: u64 = 0;
        for (0..8) |b| {
            bytes_prev |= @as(u64, fx.wit.ucopy[r - 1][L.ucopy.bytes + b].v) << @intCast(8 * b);
            bytes_cur |= @as(u64, fx.wit.ucopy[r][L.ucopy.bytes + b].v) << @intCast(8 * b);
        }
        const v = T.shifted(bytes_prev, bytes_cur, sh);
        for (0..4) |i| fx.wit.ucopy[r][L.ucopy.out + i] = mm(@as(u16, @truncate(v >> @intCast(16 * i))));
    }
    const b = try fx.check();
    try testing.expectEqual(@as(usize, 0), b.local);
    try testing.expect(b.ranges and b.owner and !b.ram);
    // (c) Non-canonical byte split of a correct limb (lo + 256, hi - 1): the
    // limb and RAM agree, but the low byte is out of range.
    try fx.reset();
    const r = 1;
    fx.wit.ucopy[r][L.ucopy.bytes + 2] = fx.wit.ucopy[r][L.ucopy.bytes + 2].add(mm(256));
    fx.wit.ucopy[r][L.ucopy.bytes + 3] = fx.wit.ucopy[r][L.ucopy.bytes + 3].sub(M.one());
    const c = try fx.check();
    try testing.expect(!c.ranges and !accepted(c));
}

test "bulk memory adversarial: unaligned copy skipped or extra words are rejected" {
    var fx = try Fixture2.init(testing.allocator);
    defer fx.deinit();
    const honest_rows = fx.wit.ucopy;
    // (a) Drop B's last row: the run ends at remaining = 2.
    for (3..N - 1) |r| fx.wit.ucopy[r] = honest_rows[r + 1];
    fx.wit.rows[3] -= 1;
    try testing.expect((try fx.check()).local != 0);
    // (b) Also relabel remaining so the run is locally valid: the token's N
    // differs and destination word 2 is never written.
    for (0..3) |r| fx.wit.ucopy[r][L.ucopy.remaining] = mm(@intCast(3 - r));
    const b = try fx.check();
    try testing.expectEqual(@as(usize, 0), b.local);
    try testing.expect(!b.owner and !b.ram);
    // (c) The lead row also writes (start = 0 on row 0 is a continuation of padding).
    fx.wit.ucopy = honest_rows;
    fx.wit.rows[3] = 9;
    fx.wit.ucopy[0][L.ucopy.start] = M.zero();
    try testing.expect((try fx.check()).local != 0);
    // (d) The destination does not advance after word 0 (same word twice).
    fx.wit.ucopy = honest_rows;
    for (0..4) |i| fx.wit.ucopy[2][L.ucopy.dst + i] = fx.wit.ucopy[1][L.ucopy.dst + i];
    try testing.expect((try fx.check()).local != 0);
}

test "bulk memory adversarial: memcmp with a wrong result is rejected" {
    var fx = try Fixture2.init(testing.allocator);
    defer fx.deinit();
    // (a) E claims a > b at its first difference (lt flipped): the gap is negative.
    fx.wit.cmp[3][L.cmp.lt] = M.zero();
    const d = @as(i64, fx.wit.cmp[3][L.cmp.da].v) - @as(i64, fx.wit.cmp[3][L.cmp.db].v);
    fx.wit.cmp[3][L.cmp.gap] = if (d - 1 >= 0) mm(@intCast(d - 1)) else neg(@intCast(1 - d));
    fx.wit.cdesc[1][L.cdesc.neg] = M.zero();
    fx.wit.cdesc[1][L.cdesc.pos] = M.one();
    _ = try fx.world.states.put(0x10C0 + 24, .{ .value = 1, .epoch = 1, .tick = 20, .rights = 3 });
    const a = try fx.check();
    try testing.expectEqual(@as(usize, 0), a.local);
    try testing.expect(!a.ranges);
    // (b) The descriptor writes 0 for E while the body reports -1.
    try fx.reset();
    _ = try fx.world.states.put(0x10C0 + 24, .{ .value = 0, .epoch = 1, .tick = 20, .rights = 3 });
    fx.wit.cdesc[1][L.cdesc.neg] = M.zero();
    const b = try fx.check();
    try testing.expectEqual(@as(usize, 0), b.local);
    try testing.expect(!b.owner);
    // (c) A later limb chosen as the first difference while an earlier byte
    // differs: E's row picks limb 3 instead of limb 2.
    try fx.reset();
    _ = try fx.world.states.put(0x10C0 + 24, .{ .value = std.math.maxInt(u64), .epoch = 1, .tick = 20, .rights = 3 });
    const row = &fx.wit.cmp[3];
    row[L.cmp.limbsel + 2] = M.zero();
    row[L.cmp.limbsel + 3] = M.one();
    try testing.expect((try fx.check()).local != 0);
    // (d) The first difference placed in the high byte while the low bytes
    // differ (F: byte 0 differs).
    try fx.reset();
    fx.wit.cmp[4][L.cmp.hb] = M.one();
    try testing.expect((try fx.check()).local != 0);
}

test "bulk memory adversarial: memcmp early or late stops are rejected" {
    var fx = try Fixture2.init(testing.allocator);
    defer fx.deinit();
    // (a) D stops after its first (equal) word claiming a difference: no byte
    // differs, the gap would be -1.
    const r0 = &fx.wit.cmp[0];
    r0[L.cmp.last] = M.one();
    r0[L.cmp.diff] = M.one();
    r0[L.cmp.limbsel] = M.one();
    r0[L.cmp.alo] = M.fromCanonical(r0[L.cmp.va].v & 0xff);
    r0[L.cmp.ahi] = M.fromCanonical(r0[L.cmp.va].v >> 8);
    r0[L.cmp.blo] = r0[L.cmp.alo];
    r0[L.cmp.bhi] = r0[L.cmp.ahi];
    r0[L.cmp.da] = r0[L.cmp.alo];
    r0[L.cmp.db] = r0[L.cmp.blo];
    r0[L.cmp.gap] = neg(1);
    for (1..N - 1) |r| fx.wit.cmp[r] = fx.wit.cmp[r + 1];
    fx.wit.rows[5] -= 1;
    const a = try fx.check();
    try testing.expect(!accepted(a) and !a.ranges);
    // (b) D stops early with result 0 (last without a difference before remaining = 1).
    try fx.reset();
    fx.wit.cmp[0][L.cmp.last] = M.one();
    for (1..N - 1) |r| fx.wit.cmp[r] = fx.wit.cmp[r + 1];
    fx.wit.rows[5] -= 1;
    try testing.expect((try fx.check()).local != 0);
    // (c) E skips its differing word: diff = 0 on unequal words.
    try fx.reset();
    const e = &fx.wit.cmp[3];
    inline for (.{ L.cmp.diff, L.cmp.limbsel + 2, L.cmp.hb, L.cmp.lt, L.cmp.alo, L.cmp.ahi, L.cmp.blo, L.cmp.bhi, L.cmp.da, L.cmp.db, L.cmp.gap }) |col| e[col] = M.zero();
    try testing.expect((try fx.check()).local != 0);
    // (d) D runs past its length: a third row at remaining 0 (is_one = 1 on
    // row 1 forces it to be last).
    try fx.reset();
    const honest_rows = fx.wit.cmp;
    for (3..N) |r| fx.wit.cmp[r] = honest_rows[r - 1];
    fx.wit.cmp[1][L.cmp.last] = M.zero();
    fx.wit.cmp[2] = Src.cmpRow(fx.world.calls.items[2], 2, .{ .dst = .{ .value = 7, .rights = 3 }, .src = .{ .value = 9, .rights = 3 } });
    fx.wit.rows[5] += 1;
    try testing.expect((try fx.check()).local != 0);
}

test "bulk memory adversarial: memcmp result token without a descriptor or call is rejected" {
    var fx = try Fixture2.init(testing.allocator);
    defer fx.deinit();
    // F's descriptor dropped (memcmp executed as nothing): OWNER and RAM fail.
    fx.wit.cdesc[2] = Src.cdescRow(null);
    fx.wit.rows[4] = 2;
    const v = try fx.check();
    try testing.expect(!v.owner and !v.ram);
}
