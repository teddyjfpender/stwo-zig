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
        for ([_]u64{ dst, word1, len }, 0..) |v, k| if (!self.states.contains(pointer + 8 * k)) try self.image(pointer + 8 * k, v);
        var c = T.Call{ .op = op, .pointer = pointer, .epoch = epoch, .tick = tick, .dst = dst, .word1 = word1, .len = len, .packet = undefined };
        for (0..3) |k| {
            c.packet[k] = try self.get(pointer + 8 * k);
            try self.states.put(pointer + 8 * k, .{ .value = c.packet[k].value, .epoch = epoch, .tick = tick, .rights = c.packet[k].rights });
        }
        var fresh: std.ArrayList(T.Word) = .{};
        defer fresh.deinit(self.a);
        for (0..c.count()) |j| {
            var w = T.Word{ .dst = try self.get(dst + 8 * j) };
            if (op == .copy) w.src = try self.get(word1 + 8 * j);
            try fresh.append(self.a, w);
        }
        for (fresh.items, 0..) |w, j| {
            const value = if (op == .copy) w.src.value else @as(u64, c.fill()) * 0x0101010101010101;
            if (op == .copy) try self.states.put(word1 + 8 * j, .{ .value = w.src.value, .epoch = epoch, .tick = tick, .rights = w.src.rights });
            try self.states.put(dst + 8 * j, .{ .value = value, .epoch = epoch, .tick = tick, .rights = w.dst.rights });
        }
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
    rows: [3]u32,
};
fn honest(a: std.mem.Allocator, w: *World) !Witness {
    var out: Witness = undefined;
    inline for (.{ L.Kind.desc, L.Kind.copy, L.Kind.set }, 0..) |kind, k| {
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
    inline for (.{ L.Kind.desc, L.Kind.copy, L.Kind.set }, 0..) |kind, k| {
        const rows = &@field(wit, @tagName(kind));
        var provider = Rows(kind){ .items = rows };
        const built = try B.interaction.generateRows(kind, a, LOG, N, &provider, Rows(kind).get, ch);
        defer a.free(built.interaction);
        ram = ram.add(built.claims.ram);
        owner = owner.add(built.claims.owner);
        const width = L.interaction(kind);
        var residuals: [128]Q = undefined;
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
