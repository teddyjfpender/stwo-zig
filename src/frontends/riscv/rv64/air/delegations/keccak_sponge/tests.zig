//! Known-answer and adversarial tests for the Keccak-sponge bridge AIR.
//!
//! A witness is accepted only if every local residual is zero, every U16/U8
//! lookup value lies in its table, every AND tuple is a table row, RAM14
//! closes against the memory chain endpoints (INIT/TERM of every touched
//! word), OWNER19 closes against the CPU ECALL tuples, and IO11 closes against
//! an honest Keccak-f truth that permutes exactly the inputs the permutation
//! rows consume (any input the prover chooses, but the true permutation).
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
    ch.io.offset = q(3);
    for (&ch.io.coefficients, 0..) |*c, i| c.* = q(@intCast(70 + i));
    ch.and_.offset = q(4);
    for (&ch.and_.coefficients, 0..) |*c, i| c.* = q(@intCast(90 + i));
    ch.range16 = .{ .offset = q(5), .coefficient = q(6) };
    ch.range8 = .{ .offset = q(7), .coefficient = q(8) };
    return ch;
}
const FIRST_ID: u32 = 7;
const RW: u2 = 3;
const RO: u2 = 1;
fn rightsAt(address: u64) u2 {
    return if (address >= 0x9000 and address < 0xA000) RO else RW;
}

/// Honest chronological ledger producing admitted calls and words.
pub const World = struct {
    a: std.mem.Allocator,
    states: std.AutoHashMap(u64, T.State),
    initial: std.AutoHashMap(u64, T.State),
    calls: std.ArrayList(T.Call) = .{},
    words: std.ArrayList(T.State) = .{},
    perms: u32 = 0,
    /// Test-only RAM environment correction (a forged terminal token).
    ram_adjust: Q = Q.zero(),
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
    fn bytes(self: *World, address: u64, data: []const u8) !void {
        var at: usize = 0;
        while (at < data.len) {
            const w = (address + at) & ~@as(u64, 7);
            var value = (try self.get(w)).value;
            const off: u6 = @intCast(address + at - w);
            var b: u6 = off;
            while (b < 8 and at < data.len) : (b += 1) {
                value = (value & ~(@as(u64, 0xff) << (8 * b))) | (@as(u64, data[at]) << (8 * b));
                at += 1;
            }
            try self.image(w, value);
        }
    }
    fn call(self: *World, pointer: u64, epoch: u16, tick: u24, state: u64, input: u64, len: u64, flags: u64) !void {
        for ([_]u64{ state, input, len, flags }, 0..) |v, k| try self.image(pointer + 8 * k, v);
        var c = T.Call{ .pointer = pointer, .epoch = epoch, .tick = tick, .packet = undefined, .state = undefined, .first_word = @intCast(self.words.items.len), .first_perm = self.perms };
        for (0..4) |k| c.packet[k] = try self.get(pointer + 8 * k);
        for (0..25) |l| c.state[l] = try self.get(state + 8 * l);
        const p = c.p();
        const start = self.words.items.len;
        for (0..p.words()) |j| try self.words.append(self.a, try self.get(p.base() + 8 * j));
        try T.validateCall(c, self.words.items[start..]);
        const perms = try T.permutations(self.a, c, self.words.items[start..]);
        defer self.a.free(perms);
        for (0..4) |k| try self.states.put(pointer + 8 * k, .{ .value = c.packet[k].value, .epoch = epoch, .tick = tick, .rights = c.packet[k].rights });
        for (self.words.items[start..], 0..) |s, j| try self.states.put(p.base() + 8 * j, .{ .value = s.value, .epoch = epoch, .tick = tick, .rights = s.rights });
        for (0..25) |l| try self.states.put(state + 8 * l, .{ .value = perms[perms.len - 1][1][l], .epoch = epoch, .tick = tick, .rights = c.state[l].rights });
        self.perms += @intCast(perms.len);
        try self.calls.append(self.a, c);
    }
    fn ramEnvironment(self: *World, ch: T.Challenges) !Q {
        var sum = Q.zero();
        var it = self.initial.iterator();
        while (it.next()) |entry| {
            const address = entry.key_ptr.*;
            sum = sum.sub(try den(ch, address, entry.value_ptr.*).inv());
            sum = sum.add(try den(ch, address, self.states.get(address).?).inv());
        }
        return sum.add(self.ram_adjust);
    }
    fn cpuOwner(self: *World, ch: T.Challenges) !Q {
        var sum = Q.zero();
        for (self.calls.items) |c| {
            var t: [19]Q = @splat(Q.zero());
            t[0] = E.q(@intFromEnum(Decode.Opcode.ECALL));
            for (0..4) |i| t[1 + i] = E.q(@as(u16, @truncate(c.pointer >> @as(u6, @intCast(16 * i)))));
            for (0..4) |i| t[9 + i] = E.q(@as(u16, @truncate(T.TAG >> @as(u6, @intCast(16 * i)))));
            t[17] = E.q(c.epoch);
            t[18] = E.q(c.tick);
            sum = sum.add(try ch.owner.denominatorFor(Q, t).inv());
        }
        return sum;
    }
    fn digest(self: *World, state: u64) [32]u8 {
        var out: [32]u8 = undefined;
        for (0..4) |l| std.mem.writeInt(u64, out[8 * l ..][0..8], self.states.get(state + 8 * l).?.value, .little);
        return out;
    }
};
fn den(ch: T.Challenges, address: u64, s: T.State) Q {
    var value: [4]Q = undefined;
    for (0..4) |i| value[i] = E.q(@as(u16, @truncate(s.value >> @as(u6, @intCast(16 * i)))));
    return denLimbs(ch, address, s, value);
}
/// RAM14 denominator with explicit (possibly non-canonical) value limbs.
fn denLimbs(ch: T.Challenges, address: u64, s: T.State, value: [4]Q) Q {
    var addr: [4]Q = undefined;
    for (0..4) |i| addr[i] = E.q(@as(u16, @truncate(address >> @as(u6, @intCast(16 * i)))));
    return ch.ram.denominatorFor(Q, Eq.ramTuple(Q, addr, E.q(s.epoch), E.q(@as(u16, @truncate(s.tick))), E.q(s.tick >> 16), value, E.q(s.rights & 1), E.q(s.rights >> 1)));
}

fn message(out: []u8, seed: u32) void {
    for (out, 0..) |*b, i| b.* = @truncate((i +% seed) *% 0x3B +% (seed >> 3));
}
/// Standard scenario (row map in the adversarial section):
/// A fresh+finalize, shift 3, 300 bytes (3 permutations, tail 28);
/// B non-fresh absorb, aligned, 272 bytes (2 permutations, no padding);
/// C finalize of B's state with an empty tail (1 padding-only permutation);
/// D fresh+finalize, shift 7, 136 bytes (full block + padding block), epoch 2;
/// E fresh+finalize, shift 1, 135 bytes from A's written state (0x81 byte).
fn scenario(w: *World) !void {
    var a: [300]u8 = undefined;
    message(&a, 1);
    try w.bytes(0x2003, &a);
    try w.call(0x1000, 1, 8, 0x4000, 0x2003, 300, 3);
    var b: [272]u8 = undefined;
    message(&b, 2);
    try w.bytes(0x3000, &b);
    try w.call(0x1020, 1, 12, 0x5000, 0x3000, 272, 0);
    try w.call(0x1040, 1, 16, 0x5000, 0x3500, 0, 1);
    var d: [136]u8 = undefined;
    message(&d, 3);
    try w.bytes(0x6007, &d);
    try w.call(0x1060, 2, 4, 0x7000, 0x6007, 136, 3);
    try w.call(0x9000, 2, 8, 0x8000, 0x4001, 135, 3);
}
fn scenarioDigests(w: *World) !void {
    var a: [300]u8 = undefined;
    message(&a, 1);
    var want: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(&a, &want, .{});
    try testing.expectEqualSlices(u8, &want, &w.digest(0x4000));
    var d: [136]u8 = undefined;
    message(&d, 3);
    std.crypto.hash.sha3.Keccak256.hash(&d, &want, .{});
    try testing.expectEqualSlices(u8, &want, &w.digest(0x7000));
}

const CALL_LOG: u32 = 5;
const PERM_LOG: u32 = 5;
const NC: usize = 1 << CALL_LOG;
const NP: usize = 1 << PERM_LOG;
const Witness = struct {
    call: [NC][L.call.MAIN]M,
    perm: [NP][L.perm.MAIN]M,
    rows: [2]u32,
};
fn honest(a: std.mem.Allocator, w: *World) !*Witness {
    var plan = try Src.Plan.init(a, w.calls.items, w.words.items);
    defer plan.deinit(a);
    const out = try a.create(Witness);
    errdefer a.destroy(out);
    out.rows = .{ plan.rows(.call), plan.rows(.perm) };
    for (&out.call, 0..) |*r, i| r.* = plan.row(.call, i, FIRST_ID);
    for (&out.perm, 0..) |*r, i| r.* = plan.row(.perm, i, FIRST_ID);
    // The Source agrees with the plan's rows and counts.
    var s = try Src.Source.init(a, .perm, &plan, FIRST_ID, PERM_LOG);
    defer s.deinit();
    try testing.expectEqual(out.rows[1], s.rows);
    return out;
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
pub const Verdict = struct { local: usize = 0, ranges: bool = true, and_: bool = true, ram: bool = true, owner: bool = true, io: bool = true };
fn accepted(v: Verdict) bool {
    return v.local == 0 and v.ranges and v.and_ and v.ram and v.owner and v.io;
}
fn toByte(x: Q) ?u8 {
    const v = x.tryIntoM31() catch return null;
    return if (v.v < 256) @intCast(v.v) else null;
}
/// Honest truth production for every active permutation row's consumed input.
fn truthIo(ch: T.Challenges, rows: []const [L.perm.MAIN]M, count: u32) !?Q {
    var sum = Q.zero();
    for (rows[0..count], 0..) |r, i| {
        var m: [L.perm.MAIN]Q = undefined;
        for (&m, r) |*x, v| x.* = Q.fromBase(v);
        var st: [25]u64 = undefined;
        for (0..25) |l| {
            const in = Eq.inputBytes(Q, &m, l);
            var word: u64 = 0;
            for (in, 0..) |b, k| word |= @as(u64, toByte(b) orelse return null) << @intCast(8 * k);
            st[l] = word;
        }
        const id = FIRST_ID + @as(u32, @intCast(i));
        for (0..25) |l| sum = sum.add(try ioDen(ch, id, 0, l, st[l]).inv());
        T.Native.permute(&st);
        for (0..25) |l| sum = sum.add(try ioDen(ch, id, 1, l, st[l]).inv());
    }
    return sum;
}
fn ioDen(ch: T.Challenges, id: u32, dir: u32, lane: usize, value: u64) Q {
    var bytes: [8]Q = undefined;
    for (&bytes, 0..) |*b, k| b.* = E.q(@as(u8, @truncate(value >> @intCast(8 * k))));
    const tuple = Eq.ioTuple(Q, E.q(id), E.q(dir), lane, bytes);
    return E.denominatorFor(Q, ch.io.offset, &ch.io.coefficients, &tuple, true);
}
fn verdict(a: std.mem.Allocator, w: *World, wit: *Witness) !Verdict {
    const ch = challenges();
    var out = Verdict{};
    var ram = try w.ramEnvironment(ch);
    var owner = try w.cpuOwner(ch);
    var io = Q.zero();
    if (try truthIo(ch, &wit.perm, wit.rows[1])) |t| io = t else out.io = false;
    inline for (.{ L.Kind.call, L.Kind.perm }, 0..) |kind, k| {
        const n: usize = if (kind == .call) NC else NP;
        const log: u32 = if (kind == .call) CALL_LOG else PERM_LOG;
        const rows = &@field(wit, @tagName(kind));
        var provider = Rows(kind){ .items = rows };
        const built = try B.interaction.generateRows(kind, a, log, n, FIRST_ID, &provider, Rows(kind).get, ch);
        defer a.free(built.interaction);
        ram = ram.add(built.claims.ram);
        owner = owner.add(built.claims.owner);
        io = io.add(built.claims.io);
        const width = L.interaction(kind);
        const residuals = try a.alloc(Q, 4096);
        defer a.free(residuals);
        for (0..n) |r| {
            const prev = (r + n - 1) % n;
            var fq: [3]Q = .{ E.q(@intCast(r)), E.q(@intFromBool(r == 0)), E.q(@intFromBool(r == n - 1)) };
            var m: [L.main(kind)]Q = undefined;
            var pm: [L.main(kind)]Q = undefined;
            var i: [L.interaction(kind)]Q = undefined;
            var pi: [L.interaction(kind)]Q = undefined;
            for (&m, rows[r]) |*x, v| x.* = Q.fromBase(v);
            for (&pm, rows[prev]) |*x, v| x.* = Q.fromBase(v);
            for (0..width) |c| {
                i[c] = Q.fromBase(built.interaction[c * n + Src.physical(r, log)]);
                pi[c] = Q.fromBase(built.interaction[c * n + Src.physical(prev, log)]);
            }
            var sink = E.Sink{ .values = residuals };
            Eq.emitFor(Q, kind, &fq, &m, &pm, &i, &pi, wit.rows[k], FIRST_ID, built.claims, ch, &sink);
            if (sink.count != L.constraints(kind)) {
                std.debug.print("constraint count {s}: {d}\n", .{ @tagName(kind), sink.count });
                return error.ConstraintCountDrift;
            }
            for (residuals[0..sink.count]) |v| out.local += @intFromBool(!v.isZero());
            for (Eq.fractions(Q, kind, &fq, &m, FIRST_ID, ch)) |fr| switch (fr.relation) {
                Eq.RANGE16, Eq.RANGE8 => {
                    const rc = if (fr.relation == Eq.RANGE16) ch.range16 else ch.range8;
                    const value = rc.offset.sub(fr.d).div(rc.coefficient) catch unreachable;
                    const base = value.tryIntoM31() catch unreachable;
                    if (base.v >= @as(u32, if (fr.relation == Eq.RANGE16) 65536 else 256)) out.ranges = false;
                },
                else => {},
            };
            if (kind == .perm) for (0..T.RATE) |t| {
                const x = toByte(m[L.perm.pre + t]);
                const y = toByte(m[L.perm.msg + t]);
                const z = toByte(m[L.perm.and_ + t]);
                if (x == null or y == null or z == null or z.? != x.? & y.?) out.and_ = false;
            };
        }
    }
    out.ram = ram.isZero();
    out.owner = owner.isZero();
    if (out.io) out.io = io.isZero();
    return out;
}

const Fixture = struct {
    a: std.mem.Allocator,
    world: World,
    wit: *Witness,
    fn init(a: std.mem.Allocator) !Fixture {
        var w = World.init(a);
        errdefer w.deinit();
        try scenario(&w);
        return .{ .a = a, .world = w, .wit = try honest(a, &w) };
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

test "keccak sponge: honest scenario satisfies every constraint and closes every relation" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    try scenarioDigests(&fx.world);
    try testing.expectEqual(@as(u32, 5), fx.wit.rows[0]);
    try testing.expectEqual(@as(u32, 3 + 2 + 1 + 2 + 1), fx.wit.rows[1]);
    try testing.expectEqual(Verdict{}, try fx.check());
}

test "keccak sponge: every length and alignment closes and matches Keccak-256" {
    const a = testing.allocator;
    const lengths = [_]u64{ 0, 1, 7, 8, 9, 31, 64, 65, 127, 128, 134, 135, 136, 137, 143, 144, 200, 271, 272, 273, 407, 408, 409 };
    var data: [420]u8 = undefined;
    message(&data, 9);
    for (lengths) |len| for (0..8) |shift| {
        var w = World.init(a);
        defer w.deinit();
        try w.bytes(0x2000 + shift, data[0..len]);
        try w.call(0x1000, 1, 8, 0x4000, 0x2000 + shift, len, 3);
        var want: [32]u8 = undefined;
        std.crypto.hash.sha3.Keccak256.hash(data[0..len], &want, .{});
        try testing.expectEqualSlices(u8, &want, &w.digest(0x4000));
        const wit = try honest(a, &w);
        defer a.destroy(wit);
        const v = try verdict(a, &w, wit);
        if (!accepted(v)) std.debug.print("len {d} shift {d}: {any}\n", .{ len, shift, v });
        try testing.expectEqual(Verdict{}, v);
    };
}

// ---------------------------------------------------------------------------
// Adversarial cases. Row map: call 0..4 = A..E; perm 0..2 = A, 3..4 = B,
// 5 = C, 6..7 = D, 8 = E.

fn redoAnd(row: *[L.perm.MAIN]M) void {
    for (0..T.RATE) |t| row[L.perm.and_ + t] = mm(row[L.perm.pre + t].v & row[L.perm.msg + t].v);
}

test "keccak sponge adversarial: wrong XOR (AND result) is rejected by the AND table" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    // Input byte = pre + msg - 2 t; a wrong t changes the absorbed byte.
    fx.wit.perm[1][L.perm.and_ + 5] = fx.wit.perm[1][L.perm.and_ + 5].add(mm(1));
    const v = try fx.check();
    try testing.expect(!accepted(v));
    try testing.expect(!v.and_);
}

test "keccak sponge adversarial: wrong absorbed message byte is rejected" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    // Change a data byte consistently in msg and AND: the msg equation
    // (mask * window + pad) no longer holds.
    const r = &fx.wit.perm[0];
    r[L.perm.msg + 10] = mm(r[L.perm.msg + 10].v ^ 1);
    redoAnd(r);
    const v = try fx.check();
    try testing.expect(!accepted(v) and v.local != 0);
    // Also forge the window byte: now the RAM read no longer matches memory.
    const shift = 3;
    r[L.perm.window + 10 + shift] = mm(r[L.perm.window + 10 + shift].v ^ 1);
    const v2 = try fx.check();
    try testing.expectEqual(@as(usize, 0), v2.local);
    try testing.expect(!v2.ram);
}

test "keccak sponge adversarial: skipped block is rejected" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    // Drop A's middle block (rows 0, 2 only): the byte/word counters and the
    // previous-output link break.
    const honest_perm = fx.wit.perm;
    fx.wit.perm[1] = honest_perm[2];
    for (2..NP - 1) |r| fx.wit.perm[r] = honest_perm[r + 1];
    fx.wit.rows[1] -= 1;
    const v = try fx.check();
    try testing.expect(!accepted(v));
    try testing.expect(v.local != 0 or !v.io);
}

test "keccak sponge adversarial: reordered blocks are rejected" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    // Swap B's two blocks (rows 3, 4) including their first/last flags.
    const r3 = fx.wit.perm[3];
    const r4 = fx.wit.perm[4];
    fx.wit.perm[3] = r4;
    fx.wit.perm[4] = r3;
    for ([_]usize{ L.perm.first, L.perm.last, L.perm.freshfirst, L.perm.rb, L.perm.wr }) |c| {
        fx.wit.perm[3][c] = r3[c];
        fx.wit.perm[4][c] = r4[c];
    }
    const v = try fx.check();
    try testing.expect(!accepted(v));
}

test "keccak sponge adversarial: forged final state is rejected by IO closure" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    // The call writes a state the truth never produced (and keeps RAM
    // consistent by also forging the environment's terminal word).
    const c = fx.world.calls.items[0];
    // Lane 24 (call E later reads lanes 0..16 of A's state as its message).
    fx.wit.call[0][L.call.new + 8 * 24 + 3] = mm(fx.wit.call[0][L.call.new + 8 * 24 + 3].v ^ 0x10);
    const address = c.p().state + 8 * 24;
    var s = fx.world.states.get(address).?;
    s.value ^= @as(u64, 0x10) << 24;
    try fx.world.states.put(address, s);
    const v = try fx.check();
    try testing.expectEqual(@as(usize, 0), v.local);
    try testing.expect(v.ram);
    try testing.expect(!v.io);
}

test "keccak sponge adversarial: length mismatch is rejected" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    // (a) Claim one byte less in A's last block: rb = 27 but the mask still
    // covers 28 bytes, or the packet len no longer matches memory.
    fx.wit.perm[2][L.perm.rb] = mm(27);
    const a = try fx.check();
    try testing.expect(!accepted(a) and a.local != 0);
    // (b) Shorten the whole call consistently (len 299): the packet word len
    // no longer matches the RAM packet value.
    var fx2 = try Fixture.init(testing.allocator);
    defer fx2.deinit();
    const C = L.call;
    fx2.wit.call[0][C.len0] = mm(299);
    fx2.wit.call[0][C.r] = mm(27);
    fx2.wit.call[0][C.e] = mm(fx2.wit.call[0][C.e].v - 1);
    for (0..3) |k| fx2.wit.perm[k][L.perm.rb] = mm(@intCast(299 - 136 * k));
    fx2.wit.perm[2][L.perm.mask + 27] = mm(0);
    fx2.wit.perm[2][L.perm.msg + 27] = mm(1);
    fx2.wit.perm[2][L.perm.msg + 28] = mm(0);
    redoAnd(&fx2.wit.perm[2]);
    const b = try fx2.check();
    try testing.expect(!accepted(b));
    try testing.expect(!b.ram);
}

test "keccak sponge adversarial: forged padding and fresh state are rejected" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    // Omit the 0x80 of A's final block (keeping the AND consistent).
    fx.wit.perm[2][L.perm.msg + 135] = mm(fx.wit.perm[2][L.perm.msg + 135].v ^ 0x80);
    redoAnd(&fx.wit.perm[2]);
    const v = try fx.check();
    try testing.expect(!accepted(v) and v.local != 0);
    // A fresh call whose first permutation starts from a nonzero state.
    var fx2 = try Fixture.init(testing.allocator);
    defer fx2.deinit();
    fx2.wit.perm[6][L.perm.pre + 150] = mm(1);
    redoAnd(&fx2.wit.perm[6]);
    const v2 = try fx2.check();
    try testing.expect(!accepted(v2) and v2.local != 0);
}

test "keccak sponge adversarial: non-canonical tail byte decomposition is rejected" {
    var fx = try Fixture.init(testing.allocator);
    defer fx.deinit();
    // A's last data byte (stream 302, slot 37 -> row 2 slot 3 byte 6) is the
    // low byte of a limb whose high byte is outside the message. Shift the
    // limb's split: low + 1, high - 1/256 keeps the RAM limb; the U8 check of
    // the high byte rejects it.
    const r = &fx.wit.perm[2];
    const at = L.perm.window + 8 * 3 + 6;
    const inv256 = M.fromCanonical(256).inv() catch unreachable;
    r[at] = r[at].add(mm(1));
    r[at + 1] = r[at + 1].sub(inv256);
    const t = 3 * 8 + 6 - 3; // msg index of that byte (shift 3)
    r[L.perm.msg + t] = r[at];
    redoAnd(r);
    const v = try fx.check();
    try testing.expect(!accepted(v));
    try testing.expect(!v.ranges);
}

test "keccak sponge adversarial: digest-write forgery is rejected" {
    const a = testing.allocator;
    const C = L.call;
    const lane = 24; // A's lane 24 is only read by TERM (call E reads lanes 0..16)
    const at = C.new + 8 * lane;
    const inv256 = M.fromCanonical(256).inv() catch unreachable;
    // (a) Non-canonical written limbs with the same integer word value:
    // limb0 + 65536, limb1 - 1 (byte1 + 256, byte2 - 1). The environment's
    // terminal token is forged to the same limbs, so RAM14 closes and every
    // local residual and range holds; only the truth's canonical output bytes
    // (IO11) exclude the write.
    {
        var fx = try Fixture.init(a);
        defer fx.deinit();
        const r = &fx.wit.call[0];
        r[at + 1] = r[at + 1].add(mm(256));
        r[at + 2] = r[at + 2].sub(mm(1));
        const ch = challenges();
        const address = fx.world.calls.items[0].p().state + 8 * lane;
        const s = fx.world.states.get(address).?;
        var limbs: [4]Q = undefined;
        for (0..4) |i| limbs[i] = E.q(@as(u16, @truncate(s.value >> @as(u6, @intCast(16 * i)))));
        limbs[0] = limbs[0].add(E.q(65536));
        limbs[1] = limbs[1].sub(Q.one());
        fx.world.ram_adjust = (try denLimbs(ch, address, s, limbs).inv()).sub(try den(ch, address, s).inv());
        const v = try fx.check();
        try testing.expectEqual(@as(usize, 0), v.local);
        try testing.expect(v.ranges and v.ram and v.owner and v.and_);
        try testing.expect(!v.io);
    }
    // (b) Same RAM limbs, non-canonical byte split (byte0 + 1, byte1 - 1/256):
    // RAM is untouched; the IO11 output tuple no longer matches the truth.
    {
        var fx = try Fixture.init(a);
        defer fx.deinit();
        const r = &fx.wit.call[0];
        r[at] = r[at].add(mm(1));
        r[at + 1] = r[at + 1].sub(inv256);
        const v = try fx.check();
        try testing.expectEqual(@as(usize, 0), v.local);
        try testing.expect(v.ranges and v.ram and v.owner);
        try testing.expect(!v.io);
    }
    // (c) Digest redirected: the call writes its state at another pointer
    // (state limb 0 + 8, carries unchanged): the packet word read no longer
    // matches memory, and the state words are not the ones the guest named.
    {
        var fx = try Fixture.init(a);
        defer fx.deinit();
        const r = &fx.wit.call[0];
        r[C.state] = r[C.state].add(mm(8));
        const v = try fx.check();
        try testing.expect(!accepted(v));
        try testing.expect(!v.ram);
    }
}

test "keccak sponge: degree three on random lines (finite differences)" {
    const ch = challenges();
    var prng = std.Random.DefaultPrng.init(7);
    const random = prng.random();
    inline for (.{ L.Kind.call, L.Kind.perm }) |kind| {
        const W = comptime L.FIXED + 2 * L.main(kind) + 2 * L.interaction(kind);
        var base: [W]Q = undefined;
        var dir: [W]Q = undefined;
        for (&base, &dir) |*x, *y| {
            x.* = E.q(random.int(u31) % 0x7fff0000);
            y.* = E.q(random.int(u31) % 0x7fff0000);
        }
        var samples: [5][]Q = undefined;
        var store: [5][4096]Q = undefined;
        for (0..5) |s| {
            var point: [W]Q = undefined;
            for (&point, base, dir) |*p, x, y| p.* = x.add(y.mul(E.q(@intCast(s))));
            const f = point[0..L.FIXED];
            const m = point[L.FIXED..][0..L.main(kind)];
            const pm = point[L.FIXED + L.main(kind) ..][0..L.main(kind)];
            const i = point[L.FIXED + 2 * L.main(kind) ..][0..L.interaction(kind)];
            const pi = point[L.FIXED + 2 * L.main(kind) + L.interaction(kind) ..][0..L.interaction(kind)];
            var sink = E.Sink{ .values = &store[s] };
            Eq.emitFor(Q, kind, f, m, pm, i, pi, 3, FIRST_ID, T.Claims.zero(), ch, &sink);
            samples[s] = store[s][0..sink.count];
        }
        for (0..samples[0].len) |c| {
            // Fourth finite difference vanishes iff degree <= 3 along the line.
            const d = samples[4][c].sub(samples[3][c].mul(E.q(4))).add(samples[2][c].mul(E.q(6))).sub(samples[1][c].mul(E.q(4))).add(samples[0][c]);
            if (!d.isZero()) {
                std.debug.print("{s} constraint {d} has degree > 3\n", .{ @tagName(kind), c });
                return error.DegreeTooHigh;
            }
        }
    }
}
