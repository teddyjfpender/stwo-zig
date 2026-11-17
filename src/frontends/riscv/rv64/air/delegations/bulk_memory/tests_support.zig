//! Shared fixtures and independent relation oracles for this test owner.
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

pub fn q(n: u32) Q {
    const h = n *% 0x9E3779B1;
    return Q.fromU32Unchecked((h % 0x7fff0000) + 1, ((h >> 3) % 0x7fff0000) + 3, ((h >> 7) % 0x7fff0000) + 7, ((h >> 11) % 0x7fff0000) + 11);
}
pub fn challenges() T.Challenges {
    var ch: T.Challenges = undefined;
    ch.ram.offset = q(1);
    for (&ch.ram.coefficients, 0..) |*c, i| c.* = q(@intCast(10 + i));
    ch.owner.offset = q(2);
    for (&ch.owner.coefficients, 0..) |*c, i| c.* = q(@intCast(40 + i));
    ch.range16 = .{ .offset = q(3), .coefficient = q(4) };
    return ch;
}

pub const RW: u2 = 3;
pub const RO: u2 = 1;
pub fn rightsAt(address: u64) u2 {
    return if (address >= 0x5000 and address < 0x6000) RO else if (address >= 0x7000 and address < 0x7100) RO else RW;
}

/// Honest chronological memory ledger producing calls, words and the
/// environment's RAM endpoint sum.
pub const World = struct {
    a: std.mem.Allocator,
    states: std.AutoHashMap(u64, T.State),
    initial: std.AutoHashMap(u64, T.State),
    calls: std.ArrayList(T.Call) = .{},
    words: std.ArrayList(T.Word) = .{},
    pub fn init(a: std.mem.Allocator) World {
        return .{ .a = a, .states = std.AutoHashMap(u64, T.State).init(a), .initial = std.AutoHashMap(u64, T.State).init(a) };
    }
    pub fn deinit(self: *World) void {
        self.states.deinit();
        self.initial.deinit();
        self.calls.deinit(self.a);
        self.words.deinit(self.a);
    }
    pub fn image(self: *World, address: u64, value: u64) !void {
        const s = T.State{ .value = value, .rights = rightsAt(address) };
        try self.states.put(address, s);
        try self.initial.put(address, s);
    }
    pub fn get(self: *World, address: u64) !T.State {
        if (self.states.get(address)) |s| return s;
        try self.image(address, address *% 0x9E3779B97F4A7C15);
        return self.states.get(address).?;
    }
    pub fn call(self: *World, op: T.Op, pointer: u64, epoch: u16, tick: u24, dst: u64, word1: u64, len: u64) !void {
        const pw: usize = if (op == .cmp) 4 else 3;
        const packet_values = if (op == .jumpdest) [_]u64{ dst, len, word1, 0x5EED } else [_]u64{ dst, word1, len, 0x5EED };
        for (packet_values, 0..) |v, k| if (k < pw and !self.states.contains(pointer + 8 * k)) try self.image(pointer + 8 * k, v);
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
            .jumpdest => {
                for (0..n) |j| try fresh.append(self.a, .{ .dst = .{ .value = 0, .rights = 0 }, .src = try self.get(dst + 8 * j) });
                for (0..c.bitmapWords()) |r| try fresh.append(self.a, .{ .dst = try self.get(word1 + 8 * r) });
            },
        }
        // jumpdest: the canonical bitmap of the code words read.
        var bitmap: []u64 = &.{};
        defer self.a.free(bitmap);
        if (op == .jumpdest) {
            const code = try self.a.alloc(u64, n);
            defer self.a.free(code);
            for (fresh.items[0..n], code) |x, *v| v.* = x.src.value;
            const pending = try self.a.alloc(u8, c.bitmapWords());
            defer self.a.free(pending);
            bitmap = try self.a.alloc(u64, c.bitmapWords());
            T.analyzeWords(code, pending, bitmap);
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
            .jumpdest => if (r < n) {
                try self.states.put(dst + 8 * r, .{ .value = w.src.value, .epoch = epoch, .tick = tick, .rights = w.src.rights });
            } else {
                try self.states.put(word1 + 8 * (r - n), .{ .value = bitmap[r - n], .epoch = epoch, .tick = tick, .rights = w.dst.rights });
            },
            .cmp => {
                try self.states.put(dst + 8 * r, .{ .value = w.dst.value, .epoch = epoch, .tick = tick, .rights = w.dst.rights });
                try self.states.put(word1 + 8 * r, .{ .value = w.src.value, .epoch = epoch, .tick = tick, .rights = w.src.rights });
            },
        };
        try self.calls.append(self.a, c);
        try self.words.appendSlice(self.a, fresh.items);
    }
    pub fn ramEnvironment(self: *World, ch: T.Challenges) !Q {
        var sum = Q.zero();
        var it = self.initial.iterator();
        while (it.next()) |entry| {
            const address = entry.key_ptr.*;
            sum = sum.sub(try den(ch, address, entry.value_ptr.*).inv());
            sum = sum.add(try den(ch, address, self.states.get(address).?).inv());
        }
        return sum;
    }
    pub fn cpuOwner(self: *World, ch: T.Challenges) !Q {
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
pub fn den(ch: T.Challenges, address: u64, s: T.State) Q {
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
pub fn scenario(w: *World) !void {
    try w.call(.set, 0x1000, 1, 8, 0x2000, 0xAB, 24);
    try w.call(.copy, 0x1018, 1, 16, 0x3000, 0x2000, 32);
    try w.call(.copy, 0x1030, 2, 4, 0x3010, 0x3000, 16); // adjacent: dst = src + len
    try w.call(.set, 0x7000, 2, 12, 0x4000, 0xFFFF_1234, 8);
    try w.call(.copy, 0x1048, 2, 20, 0x6000, 0x5000, 16);
}

pub fn Rows(comptime kind: L.Kind) type {
    return struct {
        items: [][L.main(kind)]M,
        pub fn get(ctx: *const anyopaque, logical: usize) [L.main(kind)]M {
            const self: *const @This() = @ptrCast(@alignCast(ctx));
            return self.items[logical];
        }
    };
}
pub const LOG: u32 = 6;
pub const N: usize = 1 << LOG;
/// Every row of one kind (honest from the source, then possibly forged).
pub const Witness = struct {
    desc: [N][L.desc.MAIN]M,
    copy: [N][L.copy.MAIN]M,
    set: [N][L.set.MAIN]M,
    ucopy: [N][L.ucopy.MAIN]M,
    cdesc: [N][L.cdesc.MAIN]M,
    cmp: [N][L.cmp.MAIN]M,
    rows: [6]u32,
};
/// All rows padding (zero) and no active rows.
pub fn emptyWitness(wit: *Witness) void {
    inline for (L.kinds) |kind| for (&@field(wit, @tagName(kind))) |*r| {
        r.* = @splat(M.zero());
    };
    wit.rows = @splat(0);
}
pub fn honest(a: std.mem.Allocator, w: *World) !Witness {
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
pub const Verdict = struct { local: usize = 0, ranges: bool = true, ram: bool = true, owner: bool = true };
pub fn verdict(a: std.mem.Allocator, w: *World, wit: *Witness) !Verdict {
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
            for (Eq.fractions(Q, kind, &fq, &m, ch)) |fr| if (fr.relation == Eq.RANGE16) {
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
pub fn accepted(v: Verdict) bool {
    return v.local == 0 and v.ranges and v.ram and v.owner;
}

pub fn setup(a: std.mem.Allocator) !struct { world: World, wit: *Witness } {
    var w = World.init(a);
    errdefer w.deinit();
    try scenario(&w);
    const wit = try a.create(Witness);
    wit.* = try honest(a, &w);
    return .{ .world = w, .wit = wit };
}

pub const Fixture = struct {
    a: std.mem.Allocator,
    world: World,
    wit: *Witness,
    pub fn init(a: std.mem.Allocator) !Fixture {
        const s = try setup(a);
        return .{ .a = a, .world = s.world, .wit = s.wit };
    }
    pub fn deinit(self: *Fixture) void {
        self.world.deinit();
        self.a.destroy(self.wit);
    }
    pub fn check(self: *Fixture) !Verdict {
        return verdict(self.a, &self.world, self.wit);
    }
};
pub fn mm(v: u32) M {
    return M.fromCanonical(v);
}
pub fn neg(v: u32) M {
    return M.zero().sub(M.fromCanonical(v));
}

pub fn scenario2(w: *World) !void {
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
pub const Fixture2 = struct {
    a: std.mem.Allocator,
    world: World,
    wit: *Witness,
    pub fn init(a: std.mem.Allocator) !Fixture2 {
        var w = World.init(a);
        errdefer w.deinit();
        try scenario2(&w);
        const wit = try a.create(Witness);
        wit.* = try honest(a, &w);
        return .{ .a = a, .world = w, .wit = wit };
    }
    pub fn deinit(self: *Fixture2) void {
        self.world.deinit();
        self.a.destroy(self.wit);
    }
    pub fn check(self: *Fixture2) !Verdict {
        return verdict(self.a, &self.world, self.wit);
    }
    pub fn reset(self: *Fixture2) !void {
        self.wit.* = try honest(self.a, &self.world);
    }
};

pub const JLOG: u32 = 6;
pub const JN: usize = 1 << JLOG;
pub const J = L.jscan;

pub fn codeWord(bytes: []const u8) u64 {
    var v: u64 = 0;
    for (bytes, 0..) |b, i| v |= @as(u64, b) << @intCast(8 * i);
    return v;
}
pub fn imageCode(w: *World, address: u64, bytes: []const u8) !void {
    var k: usize = 0;
    while (k < bytes.len) : (k += 8) try w.image(address + k, codeWord(bytes[k..@min(k + 8, bytes.len)]));
}
pub fn scenarioJ(w: *World) !void {
    // A: 72 bytes. 0x5b at 0; PUSH1 0x5b at 1..2; 0x5b at 3; PUSH32 at 40
    // (data 41..72, crossing into row 1); 0x5b at 70 is data.
    var a: [72]u8 = @splat(0x01);
    a[0] = 0x5b;
    a[1] = 0x60;
    a[2] = 0x5b;
    a[3] = 0x5b;
    a[10] = 0x5b;
    a[40] = 0x7f;
    a[64] = 0x5b;
    a[70] = 0x5b;
    try imageCode(w, 0x8000, &a);
    // B: 64 bytes of read-only code; JUMPDEST at 63 after a truncated PUSH32 at 60? No:
    // PUSH2 at 50 (data 51, 52), JUMPDEST at 53, PUSH32 at 60 (data cut off at 64).
    var b: [64]u8 = @splat(0x5b);
    b[50] = 0x61;
    b[60] = 0x7f;
    try imageCode(w, 0x5000, &b);
    try w.call(.jumpdest, 0x1000, 1, 8, 0x8000, 0x9000, 72);
    try w.call(.jumpdest, 0x1018, 1, 12, 0x5000, 0x9100, 64);
    // C: A's two bitmap words as code.
    try w.call(.jumpdest, 0x1030, 2, 4, 0x9000, 0x9200, 16);
}

pub const JWitness = struct {
    jdesc: [][L.jdesc.MAIN]M,
    jscan: [][L.jscan.MAIN]M,
    jtab: [][L.jtab.MAIN]M,
    rows: [3]u32,
    pub fn deinit(self: *JWitness, a: std.mem.Allocator) void {
        a.free(self.jdesc);
        a.free(self.jscan);
        a.free(self.jtab);
    }
};
pub fn jlog(comptime kind: L.Kind) u32 {
    return if (kind == .jtab) T.TABLE_LOG else JLOG;
}
pub fn honestJ(a: std.mem.Allocator, w: *World) !JWitness {
    var out: JWitness = undefined;
    inline for (L.jumpdest_kinds, 0..) |kind, k| {
        var s = try Src.Source.init(a, kind, w.calls.items, w.words.items, jlog(kind));
        defer s.deinit();
        out.rows[k] = s.rows;
        const n = @as(usize, 1) << @intCast(jlog(kind));
        const rows = try a.alloc([L.main(kind)]M, n);
        for (rows, 0..) |*r, i| r.* = s.row(kind, i);
        @field(out, @tagName(kind)) = rows;
    }
    return out;
}
pub fn verdictJ(a: std.mem.Allocator, w: *World, wit: *JWitness) !Verdict {
    const ch = challenges();
    var out = Verdict{};
    var ram = try w.ramEnvironment(ch);
    var owner = try w.cpuOwner(ch);
    inline for (L.jumpdest_kinds, 0..) |kind, k| {
        const log = jlog(kind);
        const n = @as(usize, 1) << @intCast(log);
        const rows = @field(wit, @tagName(kind));
        var provider = Rows(kind){ .items = rows };
        const built = try B.interaction.generateRows(kind, a, log, n, &provider, Rows(kind).get, ch);
        defer a.free(built.interaction);
        const fixed = try Src.fixedFor(a, kind, log);
        defer a.free(fixed);
        ram = ram.add(built.claims.ram);
        owner = owner.add(built.claims.owner);
        const FW = comptime L.fixedWidth(kind);
        const width = L.interaction(kind);
        var residuals: [1024]Q = undefined;
        for (0..n) |r| {
            const prev = (r + n - 1) % n;
            var fq: [FW]Q = undefined;
            var m: [L.main(kind)]Q = undefined;
            var pm: [L.main(kind)]Q = undefined;
            var i: [L.interaction(kind)]Q = undefined;
            var pi: [L.interaction(kind)]Q = undefined;
            for (&fq, 0..) |*x, c| x.* = Q.fromBase(fixed[c * n + Src.physical(r, log)]);
            for (&m, rows[r]) |*x, v| x.* = Q.fromBase(v);
            for (&pm, rows[prev]) |*x, v| x.* = Q.fromBase(v);
            for (0..width) |c| {
                i[c] = Q.fromBase(built.interaction[c * n + Src.physical(r, log)]);
                pi[c] = Q.fromBase(built.interaction[c * n + Src.physical(prev, log)]);
            }
            var sink = E.Sink{ .values = &residuals };
            Eq.emitFor(Q, kind, &fq, &m, &pm, &i, &pi, wit.rows[k], built.claims, ch, &sink);
            if (sink.count != L.constraints(kind)) {
                std.debug.print("constraint count {s}: {d} (layout {d})\n", .{ @tagName(kind), sink.count, L.constraints(kind) });
                return error.ConstraintCountDrift;
            }
            for (residuals[0..sink.count]) |v| out.local += @intFromBool(!v.isZero());
            for (Eq.fractions(Q, kind, &fq, &m, ch)) |fr| if (fr.relation == Eq.RANGE16) {
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
pub const JFixture = struct {
    a: std.mem.Allocator,
    world: World,
    wit: JWitness,
    pub fn init(a: std.mem.Allocator) !JFixture {
        var w = World.init(a);
        errdefer w.deinit();
        try scenarioJ(&w);
        return .{ .a = a, .world = w, .wit = try honestJ(a, &w) };
    }
    pub fn deinit(self: *JFixture) void {
        self.wit.deinit(self.a);
        self.world.deinit();
    }
    pub fn check(self: *JFixture) !Verdict {
        return verdictJ(self.a, &self.world, &self.wit);
    }
    /// Make the environment's TERM of `address` agree with a forged bitmap
    /// write, so only the forged analysis itself can be what rejects it.
    pub fn acceptWrite(self: *JFixture, address: u64, row: []const M) !void {
        var s = self.world.states.get(address).?;
        s.value = Src.jscanBitmap(row);
        try self.world.states.put(address, s);
    }
    /// Recompute the jtab multiplicities from the (possibly forged) scan rows.
    pub fn retable(self: *JFixture) void {
        for (self.wit.jtab) |*r| r.* = .{M.zero()};
        for (self.wit.jscan) |row| {
            if (row[J.active].isZero()) continue;
            for (0..64) |k| {
                const valid = if (k < 8) true else !row[J.valid + k / 8 - 1].isZero();
                if (!valid) continue;
                const p = row[J.pending + k].v;
                const b = row[J.bytes + k].v;
                if (p > T.MAX_PENDING or b > 255) continue;
                const e = p * 256 + b;
                const t = T.tableEntry(e);
                if (t.next == row[J.pending + k + 1].v and t.jumpdest == row[J.jd + k].v) self.wit.jtab[e][0] = self.wit.jtab[e][0].add(M.one());
            }
        }
    }
};

/// Sets a word's initial and final ledger value (a read-only word of the
/// forged history, e.g. a packet field the prover rewrites).
pub fn rewriteWord(w: *World, address: u64, value: u64) !void {
    var initial = w.initial.get(address).?;
    var final = w.states.get(address).?;
    initial.value = value;
    final.value = value;
    try w.initial.put(address, initial);
    try w.states.put(address, final);
}
pub fn inverse(v: u32) M {
    return M.fromCanonical(v).inv() catch unreachable;
}
