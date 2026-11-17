//! Shared fixtures and independent relation oracles for this test owner.
//! LS-D64 known-answer, projection and adversarial tests.
//!
//! Acceptance model (as in the bulk-memory tests): a witness is accepted only
//! if every local residual of every row is zero, every U16/U8 query value lies
//! in its table, RAM14 closes against the honest INIT/TERM endpoints of every
//! touched word, and OWNER19 closes against the honest CPU LS tuples. The
//! interaction for a forged MAIN is rebuilt independently from the expanded
//! rows (exact inverses and prefixes), so a rejection is never an artifact of
//! a stale interaction column. Each adversarial case names the failing check.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../../evaluation.zig");
const Decode = @import("../../../decode.zig");
const D = @import("mod.zig");
const V2 = @import("../load_store/mod.zig");
const R = @import("../closed_ram/mod.zig");
const L = D.layout;
const Eq = D.equations;
const M = core.fields.m31.M31;
const Q = D.types.Q;
const testing = std.testing;
const a = testing.allocator;
const LOG: u32 = 5;
const N: usize = 1 << LOG;

pub fn q(n: u32) Q {
    const h = n *% 0x9E3779B1;
    return Q.fromU32Unchecked((h % 0x7fff0000) + 1, ((h >> 3) % 0x7fff0000) + 3, ((h >> 7) % 0x7fff0000) + 7, ((h >> 11) % 0x7fff0000) + 11);
}
pub fn challenges() D.types.Challenges {
    var ch: D.types.Challenges = undefined;
    ch.ram.offset = q(1);
    for (&ch.ram.coefficients, 0..) |*c, i| c.* = q(@intCast(10 + i));
    ch.owner.offset = q(2);
    for (&ch.owner.coefficients, 0..) |*c, i| c.* = q(@intCast(40 + i));
    ch.range16 = .{ .offset = q(3), .coefficient = q(4) };
    ch.range8 = .{ .offset = q(5), .coefficient = Q.one() };
    ch.selection.offset = q(6);
    for (&ch.selection.coefficients, 0..) |*c, i| c.* = q(@intCast(70 + i));
    return ch;
}
pub fn dictionary(ch: @import("../../providers/scalar_range.zig").Challenges, size: usize) ![]Q {
    const out = try a.alloc(Q, size);
    for (out, 0..) |*v, i| v.* = try ch.denominatorFor(Q, E.q(@intCast(i))).inv();
    return out;
}

pub const State = R.types.State;
/// Honest chronological memory: initial image, LD/SD events, final states.
pub const World = struct {
    states: std.AutoArrayHashMap(u64, State),
    initial: std.AutoArrayHashMap(u64, State),
    events: std.ArrayList(D.source.Event) = .{},
    tick: u24 = 0,
    pub fn init() World {
        return .{ .states = std.AutoArrayHashMap(u64, State).init(a), .initial = std.AutoArrayHashMap(u64, State).init(a) };
    }
    pub fn deinit(self: *World) void {
        self.states.deinit();
        self.initial.deinit();
        self.events.deinit(a);
    }
    pub fn image(self: *World, address: u64, value: u64, rights: u2) !void {
        try self.states.put(address, .{ .value = value, .rights = rights });
        try self.initial.put(address, .{ .value = value, .rights = rights });
    }
    /// One LS instruction at the next CPU tick 4r+4 (or after `skip` ticks).
    pub fn access(self: *World, opcode: Decode.Opcode, base: u64, immediate: u64, b: u64, skip: u24) !void {
        self.tick += 4 * (skip + 1);
        const address = base +% immediate;
        const word = address & ~@as(u64, 7);
        const before = self.states.get(word) orelse return error.TestUnmappedAddress;
        const d = try V2.native.describe(opcode);
        const shift: u6 = @intCast(8 * (address & 7));
        const bits: usize = 8 * @as(usize, d.width);
        const mask: u64 = if (d.width == 8) std.math.maxInt(u64) else (@as(u64, 1) << @as(u6, @intCast(bits))) - 1;
        var after = before;
        after.epoch = 1;
        after.tick = self.tick;
        var c: u64 = 0;
        if (d.write) {
            after.value = (before.value & ~(mask << shift)) | ((b & mask) << shift);
        } else {
            const v = (before.value >> shift) & mask;
            c = if (d.signed and (v & (@as(u64, 1) << @as(u6, @intCast(bits - 1)))) != 0) v | ~mask else v;
        }
        try self.events.append(a, .{ .opcode = opcode, .immediate = immediate, .a = base, .b = if (d.write) b else 0, .c = c, .epoch = 1, .tick = self.tick, .before = before, .after = after });
        try self.states.put(word, after);
    }
    pub fn ramEnvironment(self: *const World, ch: D.types.Challenges) !Q {
        var sum = Q.zero();
        for (self.initial.keys(), self.initial.values()) |address, s| {
            sum = sum.add(try ch.ram.denominatorFor(Q, cell(address, s)).inv());
            sum = sum.sub(try ch.ram.denominatorFor(Q, cell(address, self.states.get(address).?)).inv());
        }
        return sum;
    }
    pub fn cpuOwner(self: *const World, ch: D.types.Challenges, events: []const D.source.Event) !Q {
        _ = self;
        var sum = Q.zero();
        for (events) |e| sum = sum.add(try ch.owner.denominatorFor(Q, cpuTuple(e)).inv());
        return sum;
    }
};
pub fn cell(address: u64, s: State) [14]Q {
    var t: [14]Q = @splat(Q.zero());
    t[0] = Q.one();
    for (0..4) |i| t[1 + i] = E.q(@as(u16, @truncate(address >> @as(u6, @intCast(16 * i)))));
    t[5] = E.q(s.epoch);
    t[6] = E.q(@as(u16, @truncate(s.tick)));
    t[7] = E.q(s.tick >> 16);
    for (0..4) |i| t[8 + i] = E.q(@as(u16, @truncate(s.value >> @as(u6, @intCast(16 * i)))));
    t[12] = E.q(s.rights & 1);
    t[13] = E.q(s.rights >> 1);
    return t;
}
/// The CPU side of OWNER19 for one LS instruction: opcode, A, ROM immediate,
/// B (store source), C (load result), epoch, tick.
pub fn cpuTuple(e: D.source.Event) [19]Q {
    var t: [19]Q = undefined;
    t[0] = E.q(@intFromEnum(e.opcode));
    for ([_]u64{ e.a, e.immediate, e.b, e.c }, 0..) |w, k| {
        for (0..4) |i| t[1 + 4 * k + i] = E.q(@as(u16, @truncate(w >> @as(u6, @intCast(16 * i)))));
    }
    t[17] = E.q(e.epoch);
    t[18] = E.q(e.tick);
    return t;
}
pub fn honestWorld() !World {
    var w = World.init();
    errdefer w.deinit();
    try w.image(0x1000, 0x0123456789abcdef, 3);
    try w.image(0x1008, 0xfedcba9876543210, 3);
    try w.image(0x2000, 0x8000000000000001, 3);
    try w.image(0x5000, 0x1122334455667788, 1); // read-only
    try w.image(0xfffffffffffffff8, 0x00000000ffffffff, 3);
    try w.access(.SD, 0x1000, 0, 0x1111222233334444, 0);
    try w.access(.LD, 0x1000, 0, 0, 0);
    try w.access(.LD, 0x0ff8, 16, 0, 0);
    try w.access(.SD, 0x1ff0, 0x10, 0xdeadbeefcafef00d, 0);
    try w.access(.LD, 0x5000, 0, 0, 0);
    // Negative immediate: carries propagate through every limb.
    try w.access(.LD, 0x2010, @bitCast(@as(i64, -16)), 0, 0);
    // Wrapped 64-bit EA at the top of the address space.
    try w.access(.SD, 0x8, 0xfffffffffffffff0, 0x0f0f0f0f0f0f0f0f, 0);
    // A same-epoch gap above 2^16 ticks exercises gap_hi and the carry.
    try w.access(.SD, 0x1008, 0, 0xaaaaaaaaaaaaaaaa, 70000);
    try w.access(.LD, 0x1008, 0, 0, 0);
    try w.access(.LD, 0xfffffffffffffff8, 0, 0, 3);
    return w;
}

/// Self-consistent interaction for an arbitrary physical MAIN (logical row
/// order), with the claims it implies. Lookup residuals are then zero by
/// construction; acceptance is decided by the remaining checks.
pub const Relations = struct {
    inter: [L.INTERACTION * N]M,
    ram: Q,
    owner: Q,
    range16: Q,
    range8: Q,
    canonical_ranges: bool,
};
pub fn relations(main: []const M, ch: D.types.Challenges) !Relations {
    var out: Relations = .{ .inter = undefined, .ram = Q.zero(), .owner = Q.zero(), .range16 = Q.zero(), .range8 = Q.zero(), .canonical_ranges = true };
    var running = [2]Q{ Q.zero(), Q.zero() };
    var prefixes: [N][2]Q = undefined;
    for (0..N) |r| {
        const pos = R.trace.physical(r, LOG);
        const m = expanded(main, pos);
        const before = ch.ram.denominatorFor(Q, R.equations.ramTuple(Q, .transition, m[0..28], false));
        const after = ch.ram.denominatorFor(Q, R.equations.ramTuple(Q, .transition, m[0..28], true));
        const inverse = try before.mul(after).inv();
        R.trace.store(&out.inter, N, pos, 0, inverse);
        running[0] = running[0].add(after.sub(before).mul(inverse).mul(m[0]));
        const d = Eq.denominatorsFor(Q, &m, ch);
        var contribution = Q.zero();
        for (0..L.LOCAL_PAIRS) |pair| {
            const x = d[2 * pair];
            if (2 * pair + 1 < L.LOCAL_FRACTIONS) {
                const y = d[2 * pair + 1];
                const inv = try x.mul(y).inv();
                R.trace.store(&out.inter, N, pos, L.LOCAL_INVERSES + 4 * pair, inv);
                contribution = contribution.add((if (pair == 0) y.mul(m[0]).add(x) else x.add(y)).mul(inv));
            } else {
                const inv = try x.inv();
                R.trace.store(&out.inter, N, pos, L.LOCAL_INVERSES + 4 * pair, inv);
                contribution = contribution.add(inv);
            }
        }
        running[1] = running[1].add(contribution);
        out.owner = out.owner.add((try d[0].inv()).mul(m[0]));
        for (L.LOGICAL_U16, 0..) |c, j| {
            out.range16 = out.range16.add(try d[1 + j].inv());
            out.canonical_ranges = out.canonical_ranges and canonical(m[c], 65536);
        }
        for (L.LOGICAL_U8, 0..) |c, j| {
            out.range8 = out.range8.add(try d[1 + L.LOGICAL_U16.len + j].inv());
            out.canonical_ranges = out.canonical_ranges and canonical(m[c], 256);
        }
        prefixes[r] = running;
    }
    out.ram = running[0];
    for (0..N) |r| {
        const pos = R.trace.physical(r, LOG);
        R.trace.store(&out.inter, N, pos, 4, prefixes[r][0].sub(out.ram));
        R.trace.store(&out.inter, N, pos, L.LOCAL_PREFIX, prefixes[r][1].sub(running[1]));
    }
    return out;
}
pub fn canonical(v: Q, bound: u32) bool {
    const base = v.tryIntoM31() catch return false;
    return base.v < bound;
}
pub fn expanded(main: []const M, pos: usize) [L.LOGICAL_MAIN]Q {
    var physical: [L.MAIN]Q = undefined;
    for (&physical, 0..) |*v, c| v.* = Q.fromBase(main[c * N + pos]);
    return L.expandFor(Q, &physical);
}
/// Index of the first nonzero residual over all rows, or null.
pub fn firstResidual(fixed: []const M, main: []const M, inter: []const M, rows: u32, claims: D.types.Claims, ch: D.types.Challenges) ?struct { row: usize, index: usize } {
    const component = D.component.Component{ .log_size = LOG, .rows = rows, .offsets = .{ 0, 0, 0 }, .claims = claims, .challenges = ch };
    var values: [D.component.CONSTRAINTS]Q = undefined;
    for (0..N) |r| {
        const pos = R.trace.physical(r, LOG);
        const prev = R.trace.physical((r + N - 1) % N, LOG);
        var f: [L.FIXED]Q = undefined;
        var m: [L.MAIN]Q = undefined;
        var pm: [L.MAIN]Q = undefined;
        var i: [L.INTERACTION]Q = undefined;
        var pi: [L.INTERACTION]Q = undefined;
        for (&f, 0..) |*v, c| v.* = Q.fromBase(fixed[c * N + pos]);
        for (&m, &pm, 0..) |*v, *p, c| {
            v.* = Q.fromBase(main[c * N + pos]);
            p.* = Q.fromBase(main[c * N + prev]);
        }
        for (&i, &pi, 0..) |*v, *p, c| {
            v.* = Q.fromBase(inter[c * N + pos]);
            p.* = Q.fromBase(inter[c * N + prev]);
        }
        var sink = E.Sink{ .values = &values };
        component.emitFor(Q, &f, &m, &pm, &i, &pi, &sink);
        std.debug.assert(sink.count == D.component.CONSTRAINTS);
        for (values, 0..) |v, k| if (!v.isZero()) return .{ .row = r, .index = k };
    }
    return null;
}
pub const Verdict = enum { accepted, local_residual, range_membership, ram_unclosed, owner_unclosed };
/// The whole acceptance model for a candidate MAIN against the honest world.
pub fn judge(w: *const World, main: []const M, rows: u32, ch: D.types.Challenges) !Verdict {
    const fixed = try D.source.fixed(a, LOG);
    defer a.free(fixed);
    const rel = try relations(main, ch);
    const claims = D.types.Claims{ .ram = rel.ram, .owner = rel.owner, .range16 = rel.range16, .range8 = rel.range8 };
    if (firstResidual(fixed, main, &rel.inter, rows, claims, ch) != null) return .local_residual;
    if (!rel.canonical_ranges) return .range_membership;
    if (!rel.ram.sub(try w.ramEnvironment(ch)).isZero()) return .ram_unclosed;
    if (!rel.owner.add(try w.cpuOwner(ch, w.events.items)).isZero()) return .owner_unclosed;
    return .accepted;
}
pub fn honestMain(w: *const World) ![L.MAIN * N]M {
    var main: [L.MAIN * N]M = undefined;
    for (0..N) |r| {
        const row = D.source.row(if (r < w.events.items.len) w.events.items[r] else null);
        for (row, 0..) |v, c| main[c * N + R.trace.physical(r, LOG)] = v;
    }
    return main;
}
pub fn at(main: []M, r: usize, logical: usize) *M {
    return &main[L.column(logical) * N + R.trace.physical(r, LOG)];
}
pub fn rowOf(w: *const World, opcode: Decode.Opcode) usize {
    for (w.events.items, 0..) |e, r| if (e.opcode == opcode) return r;
    unreachable;
}

pub const Tables = @import("../../providers/tables.zig");
pub fn pairChallenges() Tables.Challenges {
    var pc: Tables.Challenges = undefined;
    pc.offset = q(900);
    for (&pc.coefficients, 0..) |*c, i| c.* = q(@intCast(901 + i));
    return pc;
}
pub fn pairDictionary(pc: Tables.Challenges) ![]Q {
    const out = try a.alloc(Q, 65536);
    for (out, 0..) |*v, i| v.* = try Tables.pairDenominatorFor(Q, pc, E.q(@intCast(i >> 8)), E.q(@intCast(i & 255))).inv();
    return out;
}
/// First nonzero fused-layout residual over all rows, or null.
pub fn firstFusedResidual(fixed: []const M, main: []const M, inter: []const M, rows: u32, claims: D.types.Claims, ch: D.types.Challenges, pc: Tables.Challenges) ?struct { row: usize, index: usize } {
    const component = D.component.Component{ .log_size = LOG, .rows = rows, .offsets = .{ 0, 0, 0 }, .claims = claims, .challenges = ch, .pairs = pc };
    var values: [L.fused.CONSTRAINTS]Q = undefined;
    for (0..N) |r| {
        const pos = R.trace.physical(r, LOG);
        const prev = R.trace.physical((r + N - 1) % N, LOG);
        var f: [L.FIXED]Q = undefined;
        var m: [L.MAIN]Q = undefined;
        var pm: [L.MAIN]Q = undefined;
        var i: [L.fused.INTERACTION]Q = undefined;
        var pi: [L.fused.INTERACTION]Q = undefined;
        for (&f, 0..) |*v, c| v.* = Q.fromBase(fixed[c * N + pos]);
        for (&m, &pm, 0..) |*v, *p, c| {
            v.* = Q.fromBase(main[c * N + pos]);
            p.* = Q.fromBase(main[c * N + prev]);
        }
        for (&i, &pi, 0..) |*v, *p, c| {
            v.* = Q.fromBase(inter[c * N + pos]);
            p.* = Q.fromBase(inter[c * N + prev]);
        }
        var sink = E.Sink{ .values = &values };
        component.emitFor(Q, &f, &m, &pm, &i, &pi, &sink);
        std.debug.assert(sink.count == L.fused.CONSTRAINTS);
        for (values, 0..) |v, k| if (!v.isZero()) return .{ .row = r, .index = k };
    }
    return null;
}
pub fn readInter(inter: []const M, r: usize, column: usize) Q {
    const pos = R.trace.physical(r, LOG);
    return Q.fromM31(inter[column * N + pos], inter[(column + 1) * N + pos], inter[(column + 2) * N + pos], inter[(column + 3) * N + pos]);
}
pub fn addInter(inter: []M, r: usize, column: usize, value: Q) void {
    R.trace.store(inter, N, R.trace.physical(r, LOG), column, readInter(inter, r, column).add(value));
}
pub const FusedHonest = struct { source: D.source.Source, claims: D.types.Claims, classic: D.types.Claims, w: World, pc: Tables.Challenges, ch: D.types.Challenges, pairs: []Q };
pub fn fusedHonest() !FusedHonest {
    var w = try honestWorld();
    errdefer w.deinit();
    const ch = challenges();
    const pc = pairChallenges();
    const d16 = try dictionary(ch.range16, 65536);
    defer a.free(d16);
    const d8 = try dictionary(ch.range8, 256);
    defer a.free(d8);
    const pairs = try pairDictionary(pc);
    errdefer a.free(pairs);
    var classic_source = try D.source.Source.init(a, w.events.items, LOG);
    defer classic_source.deinit();
    const classic = try classic_source.generate(ch, d16, d8);
    var source = try D.source.Source.init(a, w.events.items, LOG);
    errdefer source.deinit();
    const claims = try source.generatePairs(ch, d16, pairs);
    return .{ .source = source, .claims = claims, .classic = classic, .w = w, .pc = pc, .ch = ch, .pairs = pairs };
}
