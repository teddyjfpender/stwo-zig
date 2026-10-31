//! Narrow call/predecessor metadata survives MAIN ownership transfer. No
//! permutation is re-executed here; output truth belongs to the K component.
const std = @import("std");
const core = @import("stwo_core");
const R = @import("../../../memory/closed_ram/mod.zig");
const LS = @import("../../../memory/load_store_v2/mod.zig");
const L = @import("layout.zig");
const T = @import("types.zig");
const Eq = @import("equations.zig");
const M = core.fields.m31.M31;
const Q = T.Q;
pub fn fixed(a: std.mem.Allocator, log: u32) ![]M {
    const n = try T.validateGeometry(0, 1, log);
    const out = try a.alloc(M, L.FIXED * n);
    @memset(out, M.zero());
    for (0..n) |row| {
        const p = R.trace.physical(row, log);
        out[p] = M.fromCanonical(@intCast(row));
        out[n + p] = M.fromCanonical(@intFromBool(row == 0));
        out[2 * n + p] = M.fromCanonical(@intFromBool(row == n - 1));
        out[3 * n + p] = M.fromCanonical(@intCast(row % 25));
        out[4 * n + p] = M.fromCanonical(@intFromBool(row % 25 == 0));
        out[5 * n + p] = M.fromCanonical(@intCast(row / 25));
    }
    return out;
}
pub fn validate(call: T.Call) !void {
    if (call.epoch == 0 or call.tick == 0 or call.tick & 3 != 0 or call.pointer & 7 != 0 or call.pointer > std.math.maxInt(u64) - 199) return error.InvalidWord16KeccakCall;
    for (call.predecessors, call.before) |pred, value| {
        if (pred.value != value or pred.rights != 3 or pred.epoch > call.epoch or (pred.epoch == call.epoch and pred.tick >= call.tick)) return error.InvalidWord16KeccakPredecessor;
    }
}
pub fn nativeRow(call: ?T.Call, lane: usize, id: u32) [L.MAIN]M {
    var out: [L.MAIN]M = @splat(M.zero());
    const c = call orelse return out;
    const before = c.predecessors[lane];
    const old = LS.native.row(.{ .opcode = .SD, .a = c.pointer + 8 * lane, .immediate = 0, .b = c.after[lane], .epoch = c.epoch, .tick = c.tick, .before = before, .after = .{ .value = c.after[lane], .epoch = c.epoch, .tick = c.tick, .rights = 3 } });
    @memcpy(out[0..28], old[0..28]);
    R.trace.word(out[L.POINTER..], c.pointer);
    out[L.CALL_ID] = M.fromCanonical(id);
    for (0..8) |i| {
        out[L.BEFORE_BYTES + i] = M.fromCanonical(@as(u8, @truncate(c.before[lane] >> @as(u6, @intCast(8 * i)))));
        out[L.AFTER_BYTES + i] = M.fromCanonical(@as(u8, @truncate(c.after[lane] >> @as(u6, @intCast(8 * i)))));
    }
    var carry: u32 = 0;
    for (0..4) |i| {
        carry = (out[L.POINTER + i].v + (if (i == 0) @as(u32, @intCast(8 * lane)) else carry)) >> 16;
        out[L.ADDRESS_CARRY + i] = M.fromCanonical(carry);
    }
    for (0..13) |i| out[L.ALIGN_BITS + i] = M.fromCanonical(@as(u1, @truncate(c.pointer >> @as(u6, @intCast(i + 3)))));
    return out;
}
pub const Source = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    first_id: u32,
    calls: []T.Call,
    fixed: []M,
    main: []M,
    interaction: []M = &.{},
    owns_main: bool,
    counts16: []u64,
    counts8: []u64,
    pub fn init(a: std.mem.Allocator, calls: []const T.Call, first_id: u32, log: u32) !Source {
        return create(a, calls, first_id, log, null);
    }
    pub fn initWithMainBuffer(a: std.mem.Allocator, calls: []const T.Call, first_id: u32, log: u32, main: []M) !Source {
        return create(a, calls, first_id, log, main);
    }
    fn create(a: std.mem.Allocator, calls: []const T.Call, first_id: u32, log: u32, buffer: ?[]M) !Source {
        const n = try T.validateGeometry(calls.len, first_id, log);
        for (calls) |c| try validate(c);
        for (calls, 0..) |c, i| if (i != 0 and (c.epoch < calls[i - 1].epoch or (c.epoch == calls[i - 1].epoch and c.tick <= calls[i - 1].tick))) return error.InvalidWord16KeccakCallOrder;
        if (buffer) |b| {
            if (b.len != L.MAIN * n) return error.InvalidWord16KeccakMain;
            const storage = @import("../../main_storage.zig");
            try storage.validate(&.{.{ .values = b, .cells = L.MAIN * n }});
            try storage.exclude(&.{.{ .values = b, .cells = L.MAIN * n }}, std.mem.sliceAsBytes(calls));
        }
        const copy = try a.dupe(T.Call, calls);
        errdefer a.free(copy);
        const f = try fixed(a, log);
        errdefer a.free(f);
        const c16 = try a.alloc(u64, 65536);
        errdefer a.free(c16);
        @memset(c16, 0);
        const c8 = try a.alloc(u64, 256);
        errdefer a.free(c8);
        @memset(c8, 0);
        const main = if (buffer) |b| b else try a.alloc(M, L.MAIN * n);
        for (0..n) |p| {
            const row = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(p, log), log);
            const values = nativeRow(if (row / 25 < calls.len) calls[row / 25] else null, row % 25, if (row / 25 < calls.len) first_id + @as(u32, @intCast(row / 25)) else 0);
            for (values, 0..) |v, c| main[c * n + p] = v;
            for (L.U16) |c| c16[values[c].v] += 1;
            for (L.U8) |c| c8[values[c].v] += 1;
        }
        return .{ .allocator = a, .log_size = log, .first_id = first_id, .calls = copy, .fixed = f, .main = main, .owns_main = buffer == null, .counts16 = c16, .counts8 = c8 };
    }
    pub fn size(self: *const Source) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn releaseMain(self: *Source) void {
        if (self.owns_main) self.allocator.free(self.main);
        self.main = &.{};
        self.owns_main = false;
    }
    pub fn takeMain(self: *Source) ![]M {
        if (!self.owns_main or self.main.len == 0) return error.Word16KeccakMainNotOwned;
        const m = self.main;
        self.main = &.{};
        self.owns_main = false;
        return m;
    }
    pub fn deinit(self: *Source) void {
        self.releaseMain();
        self.allocator.free(self.fixed);
        self.allocator.free(self.calls);
        self.allocator.free(self.counts16);
        self.allocator.free(self.counts8);
        self.allocator.free(self.interaction);
        self.* = undefined;
    }
    pub fn generate(self: *Source, ch: T.Challenges, dict16: []const Q, dict8: []const Q) !T.Claims {
        return @import("interaction.zig").generate(self, ch, dict16, dict8);
    }
    /// Exact old native recipe retained only as a qualification oracle. This
    /// entry is never selected by a production component or runtime policy.
    pub fn generateOracleForQualification(self: *Source, ch: T.Challenges, dict16: []const Q, dict8: []const Q) !T.Claims {
        if (self.interaction.len != 0) return error.InvalidWord16KeccakPhase;
        try LS.interaction.validateDictionary(ch.range16, dict16, 65536);
        try LS.interaction.validateDictionary(ch.range8, dict8, 256);
        const n = self.size();
        const output = try self.allocator.alloc(M, L.INTERACTION * n);
        errdefer self.allocator.free(output);
        var total = T.Claims.zero();
        total.range16 = try LS.interaction.countDot(self.counts16, dict16);
        total.range8 = try LS.interaction.countDot(self.counts8, dict8);
        var ranges = [_]Q{ total.range16.neg(), total.range8.neg() };
        for (0..n) |row| {
            const p = R.trace.physical(row, self.log_size);
            const values = nativeRow(if (row / 25 < self.calls.len) self.calls[row / 25] else null, row % 25, if (row / 25 < self.calls.len) self.first_id + @as(u32, @intCast(row / 25)) else 0);
            var m: [L.MAIN]Q = undefined;
            for (values, &m) |v, *q| q.* = Q.fromBase(v);
            var f: [L.FIXED]Q = undefined;
            for (&f, 0..) |*q, c| q.* = Q.fromBase(self.fixed[c * n + p]);
            const bd = ch.ram.denominatorFor(Q, R.equations.ramTuple(Q, .transition, &m, false));
            const ad = ch.ram.denominatorFor(Q, R.equations.ramTuple(Q, .transition, &m, true));
            const ri = try bd.mul(ad).inv();
            R.trace.store(output, n, p, L.RAM, ri);
            total.ram = total.ram.add(ad.sub(bd).mul(ri).mul(m[0]));
            R.trace.store(output, n, p, L.RAM + 4, total.ram);
            const oi = try ch.owner.denominatorFor(Q, Eq.ownerTuple(Q, &m)).inv();
            R.trace.store(output, n, p, L.OWNER, oi);
            total.owner = total.owner.sub(oi.mul(m[0]).mul(f[4]));
            R.trace.store(output, n, p, L.OWNER + 4, total.owner);
            const di = ch.io.denominator(&Eq.ioTuple(Q, &f, &m, false));
            const ei = ch.io.denominator(&Eq.ioTuple(Q, &f, &m, true));
            const ii = try di.mul(ei).inv();
            R.trace.store(output, n, p, L.IO, ii);
            total.io = total.io.sub(di.add(ei).mul(ii).mul(m[0]));
            R.trace.store(output, n, p, L.IO + 4, total.io);
            inline for (.{ L.U16, L.U8 }, 0..) |indices, k| {
                const dict = if (k == 0) dict16 else dict8;
                const start = if (k == 0) L.RANGE16 else L.RANGE8;
                for (0..(indices.len + 1) / 2) |batch| {
                    const x = dict[values[indices[2 * batch]].v];
                    var inv = x;
                    ranges[k] = ranges[k].add(x);
                    if (2 * batch + 1 < indices.len) {
                        const y = dict[values[indices[2 * batch + 1]].v];
                        inv = inv.mul(y);
                        ranges[k] = ranges[k].add(y);
                    }
                    R.trace.store(output, n, p, start + 4 * batch, inv);
                }
                R.trace.store(output, n, p, start + 4 * ((indices.len + 1) / 2), ranges[k]);
            }
        }
        if (!ranges[0].isZero() or !ranges[1].isZero()) return error.InvalidWord16KeccakCounts;
        R.trace.center(output, n, L.RAM + 4, total.ram);
        R.trace.center(output, n, L.OWNER + 4, total.owner);
        R.trace.center(output, n, L.IO + 4, total.io);
        self.interaction = output;
        self.allocator.free(self.calls);
        self.calls = &.{};
        return total;
    }
};
