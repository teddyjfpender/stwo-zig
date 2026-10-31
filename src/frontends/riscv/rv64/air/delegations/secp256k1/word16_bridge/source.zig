//! Copied narrow packet/predecessor metadata survives MAIN release. No group
//! operation is re-executed here; result truth belongs to unchanged RCB AIR.
const std = @import("std");
const core = @import("stwo_core");
const R = @import("../../../memory/closed_ram/mod.zig");
const LS = @import("../../../memory/load_store_v2/mod.zig");
const L = @import("layout.zig");
const T = @import("types.zig");
const P = @import("../program.zig");
const M = core.fields.m31.M31;
pub fn fixed(a: std.mem.Allocator, kind: P.Kind, log: u32) ![]M {
    const n = try T.validateGeometry(kind, 0, 1, log);
    const out = try a.alloc(M, L.FIXED * n);
    @memset(out, M.zero());
    const coords = T.coordinates(kind);
    for (0..n) |row| {
        const p = R.trace.physical(row, log);
        const coord = row % coords;
        out[p] = M.fromCanonical(@intCast(row));
        out[n + p] = M.fromCanonical(@intFromBool(row == 0));
        out[2 * n + p] = M.fromCanonical(@intFromBool(row == n - 1));
        out[3 * n + p] = M.fromCanonical(@intCast(coord));
        out[4 * n + p] = M.fromCanonical(@intFromBool(coord == 0));
        out[5 * n + p] = M.fromCanonical(@intCast(row / coords));
        out[6 * n + p] = M.fromCanonical(@intFromBool(coord < 3));
        out[7 * n + p] = M.fromCanonical(if (coord < 3) P.get(kind).outputs[coord] else 0);
    }
    return out;
}
pub fn validate(kind: P.Kind, c: T.Call) !void {
    const words = 4 * T.coordinates(kind);
    if (c.epoch == 0 or c.tick == 0 or c.tick & 3 != 0 or c.pointer & 31 != 0 or c.pointer > std.math.maxInt(u64) - (8 * words - 1)) return error.InvalidWord16SecpCall;
    for (c.predecessors[0..words], c.before[0..words], c.after[0..words], 0..) |pred, before, after, lane| {
        if (pred.value != before or pred.rights & 1 == 0 or (lane < 12 and pred.rights & 2 == 0) or (lane >= 12 and after != before) or pred.epoch > c.epoch or (pred.epoch == c.epoch and pred.tick >= c.tick)) return error.InvalidWord16SecpPredecessor;
    }
}
pub fn nativeRow(kind: P.Kind, call: ?T.Call, coord: usize, id: u32) [L.MAIN]M {
    var out: [L.MAIN]M = @splat(M.zero());
    const c = call orelse return out;
    out[L.ACTIVE] = M.one();
    out[L.WRITE] = M.fromCanonical(@intFromBool(coord < 3));
    out[L.TICK] = M.fromCanonical(c.tick);
    out[L.EPOCH] = M.fromCanonical(c.epoch);
    out[L.LOW] = M.fromCanonical(@as(u16, @truncate(c.tick)));
    out[L.HIGH] = M.fromCanonical(c.tick >> 16);
    out[L.CALL_ID] = M.fromCanonical(id);
    R.trace.word(out[L.POINTER..], c.pointer);
    R.trace.word(out[L.ADDRESS..], c.pointer + 32 * coord);
    for (0..4) |lane| {
        const index = 4 * coord + lane;
        const old = LS.native.row(.{ .opcode = if (coord < 3) .SD else .LD, .a = c.pointer + 8 * index, .immediate = 0, .b = if (coord < 3) c.after[index] else 0, .c = if (coord < 3) 0 else c.before[index], .epoch = c.epoch, .tick = c.tick, .before = c.predecessors[index], .after = .{ .value = c.after[index], .epoch = c.epoch, .tick = c.tick, .rights = c.predecessors[index].rights } });
        for ([_]usize{ 8, 10, 11, 24, 25, 26, 2, 27, 22, 23 }, [_]usize{ L.PREV_EPOCH, L.PREV_LOW, L.PREV_HIGH, L.GAP_EPOCH, L.GAP_LOW, L.GAP_HIGH, L.SAME, L.BORROW, L.READABLE, L.WRITABLE }) |from, to| out[to + lane] = old[from];
        for (0..8) |byte| {
            out[L.BEFORE + 8 * lane + byte] = M.fromCanonical(@as(u8, @truncate(c.before[index] >> @as(u6, @intCast(8 * byte)))));
            out[L.AFTER + 8 * lane + byte] = M.fromCanonical(@as(u8, @truncate(c.after[index] >> @as(u6, @intCast(8 * byte)))));
        }
    }
    var carry: u32 = 0;
    for (0..4) |i| {
        carry = (out[L.POINTER + i].v + (if (i == 0) @as(u32, @intCast(32 * coord)) else carry)) >> 16;
        out[L.CARRY + i] = M.fromCanonical(carry);
    }
    for (0..11) |bit| out[L.ALIGN + bit] = M.fromCanonical(@as(u1, @truncate(c.pointer >> @as(u6, @intCast(bit + 5)))));
    _ = kind;
    return out;
}
pub const Source = struct {
    allocator: std.mem.Allocator,
    kind: P.Kind,
    log_size: u32,
    first_id: u32,
    calls: []T.Call,
    fixed: []M,
    main: []M,
    owns_main: bool,
    interaction: []M = &.{},
    counts16: []u64,
    counts8: []u64,
    pub fn init(a: std.mem.Allocator, kind: P.Kind, calls: []const T.Call, first_id: u32, log: u32) !Source {
        return create(a, kind, calls, first_id, log, null);
    }
    pub fn initWithMainBuffer(a: std.mem.Allocator, kind: P.Kind, calls: []const T.Call, first_id: u32, log: u32, main: []M) !Source {
        return create(a, kind, calls, first_id, log, main);
    }
    fn create(a: std.mem.Allocator, kind: P.Kind, calls: []const T.Call, first_id: u32, log: u32, buffer: ?[]M) !Source {
        const n = try T.validateGeometry(kind, calls.len, first_id, log);
        for (calls, 0..) |c, index| {
            try validate(kind, c);
            if (index != 0 and (c.epoch < calls[index - 1].epoch or (c.epoch == calls[index - 1].epoch and c.tick <= calls[index - 1].tick))) return error.InvalidWord16SecpCallOrder;
        }
        if (buffer) |b| {
            const Storage = @import("../../main_storage.zig");
            try Storage.validate(&.{.{ .values = b, .cells = L.MAIN * n }});
            try Storage.exclude(&.{.{ .values = b, .cells = L.MAIN * n }}, std.mem.sliceAsBytes(calls));
        }
        const copy = try a.dupe(T.Call, calls);
        errdefer a.free(copy);
        const f = try fixed(a, kind, log);
        errdefer a.free(f);
        const counts16 = try a.alloc(u64, 65536);
        errdefer a.free(counts16);
        const counts8 = try a.alloc(u64, 256);
        errdefer a.free(counts8);
        @memset(counts16, 0);
        @memset(counts8, 0);
        const main = if (buffer) |b| b else try a.alloc(M, L.MAIN * n);
        const coords = T.coordinates(kind);
        for (0..n) |p| {
            const row = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(p, log), log);
            const index = row / coords;
            const values = nativeRow(kind, if (index < calls.len) calls[index] else null, row % coords, if (index < calls.len) first_id + @as(u32, @intCast(index)) else 0);
            for (values, 0..) |v, c| main[c * n + p] = v;
            for (L.U16) |c| counts16[values[c].v] += 1;
            for (L.U8) |c| counts8[values[c].v] += 1;
        }
        return .{ .allocator = a, .kind = kind, .log_size = log, .first_id = first_id, .calls = copy, .fixed = f, .main = main, .owns_main = buffer == null, .counts16 = counts16, .counts8 = counts8 };
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
        if (!self.owns_main or self.main.len == 0) return error.Word16SecpMainNotOwned;
        const m = self.main;
        self.main = &.{};
        self.owns_main = false;
        return m;
    }
    pub fn deinit(self: *Source) void {
        self.releaseMain();
        const a = self.allocator;
        a.free(self.fixed);
        a.free(self.calls);
        a.free(self.counts16);
        a.free(self.counts8);
        a.free(self.interaction);
        self.* = undefined;
    }
    pub fn generate(self: *Source, ch: T.Challenges, d16: []const T.Q, d8: []const T.Q) !T.Claims {
        return @import("interaction.zig").generate(self, ch, d16, d8);
    }
};
