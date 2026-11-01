//! Native witness rows for the three bulk-memory kinds. Call/word metadata
//! survives MAIN ownership transfer; interaction generation recomputes rows.
const std = @import("std");
const core = @import("stwo_core");
const R = @import("../../memory/closed_ram/mod.zig");
const L = @import("layout.zig");
const T = @import("types.zig");
const M = core.fields.m31.M31;

pub fn physical(row: usize, log: u32) usize {
    return R.trace.physical(row, log);
}
fn put(out: []M, at: usize, value: u64) void {
    for (0..4) |i| out[at + i] = M.fromCanonical(@as(u16, @truncate(value >> @as(u6, @intCast(16 * i)))));
}
fn carries(out: []M, at: usize, base: u64) void {
    var carry: u32 = 8;
    for (0..3) |i| {
        carry = (@as(u32, @as(u16, @truncate(base >> @as(u6, @intCast(16 * i))))) + carry) >> 16;
        out[at + i] = M.fromCanonical(carry);
    }
}
fn clockBlock(out: []M, at: usize, state: T.State, epoch: u16, tick: u24) void {
    out[at + L.clock.epoch] = M.fromCanonical(state.epoch);
    out[at + L.clock.low] = M.fromCanonical(@as(u16, @truncate(state.tick)));
    out[at + L.clock.high] = M.fromCanonical(state.tick >> 16);
    if (state.epoch == epoch) {
        const gap = tick - state.tick - 1;
        out[at + L.clock.same] = M.one();
        out[at + L.clock.gap16] = M.fromCanonical(@as(u16, @truncate(gap)));
        out[at + L.clock.gap8] = M.fromCanonical(gap >> 16);
    } else {
        out[at + L.clock.same] = M.zero();
        out[at + L.clock.gap16] = M.fromCanonical(epoch - state.epoch - 1);
        out[at + L.clock.gap8] = M.zero();
    }
}
fn afterClock(out: []M, at: usize, call: T.Call) void {
    out[at] = M.fromCanonical(call.epoch);
    out[at + 1] = M.fromCanonical(@as(u16, @truncate(call.tick)));
    out[at + 2] = M.fromCanonical(call.tick >> 16);
}
pub fn descRow(call: ?T.Call) [L.desc.MAIN]M {
    var out: [L.desc.MAIN]M = @splat(M.zero());
    const c = call orelse return out;
    const D = L.desc;
    out[D.active] = M.one();
    out[D.set] = M.fromCanonical(@intFromEnum(c.op));
    put(&out, D.pointer, c.pointer);
    carries(&out, D.carry8, c.pointer);
    carries(&out, D.carry16, c.pointer + 8);
    afterClock(&out, D.epoch, c);
    put(&out, D.dst, c.dst);
    put(&out, D.word1, c.word1);
    out[D.len_q0] = M.fromCanonical(@as(u16, @truncate(c.len)) / 8);
    out[D.len_l1] = M.fromCanonical(@as(u16, @truncate(c.len >> 16)));
    out[D.fill_low] = M.fromCanonical(@as(u8, @truncate(c.word1)));
    out[D.fill_high] = M.fromCanonical(@as(u8, @truncate(c.word1 >> 8)));
    for (c.packet, 0..) |state, k| {
        clockBlock(&out, D.clocks + L.CLOCK * k, state, c.epoch, c.tick);
        out[D.writable + k] = M.fromCanonical(state.rights >> 1);
    }
    return out;
}
pub fn copyRow(call: ?T.Call, j: usize, word: T.Word) [L.copy.MAIN]M {
    var out: [L.copy.MAIN]M = @splat(M.zero());
    const c = call orelse return out;
    const C = L.copy;
    out[C.active] = M.one();
    out[C.start] = M.fromCanonical(@intFromBool(j == 0));
    afterClock(&out, C.epoch, c);
    out[C.remaining] = M.fromCanonical(@intCast(c.count() - j));
    put(&out, C.dst, c.dst + 8 * j);
    put(&out, C.src, c.word1 + 8 * j);
    if (j != 0) {
        carries(&out, C.dst_carry, c.dst + 8 * (j - 1));
        carries(&out, C.src_carry, c.word1 + 8 * (j - 1));
    }
    put(&out, C.value, word.src.value);
    put(&out, C.dst_before, word.dst.value);
    clockBlock(&out, C.dst_clock, word.dst, c.epoch, c.tick);
    clockBlock(&out, C.src_clock, word.src, c.epoch, c.tick);
    out[C.src_writable] = M.fromCanonical(word.src.rights >> 1);
    return out;
}
pub fn setRow(call: ?T.Call, j: usize, word: T.Word) [L.set.MAIN]M {
    var out: [L.set.MAIN]M = @splat(M.zero());
    const c = call orelse return out;
    const S = L.set;
    out[S.active] = M.one();
    out[S.start] = M.fromCanonical(@intFromBool(j == 0));
    afterClock(&out, S.epoch, c);
    out[S.remaining] = M.fromCanonical(@intCast(c.count() - j));
    put(&out, S.dst, c.dst + 8 * j);
    if (j != 0) carries(&out, S.dst_carry, c.dst + 8 * (j - 1));
    out[S.fill] = M.fromCanonical(c.fill());
    put(&out, S.dst_before, word.dst.value);
    clockBlock(&out, S.dst_clock, word.dst, c.epoch, c.tick);
    return out;
}
/// The U16 lookup values of one row, in fraction order (equations.fractions).
pub fn rangeValues(comptime kind: L.Kind, m: []const M) [L.range16Count(kind)]u32 {
    var out: [L.range16Count(kind)]u32 = undefined;
    switch (kind) {
        .desc => {
            const D = L.desc;
            out[0] = m[D.tick_low].v;
            out[1] = m[D.tick_high].v;
            out[2] = 256 * m[D.tick_high].v;
            out[3] = m[D.fill_low].v;
            out[4] = 256 * m[D.fill_low].v;
            out[5] = m[D.fill_high].v;
            out[6] = 256 * m[D.fill_high].v;
            out[7] = m[D.len_q0].v;
            for (0..3) |k| clockValues(out[8 + 3 * k ..][0..3], m[D.clocks + L.CLOCK * k ..]);
        },
        .copy => {
            clockValues(out[0..3], m[L.copy.dst_clock..]);
            clockValues(out[3..6], m[L.copy.src_clock..]);
        },
        .set => clockValues(out[0..3], m[L.set.dst_clock..]),
    }
    return out;
}
fn clockValues(out: *[3]u32, k: []const M) void {
    out[0] = k[L.clock.gap16].v;
    out[1] = k[L.clock.gap8].v;
    out[2] = 256 * k[L.clock.gap8].v;
}

pub fn fixed(a: std.mem.Allocator, log: u32) ![]M {
    const n = @as(usize, 1) << @intCast(log);
    const out = try a.alloc(M, L.FIXED * n);
    @memset(out, M.zero());
    for (0..n) |row| {
        const p = physical(row, log);
        out[p] = M.fromCanonical(@intCast(row));
        out[n + p] = M.fromCanonical(@intFromBool(row == 0));
        out[2 * n + p] = M.fromCanonical(@intFromBool(row == n - 1));
    }
    return out;
}

/// One kind's rows. `calls` are all admitted calls of the CPU proof in
/// chronological order; `words` their data-word predecessors concatenated.
pub const Source = struct {
    allocator: std.mem.Allocator,
    kind: L.Kind,
    log_size: u32,
    rows: u32,
    calls: []T.Call,
    words: []T.Word,
    /// Body kinds: per active row, the call index and word index.
    row_call: []u32,
    row_word: []u32,
    /// Body kinds: first row of each call of this kind (unused entries 0).
    call_row: []u32,
    fixed: []M,
    main: []M,
    interaction: []M = &.{},
    owns_main: bool,
    counts16: []u64,
    counts8: []u64,

    pub fn rowsFor(kind: L.Kind, calls: []const T.Call) u64 {
        var total: u64 = 0;
        for (calls) |c| switch (kind) {
            .desc => total += 1,
            .copy => total += if (c.op == .copy) c.count() else 0,
            .set => total += if (c.op == .set) c.count() else 0,
        };
        return total;
    }
    pub fn init(a: std.mem.Allocator, kind: L.Kind, calls: []const T.Call, words: []const T.Word, log: u32) !Source {
        return create(a, kind, calls, words, log, null);
    }
    pub fn initWithMainBuffer(a: std.mem.Allocator, kind: L.Kind, calls: []const T.Call, words: []const T.Word, log: u32, main: []M) !Source {
        return create(a, kind, calls, words, log, main);
    }
    fn create(a: std.mem.Allocator, kind: L.Kind, calls: []const T.Call, words: []const T.Word, log: u32, buffer: ?[]M) !Source {
        const total = rowsFor(kind, calls);
        const n = try T.validateGeometry(kind, total, log);
        var offset: usize = 0;
        for (calls, 0..) |c, k| {
            if (offset + c.count() > words.len) return error.InvalidBulkMemoryWords;
            try T.validateCall(c, words[offset..][0..c.count()]);
            if (k != 0 and (c.epoch < calls[k - 1].epoch or (c.epoch == calls[k - 1].epoch and c.tick <= calls[k - 1].tick))) return error.InvalidBulkMemoryCallOrder;
            offset += c.count();
        }
        if (offset != words.len) return error.InvalidBulkMemoryWords;
        const width = L.main(kind);
        if (buffer) |b| if (b.len != width * n) return error.InvalidBulkMemoryMain;
        const call_copy = try a.dupe(T.Call, calls);
        errdefer a.free(call_copy);
        const word_copy = try a.dupe(T.Word, words);
        errdefer a.free(word_copy);
        const body = kind != .desc;
        const row_call = try a.alloc(u32, if (body) total else 0);
        errdefer a.free(row_call);
        const row_word = try a.alloc(u32, if (body) total else 0);
        errdefer a.free(row_word);
        const call_row = try a.alloc(u32, if (body) calls.len else 0);
        errdefer a.free(call_row);
        if (body) {
            var at: usize = 0;
            offset = 0;
            @memset(call_row, 0);
            for (calls, 0..) |c, k| {
                if (c.op == (if (kind == .copy) T.Op.copy else T.Op.set)) call_row[k] = @intCast(at);
                if (c.op == (if (kind == .copy) T.Op.copy else T.Op.set)) for (0..c.count()) |j| {
                    row_call[at] = @intCast(k);
                    row_word[at] = @intCast(offset + j);
                    at += 1;
                };
                offset += c.count();
            }
        }
        const f = try fixed(a, log);
        errdefer a.free(f);
        const c16 = try a.alloc(u64, 65536);
        errdefer a.free(c16);
        @memset(c16, 0);
        const c8 = try a.alloc(u64, 256);
        errdefer a.free(c8);
        @memset(c8, 0);
        const main = if (buffer) |b| b else try a.alloc(M, width * n);
        var self = Source{ .allocator = a, .kind = kind, .log_size = log, .rows = @intCast(total), .calls = call_copy, .words = word_copy, .row_call = row_call, .row_word = row_word, .call_row = call_row, .fixed = f, .main = main, .owns_main = buffer == null, .counts16 = c16, .counts8 = c8 };
        switch (kind) {
            inline else => |k| for (0..n) |logical| {
                const values = self.row(k, logical);
                for (values, 0..) |v, col| main[col * n + physical(logical, log)] = v;
                for (rangeValues(k, &values)) |v| c16[v] += 1;
            },
        }
        return self;
    }
    pub fn row(self: *const Source, comptime kind: L.Kind, logical: usize) [L.main(kind)]M {
        return switch (kind) {
            .desc => descRow(if (logical < self.rows) self.calls[logical] else null),
            .copy, .set => block: {
                if (logical >= self.rows) break :block (if (kind == .copy) copyRow(null, 0, .{ .dst = undefined }) else setRow(null, 0, .{ .dst = undefined }));
                const k = self.row_call[logical];
                const w = self.row_word[logical];
                // Rows of one call are consecutive; its first row holds word 0.
                const j = logical - self.call_row[k];
                break :block (if (kind == .copy) copyRow(self.calls[k], j, self.words[w]) else setRow(self.calls[k], j, self.words[w]));
            },
        };
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
        if (!self.owns_main or self.main.len == 0) return error.BulkMemoryMainNotOwned;
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
        a.free(self.words);
        a.free(self.row_call);
        a.free(self.row_word);
        a.free(self.call_row);
        a.free(self.counts16);
        a.free(self.counts8);
        a.free(self.interaction);
        self.* = undefined;
    }
    pub fn generate(self: *Source, ch: T.Challenges, dict16: []const T.Q) !T.Claims {
        return @import("interaction.zig").generate(self, ch, dict16);
    }
};
