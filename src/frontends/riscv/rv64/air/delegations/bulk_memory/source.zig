//! Native witness rows for the six bulk-memory kinds. Call/word metadata
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
    carriesBy(out, at, base, 8);
}
fn carriesBy(out: []M, at: usize, base: u64, step: u32) void {
    var carry: u32 = step;
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
/// Unaligned copy row r of a run (r = 0 lead row): `words[r]` holds source
/// word r (and destination word r - 1); `prev` is `words[r - 1]` (r >= 1).
pub fn ucopyRow(call: ?T.Call, r: usize, word: T.Word, prev: T.Word) [L.ucopy.MAIN]M {
    var out: [L.ucopy.MAIN]M = @splat(M.zero());
    const c = call orelse return out;
    const U = L.ucopy;
    const shift = c.shift();
    const base = c.word1 & ~@as(u64, 7);
    out[U.active] = M.one();
    out[U.start] = M.fromCanonical(@intFromBool(r == 0));
    afterClock(&out, U.epoch, c);
    out[U.remaining] = M.fromCanonical(@intCast(c.entries() - r));
    put(&out, U.dst, c.dst + 8 * (if (r == 0) 0 else r - 1));
    put(&out, U.src, base + 8 * r);
    if (r >= 2) carries(&out, U.dst_carry, c.dst + 8 * (r - 2));
    if (r == 1) carriesBy(&out, U.dst_carry, c.dst, 0);
    if (r != 0) carries(&out, U.src_carry, base + 8 * (r - 1));
    out[U.sel + @as(usize, shift) - 1] = M.one();
    for (0..8) |b| out[U.bytes + b] = M.fromCanonical(@as(u8, @truncate(word.src.value >> @intCast(8 * b))));
    if (r != 0) {
        put(&out, U.out, T.shifted(prev.src.value, word.src.value, shift));
        put(&out, U.dst_before, word.dst.value);
        clockBlock(&out, U.dst_clock, word.dst, c.epoch, c.tick);
    }
    clockBlock(&out, U.src_clock, word.src, c.epoch, c.tick);
    out[U.src_writable] = M.fromCanonical(word.src.rights >> 1);
    return out;
}
fn zeroBlock(out: []M, at: usize) void {
    @memset(out[at..][0..L.CLOCK], M.zero());
}
pub fn cdescRow(call: ?T.Call) [L.cdesc.MAIN]M {
    var out: [L.cdesc.MAIN]M = @splat(M.zero());
    const c = call orelse return out;
    const D = L.cdesc;
    out[D.active] = M.one();
    put(&out, D.pointer, c.pointer);
    carries(&out, D.carry8, c.pointer);
    carries(&out, D.carry16, c.pointer + 8);
    carries(&out, D.carry24, c.pointer + 16);
    afterClock(&out, D.epoch, c);
    put(&out, D.a, c.dst);
    put(&out, D.b, c.word1);
    out[D.len_q0] = M.fromCanonical(@as(u16, @truncate(c.len)) / 8);
    out[D.len_l1] = M.fromCanonical(@as(u16, @truncate(c.len >> 16)));
    for (c.packet, 0..) |state, k| clockBlock(&out, D.clocks + L.CLOCK * k, state, c.epoch, c.tick);
    for (c.packet[0..3], 0..) |state, k| out[D.writable + k] = M.fromCanonical(state.rights >> 1);
    put(&out, D.result_before, c.packet[3].value);
    out[D.neg] = M.fromCanonical(@intFromBool(c.result < 0));
    out[D.pos] = M.fromCanonical(@intFromBool(c.result > 0));
    return out;
}
pub fn cmpRow(call: ?T.Call, j: usize, word: T.Word) [L.cmp.MAIN]M {
    var out: [L.cmp.MAIN]M = @splat(M.zero());
    const c = call orelse return out;
    const C = L.cmp;
    const remaining: u32 = c.count() - @as(u32, @intCast(j));
    const last = j + 1 == c.examined;
    out[C.active] = M.one();
    out[C.start] = M.fromCanonical(@intFromBool(j == 0));
    afterClock(&out, C.epoch, c);
    out[C.remaining] = M.fromCanonical(remaining);
    out[C.last] = M.fromCanonical(@intFromBool(last));
    out[C.is_one] = M.fromCanonical(@intFromBool(remaining == 1));
    if (remaining != 1) out[C.inv] = M.fromCanonical(remaining - 1).inv() catch unreachable;
    put(&out, C.a, c.dst + 8 * j);
    put(&out, C.b, c.word1 + 8 * j);
    if (j != 0) {
        carries(&out, C.a_carry, c.dst + 8 * (j - 1));
        carries(&out, C.b_carry, c.word1 + 8 * (j - 1));
    }
    const va = word.dst.value;
    const vb = word.src.value;
    put(&out, C.va, va);
    put(&out, C.vb, vb);
    clockBlock(&out, C.a_clock, word.dst, c.epoch, c.tick);
    clockBlock(&out, C.b_clock, word.src, c.epoch, c.tick);
    out[C.a_writable] = M.fromCanonical(word.dst.rights >> 1);
    out[C.b_writable] = M.fromCanonical(word.src.rights >> 1);
    if (va != vb) {
        const byte: u6 = @intCast(@ctz(va ^ vb) / 8);
        const limb = byte / 2;
        const x: u8 = @truncate(va >> (8 * byte));
        const y: u8 = @truncate(vb >> (8 * byte));
        out[C.diff] = M.one();
        out[C.limbsel + limb] = M.one();
        out[C.hb] = M.fromCanonical(byte & 1);
        out[C.lt] = M.fromCanonical(@intFromBool(x < y));
        out[C.alo] = M.fromCanonical(@as(u8, @truncate(va >> (16 * limb))));
        out[C.ahi] = M.fromCanonical(@as(u8, @truncate(va >> (16 * limb + 8))));
        out[C.blo] = M.fromCanonical(@as(u8, @truncate(vb >> (16 * limb))));
        out[C.bhi] = M.fromCanonical(@as(u8, @truncate(vb >> (16 * limb + 8))));
        out[C.da] = M.fromCanonical(x);
        out[C.db] = M.fromCanonical(y);
        out[C.gap] = M.fromCanonical(@as(u32, if (x < y) y - x else x - y) - 1);
    }
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
        .ucopy => {
            clockValues(out[0..3], m[L.ucopy.dst_clock..]);
            clockValues(out[3..6], m[L.ucopy.src_clock..]);
            for (0..4) |i| limbByteValues(out[6 + 3 * i ..][0..3], m[L.ucopy.bytes + 2 * i].v, m[L.ucopy.bytes + 2 * i + 1].v);
        },
        .cdesc => {
            const D = L.cdesc;
            out[0] = m[D.tick_low].v;
            out[1] = m[D.tick_high].v;
            out[2] = 256 * m[D.tick_high].v;
            out[3] = m[D.len_q0].v;
            for (0..4) |k| clockValues(out[4 + 3 * k ..][0..3], m[D.clocks + L.CLOCK * k ..]);
        },
        .cmp => {
            const C = L.cmp;
            clockValues(out[0..3], m[C.a_clock..]);
            clockValues(out[3..6], m[C.b_clock..]);
            limbByteValues(out[6..9], m[C.alo].v, m[C.ahi].v);
            limbByteValues(out[9..12], m[C.blo].v, m[C.bhi].v);
            out[12] = m[C.gap].v;
        },
    }
    return out;
}
fn limbByteValues(out: *[3]u32, lo: u32, hi: u32) void {
    out[0] = lo;
    out[1] = 256 * lo;
    out[2] = hi;
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
    /// Per active row, the call index and word index.
    row_call: []u32,
    row_word: []u32,
    /// First row of each call of this kind (unused entries 0).
    call_row: []u32,
    fixed: []M,
    main: []M,
    interaction: []M = &.{},
    owns_main: bool,
    counts16: []u64,
    counts8: []u64,

    pub fn rowsFor(kind: L.Kind, calls: []const T.Call) u64 {
        var total: u64 = 0;
        for (calls) |c| {
            if (c.descriptor() == kind) total += 1;
            if (c.body() == kind) total += c.entries();
        }
        return total;
    }
    fn isDescriptor(kind: L.Kind) bool {
        return kind == .desc or kind == .cdesc;
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
            if (offset + c.entries() > words.len) return error.InvalidBulkMemoryWords;
            try T.validateCall(c, words[offset..][0..c.entries()]);
            if (k != 0 and (c.epoch < calls[k - 1].epoch or (c.epoch == calls[k - 1].epoch and c.tick <= calls[k - 1].tick))) return error.InvalidBulkMemoryCallOrder;
            offset += c.entries();
        }
        if (offset != words.len) return error.InvalidBulkMemoryWords;
        const width = L.main(kind);
        if (buffer) |b| if (b.len != width * n) return error.InvalidBulkMemoryMain;
        const call_copy = try a.dupe(T.Call, calls);
        errdefer a.free(call_copy);
        const word_copy = try a.dupe(T.Word, words);
        errdefer a.free(word_copy);
        // Per active row: the call index and the word index (descriptor
        // kinds: the word index is unused); per call: its first row here.
        const row_call = try a.alloc(u32, total);
        errdefer a.free(row_call);
        const row_word = try a.alloc(u32, total);
        errdefer a.free(row_word);
        const call_row = try a.alloc(u32, calls.len);
        errdefer a.free(call_row);
        {
            var at: usize = 0;
            offset = 0;
            @memset(call_row, 0);
            for (calls, 0..) |c, k| {
                if (c.descriptor() == kind) {
                    call_row[k] = @intCast(at);
                    row_call[at] = @intCast(k);
                    row_word[at] = @intCast(offset);
                    at += 1;
                }
                if (c.body() == kind) {
                    call_row[k] = @intCast(at);
                    for (0..c.entries()) |j| {
                        row_call[at] = @intCast(k);
                        row_word[at] = @intCast(offset + j);
                        at += 1;
                    }
                }
                offset += c.entries();
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
        const empty = T.Word{ .dst = .{ .value = 0, .rights = 0 } };
        const active = logical < self.rows;
        const k = if (active) self.row_call[logical] else 0;
        const call: ?T.Call = if (active) self.calls[k] else null;
        const w = if (active) self.row_word[logical] else 0;
        const j = if (active) logical - self.call_row[k] else 0;
        const word = if (active and !isDescriptor(kind)) self.words[w] else empty;
        return switch (kind) {
            .desc => descRow(call),
            .cdesc => cdescRow(call),
            .copy => copyRow(call, j, word),
            .set => setRow(call, j, word),
            .ucopy => ucopyRow(call, j, word, if (active and j != 0) self.words[w - 1] else empty),
            .cmp => cmpRow(call, j, word),
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
