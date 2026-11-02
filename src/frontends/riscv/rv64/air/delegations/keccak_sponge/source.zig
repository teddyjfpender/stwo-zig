//! Native witness rows for the two Keccak-sponge kinds. Call metadata and the
//! natively computed permutation states survive MAIN ownership transfer;
//! interaction generation recomputes rows from them.
const std = @import("std");
const core = @import("stwo_core");
const R = @import("../../memory/closed_ram/mod.zig");
const L = @import("layout.zig");
const T = @import("types.zig");
const M = core.fields.m31.M31;

pub fn physical(row: usize, log: u32) usize {
    return R.trace.physical(row, log);
}
fn m(value: u64) M {
    return M.fromCanonical(@intCast(value));
}
fn put(out: []M, at: usize, value: u64) void {
    for (0..4) |i| out[at + i] = M.fromCanonical(@as(u16, @truncate(value >> @as(u6, @intCast(16 * i)))));
}
fn putBytes(out: []M, at: usize, value: u64) void {
    for (0..8) |i| out[at + i] = M.fromCanonical(@as(u8, @truncate(value >> @as(u6, @intCast(8 * i)))));
}
/// Carries of `base + step` limb by limb (three Boolean carries).
fn carries(out: []M, at: usize, base: u64, step: u32) void {
    var carry: u32 = step;
    for (0..3) |i| {
        carry = (@as(u32, @as(u16, @truncate(base >> @as(u6, @intCast(16 * i))))) + carry) >> 16;
        out[at + i] = M.fromCanonical(carry);
    }
}
fn clockBlock(out: []M, at: usize, state: T.State, epoch: u16, tick: u24) void {
    out[at + L.clock.epoch] = m(state.epoch);
    out[at + L.clock.low] = m(@as(u16, @truncate(state.tick)));
    out[at + L.clock.high] = m(state.tick >> 16);
    if (state.epoch == epoch) {
        const gap = tick - state.tick - 1;
        out[at + L.clock.same] = M.one();
        out[at + L.clock.gap16] = m(@as(u16, @truncate(gap)));
        out[at + L.clock.gap8] = m(gap >> 16);
    } else {
        out[at + L.clock.same] = M.zero();
        out[at + L.clock.gap16] = m(epoch - state.epoch - 1);
        out[at + L.clock.gap8] = M.zero();
    }
}
fn afterClock(out: []M, at: usize, call: T.Call) void {
    out[at] = m(call.epoch);
    out[at + 1] = m(@as(u16, @truncate(call.tick)));
    out[at + 2] = m(call.tick >> 16);
}

/// `id` is the IO11 ID of the call's first permutation.
pub fn callRow(call: ?T.Call, id: u32, last_out: [25]u64) [L.call.MAIN]M {
    var out: [L.call.MAIN]M = @splat(M.zero());
    const c = call orelse return out;
    const C = L.call;
    const p = c.p();
    out[C.active] = M.one();
    put(&out, C.pointer, c.pointer);
    for (0..3) |k| carries(&out, C.pcarry + 3 * k, c.pointer + 8 * k, 8);
    afterClock(&out, C.epoch, c);
    put(&out, C.state, p.state);
    out[C.shift + @as(usize, p.shift())] = M.one();
    out[C.in_q0] = m(@as(u16, @truncate(p.input)) >> 3);
    for (0..3) |i| out[C.in_hi + i] = m(@as(u16, @truncate(p.input >> @as(u6, @intCast(16 * (i + 1))))));
    out[C.len0] = m(@as(u16, @truncate(p.len)));
    out[C.len1] = m(p.len >> 16);
    out[C.fin] = m(@intFromBool(p.finalize()));
    out[C.fresh] = m(@intFromBool(p.fresh()));
    out[C.q] = m(p.len / T.RATE);
    out[C.r] = m(p.len % T.RATE);
    if (p.len == 0) out[C.zero] = M.one() else out[C.zinv] = M.fromCanonical(@intCast(p.len)).inv() catch unreachable;
    if (p.len != 0) out[C.e] = m((@as(u64, p.shift()) + p.len - 1) % 8);
    out[C.words] = m(p.words());
    out[C.id] = m(id);
    for (c.packet, 0..) |s, k| {
        clockBlock(&out, C.pclock + L.CLOCK * k, s, c.epoch, c.tick);
        out[C.pwritable + k] = m(s.rights >> 1);
    }
    for (c.state, 0..) |s, l| {
        clockBlock(&out, C.sclock + L.CLOCK * l, s, c.epoch, c.tick);
        if (l != 0) carries(&out, C.scarry + 3 * (l - 1), p.state, @intCast(8 * l));
        putBytes(&out, C.old + 8 * l, s.value);
        putBytes(&out, C.new + 8 * l, last_out[l]);
    }
    return out;
}

/// Row `k` (block index) of a call's permutation run.
pub fn permRow(call: ?T.Call, words: []const T.State, k: u32, perms: []const [2][25]u64) [L.perm.MAIN]M {
    var out: [L.perm.MAIN]M = @splat(M.zero());
    const c = call orelse return out;
    const P = L.perm;
    const p = c.p();
    const count = c.permutations();
    const w: u64 = p.words();
    const fin = p.finalize();
    out[P.active] = M.one();
    out[P.first] = m(@intFromBool(k == 0));
    out[P.last] = m(@intFromBool(k + 1 == count));
    out[P.lastfin] = m(@intFromBool(k + 1 == count and fin));
    out[P.freshfirst] = m(@intFromBool(k == 0 and p.fresh()));
    afterClock(&out, P.epoch, c);
    out[P.fin] = m(@intFromBool(fin));
    out[P.shift + @as(usize, p.shift())] = M.one();
    const base = p.base() + T.RATE * @as(u64, k);
    put(&out, P.base, base);
    if (k != 0) carries(&out, P.bcarry, base - T.RATE, T.RATE);
    out[P.rb] = m(p.len - T.RATE * @as(u64, k));
    out[P.wr] = m(if (k == 0) w else w - @min(w, 17 * @as(u64, k) + 1));
    var pre: [25]u64 = undefined;
    if (k != 0) {
        pre = perms[k - 1][1];
    } else if (p.fresh()) {
        pre = @splat(0);
    } else for (&pre, c.state) |*v, s| {
        v.* = s.value;
    }
    for (pre, 0..) |v, l| putBytes(&out, P.pre + 8 * l, v);
    var values: [T.SLOTS]u64 = @splat(0);
    var reads: [T.SLOTS]bool = @splat(false);
    for (0..T.SLOTS) |j| {
        const index = 17 * @as(u64, k) + j;
        reads[j] = index < w and (j != 0 or k == 0);
        if (index < w) values[j] = words[index].value;
    }
    var block: [T.RATE]u8 = undefined;
    for (0..T.RATE) |t| {
        const stream = T.RATE * @as(u64, k) + t;
        block[t] = if (stream < p.len) T.Native.byteAt(values[0..], @as(u64, p.shift()) + t) else 0;
        out[P.mask + t] = m(@intFromBool(stream < p.len));
    }
    if (fin and k + 1 == count) {
        block[p.len - T.RATE * @as(u64, k)] ^= 0x01;
        block[T.RATE - 1] ^= 0x80;
    }
    for (0..T.RATE) |t| {
        const x: u8 = @truncate(pre[t / 8] >> @as(u6, @intCast(8 * (t % 8))));
        out[P.msg + t] = m(block[t]);
        out[P.and_ + t] = m(x & block[t]);
    }
    for (0..T.SLOTS) |j| {
        putBytes(&out, P.window + 8 * j, values[j]);
        out[P.read + j] = m(@intFromBool(reads[j]));
        if (j != 0) carries(&out, P.wcarry + 3 * (j - 1), base, @intCast(8 * j));
        if (reads[j]) {
            const s = words[17 * @as(u64, k) + j];
            clockBlock(&out, P.wclock + L.CLOCK * j, s, c.epoch, c.tick);
            out[P.wwritable + j] = m(s.rights >> 1);
        }
    }
    return out;
}

/// Lookup values of one row in fraction order: U16, U8, and AND table rows.
pub fn range16Values(comptime kind: L.Kind, r: []const M) [L.range16Count(kind)]u32 {
    var out: [L.range16Count(kind)]u32 = undefined;
    switch (kind) {
        .call => {
            const C = L.call;
            out[0] = r[C.tick_low].v;
            out[1] = r[C.in_q0].v;
            out[2] = r[C.q].v;
            out[3] = 4096 * r[C.len1].v;
            for (0..4) |k| out[4 + k] = r[C.pclock + L.CLOCK * k + L.clock.gap16].v;
            for (0..25) |l| out[8 + l] = r[C.sclock + L.CLOCK * l + L.clock.gap16].v;
        },
        .perm => for (0..T.SLOTS) |j| {
            out[j] = r[L.perm.wclock + L.CLOCK * j + L.clock.gap16].v;
        },
    }
    return out;
}
pub fn range8Values(comptime kind: L.Kind, r: []const M) [L.range8Count(kind)]u32 {
    var out: [L.range8Count(kind)]u32 = undefined;
    switch (kind) {
        .call => {
            const C = L.call;
            out[0..5].* = .{ r[C.tick_high].v, r[C.r].v, r[C.r].v + 120, r[C.e].v, r[C.e].v + 248 };
            for (0..4) |k| out[5 + k] = r[C.pclock + L.CLOCK * k + L.clock.gap8].v;
            for (0..25) |l| out[9 + l] = r[C.sclock + L.CLOCK * l + L.clock.gap8].v;
        },
        .perm => {
            const P = L.perm;
            for (0..T.SLOTS) |j| out[j] = r[P.wclock + L.CLOCK * j + L.clock.gap8].v;
            for (0..T.SLOTS) |j| for (0..4) |i| {
                out[T.SLOTS + 4 * j + i] = r[P.window + 8 * j + 2 * i + 1].v;
            };
        },
    }
    return out;
}

pub fn fixed(a: std.mem.Allocator, log: u32) ![]M {
    const n = @as(usize, 1) << @intCast(log);
    const out = try a.alloc(M, L.FIXED * n);
    @memset(out, M.zero());
    for (0..n) |row| {
        const p = physical(row, log);
        out[p] = m(row);
        out[n + p] = m(@intFromBool(row == 0));
        out[2 * n + p] = m(@intFromBool(row == n - 1));
    }
    return out;
}

/// All admitted calls of one CPU proof (chronological), their message word
/// predecessors (concatenated) and natively computed permutation states.
pub const Plan = struct {
    calls: []T.Call,
    words: []T.State,
    /// Per permutation row: input and output state.
    perms: [][2][25]u64,
    /// Per permutation row: owning call index.
    row_call: []u32,
    pub fn init(a: std.mem.Allocator, calls: []const T.Call, words: []const T.State) !Plan {
        var total_words: usize = 0;
        var total_perms: usize = 0;
        for (calls, 0..) |c, k| {
            if (c.first_word != total_words or c.first_perm != total_perms) return error.InvalidKeccakSpongeCallOrder;
            if (total_words + c.words() > words.len) return error.InvalidKeccakSpongeWords;
            try T.validateCall(c, words[total_words..][0..c.words()]);
            if (k != 0 and (c.epoch < calls[k - 1].epoch or (c.epoch == calls[k - 1].epoch and c.tick <= calls[k - 1].tick))) return error.InvalidKeccakSpongeCallOrder;
            total_words += c.words();
            total_perms += c.permutations();
        }
        if (total_words != words.len) return error.InvalidKeccakSpongeWords;
        const call_copy = try a.dupe(T.Call, calls);
        errdefer a.free(call_copy);
        const word_copy = try a.dupe(T.State, words);
        errdefer a.free(word_copy);
        const perms = try a.alloc([2][25]u64, total_perms);
        errdefer a.free(perms);
        const row_call = try a.alloc(u32, total_perms);
        errdefer a.free(row_call);
        for (calls, 0..) |c, k| {
            const computed = try T.permutations(a, c, words[c.first_word..][0..c.words()]);
            defer a.free(computed);
            @memcpy(perms[c.first_perm..][0..computed.len], computed);
            @memset(row_call[c.first_perm..][0..computed.len], @intCast(k));
        }
        return .{ .calls = call_copy, .words = word_copy, .perms = perms, .row_call = row_call };
    }
    pub fn deinit(self: *Plan, a: std.mem.Allocator) void {
        a.free(self.calls);
        a.free(self.words);
        a.free(self.perms);
        a.free(self.row_call);
        self.* = undefined;
    }
    pub fn rows(self: *const Plan, kind: L.Kind) u32 {
        return @intCast(if (kind == .call) self.calls.len else self.perms.len);
    }
    pub fn row(self: *const Plan, comptime kind: L.Kind, logical: usize, first_id: u32) [L.main(kind)]M {
        switch (kind) {
            .call => {
                if (logical >= self.calls.len) return callRow(null, 0, undefined);
                const c = self.calls[logical];
                return callRow(c, first_id + c.first_perm, self.perms[c.first_perm + c.permutations() - 1][1]);
            },
            .perm => {
                if (logical >= self.perms.len) return permRow(null, &.{}, 0, &.{});
                const c = self.calls[self.row_call[logical]];
                return permRow(c, self.words[c.first_word..][0..c.words()], @intCast(logical - c.first_perm), self.perms[c.first_perm..][0..c.permutations()]);
            },
        }
    }
};

/// One kind's committed rows. The plan is shared by both kinds of one CPU proof.
pub const Source = struct {
    allocator: std.mem.Allocator,
    kind: L.Kind,
    log_size: u32,
    rows: u32,
    first_id: u32,
    plan: *const Plan,
    fixed: []M,
    main: []M,
    interaction: []M = &.{},
    owns_main: bool,
    counts16: []u64,
    counts8: []u64,
    /// AND table multiplicities (65536 rows, x * 256 + y); empty for `call`.
    counts_and: []u64,
    pub fn init(a: std.mem.Allocator, kind: L.Kind, plan: *const Plan, first_id: u32, log: u32) !Source {
        return create(a, kind, plan, first_id, log, null);
    }
    pub fn initWithMainBuffer(a: std.mem.Allocator, kind: L.Kind, plan: *const Plan, first_id: u32, log: u32, main: []M) !Source {
        return create(a, kind, plan, first_id, log, main);
    }
    fn create(a: std.mem.Allocator, kind: L.Kind, plan: *const Plan, first_id: u32, log: u32, buffer: ?[]M) !Source {
        const total = plan.rows(kind);
        const n = try T.validateGeometry(kind, total, log);
        if (first_id == 0 or @as(u64, first_id) + plan.perms.len >= core.fields.m31.Modulus) return error.InvalidKeccakSpongeGeometry;
        const width = L.main(kind);
        if (buffer) |b| if (b.len != width * n) return error.InvalidKeccakSpongeMain;
        const f = try fixed(a, log);
        errdefer a.free(f);
        const c16 = try a.alloc(u64, 65536);
        errdefer a.free(c16);
        @memset(c16, 0);
        const c8 = try a.alloc(u64, 256);
        errdefer a.free(c8);
        @memset(c8, 0);
        const cand = try a.alloc(u64, if (kind == .perm) 65536 else 0);
        errdefer a.free(cand);
        @memset(cand, 0);
        const main = if (buffer) |b| b else try a.alloc(M, width * n);
        const self = Source{ .allocator = a, .kind = kind, .log_size = log, .rows = total, .first_id = first_id, .plan = plan, .fixed = f, .main = main, .owns_main = buffer == null, .counts16 = c16, .counts8 = c8, .counts_and = cand };
        switch (kind) {
            inline else => |k| for (0..n) |logical| {
                const values = plan.row(k, logical, first_id);
                for (values, 0..) |v, col| main[col * n + physical(logical, log)] = v;
                for (range16Values(k, &values)) |v| c16[v] += 1;
                for (range8Values(k, &values)) |v| c8[v] += 1;
                if (k == .perm) for (0..T.RATE) |t| {
                    cand[values[L.perm.pre + t].v * 256 + values[L.perm.msg + t].v] += 1;
                };
            },
        }
        return self;
    }
    pub fn size(self: *const Source) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn releaseMain(self: *Source) void {
        if (self.owns_main) self.allocator.free(self.main);
        self.main = &.{};
        self.owns_main = false;
    }
    pub fn deinit(self: *Source) void {
        self.releaseMain();
        const a = self.allocator;
        a.free(self.fixed);
        a.free(self.counts16);
        a.free(self.counts8);
        a.free(self.counts_and);
        a.free(self.interaction);
        self.* = undefined;
    }
    pub fn generate(self: *Source, ch: T.Challenges, dict16: []const T.Q, dict8: []const T.Q) !T.Claims {
        return @import("interaction.zig").generate(self, ch, dict16, dict8);
    }
};
