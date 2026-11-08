//! Source-derived upper bound for the legacy M31/Blake32 native PCS pipeline.
//! Every C-owned allocation request is rounded separately. Summing requests
//! deliberately charges phase reuse twice and assumes coefficient copies and a
//! cold domain cache. The opt-in rolling phase bound requires native joined
//! retirement and zero idle retention. Neither bound is an exact process peak.
//! No allocations occur here; no device pointers are dereferenced. Host cost
//! and production plan enforcement remain unqualified, so this cannot enable
//! the global planner's PCS coverage bit by itself.
const std = @import("std");
const Abi = @import("pcs_native_abi.zig");
const Admission = @import("global_admission.zig");
const Stream = @import("trace_stream_plan.zig");

pub const Format = enum { m31_blake32 };
pub const Kind = enum { immutable_fixed, coefficient_copy, arena, source_twiddles, trace_roots, metadata, domain_cold, transcript, sample_scratch, deep, trace_tree, trace_values, trace_paths, fri, late_trace };
pub const Lifetime = enum { persistent, before_late, late };
pub const Allocation = struct { kind: Kind, words: u64, bytes: u64, rounded: Admission.Footprint, lifetime: Lifetime };
pub const Options = struct {
    /// Producer checks native retirement capability and frozen zero idle cap.
    phase_retirement: bool = false,
    compact_eager: bool = false,
    format: Format = .m31_blake32,
    rolling_beta2: bool = false,
    /// Monotonic per-session fact: canonical domain stays resident to destroy.
    domain_cached: bool = false,
    /// Producer promise: one sorted retained lease/tree. Strict runtime plans
    /// validate the complete pointer/token/generation roster before borrowing.
    borrowed_trees: [4]bool = @splat(false),
    /// Freeze this from the host environment before requesting a permit.
    /// Zero means the unstreamed late trace rebuild, matching pcsStreamBudget.
    stream_chunk_words: usize = Stream.default_chunk_words,
};
pub fn optionsFromEnv() !Options {
    var result: Options = .{};
    if (std.posix.getenv("STWO_RV64_PCS_PHASE_BOUND")) |v| result.phase_retirement = std.mem.eql(u8, v, "1");
    if (result.phase_retirement) {
        const cap = std.posix.getenv("STWO_RV64_PCS_IDLE_CACHE_BYTES") orelse return error.PcsPhaseBoundNeedsZeroIdleCache;
        if (!std.mem.eql(u8, cap, "0")) return error.PcsPhaseBoundNeedsZeroIdleCache;
    }
    if (std.posix.getenv("STWO_RV64_COMPACT_EAGER_STATE")) |v| result.compact_eager = std.mem.eql(u8, v, "1");
    if (std.posix.getenv("STWO_RV64_PCS_ROLLING_BETA2")) |v| result.rolling_beta2 = std.mem.eql(u8, v, "1");
    if (std.posix.getenv("STWO_RV64_PCS_STREAM")) |v| if (std.mem.eql(u8, v, "0")) {
        result.stream_chunk_words = 0;
        return result;
    };
    if (std.posix.getenv("STWO_RV64_PCS_STREAM_CHUNK_WORDS")) |v| {
        const n = std.fmt.parseInt(usize, v, 10) catch return error.InvalidPcsStreamBudget;
        if (n != 0) result.stream_chunk_words = n;
    }
    return result;
}
pub const Plan = struct {
    allocations: std.ArrayList(Allocation) = .empty,
    additional_upper: Admission.Footprint = .{},
    before_late_upper: Admission.Footprint = .{},
    late_survivors_upper: Admission.Footprint = .{},
    late_scratch_upper: Admission.Footprint = .{},
    phase_retirement: bool = false,
    retained_after_upper: Admission.Footprint = .{},
    requested_upper_bytes: u64 = 0,
    result_words: u64 = 0,
    rolling_sources: bool,
    selected_stream_budget: usize,
    /// Never substitute zero host cost for unknown host cost.
    host_cost_known: bool = false,
    pub fn deinit(self: *Plan, a: std.mem.Allocator) void {
        self.allocations.deinit(a);
        self.* = undefined;
    }
    pub fn includeFixedCold(self: *Plan, a: std.mem.Allocator, words: u64) !void {
        if (words != 0) try self.add(a, .immutable_fixed, words);
    }
    /// JobOwner retains retired blocks, comparing RAW word capacities for
    /// best-fit late reuse. Each external heap request is rounded to 64 words.
    /// This is a source-derived upper bound, including borrowed seed/point.
    pub fn jobWords(self: *const Plan, a: std.mem.Allocator) !u64 {
        var reusable: std.ArrayList(u64) = .empty;
        defer reusable.deinit(a);
        var words: u64 = 0;
        for (self.allocations.items) |event| if (event.lifetime != .late) {
            words = try sum(words, std.mem.alignForward(u64, @max(event.words, 1), 64));
            if (event.lifetime == .before_late) try reusable.append(a, event.words);
        };
        for (self.allocations.items) |event| if (event.lifetime == .late) {
            var best: ?usize = null;
            for (reusable.items, 0..) |capacity, i| if (capacity >= event.words and (best == null or capacity < reusable.items[best.?])) {
                best = i;
            };
            if (best) |i| {
                _ = reusable.swapRemove(i);
            } else words = try sum(words, std.mem.alignForward(u64, @max(event.words, 1), 64));
        };
        return words;
    }
    fn add(self: *Plan, a: std.mem.Allocator, kind: Kind, words: u64) !void {
        return self.addLifetime(a, kind, words, .persistent);
    }
    fn addLifetime(self: *Plan, a: std.mem.Allocator, kind: Kind, words: u64, lifetime: Lifetime) !void {
        const bytes = try mul(words, 4);
        const rounded = try Admission.Footprint.allocation(bytes);
        const actual_lifetime: Lifetime = if (!self.rolling_sources and lifetime == .before_late) .persistent else lifetime;
        switch (actual_lifetime) {
            .persistent => {
                self.before_late_upper = try self.before_late_upper.add(rounded);
                self.late_survivors_upper = try self.late_survivors_upper.add(rounded);
            },
            .before_late => self.before_late_upper = try self.before_late_upper.add(rounded),
            .late => self.late_scratch_upper = try self.late_scratch_upper.add(rounded),
        }
        self.additional_upper = if (self.phase_retirement)
            self.before_late_upper.max(try self.late_survivors_upper.add(self.late_scratch_upper))
        else
            try self.before_late_upper.add(self.late_scratch_upper);
        if (kind == .domain_cold or kind == .immutable_fixed) self.retained_after_upper = try self.retained_after_upper.add(rounded);
        self.requested_upper_bytes = try sum(self.requested_upper_bytes, bytes);
        try self.allocations.append(a, .{ .kind = kind, .words = words, .bytes = bytes, .rounded = rounded, .lifetime = actual_lifetime });
    }
};
fn sum(x: u64, y: u64) !u64 {
    return std.math.add(u64, x, y);
}

test "job retained-block bound preserves charges and compares unrounded capacities" {
    var p = Plan{ .rolling_sources = true, .selected_stream_budget = 0 };
    defer p.deinit(std.testing.allocator);
    try p.add(std.testing.allocator, .metadata, 64);
    try p.addLifetime(std.testing.allocator, .deep, 65, .before_late);
    try p.addLifetime(std.testing.allocator, .late_trace, 100, .late);
    // 65 raw words cannot satisfy 100, even though both round to 128.
    try std.testing.expectEqual(@as(u64, 320), try p.jobWords(std.testing.allocator));
    try p.addLifetime(std.testing.allocator, .late_trace, 64, .late);
    // Reuse the retired block but keep its full original charge.
    try std.testing.expectEqual(@as(u64, 320), try p.jobWords(std.testing.allocator));
}
fn mul(x: u64, y: u64) !u64 {
    return std.math.mul(u64, x, y);
}
fn pow(log: u32) !u64 {
    if (log > 28) return error.InvalidPcsCostGeometry;
    return @as(u64, 1) << @intCast(log);
}
fn span(request: *const Abi.Request, index: usize, count: u64) ![]const u32 {
    const s = request.sections[index];
    if (s.count != count or count > std.math.maxInt(usize) or (count != 0 and s.words == null)) return error.InvalidPcsCostSpan;
    return if (count == 0) &.{} else s.words.?[0..@intCast(count)];
}
fn pair(lo: u32, hi: u32) u64 {
    return @as(u64, lo) | (@as(u64, hi) << 32);
}
fn prefixWords(groups: []const u32) !u64 {
    var banks: [2]u64 = .{ 0, 0 };
    var bank: u1 = 0;
    var i: usize = 0;
    while (i + 8 < groups.len) : (i += 8) {
        if (groups[i + 3] != groups[i + 11]) {
            banks[bank] = try pow(groups[i + 3]);
            bank ^= 1;
        }
    }
    return mul(try sum(banks[0], banks[1]), 24);
}
fn treeWords(log: u32) !u64 {
    return mul((try mul(try pow(log), 2)) - 1, 8);
}

pub fn init(a: std.mem.Allocator, request: *const Abi.Request, options: Options) !Plan {
    return initMode(a, request, options, false);
}
/// Geometry-only descriptors deliberately contain no coefficient or FFT data
/// pointers and cannot be submitted to the native prover. Scalar source framing
/// and every allocation count are validated identically.
pub fn initGeometry(a: std.mem.Allocator, request: *const Abi.Request, options: Options) !Plan {
    return initMode(a, request, options, true);
}
fn initMode(a: std.mem.Allocator, request: *const Abi.Request, options: Options, geometry_only: bool) !Plan {
    _ = options.format; // The only accepted enum value is explicitly Blake32.
    if (request.version != 1 or request.section_count != 17) return error.UnsupportedPcsCostFormat;
    const h = try span(request, 0, request.sections[0].count);
    if ((h.len != 24 and h.len != 28) or h[0] != 0x52564d53 or h[2] != 0 or
        !((h[1] == 2 and h.len == 24) or (h[1] == 3 and h.len == 28)) or
        h[21] > 1 or h[22] > 32 or h[23] != 0) return error.UnsupportedPcsCostFormat;
    if (h[3] > 28 or h[4] > 28 or h[5] == 0 or h[5] > 4 or h[3] + h[5] != h[4] or h[6] == 0 or h[6] > 1024 or
        h[8] == 0 or h[8] > 65536 or h[9] == 0 or h[9] > 65536 or
        h[10] == 0 or h[10] > 1024 or h[11] == 0 or h[11] > 96 or
        h[12] == 0 or h[12] > 4 or h[13] == 0 or h[13] > 65536 or h[14] > 28 or
        request.coefficient_count != h[8]) return error.InvalidPcsCostGeometry;
    var aggregate: [4]u64 = undefined;
    for (&aggregate, 0..) |*n, i| {
        n.* = pair(h[15 + i], if (h[1] == 3) h[24 + i] else 0);
        if (n.* > @as(u64, 1) << 48) return error.InvalidPcsCostGeometry;
    }
    const sc: u64 = h[8];
    const tc: u64 = h[9];
    const gc: u64 = h[10];
    const sgc: u64 = h[11];
    const nt: u64 = h[12];
    const queries: u64 = h[6];
    const sizes = [_]u64{ h.len, 9, if (h[21] != 0) 16 else 0, sc * 4, tc * 4, gc * 8, sgc * 8, nt * 6, gc * 4, gc * 2, h[13], sc, h[19], @as(u64, h[14]) * 8, h[20], nt * 8, 4 };
    var sections: [17][]const u32 = undefined;
    for (&sections, sizes, 0..) |*s, n, i| {
        if (geometry_only and (i == 12 or i == 14) and request.sections[i].words == null) {
            if (request.sections[i].count != n) return error.InvalidPcsCostSpan;
            s.* = &.{};
        } else s.* = try span(request, i, n);
    }
    const sources = sections[3];
    const groups = sections[5];
    const source_groups = sections[6];
    const trees = sections[7];
    const fri = sections[13];
    const rolling = h[21] != 0 and (h[5] == 1 or (h[5] == 2 and options.rolling_beta2));
    var out: Plan = .{ .rolling_sources = rolling, .phase_retirement = rolling and options.phase_retirement, .selected_stream_budget = if (rolling) options.stream_chunk_words else 0 };
    errdefer out.deinit(a);
    const coefficients = request.coefficients[0..@intCast(sc)];
    for (coefficients, 0..) |c, i| {
        const n = try pow(sources[4 * i + 3]);
        const offset = pair(sources[4 * i], sources[4 * i + 1]);
        if (c.kind > 1 or (!geometry_only and c.words == null) or c.count != n or c.coefficient_log != sources[4 * i + 3] or
            offset > aggregate[0] or n > aggregate[0] - offset) return error.InvalidPcsCostGeometry;
    }
    // C++ constructs coefficient_logs by concatenating source-group widths.
    // Requiring the canonical partition in BOTH branches bounds that upload by
    // sc; otherwise duplicated groups could silently exceed the charged sc.
    var source_cursor: u64 = 0;
    for (0..@intCast(sgc)) |i| {
        const g = source_groups[i * 8 ..][0..8];
        if (g[4] != source_cursor or g[5] > sc - source_cursor) return error.InvalidPcsCostGeometry;
        for (sources[g[4] * 4 ..][0 .. g[5] * 4], 0..) |word, j| {
            if (j % 4 == 3 and word != g[2]) return error.InvalidPcsCostGeometry;
        }
        source_cursor += g[5];
    }
    if (source_cursor != sc) return error.InvalidPcsCostGeometry;
    var max_evaluations: u64 = 0;
    var max_nodes: u64 = 0;
    var max_stream: u64 = 0;
    var next_source: u64 = 0;
    var next_group: u64 = 0;
    for (0..@intCast(nt)) |t| {
        const d = trees[t * 6 ..][0..6];
        if (d[5] != 0 or d[0] > sc or d[1] > sc - d[0] or d[2] > sgc or d[3] > sgc - d[2] or d[4] > h[4]) return error.InvalidPcsCostGeometry;
        if (d[0] != next_source or d[2] != next_group) return error.InvalidPcsCostGeometry;
        next_source += d[1];
        next_group += d[3];
        var count: u64 = 0;
        for (coefficients[d[0]..][0..d[1]]) |c| count = try sum(count, c.count);
        // Always charge a copy, even if C++ can borrow one validated device lease.
        if (rolling and options.borrowed_trees[t]) {
            if (!geometry_only) {
                var next_address: usize = 0;
                var context: u64 = 0;
                var generation: u64 = 0;
                for (coefficients[d[0]..][0..d[1]], 0..) |c, i| {
                    if (c.kind != 1 or c.words == null or c.context_token == 0 or c.generation == 0) return error.InvalidPcsBorrowPromise;
                    const address = @intFromPtr(c.words.?);
                    if (i != 0 and (address != next_address or c.context_token != context or c.generation != generation)) return error.InvalidPcsBorrowPromise;
                    next_address = try std.math.add(usize, address, try std.math.mul(usize, @intCast(c.count), 4));
                    context = c.context_token;
                    generation = c.generation;
                }
            }
        } else if (rolling) try out.add(a, .coefficient_copy, count);
        var rows: std.ArrayList(u32) = .empty;
        defer rows.deinit(a);
        var evaluations: u64 = 0;
        const tree_groups = source_groups[d[2] * 8 ..][0 .. d[3] * 8];
        for (0..d[3]) |j| {
            const g = tree_groups[j * 8 ..][0..8];
            if (g[2] > 28 or g[3] > 28 or g[3] != g[2] + h[5] or g[4] > sc or g[5] > sc - g[4]) return error.InvalidPcsCostGeometry;
            if (g[3] > d[4] or (j != 0 and g[3] < tree_groups[(j - 1) * 8 + 3])) return error.InvalidPcsCostGeometry;
            if (rolling and (g[4] < d[0] or g[4] > d[0] + d[1] or g[5] > d[0] + d[1] - g[4] or
                g[6] > h[19] or g[7] > h[19] - g[6])) return error.InvalidPcsCostGeometry;
            const size = try pow(g[3]);
            evaluations = try sum(evaluations, try mul(size, g[5]));
            if (rolling and options.stream_chunk_words != 0) for (0..g[5]) |_| try rows.append(a, @intCast(size));
        }
        const nodes = try sum(try treeWords(d[4]), try prefixWords(tree_groups));
        max_evaluations = @max(max_evaluations, evaluations);
        max_nodes = @max(max_nodes, nodes);
        if (rolling and options.stream_chunk_words != 0) {
            var plan = try Stream.planSelected(a, rows.items, options.stream_chunk_words, options.compact_eager);
            defer plan.deinit(a);
            if (try pow(d[4]) < plan.leaves) return error.InvalidPcsCostGeometry;
            // C++ supports an explicitly lifted tree taller than all columns.
            const bank = plan.calls[plan.calls.len - 1].out_bank;
            plan.bank_words[bank] = @max(plan.bank_words[bank], try treeWords(d[4]));
            max_stream = @max(max_stream, plan.scratchWords());
        }
    }
    if (next_source != sc or next_group != sgc) return error.InvalidPcsCostGeometry;
    var arena = try sum(aggregate[2], aggregate[3]);
    if (!rolling) arena = try sum(arena, try sum(try sum(aggregate[0], aggregate[1]), h[19]));
    arena = try sum(arena, try mul(try sum(sc, gc * 8), 6));
    try out.addLifetime(a, .arena, arena, .before_late);
    if (rolling) {
        try out.add(a, .source_twiddles, h[19]);
        try out.add(a, .trace_roots, nt * 8);
    }
    var scratch: u64 = 0;
    var max_terms: u64 = 0;
    for (0..@intCast(gc)) |i| {
        const g = groups[i * 8 ..][0..8];
        const n = try pow(g[2]);
        const m = try pow(g[3]);
        if (g[0] >= g[1] or g[1] > tc or (rolling and g[3] != g[2] + h[5])) return error.InvalidPcsCostGeometry;
        if (rolling) {
            const co = pair(g[4], g[5]);
            const ev = pair(g[6], g[7]);
            if (co > aggregate[2] or n * 8 > aggregate[2] - co or ev > aggregate[3] or m * 8 > aggregate[3] - ev) return error.InvalidPcsCostGeometry;
        }
        const terms = g[1] - g[0];
        scratch = @max(scratch, try mul(try mul((n + 1023) / 1024, terms), 8));
        max_terms = @max(max_terms, terms);
    }
    // Match the concrete retirePlanes roster, including mixed lifetimes of
    // metadata/transcript allocations sharing the same reporting Kind.
    for ([_]u64{ h[13], @as(u64, h[13]) * 8, sc, 9, sc * 4, tc * 4, gc * 8, gc * 4 }, 0..) |n, i|
        try out.addLifetime(a, .metadata, n, if (i == 1 or i == 2) .persistent else .before_late);
    // Cold domain is an independent immutable reservation. A hit only lowers cost.
    if (!options.domain_cached) try out.add(a, .domain_cold, try mul(try pow(h[4]), 2));
    try out.addLifetime(a, .metadata, h[20], .before_late);
    for ([_]u64{ 16, 16, if (h[21] != 0) 16 else 8, (gc + 1) * 16, gc * 28 * 8, gc + 1 }, 0..) |n, i| try out.addLifetime(a, .transcript, n, if (i < 2) .persistent else .before_late);
    for ([_]u64{ scratch, scratch, max_terms }) |n| try out.addLifetime(a, .sample_scratch, n, .before_late);
    for ([_]u64{ tc * 8, 8, tc * 8, gc * 16, 2 }) |n| try out.addLifetime(a, .transcript, n, .before_late);
    try out.addLifetime(a, .deep, try mul(try pow(h[4]), 8), .before_late);
    for ([_]u64{ 8, queries, 2, 1, 8, 2, 1 }) |n| try out.add(a, .transcript, n);
    var result: u64 = 14 + 1 + 16 + nt * 8 + @as(u64, h[13]) * 8 + 2 + 8 + queries;
    for (0..@intCast(nt)) |t| {
        const d = trees[t * 6 ..][0..6];
        if (!rolling) try out.add(a, .trace_tree, try sum(try treeWords(d[4]), try prefixWords(source_groups[d[2] * 8 ..][0 .. d[3] * 8])));
        const values = @as(u64, d[1]) * queries;
        const paths = queries * d[4] * 8;
        try out.add(a, .trace_values, values);
        try out.add(a, .trace_paths, paths);
        result = try sum(result, try sum(values, paths));
    }
    try out.addLifetime(a, .fri, try mul(try pow(h[5]), 8), .before_late);
    if (rolling and h[14] != 0) try out.add(a, .fri, @as(u64, h[14]) * 8);
    for (0..h[14]) |i| {
        const d = fri[i * 8 ..][0..8];
        if (d[0] < 2 or !std.math.isPowerOfTwo(d[0]) or d[1] > 28 or d[2] > d[1] or d[2] > std.math.log2_int(u32, d[0])) return error.InvalidPcsCostGeometry;
        if (i != 0) try out.addLifetime(a, .fri, @as(u64, d[0]) * 8, .before_late);
        const values = try mul(try mul(queries, try pow(d[1])), 8);
        const paths = try mul(try mul(try mul(queries, try pow(d[1] - d[2])), std.math.log2_int(u32, d[0]) - d[2]), 8);
        try out.addLifetime(a, .fri, (@as(u64, d[0] >> @intCast(d[2])) * 2 - 1) * 8, .before_late);
        try out.addLifetime(a, .fri, 8, .before_late);
        try out.add(a, .fri, values);
        try out.add(a, .fri, paths);
        result = try sum(result, try sum(8, try sum(values, paths)));
    }
    if (rolling) {
        if (options.stream_chunk_words != 0) try out.addLifetime(a, .late_trace, max_stream, .late) else {
            try out.addLifetime(a, .late_trace, max_evaluations, .late);
            try out.addLifetime(a, .late_trace, max_nodes, .late);
        }
    }
    out.result_words = result;
    return out;
}

const Fixture = struct {
    header: [28]u32 = @splat(0),
    dummy: [64]u32 = @splat(0),
    source: [4]u32 = .{ 0, 0, 0, 4 },
    groups: [8]u32 = .{ 0, 1, 4, 5, 0, 0, 0, 0 },
    source_groups: [8]u32 = .{ 0, 0, 4, 5, 0, 1, 0, 0 },
    tree: [6]u32 = .{ 0, 1, 0, 1, 5, 0 },
    fri: [8]u32 = .{ 32, 1, 1, 0, 0, 0, 0, 0 },
    columns: [1]Abi.Column = undefined,
    fn request(self: *Fixture, beta: u32, imported: bool, wide: bool) Abi.Request {
        self.header = .{ 0x52564d53, if (wide) 3 else 2, 0, 4, 4 + beta, beta, 2, 0, 1, 1, 1, 1, 1, 1, 1, 16, (@as(u32, 16) << @intCast(beta)), 128, (@as(u32, 128) << @intCast(beta)), 0, 0, @intFromBool(imported), 0, 0, 0, 0, 0, 0 };
        self.groups[3] = 4 + beta;
        self.source_groups[3] = 4 + beta;
        self.tree[4] = 4 + beta;
        self.fri[0] = @as(u32, 16) << @intCast(beta);
        self.columns[0] = .{ .kind = 0, .coefficient_log = 4, .words = &self.dummy, .count = 16 };
        var r: Abi.Request = .{ .sections = undefined, .coefficients = &self.columns, .coefficient_count = 1 };
        const sizes = [_]u64{ if (wide) 28 else 24, 9, if (imported) 16 else 0, 4, 4, 8, 8, 6, 4, 2, 1, 1, 0, 8, 0, 8, 4 };
        for (&r.sections, sizes) |*s, n| s.* = .{ .words = &self.dummy, .count = n };
        r.sections[0].words = &self.header;
        r.sections[3].words = &self.source;
        r.sections[5].words = &self.groups;
        r.sections[6].words = &self.source_groups;
        r.sections[7].words = &self.tree;
        r.sections[13].words = &self.fri;
        return r;
    }
};
test "PCS envelope covers rolling D1 and full D2 without silently borrowing the M6 branch" {
    const a = std.testing.allocator;
    var f: Fixture = .{};
    var r = f.request(1, true, false);
    var d1 = try init(a, &r, .{});
    defer d1.deinit(a);
    try std.testing.expect(d1.rolling_sources);
    try std.testing.expect(!d1.host_cost_known);
    try std.testing.expectEqual(@as(usize, 1), countKind(d1, .coefficient_copy));
    try std.testing.expectEqual(@as(usize, 1), countKind(d1, .late_trace));
    r = f.request(2, true, true);
    var d2 = try init(a, &r, .{});
    defer d2.deinit(a);
    try std.testing.expect(!d2.rolling_sources);
    try std.testing.expectEqual(@as(usize, 0), countKind(d2, .coefficient_copy));
    try std.testing.expectEqual(@as(usize, 0), countKind(d2, .late_trace));
    try std.testing.expectEqual(@as(usize, 1), countKind(d2, .trace_tree));
    try std.testing.expect(d2.result_words > d1.result_words);
    var total: u64 = 0;
    for (d2.allocations.items) |v| total = try sum(total, v.bytes);
    try std.testing.expectEqual(total, d2.requested_upper_bytes);
}
fn countKind(p: Plan, kind: Kind) usize {
    var n: usize = 0;
    for (p.allocations.items) |v| {
        if (v.kind == kind) n += 1;
    }
    return n;
}
test "PCS envelope rejects malformed framed spans before any allocation admission" {
    const a = std.testing.allocator;
    var f: Fixture = .{};
    var r = f.request(1, true, false);
    r.sections[6].count = 7;
    try std.testing.expectError(error.InvalidPcsCostSpan, init(a, &r, .{}));
    r = f.request(1, true, true);
    f.header[24] = 65537;
    try std.testing.expectError(error.InvalidPcsCostGeometry, init(a, &r, .{}));
    r = f.request(1, true, false);
    f.fri[2] = 3;
    try std.testing.expectError(error.InvalidPcsCostGeometry, init(a, &r, .{}));
    r = f.request(1, true, false);
    f.source_groups[3] = 6;
    try std.testing.expectError(error.InvalidPcsCostGeometry, init(a, &r, .{}));
}

test "rolling phase bound covers each joined lifetime and preserves the allocation sum" {
    const a = std.testing.allocator;
    var f: Fixture = .{};
    for ([_]u32{ 1, 2 }) |beta| for ([_]usize{ 0, 16, Stream.default_chunk_words }) |budget| for ([_]bool{ false, true }) |compact| for ([_]bool{ false, true }) |cached| {
        const r = f.request(beta, true, true);
        const options = Options{ .rolling_beta2 = true, .stream_chunk_words = budget, .compact_eager = compact, .domain_cached = cached };
        var summed = try init(a, &r, options);
        defer summed.deinit(a);
        var phased_options = options;
        phased_options.phase_retirement = true;
        var phased = try init(a, &r, phased_options);
        defer phased.deinit(a);
        try std.testing.expect(phased.phase_retirement);
        try std.testing.expectEqual(summed.requested_upper_bytes, phased.requested_upper_bytes);
        try std.testing.expectEqual(summed.allocations.items.len, phased.allocations.items.len);
        try std.testing.expectEqual(summed.retained_after_upper, phased.retained_after_upper);
        var early: Admission.Footprint = .{};
        var late: Admission.Footprint = .{};
        var all: Admission.Footprint = .{};
        var persistent_metadata: usize = 0;
        for (phased.allocations.items, summed.allocations.items) |event, original| {
            try std.testing.expect(std.meta.eql(event, original));
            all = try all.add(event.rounded);
            if (event.lifetime != .late) early = try early.add(event.rounded);
            if (event.lifetime != .before_late) late = try late.add(event.rounded);
            if (event.kind == .metadata and event.lifetime == .persistent) persistent_metadata += 1;
            if (event.kind == .coefficient_copy or event.kind == .domain_cold) try std.testing.expectEqual(Lifetime.persistent, event.lifetime);
        }
        try std.testing.expectEqual(@as(usize, 2), persistent_metadata); // ordered values + coefficient logs
        try std.testing.expectEqual(all, summed.additional_upper);
        try std.testing.expectEqual(early.max(late), phased.additional_upper);
        try std.testing.expect(phased.additional_upper.contains(early));
        try std.testing.expect(phased.additional_upper.contains(late));
        try std.testing.expect(summed.additional_upper.contains(phased.additional_upper));
        try std.testing.expect(phased.additional_upper.large < summed.additional_upper.large or phased.additional_upper.small < summed.additional_upper.small);
    };
}

test "phase bound never discounts nonrolling formats and charges late-added cold FIXED in both phases" {
    const a = std.testing.allocator;
    var f: Fixture = .{};
    var r = f.request(2, true, true);
    var legacy = try init(a, &r, .{});
    defer legacy.deinit(a);
    var unavailable = try init(a, &r, .{ .phase_retirement = true });
    defer unavailable.deinit(a);
    try std.testing.expect(!unavailable.phase_retirement);
    try std.testing.expectEqual(legacy.additional_upper, unavailable.additional_upper);
    for (unavailable.allocations.items) |event| try std.testing.expectEqual(Lifetime.persistent, event.lifetime);
    r = f.request(1, true, true);
    var phased = try init(a, &r, .{ .phase_retirement = true });
    defer phased.deinit(a);
    const before = phased.additional_upper;
    const cold_words = 1 << 26;
    const fixed = try Admission.Footprint.allocation(cold_words * 4);
    try phased.includeFixedCold(a, cold_words);
    try std.testing.expectEqual(try before.add(fixed), phased.additional_upper);
    try std.testing.expect(phased.retained_after_upper.contains(fixed));
    try std.testing.expectEqual(Lifetime.persistent, phased.allocations.items[phased.allocations.items.len - 1].lifetime);
}
