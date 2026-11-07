//! M9 prep, STWO_RV64_M9_WITNESS_ROWPAR (default off; nothing in the prover
//! reads this file yet): a row-parallel schedule of the recursion MAIN
//! assignment, built from the SAME authenticated device records
//! (outer_assignment_pack: kind, out, args[6]) that the task DAG runs.
//!
//! The DAG (circuit_fill_chain.cu chain_run) pays one CTA barrier plus a
//! dependent global round trip per dependency level: ~120-146 k levels per
//! leaf, 69-90% of them Blake G levels of mean width ~26 [M, M6 level census].
//! This schedule removes the depth instead of shaving the per-level constant:
//!
//! 1. Per-component generator, Blake2s: the 80 G records of one compression
//!    (10 rounds x 8, out = base + 4k) plus its 8 finalisation triple-xors are
//!    recognised structurally (state wiring of g_state_indices, message wiring
//!    of the Blake2s sigma) and become ONE unit. A thread computes the whole
//!    compression with the 16-word state in registers and stores all 80x4 G
//!    outputs and the 8 xor outputs: 20 G levels + 1 xor level -> 1 step.
//! 2. Strands: a unit whose outputs are consumed by exactly one other unit is
//!    executed by the same thread right before that consumer (path
//!    contraction: hash chains of multi-block messages, Merkle paths, Horner
//!    and running-sum accumulations). The running value of a plain chain is
//!    forwarded in a register.
//! 3. Strands are layered by longest path; one barrier per strand level.
//!
//! Exactness: every record is evaluated by the arithmetic of `at` on the same
//! input values. The plan refuses (error, so the caller keeps the DAG) unless
//! every variable has at most one producer and every static `at` failure is
//! absent (kind, out, args, Blake out+4, byte index); the only remaining
//! failures are data-dependent (kind 8/9 zero inputs), which store nothing and
//! are never forwarded, exactly as chain_run. Contracting an edge whose source
//! has a single consumer keeps the graph acyclic; a grouping that would close a
//! cycle is detected (Kahn) and refused.
const std = @import("std");

pub const Task = extern struct { kind: u32, out: u32, args: [6]u32 = @splat(0) };
pub const blake_unit_words = 48;
/// GPU record of one fused compression: base, init[16], msg[16], xout[8],
/// flags (bit 0: some G output has a consumer outside the compression, so the
/// critical pass stores the G outputs inline; otherwise they are deferred to
/// the parallel fill pass), pad.
pub const BlakeUnit = extern struct { base: u32, init: [16]u32, msg: [16]u32, xout: [8]u32, flags: u32 = 0, pad: [6]u32 = @splat(0) };
pub const blake_inline_stores: u32 = 1;
comptime {
    std.debug.assert(@sizeOf(BlakeUnit) == blake_unit_words * 4);
}
pub const blake_flag: u32 = 1 << 31;
pub const none = std.math.maxInt(u32);

pub const sigma = [10][16]u8{
    .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    .{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    .{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    .{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    .{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    .{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    .{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    .{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    .{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    .{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};
pub const g_state = [8][4]u8{
    .{ 0, 4, 8, 12 }, .{ 1, 5, 9, 13 }, .{ 2, 6, 10, 14 }, .{ 3, 7, 11, 15 },
    .{ 0, 5, 10, 15 }, .{ 1, 6, 11, 12 }, .{ 2, 7, 8, 13 }, .{ 3, 4, 9, 14 },
};

pub fn arity(kind: u32) u32 {
    return if (kind == 15) 0 else if (kind <= 3) 2 else if (kind == 4) 3 else if (kind == 6) 6 else if (kind == 9) 2 else 1;
}

pub const Options = struct {
    /// Fuse Blake2s compressions into one generator unit.
    blake: bool = true,
    /// Contract single-consumer units into strands.
    strands: bool = true,
    /// Upper bound on the serial cost of one strand (0 = none), in plain
    /// record units; a deferred-store compression costs `blake_cost`.
    max_strand_records: u32 = 0,
    blake_cost: u32 = 8,
};

pub const Stats = struct {
    dag_levels: usize = 0,
    tasks: usize = 0,
    blake_units: usize = 0,
    blake_inline: usize = 0,
    blake_tasks: usize = 0,
    plain_units: usize = 0,
    strands: usize = 0,
    levels: usize = 0,
    /// Sum over strand levels of the longest strand in records (the serial
    /// critical path the one-CTA executor walks), and of its Blake units.
    critical_records: u64 = 0,
    critical_blake: u64 = 0,
    max_level_width: usize = 0,
    max_strand_records: usize = 0,
};

pub const Plan = struct {
    allocator: std.mem.Allocator,
    /// CSR over strands (absolute strand ends per level).
    level_ends: []u32,
    /// CSR over units (absolute unit ends per strand), execution order.
    strand_ends: []u32,
    /// Plain record index, or blake_flag | blake unit index.
    units: []u32,
    blake: []BlakeUnit,
    stats: Stats,
    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.level_ends);
        self.allocator.free(self.strand_ends);
        self.allocator.free(self.units);
        self.allocator.free(self.blake);
        self.* = undefined;
    }
};

pub const Error = error{ RowparDuplicateProducer, RowparStaticFailure, RowparCycle, RowparBadLevels, OutOfMemory };

/// Outputs of record t (permutation outputs through `indices`).
fn outputsOf(t: Task, indices: []const u32, buf: *[4]u32) []const u32 {
    if (t.kind == 7) return indices[t.args[0] + t.args[1] ..][0..t.args[1]];
    if (t.kind == 6) {
        buf.* = .{ t.out, t.out + 1, t.out + 2, t.out + 3 };
        return buf[0..4];
    }
    buf[0] = t.out;
    return buf[0..1];
}
fn inputsOf(t: *const Task, indices: []const u32) []const u32 {
    if (t.kind == 7) return indices[t.args[0]..][0..t.args[1]];
    return t.args[0..arity(t.kind)];
}

/// Refuses every record on which `at` could fail for a static reason.
fn validate(tasks: []const Task, indices: []const u32, n_vars: u32) Error!void {
    for (tasks) |t| {
        if (t.kind > 15 or t.out >= n_vars) return error.RowparStaticFailure;
        if (t.kind == 7) {
            if (@as(u64, t.args[0]) + @as(u64, t.args[1]) * 2 > indices.len) return error.RowparStaticFailure;
            for (indices[t.args[0]..][0 .. 2 * @as(usize, t.args[1])]) |v| if (v >= n_vars) return error.RowparStaticFailure;
            continue;
        }
        for (t.args[0..arity(t.kind)]) |v| if (v >= n_vars) return error.RowparStaticFailure;
        if (t.kind == 6 and @as(u64, t.out) + 4 > n_vars) return error.RowparStaticFailure;
        if ((t.kind == 12 or t.kind == 13) and t.args[1] > 3) return error.RowparStaticFailure;
    }
}

pub fn build(a: std.mem.Allocator, tasks: []const Task, indices: []const u32, n_vars: u32, dag_level_ends: []const u32, options: Options) Error!Plan {
    try validate(tasks, indices, n_vars);
    const n: u32 = @intCast(tasks.len);
    var stats = Stats{ .dag_levels = dag_level_ends.len, .tasks = tasks.len };
    {
        var prev: u32 = 0;
        for (dag_level_ends) |e| {
            if (e < prev or e > n) return error.RowparBadLevels;
            prev = e;
        }
        if (prev != n) return error.RowparBadLevels;
    }
    // producer[var] = record index or none (seed).
    const producer = try a.alloc(u32, n_vars);
    defer a.free(producer);
    @memset(producer, none);
    for (tasks, 0..) |t, i| {
        var buf: [4]u32 = undefined;
        for (outputsOf(t, indices, &buf)) |v| {
            if (producer[v] != none) return error.RowparDuplicateProducer;
            producer[v] = @intCast(i);
        }
    }
    // Consumer CSR over records (record -> consuming records, with repeats).
    const cons_start = try a.alloc(u32, n + 1);
    defer a.free(cons_start);
    @memset(cons_start, 0);
    for (tasks) |*t| for (inputsOf(t, indices)) |v| {
        const p = producer[v];
        if (p != none) cons_start[p + 1] += 1;
    };
    for (1..n + 1) |i| cons_start[i] += cons_start[i - 1];
    const cons = try a.alloc(u32, cons_start[n]);
    defer a.free(cons);
    {
        const fill = try a.dupe(u32, cons_start[0..n]);
        defer a.free(fill);
        for (tasks, 0..) |*t, i| for (inputsOf(t, indices)) |v| {
            const p = producer[v];
            if (p != none) {
                cons[fill[p]] = @intCast(i);
                fill[p] += 1;
            }
        };
    }
    // unit_of[record]; blake units first claim their 88 records.
    const unit_of = try a.alloc(u32, n);
    defer a.free(unit_of);
    @memset(unit_of, none);
    var blake: std.ArrayList(BlakeUnit) = .empty;
    defer blake.deinit(a);
    var blake_records: std.ArrayList([88]u32) = .empty;
    defer blake_records.deinit(a);
    if (options.blake) {
        for (tasks, 0..) |t0, first| {
            if (t0.kind != 6 or unit_of[first] != none) continue;
            if (matchCompression(tasks, producer, cons_start, cons, @intCast(first))) |m| {
                const id: u32 = @intCast(blake.items.len);
                for (m.records) |r| unit_of[r] = blake_flag | id;
                try blake.append(a, m.unit);
                try blake_records.append(a, m.records);
            }
        }
    }
    stats.blake_units = blake.items.len;
    for (blake.items) |b| stats.blake_inline += @intFromBool(b.flags & blake_inline_stores != 0);
    stats.blake_tasks = blake.items.len * 88;
    // Dense unit ids: blake units 0..B-1, then plain records.
    const n_blake: u32 = @intCast(blake.items.len);
    var n_units: u32 = n_blake;
    for (unit_of) |*u| {
        if (u.* == none) {
            u.* = n_units;
            n_units += 1;
        } else u.* &= ~blake_flag;
    }
    stats.plain_units = n_units - n_blake;
    // unit -> member records (blake: 88 in execution order; plain: itself).
    const plain_record = try a.alloc(u32, n_units - n_blake);
    defer a.free(plain_record);
    for (unit_of, 0..) |u, r| if (u >= n_blake) {
        plain_record[u - n_blake] = @intCast(r);
    };
    const Members = struct {
        blake_records: [][88]u32,
        plain_record: []u32,
        n_blake: u32,
        fn get(self: @This(), u: u32, one: *[1]u32) []const u32 {
            if (u < self.n_blake) return &self.blake_records[u];
            one[0] = self.plain_record[u - self.n_blake];
            return one;
        }
    };
    const members = Members{ .blake_records = blake_records.items, .plain_record = plain_record, .n_blake = n_blake };
    // Unit graph (deduplicated): in-degree, single consumer unit or none.
    const indeg = try a.alloc(u32, n_units);
    defer a.free(indeg);
    @memset(indeg, 0);
    const only_consumer = try a.alloc(u32, n_units);
    defer a.free(only_consumer);
    @memset(only_consumer, none);
    const multi = try a.alloc(bool, n_units);
    defer a.free(multi);
    @memset(multi, false);
    const mark = try a.alloc(u32, n_units);
    defer a.free(mark);
    @memset(mark, none);
    for (0..n_units) |ui| {
        const u: u32 = @intCast(ui);
        var one: [1]u32 = undefined;
        for (members.get(u, &one)) |r| for (inputsOf(&tasks[r], indices)) |v| {
            const p = producer[v];
            if (p == none) continue;
            const pu = unit_of[p];
            if (pu == u or mark[pu] == u) continue;
            mark[pu] = u;
            indeg[u] += 1;
            if (only_consumer[pu] == none) only_consumer[pu] = u else if (only_consumer[pu] != u) multi[pu] = true;
        };
    }
    // Unit successor CSR (dedup via mark again) for Kahn.
    const succ_start = try a.alloc(u32, n_units + 1);
    defer a.free(succ_start);
    @memset(succ_start, 0);
    @memset(mark, none);
    for (0..n_units) |ui| {
        const u: u32 = @intCast(ui);
        var one: [1]u32 = undefined;
        for (members.get(u, &one)) |r| for (inputsOf(&tasks[r], indices)) |v| {
            const p = producer[v];
            if (p == none) continue;
            const pu = unit_of[p];
            if (pu == u or mark[pu] == u) continue;
            mark[pu] = u;
            succ_start[pu + 1] += 1;
        };
    }
    for (1..n_units + 1) |i| succ_start[i] += succ_start[i - 1];
    const succ = try a.alloc(u32, succ_start[n_units]);
    defer a.free(succ);
    {
        const fill = try a.dupe(u32, succ_start[0..n_units]);
        defer a.free(fill);
        @memset(mark, none);
        for (0..n_units) |ui| {
            const u: u32 = @intCast(ui);
            var one: [1]u32 = undefined;
            for (members.get(u, &one)) |r| for (inputsOf(&tasks[r], indices)) |v| {
                const p = producer[v];
                if (p == none) continue;
                const pu = unit_of[p];
                if (pu == u or mark[pu] == u) continue;
                mark[pu] = u;
                succ[fill[pu]] = u;
                fill[pu] += 1;
            };
        }
    }
    // Kahn topological order of units; unit longest-path level.
    const order = try a.alloc(u32, n_units);
    defer a.free(order);
    const ulevel = try a.alloc(u32, n_units);
    defer a.free(ulevel);
    @memset(ulevel, 0);
    {
        const deg = try a.dupe(u32, indeg);
        defer a.free(deg);
        var head: usize = 0;
        var tail: usize = 0;
        for (deg, 0..) |d, u| if (d == 0) {
            order[tail] = @intCast(u);
            tail += 1;
        };
        while (head < tail) : (head += 1) {
            const u = order[head];
            for (succ[succ_start[u]..succ_start[u + 1]]) |s| {
                ulevel[s] = @max(ulevel[s], ulevel[u] + 1);
                deg[s] -= 1;
                if (deg[s] == 0) {
                    order[tail] = s;
                    tail += 1;
                }
            }
        }
        if (tail != n_units) return error.RowparCycle;
    }
    // Strands: in topological order, a unit joins the strand whose tail is
    // its single-consumer producer with the greatest level (critical input).
    const strand_of = try a.alloc(u32, n_units);
    defer a.free(strand_of);
    @memset(strand_of, none);
    const next_in_strand = try a.alloc(u32, n_units);
    defer a.free(next_in_strand);
    @memset(next_in_strand, none);
    var strand_heads: std.ArrayList(u32) = .empty;
    defer strand_heads.deinit(a);
    var strand_tail: std.ArrayList(u32) = .empty;
    defer strand_tail.deinit(a);
    var strand_records: std.ArrayList(u32) = .empty;
    defer strand_records.deinit(a);
    @memset(mark, none);
    for (order) |u| {
        var best: u32 = none;
        if (options.strands and !isPermutation(tasks, members, u)) {
            var one: [1]u32 = undefined;
            for (members.get(u, &one)) |r| for (inputsOf(&tasks[r], indices)) |v| {
                const p = producer[v];
                if (p == none) continue;
                const pu = unit_of[p];
                if (pu == u or multi[pu] or only_consumer[pu] != u) continue;
                const s = strand_of[pu];
                if (strand_tail.items[s] != pu or isPermutation(tasks, members, pu)) continue;
                const cost: u32 = if (u < n_blake) options.blake_cost else 1;
                if (options.max_strand_records != 0 and strand_records.items[s] + cost > options.max_strand_records) continue;
                if (best == none or ulevel[pu] > ulevel[best]) best = pu;
            };
        }
        const cost: u32 = if (u < n_blake) options.blake_cost else 1;
        if (best != none) {
            const s = strand_of[best];
            next_in_strand[best] = u;
            strand_tail.items[s] = u;
            strand_records.items[s] += cost;
            strand_of[u] = s;
        } else {
            strand_of[u] = @intCast(strand_heads.items.len);
            try strand_heads.append(a, u);
            try strand_tail.append(a, u);
            try strand_records.append(a, cost);
        }
    }
    const n_strands: u32 = @intCast(strand_heads.items.len);
    stats.strands = n_strands;
    // Strand levels: longest path over the contracted graph, in unit
    // topological order (a strand's level is final once all its members'
    // producers are placed; members appear in topological order).
    const slevel = try a.alloc(u32, n_strands);
    defer a.free(slevel);
    @memset(slevel, 0);
    {
        // Strand graph Kahn: in-degree over distinct producer strands.
        const sdeg = try a.alloc(u32, n_strands);
        defer a.free(sdeg);
        @memset(sdeg, 0);
        const smark = try a.alloc(u32, n_strands);
        defer a.free(smark);
        @memset(smark, none);
        const ssucc_start = try a.alloc(u32, n_strands + 1);
        defer a.free(ssucc_start);
        @memset(ssucc_start, 0);
        for (0..n_strands) |si| {
            const s: u32 = @intCast(si);
            var u = strand_heads.items[s];
            while (u != none) : (u = next_in_strand[u]) {
                var one: [1]u32 = undefined;
                for (members.get(u, &one)) |r| for (inputsOf(&tasks[r], indices)) |v| {
                    const p = producer[v];
                    if (p == none) continue;
                    const ps = strand_of[unit_of[p]];
                    if (ps == s or smark[ps] == s) continue;
                    smark[ps] = s;
                    sdeg[s] += 1;
                    ssucc_start[ps + 1] += 1;
                };
            }
        }
        for (1..n_strands + 1) |i| ssucc_start[i] += ssucc_start[i - 1];
        const ssucc = try a.alloc(u32, ssucc_start[n_strands]);
        defer a.free(ssucc);
        const fill = try a.dupe(u32, ssucc_start[0..n_strands]);
        defer a.free(fill);
        @memset(smark, none);
        for (0..n_strands) |si| {
            const s: u32 = @intCast(si);
            var u = strand_heads.items[s];
            while (u != none) : (u = next_in_strand[u]) {
                var one: [1]u32 = undefined;
                for (members.get(u, &one)) |r| for (inputsOf(&tasks[r], indices)) |v| {
                    const p = producer[v];
                    if (p == none) continue;
                    const ps = strand_of[unit_of[p]];
                    if (ps == s or smark[ps] == s) continue;
                    smark[ps] = s;
                    ssucc[fill[ps]] = s;
                    fill[ps] += 1;
                };
            }
        }
        const queue = try a.alloc(u32, n_strands);
        defer a.free(queue);
        var head: usize = 0;
        var tail: usize = 0;
        for (sdeg, 0..) |d, s| if (d == 0) {
            queue[tail] = @intCast(s);
            tail += 1;
        };
        while (head < tail) : (head += 1) {
            const s = queue[head];
            for (ssucc[ssucc_start[s]..ssucc_start[s + 1]]) |t| {
                slevel[t] = @max(slevel[t], slevel[s] + 1);
                sdeg[t] -= 1;
                if (sdeg[t] == 0) {
                    queue[tail] = t;
                    tail += 1;
                }
            }
        }
        if (tail != n_strands) return error.RowparCycle;
    }
    var n_levels: u32 = 0;
    for (slevel) |l| n_levels = @max(n_levels, l + 1);
    if (n_strands == 0) n_levels = 0;
    stats.levels = n_levels;
    // Order strands by level (stable), emit CSR.
    const level_count = try a.alloc(u32, n_levels + 1);
    defer a.free(level_count);
    @memset(level_count, 0);
    for (slevel) |l| level_count[l + 1] += 1;
    for (1..n_levels + 1) |i| level_count[i] += level_count[i - 1];
    const level_ends = try a.alloc(u32, n_levels);
    errdefer a.free(level_ends);
    for (level_ends, 0..) |*e, i| e.* = level_count[i + 1];
    const strand_order = try a.alloc(u32, n_strands);
    defer a.free(strand_order);
    {
        const fill = try a.dupe(u32, level_count[0..n_levels]);
        defer a.free(fill);
        for (slevel, 0..) |l, s| {
            strand_order[fill[l]] = @intCast(s);
            fill[l] += 1;
        }
    }
    const strand_ends = try a.alloc(u32, n_strands);
    errdefer a.free(strand_ends);
    const units = try a.alloc(u32, n_units);
    errdefer a.free(units);
    var cursor: u32 = 0;
    {
        var level: usize = 0;
        var begin: usize = 0;
        while (level < n_levels) : (level += 1) {
            const end = level_ends[level];
            stats.max_level_width = @max(stats.max_level_width, end - begin);
            var worst: u32 = 0;
            var worst_blake: u32 = 0;
            for (strand_order[begin..end], begin..) |s, k| {
                var u = strand_heads.items[s];
                var blakes: u32 = 0;
                while (u != none) : (u = next_in_strand[u]) {
                    units[cursor] = if (u < n_blake) blake_flag | u else plain_record[u - n_blake];
                    blakes += @intFromBool(u < n_blake);
                    cursor += 1;
                }
                strand_ends[k] = cursor;
                if (strand_records.items[s] > worst) {
                    worst = strand_records.items[s];
                    worst_blake = blakes;
                }
                stats.max_strand_records = @max(stats.max_strand_records, strand_records.items[s]);
            }
            stats.critical_records += worst;
            stats.critical_blake += worst_blake;
            begin = end;
        }
    }
    std.debug.assert(cursor == n_units);
    return .{ .allocator = a, .level_ends = level_ends, .strand_ends = strand_ends, .units = units, .blake = try blake.toOwnedSlice(a), .stats = stats };
}

fn isPermutation(tasks: []const Task, members: anytype, u: u32) bool {
    if (u < members.n_blake) return false;
    return tasks[members.plain_record[u - members.n_blake]].kind == 7;
}

const Match = struct { unit: BlakeUnit, records: [88]u32 };

/// Structural match of one Blake2s compression whose first G record is first
/// (round 0, g 0): 80 G records at out = base + 4k in gadget order, wired
/// through g_state / sigma, and one triple-xor per output word i over
/// {init[i], v[i], v[i + 8]}.
fn matchCompression(tasks: []const Task, producer: []const u32, cons_start: []const u32, cons: []const u32, first: u32) ?Match {
    const base = tasks[first].out;
    if (@as(u64, base) + 320 > producer.len) return null;
    var m: Match = undefined;
    var v: [16]u32 = undefined;
    var have_msg: [16]bool = @splat(false);
    var k: u32 = 0;
    for (0..10) |r| for (0..8) |g| {
        const out = base + 4 * k;
        const ti = producer[out];
        if (ti == none) return null;
        const t = tasks[ti];
        if (t.kind != 6 or t.out != out) return null;
        if (r == 0 and g < 4) {
            for (0..4) |j| {
                v[g_state[g][j]] = t.args[j];
                m.unit.init[g_state[g][j]] = t.args[j];
            }
        }
        for (0..4) |j| if (t.args[j] != v[g_state[g][j]]) return null;
        for (0..2) |j| {
            const w = sigma[r][2 * g + j];
            if (!have_msg[w]) {
                m.unit.msg[w] = t.args[4 + j];
                have_msg[w] = true;
            } else if (m.unit.msg[w] != t.args[4 + j]) return null;
        }
        for (0..4) |j| v[g_state[g][j]] = out + @as(u32, @intCast(j));
        m.records[k] = ti;
        k += 1;
    };
    // An init or message variable must not be produced inside this group
    // (the gadget wires them from outside; anything else is not a match).
    for (m.unit.init) |x| if (x >= base and x < base + 320) return null;
    for (m.unit.msg) |x| if (x >= base and x < base + 320) return null;
    // Finalisation: h[i] = triple_xor(init[i], v[i], v[i + 8]).
    for (0..8) |i| {
        const pi = producer[v[i]];
        var found: u32 = none;
        for (cons[cons_start[pi]..cons_start[pi + 1]]) |c| {
            const t = tasks[c];
            if (t.kind != 4) continue;
            if (sameSet(t.args[0..3].*, .{ m.unit.init[i], v[i], v[i + 8] })) {
                if (found != none and found != c) return null;
                found = c;
            }
        }
        if (found == none) return null;
        m.unit.xout[i] = tasks[found].out;
        m.records[80 + i] = found;
    }
    m.unit.base = base;
    m.unit.flags = 0;
    m.unit.pad = @splat(0);
    // Deferral is exact only if no record outside the compression reads a G
    // output (the critical pass then needs just h); otherwise store inline.
    for (m.records[0..80]) |r| {
        for (cons[cons_start[r]..cons_start[r + 1]]) |c| {
            var inside = false;
            for (m.records) |x| if (x == c) {
                inside = true;
                break;
            };
            if (!inside) m.unit.flags |= blake_inline_stores;
        }
    }
    return m;
}

fn sameSet(x: [3]u32, y: [3]u32) bool {
    var used: [3]bool = @splat(false);
    for (x) |e| {
        var hit = false;
        for (y, 0..) |f, j| if (!used[j] and e == f) {
            used[j] = true;
            hit = true;
            break;
        };
        if (!hit) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// CPU reference executor of a rowpar plan: the `at` arithmetic over u32 limbs
// in the same strand/unit order the GPU uses. Used by the tests and the
// planner tool to prove plan-level exactness without a GPU.
const P: u64 = 0x7fffffff;
fn madd(x: u32, y: u32) u32 {
    const s = @as(u64, x) + y;
    return @intCast(if (s >= P) s - P else s);
}
fn msub(x: u32, y: u32) u32 {
    return if (x >= y) x - y else @intCast(@as(u64, x) + P - y);
}
fn mmul(x: u32, y: u32) u32 {
    return @intCast((@as(u64, x) * y) % P);
}
fn mpow(x: u32, e: u64) u32 {
    var r: u32 = 1;
    var b = x;
    var k = e;
    while (k != 0) : (k >>= 1) {
        if (k & 1 != 0) r = mmul(r, b);
        b = mmul(b, b);
    }
    return r;
}
fn minv(x: u32) u32 {
    return mpow(x, P - 2);
}
const V4 = [4]u32;
// QM31 = CM31[u]/(u^2 - (2 + i)), CM31 = M31[i]/(i^2 + 1); limbs (a.a, a.b, b.a, b.b).
fn cmul(a0: u32, a1: u32, b0: u32, b1: u32) [2]u32 {
    return .{ msub(mmul(a0, b0), mmul(a1, b1)), madd(mmul(a0, b1), mmul(a1, b0)) };
}
fn qadd(x: V4, y: V4) V4 {
    return .{ madd(x[0], y[0]), madd(x[1], y[1]), madd(x[2], y[2]), madd(x[3], y[3]) };
}
fn qsub(x: V4, y: V4) V4 {
    return .{ msub(x[0], y[0]), msub(x[1], y[1]), msub(x[2], y[2]), msub(x[3], y[3]) };
}
fn qmul(x: V4, y: V4) V4 {
    const ac = cmul(x[0], x[1], y[0], y[1]);
    const bd = cmul(x[2], x[3], y[2], y[3]);
    const ad = cmul(x[0], x[1], y[2], y[3]);
    const bc = cmul(x[2], x[3], y[0], y[1]);
    // bd * (2 + i)
    const r = cmul(bd[0], bd[1], 2, 1);
    return .{ madd(ac[0], r[0]), madd(ac[1], r[1]), madd(ad[0], bc[0]), madd(ad[1], bc[1]) };
}
fn qinv(x: V4) V4 {
    // (a + b u)^-1 = (a - b u) / (a^2 - b^2 (2 + i))
    const a2 = cmul(x[0], x[1], x[0], x[1]);
    const b2 = cmul(x[2], x[3], x[2], x[3]);
    const r = cmul(b2[0], b2[1], 2, 1);
    const d0 = msub(a2[0], r[0]);
    const d1 = msub(a2[1], r[1]);
    // CM31 inverse: (d0 - d1 i) / (d0^2 + d1^2)
    const n = minv(madd(mmul(d0, d0), mmul(d1, d1)));
    const di0 = mmul(d0, n);
    const di1 = mmul(msub(0, d1), n);
    const ra = cmul(x[0], x[1], di0, di1);
    const rb = cmul(msub(0, x[2]), msub(0, x[3]), di0, di1);
    return .{ ra[0], ra[1], rb[0], rb[1] };
}
fn isZero(x: V4) bool {
    return (x[0] | x[1] | x[2] | x[3]) == 0;
}
fn word(x: V4) u32 {
    return x[0] | (x[1] << 16);
}
fn packWord(w: u32) V4 {
    return .{ w & 65535, w >> 16, 0, 0 };
}
pub fn blakeG(a0: u32, b0: u32, c0: u32, d0: u32, f0: u32, f1: u32) [4]u32 {
    const a1 = a0 +% b0 +% f0;
    const d1 = std.math.rotr(u32, d0 ^ a1, 16);
    const c1 = c0 +% d1;
    const b1 = std.math.rotr(u32, b0 ^ c1, 12);
    const a2 = a1 +% b1 +% f1;
    const d2 = std.math.rotr(u32, d1 ^ a2, 8);
    const c2 = c1 +% d2;
    const b2 = std.math.rotr(u32, b1 ^ c2, 7);
    return .{ a2, b2, c2, d2 };
}

/// `at` of circuit_assignment.cu on host limbs. Returns false on a failing task.
pub fn at(values: []V4, indices: []const u32, t: Task, status: *u32) void {
    if (t.kind == 7) {
        const base = t.args[0];
        const count = t.args[1];
        for (0..count) |i| {
            const x = values[indices[base + i]];
            var rank: u32 = 0;
            for (0..count) |kk| {
                const y = values[indices[base + kk]];
                rank += @intFromBool(y[2] < x[2] or (y[2] == x[2] and kk < i));
            }
            values[indices[base + count + rank]] = x;
        }
        return;
    }
    var x: [6]V4 = undefined;
    for (0..arity(t.kind)) |i| x[i] = values[t.args[i]];
    const v: V4 = switch (t.kind) {
        0 => qadd(x[0], x[1]),
        1 => qsub(x[0], x[1]),
        2 => qmul(x[0], x[1]),
        3 => .{ mmul(x[0][0], x[1][0]), mmul(x[0][1], x[1][1]), mmul(x[0][2], x[1][2]), mmul(x[0][3], x[1][3]) },
        4 => packWord(word(x[0]) ^ word(x[1]) ^ word(x[2])),
        5 => packWord(x[0][0]),
        6 => {
            const o = blakeG(word(x[0]), word(x[1]), word(x[2]), word(x[3]), word(x[4]), word(x[5]));
            for (0..4) |i| values[t.out + i] = packWord(o[i]);
            return;
        },
        8 => blk: {
            if (isZero(x[0])) {
                status.* |= 1;
                return;
            }
            break :blk qinv(x[0]);
        },
        9 => blk: {
            if (isZero(x[1])) {
                status.* |= 1;
                return;
            }
            break :blk qmul(x[0], qinv(x[1]));
        },
        10 => .{ if (x[0][0] != 0) minv(x[0][0]) else 0, if (x[0][1] != 0) minv(x[0][1]) else 0, if (x[0][2] != 0) minv(x[0][2]) else 0, if (x[0][3] != 0) minv(x[0][3]) else 0 },
        11 => .{ x[0][0] & 1, x[0][1] & 1, x[0][2] & 1, x[0][3] & 1 },
        12, 13 => blk: {
            const octet = (word(x[0]) >> @intCast(t.args[1] * 8)) & 255;
            break :blk .{ if (t.kind == 12) octet else 255 - octet, 0, 0, 0 };
        },
        14 => .{ if (isZero(x[0])) 0 else 1, 0, 0, 0 },
        15 => .{ 0, 0, 0, 0 },
        else => unreachable,
    };
    values[t.out] = v;
}

/// Fused compression: identical stores to its 80 G records + 8 xors.
/// `phase`: .full stores all 328 outputs; .h stores only the 8 finalisation
/// outputs (critical pass); .fill stores only the 320 G outputs (deferred
/// parallel pass, after every input is final).
pub const Phase = enum { full, h, fill };
pub fn runBlake(values: []V4, u: BlakeUnit) void {
    runBlakePhase(values, u, .full);
}
pub fn runBlakePhase(values: []V4, u: BlakeUnit, phase: Phase) void {
    var v: [16]u32 = undefined;
    for (0..16) |i| v[i] = word(values[u.init[i]]);
    var init_words: [8]u32 = undefined;
    for (0..8) |i| init_words[i] = v[i];
    var msg: [16]u32 = undefined;
    for (0..16) |i| msg[i] = word(values[u.msg[i]]);
    var k: u32 = 0;
    for (0..10) |r| for (0..8) |g| {
        const s = g_state[g];
        const o = blakeG(v[s[0]], v[s[1]], v[s[2]], v[s[3]], msg[sigma[r][2 * g]], msg[sigma[r][2 * g + 1]]);
        for (0..4) |j| {
            v[s[j]] = o[j];
            if (phase != .h) values[u.base + 4 * k + j] = packWord(o[j]);
        }
        k += 1;
    };
    if (phase == .fill) return;
    for (0..8) |i| values[u.xout[i]] = packWord(init_words[i] ^ v[i] ^ v[i + 8]);
}

/// Executes the rowpar plan on host limbs (strand-serial, level order).
/// Two passes, as on the GPU: the critical pass (compressions with deferred
/// stores write only h), then the parallel G fill of the deferred ones.
pub fn execute(plan: *const Plan, tasks: []const Task, indices: []const u32, values: []V4, status: *u32) void {
    for (plan.units) |u| {
        if (u & blake_flag != 0) {
            const b = plan.blake[u & ~blake_flag];
            runBlakePhase(values, b, if (b.flags & blake_inline_stores != 0) .full else .h);
        } else at(values, indices, tasks[u], status);
    }
    for (plan.blake) |b| if (b.flags & blake_inline_stores == 0) runBlakePhase(values, b, .fill);
}

/// Executes the DAG in record order (the level order chain_run uses).
pub fn executeDag(tasks: []const Task, indices: []const u32, values: []V4, status: *u32) void {
    for (tasks) |t| at(values, indices, t, status);
}

test {
    _ = @import("plan_test.zig");
}
