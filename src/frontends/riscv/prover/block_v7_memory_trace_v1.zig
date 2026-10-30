//! Owned column-major committed-row storage. No cached proof receipts.
const std = @import("std");
const core = @import("stwo_core");
const R = @import("block_v7_memory_relations_v1.zig");
const M = R.M;
const Q = R.Q;
const Column = @import("block_v5_word_pcs_v1.zig").Column;
const Placement = @import("../air/block/memory_component_trace.zig");
const Ram = @import("block_v7_ram_component_v1.zig");
const Initial = @import("block_v7_initial_intervals_v1.zig");
const Init = @import("block_v7_initial_algebra_v1.zig");
const Word = @import("../air/block/word_memory_v5.zig");
const Original = @import("../air/block/word_memory_lanes_trace_v1.zig");
const Terminal = @import("block_v7_terminal_protocol_v1.zig");
pub const Matrix = struct {
    a: std.mem.Allocator,
    log: u32,
    storage: []M,
    columns: []Column,
    pub fn init(a: std.mem.Allocator, log: u32, count: usize, max_bytes: usize) !Matrix {
        if (log > 24 or count == 0) return error.V7MemoryResourceLimit;
        const rows = @as(usize, 1) << @intCast(log);
        const cells = try std.math.mul(usize, rows, count);
        if (try std.math.mul(usize, cells, @sizeOf(M)) > max_bytes) return error.V7MemoryResourceLimit;
        const storage = try a.alloc(M, cells);
        errdefer a.free(storage);
        @memset(storage, M.zero());
        const columns = try a.alloc(Column, count);
        errdefer a.free(columns);
        for (columns, 0..) |*c, i| c.* = .{ .log_size = log, .values = storage[i * rows ..][0..rows] };
        return .{ .a = a, .log = log, .storage = storage, .columns = columns };
    }
    pub fn deinit(self: *Matrix) void {
        self.a.free(self.columns);
        self.a.free(self.storage);
        self.* = undefined;
    }
    pub fn size(self: Matrix) usize {
        return @as(usize, 1) << @intCast(self.log);
    }
    pub fn set(self: *Matrix, column: usize, logical: usize, value: M) void {
        self.storage[column * self.size() + Placement.committedRow(logical, self.log)] = value;
    }
    pub fn get(self: Matrix, column: usize, logical: usize) M {
        return self.storage[column * self.size() + Placement.committedRow(logical, self.log)];
    }
    pub fn row(self: Matrix, comptime n: usize, offset: usize, logical: usize) [n]Q {
        var out: [n]Q = undefined;
        for (&out, 0..) |*v, i| v.* = Q.fromBase(self.get(offset + i, logical));
        return out;
    }
};
pub fn ram(a: std.mem.Allocator, original: *const Original.Trace, policy: *const Initial.Owned, terminal_policy: Terminal.Policy, max_bytes: usize) !Matrix {
    return ramWithHaltConstants(a, original, policy, try @import("block_v7_halt_algebra_v1.zig").derive(terminal_policy), max_bytes);
}
pub fn ramWithHaltConstants(a: std.mem.Allocator, original: *const Original.Trace, policy: *const Initial.Owned, halt_constants: @import("block_v7_halt_algebra_v1.zig").Constants(Q), max_bytes: usize) !Matrix {
    if (!original.sealed) return error.InvalidV7MemoryPhase;
    var out = try Matrix.init(a, original.claim.row_log, Ram.Spec.FIXED_COUNT + Ram.Spec.MAIN_COUNT, max_bytes);
    errdefer out.deinit();
    for (0..24) |i| @memcpy(out.storage[i * out.size() ..][0..out.size()], original.fixedColumn(i));
    for (0..54) |i| @memcpy(out.storage[(24 + i) * out.size() ..][0..out.size()], original.mainColumn(i));
    for (0..out.size()) |logical| {
        const f = original.fixedAt(logical);
        const r = original.rowAt(logical);
        for (0..2) |lane| {
            const event = @import("../air/block/word_memory_v5.zig").Algebra(Q).tuple(r[lane]);
            const address = try natural(event[1]) | (try natural(event[2])) << 16;
            var clock: u64 = 0;
            for (event[3..7], 0..) |limb, i| clock |= @as(u64, try natural(limb)) << @as(u6, @intCast(16 * i));
            const after = try natural(event[9]) | (try natural(event[10])) << 16;
            const halt = try @import("block_v7_halt_algebra_v1.zig").witnessWithConstants(!f[lane].active.isZero(), address, clock, after, halt_constants);
            for (halt, 0..) |value, i| out.set(24 + 76 + 6 * lane + i, logical, value);
            const ac = Ram.access(Q, f, r, lane);
            const gate = ac.gate();
            if (!gate.eql(Q.zero()) and !gate.eql(Q.one())) return error.InvalidV7FirstTouch;
            if (gate.isZero()) continue;
            const w = (try Init.witness(try policy.find(address), address, true)).columns();
            for (w, 0..) |v, i| out.set(24 + 54 + 11 * lane + i, logical, v);
        }
    }
    return out;
}
pub fn interval(a: std.mem.Allocator, policy: *const Initial.Owned, counts: []const u32, max_bytes: usize) !Matrix {
    if (counts.len != policy.intervals.len) return error.InvalidV7TableCensus;
    const log = @max(@as(u32, 4), std.math.log2_int_ceil(usize, policy.intervals.len));
    var out = try Matrix.init(a, log, 8, max_bytes);
    errdefer out.deinit();
    for (policy.intervals, counts, 0..) |item, count, i| {
        if (count >= core.fields.m31.Modulus) return error.InvalidV7TableCensus;
        out.set(0, i, M.one());
        for (item.tuple(), 0..) |v, j| out.set(1 + j, i, v);
        out.set(7, i, M.fromCanonical(count));
    }
    return out;
}
pub fn range16(a: std.mem.Allocator, counts: []const u32, max_bytes: usize) !Matrix {
    if (counts.len != 65536) return error.InvalidV7TableCensus;
    var out = try Matrix.init(a, 16, 3, max_bytes);
    errdefer out.deinit();
    for (counts, 0..) |count, i| {
        if (count >= core.fields.m31.Modulus) return error.InvalidV7TableCensus;
        out.set(0, i, M.one());
        out.set(1, i, M.fromCanonical(@intCast(i)));
        out.set(2, i, M.fromCanonical(count));
    }
    return out;
}
pub fn terminal(a: std.mem.Allocator, plan: Terminal.Plan, high_byte: u8, max_bytes: usize) !Matrix {
    var out = try Matrix.init(a, 4, 29, max_bytes);
    errdefer out.deinit();
    for (plan.fixed, 0..) |f, i| {
        const fixed = .{ f.active, f.tail } ++ f.address ++ f.clock ++ f.value;
        for (fixed, 0..) |v, j| out.set(j, i, v);
        const row = try @import("block_v7_terminal_algebra_v1.zig").witness(plan, i, high_byte);
        for (row, 0..) |v, j| out.set(10 + j, i, v);
    }
    return out;
}
pub fn natural(value: Q) !u32 {
    const limbs = value.toM31Array();
    for (limbs[1..]) |v| if (!v.isZero()) return error.InvalidV7Natural;
    return limbs[0].toU32();
}
pub fn census(matrix: Matrix, claim: @import("block_v5_ram_lanes_protocol_v1.zig").Claim, policy: *const Initial.Owned, interval_counts: []u32, range_counts: []u32) !void {
    // One independently valid partition gives each address exactly one row.
    // Keep the binary lookup's row identity instead of recovering it with an
    // O(intervals) equality scan for every distinct RAM address.
    try Initial.validatePartition(policy.intervals);
    if (interval_counts.len != policy.intervals.len or range_counts.len != 65536) return error.InvalidV7TableCensus;
    const I = Init.Algebra(Q);
    const W = Word.Algebra(Q);
    for (0..matrix.size()) |logical| {
        const f = Original.fixedPoint(Q, matrix.row(24, 0, logical), claim);
        const r = Ram.rows(Q, matrix.row(Ram.Spec.MAIN_COUNT, 24, logical));
        for (0..2) |lane| {
            const event = @import("../air/block/word_memory_v5.zig").Algebra(Q).tuple(r[lane]);
            const address = try natural(event[1]) | (try natural(event[2])) << 16;
            const ac = Ram.access(Q, f, r, lane);
            const ir = matrix.row(11, 24 + 54 + 11 * lane, logical);
            if (!ac.gate().isZero()) {
                if (!ac.gate().eql(Q.one())) return error.InvalidV7TableCensus;
                const index = try policy.findIndex(address);
                try increment(&interval_counts[index]);
            }
            for (W.rangePoints(f[lane], r[lane])) |point| try addRange(range_counts, point.value, point.weight);
            for (I.rangePoints(ac, ir)) |point| try addRange(range_counts, point.value, point.weight);
        }
    }
}
fn increment(value: *u32) !void {
    if (value.* >= core.fields.m31.Modulus - 1) return error.InvalidV7TableCensus;
    value.* += 1;
}
fn addRange(counts: []u32, value: Q, weight: Q) !void {
    if (weight.isZero()) return;
    if (!weight.eql(Q.one())) return error.InvalidV7TableCensus;
    const n = try natural(value);
    if (n >= 65536) return error.InvalidV7Range;
    try increment(&counts[n]);
}
/// Build every physical cyclic prefix and return every claimed sum; the caller
/// must absorb all sums, not a collapsed aggregate, before committing this tree.
pub fn Generated(comptime planes: usize) type {
    return struct {
        matrix: Matrix,
        sums: [planes]Q,
        pub fn deinit(self: *@This()) void {
            self.matrix.deinit();
            self.* = undefined;
        }
    };
}
/// Parallel batch inversion preserves the independent-plane protocol. Context
/// setup is performed once, before worker submission, never once per row.
pub fn interactions(comptime planes: usize, a: std.mem.Allocator, source: Matrix, context: anytype, max_bytes: usize) !Generated(planes) {
    if (comptime @hasDecl(@TypeOf(context), "prepare")) {
        return interactionsPrepared(planes, a, source, try context.prepare(source.size()), max_bytes);
    }
    return interactionsPrepared(planes, a, source, context, max_bytes);
}
fn interactionsPrepared(comptime planes: usize, a: std.mem.Allocator, source: Matrix, context: anytype, max_bytes: usize) !Generated(planes) {
    const LogUp = @import("stwo_prover_engine").air.logup_columns;
    const Adapter = struct {
        source: Matrix,
        context: @TypeOf(context),
        fn fill(self: @This(), physical: usize, fractions: []LogUp.Fraction) !void {
            const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(physical, self.source.log), self.source.log);
            const terms = try self.context.termsAt(self.source, logical);
            for (terms, fractions) |term, *fraction| {
                // Preserve the reference path's rejection even when a zero
                // numerator could otherwise hide a singular denominator.
                if (term.left.isZero() or term.right.isZero()) return error.DivisionByZero;
                const denominator = term.left.mul(term.right);
                fraction.* = .{ .denominator = denominator, .numerator = term.constant.mul(denominator).add(term.wl.mul(term.right)).add(term.wr.mul(term.left)) };
            }
        }
    };
    var out = try Matrix.init(a, source.log, planes * 4, max_bytes);
    errdefer out.deinit();
    var sums: [planes]Q = undefined;
    try LogUp.buildIndependentInto(a, source.log, out.columns, &sums, Adapter{ .source = source, .context = context }, Adapter.fill);
    return .{ .matrix = out, .sums = sums };
}
/// Scalar reference used by exact committed-matrix qualification.
pub fn interactionsReference(comptime planes: usize, a: std.mem.Allocator, source: Matrix, context: anytype, max_bytes: usize) !Generated(planes) {
    var out = try Matrix.init(a, source.log, planes * 4, max_bytes);
    errdefer out.deinit();
    var sums: [planes]Q = @splat(Q.zero());
    for (0..source.size()) |logical| {
        const ts = try context.termsAt(source, logical);
        for (ts, 0..) |term, i| {
            const fraction = try term.fraction();
            sums[i] = sums[i].add(fraction);
            for (fraction.toM31Array(), 0..) |v, j| out.set(i * 4 + j, logical, v);
        }
    }
    const normalized = try R.normalize(planes, sums, @intCast(source.size()));
    for (0..planes) |i| {
        var running = Q.zero();
        for (0..source.size()) |logical| {
            const v = Q.fromM31Array(.{ out.get(i * 4, logical), out.get(i * 4 + 1, logical), out.get(i * 4 + 2, logical), out.get(i * 4 + 3, logical) });
            running = running.add(v).sub(normalized[i]);
            for (running.toM31Array(), 0..) |x, j| out.set(i * 4 + j, logical, x);
        }
        if (!running.isZero()) return error.InvalidV7CyclicPrefix;
    }
    return .{ .matrix = out, .sums = sums };
}
