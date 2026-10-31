//! Owned/borrowed native Word16 SHIFT witnesses. Main is written once; after
//! its commitment only an owned 30-byte payload/multiplicity per row and count ledgers remain.
//! Physical table shape is external: both Word16 controls have the same truth
//! dictionary. A BYTE dictionary has a distinct semantic relation and is rejected.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const E = @import("../evaluation.zig");
const NativeFill = @import("shift_word_native_fill.zig");
const S = @import("shift_word.zig");
const P = @import("shift_word_lookup.zig");
const Table = @import("shift_word_table.zig");
const PackedTable = @import("shift_word_packed_table.zig");
const Bus = @import("function_bus.zig");
const Ops = @import("operations.zig");
const Geometry = @import("binary_source.zig");
const physical = @import("../witness.zig").physical;
const M = core.fields.m31.M31;
const Q = E.Q;
const CHUNK: usize = 4096;
pub const Fact = Ops.ShiftFact;
pub const MainBuffers = struct { main: []M };
pub const Metadata = struct {
    payload: [13]u16,
    multiplicity_words: [2]u16,
    pub fn multiplicity(self: Metadata) u32 {
        return @as(u32, self.multiplicity_words[0]) | (@as(u32, self.multiplicity_words[1]) << 16);
    }
};
comptime {
    std.debug.assert(@sizeOf(Metadata) == 30);
}
pub const Mass = struct { fact_capacity: u64, shift_queries: u64, range16_queries: u64 };
pub fn massForLog(log: u32) !Mass {
    if (log < 5 or log > 26) return error.InvalidShiftGeometry;
    const n = @as(u64, 1) << @intCast(log);
    _ = try Bus.admitPositiveMass(&.{5 * n});
    _ = try Bus.admitPositiveMass(&.{9 * n});
    return .{ .fact_capacity = n, .shift_queries = 5 * n, .range16_queries = 9 * n };
}
pub fn fixedForLog(a: std.mem.Allocator, log: u32) ![]M {
    _ = try massForLog(log);
    return Geometry.fixedForLog(a, log);
}
fn overlaps(main: []M, facts: []const Fact) bool {
    if (main.len == 0 or facts.len == 0) return false;
    const mb = @intFromPtr(main.ptr);
    const fb = @intFromPtr(facts.ptr);
    const me = std.math.add(usize, mb, std.math.mul(usize, main.len, @sizeOf(M)) catch return true) catch return true;
    const fe = std.math.add(usize, fb, std.math.mul(usize, facts.len, @sizeOf(Fact)) catch return true) catch return true;
    return mb < fe and fb < me;
}
fn nativeRow(value: ?Fact) S.RowFor(M) {
    var r = std.mem.zeroes(S.RowFor(M));
    if (value == null) {
        r.table_outputs[4][0] = M.fromCanonical(65535);
        r.table_outputs[4][2] = M.fromCanonical(65535);
        return r;
    }
    const f = value.?;
    r.active = M.one();
    r.payload[0] = M.fromCanonical(Ops.busIdFor(.shift, @intFromEnum(f.op)));
    r.selectors[@intFromEnum(f.op)] = M.one();
    for (0..4) |i| {
        const shift: u6 = @intCast(16 * i);
        r.payload[1 + i] = M.fromCanonical(@as(u16, @truncate(f.a >> shift)));
        r.payload[5 + i] = M.fromCanonical(@as(u16, @truncate(f.b >> shift)));
        r.payload[9 + i] = M.fromCanonical(@as(u16, @truncate(f.c >> shift)));
    }
    const word = @intFromEnum(f.op) >= 3;
    const amount: u32 = @intCast(f.b & 15);
    r.amount = M.fromCanonical(amount);
    r.offset[(f.b >> 4) & @as(u64, if (word) 1 else 3)] = M.one();
    r.quotient = M.fromCanonical(@as(u16, @truncate(f.b)) >> 6);
    r.ignored_w_bit = M.fromCanonical(if (word) @intCast((f.b >> 5) & 1) else 0);
    r.sign = .{ M.fromCanonical(@intCast((f.a >> 31) & 1)), M.fromCanonical(@intCast(f.a >> 63)), M.fromCanonical(@intCast((f.c >> 31) & 1)) };
    r.fill = .{ if (f.op == .sra) r.sign[1] else M.zero(), if (f.op == .sraw) r.sign[0] else M.zero() };
    for (0..5) |query| {
        const input = if (query < 4) r.payload[1 + query].v else 65535;
        const tuple = Table.tupleAt(@as(usize, input) * 16 + amount);
        for (0..4) |j| r.table_outputs[query][j] = M.fromCanonical(tuple[j + 2]);
    }
    return r;
}
fn tableIndex(meta: Metadata, query: usize) usize {
    return @as(usize, if (query < 4) meta.payload[1 + query] else 65535) * 16 + (meta.payload[5] & 15);
}
fn rangeIndex(meta: Metadata, query: usize) u16 {
    if (query < 4) return meta.payload[5 + query];
    if (query == 4) return meta.payload[5] >> 6;
    if (query == 5) return meta.payload[5] & 0xffc0;
    const limb = switch (query) {
        6 => meta.payload[2],
        7 => meta.payload[4],
        8 => meta.payload[10],
        else => unreachable,
    };
    return (limb & 32767) * 2;
}
pub const Source = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    fact_count: usize,
    function_mass: u32,
    fixed: []M,
    main: []M,
    owns_main: bool,
    interaction: []M = &.{},
    shift_counts: []u64,
    range16_counts: []u64,
    metadata: []Metadata,
    pub fn init(a: std.mem.Allocator, facts: []const Fact, log: u32) !Source {
        return initInternal(a, facts, null, log, null, engine.work_pool.currentScopedPool(), null);
    }
    pub fn initWithMainBuffers(a: std.mem.Allocator, facts: []const Fact, log: u32, buffers: MainBuffers) !Source {
        return initInternal(a, facts, null, log, buffers, engine.work_pool.currentScopedPool(), null);
    }
    pub fn initWeighted(a: std.mem.Allocator, facts: []const Fact, weights: []const u32, log: u32) !Source {
        return initInternal(a, facts, weights, log, null, engine.work_pool.currentScopedPool(), null);
    }
    pub fn initWeightedWithMainBuffers(a: std.mem.Allocator, facts: []const Fact, weights: []const u32, log: u32, buffers: MainBuffers) !Source {
        return initInternal(a, facts, weights, log, buffers, engine.work_pool.currentScopedPool(), null);
    }
    fn initInternal(a: std.mem.Allocator, facts: []const Fact, weights: ?[]const u32, log: u32, buffers: ?MainBuffers, pool: ?*engine.work_pool.WorkPool, fail_after: ?usize) !Source {
        const mass = try massForLog(log);
        const n: usize = @intCast(mass.fact_capacity);
        const length = std.math.mul(usize, P.MAIN, n) catch return error.InvalidShiftGeometry;
        if (facts.len > n) return error.ShiftCapacityExceeded;
        var function_mass: u64 = facts.len;
        if (weights) |input_weights| {
            if (input_weights.len != facts.len) return error.InvalidShiftWeights;
            function_mass = 0;
            for (input_weights) |weight| {
                if (weight >= core.fields.m31.Modulus) return error.InvalidShiftWeights;
                function_mass = try std.math.add(u64, function_mass, weight);
                if (function_mass >= core.fields.m31.Modulus) return error.ShiftMultiplicityMassExceeded;
            }
        }
        if (function_mass >= core.fields.m31.Modulus) return error.ShiftMultiplicityMassExceeded;
        if (buffers) |b| {
            if (b.main.len != length) return error.InvalidShiftMain;
            if (overlaps(b.main, facts)) return error.OverlappingShiftInputs;
            if (weights) |input_weights| {
                const mb = @intFromPtr(b.main.ptr);
                const me = std.math.add(usize, mb, std.mem.sliceAsBytes(b.main).len) catch return error.OverlappingShiftInputs;
                const wb = @intFromPtr(input_weights.ptr);
                const we = std.math.add(usize, wb, std.mem.sliceAsBytes(input_weights).len) catch return error.OverlappingShiftInputs;
                if (input_weights.len != 0 and mb < we and wb < me) return error.OverlappingShiftInputs;
            }
        }
        for (facts) |f| if (@intFromEnum(f.op) > 5 or f.c != S.nativeResult(f.op, f.a, f.b)) return error.InvalidShiftFact;
        const fixed = try fixedForLog(a, log);
        errdefer a.free(fixed);
        const range_counts = try a.alloc(u64, 65536);
        errdefer a.free(range_counts);
        const shift_counts = try a.alloc(u64, Table.SIZE);
        errdefer a.free(shift_counts);
        const metadata = try a.alloc(Metadata, n);
        errdefer a.free(metadata);
        const main = if (buffers) |b| b.main else try a.alloc(M, length);
        errdefer if (buffers == null) a.free(main);
        @memset(range_counts, 0);
        @memset(shift_counts, 0);
        const fill = NativeFill.Fill{ .facts = facts, .weights = weights, .log = log, .main = main, .metadata = metadata };
        if (comptime @import("builtin").is_test) {
            if (fail_after) |after| {
                try NativeFill.testing.failSubmission(fill, a, range_counts, shift_counts, pool orelse return error.ExpectedShiftNativePool, after);
            } else try fill.run(a, range_counts, shift_counts, pool);
        } else try fill.run(a, range_counts, shift_counts, pool);
        return .{ .allocator = a, .log_size = log, .fact_count = facts.len, .function_mass = @intCast(function_mass), .fixed = fixed, .main = main, .owns_main = buffers == null, .shift_counts = shift_counts, .range16_counts = range_counts, .metadata = metadata };
    }
    pub const testing = if (@import("builtin").is_test) struct {
        pub fn initSerial(a: std.mem.Allocator, facts: []const Fact, log: u32) !Source {
            return initInternal(a, facts, null, log, null, null, null);
        }
        pub fn initWeightedSerial(a: std.mem.Allocator, facts: []const Fact, weights: []const u32, log: u32) !Source {
            return initInternal(a, facts, weights, log, null, null, null);
        }
        pub fn failSubmission(a: std.mem.Allocator, facts: []const Fact, log: u32, buffers: MainBuffers, pool: *engine.work_pool.WorkPool, after: usize) !Source {
            return initInternal(a, facts, null, log, buffers, pool, after);
        }
    } else struct {};
    pub fn size(self: *const Source) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn releaseMain(self: *Source) void {
        if (self.owns_main) self.allocator.free(self.main);
        self.main = &.{};
        self.owns_main = false;
    }
    pub fn takeMainForCommit(self: *Source) ![]M {
        if (self.main.len == 0) return error.ShiftMainUnavailable;
        if (!self.owns_main) return error.BorrowedShiftMain;
        const data = self.main;
        self.main = &.{};
        self.owns_main = false;
        return data;
    }
    pub fn deinit(self: *Source) void {
        self.releaseMain();
        const a = self.allocator;
        a.free(self.fixed);
        a.free(self.interaction);
        a.free(self.shift_counts);
        a.free(self.range16_counts);
        a.free(self.metadata);
        self.* = undefined;
    }
    pub fn columns(self: *const Source, a: std.mem.Allocator, tree: u2) ![]engine.pcs.ColumnEvaluation {
        const data = switch (tree) {
            0 => self.fixed,
            1 => if (self.main.len != 0) self.main else return error.ShiftMainUnavailable,
            2 => if (self.interaction.len != 0) self.interaction else return error.ShiftInteractionUnavailable,
            else => return error.InvalidShiftTree,
        };
        const n = self.size();
        const columns_ = try a.alloc(engine.pcs.ColumnEvaluation, data.len / n);
        for (columns_, 0..) |*column, i| column.* = .{ .log_size = self.log_size, .values = data[i * n ..][0..n] };
        return columns_;
    }
    pub fn generate(self: *Source, ch: P.Challenges, shift_dictionary: []const Q, range_dictionary: []const Q) !P.Claims {
        const n = self.size();
        if (self.interaction.len != 0 or self.metadata.len != n or self.fact_count > n) return error.InvalidShiftSourcePhase;
        var function_mass: u64 = 0;
        for (self.metadata, 0..) |meta, i| {
            const weight = meta.multiplicity();
            if (weight >= core.fields.m31.Modulus or (i >= self.fact_count and weight != 0)) return error.InvalidShiftMetadata;
            function_mass += weight;
            if (function_mass >= core.fields.m31.Modulus) return error.InvalidShiftMetadata;
        }
        if (function_mass != self.function_mass) return error.InvalidShiftMetadata;
        if (shift_dictionary.len != Table.SIZE or range_dictionary.len != 65536 or self.shift_counts.len != Table.SIZE or self.range16_counts.len != 65536) return error.InvalidShiftDictionary;
        if (try Bus.admitPositiveMass(self.shift_counts) != 5 * n or try Bus.admitPositiveMass(self.range16_counts) != 9 * n) return error.InvalidShiftMetadata;
        try validateDictionaries(ch, shift_dictionary, range_dictionary);
        const shift_claim = countDot(self.shift_counts, shift_dictionary);
        const range_claim = countDot(self.range16_counts, range_dictionary);
        const a = self.allocator;
        const output = try a.alloc(M, P.INTERACTION * n);
        errdefer a.free(output);
        const window: usize = @min(CHUNK, n);
        const scratch = try a.alloc(Q, 2 * window);
        defer a.free(scratch);
        var shift_prefix = shift_claim.neg();
        var range_prefix = range_claim.neg();
        var function_sum = Q.zero();
        var start: usize = 0;
        while (start < n) : (start += window) {
            const count: usize = @min(window, n - start);
            functionDenominators(self.metadata[start..][0..count], scratch[0..count], ch.function);
            try core.fields.batchInverseInPlace(Q, scratch[0..count], scratch[window..][0..count]);
            for (0..count) |i| {
                const logical = start + i;
                const p = physical(logical, self.log_size);
                const meta = self.metadata[logical];
                if (logical < self.fact_count) {
                    if (meta.payload[0] < 32 or meta.payload[0] > 37) return error.InvalidShiftMetadata;
                } else for (meta.payload) |value| if (value != 0) return error.InvalidShiftMetadata;
                for (0..3) |batch| {
                    const x = shift_dictionary[tableIndex(meta, 2 * batch)];
                    var inverse = x;
                    shift_prefix = shift_prefix.add(x);
                    if (2 * batch + 1 < 5) {
                        const y = shift_dictionary[tableIndex(meta, 2 * batch + 1)];
                        inverse = inverse.mul(y);
                        shift_prefix = shift_prefix.add(y);
                    }
                    store(output, n, p, 4 * batch, inverse);
                }
                store(output, n, p, 12, shift_prefix);
                for (0..5) |batch| {
                    const x = range_dictionary[rangeIndex(meta, 2 * batch)];
                    var inverse = x;
                    range_prefix = range_prefix.add(x);
                    if (2 * batch + 1 < 9) {
                        const y = range_dictionary[rangeIndex(meta, 2 * batch + 1)];
                        inverse = inverse.mul(y);
                        range_prefix = range_prefix.add(y);
                    }
                    store(output, n, p, 16 + 4 * batch, inverse);
                }
                store(output, n, p, 36, range_prefix);
                const inverse = scratch[window + i];
                store(output, n, p, 40, inverse);
                const weight = meta.multiplicity();
                if (weight == 1) function_sum = function_sum.sub(inverse) else if (weight != 0) function_sum = function_sum.sub(inverse.mulM31(M.fromCanonical(weight)));
                store(output, n, p, 44, function_sum);
            }
        }
        if (!shift_prefix.isZero() or !range_prefix.isZero()) return error.InvalidShiftMetadata;
        for (function_sum.toM31Array(), 0..) |v, c| for (0..n) |p| {
            output[(44 + c) * n + p] = output[(44 + c) * n + p].sub(v);
        };
        self.interaction = output;
        a.free(self.metadata);
        self.metadata = &.{};
        return .{ .shift = shift_claim, .range16 = range_claim, .function = function_sum };
    }
};
fn countDot(counts: []const u64, dictionary: []const Q) Q {
    var sum = Q.zero();
    for (counts, dictionary) |count, inverse| if (count != 0) {
        sum = sum.add(inverse.mulM31(M.fromCanonical(@intCast(count))));
    };
    return sum;
}
fn store(data: []M, n: usize, row: usize, start: usize, value: Q) void {
    for (value.toM31Array(), 0..) |v, c| data[(start + c) * n + row] = v;
}
fn checkProducts(denominator: E.PackedSecure, values: [E.LANES]Q) !void {
    for (values) |value| for (value.toM31Array()) |v| if (v.v >= core.fields.m31.Modulus) return error.InvalidShiftDictionary;
    const products = denominator.mul(E.PackedSecure.fromLanes(values));
    for (0..E.LANES) |lane| {
        if (denominator.lane(lane).isZero()) return error.DivisionByZero;
        if (!products.lane(lane).eql(Q.one())) return error.InvalidShiftDictionary;
    }
}
fn validateDictionaries(ch: P.Challenges, shift: []const Q, range: []const Q) !void {
    const prepared = PackedTable.Prepared.init(ch.shift);
    var start: usize = 0;
    while (start < 65536) : (start += E.LANES) {
        var fields: [16]E.PackedBase = undefined;
        for (&fields, 0..) |*field, c| {
            var lanes: [E.LANES]M = undefined;
            for (&lanes, 0..) |*v, lane| v.* = M.fromCanonical(@intCast((start + lane) >> @as(u6, @intCast(c))));
            field.* = E.PackedBase.fromLanes(lanes);
        }
        try checkProducts(ch.range16.denominatorFor(E.PackedBase, fields[0]), range[start..][0..E.LANES].*);
        for (0..16) |r| {
            var values: [E.LANES]Q = undefined;
            for (&values, 0..) |*v, lane| v.* = shift[16 * (start + lane) + r];
            try checkProducts(prepared.denominatorFor(E.PackedBase, &fields, r), values);
        }
    }
}
fn functionDenominators(metadata: []const Metadata, output: []Q, ch: Bus.Challenges) void {
    std.debug.assert(metadata.len == output.len and metadata.len % E.LANES == 0);
    var start: usize = 0;
    while (start < metadata.len) : (start += E.LANES) {
        var tuple: [13]E.PackedBase = undefined;
        for (&tuple, 0..) |*column, c| {
            var lanes: [E.LANES]M = undefined;
            for (&lanes, 0..) |*v, lane| v.* = M.fromCanonical(metadata[start + lane].payload[c]);
            column.* = E.PackedBase.fromLanes(lanes);
        }
        const values = ch.denominatorFor(E.PackedBase, tuple);
        for (0..E.LANES) |lane| output[start + lane] = values.lane(lane);
    }
}

/// One existing native row authority for scalar and joined physical formatters.
pub const NativeSupport = struct {
    pub fn write(facts: []const Fact, weights: ?[]const u32, main: []M, metadata: []Metadata, ranges: []u64, shifts: []u64, n: usize, i: usize, p: usize) void {
        const row = nativeRow(if (i < facts.len) facts[i] else null);
        const values = S.rowToColumnsFor(M, &row);
        for (values, 0..) |v, c| main[c * n + p] = v;
        const weight: u32 = if (i < facts.len) (if (weights) |w| w[i] else 1) else 0;
        main[S.LOCAL_MAIN * n + p] = M.fromCanonical(weight);
        metadata[i].multiplicity_words = .{ @truncate(weight), @truncate(weight >> 16) };
        for (row.payload, 0..) |v, c| metadata[i].payload[c] = @intCast(v.v);
        for (0..5) |query| shifts[tableIndex(metadata[i], query)] += 1;
        for (0..9) |query| ranges[rangeIndex(metadata[i], query)] += 1;
    }
};
