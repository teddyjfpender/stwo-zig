//! Native witness ownership for the qualified BINARY truth authority.
//! Fact order/count are witness metadata, not CPU coverage or owner claims.
//! The coordinator must seal these main columns before deriving challenges,
//! close the positive CPU function claim, and admit all shared AND masses.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const E = @import("../evaluation.zig");
const B = @import("binary.zig");
const P = @import("binary_lookup.zig");
const Bus = @import("function_bus.zig");
const Operations = @import("operations.zig");
const NativeFill = @import("binary_native_fill.zig");
const Tables = @import("../providers/tables.zig");
const physical = @import("../witness.zig").physical;
const M = core.fields.m31.M31;
const Q = E.Q;
const Column = engine.pcs.ColumnEvaluation;
const CHUNK: usize = 4096;
pub const MAIN = P.MAIN;
pub const INTERACTION = P.INTERACTION;
pub const Fact = struct { op: Operations.Binary, a: u64, b: u64, c: u64 };
pub const MainBuffers = struct { main: []M };
pub const Mass = struct { fact_capacity: u64, and_queries: u64 };
/// Packed original lookup inputs, not a second wide trace or replayed ALU.
pub const Metadata = struct {
    payload: [13]u16,
    and_indices: [8]u16,
    multiplicity_words: [2]u16,
    pub fn multiplicity(self: Metadata) u32 {
        return @as(u32, self.multiplicity_words[0]) | (@as(u32, self.multiplicity_words[1]) << 16);
    }
};
comptime {
    std.debug.assert(@sizeOf(Metadata) == 46);
}

pub fn massForLog(log: u32) !Mass {
    if (log < 5 or log > 27) return error.InvalidBinaryGeometry;
    const n = @as(u64, 1) << @intCast(log);
    const mass = n * 8;
    _ = try Bus.admitPositiveMass(&.{mass});
    return .{ .fact_capacity = n, .and_queries = mass };
}
pub fn fixedForLog(a: std.mem.Allocator, log: u32) ![]M {
    const mass = try massForLog(log);
    const n: usize = @intCast(mass.fact_capacity);
    const fixed = try a.alloc(M, 2 * n);
    @memset(fixed, M.zero());
    fixed[physical(0, log)] = M.one();
    fixed[n + physical(n - 1, log)] = M.one();
    return fixed;
}
fn result(fact: Fact) u64 {
    return switch (fact.op) {
        .and_ => fact.a & fact.b,
        .or_ => fact.a | fact.b,
        .xor => fact.a ^ fact.b,
    };
}
fn overlaps(main: []M, facts: []const Fact) bool {
    if (main.len == 0 or facts.len == 0) return false;
    const mb = @intFromPtr(main.ptr);
    const fb = @intFromPtr(facts.ptr);
    const me = std.math.add(usize, mb, std.math.mul(usize, main.len, @sizeOf(M)) catch return true) catch return true;
    const fe = std.math.add(usize, fb, std.math.mul(usize, facts.len, @sizeOf(Fact)) catch return true) catch return true;
    return mb < fe and fb < me;
}
fn nativeRow(fact: ?Fact) B.RowFor(M) {
    var row: B.RowFor(M) = .{ .payload = @splat(M.zero()), .active = M.zero(), .selectors = @splat(M.zero()), .a = @splat(M.zero()), .b = @splat(M.zero()), .ab = @splat(M.zero()) };
    const f = fact orelse return row;
    row.active = M.one();
    row.selectors[@intFromEnum(f.op)] = M.one();
    row.payload[0] = M.fromCanonical(Operations.busIdFor(.binary, @intFromEnum(f.op)));
    for (0..4) |i| {
        const shift: u6 = @intCast(16 * i);
        row.payload[1 + i] = M.fromCanonical(@as(u16, @truncate(f.a >> shift)));
        row.payload[5 + i] = M.fromCanonical(@as(u16, @truncate(f.b >> shift)));
        row.payload[9 + i] = M.fromCanonical(@as(u16, @truncate(f.c >> shift)));
    }
    for (0..8) |i| {
        const shift: u6 = @intCast(8 * i);
        const av: u8 = @truncate(f.a >> shift);
        const bv: u8 = @truncate(f.b >> shift);
        row.a[i] = M.fromCanonical(av);
        row.b[i] = M.fromCanonical(bv);
        row.ab[i] = M.fromCanonical(av & bv);
    }
    return row;
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
    and_counts: []u64,
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
        const main_len = std.math.mul(usize, MAIN, n) catch return error.InvalidBinaryGeometry;
        if (facts.len > n) return error.BinaryCapacityExceeded;
        var function_mass: u64 = facts.len;
        if (weights) |input_weights| {
            if (input_weights.len != facts.len) return error.InvalidBinaryWeights;
            function_mass = 0;
            for (input_weights) |weight| {
                if (weight >= core.fields.m31.Modulus) return error.InvalidBinaryWeights;
                function_mass = try std.math.add(u64, function_mass, weight);
                if (function_mass >= core.fields.m31.Modulus) return error.BinaryMultiplicityMassExceeded;
            }
        }
        if (function_mass >= core.fields.m31.Modulus) return error.BinaryMultiplicityMassExceeded;
        if (buffers) |value| {
            if (value.main.len != main_len) return error.InvalidBinaryMain;
            if (overlaps(value.main, facts)) return error.OverlappingBinaryInputs;
            if (weights) |input_weights| {
                const mb = @intFromPtr(value.main.ptr);
                const me = std.math.add(usize, mb, std.mem.sliceAsBytes(value.main).len) catch return error.OverlappingBinaryInputs;
                const wb = @intFromPtr(input_weights.ptr);
                const we = std.math.add(usize, wb, std.mem.sliceAsBytes(input_weights).len) catch return error.OverlappingBinaryInputs;
                if (input_weights.len != 0 and mb < we and wb < me) return error.OverlappingBinaryInputs;
            }
        }
        for (facts) |fact| {
            if (@intFromEnum(fact.op) > 2 or fact.c != result(fact)) return error.InvalidBinaryFact;
        }
        const fixed = try fixedForLog(a, log);
        errdefer a.free(fixed);
        const counts = try a.alloc(u64, 65536);
        errdefer a.free(counts);
        const metadata = try a.alloc(Metadata, n);
        errdefer a.free(metadata);
        const main = if (buffers) |value| value.main else try a.alloc(M, main_len);
        errdefer if (buffers == null) a.free(main);
        @memset(counts, 0);
        const fill = NativeFill.Fill{ .facts = facts, .weights = weights, .log = log, .main = main, .metadata = metadata };
        if (comptime @import("builtin").is_test) {
            if (fail_after) |after| {
                try NativeFill.testing.failSubmission(fill, a, counts, pool orelse return error.ExpectedBinaryNativePool, after);
            } else try fill.run(a, counts, pool);
        } else try fill.run(a, counts, pool);
        return .{ .allocator = a, .log_size = log, .fact_count = facts.len, .function_mass = @intCast(function_mass), .fixed = fixed, .main = main, .owns_main = buffers == null, .and_counts = counts, .metadata = metadata };
    }
    pub const testing = if (@import("builtin").is_test) struct {
        pub fn initSerial(a: std.mem.Allocator, facts: []const Fact, weights: ?[]const u32, log: u32) !Source {
            return initInternal(a, facts, weights, log, null, null, null);
        }
        pub fn failSubmission(a: std.mem.Allocator, facts: []const Fact, log: u32, buffers: MainBuffers, pool: *engine.work_pool.WorkPool, after: usize) !Source {
            return initInternal(a, facts, null, log, buffers, pool, after);
        }
    } else struct {};
    pub fn size(self: *const Source) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn deinit(self: *Source) void {
        self.releaseMain();
        self.allocator.free(self.fixed);
        self.allocator.free(self.interaction);
        self.allocator.free(self.and_counts);
        self.allocator.free(self.metadata);
        self.* = undefined;
    }
    pub fn releaseMain(self: *Source) void {
        if (self.owns_main) self.allocator.free(self.main);
        self.main = &.{};
        self.owns_main = false;
    }
    /// Transfers the original allocation; borrowed matrices cannot be adopted.
    pub fn takeMainForCommit(self: *Source) ![]M {
        if (self.main.len == 0) return error.BinaryMainUnavailable;
        if (!self.owns_main) return error.BorrowedBinaryMain;
        const main = self.main;
        self.main = &.{};
        self.owns_main = false;
        return main;
    }
    pub fn columns(self: *const Source, a: std.mem.Allocator, tree: u2) ![]Column {
        const storage: []const M = switch (tree) {
            0 => self.fixed,
            1 => if (self.main.len != 0) self.main else return error.BinaryMainUnavailable,
            2 => if (self.interaction.len != 0) self.interaction else return error.BinaryInteractionUnavailable,
            else => return error.InvalidBinaryTree,
        };
        const n = self.size();
        const result_ = try a.alloc(Column, storage.len / n);
        for (result_, 0..) |*column, c| column.* = .{ .log_size = self.log_size, .values = storage[c * n ..][0..n] };
        return result_;
    }
    /// Challenge inputs come from the complete sealed-root manifest. Metadata
    /// survives main adoption, and is retired only after private output passes.
    pub fn generate(self: *Source, ch: P.Challenges) !P.Claims {
        const n = self.size();
        const a = self.allocator;
        if (self.interaction.len != 0 or self.metadata.len != n) return error.InvalidBinarySourcePhase;
        if (self.and_counts.len != 65536 or self.fact_count > n) return error.InvalidBinaryMetadata;
        var function_mass: u64 = 0;
        for (self.metadata, 0..) |meta, i| {
            const weight = meta.multiplicity();
            if (weight >= core.fields.m31.Modulus or (i >= self.fact_count and weight != 0)) return error.InvalidBinaryMetadata;
            function_mass += weight;
            if (function_mass >= core.fields.m31.Modulus) return error.InvalidBinaryMetadata;
        }
        if (function_mass != self.function_mass) return error.InvalidBinaryMetadata;
        const output = try a.alloc(M, INTERACTION * n);
        errdefer a.free(output);
        const dictionary = try a.alloc(Q, 65536);
        defer a.free(dictionary);
        const scratch = try a.alloc(Q, 2 * CHUNK);
        defer a.free(scratch);
        try dictionaryInverses(dictionary, scratch, ch);
        var and_claim = Q.zero();
        for (self.and_counts, dictionary) |count, inverse| {
            if (count >= core.fields.m31.Modulus) return error.InvalidBinaryMetadata;
            and_claim = and_claim.add(inverse.mulM31(M.fromCanonical(@intCast(count))));
        }
        var and_prefix = and_claim.neg();
        var function_sum = Q.zero();
        var start: usize = 0;
        while (start < n) : (start += CHUNK) {
            const count: usize = @min(CHUNK, n - start);
            functionDenominators(self.metadata[start..][0..count], scratch[0..count], ch.function);
            try core.fields.batchInverseInPlace(Q, scratch[0..count], scratch[CHUNK..][0..count]);
            for (0..count) |i| {
                const logical = start + i;
                const p = physical(logical, self.log_size);
                const meta = self.metadata[logical];
                for (0..4) |batch| {
                    const x = dictionary[meta.and_indices[2 * batch]];
                    const y = dictionary[meta.and_indices[2 * batch + 1]];
                    store(output, n, p, 4 * batch, x.mul(y));
                    and_prefix = and_prefix.add(x).add(y);
                }
                const inverse = scratch[CHUNK + i];
                store(output, n, p, 16, inverse);
                function_sum = function_sum.sub(inverse.mulM31(M.fromCanonical(meta.multiplicity())));
                store(output, n, p, 20, and_prefix.add(function_sum));
            }
        }
        if (!and_prefix.isZero()) return error.InvalidBinaryMetadata;
        const correction = function_sum.toM31Array();
        for (0..4) |c| for (0..n) |row| {
            output[(20 + c) * n + row] = output[(20 + c) * n + row].sub(correction[c]);
        };
        self.interaction = output;
        a.free(self.metadata);
        self.metadata = &.{};
        return .{ .and_ = and_claim, .function = function_sum };
    }
};

fn store(data: []M, n: usize, row: usize, start: usize, value: Q) void {
    for (value.toM31Array(), 0..) |v, c| data[(start + c) * n + row] = v;
}
fn dictionaryInverses(dictionary: []Q, scratch: []Q, ch: P.Challenges) !void {
    var start: usize = 0;
    while (start < dictionary.len) : (start += CHUNK) {
        const count: usize = @min(CHUNK, dictionary.len - start);
        var i: usize = 0;
        while (i < count) : (i += E.LANES) {
            var tuple: [3]E.PackedBase = undefined;
            for (0..3) |c| {
                var lanes: [E.LANES]M = undefined;
                for (&lanes, 0..) |*v, lane| v.* = M.fromCanonical(Tables.Kind.byte_and.tupleAt(start + i + lane)[c]);
                tuple[c] = E.PackedBase.fromLanes(lanes);
            }
            const values = E.denominatorFor(E.PackedBase, ch.and_.offset, ch.and_.coefficients[0..3], &tuple, true);
            for (0..E.LANES) |lane| scratch[i + lane] = values.lane(lane);
        }
        try core.fields.batchInverseInPlace(Q, scratch[0..count], dictionary[start..][0..count]);
    }
}
fn functionDenominators(metadata: []const Metadata, values: []Q, ch: P.FunctionChallenges) void {
    std.debug.assert(metadata.len == values.len and metadata.len % E.LANES == 0);
    var start: usize = 0;
    while (start < metadata.len) : (start += E.LANES) {
        var tuple: [13]E.PackedBase = undefined;
        for (0..13) |c| {
            var lanes: [E.LANES]M = undefined;
            for (&lanes, 0..) |*v, lane| v.* = M.fromCanonical(metadata[start + lane].payload[c]);
            tuple[c] = E.PackedBase.fromLanes(lanes);
        }
        const result_ = ch.denominatorFor(E.PackedBase, tuple);
        for (0..E.LANES) |lane| values[start + lane] = result_.lane(lane);
    }
}

/// One native row authority, shared by scalar and joined physical formatters.
pub const NativeSupport = struct {
    pub fn write(facts: []const Fact, weights: ?[]const u32, main: []M, metadata: []Metadata, counts: []u64, n: usize, i: usize, p: usize) void {
        const row = nativeRow(if (i < facts.len) facts[i] else null);
        const values = P.rowToColumnsFor(M, row);
        for (values, 0..) |v, c| main[c * n + p] = v;
        const weight: u32 = if (i < facts.len) (if (weights) |w| w[i] else 1) else 0;
        main[B.LOCAL_MAIN * n + p] = M.fromCanonical(weight);
        metadata[i].multiplicity_words = .{ @truncate(weight), @truncate(weight >> 16) };
        for (row.payload, 0..) |v, c| metadata[i].payload[c] = @intCast(v.v);
        for (0..8) |j| {
            const index = Tables.Kind.byte_and.rowIndex(.{ row.a[j].v, row.b[j].v, row.ab[j].v, 0, 0, 0 }) catch unreachable;
            metadata[i].and_indices[j] = @intCast(index);
            counts[index] += 1;
        }
    }
};
