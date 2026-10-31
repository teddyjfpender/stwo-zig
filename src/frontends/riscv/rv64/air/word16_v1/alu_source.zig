//! Independently sized ALU truth witnesses. One native filler serves owned and
//! borrowed main matrices. CPU coverage is established by the closed function
//! bus, never by the private fact_count metadata used here.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const E = @import("../evaluation.zig");
const A = @import("alu.zig");
const P = @import("alu_lookup.zig");
const Ops = @import("operations.zig");
const Bus = @import("function_bus.zig");
const Geometry = @import("binary_source.zig");
const physical = @import("../witness.zig").physical;
const M = core.fields.m31.M31;
const Q = E.Q;
const CHUNK = 4096;
pub const Fact = struct { op: Ops.Alu, a: u64, b: u64, c: u64 };
pub const MainBuffers = struct { main: []M };
pub const Metadata = struct { payload: [13]u16, range_indices: [20]u16 };
comptime {
    std.debug.assert(@sizeOf(Metadata) == 66);
}
pub const Mass = struct { fact_capacity: u64, range16_queries: u64 };
pub fn massForLog(log: u32) !Mass {
    if (log < 5 or log > 26) return error.InvalidAluGeometry;
    const n = @as(u64, 1) << @intCast(log);
    _ = try Bus.admitPositiveMass(&.{20 * n});
    return .{ .fact_capacity = n, .range16_queries = 20 * n };
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
fn nativeRow(value: ?Fact, inverses: []const M) A.RowFor(M) {
    const f = value orelse Fact{ .op = .add, .a = 0, .b = 0, .c = 0 };
    var r: A.RowFor(M) = undefined;
    r.payload[0] = M.fromCanonical(if (value != null) Ops.busIdFor(.alu, @intFromEnum(f.op)) else 0);
    r.active = M.fromCanonical(@intFromBool(value != null));
    r.selectors = @splat(M.zero());
    if (value != null) r.selectors[@intFromEnum(f.op)] = M.one();
    var carry: u32 = 0;
    var borrow: u32 = 0;
    for (0..4) |i| {
        const shift: u6 = @intCast(16 * i);
        const av: u32 = @as(u16, @truncate(f.a >> shift));
        const bv: u32 = @as(u16, @truncate(f.b >> shift));
        r.payload[1 + i] = M.fromCanonical(av);
        r.payload[5 + i] = M.fromCanonical(bv);
        r.payload[9 + i] = M.fromCanonical(@as(u16, @truncate(f.c >> shift)));
        const sum = av + bv + carry;
        const difference = av + 65536 - bv - borrow;
        carry = sum >> 16;
        borrow = @intFromBool(difference < 65536);
        r.sum[i] = M.fromCanonical(sum & 65535);
        r.difference[i] = M.fromCanonical(difference & 65535);
        r.carry[i] = M.fromCanonical(carry);
        r.borrow[i] = M.fromCanonical(borrow);
        r.zero[i] = M.fromCanonical(@intFromBool((difference & 65535) == 0));
        r.inverse[i] = inverses[difference & 65535];
    }
    for ([4]M{ r.payload[4], r.payload[8], r.sum[1], r.difference[1] }, 0..) |v, i| {
        r.sign[i] = M.fromCanonical(v.v >> 15);
        r.low[i] = M.fromCanonical(v.v & 32767);
    }
    r.zero_pair = .{ r.zero[0].mul(r.zero[1]), r.zero[2].mul(r.zero[3]) };
    r.signed_less = M.fromCanonical(@intCast(A.nativeResult(.slt, f.a, f.b)));
    return r;
}
fn rangeIndex(r: *const A.RowFor(M), i: usize) u16 {
    const value = if (i < 8) r.payload[1 + i].v else if (i < 12) r.sum[i - 8].v else if (i < 16) r.difference[i - 12].v else 2 * r.low[i - 16].v;
    std.debug.assert(value < 65536);
    return @intCast(value);
}
pub const Source = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    fact_count: usize,
    fixed: []M,
    main: []M,
    owns_main: bool,
    interaction: []M = &.{},
    range16_counts: []u64,
    metadata: []Metadata,
    pub fn init(a: std.mem.Allocator, facts: []const Fact, log: u32) !Source {
        return initInternal(a, facts, log, null);
    }
    pub fn initWithMainBuffers(a: std.mem.Allocator, facts: []const Fact, log: u32, buffers: MainBuffers) !Source {
        return initInternal(a, facts, log, buffers);
    }
    fn initInternal(a: std.mem.Allocator, facts: []const Fact, log: u32, buffers: ?MainBuffers) !Source {
        const mass = try massForLog(log);
        const n: usize = @intCast(mass.fact_capacity);
        const length = std.math.mul(usize, P.MAIN, n) catch return error.InvalidAluGeometry;
        if (facts.len > n) return error.AluCapacityExceeded;
        if (buffers) |b| {
            if (b.main.len != length) return error.InvalidAluMain;
            if (overlaps(b.main, facts)) return error.OverlappingAluInputs;
        }
        for (facts) |f| if (@intFromEnum(f.op) > 9 or f.c != A.nativeResult(f.op, f.a, f.b)) return error.InvalidAluFact;
        const fixed = try fixedForLog(a, log);
        errdefer a.free(fixed);
        const counts = try a.alloc(u64, 65536);
        errdefer a.free(counts);
        const metadata = try a.alloc(Metadata, n);
        errdefer a.free(metadata);
        const inverses = try a.alloc(M, 65536);
        defer a.free(inverses);
        inverses[0] = M.zero();
        const nonzero = try a.alloc(M, 65535);
        defer a.free(nonzero);
        for (nonzero, 0..) |*v, i| v.* = M.fromCanonical(@intCast(i + 1));
        try core.fields.batchInverseInPlace(M, nonzero, inverses[1..]);
        const main = if (buffers) |b| b.main else try a.alloc(M, length);
        // Every allocation/validation precedes the first borrowed write.
        @memset(counts, 0);
        for (0..n) |i| {
            const row = nativeRow(if (i < facts.len) facts[i] else null, inverses);
            const values = P.rowToColumnsFor(M, row);
            const p = physical(i, log);
            for (values, 0..) |v, c| main[c * n + p] = v;
            main[A.LOCAL_MAIN * n + p] = row.active;
            for (row.payload, 0..) |v, c| metadata[i].payload[c] = @intCast(v.v);
            for (0..20) |j| {
                const index = rangeIndex(&row, j);
                metadata[i].range_indices[j] = index;
                counts[index] += 1;
            }
        }
        return .{ .allocator = a, .log_size = log, .fact_count = facts.len, .fixed = fixed, .main = main, .owns_main = buffers == null, .range16_counts = counts, .metadata = metadata };
    }
    pub fn size(self: *const Source) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn deinit(self: *Source) void {
        self.releaseMain();
        const a = self.allocator;
        a.free(self.fixed);
        a.free(self.interaction);
        a.free(self.range16_counts);
        a.free(self.metadata);
        self.* = undefined;
    }
    pub fn releaseMain(self: *Source) void {
        if (self.owns_main) self.allocator.free(self.main);
        self.main = &.{};
        self.owns_main = false;
    }
    pub fn takeMainForCommit(self: *Source) ![]M {
        if (self.main.len == 0) return error.AluMainUnavailable;
        if (!self.owns_main) return error.BorrowedAluMain;
        const main = self.main;
        self.main = &.{};
        self.owns_main = false;
        return main;
    }
    pub fn columns(self: *const Source, a: std.mem.Allocator, tree: u2) ![]engine.pcs.ColumnEvaluation {
        const data = switch (tree) {
            0 => self.fixed,
            1 => if (self.main.len != 0) self.main else return error.AluMainUnavailable,
            2 => if (self.interaction.len != 0) self.interaction else return error.AluInteractionUnavailable,
            else => return error.InvalidAluTree,
        };
        const n = self.size();
        const out = try a.alloc(engine.pcs.ColumnEvaluation, data.len / n);
        for (out, 0..) |*c, i| c.* = .{ .log_size = self.log_size, .values = data[i * n ..][0..n] };
        return out;
    }
    /// Dictionary is the ONE shared local U16 provider's post-challenge output.
    /// Native validation is bounded by table size, not repeated per query.
    pub fn generate(self: *Source, ch: P.Challenges, dictionary: []const Q) !P.Claims {
        const n = self.size();
        const a = self.allocator;
        if (self.interaction.len != 0 or self.metadata.len != n) return error.InvalidAluSourcePhase;
        if (dictionary.len != 65536 or self.range16_counts.len != 65536 or self.fact_count > n) return error.InvalidAluDictionary;
        try validateDictionary(ch, dictionary);
        const output = try a.alloc(M, P.INTERACTION * n);
        errdefer a.free(output);
        const scratch = try a.alloc(Q, 2 * CHUNK);
        defer a.free(scratch);
        var range_claim = Q.zero();
        for (self.range16_counts, dictionary) |count, inverse| {
            if (count >= core.fields.m31.Modulus) return error.InvalidAluMetadata;
            range_claim = range_claim.add(inverse.mulM31(M.fromCanonical(@intCast(count))));
        }
        var prefix = range_claim.neg();
        var function_sum = Q.zero();
        var start: usize = 0;
        while (start < n) : (start += CHUNK) {
            const count = @min(CHUNK, n - start);
            functionDenominators(self.metadata[start..][0..count], scratch[0..count], ch.function);
            try core.fields.batchInverseInPlace(Q, scratch[0..count], scratch[CHUNK..][0..count]);
            for (0..count) |i| {
                const logical = start + i;
                const p = physical(logical, self.log_size);
                const meta = self.metadata[logical];
                for (0..10) |batch| {
                    const x = dictionary[meta.range_indices[2 * batch]];
                    const y = dictionary[meta.range_indices[2 * batch + 1]];
                    store(output, n, p, 4 * batch, x.mul(y));
                    prefix = prefix.add(x).add(y);
                }
                store(output, n, p, 40, prefix);
                const inverse = scratch[CHUNK + i];
                store(output, n, p, 44, inverse);
                if (logical < self.fact_count) function_sum = function_sum.sub(inverse);
                store(output, n, p, 48, function_sum);
            }
        }
        if (!prefix.isZero()) return error.InvalidAluMetadata;
        const correction = function_sum.toM31Array();
        for (correction, 0..) |v, c| for (0..n) |r| {
            output[(48 + c) * n + r] = output[(48 + c) * n + r].sub(v);
        };
        self.interaction = output;
        a.free(self.metadata);
        self.metadata = &.{};
        return .{ .range16 = range_claim, .function = function_sum };
    }
};
fn store(data: []M, n: usize, row: usize, start: usize, value: Q) void {
    for (value.toM31Array(), 0..) |v, c| data[(start + c) * n + row] = v;
}
fn validateDictionary(ch: P.Challenges, dictionary: []const Q) !void {
    var start: usize = 0;
    while (start < dictionary.len) : (start += E.LANES) {
        var inputs: [E.LANES]M = undefined;
        for (&inputs, 0..) |*v, i| v.* = M.fromCanonical(@intCast(start + i));
        const denominator = ch.range16.denominatorFor(E.PackedBase, E.PackedBase.fromLanes(inputs));
        const product = denominator.mul(E.PackedSecure.fromLanes(dictionary[start..][0..E.LANES].*));
        for (0..E.LANES) |i| {
            if (denominator.lane(i).isZero()) return error.DivisionByZero;
            if (!product.lane(i).eql(Q.one())) return error.InvalidAluDictionary;
        }
    }
}
fn functionDenominators(metadata: []const Metadata, output: []Q, ch: Bus.Challenges) void {
    std.debug.assert(metadata.len == output.len and metadata.len % E.LANES == 0);
    var start: usize = 0;
    while (start < metadata.len) : (start += E.LANES) {
        var tuple: [13]E.PackedBase = undefined;
        for (0..13) |c| {
            var lanes: [E.LANES]M = undefined;
            for (&lanes, 0..) |*v, i| v.* = M.fromCanonical(metadata[start + i].payload[c]);
            tuple[c] = E.PackedBase.fromLanes(lanes);
        }
        const values = ch.denominatorFor(E.PackedBase, tuple);
        for (0..E.LANES) |i| output[start + i] = values.lane(i);
    }
}
