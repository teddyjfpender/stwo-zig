//! Separate range provider for the experimental endpoint source. Its two
//! physical claims belong to the B8 native-source first roots, not the old
//! global RAM range16 family: mixing the censuses would change that theorem.
//! This owner and its algebraic closure helpers confer NO proof authority.
//! Source AIR, canonical fixed columns, physical claims and lookup providers
//! must all be independently authenticated before accepting their equations.
const std = @import("std");
const core = @import("stwo_core");
const R = @import("block_v7_memory_relations_v1.zig");
const K = @import("block_v8_ram_endpoint_kernel_v1.zig");
const Endpoint = @import("block_v8_ram_endpoint_component_v1.zig");
const T = @import("block_v7_memory_trace_v1.zig");
const Counter = @import("../air/lookups/tables/counter.zig").Counter;
const Schema = @import("../air/lookups/tables/schema.zig");
const M = R.M;
const Q = R.Q;
pub const Spec = @import("block_v7_provider_component_v1.zig").For(.range16);
pub const RANGE_REQUESTS: u32 = 13;
pub const BYTE_REQUESTS: u32 = 4;
pub const Counts = struct { endpoints: u32, range16: u32, byte_pairs: u32 };
pub const Limits = struct {
    max_endpoints: u32 = 1 << 24,
    max_row_log: u32 = 24,
    max_live_bytes: usize = 8 << 20,
};

/// Independent source admission must establish the endpoint count. These
/// characteristic bounds prevent request multiplicities disappearing modulo p.
pub fn requests(endpoint_count: u64) !Counts {
    const range = std.math.mul(u64, endpoint_count, RANGE_REQUESTS) catch return error.EndpointRangeCountExceedsField;
    const bytes = std.math.mul(u64, endpoint_count, BYTE_REQUESTS) catch return error.EndpointRangeCountExceedsField;
    if (range >= core.fields.m31.Modulus or bytes >= core.fields.m31.Modulus)
        return error.EndpointRangeCountExceedsField;
    return .{ .endpoints = @intCast(endpoint_count), .range16 = @intCast(range), .byte_pairs = @intCast(bytes) };
}
fn canonical(value: M) !u32 {
    if (value.v >= core.fields.m31.Modulus) return error.NonCanonicalM31;
    return value.toU32();
}
fn matrixShape(matrix: T.Matrix, endpoint_count: u32, limits: Limits) !void {
    if (limits.max_row_log < 4 or limits.max_row_log > 24 or matrix.log < 4 or matrix.log > limits.max_row_log)
        return error.EndpointRangeResourceLimit;
    const log = @max(@as(u32, 4), std.math.log2_int_ceil(u32, @max(@as(u32, 1), endpoint_count)));
    if (matrix.log != log) return error.InvalidEndpointRangeSource;
    const width = Endpoint.Spec.FIXED_COUNT + Endpoint.Spec.MAIN_COUNT;
    const rows = matrix.size();
    if (matrix.columns.len != width or matrix.storage.len != try std.math.mul(usize, rows, width))
        return error.InvalidEndpointRangeSource;
    for (matrix.columns, 0..) |column, index| {
        if (column.log_size != matrix.log or column.values.len != rows or column.values.ptr != matrix.storage[index * rows ..].ptr)
            return error.InvalidEndpointRangeSource;
    }
}
pub const Owned = struct {
    allocator: std.mem.Allocator,
    counts: Counts,
    /// Canonical range16 fixed columns + endpoint-only multiplicity column.
    range16: T.Matrix,
    /// Signed source numerators. Endpoint byte terms are negative, so these
    /// counters are negative; compact lookup providers negate them to balance.
    byte_counter: Counter,
    owned_bytes: usize,
    construction_peak_bytes: usize,
    pub fn init(a: std.mem.Allocator, endpoint_matrix: T.Matrix, endpoint_count: u32, limits: Limits) !Owned {
        const counts = try requests(endpoint_count);
        if (endpoint_count > limits.max_endpoints or limits.max_live_bytes == 0)
            return error.EndpointRangeResourceLimit;
        try matrixShape(endpoint_matrix, endpoint_count, limits);
        const range_rows: usize = 65536;
        const count_bytes = range_rows * @sizeOf(u32);
        const matrix_bytes = range_rows * (Spec.FIXED_COUNT + Spec.MAIN_COUNT) * @sizeOf(M) +
            (Spec.FIXED_COUNT + Spec.MAIN_COUNT) * @sizeOf(@import("block_v5_word_pcs_v1.zig").Column);
        const counter_bytes = Schema.size(.range_check_8_8) * @sizeOf(M);
        const owned_bytes = try std.math.add(usize, matrix_bytes, counter_bytes);
        const peak = try std.math.add(usize, owned_bytes, count_bytes);
        if (peak > limits.max_live_bytes) return error.EndpointRangeResourceLimit;
        const multiplicities = try a.alloc(u32, range_rows);
        defer a.free(multiplicities);
        @memset(multiplicities, 0);
        var bytes = try Counter.init(a, .range_check_8_8);
        errdefer bytes.deinit(a);
        for (0..endpoint_matrix.size()) |row| {
            const active = try canonical(endpoint_matrix.get(0, row));
            const first = try canonical(endpoint_matrix.get(1, row));
            if (active != @intFromBool(row < endpoint_count) or first != @intFromBool(row == 0))
                return error.InvalidEndpointRangeSource;
            var main: [K.COLUMN_COUNT]M = undefined;
            for (&main, 0..) |*value, column| {
                value.* = endpoint_matrix.get(Endpoint.Spec.FIXED_COUNT + column, row);
                _ = try canonical(value.*);
                if (active == 0 and !value.isZero()) return error.InvalidEndpointRangeSource;
            }
            if (active == 0) continue;
            for (K.range16_columns) |column| try increment(multiplicities, main[column]);
            // Essential thirteenth request: two Boolean carry bits alone do
            // not establish the selected byte-address low limb is unsigned.
            var secure_main: [K.COLUMN_COUNT]Q = undefined;
            for (&secure_main, main) |*value, base| value.* = Q.fromBase(base);
            try increment(multiplicities, try K.derivedRange16(Q, secure_main)[0].tryIntoM31());
            for (K.byte_pairs) |pair| {
                if (main[pair[0]].toU32() > 255 or main[pair[1]].toU32() > 255)
                    return error.InvalidEndpointBytePair;
                try bytes.registerBase(M.one().neg(), &.{ main[pair[0]], main[pair[1]] });
            }
        }
        var total: u64 = 0;
        for (multiplicities) |count| total = try std.math.add(u64, total, count);
        if (total != counts.range16) return error.InvalidEndpointRangeCensus;
        try validateByteCounter(&bytes, counts.byte_pairs);
        var range = try T.range16(a, multiplicities, limits.max_live_bytes);
        errdefer range.deinit();
        return .{ .allocator = a, .counts = counts, .range16 = range, .byte_counter = bytes, .owned_bytes = owned_bytes, .construction_peak_bytes = peak };
    }
    pub fn deinit(self: *Owned) void {
        self.range16.deinit();
        self.byte_counter.deinit(self.allocator);
        self.* = undefined;
    }
    pub fn interactions(self: *const Owned, a: std.mem.Allocator, challenges: R.Challenges(Q), max_bytes: usize) !T.Generated(Spec.PLANES) {
        return T.interactions(Spec.PLANES, a, self.range16, Context{ .challenges = challenges }, max_bytes);
    }
    /// Transactional addition into the existing range8 lookup source. Positive
    /// request bounds are independent of the signed field-valued counters.
    /// The caller must include this exact contribution once in the B8 roster.
    pub fn appendToLookup(self: *const Owned, destination: *Counter, demand: *[Schema.KIND_COUNT]u64) !void {
        try validateByteCounter(&self.byte_counter, self.counts.byte_pairs);
        if (destination.kind != .range_check_8_8 or destination.values.len != Schema.size(.range_check_8_8))
            return error.InvalidEndpointByteCounter;
        for (destination.values) |value| _ = try canonical(value);
        var next = demand.*;
        const kind = @intFromEnum(Schema.Kind.range_check_8_8);
        next[kind] = try std.math.add(u64, next[kind], self.counts.byte_pairs);
        var total: u64 = 0;
        for (next) |count| total = try std.math.add(u64, total, count);
        if (total >= core.fields.m31.Modulus) return error.EndpointRangeCountExceedsField;
        for (destination.values, self.byte_counter.values) |*value, addend| value.* = value.add(addend);
        demand.* = next;
    }
};
fn increment(counts: []u32, value: M) !void {
    const index = try canonical(value);
    if (index >= 65536) return error.InvalidEndpointRange16;
    if (counts[index] >= core.fields.m31.Modulus - 1) return error.EndpointRangeCountExceedsField;
    counts[index] += 1;
}
fn validateByteCounter(counter: *const Counter, expected: u32) !void {
    if (counter.kind != .range_check_8_8 or counter.values.len != Schema.size(.range_check_8_8))
        return error.InvalidEndpointByteCounter;
    var total: u64 = 0;
    for (counter.values) |value| {
        const raw = try canonical(value);
        const magnitude: u32 = if (raw == 0) 0 else core.fields.m31.Modulus - raw;
        total = try std.math.add(u64, total, magnitude);
        if (total > expected) return error.InvalidEndpointByteCounter;
    }
    if (total != expected) return error.InvalidEndpointByteCounter;
}
pub const Context = struct {
    challenges: R.Challenges(Q),
    pub fn termsAt(self: @This(), matrix: T.Matrix, logical: usize) ![Spec.PLANES]R.Term(Q) {
        return Spec.terms(Q, self.challenges, matrix.row(Spec.FIXED_COUNT, 0, logical), matrix.row(Spec.MAIN_COUNT, Spec.FIXED_COUNT, logical));
    }
};
/// Pure algebra ONLY, after source and provider proof authentication. Count is
/// the independently admitted number of active endpoint rows, not a wire claim.
pub fn closeRangeClaims(endpoint_count: u32, endpoint_sums: [Endpoint.PLANES]Q, provider_sums: [Spec.PLANES]Q) !void {
    return closeRangeClaimsWithExtra(endpoint_count, endpoint_sums, provider_sums, 0, Q.zero());
}
pub fn closeRangeClaimsWithExtra(endpoint_count: u32, endpoint_sums: [Endpoint.PLANES]Q, provider_sums: [Spec.PLANES]Q, extra_requests: u32, extra_sum: Q) !void {
    const expected = try requests(endpoint_count);
    const total = try std.math.add(u32, expected.range16, extra_requests);
    if (total >= core.fields.m31.Modulus or !@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&extra_sum)) return error.InvalidEndpointPhysicalClaim;
    for (endpoint_sums) |claim| if (!@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&claim))
        return error.InvalidEndpointPhysicalClaim;
    for (provider_sums) |claim| if (!@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&claim))
        return error.InvalidEndpointPhysicalClaim;
    var sum = provider_sums[0].add(extra_sum);
    for (endpoint_sums[2..9]) |physical| sum = sum.add(physical);
    if (!provider_sums[1].eql(Q.fromBase(M.fromCanonical(total))))
        return error.UnclosedEndpointRangeCount;
    if (!sum.isZero()) return error.UnclosedEndpointRangeRelation;
}
