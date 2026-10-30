const std = @import("std");
const core = @import("stwo_core");
const R = @import("../block_v7_memory_relations_v1.zig");
const Q = R.Q;
const M = R.M;
const T = @import("../block_v7_memory_trace_v1.zig");
const K = @import("../block_v8_ram_endpoint_kernel_v1.zig");
const C = @import("../block_v8_ram_endpoint_component_v1.zig");
const Collect = @import("../block_v8_ram_endpoint_collector_v1.zig");
const Provider = @import("../block_v8_endpoint_range_provider_v1.zig");
const Counter = @import("../../air/lookups/tables/counter.zig").Counter;
const Schema = @import("../../air/lookups/tables/schema.zig");
const Epoch = @import("../block_v7_execution_epoch_v1.zig");
fn fixture(a: std.mem.Allocator) !Collect.Owned {
    return Collect.collectGlobal(a, .{ .frame = .{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 16 }, .cohort_ordinal = 0, .cohort_count = 1 }, &.{
        .{ .space = 1, .address = 0x1000, .clock = 1, .before = 7, .after = 9 },
        .{ .space = 1, .address = 0x10000, .clock = 7, .before = 0xff00_0102, .after = 0xffff_ffff },
    }, .{});
}
fn drawn(a: std.mem.Allocator) !Epoch.Drawn {
    const epoch = Epoch.Epoch{ .statement = @splat(1), .digest = @splat(2), .counts = @splat(0), .config = @import("../../recursion/blake3_execution_parent_protocol.zig").Profile.diagnostic_q8_pow0.config() };
    return epoch.draw(a);
}
fn endpointClaims(matrix: T.Matrix, policy: K.Policy, ch: C.Challenges(Q)) ![C.PLANES]Q {
    var sums: [C.PLANES]Q = @splat(Q.zero());
    for (0..matrix.size()) |row| {
        const terms = C.terms(Q, policy, ch, Q.fromBase(matrix.get(0, row)), matrix.row(K.COLUMN_COUNT, C.Spec.FIXED_COUNT, row));
        for (&sums, terms) |*sum, term| sum.* = sum.add(try term.fraction());
    }
    return sums;
}
test "endpoint-only range provider closes all thirteen requests and exact byte-pair counter signs" {
    const a = std.testing.allocator;
    var source = try fixture(a);
    defer source.deinit();
    var provider = try Provider.Owned.init(a, source.matrix, @intCast(source.endpoints.len), .{});
    defer provider.deinit();
    try std.testing.expectEqual(@as(u32, 26), provider.counts.range16);
    try std.testing.expectEqual(@as(u32, 8), provider.counts.byte_pairs);
    const d = try drawn(a);
    const ch = C.fromEpoch(d);
    const sums = try endpointClaims(source.matrix, source.policy, ch);
    var generated = try provider.interactions(a, d.memory, 8 << 20);
    defer generated.deinit();
    try Provider.closeRangeClaims(2, sums, generated.sums);
    var spec = Provider.Spec{ .challenges = d.memory, .sums = generated.sums };
    const domain = try spec.prepareDomain(@intCast(provider.range16.size()));
    for (0..provider.range16.size()) |row| {
        const previous = if (row == 0) provider.range16.size() - 1 else row - 1;
        for (try domain.evaluate(provider.range16.row(2, 0, row), provider.range16.row(1, 2, row), provider.range16.row(1, 2, previous), generated.matrix.row(8, 0, row), generated.matrix.row(8, 0, previous), @intCast(provider.range16.size()))) |value| {
            try std.testing.expect(value.isZero());
        }
    }
    // Reuse the existing lookup provider's actual sign convention. Endpoint
    // source terms are negative; negating signed counters balances them.
    const Lookup = @import("../block_v7_lookup_compact_algebra_v1.zig").For(.range_check_8_8, .dense);
    var byte_sum = sums[9].add(sums[10]);
    for (provider.byte_counter.values, 0..) |multiplicity, row| {
        if (multiplicity.isZero()) continue;
        const tuple = try Schema.tupleAt(.range_check_8_8, row);
        byte_sum = byte_sum.add(try Lookup.term(Q, ch.bytes, .{ Q.one(), Q.fromBase(tuple.values[0]), Q.fromBase(tuple.values[1]) }, .{Q.fromBase(multiplicity)}).fraction());
    }
    try std.testing.expect(byte_sum.isZero());
    try std.testing.expectEqualDeep(M.fromCanonical(8).neg(), provider.byte_counter.signedTotal());
    var counter = try Counter.init(a, .range_check_8_8);
    defer counter.deinit(a);
    var demand: [Schema.KIND_COUNT]u64 = @splat(0);
    try provider.appendToLookup(&counter, &demand);
    try std.testing.expectEqualSlices(M, provider.byte_counter.values, counter.values);
    try std.testing.expectEqual(@as(u64, 8), demand[@intFromEnum(Schema.Kind.range_check_8_8)]);
}
test "endpoint provider multiplicity count and compensated fraction mutations fail pure closure" {
    const a = std.testing.allocator;
    var source = try fixture(a);
    defer source.deinit();
    var provider = try Provider.Owned.init(a, source.matrix, 2, .{});
    defer provider.deinit();
    const d = try drawn(a);
    const sums = try endpointClaims(source.matrix, source.policy, C.fromEpoch(d));
    const zero_count = provider.range16.get(2, 0);
    provider.range16.set(2, 0, zero_count.add(M.one()));
    var extra = try provider.interactions(a, d.memory, 8 << 20);
    defer extra.deinit();
    try std.testing.expectError(error.UnclosedEndpointRangeCount, Provider.closeRangeClaims(2, sums, extra.sums));
    provider.range16.set(2, 0, zero_count.sub(M.one()));
    provider.range16.set(2, 60000, provider.range16.get(2, 60000).add(M.one()));
    var compensated = try provider.interactions(a, d.memory, 8 << 20);
    defer compensated.deinit();
    try std.testing.expectError(error.UnclosedEndpointRangeRelation, Provider.closeRangeClaims(2, sums, compensated.sums));
}
test "endpoint derived carry limb range is required even with Boolean carry bits" {
    const a = std.testing.allocator;
    var source = try fixture(a);
    defer source.deinit();
    // The low-address carry can be another Boolean without violating direct
    // endpoint equations. The mandatory derived low16 request rejects it.
    source.matrix.set(C.Spec.FIXED_COUNT + 21, 0, M.one());
    const current = source.matrix.row(K.COLUMN_COUNT, C.Spec.FIXED_COUNT, 0);
    for (K.constraintsPrevious(Q, current, @splat(Q.zero()), Q.one(), Q.zero(), Q.one(), Q.fromBase(M.fromCanonical(source.policy.max_local_clock)))) |value| {
        try std.testing.expect(value.isZero());
    }
    try std.testing.expectError(error.InvalidEndpointRange16, Provider.Owned.init(a, source.matrix, 2, .{}));
}
test "endpoint range provider rejects malformed active rows padding bytes and resource bounds" {
    const a = std.testing.allocator;
    var source = try fixture(a);
    defer source.deinit();
    source.matrix.set(0, 0, M.fromCanonical(2));
    try std.testing.expectError(error.InvalidEndpointRangeSource, Provider.Owned.init(a, source.matrix, 2, .{}));
    source.matrix.set(0, 0, M.one());
    source.matrix.set(C.Spec.FIXED_COUNT + 3, 2, M.one());
    try std.testing.expectError(error.InvalidEndpointRangeSource, Provider.Owned.init(a, source.matrix, 2, .{}));
    source.matrix.set(C.Spec.FIXED_COUNT + 3, 2, M.zero());
    source.matrix.set(C.Spec.FIXED_COUNT + 3, 0, M.fromCanonical(256));
    try std.testing.expectError(error.InvalidEndpointBytePair, Provider.Owned.init(a, source.matrix, 2, .{}));
    source.matrix.set(C.Spec.FIXED_COUNT + 3, 0, M.fromCanonical(7));
    try std.testing.expectError(error.EndpointRangeResourceLimit, Provider.Owned.init(a, source.matrix, 2, .{ .max_live_bytes = 1 }));
    try std.testing.expectError(error.EndpointRangeResourceLimit, Provider.Owned.init(a, source.matrix, 2, .{ .max_endpoints = 1 }));
    try std.testing.expectError(error.InvalidEndpointRangeSource, Provider.Owned.init(a, source.matrix, 17, .{}));
    try std.testing.expectError(error.EndpointRangeCountExceedsField, Provider.requests(core.fields.m31.Modulus));
    try std.testing.expectError(error.EndpointRangeCountExceedsField, Provider.requests(std.math.maxInt(u64)));
}
test "endpoint byte-counter merge is transactional at the lookup characteristic boundary" {
    const a = std.testing.allocator;
    var source = try fixture(a);
    defer source.deinit();
    var provider = try Provider.Owned.init(a, source.matrix, 2, .{});
    defer provider.deinit();
    var counter = try Counter.init(a, .range_check_8_8);
    defer counter.deinit(a);
    var demand: [Schema.KIND_COUNT]u64 = @splat(0);
    demand[0] = core.fields.m31.Modulus - 1;
    try std.testing.expectError(error.EndpointRangeCountExceedsField, provider.appendToLookup(&counter, &demand));
    for (counter.values) |value| try std.testing.expect(value.isZero());
    try std.testing.expectEqual(@as(u64, core.fields.m31.Modulus - 1), demand[0]);
    try std.testing.expectEqual(@as(u64, 0), demand[@intFromEnum(Schema.Kind.range_check_8_8)]);
}
test "endpoint provider allocation failures preserve source and release owned state" {
    var source = try fixture(std.testing.allocator);
    defer source.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(a: std.mem.Allocator, matrix: T.Matrix) !void {
            var result = try Provider.Owned.init(a, matrix, 2, .{});
            defer result.deinit();
        }
    }.run, .{source.matrix});
}
