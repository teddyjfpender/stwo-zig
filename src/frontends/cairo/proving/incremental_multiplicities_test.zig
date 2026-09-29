const std = @import("std");
const prover = @import("stwo_prover_engine");
const adapter = @import("../adapter/mod.zig");
const memory = @import("../common/memory.zig");
const topology = @import("../witness/feed_topology.zig");
const fixed = @import("../witness/fixed_table_bundle.zig");
const tables_mod = @import("../conformance/multiplicity_tables.zig");
const counts_mod = @import("../witness/cpu_memory_multiplicity.zig");
const State = @import("incremental_multiplicities.zig").State;
const Producer = @import("../witness/producer_output.zig").ProducerOutput;
const graph = @import("../witness/live_graph.zig");
const claim = @import("../claim_generator.zig");

fn parityCase(a: std.mem.Allocator, rows: usize) !void {
    var addresses = [_]memory.EncodedMemoryValueId{ memory.EncodedMemoryValueId.EMPTY, memory.EncodedMemoryValueId.small(0), memory.EncodedMemoryValueId.f252(0) };
    var big_values = [_]memory.F252{ @splat(0), @splat(0) };
    var small_values = [_]u128{ 0, 1, 2 };
    var public = [_]u32{ 1, 2 };
    var input: adapter.ProverInput = undefined;
    input.memory.address_to_id = &addresses;
    input.memory.f252_values = &big_values;
    input.memory.small_values = &small_values;
    input.public_memory_addresses = &public;
    const feeds = [_]topology.Feed{
        .{ .field = "fixed", .instance = 0, .target = "blake_round_sigma", .relation = 0, .word_base = 0, .words_per_instance = 1 },
        .{ .field = "address", .instance = 0, .target = "memory_address_to_id", .relation = 0, .word_base = 1, .words_per_instance = 1 },
        .{ .field = "value", .instance = 0, .target = "memory_id_to_big", .relation = 0, .word_base = 2, .words_per_instance = 1 },
    };
    const components = [_]topology.Component{.{ .producer = "source", .sub_words_per_row = 3, .feeds = &feeds, .lookup_words_per_row = 0, .lookup_fields = &.{}, .logup_columns = &.{} }};
    var routing: topology.Loaded = undefined;
    routing.parsed.value.components = &components;
    var entries = [_]fixed.Entry{.{ .component = @constCast("blake_round_sigma"), .log_size = 3, .row_count = 8, .multiplicity_columns = 1, .trace_multiplicity_columns = &.{}, .preprocessed_sources = &.{}, .lookup_descriptors = &.{} }};
    const bundle = fixed.Bundle{ .allocator = undefined, .graph_hash = 0, .preprocessed_identities = &.{}, .entries = &entries };
    var sources: [3][]u32 = undefined;
    var initialized: usize = 0;
    defer for (sources[0..initialized]) |source| a.free(source);
    var producers: [3]Producer = undefined;
    var expected_fixed = [_]u32{0} ** 8;
    var expected_address = [_]u32{ 1, 1 };
    var expected_big: u32 = 1;
    var expected_small: u32 = 0;
    for (&sources, &producers, 0..) |*source, *producer, i| {
        source.* = try a.alloc(u32, rows * 3);
        initialized += 1;
        for (0..rows) |row| {
            source.*[row * 3] = @intCast((row + i) % 8);
            source.*[row * 3 + 1] = @intCast(1 + row % 2);
            source.*[row * 3 + 2] = if (row % 2 == 0) memory.EncodedMemoryValueId.f252(0).raw else memory.EncodedMemoryValueId.small(2).raw;
            if (row >= rows - 3) continue;
            expected_fixed[(row + i) % 8] += 1;
            expected_address[row % 2] += 1;
            if (row % 2 == 0) expected_big += 1 else expected_small += 1;
        }
        producer.* = .{ .label = "source", .row_count = @intCast(rows), .active_rows = @intCast(rows - 3), .words_per_row = 3, .words = source.*, .lookup_words_per_row = 0, .lookup_words = &.{} };
    }
    var batch_fixed = try tables_mod.Tables.init(a, &bundle);
    defer batch_fixed.deinit();
    try batch_fixed.route(routing, &producers);
    var batch_counts = try counts_mod.collectTopology(a, &input, routing, &producers);
    defer batch_counts.deinit();
    var state = try State.init(a, &input, routing, &bundle);
    defer state.deinit();
    for (&producers) |*producer| try state.consume(producer);
    var actual_fixed = try state.takeTables();
    defer actual_fixed.deinit();
    var actual_counts = try state.takeCounts();
    defer actual_counts.deinit();
    try std.testing.expectError(error.IncrementalCountsClosed, state.consume(&producers[0]));
    try std.testing.expectEqualSlices(u32, &expected_fixed, actual_fixed.items[0].dense.?);
    try std.testing.expectEqualSlices(u32, batch_fixed.items[0].dense.?, actual_fixed.items[0].dense.?);
    try std.testing.expectEqualSlices(u32, batch_counts.address, actual_counts.address);
    try std.testing.expectEqualSlices(u32, batch_counts.big, actual_counts.big);
    try std.testing.expectEqualSlices(u32, batch_counts.small, actual_counts.small);
    try std.testing.expectEqualSlices(u32, &expected_address, actual_counts.address[0..2]);
    try std.testing.expectEqual(expected_big, actual_counts.big[0]);
    try std.testing.expectEqual(@as(u32, 1), actual_counts.small[0]);
    try std.testing.expectEqual(expected_small, actual_counts.small[2]);
    // Neither counting route may write a retained source slab.
    for (sources, 0..) |source, i| for (0..rows) |row|
        try std.testing.expectEqual(@as(u32, @intCast((row + i) % 8)), source[row * 3]);
    var invalid = producers[0];
    invalid.words_per_row = 2;
    try std.testing.expectError(error.InvalidDescriptor, counts_mod.accumulateProducers(a, routing, &.{invalid}, &actual_counts));
    actual_counts.address[0] = std.math.maxInt(u32);
    try std.testing.expectError(error.CountOverflow, counts_mod.accumulateProducers(a, routing, &.{producers[0]}, &actual_counts));
}

test "Cairo incremental feeds preserve multiplicities, public seeds and active row padding" {
    try parityCase(std.testing.allocator, 16);
}

test "Cairo incremental feeds close every allocation failure and transfer both count owners" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, parityCase, .{@as(usize, 16)});
}

test "Cairo incremental feeds preserve parallel scatter collision counts" {
    var pool: prover.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .backing_allocator = std.testing.allocator });
    defer pool.deinit();
    var binding = try prover.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    try parityCase(std.testing.allocator, 32771);
}

test "Cairo incremental feeds retire after the last gathered consumer and retain independent lookups" {
    const a = std.testing.allocator;
    var producers = [_]Producer{
        .{ .label = "blake_round", .row_count = 16, .active_rows = 16, .words_per_row = 1, .words = try a.alloc(u32, 16), .lookup_words_per_row = 1, .lookup_words = &.{} },
        .{ .label = "unconsumed", .row_count = 16, .active_rows = 16, .words_per_row = 1, .words = &.{}, .lookup_words_per_row = 1, .lookup_words = &.{} },
    };
    defer for (producers) |producer| producer.deinit(a);
    producers[0].lookup_words = try a.alloc(u32, 16);
    producers[1].words = try a.alloc(u32, 16);
    producers[1].lookup_words = try a.alloc(u32, 16);
    const retained = producers[0].words.ptr;
    const lookup = producers[0].lookup_words.ptr;
    @memset(producers[0].words, 17);
    @memset(producers[0].lookup_words, 23);
    const remaining = [_]claim.ComponentGeometry{.{ .name = "blake_g", .log_size = .{ .known = 4 } }};
    graph.retireConsumedFeeds(a, &producers, &remaining);
    try std.testing.expectEqual(retained, producers[0].words.ptr);
    try std.testing.expectEqual(@as(usize, 0), producers[1].words.len);
    graph.retireConsumedFeeds(a, &producers, &.{});
    try std.testing.expectEqual(@as(usize, 0), producers[0].words.len);
    try std.testing.expectEqual(lookup, producers[0].lookup_words.ptr);
    for (producers[0].lookup_words) |word| try std.testing.expectEqual(@as(u32, 23), word);
}
