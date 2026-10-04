//! Authentic graph/evaluation parity and owner cleanup only. No child STARK,
//! parent proof, guest, device or execution segment is run by these fixtures.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Samples = @import("../blake3_execution_sample_links.zig");
const Composition = @import("../blake3_execution_composition.zig");
const NativeDeep = @import("../blake3_native_deep.zig");
const Deep = @import("../pcs_deep_circuit.zig");
const Recorder = @import("../composition_graph_recorder.zig");
const Scalar = @import("../scalar_wire_source.zig");
const Pack = @import("../qm31_pack_wire.zig");
const View = @import("../blake3_recursive_column_rows_v1.zig");
const Storage = @import("../blake3_parent_row_storage.zig");
const Source = @import("../blake3_direct_source_columns_v1.zig");
const logs = [_]u32{ 4, 3 };
const trees = [_]Deep.TreeProfile{.{ .column_log_sizes = &logs }};
const layouts = [_]Deep.SamplePointLayout{ .current_previous, .current };
const zeros_q = [_]Q{Q.zero()} ** 3;
const zeros_m = [_]M{M.zero()} ** 2;
const witness = Deep.Witness{ .active = false, .sampled_values = &zeros_q, .queried_values = &zeros_m, .oods_seed = Q.zero(), .deep_randomness = Q.zero(), .raw_queries = zeros_m[0..1], .answers = zeros_q[0..1] };
const Fixture = struct {
    composition: Composition.Prepared,
    deep: NativeDeep.Prepared,
    fn deinit(self: *@This()) void {
        self.composition.deinit();
        self.deep.deinit();
    }
    fn init(a: std.mem.Allocator) !@This() {
        var graph = try Deep.build(a, .{ .trees = &trees, .sample_layouts = &layouts, .lifting_log_size = 5, .log_blowup_factor = 1, .query_count = 1 });
        errdefer graph.deinit();
        var evaluation = try graph.evaluate(a, witness);
        errdefer evaluation.deinit();
        var builder = Recorder.Builder.init(a);
        defer builder.deinit();
        var inputs: [3]Recorder.Input = undefined;
        for (&inputs) |*input| input.* = try builder.input();
        try builder.activate();
        try builder.constrainZero(inputs[0].value);
        builder.deactivate();
        var circuit = try builder.finish();
        errdefer circuit.deinit();
        var arena = std.heap.ArenaAllocator.init(a);
        errdefer arena.deinit();
        const owned = arena.allocator();
        const values = try owned.alloc(Q, circuit.nodes.len);
        const concrete = try owned.dupe(Q, &zeros_q);
        try circuit.evaluateInto(concrete, values);
        // Deliberately reversed sample/node order exercises the old indexed
        // scalar schedule and the independently preserved pack emission order.
        const sources = try owned.dupe(Composition.Source, &.{ .{ .sample = 2 }, .{ .sample = 1 }, .{ .sample = 0 } });
        var composition = Composition.Prepared{ .arena = arena, .circuit = circuit, .inputs = concrete, .sources = sources, .values = values, .key_id = @splat(1), .capture_seal = @splat(2), .seal = undefined };
        composition.seal = composition.identity();
        return .{ .composition = composition, .deep = .{ .graph = graph, .evaluation = evaluation, .inputs = .{ .arena = std.heap.ArenaAllocator.init(a), .inputs = witness } } };
    }
};
fn parity(comptime Air: type, rows: []const Air.Row, fixed: []const Air.Row, columns: anytype) !void {
    const borrowed = try View.ForAir(Air).init(columns.main, columns.fixed);
    try std.testing.expectEqual(rows.len, borrowed.rowCount());
    for (rows, fixed, 0..) |row, trusted, index| {
        try std.testing.expectEqualDeep(row, borrowed.rowAt(index));
        try std.testing.expectEqualDeep(Storage.compactFixed(Air, trusted), columns.fixed[index]);
    }
}
fn checkSamples(a: std.mem.Allocator) !void {
    var fixture = try Fixture.init(a);
    defer fixture.deinit();
    for ([_]u32{ 0, 1 }) |encoding_uses| {
        var legacy = try Samples.prepare(a, &fixture.composition, &fixture.deep, 1500, 1502, encoding_uses);
        defer legacy.deinit();
        var direct = try Samples.prepareColumns(a, &fixture.composition, &fixture.deep, 1500, 1502, encoding_uses);
        defer direct.deinit();
        try std.testing.expectEqual(@as(usize, 0), direct.sources.len);
        try std.testing.expectEqual(@as(usize, 0), direct.fixed_sources.len);
        try std.testing.expectEqual(@as(usize, 0), direct.packs.len);
        try std.testing.expectEqual(@as(usize, 0), direct.fixed_packs.len);
        try parity(Scalar, legacy.sources, legacy.fixed_sources, direct.columns.?.sources);
        try parity(Pack, legacy.packs, legacy.fixed_packs, direct.columns.?.packs);
        try std.testing.expectEqual(@as(usize, if (encoding_uses == 0) 1 else 3), direct.columns.?.packs.fixed.len);
        // The real source append API counts/scatters borrowed owners directly.
        var counts = Source.Counts{};
        try direct.appendInputs(&counts);
        try std.testing.expectEqual(@as(usize, 12), counts.counts[12]);
        var rejected = Source.Counts{};
        direct.sources = legacy.sources;
        try std.testing.expectError(error.InvalidExecutionSampleLink, direct.appendInputs(&rejected));
        direct.sources = &.{};
        direct.columns.?.sources.next -= 1;
        try std.testing.expectError(error.DirectRecursiveRowCountMismatch, direct.appendInputs(&rejected));
        direct.columns.?.sources.next += 1;
        try std.testing.expectEqual(@as(usize, 0), rejected.counts[12]);
        var old = Storage.Builder.init(a);
        defer old.deinit();
        var destination = try Source.Builder.init(a, &old, counts.counts);
        defer destination.deinit();
        try direct.appendInputs(&destination);
        try std.testing.expectEqual(@as(usize, 0), old.rows[12].capacity);
        try std.testing.expectEqual(@as(usize, 0), old.fixed[12].capacity);
        var prepared = Storage.Prepared{ .allocator = a, .main = @splat(&.{}), .fixed = undefined, .input_count = 0 };
        inline for (0..Storage.Airs.len) |slot| prepared.fixed[slot] = &.{};
        defer prepared.deinit();
        try destination.takeInto(&prepared.main, &prepared.fixed);
        const borrowed = try View.ForAir(Scalar).init(prepared.main[12], prepared.fixed[12]);
        for (legacy.sources, 0..) |row, index| try std.testing.expectEqualDeep(row, borrowed.rowAt(index));
    }
}
test "direct recursive scalar upstream sample columns preserve exact source and pack schedules" {
    try checkSamples(std.testing.allocator);
}
test "direct recursive scalar upstream sample owners release every allocation failure" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, checkSamples, .{});
}
test "direct recursive scalar upstream samples reject duplicate missing and changed secure inputs" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    fixture.composition.sources[1] = .{ .sample = 2 };
    try std.testing.expectError(error.InvalidExecutionSampleLink, Samples.prepareColumns(std.testing.allocator, &fixture.composition, &fixture.deep, 1500, 1502, 1));
    fixture.composition.sources[1] = .{ .sample = 1 };
    fixture.composition.sources[2] = .{ .claim = 0 };
    try std.testing.expectError(error.InvalidExecutionSampleLink, Samples.prepareColumns(std.testing.allocator, &fixture.composition, &fixture.deep, 1500, 1502, 1));
    fixture.composition.sources[2] = .{ .sample = 0 };
    fixture.composition.inputs[1] = Q.one();
    try std.testing.expectError(error.InvalidExecutionSampleLink, Samples.prepareColumns(std.testing.allocator, &fixture.composition, &fixture.deep, 1500, 1502, 1));
}
test "direct recursive scalar canonical payload preparation body codegen" {
    const payload = @import("../blake3_execution_payloads.zig");
    const prepare: *const @TypeOf(payload.prepare) = &payload.prepare;
    std.mem.doNotOptimizeAway(prepare);
}
