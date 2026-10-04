//! Independent source-construction fixtures; no fresh child proof or hash-path
//! receipt is fabricated. Canonical parent wiring waits for the prior freeze.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Deep = @import("../pcs_deep_circuit.zig");
const Fri = @import("../fri_verifier_circuit.zig");
const NativeDeep = @import("../blake3_native_deep.zig");
const NativeFri = @import("../blake3_native_fri.zig");
const Native = @import("../blake3_native_transcript.zig");
const Transcript = @import("../blake3_transcript_witness.zig");
const Terminal = @import("../blake3_terminal_links.zig");
const Columns = @import("../blake3_pcs_source_columns_v1.zig");
const LegacyQueries = @import("../blake3_native_queries.zig");
const Opening = @import("../blake3_opening_inputs.zig");
const Scalar = @import("../scalar_wire_source.zig");
const Lower = @import("../verifier_arithmetic_lowering.zig");
const Source = @import("../blake3_direct_source_columns_v1.zig");
const logs = [_]u32{2};
const trees = [_]Deep.TreeProfile{.{ .column_log_sizes = &logs }};
const layouts = [_]Deep.SamplePointLayout{.current};
const q0 = [_]Q{Q.zero()};
const m0 = [_]M{M.zero()};
const pair = [_]Q{ Q.zero(), Q.zero() };
const authenticated = [_][]const Q{&pair};
const positions = [_][]const M{&m0};
const widths = [_]u32{2};
const query_values = [_]u32{0};
const operations = [_]Transcript.Operation{.{ .queries = .{ .log_domain_size = 2, .values = &query_values, .export_outputs = true } }};
const dw = Deep.Witness{ .active = false, .sampled_values = &q0, .queried_values = &m0, .oods_seed = Q.zero(), .deep_randomness = Q.zero(), .raw_queries = &m0, .answers = &q0 };
const fw = Fri.Witness{ .active = false, .deep_answers = &q0, .authenticated_values = &authenticated, .fri_alphas = &q0, .raw_queries = &m0, .fri_positions = &positions, .fri_offsets = &positions, .last_layer_positions = &m0, .last_layer_coefficients = &q0 };
pub const Fixture = struct {
    a: std.mem.Allocator,
    deep: NativeDeep.Prepared,
    fri: NativeFri.Prepared,
    transcript: Native.Planned,
    sources: []Opening.Source,
    pub fn init(a: std.mem.Allocator) !Fixture {
        var dg = try Deep.build(a, .{ .trees = &trees, .sample_layouts = &layouts, .lifting_log_size = 2, .log_blowup_factor = 1, .query_count = 1 });
        errdefer dg.deinit();
        var de = try dg.evaluate(a, dw);
        errdefer de.deinit();
        var fg = try Fri.build(a, .{ .lifting_log_size = 2, .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .fold_widths = &widths, .query_count = 1 });
        errdefer fg.deinit();
        var fe = try fg.evaluate(a, fw);
        errdefer fe.deinit();
        var links = try Terminal.build(a, &dg, &fg, 1, 1);
        errdefer links.deinit();
        var arena = std.heap.ArenaAllocator.init(a);
        errdefer arena.deinit();
        const copied_ops = try arena.allocator().dupe(Transcript.Operation, &operations);
        var plan = try @import("../blake3_transcript_plan.zig").Plan.initCompact(a, .{ .namespace = 9_000_101, .attempt_capacity = 1 }, copied_ops);
        errdefer plan.deinit();
        var sources: std.ArrayList(Opening.Source) = .empty;
        defer sources.deinit(a);
        for (dg.bindings) |binding| if (binding.source == .queried_value) {
            try sources.append(a, .{ .lane = 1, .node = binding.node_id, .value = de.values[binding.node_id].toM31Array()[0] });
        };
        for (fg.bindings) |binding| if (binding.source == .authenticated_value_word) {
            try sources.append(a, .{ .lane = 2, .node = binding.node_id, .value = fe.values[binding.node_id].toM31Array()[0] });
        };
        std.mem.reverse(Opening.Source, sources.items);
        const owned_sources = try sources.toOwnedSlice(a);
        return .{ .a = a, .sources = owned_sources, .deep = .{ .graph = dg, .evaluation = de, .inputs = .{ .arena = std.heap.ArenaAllocator.init(a), .inputs = dw } }, .fri = .{ .arena = std.heap.ArenaAllocator.init(a), .graph = fg, .evaluation = fe, .links = links, .inputs = .{ .arena = std.heap.ArenaAllocator.init(a), .inputs = fw }, .sources = &.{}, .fixed_sources = &.{}, .destinations = &.{}, .fixed_destinations = &.{} }, .transcript = .{ .arena = arena, .operations = copied_ops, .claim_payloads = &.{}, .plan = plan, .end = .{} } };
    }
    pub fn deinit(self: *Fixture) void {
        self.a.free(self.sources);
        self.transcript.deinit();
        self.fri.deinit();
        self.deep.deinit();
    }
};
fn check(a: std.mem.Allocator, f: *const Fixture) !void {
    var answers = try Columns.Answers.init(a, &f.deep, &f.fri.graph, &f.fri.evaluation, 1502, 1504);
    defer answers.deinit();
    const deep_scratch = try a.alloc(u32, f.deep.graph.nodes.len);
    defer a.free(deep_scratch);
    const deep_uses = try Lower.computeUseCountsInto(f.deep.graph.graph(), deep_scratch);
    const fri_scratch = try a.alloc(u32, f.fri.graph.nodes.len);
    defer a.free(fri_scratch);
    const fri_uses = try Lower.computeUseCountsInto(f.fri.graph.graph(), fri_scratch);
    const answer_view = try answers.columns.view(12);
    for (f.fri.links.?.answers, 0..) |link, index| {
        const value = f.deep.evaluation.values[link.deep].toM31Array()[0];
        const source = try Scalar.logicalRow(1502, link.deep, try std.math.add(u32, deep_uses[link.deep], 1), value);
        const destination = try Scalar.routedRow(1504, link.fri, fri_uses[link.fri], 1502, link.deep, value);
        try std.testing.expectEqualDeep(source, answer_view.rowAt(index));
        try std.testing.expectEqualDeep(destination, answer_view.rowAt(f.fri.links.?.answers.len + index));
    }
    var query_rows = try LegacyQueries.prepareRows(a, &f.transcript, &f.deep, &f.fri);
    defer query_rows.deinit();
    var queries = try Columns.Queries.init(a, &f.transcript, &f.deep, &f.fri);
    defer queries.deinit();
    var canonical = try LegacyQueries.prepare(a, &f.transcript, &f.deep, &f.fri);
    defer canonical.deinit();
    try std.testing.expectEqual(@as(usize, 0), canonical.rows.len);
    try std.testing.expectEqual(@as(usize, 0), canonical.fixed.len);
    var count = Source.Counts{};
    try std.testing.expectError(error.UnfinalizedNativeQueryPaths, queries.appendInputs(&count));
    try std.testing.expectEqual(@as(usize, 0), count.counts[12]);
    const projection = [_][31]u32{@splat(2)};
    for (0..31) |bit| {
        try query_rows.links.addPathUses(0, bit, 8);
        try queries.links.addPathUses(0, bit, 8);
        try canonical.links.addPathUses(0, bit, 8);
    }
    try LegacyQueries.applyPathReads(a, &query_rows, &f.deep, &projection);
    try queries.applyPathReads(a, &f.deep, &projection);
    try LegacyQueries.applyPathReads(a, &canonical, &f.deep, &projection);
    const query_view = try queries.columns.view(12);
    const canonical_view = try canonical.columns.?.view(12);
    for (query_rows.rows, 0..) |row, index| try std.testing.expectEqualDeep(row, query_view.rowAt(index));
    for (query_rows.rows, 0..) |row, index| try std.testing.expectEqualDeep(row, canonical_view.rowAt(index));
    const encoded_view = try queries.columns.view(10);
    for (query_rows.encoded, 0..) |row, index| try std.testing.expectEqualDeep(row, encoded_view.rowAt(index));
    try queries.applyPathReads(a, &f.deep, &projection);
    for (query_rows.rows, 0..) |row, index| try std.testing.expectEqualDeep(row, query_view.rowAt(index));
    try answers.appendInputs(&count);
    try queries.appendInputs(&count);
    try queries.appendEncoded(&count);
    var openings = try Columns.Openings.init(a, f.sources, &f.deep, &f.fri);
    defer openings.deinit();
    const opening_view = try openings.columns.view(12);
    for (f.sources, 0..) |source, index| {
        const lane = source.lane - 1;
        const weight = try std.math.add(u32, (if (lane == 0) deep_uses else fri_uses)[source.node], if (lane == 0) @as(u32, 2) else 1);
        try std.testing.expectEqualDeep(try Scalar.logicalRow(if (lane == 0) 1502 else 1504, source.node, weight, source.value), opening_view.rowAt(index));
    }
    try openings.appendInputs(&count);
    try std.testing.expectEqual(answer_view.rowCount() + query_view.rowCount() + opening_view.rowCount(), count.counts[12]);
    try std.testing.expectEqual(query_rows.encoded.len, count.counts[10]);
    // Source mode cannot silently blend a direct source with an old dense row
    // roster. Failed admission must not increment any cohort counts.
    canonical.rows = query_rows.rows;
    const prior = count.counts;
    try std.testing.expectError(error.InvalidNativeQueryLink, canonical.appendInputs(&count));
    try std.testing.expectEqualDeep(prior, count.counts);
    canonical.rows = &.{};
}
test "PCS direct source columns preserve answer query fanout and opening inventory" {
    var f = try Fixture.init(std.testing.allocator);
    defer f.deinit();
    try check(std.testing.allocator, &f);
}
test "PCS direct source columns release every failed constructor and fanout allocation" {
    var f = try Fixture.init(std.testing.allocator);
    defer f.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, check, .{&f});
}
fn reject(expected: anyerror, result: anytype) !void {
    if (result) |value| {
        var owner = value;
        owner.deinit();
        return error.TestUnexpectedError;
    } else |err| {
        if (err == error.OutOfMemory) return err;
        try std.testing.expectEqual(expected, err);
    }
}
test "PCS direct source columns reject changed missing duplicate and wrong lane openings" {
    const a = std.testing.allocator;
    var f = try Fixture.init(a);
    defer f.deinit();
    try reject(error.InvalidNativeOpeningSource, Columns.Openings.init(a, f.sources[1..], &f.deep, &f.fri));
    const original = f.sources[0];
    f.sources[0] = f.sources[1];
    try reject(error.InvalidNativeOpeningSource, Columns.Openings.init(a, f.sources, &f.deep, &f.fri));
    f.sources[0] = original;
    f.sources[0].value = M.one();
    try reject(error.InvalidNativeOpeningSource, Columns.Openings.init(a, f.sources, &f.deep, &f.fri));
    f.sources[0] = original;
    f.sources[0].lane = 3;
    try reject(error.InvalidNativeOpeningSource, Columns.Openings.init(a, f.sources, &f.deep, &f.fri));
    f.sources[0] = original;
}
test "PCS direct source columns reject transcript query swap and fanout overflow atomically" {
    const a = std.testing.allocator;
    var f = try Fixture.init(a);
    defer f.deinit();
    const altered = [_]u32{1};
    f.transcript.operations[0].queries.values = &altered;
    try reject(error.InvalidNativeQueryLink, Columns.Queries.init(a, &f.transcript, &f.deep, &f.fri));
    f.transcript.operations[0].queries.values = &query_values;
    var queries = try Columns.Queries.init(a, &f.transcript, &f.deep, &f.fri);
    defer queries.deinit();
    const view = try queries.columns.view(12);
    const before = view.rowAt(1);
    const invalid = [_][31]u32{blk: {
        var tuple: [31]u32 = @splat(1);
        tuple[30] = core.fields.m31.Modulus;
        break :blk tuple;
    }};
    try std.testing.expectError(error.InvalidNativeQueryLink, queries.applyPathReads(a, &f.deep, &invalid));
    try std.testing.expectEqualDeep(before, view.rowAt(1));
    try std.testing.expect(!queries.paths_applied);
    const valid = [_][31]u32{@splat(0)};
    try queries.applyPathReads(a, &f.deep, &valid);
    const snapshot = view.rowAt(1);
    try std.testing.expectError(error.InvalidNativeQueryLink, queries.applyPathReads(a, &f.deep, &invalid));
    try std.testing.expectEqualDeep(snapshot, view.rowAt(1));
    try std.testing.expect(queries.paths_applied);
    queries.links.queries[0].bits[0].deep = std.math.maxInt(u32);
    try std.testing.expectError(error.InvalidNativeQueryLink, queries.applyPathReads(a, &f.deep, &valid));
    try std.testing.expectEqualDeep(snapshot, view.rowAt(1));
}
fn codegenFri(a: std.mem.Allocator, capture: *const core.verifier.ProofCapture(@import("../../blake3_engine_protocol.zig").Hasher), config: core.pcs.PcsConfig, deep: *const NativeDeep.Prepared) anyerror!NativeFri.Prepared {
    return NativeFri.prepareCaptured(a, capture, config, deep, 1502, 1504);
}
fn codegenFriOracle(a: std.mem.Allocator, capture: *const core.verifier.ProofCapture(@import("../../blake3_engine_protocol.zig").Hasher), config: core.pcs.PcsConfig, deep: *const NativeDeep.Prepared) anyerror!NativeFri.Prepared {
    return NativeFri.prepareCapturedRows(a, capture, config, deep, 1502, 1504);
}
fn codegenOpenings(a: std.mem.Allocator, paths: *@import("../blake3_stark_paths.zig").Prepared, deep: *const NativeDeep.Prepared, fri: *const NativeFri.Prepared) anyerror!@import("../blake3_native_openings.zig").Prepared {
    return @import("../blake3_native_openings.zig").prepare(a, paths, deep, fri);
}
test "PCS direct source columns canonical captured FRI and opening bodies compile" {
    // Functions are emitted, never called with invented captures or paths.
    inline for (.{ &codegenFri, &codegenFriOracle, &codegenOpenings }) |function| std.mem.doNotOptimizeAway(function);
}
