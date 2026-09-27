//! Nonproving original native leaf geometry/compiler tests only.
const std = @import("std");
const core = @import("stwo_core");
const Ram = @import("../recursion/block_v5_ram_lanes_recursive_shape_v1.zig");
const Range = @import("../recursion/block_v5_range16_recursive_shape_v1.zig");
const Equation = @import("../recursion/air/block_v5_word_recursive_shape_composition_v1.zig");
const Page = @import("../recursion/block_v5_memory_source_page_recursive_shape_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
fn config() !core.pcs.PcsConfig {
    return .{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 1) };
}
test "native bottom fixed: original RAM and range masks geometry independent of parent roster" {
    const a = std.testing.allocator;
    const cfg = try config();
    const ram = try Ram.Shape.init(a, 7, cfg, .{});
    defer ram.deinit();
    try ram.validateAgainst(7, cfg);
    try std.testing.expectEqualSlices(usize, &.{ 24, 54, 92, 16 }, &Ram.Shape.counts);
    try std.testing.expectEqualSlices(usize, &.{ 1, 1, 8, 8 }, &Range.Shape.counts);
    try std.testing.expectEqual(@as(u32, 7), ram.mask_log);
    try std.testing.expectEqual(@as(usize, 4), ram.deepProfile().trees.len);
    const range = try Range.Shape.init(a, 16, cfg, .{});
    defer range.deinit();
    try range.validateAgainst(16, cfg);
    for (range.layouts[2..10]) |layout| try std.testing.expectEqual(@import("../recursion/sample_point_layout.zig").Layout.current_previous, layout);
    const saved = ram.layouts[24];
    ram.layouts[24] = .previous_current;
    ram.seal = ram.identity();
    try std.testing.expectError(error.UntrustedWordRecursiveShape, ram.validateAgainst(7, cfg));
    ram.layouts[24] = saved;
    ram.seal = ram.identity();
    ram.columns[0][0] += 1;
    ram.seal = ram.identity();
    try std.testing.expectError(error.UntrustedWordRecursiveShape, ram.validateAgainst(7, cfg));
    ram.columns[0][0] -= 1;
    ram.seal = ram.identity();
    try std.testing.expectError(error.MissingWordRecursiveTranscriptAndSourcePorts, ram.requireCompleteFamilySetup());
}
test "native bottom fixed: exact52 original draw pairs and public source coordinates" {
    const a = std.testing.allocator;
    const ram = try Ram.Shape.init(a, 6, try config(), .{});
    defer ram.deinit();
    var ram_graph = try Equation.ForFamily(.ram_lanes).compile(a, ram);
    defer ram_graph.deinit();
    try checkSources(ram, &ram_graph, 61);
    const range = try Range.Shape.init(a, 16, try config(), .{});
    defer range.deinit();
    var range_graph = try Equation.ForFamily(.range16).compile(a, range);
    defer range_graph.deinit();
    try checkSources(range, &range_graph, 2);
    try range_graph.validateAgainst(range);
    range_graph.sources[range_graph.sources.len - 1] = .{ .public_input = 0 };
    range_graph.seal = range_graph.identity();
    try std.testing.expectError(error.UntrustedWordShapeComposition, range_graph.validateAgainst(range));
}
fn checkSources(shape: anytype, graph: anytype, public_count: usize) !void {
    const sample_count = try shape.sampleCount();
    try std.testing.expectEqual(sample_count + 104 + 2 + public_count, graph.sources.len);
    for (graph.sources[0..sample_count], 0..) |source, index| try std.testing.expectEqual(@as(u32, @intCast(index)), source.sample);
    for (graph.sources[sample_count..][0..104], 0..) |source, index| try std.testing.expectEqual(@as(u32, @intCast(index)), source.challenge);
    try std.testing.expectEqual(std.meta.Tag(@TypeOf(graph.sources[0])).composition, std.meta.activeTag(graph.sources[sample_count + 104]));
    try std.testing.expectEqual(std.meta.Tag(@TypeOf(graph.sources[0])).oods, std.meta.activeTag(graph.sources[sample_count + 105]));
    for (graph.sources[sample_count + 106 ..], 0..) |source, index| try std.testing.expectEqual(@as(u32, @intCast(index)), source.public_input);
}
fn wordAllocation(a: std.mem.Allocator) !void {
    const shape = try Range.Shape.init(a, 16, try config(), .{});
    defer shape.deinit();
    var graph = try Equation.ForFamily(.range16).compile(a, shape);
    defer graph.deinit();
    try shape.validateAgainst(16, try config());
    // Kernel reconstruction parity is checked once in the separate test;
    // this exhaustive OOM fixture exercises only new construction/cleanup.
    try graph.circuit.validate();
}
test "native bottom fixed: range shape and exact kernel construction rollback" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, wordAllocation, .{});
}
test "native bottom fixed: original budget owner may release before shape graph teardown" {
    const owner = try Budget.create(std.testing.allocator, 64 << 20);
    var owned = true;
    defer if (owned) owner.destroy();
    const shape = try Range.Shape.init(owner.allocator(), 16, try config(), .{});
    defer shape.deinit();
    var graph = try Equation.ForFamily(.range16).compile(owner.allocator(), shape);
    defer graph.deinit();
    owner.destroy();
    owned = false;
    try graph.circuit.validate();
    try shape.validateAgainst(16, try config());
}
fn pageGeometry(comptime kind: @import("block_v5_memory_source_page_semantic_columns_v1.zig").Kind) Page.ForKind(kind).Geometry {
    return .{ .source_log = 3, .capture_log = 3, .core_logs = @splat(4), .arithmetic_logs = .{ 1, 2, 3, 4 }, .capture_requests = 32 };
}
test "native bottom fixed: actual raw and fold PAGE nine-tree typed log inventory" {
    const a = std.testing.allocator;
    inline for (.{ .raw, .fold }) |kind| {
        const P = Page.ForKind(kind);
        const geometry = pageGeometry(kind);
        const logs = try P.deriveLogs(a, geometry, .{});
        defer for (logs) |columns| a.free(columns);
        var views: [9][]const u32 = undefined;
        for (&views, logs) |*view, columns| view.* = columns;
        try P.validateLogs(views, geometry, .{});
        try std.testing.expectEqual(@as(usize, 9), logs.len);
        for (logs, P.counts) |columns, count| try std.testing.expectEqual(count, columns.len);
        for (logs[0]) |log| try std.testing.expectEqual(@as(u32, 3), log);
        logs[8][0] += 1;
        try std.testing.expectError(error.UntrustedSourcePageShapeLogs, P.validateLogs(views, geometry, .{}));
        logs[8][0] -= 1;
        var mutated = geometry;
        mutated.capture_requests = core.fields.m31.Modulus;
        try std.testing.expectError(error.InvalidSourcePageShapeGeometry, P.requireGeometry(mutated, .{}));
        try std.testing.expectError(error.SourcePageShapeResourceLimit, P.requireGeometry(geometry, .{ .max_columns = 1 }));
    }
}
fn pageLogAllocation(a: std.mem.Allocator) !void {
    const P = Page.ForKind(.fold);
    const logs = try P.deriveLogs(a, pageGeometry(.fold), .{});
    defer for (logs) |columns| a.free(columns);
    var views: [9][]const u32 = undefined;
    for (&views, logs) |*view, columns| view.* = columns;
    try P.validateLogs(views, pageGeometry(.fold), .{});
}
test "native bottom fixed: PAGE immutable static log construction allocation cleanup" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, pageLogAllocation, .{});
}

fn pageCompilerParity(comptime kind: @import("block_v5_memory_source_page_semantic_columns_v1.zig").Kind) !void {
    const a = std.testing.allocator;
    const Components = @import("block_v5_memory_source_unified_page_components_v1.zig");
    const C = Components.ForKind(kind);
    const ArithAirs = @import("../recursion/air/arithmetic_fusion_fixed_columns_v1.zig").Airs;
    const Compiler = @import("../recursion/air/block_v5_static_component_compiler_v1.zig");
    const StaticMasks = @import("../recursion/air/block_v5_memory_source_page_shape_masks_v1.zig");
    const Recorded = @import("../recursion/air/block_v5_memory_source_page_record_v1.zig");
    const StaticEquation = @import("../recursion/air/block_v5_memory_source_page_shape_composition_v1.zig").ForKind(kind);
    const R = @import("../recursion/air/composition_graph_recorder.zig");
    const Fixture = if (kind == .raw) @import("block_v5_memory_source_page_raw_recursive_parity_test_v1.zig").Fixture else @import("block_v5_memory_source_page_recursive_test_v1.zig").Fixture;
    var fixture = try Fixture.init(a);
    defer fixture.deinit();
    // Existing algebra-only original owner/frame: constructed by its genuine
    // component factory, never accepted by a proof receiver/capture/admission.
    const core_compiler = try Compiler.ForAirs(C.CoreAirs).init(a, fixture.core_setup, fixture.frame.geometry.core_logs, @as([C.CoreAirs.len][0]core.fields.m31.M31, @splat(.{})));
    defer core_compiler.deinit();
    const arith_compiler = try Compiler.ForAirs(ArithAirs).init(a, fixture.arithmetic_setup, fixture.frame.geometry.arithmetic_logs, Components.ARITHMETIC_PARAMETERS);
    defer arith_compiler.deinit();
    try core_compiler.validateAgainst(fixture.core_setup, fixture.frame.geometry.core_logs, @as([C.CoreAirs.len][0]core.fields.m31.M31, @splat(.{})));
    try arith_compiler.validateAgainst(fixture.arithmetic_setup, fixture.frame.geometry.arithmetic_logs, Components.ARITHMETIC_PARAMETERS);
    const point = core.circle.SECURE_FIELD_CIRCLE_GEN;
    const mask_log = core.verifier_types.compositionMaskLogSize(fixture.frame.constraint_log, fixture.frame.split).?;
    const step = core.poly.circle.canonic.CanonicCoset.new(mask_log).step();
    const previous = point.sub(.{ .x = core.fields.qm31.QM31.fromBase(step.x), .y = core.fields.qm31.QM31.fromBase(step.y) });
    var live_masks = try fixture.owner.asVerifierComponent().maskPoints(a, point, mask_log);
    defer live_masks.deinitDeep(a);
    var log_views: [9][]const u32 = undefined;
    for (&log_views, fixture.frame.logs) |*view, logs| view.* = logs;
    var static_masks = try StaticMasks.derive(kind, a, fixture.frame.geometry, log_views, .{}, point, mask_log);
    defer static_masks.deinitDeep(a);
    for (live_masks.items, static_masks.items) |before, after| {
        try std.testing.expectEqual(before.len, after.len);
        for (before, after) |left, right| {
            try std.testing.expectEqual(left.len, right.len);
            for (left, right) |x, y| try std.testing.expect(x.eql(y));
        }
    }
    var compiled = try StaticEquation.compileView(a, @splat(17), fixture.graph.identity, &fixture.fixed.plan, .{ .cores = core_compiler, .arithmetic = arith_compiler }, .{ .geometry = fixture.frame.geometry, .constraint_count = fixture.frame.constraint_count, .constraint_log = fixture.frame.constraint_log, .split = fixture.frame.split }, log_views, .{});
    defer compiled.deinit();
    // Independent source layout from LIVE ORIGINAL masks, then original nominal
    // record entry. New static graph must retain every equation/input/order.
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    var builder = R.Builder.init(a);
    defer builder.deinit();
    var samples: Recorded.Samples = undefined;
    const composition_columns = core.verifier_types.compositionColumnCount(fixture.frame.split, 4).?;
    var total: usize = composition_columns;
    for (live_masks.items) |columns| for (columns) |points| {
        total += points.len;
    };
    const symbols = try temp.alloc(R.Scalar, total);
    for (symbols) |*symbol| symbol.* = (try builder.input()).value;
    samples.values = symbols;
    var cursor: usize = 0;
    for (live_masks.items, 0..) |columns, tree| {
        samples.offsets[tree] = try temp.alloc(usize, columns.len);
        samples.layouts[tree] = try temp.alloc(@import("../recursion/sample_point_layout.zig").Layout, columns.len);
        for (columns, 0..) |points, column| {
            samples.offsets[tree][column] = cursor;
            samples.layouts[tree][column] = try @import("../recursion/sample_point_layout.zig").classifyColumn(points, point, previous);
            cursor += points.len;
        }
    }
    samples.offsets[9] = try temp.alloc(usize, composition_columns);
    samples.layouts[9] = try temp.alloc(@import("../recursion/sample_point_layout.zig").Layout, composition_columns);
    @memset(samples.layouts[9], .current);
    for (samples.offsets[9]) |*offset| {
        offset.* = cursor;
        cursor += 1;
    }
    var draws: [@import("../recursion/air/universal_challenges.zig").RELATION_COUNT][2]R.Scalar = undefined;
    for (&draws) |*pair| {
        pair[0] = (try builder.input()).value;
        pair[1] = (try builder.input()).value;
    }
    const randomness = (try builder.input()).value;
    const seed = (try builder.input()).value;
    var claims: Recorded.ClaimSymbols(kind) = undefined;
    inline for (std.meta.fields(@TypeOf(claims))) |field| for (&@field(claims, field.name)) |*symbol| {
        symbol.* = (try builder.input()).value;
    };
    try builder.activate();
    var active = true;
    defer if (active) builder.deactivate();
    const challenges = try R.ChallengeSet.init(draws);
    const quotient = try Recorded.record(kind, &builder, fixture.owner, &fixture.fixed.plan, &fixture.frame, samples, claims, &challenges, randomness, seed);
    const chunks = try temp.alloc(R.Scalar, composition_columns / 4);
    for (chunks, 0..) |*chunk, index| {
        var parts: [4]R.Scalar = undefined;
        for (&parts, 0..) |*part, coordinate| part.* = try samples.at(9, 4 * index + coordinate, 0);
        chunk.* = R.fromPartialEvals(parts);
    }
    try builder.constrainZero((try R.reconstructSplitComposition(chunks, R.pointFromSeed(seed), fixture.frame.constraint_log, fixture.frame.split)).sub(quotient));
    builder.deactivate();
    active = false;
    var original_graph = try builder.finish();
    defer original_graph.deinit();
    try std.testing.expectEqual(original_graph.input_count, compiled.circuit.input_count);
    try std.testing.expectEqual(original_graph.nodes.len, compiled.circuit.nodes.len);
    try std.testing.expectEqualSlices(u8, &original_graph.identity_digest, &compiled.circuit.identity_digest);
    try std.testing.expectEqual(@as(usize, 3), compiled.circuit.outputs.len); // Both original local closures + quotient.
}
test "native bottom fixed: genuine raw PAGE static masks and all original recorded equations parity" {
    try pageCompilerParity(.raw);
}
test "native bottom fixed: genuine fold PAGE static masks and all original recorded equations parity" {
    try pageCompilerParity(.fold);
}
const ArithAirsForCustody = @import("../recursion/air/arithmetic_fusion_fixed_columns_v1.zig").Airs;
const ArithCompiler = @import("../recursion/air/block_v5_static_component_compiler_v1.zig").ForAirs(ArithAirsForCustody);
const ArithSetup = @import("block_v5_memory_source_unified_page_components_v1.zig").ArithmeticSetup;
fn compilerAllocation(a: std.mem.Allocator, setup: *const ArithSetup) !void {
    const parameters = @import("block_v5_memory_source_unified_page_components_v1.zig").ARITHMETIC_PARAMETERS;
    const compiler = try ArithCompiler.init(a, setup, @splat(2), parameters);
    defer compiler.deinit();
    try compiler.validateAgainst(setup, @splat(2), parameters);
    compiler.logs[0] += 1;
    try std.testing.expectError(error.UntrustedStaticComponentCompiler, compiler.validateAgainst(setup, @splat(2), parameters));
}
test "native bottom fixed: immutable PAGE compiler custody mutation and construction OOM" {
    const setup = try ArithSetup.create(std.testing.allocator);
    defer setup.release();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, compilerAllocation, .{setup});
    const owner = try Budget.create(std.testing.allocator, 64 << 20);
    var active = true;
    defer if (active) owner.destroy();
    const budget_setup = try ArithSetup.create(owner.allocator());
    var original_setup = true;
    defer if (original_setup) budget_setup.release();
    const compiler = try ArithCompiler.init(owner.allocator(), budget_setup, @splat(2), @import("block_v5_memory_source_unified_page_components_v1.zig").ARITHMETIC_PARAMETERS);
    defer compiler.deinit();
    budget_setup.release();
    original_setup = false;
    owner.destroy();
    active = false;
    // Both original owner references have gone; durable compiler lease keeps
    // original authenticated definitions/allocator alive until actual teardown.
    try compiler.validateAgainst(budget_setup, @splat(2), @import("block_v5_memory_source_unified_page_components_v1.zig").ARITHMETIC_PARAMETERS);
}
