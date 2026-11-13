//! Real raw-transcript AIR quotient ownership, allocation and coefficient parity.
const std = @import("std");
const stwo_core = @import("stwo_core");
const pcs = stwo_core.pcs;
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const prover_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const manifest_mod = @import("stwo_riscv_air_lang").framework.universal_adapter_manifest;
const adapter = @import("stwo_riscv_air_lang").framework.universal_typed_component;
const universal = @import("stwo_riscv_air_lang").framework.universal_challenges;
const prover_task_graph = @import("stwo_prover_engine").task_graph;
const prover_work_pool = @import("stwo_prover_engine").work_pool;

pub const RawQuotientAir = @import("../ethereum_transcript_payload_raw.zig");
pub const RawQuotientAdapter = adapter.Component(RawQuotientAir, RawQuotientAir.Relation);

pub fn runRawQuotientStorage(
    allocator: std.mem.Allocator,
    values_allocator: ?std.mem.Allocator,
    component: *const RawQuotientAdapter,
    source_trace: *const prover_component.Trace,
) ![64]QM31 {
    var measured = std.testing.FailingAllocator.init(allocator, .{});
    const tracked = measured.allocator();
    var trace = source_trace.*;
    trace.quotient_values_allocator = values_allocator;
    var accumulator = try prover_accumulation.DomainEvaluationAccumulator.init(
        tracked,
        QM31.fromU32Unchecked(3, 1, 4, 1),
        component.maxConstraintLogDegreeBound(),
        component.nConstraints(),
    );
    defer accumulator.deinit();
    const prover = component.asProverComponent();
    var prepared = (try prover.prepareConstraintQuotientsOnDomain(tracked, &trace, &accumulator)).?;
    defer prepared.deinit();
    var cancellation = prover_task_graph.CancellationToken{};
    var context = prover_task_graph.TaskContext{
        .user_context = prepared.context,
        .cancellation = &cancellation,
        .key = .{ .epoch = 0, .stage_rank = 0, .component_registry_index = 0, .shard_or_chunk_index = 0 },
        .worker_budget = prover_work_pool.WorkerBudget.serial(),
        .task_class = .leaf,
        .exclusive_lease = null,
        .child_wait_group = null,
    };
    const allocations = measured.alloc_index;
    measured.fail_index = allocations;
    measured.resize_fail_index = measured.resize_index;
    try prepared.run(&context);
    try std.testing.expectEqual(allocations, measured.alloc_index);
    try std.testing.expect(!measured.has_induced_failure);
    measured.fail_index = std.math.maxInt(usize);
    measured.resize_fail_index = std.math.maxInt(usize);
    var result = try accumulator.finalize();
    defer result.deinit(tracked);
    try std.testing.expectEqual(@as(usize, 64), result.len());
    var values: [64]QM31 = undefined;
    for (&values, 0..) |*value, index| value.* = result.at(index);
    return values;
}

pub fn failRawQuotientValues(
    allocator: std.mem.Allocator,
    component: *const RawQuotientAdapter,
    trace: *const prover_component.Trace,
) !void {
    _ = try runRawQuotientStorage(std.testing.allocator, allocator, component, trace);
}

pub fn failRawQuotientMetadata(
    allocator: std.mem.Allocator,
    component: *const RawQuotientAdapter,
    trace: *const prover_component.Trace,
) !void {
    // A distinct value allocator catches wrong-owner cleanup when metadata,
    // twiddles, the accumulator or prepared state fails after value allocation.
    var values = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    defer std.debug.assert(values.allocated_bytes == values.freed_bytes);
    _ = try runRawQuotientStorage(allocator, values.allocator(), component, trace);
}

test "Ethereum typed quotient domains route owned values and preserve mapped quotient results" {
    const allocator = std.testing.allocator;
    var definition = try RawQuotientAir.build(allocator);
    defer definition.deinit();
    const relation_plan = try RawQuotientAir.Relation.authenticate(&definition);
    var builder = manifest_mod.Builder{};
    _ = try builder.append(RawQuotientAdapter.manifestGeometry(.transcript_payload, 4));
    const manifest = try builder.seal();
    const relations = universal.UniversalRelations.dummy();
    const component = try RawQuotientAdapter.init(
        &definition,
        relation_plan,
        &manifest,
        .transcript_payload,
        4,
        [_]M31{M31.zero()} ** RawQuotientAir.PARAMETER_COUNT,
        &relations,
        QM31.zero(),
    );
    // Exactly the failing real route's geometry ratio: native log4, committed
    // log5, quotient log6, no retained coefficients. Nonconstant inputs make
    // both inverse and forward transforms observable in the quotient parity.
    const circle_poly = @import("stwo_prover_engine").poly.circle;
    var coefficients: [16]M31 = undefined;
    for (&coefficients, 0..) |*value, index| value.* = M31.fromCanonical(@intCast(index * index + 7));
    const polynomial = try circle_poly.CircleCoefficients.initBorrowed(&coefficients);
    const committed = try polynomial.evaluate(allocator, stwo_core.poly.circle.canonic.CanonicCoset.new(5).circleDomain());
    defer allocator.free(@constCast(committed.values));
    const original = try allocator.dupe(M31, committed.values);
    defer allocator.free(original);
    const poly = prover_component.Poly{ .log_size = 5, .values = committed.values };
    var pp = [_]prover_component.Poly{poly} ** RawQuotientAir.PREPROCESSED_COLUMN_COUNT;
    var main = [_]prover_component.Poly{poly} ** RawQuotientAir.PHYSICAL_MAIN_COLUMN_COUNT;
    var interaction = [_]prover_component.Poly{poly} ** RawQuotientAir.INTERACTION_COLUMN_COUNT;
    var trees = [_][]const prover_component.Poly{ &pp, &main, &interaction };
    const trace = prover_component.Trace{ .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(&trees) };
    const expected = try runRawQuotientStorage(allocator, null, &component, &trace);
    var measured = std.testing.FailingAllocator.init(allocator, .{});
    const actual = try runRawQuotientStorage(allocator, measured.allocator(), &component, &trace);
    try std.testing.expectEqualDeep(expected, actual);
    const source_count = pp.len + main.len + interaction.len;
    try std.testing.expectEqual(source_count, measured.alloc_index);
    try std.testing.expectEqual(source_count * 64 * @sizeOf(M31), measured.allocated_bytes);
    try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const directory = try tmp.dir.realpathAlloc(allocator, ".");
    defer allocator.free(directory);
    var mapped = try @import("stwo_prover_engine").mmap_alloc.FileBackedAllocator.init(directory);
    defer mapped.deinit();
    const mapped_result = try runRawQuotientStorage(allocator, mapped.allocator(), &component, &trace);
    try std.testing.expectEqualDeep(expected, mapped_result);
    try std.testing.expect(mapped.total_bytes.load(.monotonic) > 0);
    try std.testing.expectEqual(@as(usize, 0), mapped.live_bytes.load(.monotonic));
    try std.testing.expectEqualSlices(M31, original, committed.values);
    try std.testing.checkAllAllocationFailures(allocator, failRawQuotientValues, .{ &component, &trace });
    try std.testing.checkAllAllocationFailures(allocator, failRawQuotientMetadata, .{ &component, &trace });
}

test "coefficient coset composition matches full domain including rotated interactions" {
    const allocator = std.testing.allocator;
    var definition = try RawQuotientAir.build(allocator);
    defer definition.deinit();
    const relation_plan = try RawQuotientAir.Relation.authenticate(&definition);
    var builder = manifest_mod.Builder{};
    _ = try builder.append(RawQuotientAdapter.manifestGeometry(.transcript_payload, 4));
    const manifest = try builder.seal();
    const relations = universal.UniversalRelations.dummy();
    const component = try RawQuotientAdapter.init(
        &definition,
        relation_plan,
        &manifest,
        .transcript_payload,
        4,
        [_]M31{M31.zero()} ** RawQuotientAir.PARAMETER_COUNT,
        &relations,
        QM31.zero(),
    );
    // Exactly the failing real route's geometry ratio: native log4, committed
    // log5, quotient log6, no retained coefficients. Nonconstant inputs make
    // both inverse and forward transforms observable in the quotient parity.
    const circle_poly = @import("stwo_prover_engine").poly.circle;
    var coefficients: [16]M31 = undefined;
    for (&coefficients, 0..) |*value, index| value.* = M31.fromCanonical(@intCast(index * index + 7));
    const polynomial = try circle_poly.CircleCoefficients.initBorrowed(&coefficients);
    const committed = try polynomial.evaluate(allocator, stwo_core.poly.circle.canonic.CanonicCoset.new(5).circleDomain());
    defer allocator.free(@constCast(committed.values));
    const original = try allocator.dupe(M31, committed.values);
    defer allocator.free(original);
    const poly = prover_component.Poly{ .log_size = 5, .values = committed.values };
    var pp = [_]prover_component.Poly{poly} ** RawQuotientAir.PREPROCESSED_COLUMN_COUNT;
    var main = [_]prover_component.Poly{poly} ** RawQuotientAir.PHYSICAL_MAIN_COLUMN_COUNT;
    var interaction = [_]prover_component.Poly{poly} ** RawQuotientAir.INTERACTION_COLUMN_COUNT;
    var trees = [_][]const prover_component.Poly{ &pp, &main, &interaction };
    const trace = prover_component.Trace{ .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(&trees) };
    const expected = try runRawQuotientStorage(allocator, null, &component, &trace);
    const compact_poly = prover_component.Poly{ .log_size = 5, .values = &.{}, .coefficients = polynomial };
    @memset(&pp, compact_poly);
    @memset(&main, compact_poly);
    @memset(&interaction, compact_poly);
    var compact_trace = trace;
    compact_trace.partition_coefficient_composition = true;
    var values_allocator = std.testing.FailingAllocator.init(allocator, .{});
    const actual = try runRawQuotientStorage(allocator, values_allocator.allocator(), &component, &compact_trace);
    try std.testing.expectEqualDeep(expected, actual);
    const source_count = pp.len + main.len + interaction.len;
    const full_tail: usize = if (RawQuotientAir.INTERACTION_COLUMN_COUNT != 0) 4 else 0;
    const expected_values = (source_count - full_tail) * 16 + full_tail * 64;
    try std.testing.expectEqual(expected_values * @sizeOf(M31), values_allocator.allocated_bytes);
    try std.testing.expectEqual(values_allocator.allocated_bytes, values_allocator.freed_bytes);
    try std.testing.checkAllAllocationFailures(allocator, failRawQuotientValues, .{ &component, &compact_trace });
    try std.testing.checkAllAllocationFailures(allocator, failRawQuotientMetadata, .{ &component, &compact_trace });
}
