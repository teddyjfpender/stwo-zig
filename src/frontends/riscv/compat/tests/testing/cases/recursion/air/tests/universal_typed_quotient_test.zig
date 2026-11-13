//! Retained typed-component contract checks; fixtures are test-owned.
const support = @import("universal_typed_component_test_support.zig");
const std = support.std;
const stwo_core = support.stwo_core;
const circle = support.circle;
const pcs = support.pcs;
const M31 = support.M31;
const QM31 = support.QM31;
const prover_accumulation = support.prover_accumulation;
const prover_component = support.prover_component;
const prepared_domain = support.prepared_domain;
const prover_task_graph = support.prover_task_graph;
const manifest_mod = support.manifest_mod;
const adapter = support.adapter;
const universal = support.universal;
const merkle = support.merkle;
const merkle_relation = support.merkle_relation;
const MerkleAdapter = support.MerkleAdapter;
const merkleGeometry = support.merkleGeometry;
const runTypedPreparedWithWorkers = support.runTypedPreparedWithWorkers;

test "Ethereum typed quotient domains reject recovery larger than quotient buffer" {
    const helpers = @import("stwo_riscv_air_lang").framework.universal_typed_component_contract;
    const circle_poly = @import("stwo_prover_engine").poly.circle;
    const trace_log: u32 = 4;
    const committed_log: u32 = trace_log + 4;
    const quotient_log: u32 = trace_log + 2;
    const committed = [_]M31{M31.zero()} ** (1 << committed_log);
    const coefficients = [_]M31{M31.zero()} ** (1 << trace_log);
    var poly = prover_component.Poly{ .log_size = committed_log, .values = &committed };
    try std.testing.expectError(error.InvalidProofShape, helpers.sourceNeedsExtension(poly, trace_log, quotient_log));
    poly.coefficients = try circle_poly.CircleCoefficients.initBorrowed(&coefficients);
    try std.testing.expect(try helpers.sourceNeedsExtension(poly, trace_log, quotient_log));
    try std.testing.expect(!try helpers.sourceNeedsExtension(poly, trace_log, committed_log));
    try std.testing.expectError(error.InvalidProofShape, helpers.sourceNeedsExtension(poly, trace_log + 1, quotient_log));
}

test "Ethereum typed quotient domains recover released coefficients with exact polynomial parity" {
    const helpers = @import("stwo_riscv_air_lang").framework.universal_typed_component_contract;
    const circle_poly = @import("stwo_prover_engine").poly.circle;
    const twiddles_mod = @import("stwo_prover_engine").poly.twiddles;
    const allocator = std.testing.allocator;
    for ([_]u32{ 2, 4, 6, 7, 8 }) |trace_log| {
        const source_domain = helpers.canonic.CanonicCoset.new(trace_log + 1).circleDomain();
        const quotient_domain = helpers.canonic.CanonicCoset.new(trace_log + 2).circleDomain();
        const native_size = @as(usize, 1) << @intCast(trace_log);
        const coefficients = try allocator.alloc(M31, native_size);
        defer allocator.free(coefficients);
        for (coefficients, 0..) |*coefficient, index|
            coefficient.* = M31.fromCanonical(@intCast(index * index + 3 * index + 7));
        const polynomial = try circle_poly.CircleCoefficients.initBorrowed(coefficients);
        const committed = try polynomial.evaluate(allocator, source_domain);
        defer allocator.free(@constCast(committed.values));
        const original_committed = try allocator.dupe(M31, committed.values);
        defer allocator.free(original_committed);
        const expected = try polynomial.evaluate(allocator, quotient_domain);
        defer allocator.free(@constCast(expected.values));
        var empty_buffers: [0][]M31 = .{};
        var borrowed_count: usize = 0;
        const borrowed = try helpers.evaluationValues(
            allocator,
            .{ .log_size = trace_log + 1, .values = committed.values },
            trace_log,
            trace_log + 1,
            source_domain.size(),
            null,
            &empty_buffers,
            &borrowed_count,
        );
        try std.testing.expect(borrowed.ptr == committed.values.ptr);
        try std.testing.expectEqual(@as(usize, 0), borrowed_count);
        var twiddles = try twiddles_mod.precomputeM31(allocator, quotient_domain.half_coset);
        defer twiddles_mod.deinitM31(allocator, &twiddles);
        const transform = twiddles_mod.TwiddleTree([]const M31).init(
            twiddles.root_coset,
            twiddles.twiddles,
            twiddles.itwiddles,
        );
        for ([_]bool{ false, true }) |retained| {
            const source = prover_component.Poly{
                .log_size = trace_log + 1,
                .values = committed.values,
                .coefficients = if (retained) polynomial else null,
            };
            try std.testing.expect(try helpers.sourceNeedsExtension(source, trace_log, trace_log + 2));
            var buffers: [1][]M31 = undefined;
            var initialized: usize = 0;
            defer for (buffers[0..initialized]) |buffer| allocator.free(buffer);
            const values = helpers.evaluationValues(
                allocator,
                source,
                trace_log,
                trace_log + 2,
                quotient_domain.size(),
                transform,
                &buffers,
                &initialized,
            ) catch |err| {
                std.debug.print("QUOTIENT_RECOVERY_PARITY trace_log={d} retained={} source_log={d} quotient_log={d} tower_matches={} error={s}\n", .{
                    trace_log,                                                   retained,        source.log_size, quotient_domain.logSize(),
                    source_domain.half_coset.isDoublingOf(transform.root_coset), @errorName(err),
                });
                var recovered = try circle_poly.poly.interpolateFromEvaluationWithTwiddles(
                    allocator,
                    committed,
                    transform,
                );
                defer recovered.deinit(allocator);
                for (recovered.coefficients(), 0..) |actual, index| {
                    const want = if (index < coefficients.len) coefficients[index] else M31.zero();
                    if (!actual.eql(want)) {
                        std.debug.print("QUOTIENT_RECOVERY_COEFFICIENT index={d} actual={d} expected={d}\n", .{ index, actual.v, want.v });
                        break;
                    }
                }
                return err;
            };
            try std.testing.expectEqual(@as(usize, 1), initialized);
            try std.testing.expect(values.ptr == buffers[0].ptr);
            try std.testing.expectEqualSlices(M31, coefficients, values[0..native_size]);
            for (values[native_size..]) |coefficient| try std.testing.expect(coefficient.isZero());
            try circle_poly.poly.evaluateBuffersWithTwiddles(&buffers, quotient_domain, transform);
            try std.testing.expectEqualSlices(M31, expected.values, values);
            try std.testing.expectEqualSlices(M31, original_committed, committed.values);
        }
    }
}

test "Ethereum typed quotient domains reject recovered high degree before truncation" {
    const helpers = @import("stwo_riscv_air_lang").framework.universal_typed_component_contract;
    const circle_poly = @import("stwo_prover_engine").poly.circle;
    const twiddles_mod = @import("stwo_prover_engine").poly.twiddles;
    const allocator = std.testing.allocator;
    const trace_log: u32 = 4;
    const source_domain = helpers.canonic.CanonicCoset.new(trace_log + 1).circleDomain();
    const quotient_domain = helpers.canonic.CanonicCoset.new(trace_log + 2).circleDomain();
    var coefficients = [_]M31{M31.zero()} ** 32;
    coefficients[0] = M31.one();
    coefficients[16] = M31.one();
    const polynomial = try circle_poly.CircleCoefficients.initBorrowed(&coefficients);
    const committed = try polynomial.evaluate(allocator, source_domain);
    defer allocator.free(@constCast(committed.values));
    const source = prover_component.Poly{ .log_size = trace_log + 1, .values = committed.values };
    var twiddles = try twiddles_mod.precomputeM31(allocator, quotient_domain.half_coset);
    defer twiddles_mod.deinitM31(allocator, &twiddles);
    var buffers: [1][]M31 = undefined;
    var initialized: usize = 0;
    defer for (buffers[0..initialized]) |buffer| allocator.free(buffer);
    try std.testing.expectError(error.InvalidProofShape, helpers.evaluationValues(
        allocator,
        source,
        trace_log,
        trace_log + 2,
        quotient_domain.size(),
        .{ .root_coset = twiddles.root_coset, .twiddles = twiddles.twiddles, .itwiddles = twiddles.itwiddles },
        &buffers,
        &initialized,
    ));
    try std.testing.expectEqual(@as(usize, 0), initialized);
    try std.testing.expectError(error.InvalidProofShape, helpers.sourceNeedsExtension(source, trace_log + 2, trace_log + 3));
}

test "R-012 generic adapter shards exact quotient rows with bounded workers and joins failures" {
    const allocator = std.testing.allocator;
    var definition = try merkle.build(allocator);
    defer definition.deinit();
    const relation_plan = try merkle_relation.authenticate(&definition);
    var relations = universal.UniversalRelations.dummy();
    const log_size: u32 = 17;
    var builder = manifest_mod.Builder{};
    _ = try builder.append(merkleGeometry(log_size));
    const manifest = try builder.seal();
    const component = try MerkleAdapter.init(&definition, relation_plan, &manifest, .merkle_path, log_size, .{}, &relations, QM31.zero());
    const eval_log = component.maxConstraintLogDegreeBound();
    const size = @as(usize, 1) << @intCast(eval_log);
    const values = try allocator.alloc(M31, size);
    defer allocator.free(values);
    for (values, 0..) |*value, row| value.* = M31.fromU64(row * 7919 + 17);
    const poly = prover_component.Poly{ .log_size = eval_log, .values = values };
    var main = [_]prover_component.Poly{poly} ** merkle.PHYSICAL_MAIN_COLUMN_COUNT;
    var interaction = [_]prover_component.Poly{poly} ** merkle.INTERACTION_COLUMN_COUNT;
    var trees = [_][]const prover_component.Poly{ &.{}, &main, &interaction };
    const trace = prover_component.Trace{ .polys = pcs.TreeVec([]const prover_component.Poly).initOwned(&trees) };
    var expected: [4][]M31 = undefined;
    var expected_initialized: usize = 0;
    defer for (expected[0..expected_initialized]) |column| allocator.free(column);
    for ([_]usize{ 1, 2, 4 }) |workers| {
        var accumulator = try prover_accumulation.DomainEvaluationAccumulator.init(allocator, QM31.fromU32Unchecked(3, 1, 4, 1), eval_log, 2 * component.nConstraints());
        defer accumulator.deinit();
        const prover = component.asProverComponent();
        var fresh = (try prover.prepareConstraintQuotientsOnDomain(allocator, &trace, &accumulator)).?;
        defer fresh.deinit();
        var additive = (try prover.prepareConstraintQuotientsOnDomain(allocator, &trace, &accumulator)).?;
        defer additive.deinit();
        try std.testing.expectEqual(prover_task_graph.TaskClass.pool_exclusive, fresh.task_class);
        for ([_]*prepared_domain.PreparedDomainEvaluation{ &fresh, &additive }) |prepared| {
            const before = MerkleAdapter.preparedParallelTelemetrySnapshot();
            try runTypedPreparedWithWorkers(prepared, workers, false);
            const after = MerkleAdapter.preparedParallelTelemetrySnapshot();
            try std.testing.expectEqual(@as(u64, @intCast(workers - 1)), after.child_submissions - before.child_submissions);
            try std.testing.expectEqual(after.child_submissions - before.child_submissions, after.child_completions - before.child_completions);
            try std.testing.expectEqual(before.range_failures, after.range_failures);
        }
        var result = try accumulator.finalize();
        defer result.deinit(allocator);
        for (result.columns, 0..) |column, coordinate| {
            if (workers == 1) {
                expected[coordinate] = try allocator.dupe(M31, column);
                expected_initialized += 1;
            } else try std.testing.expectEqualSlices(M31, expected[coordinate], column);
        }
    }

    var accumulator = try prover_accumulation.DomainEvaluationAccumulator.init(allocator, QM31.one(), eval_log, component.nConstraints());
    defer accumulator.deinit();
    const prover = component.asProverComponent();
    var prepared = (try prover.prepareConstraintQuotientsOnDomain(allocator, &trace, &accumulator)).?;
    defer prepared.deinit();
    // Exercise cancellation on the actual four-worker path, before any row
    // writes. Every submitted range must still join before producer teardown.
    const before = MerkleAdapter.preparedParallelTelemetrySnapshot();
    try runTypedPreparedWithWorkers(&prepared, 4, true);
    const after = MerkleAdapter.preparedParallelTelemetrySnapshot();
    try std.testing.expectEqual(@as(u64, 3), after.child_submissions - before.child_submissions);
    try std.testing.expectEqual(@as(u64, 3), after.child_completions - before.child_completions);
    const column = accumulator.sub_accumulations[eval_log].?;
    for (0..column.len()) |row| try std.testing.expect(column.at(row).isZero());

    // An invalid borrowed challenge arity induces a real row-evaluation error
    // after admission. A failing helper cannot outlive the prepared owner.
    var failure_accumulator = try prover_accumulation.DomainEvaluationAccumulator.init(allocator, QM31.one(), eval_log, component.nConstraints());
    defer failure_accumulator.deinit();
    var failure_prepared = (try prover.prepareConstraintQuotientsOnDomain(allocator, &trace, &failure_accumulator)).?;
    defer failure_prepared.deinit();
    relations.elements[@intFromEnum(relation_plan.events[0].domain)].arity = 0;
    const failure_before = MerkleAdapter.preparedParallelTelemetrySnapshot();
    try std.testing.expectError(error.InvalidArity, runTypedPreparedWithWorkers(&failure_prepared, 4, false));
    const failure_after = MerkleAdapter.preparedParallelTelemetrySnapshot();
    try std.testing.expectEqual(@as(u64, 3), failure_after.child_submissions - failure_before.child_submissions);
    try std.testing.expectEqual(@as(u64, 3), failure_after.child_completions - failure_before.child_completions);
    try std.testing.expect(failure_after.range_failures > failure_before.range_failures);
}
