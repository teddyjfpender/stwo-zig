//! Focused adapter and accumulation tests for component provers.

const std = @import("std");
const circle = @import("stwo_core").circle;
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const pcs = @import("stwo_core").pcs;
const canonic = @import("stwo_core").poly.circle.canonic;
const accumulation = @import("accumulation.zig");
const oods_work = @import("oods_work.zig");
const secure_poly = @import("../poly/circle/secure_poly.zig");
const secure_column = @import("../secure_column.zig");
const owner = @import("component_prover.zig");

const CirclePointQM31 = circle.CirclePointQM31;
const M31 = m31.M31;
const QM31 = qm31.QM31;
const TreeVec = pcs.TreeVec;
const SecureColumnByCoords = secure_column.SecureColumnByCoords;
const ComponentProver = owner.ComponentProver;
const ComponentProvers = owner.ComponentProvers;
const Poly = owner.Poly;
const Trace = owner.Trace;

test "prover air component prover: poly lifting index" {
    const values = [_]M31{
        M31.fromCanonical(10),
        M31.fromCanonical(20),
        M31.fromCanonical(30),
        M31.fromCanonical(40),
    };
    const poly = Poly{ .log_size = 2, .values = values[0..] };
    try std.testing.expect((try poly.valueAtLiftingPosition(2, 3)).eql(values[3]));

    const lifted = [_]M31{
        values[0],
        values[1],
        values[0],
        values[1],
        values[2],
        values[3],
        values[2],
        values[3],
    };
    var i: usize = 0;
    while (i < lifted.len) : (i += 1) {
        try std.testing.expect((try poly.valueAtLiftingPosition(3, i)).eql(lifted[i]));
    }
}

test "prover air component prover: composition accumulation" {
    const alloc = std.testing.allocator;

    const Mock = struct {
        max_log_size: u32,

        fn asComponent(self: *const @This()) ComponentProver {
            return .{
                .ctx = self,
                .vtable = &.{
                    .nConstraints = nConstraints,
                    .maxConstraintLogDegreeBound = maxConstraintLogDegreeBound,
                    .traceLogDegreeBounds = traceLogDegreeBounds,
                    .maskPoints = maskPoints,
                    .preprocessedColumnIndices = preprocessedColumnIndices,
                    .evaluateConstraintQuotientsAtPoint = evaluateConstraintQuotientsAtPoint,
                    .evaluateConstraintQuotientsOnDomain = evaluateConstraintQuotientsOnDomain,
                },
            };
        }

        fn cast(ctx: *const anyopaque) *const @This() {
            return @ptrCast(@alignCast(ctx));
        }

        fn nConstraints(_: *const anyopaque) usize {
            return 1;
        }

        fn maxConstraintLogDegreeBound(ctx: *const anyopaque) u32 {
            return cast(ctx).max_log_size;
        }

        fn traceLogDegreeBounds(
            ctx: *const anyopaque,
            allocator: std.mem.Allocator,
        ) !core_air_components.TraceLogDegreeBounds {
            const self = cast(ctx);
            const preprocessed = try allocator.alloc(u32, 0);
            const main = try allocator.dupe(u32, &[_]u32{self.max_log_size});
            return core_air_components.TraceLogDegreeBounds.initOwned(
                try allocator.dupe([]u32, &[_][]u32{ preprocessed, main }),
            );
        }

        fn maskPoints(
            _: *const anyopaque,
            allocator: std.mem.Allocator,
            point: CirclePointQM31,
            _: u32,
        ) !core_air_components.MaskPoints {
            const pp_cols = try allocator.alloc([]CirclePointQM31, 0);
            const main_col = try allocator.alloc(CirclePointQM31, 1);
            main_col[0] = point;
            const main_cols = try allocator.dupe([]CirclePointQM31, &[_][]CirclePointQM31{main_col});
            return core_air_components.MaskPoints.initOwned(
                try allocator.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{
                    pp_cols,
                    main_cols,
                }),
            );
        }

        fn preprocessedColumnIndices(_: *const anyopaque, allocator: std.mem.Allocator) ![]usize {
            return allocator.alloc(usize, 0);
        }

        fn evaluateConstraintQuotientsAtPoint(
            _: *const anyopaque,
            point: CirclePointQM31,
            _: *const core_air_components.MaskValues,
            evaluation_accumulator: *core_air_accumulation.PointEvaluationAccumulator,
            _: u32,
        ) !void {
            const values = domainValues();
            var col = try SecureColumnByCoords.fromSecureSlice(
                std.testing.allocator,
                &values,
            );
            defer col.deinit(std.testing.allocator);
            var polynomial = try secure_poly.interpolateFromEvaluation(
                std.testing.allocator,
                canonic.CanonicCoset.new(2).circleDomain(),
                &col,
            );
            defer polynomial.deinit(std.testing.allocator);
            evaluation_accumulator.accumulate(polynomial.evalAtPoint(point));
        }

        fn evaluateConstraintQuotientsOnDomain(
            _: *const anyopaque,
            _: *const Trace,
            evaluation_accumulator: *accumulation.DomainEvaluationAccumulator,
        ) !void {
            const values = domainValues();
            var col = try SecureColumnByCoords.fromSecureSlice(std.testing.allocator, &values);
            defer col.deinit(std.testing.allocator);
            try evaluation_accumulator.accumulateColumn(2, &col);
        }

        fn domainValues() [4]QM31 {
            return .{
                QM31.fromU32Unchecked(1, 0, 0, 0),
                QM31.fromU32Unchecked(2, 0, 0, 0),
                QM31.fromU32Unchecked(3, 0, 0, 0),
                QM31.fromU32Unchecked(4, 0, 0, 0),
            };
        }
    };

    const mock = Mock{ .max_log_size = 2 };
    var ordinary_component = mock.asComponent();
    ordinary_component.backend_composition_capability = .{
        .quadratic_sum_squares_v1 = .{
            .trace_tree_index = 0,
            .first_column = 0,
        },
    };
    const components_arr = [_]ComponentProver{ordinary_component};
    try std.testing.expect(components_arr[0].backend_composition_capability != null);
    const lifted_component = try components_arr[0]
        .withCompositionGeometryOverrideV1(.{
        .max_constraint_log_degree_bound_delta = 1,
        .composition_log_split = 2,
    });
    try std.testing.expectEqual(
        components_arr[0].maxConstraintLogDegreeBound() + 1,
        lifted_component.maxConstraintLogDegreeBound(),
    );
    try std.testing.expectEqual(@as(u32, 1), components_arr[0].compositionLogSplit());
    try std.testing.expectEqual(@as(u32, 2), lifted_component.compositionLogSplit());
    try std.testing.expect(lifted_component.ctx == components_arr[0].ctx);
    try std.testing.expect(lifted_component.vtable == components_arr[0].vtable);
    try std.testing.expect(lifted_component.backend_composition_capability == null);
    try std.testing.expect(components_arr[0].backend_composition_capability != null);
    try std.testing.expect(lifted_component.prepare_domain_evaluator ==
        components_arr[0].prepare_domain_evaluator);
    try std.testing.expect(lifted_component.domain_parallel_evaluator ==
        components_arr[0].domain_parallel_evaluator);
    const lifted_components_arr = [_]ComponentProver{lifted_component};
    const component_provers = ComponentProvers{
        .components = lifted_components_arr[0..],
        .n_preprocessed_columns = 0,
    };
    try std.testing.expect(
        component_provers.components[0].composition_geometry_override_v1 != null,
    );

    var trace = Trace{ .polys = TreeVec([]const Poly).initOwned(try alloc.alloc([]const Poly, 0)) };
    defer trace.polys.deinit(alloc);

    var combined = try component_provers.computeCompositionEvaluation(
        alloc,
        QM31.fromU32Unchecked(7, 0, 0, 0),
        &trace,
    );
    defer combined.deinit(alloc);

    const out = try combined.toVec(alloc);
    defer alloc.free(out);
    try std.testing.expectEqual(@as(usize, 8), out.len);

    // The candidate wrapper must perform true polynomial extension.  The
    // widened domain polynomial therefore evaluates at an arbitrary OODS
    // point exactly like the intrinsic q1 polynomial; a repeated-index lift
    // does not have this identity for this nonconstant fixture.
    var widened_polynomial = try secure_poly.interpolateFromEvaluation(
        alloc,
        canonic.CanonicCoset.new(3).circleDomain(),
        &combined,
    );
    defer widened_polynomial.deinit(alloc);

    var view = try component_provers.componentsView(alloc);
    defer view.deinit(alloc);

    const components = view.asCore();
    try std.testing.expectEqual(@as(usize, 1), components.components.len);
    try std.testing.expectEqual(@as(usize, 0), components.n_preprocessed_columns);

    var mask = try components.maskPoints(
        alloc,
        circle.SECURE_FIELD_CIRCLE_GEN,
        lifted_component.maxConstraintLogDegreeBound(),
        true,
    );
    defer mask.deinitDeep(alloc);
    try std.testing.expectEqual(@as(usize, 2), mask.items.len);

    var mask_values = core_air_components.MaskValues.initOwned(try alloc.alloc([][]QM31, 0));
    defer mask_values.deinitDeep(alloc);
    const eval = try components.evalCompositionPolynomialAtPoint(
        circle.SECURE_FIELD_CIRCLE_GEN,
        &mask_values,
        QM31.fromU32Unchecked(5, 0, 0, 0),
        lifted_component.maxConstraintLogDegreeBound(),
    );
    try std.testing.expect(eval.eql(
        widened_polynomial.evalAtPoint(circle.SECURE_FIELD_CIRCLE_GEN),
    ));

    // The same useful work succeeds through the cold profiled path, but a
    // component with no owner callback must never manufacture a zero receipt.
    var absent_mask_capture = oods_work.Capture{};
    var profiled_mask = try view.maskPointsWithWorkCapture(
        alloc,
        circle.SECURE_FIELD_CIRCLE_GEN,
        lifted_component.maxConstraintLogDegreeBound(),
        true,
        &absent_mask_capture,
    );
    defer profiled_mask.deinitDeep(alloc);
    try std.testing.expect(absent_mask_capture.receipt == null);

    var absent_constraint_capture = oods_work.Capture{};
    const profiled_eval = try view.evalCompositionPolynomialAtPointWithWorkCapture(
        alloc,
        circle.SECURE_FIELD_CIRCLE_GEN,
        &mask_values,
        QM31.fromU32Unchecked(5, 0, 0, 0),
        lifted_component.maxConstraintLogDegreeBound(),
        3,
        2,
        &absent_constraint_capture,
    );
    try std.testing.expect(profiled_eval.eql(eval));
    try std.testing.expect(absent_constraint_capture.receipt == null);
}

test "prover air component prover: multi-component sequential matches merged accumulators" {
    // Verify that splitting accumulation across two independent accumulators
    // (simulating what the parallel path does) produces the same result as
    // the sequential path with a single accumulator.
    const alloc = std.testing.allocator;
    const alpha = QM31.fromU32Unchecked(7, 0, 0, 0);

    const MockA = struct {
        fn asComponent(self: *const @This()) ComponentProver {
            return .{
                .ctx = self,
                .vtable = &.{
                    .nConstraints = nConstraints,
                    .maxConstraintLogDegreeBound = maxConstraintLogDegreeBound,
                    .traceLogDegreeBounds = traceLogDegreeBounds,
                    .maskPoints = maskPoints,
                    .preprocessedColumnIndices = preprocessedColumnIndices,
                    .evaluateConstraintQuotientsAtPoint = evaluateConstraintQuotientsAtPoint,
                    .evaluateConstraintQuotientsOnDomain = evaluateConstraintQuotientsOnDomain,
                },
            };
        }
        fn nConstraints(_: *const anyopaque) usize {
            return 1;
        }
        fn maxConstraintLogDegreeBound(_: *const anyopaque) u32 {
            return 2;
        }
        fn traceLogDegreeBounds(_: *const anyopaque, a: std.mem.Allocator) !core_air_components.TraceLogDegreeBounds {
            const preprocessed = try a.alloc(u32, 0);
            const main_tree = try a.dupe(u32, &[_]u32{2});
            return core_air_components.TraceLogDegreeBounds.initOwned(
                try a.dupe([]u32, &[_][]u32{ preprocessed, main_tree }),
            );
        }
        fn maskPoints(_: *const anyopaque, a: std.mem.Allocator, point: CirclePointQM31, _: u32) !core_air_components.MaskPoints {
            const pp = try a.alloc([]CirclePointQM31, 0);
            const mc = try a.alloc(CirclePointQM31, 1);
            mc[0] = point;
            const mcs = try a.dupe([]CirclePointQM31, &[_][]CirclePointQM31{mc});
            return core_air_components.MaskPoints.initOwned(
                try a.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{ pp, mcs }),
            );
        }
        fn preprocessedColumnIndices(_: *const anyopaque, a: std.mem.Allocator) ![]usize {
            return a.alloc(usize, 0);
        }
        fn evaluateConstraintQuotientsAtPoint(_: *const anyopaque, _: CirclePointQM31, _: *const core_air_components.MaskValues, _: *core_air_accumulation.PointEvaluationAccumulator, _: u32) !void {}
        fn evaluateConstraintQuotientsOnDomain(
            _: *const anyopaque,
            _: *const Trace,
            evaluation_accumulator: *accumulation.DomainEvaluationAccumulator,
        ) !void {
            const values = [_]QM31{
                QM31.fromU32Unchecked(1, 0, 0, 0),
                QM31.fromU32Unchecked(2, 0, 0, 0),
                QM31.fromU32Unchecked(3, 0, 0, 0),
                QM31.fromU32Unchecked(4, 0, 0, 0),
            };
            var col = try SecureColumnByCoords.fromSecureSlice(std.testing.allocator, values[0..]);
            defer col.deinit(std.testing.allocator);
            try evaluation_accumulator.accumulateColumn(2, &col);
        }
    };

    const MockB = struct {
        fn asComponent(self: *const @This()) ComponentProver {
            return .{
                .ctx = self,
                .vtable = &.{
                    .nConstraints = nConstraints,
                    .maxConstraintLogDegreeBound = maxConstraintLogDegreeBound,
                    .traceLogDegreeBounds = traceLogDegreeBounds,
                    .maskPoints = maskPoints,
                    .preprocessedColumnIndices = preprocessedColumnIndices,
                    .evaluateConstraintQuotientsAtPoint = evaluateConstraintQuotientsAtPoint,
                    .evaluateConstraintQuotientsOnDomain = evaluateConstraintQuotientsOnDomain,
                },
            };
        }
        fn nConstraints(_: *const anyopaque) usize {
            return 1;
        }
        fn maxConstraintLogDegreeBound(_: *const anyopaque) u32 {
            return 2;
        }
        fn traceLogDegreeBounds(_: *const anyopaque, a: std.mem.Allocator) !core_air_components.TraceLogDegreeBounds {
            const preprocessed = try a.alloc(u32, 0);
            const main_tree = try a.dupe(u32, &[_]u32{2});
            return core_air_components.TraceLogDegreeBounds.initOwned(
                try a.dupe([]u32, &[_][]u32{ preprocessed, main_tree }),
            );
        }
        fn maskPoints(_: *const anyopaque, a: std.mem.Allocator, point: CirclePointQM31, _: u32) !core_air_components.MaskPoints {
            const pp = try a.alloc([]CirclePointQM31, 0);
            const mc = try a.alloc(CirclePointQM31, 1);
            mc[0] = point;
            const mcs = try a.dupe([]CirclePointQM31, &[_][]CirclePointQM31{mc});
            return core_air_components.MaskPoints.initOwned(
                try a.dupe([][]CirclePointQM31, &[_][][]CirclePointQM31{ pp, mcs }),
            );
        }
        fn preprocessedColumnIndices(_: *const anyopaque, a: std.mem.Allocator) ![]usize {
            return a.alloc(usize, 0);
        }
        fn evaluateConstraintQuotientsAtPoint(_: *const anyopaque, _: CirclePointQM31, _: *const core_air_components.MaskValues, _: *core_air_accumulation.PointEvaluationAccumulator, _: u32) !void {}
        fn evaluateConstraintQuotientsOnDomain(
            _: *const anyopaque,
            _: *const Trace,
            evaluation_accumulator: *accumulation.DomainEvaluationAccumulator,
        ) !void {
            const values = [_]QM31{
                QM31.fromU32Unchecked(10, 0, 0, 0),
                QM31.fromU32Unchecked(20, 0, 0, 0),
                QM31.fromU32Unchecked(30, 0, 0, 0),
                QM31.fromU32Unchecked(40, 0, 0, 0),
            };
            var col = try SecureColumnByCoords.fromSecureSlice(std.testing.allocator, values[0..]);
            defer col.deinit(std.testing.allocator);
            try evaluation_accumulator.accumulateColumn(2, &col);
        }
    };

    const mock_a = MockA{};
    const mock_b = MockB{};
    const components_arr = [_]ComponentProver{ mock_a.asComponent(), mock_b.asComponent() };
    const component_provers = ComponentProvers{
        .components = components_arr[0..],
        .n_preprocessed_columns = 0,
    };

    var trace = Trace{ .polys = TreeVec([]const Poly).initOwned(try alloc.alloc([]const Poly, 0)) };
    defer trace.polys.deinit(alloc);

    // Test builds deliberately suppress the process-global pool, so the public
    // entry point exercises the sequential fallback without widening the
    // production API solely for test visibility.
    var sequential = try component_provers.computeCompositionEvaluation(
        alloc,
        alpha,
        &trace,
    );
    defer sequential.deinit(alloc);
    const seq_vec = try sequential.toVec(alloc);
    defer alloc.free(seq_vec);
    const total_constraints = component_provers.totalConstraints();
    const max_log_size = component_provers.compositionLogDegreeBound();
    const powers = try accumulation.generateSecurePowers(alloc, alpha, total_constraints);
    defer alloc.free(powers);
    var acc_a = try accumulation.DomainEvaluationAccumulator.initForComponent(powers, alloc, max_log_size, 2);
    defer acc_a.deinit();
    var acc_b = try accumulation.DomainEvaluationAccumulator.initForComponent(powers, alloc, max_log_size, 1);
    defer acc_b.deinit();
    try components_arr[0].evaluateConstraintQuotientsOnDomain(&trace, &acc_a);
    try components_arr[1].evaluateConstraintQuotientsOnDomain(&trace, &acc_b);
    acc_a.merge(&acc_b);
    acc_a.next_power_index = 0;
    var merged = try acc_a.finalize();
    defer merged.deinit(alloc);
    const merged_vec = try merged.toVec(alloc);
    defer alloc.free(merged_vec);
    try std.testing.expectEqual(seq_vec.len, merged_vec.len);
    for (seq_vec, merged_vec) |s, m| {
        try std.testing.expect(s.eql(m));
    }
}
