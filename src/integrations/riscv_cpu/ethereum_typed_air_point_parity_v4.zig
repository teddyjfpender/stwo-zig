//! Diagnostic equation parity at identical domain points. These synthetic
//! polynomials are deliberately not a valid witness or a proof fixture.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const frontend = @import("stwo_riscv_frontend");
const air = frontend.recursion.air;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const manifest_mod = air.universal_adapter_manifest;

fn affine(comptime Field: type, point: anytype, column: usize) Field {
    const a = M31.fromU64(11 + 3 * column);
    const b = M31.fromU64(17 + 5 * column);
    const c = M31.fromU64(23 + 7 * column);
    if (Field == M31) return point.x.mul(a).add(point.y.mul(b)).add(c);
    return point.x.mulM31(a).add(point.y.mulM31(b)).add(QM31.fromBase(c));
}

const GeometryMode = enum { local, legacy, admitted };

fn check(comptime Air: type, comptime row: manifest_mod.ComponentKey, comptime mode: GeometryMode, comptime lift: u32) !void {
    const allocator = std.testing.allocator;
    const Relation = air.universal_relation_binding.Binding(Air);
    const Adapter = air.universal_typed_component.Component(Air, Relation);
    var definition = try Air.build(allocator);
    defer definition.deinit();
    const plan = try Relation.authenticate(&definition);
    const relations = air.universal_challenges.UniversalRelations.dummy();
    const trace_log: u32 = 3;
    var builder = manifest_mod.Builder{};
    _ = try builder.append(Adapter.manifestGeometry(row, trace_log));
    const manifest = try builder.seal();
    const parameters = [_]M31{M31.one()} ** Adapter.PARAMETER_COLUMN_COUNT;
    const component = try Adapter.init(&definition, plan, &manifest, row, trace_log, parameters, &relations, QM31.fromU32Unchecked(2, 3, 5, 7));
    const eval_log = component.maxConstraintLogDegreeBound();
    const domain = core.poly.circle.canonic.CanonicCoset.new(eval_log).circleDomain();
    const profile = @import("ethereum_wrapper_composition_v1.zig");
    const prover_component = if (mode == .admitted)
        try profile.admitProver(component.asProverComponent(), trace_log, Adapter.PROTOCOL_CONSTRAINT_DEGREE)
    else
        component.asProverComponent();
    const verifier_component = if (mode == .admitted)
        try profile.admitVerifier(component.asVerifierComponent(), trace_log, Adapter.PROTOCOL_CONSTRAINT_DEGREE)
    else
        component.asVerifierComponent();
    const composition_log = prover_component.maxConstraintLogDegreeBound() + lift;
    const composition_domain = core.poly.circle.canonic.CanonicCoset.new(composition_log).circleDomain();
    const mask_log = if (mode != .local) composition_log - verifier_component.compositionLogSplit() else trace_log;
    const counts = [_]usize{ Air.PREPROCESSED_COLUMN_COUNT, Air.PHYSICAL_MAIN_COLUMN_COUNT, Air.INTERACTION_COLUMN_COUNT };
    const count = counts[0] + counts[1] + counts[2];
    const values = try allocator.alloc(M31, count * domain.size());
    defer allocator.free(values);
    const polys = try allocator.alloc(prover.air.component_prover.Poly, count);
    defer allocator.free(polys);
    for (polys, 0..) |*poly, column| {
        const cells = values[column * domain.size() ..][0..domain.size()];
        for (cells, 0..) |*cell, index| cell.* = affine(M31, domain.at(core.utils.bitReverseIndex(index, eval_log)), column);
        poly.* = .{ .log_size = eval_log, .values = cells };
    }
    var trees = [_][]const prover.air.component_prover.Poly{
        polys[0..counts[0]], polys[counts[0]..][0..counts[1]], polys[counts[0] + counts[1] ..],
    };
    const trace = prover.air.component_prover.Trace{ .polys = core.pcs.TreeVec([]const prover.air.component_prover.Poly).initOwned(&trees) };
    const random = QM31.fromU32Unchecked(13, 19, 29, 31);
    var domain_accumulator = try prover.air.accumulation.DomainEvaluationAccumulator.init(allocator, random, composition_log, component.nConstraints());
    defer domain_accumulator.deinit();
    try prover_component.evaluateConstraintQuotientsOnDomain(&trace, &domain_accumulator);
    var result = try domain_accumulator.finalize();
    defer result.deinit(allocator);
    for (0..composition_domain.size()) |index| {
        const base_point = composition_domain.at(core.utils.bitReverseIndex(index, composition_log));
        const point = core.circle.CirclePointQM31{ .x = QM31.fromBase(base_point.x), .y = QM31.fromBase(base_point.y) };
        var masks = try verifier_component.maskPoints(allocator, point, mask_log);
        defer masks.deinitDeep(allocator);
        var sampled_trees: [3][][]QM31 = undefined;
        var tree_count: usize = 0;
        defer for (sampled_trees[0..tree_count]) |tree| {
            for (tree) |column| allocator.free(column);
            allocator.free(tree);
        };
        var column_offset: usize = 0;
        for (masks.items, &sampled_trees) |tree, *sampled| {
            sampled.* = try allocator.alloc([]QM31, tree.len);
            var initialized: usize = 0;
            errdefer {
                for (sampled.*[0..initialized]) |column| allocator.free(column);
                allocator.free(sampled.*);
            }
            for (tree, sampled.*, 0..) |points, *column, local| {
                column.* = try allocator.alloc(QM31, points.len);
                initialized += 1;
                for (points, column.*) |sample_point, *value| value.* = affine(QM31, sample_point.repeatedDouble(mask_log - trace_log), column_offset + local);
            }
            column_offset += tree.len;
            tree_count += 1;
        }
        const samples = core.pcs.TreeVec([][]QM31).initOwned(&sampled_trees);
        var point_accumulator = core.air.accumulation.PointEvaluationAccumulator.init(random);
        try verifier_component.evaluateConstraintQuotientsAtPoint(point, &samples, &point_accumulator, mask_log);
        if (!result.at(index).eql(point_accumulator.finalize())) {
            std.debug.print("ETHEREUM_TYPED_POINT_PARITY component={s} row={d} trace_log={d} eval_log={d}\n", .{ @tagName(row), index, trace_log, eval_log });
            return error.TypedAirDomainPointMismatch;
        }
    }
}

test "Ethereum typed AIR nonzero domain and point equations agree" {
    try check(air.ethereum_publication_control_v1, .vm_public_logup_control, .local, 0);
    try check(air.merkle_path, .merkle_path, .local, 0);
}

test "Ethereum typed AIR production composition geometry agrees" {
    try check(air.merkle_path, .merkle_path, .legacy, 0);
    try check(air.merkle_path, .merkle_path, .legacy, 2);
    // Retain the actual defect: q2 evaluated with the default q1 split
    // aliases a different trace point even before any heterogeneous lift.
    try std.testing.expectError(error.TypedAirDomainPointMismatch, check(air.ethereum_publication_control_v1, .vm_public_logup_control, .legacy, 0));
    try check(air.ethereum_publication_control_v1, .vm_public_logup_control, .admitted, 0);
    try check(air.ethereum_publication_control_v1, .vm_public_logup_control, .admitted, 2);
}
