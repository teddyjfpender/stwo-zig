//! Synthetic geometry checks, not child-proof verification. Native mask
//! generation is the independent reference for the fixed sample counts.
const std = @import("std");
const core = @import("stwo_core");
const recursion = @import("stwo_riscv_frontend").recursion;
const subject = @import("ethereum_wrapper_child_shape_v1.zig");
const verifier = @import("ethereum_wrapper_root_verifier_v1.zig");
const components_mod = @import("ethereum_wrapper_verifier_components_v1.zig");
const fixture = @import("ethereum_wrapper_root_verifier_v1_test.zig");
const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;

test "Ethereum child fixed shape matches native component masks and split2 geometry" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const key = try fixture.testKey();
    const owner = try subject.OwnedV1.create(allocator, &key);
    const capture = try syntheticCapture(allocator, &key, owner);
    try owner.validateCaptureShape(allocator, &capture);
    const shape = owner.proofShape();
    const d = owner.wireDimensions();
    try std.testing.expectEqual(@as(usize, 193), d.query_count);
    try std.testing.expectEqual(@as(usize, 36), d.claimed_sum_count);
    try std.testing.expectEqual(@as(u32, 16), shape.tree_column_counts[3]);
    try std.testing.expectEqual(@as(u32, 2), owner.fixedGeometry().composition_log_split);
    try std.testing.expectEqual(@as(u64, 772), try shape.tracePathCount());
    try std.testing.expectEqual(@as(usize, shape.table_count) * 193, d.queried_value_count);
    try std.testing.expectEqual(try recursion.fixed_wire.serializedByteCountRuntime(d), shape.proof_wire_bytes);
    try recursion.fixed_wire.validateDimensionsAgainstShape(d, shape.*);
    var native_samples: usize = 0;
    for (capture.sampled_points) |tree| for (tree) |column| {
        native_samples += column.len;
    };
    try std.testing.expectEqual(native_samples, d.sampled_value_count);
    const pcs = try key.session_fields.protocol.pcsConfig();
    try std.testing.expect(shape.fri.eql(try recursion.fixed_profile.FriSchedule.init(shape.column_log_degree, pcs.fri_config)));
}

test "Ethereum child fixed shape ignores compression and rejects raw slot mutations" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const key = try fixture.testKey();
    const owner = try subject.OwnedV1.create(allocator, &key);
    var capture = try syntheticCapture(allocator, &key, owner);
    const dimensions = owner.wireDimensions();
    const unique = capture.queries.unique;
    capture.queries.unique = unique[0..1];
    try owner.validateCaptureShape(allocator, &capture);
    // Slot geometry is independent of duplicate-query compression. These are
    // shape-only fixtures: values/positions need verification separately.
    capture.queries.unique = unique;
    try owner.validateCaptureShape(allocator, &capture);
    try std.testing.expectEqualDeep(dimensions, owner.wireDimensions());
    const queried = capture.queried_values;
    capture.queried_values = queried[0 .. queried.len - 1];
    try std.testing.expectError(error.EthereumChildCaptureShapeMismatch, owner.validateCaptureShape(allocator, &capture));
    capture.queried_values = queried;
    const raw = capture.queries.raw;
    capture.queries.raw = raw[0 .. raw.len - 1];
    try std.testing.expectError(error.EthereumChildCaptureShapeMismatch, owner.validateCaptureShape(allocator, &capture));
    capture.queries.raw = raw;
    capture.fri.layers[0].query_count -= 1;
    try std.testing.expectError(error.EthereumChildCaptureShapeMismatch, owner.validateCaptureShape(allocator, &capture));
    capture.fri.layers[0].query_count += 1;
    capture.trace_paths[0].path_depth -= 1;
    try std.testing.expectError(error.EthereumChildCaptureShapeMismatch, owner.validateCaptureShape(allocator, &capture));
    capture.trace_paths[0].path_depth += 1;
    const composition = capture.sampled_points[3];
    capture.sampled_points[3] = composition[0..8];
    try std.testing.expectError(error.InvalidCompositionGeometry, owner.validateCaptureShape(allocator, &capture));
    capture.sampled_points[3] = composition;
    try owner.validateCaptureShape(allocator, &capture);
}

test "Ethereum child fixed shape owns key geometry and rejects changed admission" {
    const allocator = std.testing.allocator;
    var key = try fixture.testKey();
    const owner = try subject.OwnedV1.create(allocator, &key);
    defer owner.deinit();
    const before = owner.proofShape().*;
    try owner.validateAgainstKey(&key);
    key.preprocessed_root[0] += 1;
    key.session_fields = try @import("ethereum_wrapper_fixed_circuit_v1.zig").sessionFields(&key);
    try std.testing.expectError(error.EthereumChildShapeKeyMismatch, owner.validateAgainstKey(&key));
    try std.testing.expectEqualDeep(before, owner.proofShape().*);
    const changed = try subject.OwnedV1.create(allocator, &key);
    defer changed.deinit();
    try std.testing.expect(!std.meta.eql(before.preprocessing_id, changed.proofShape().preprocessing_id));
    // Root replacement cannot choose geometry, but it does change admission.
    try std.testing.expectEqualDeep(owner.wireDimensions(), changed.wireDimensions());
    try std.testing.expect(!subject.FOLD_ADMISSION_AVAILABLE);
}

fn syntheticCapture(allocator: std.mem.Allocator, key: *const verifier.KeyV1, shape_owner: *const subject.OwnedV1) !verifier.ProofCapture {
    const claims: verifier.ClaimsV1 = .{ .values = @splat(QM31.zero()), .poseidon_partials = @splat(QM31.zero()) };
    const relations = recursion.air.universal_challenges.UniversalRelations.dummy();
    const owner = try components_mod.OwnedComponentsV1.init(allocator, &key.manifest, key.parameters, &relations, claims);
    defer owner.deinit();
    const components = core.air.components.Components{ .components = try owner.verifierComponents(), .n_preprocessed_columns = key.manifest.total_preprocessed_columns };
    const geometry = shape_owner.fixedGeometry();
    try std.testing.expectEqual(geometry.composition_log_size, components.compositionLogDegreeBound());
    try std.testing.expectEqual(geometry.composition_log_split, try components.compositionLogSplit());
    const point = core.circle.secureFieldPointFromRandomSeed(QM31.fromU32Unchecked(3, 5, 7, 11));
    var masks = try components.maskPoints(allocator, point, geometry.composition_chunk_log_degree, false);
    defer masks.deinitDeep(allocator);
    var capture: verifier.ProofCapture = std.mem.zeroes(verifier.ProofCapture);
    const d = shape_owner.wireDimensions();
    const shape = shape_owner.proofShape();
    capture.commitments = try allocator.alloc(recursion.poseidon2_channel.Digest, d.commitment_count);
    @memset(capture.commitments, @splat(0));
    capture.commitments[0] = key.preprocessed_root;
    capture.sampled_points = try allocator.alloc([][]core.circle.CirclePointQM31, 4);
    for (masks.items, capture.sampled_points[0..3]) |tree, *out| {
        out.* = try allocator.alloc([]core.circle.CirclePointQM31, tree.len);
        for (tree, out.*) |column, *destination| destination.* = try allocator.dupe(core.circle.CirclePointQM31, column);
    }
    capture.sampled_points[3] = try allocator.alloc([]core.circle.CirclePointQM31, shape.tree_column_counts[3]);
    for (capture.sampled_points[3]) |*column| column.* = try allocator.dupe(core.circle.CirclePointQM31, &.{point});
    capture.column_log_sizes = try allocator.alloc([]u32, 4);
    for (shape.tree_column_counts, capture.column_log_sizes) |count, *out| out.* = try allocator.alloc(u32, count);
    for (key.manifest.placements) |placement_opt| {
        const p = placement_opt.?;
        const columns = [_]struct { tree: usize, first: usize, count: usize }{
            .{ .tree = 0, .first = p.preprocessed_offset, .count = p.geometry.preprocessed_columns },
            .{ .tree = 1, .first = p.main_offset, .count = p.geometry.main_columns },
            .{ .tree = 2, .first = p.interaction_offset, .count = p.geometry.interaction_columns },
        };
        for (columns) |column| @memset(capture.column_log_sizes[column.tree][column.first..][0..column.count], p.geometry.log_size + recursion.protocol.FRI_LOG_BLOWUP_FACTOR);
    }
    @memset(capture.column_log_sizes[3], shape.tree_heights[3]);
    capture.sampled_values = try allocator.alloc(QM31, d.sampled_value_count);
    capture.queried_values = try allocator.alloc(M31, d.queried_value_count);
    capture.deep_answers = try allocator.alloc(QM31, d.query_count);
    capture.last_layer_coefficients = try allocator.alloc(QM31, d.last_layer_coefficient_count);
    capture.queries = .{ .raw = try allocator.alloc(usize, d.query_count), .unique = try allocator.alloc(usize, d.query_count) };
    capture.trace_paths = try allocator.alloc(std.meta.Child(@TypeOf(capture.trace_paths)), 4);
    for (capture.trace_paths, shape.tree_heights) |*path, height| path.* = .{ .positions = try allocator.alloc(usize, d.query_count), .path_depth = height, .siblings = try allocator.alloc(recursion.poseidon2_channel.Digest, d.query_count * height) };
    capture.fri.layers = try allocator.alloc(std.meta.Child(@TypeOf(capture.fri.layers)), d.fri_layer_count);
    for (capture.fri.layers, shape.fri.active()) |*layer, round| layer.* = .{ .commitment = @splat(0), .folding_alpha = QM31.zero(), .fold_step = round.fold_step, .fold_width = round.fold_width, .path_depth = round.authentication_path_depth, .query_count = d.query_count, .positions = try allocator.alloc(usize, d.query_count), .values = try allocator.alloc(QM31, d.query_count * round.fold_width), .siblings = try allocator.alloc(recursion.poseidon2_channel.Digest, d.query_count * round.authentication_path_depth) };
    return capture;
}
