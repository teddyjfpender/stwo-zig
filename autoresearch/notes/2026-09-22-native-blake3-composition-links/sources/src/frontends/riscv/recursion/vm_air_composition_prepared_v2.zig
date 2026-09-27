//! Base VM row-18 preparation from the selected physical lookup profile.
//! The graph depends only on authenticated statement geometry and typed AIR;
//! every dynamic input comes from the successful native verifier capture.

const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const graph = @import("air/composition_circuit.zig");
const circuit = @import("vm_air_composition_circuit.zig");
const geometry_mod = @import("vm_composition_base_geometry_v2.zig");
const lookup = @import("../air/lang/lookup_physical_manifest_v2.zig");
const selected_lookup = @import("vm_selected_lookup_compiler_v2.zig");
const relations_mod = @import("../air/relation_challenges.zig");
const transcript = @import("../air/transcript/claims.zig");
const logup = @import("../air/logup.zig");
const base_graph = @import("ethereum_vm_composition_graph_base_v2.zig");
const support = @import("ethereum_vm_composition_graph_support_v2.zig");
const program = @import("ethereum_vm_composition_program_v2.zig");
const Scalar = support.Scalar;

pub fn prepare(
    allocator: std.mem.Allocator,
    capture: anytype,
    pcs: core.pcs.PcsConfig,
) !circuit.Prepared {
    try capture.validate();
    const context = &capture.vm_air;
    const profile = &context.profile;
    const native = try context.reconstructStatement(&capture.public_data.data);
    const manifest = lookup.Manifest.native();
    const authenticated = try lookup.AuthenticatedStatement.init(&native.core, &manifest);
    try profile.validateAuthority(allocator, &native.core, &manifest, &authenticated);
    var geometry = try geometry_mod.GeometryV2.init(allocator, profile);
    defer geometry.deinit();
    try validateCaptureGeometry(&geometry, &capture.proof, pcs.fri_config.log_blowup_factor);
    const selected = try selected_lookup.CompilerV2.init(allocator, &native.core, &manifest, &authenticated, profile);
    const input_profile = graph.InputProfile{
        .sampled_value_count = geometry.sampled_value_count,
        .claimed_sum_count = profile.input_profile.claimed_sum_count,
        .relation_challenge_count = relations_mod.RELATION_COUNT,
        .transcript_claimed_sum_count = transcript.COMPONENT_COUNT,
    };
    var builder = support.Builder.init(allocator);
    defer builder.deinit();
    try builder.reserve(try graph.vmInputCount(input_profile), profile.air_instruction_count + transcript.COMPONENT_COUNT + 1);
    circuit.installBuilder(&builder);
    defer circuit.uninstallBuilder();

    const selector = try builder.input(.segment_selector);
    const sampled = try allocator.alloc(Scalar, input_profile.sampled_value_count);
    defer allocator.free(sampled);
    for (sampled, 0..) |*value, index|
        value.* = try support.secureInput(&builder, .sampled_value, @intCast(index));
    const claims = try allocator.alloc(Scalar, input_profile.claimed_sum_count);
    defer allocator.free(claims);
    for (claims, 0..) |*value, index|
        value.* = try support.secureInput(&builder, .claimed_sum, @intCast(index));
    var aggregates: [transcript.COMPONENT_COUNT]Scalar = undefined;
    for (&aggregates, 0..) |*value, index|
        value.* = try support.secureInput(&builder, .transcript_claimed_sum, @intCast(index));
    var draws: [relations_mod.RELATION_COUNT][2]Scalar = undefined;
    for (&draws, 0..) |*pair, index| {
        pair[0] = try support.challengeInput(&builder, @intCast(index), 0);
        pair[1] = try support.challengeInput(&builder, @intCast(index), 4);
    }
    const randomness = try support.scalarInput(&builder, .composition_randomness);
    const seed = try support.scalarInput(&builder, .oods_point);
    try program.bindTranscriptAggregates(&builder, selector, profile, null, claims, &aggregates);
    const relations = circuit.GraphRelations.init(draws);
    var layout = try support.SampleLayoutV2.init(allocator, &geometry, null, sampled);
    defer layout.deinit();
    const point = support.pointFromSeed(seed);
    var denominators: [31]?Scalar = .{null} ** 31;
    const recorded = try base_graph.record(.legacy_role_filtered_v1, profile, &manifest, &selected, &layout, claims, &relations, point, randomness, profile.max_log_degree_bound, &denominators);
    const composition = try support.reconstructComposition(&layout, point, profile.composition_log_degree_bound, profile.composition_log_split);
    try builder.constrainZero(selector.mul(composition.sub(recorded.accumulation)));
    try builder.check();

    const lane = graph.VmLane{
        .circuit_id = circuit.CIRCUIT_ID,
        .graph = .{
            .nodes = builder.nodes.items,
            .outputs = builder.outputs.items,
            .identity_digest = graph.computeGraphDigest(builder.nodes.items, builder.outputs.items),
        },
        .profile = input_profile,
        .bindings = builder.bindings.items,
    };
    const inputs = try allocator.alloc(M31, lane.bindings.len);
    defer allocator.free(inputs);
    for (lane.bindings, inputs) |binding, *value|
        value.* = try inputWord(binding.source, capture);
    // This constructor copies the graph and replays every non-input node.
    // Admission requires all designated outputs to be zero.
    return circuit.Prepared.initFromAuthenticatedLaneV2(allocator, lane, profile.identity_digest, inputs);
}

fn validateCaptureGeometry(geometry: *const geometry_mod.GeometryV2, capture: anytype, blowup: u32) !void {
    if (capture.sampled_points.len != geometry_mod.TREE_COUNT or
        capture.column_log_sizes.len != geometry_mod.TREE_COUNT or
        capture.sampled_values.len != geometry.sampled_value_count)
        return error.InvalidBaseCaptureGeometry;
    const point = core.circle.secureFieldPointFromRandomSeed(capture.oods_seed);
    const previous = logup.prevRowPoint(geometry.composition_log_size, point);
    for (geometry.columns, capture.sampled_points, capture.column_log_sizes) |columns, samples, logs| {
        if (columns.len != samples.len or columns.len != logs.len)
            return error.InvalidBaseCaptureGeometry;
        for (columns, samples, logs) |column, points, log_size| {
            if (points.len != column.sample_count or
                log_size != try std.math.add(u32, column.log_size, blowup))
                return error.InvalidBaseCaptureGeometry;
            for (points, column.samples[0..column.sample_count]) |actual, offset| {
                const expected = if (offset == .current) point else previous;
                if (!actual.x.eql(expected.x) or !actual.y.eql(expected.y))
                    return error.InvalidBaseCaptureGeometry;
            }
        }
    }
}

fn inputWord(source: graph.VmSource, capture: anytype) !M31 {
    const context = &capture.vm_air;
    return switch (source) {
        .statement_word, .native_continuation_root => return error.InvalidInputBinding,
        .segment_selector => M31.one(),
        .sampled_value => |coordinate| word(capture.proof.sampled_values, coordinate),
        .claimed_sum => |coordinate| word(context.detailed_claims, coordinate),
        .transcript_claimed_sum => |coordinate| word(&context.canonical_claims, coordinate),
        .relation_challenge => |coordinate| blk: {
            if (coordinate.challenge >= relations_mod.RELATION_COUNT or coordinate.word_index >= 8)
                return error.InvalidInputBinding;
            break :blk context.relation_draws[2 * coordinate.challenge + coordinate.word_index / 4].toM31Array()[coordinate.word_index % 4];
        },
        .composition_randomness => |index| word(&.{capture.proof.composition_randomness}, .{ .item_index = 0, .word_index = index }),
        .oods_point => |index| word(&.{capture.proof.oods_seed}, .{ .item_index = 0, .word_index = index }),
    };
}

fn word(values: []const QM31, coordinate: graph.SecureCoordinate) !M31 {
    if (coordinate.item_index >= values.len or coordinate.word_index >= 4)
        return error.InvalidInputBinding;
    return values[coordinate.item_index].toM31Array()[coordinate.word_index];
}

test "base ContextV2 composition capture rejects extra samples wrong logs and masks" {
    const Point = core.circle.CirclePointQM31;
    const seed = QM31.fromU32Unchecked(2, 3, 4, 5);
    const point = core.circle.secureFieldPointFromRandomSeed(seed);
    const previous = logup.prevRowPoint(4, point);
    var columns: [4][1]geometry_mod.ColumnV2 = undefined;
    var points: [4][2]Point = undefined;
    var point_columns: [4][1][]Point = undefined;
    var point_trees: [4][][]Point = undefined;
    var logs = [_][1]u32{.{5}} ** 4;
    var log_trees: [4][]u32 = undefined;
    var geometry = geometry_mod.GeometryV2{
        .allocator = std.testing.allocator,
        .profile_identity = .{1} ** 32,
        .columns = undefined,
        .tree_value_offsets = .{ 0, 1, 2, 4, 5 },
        .sampled_value_count = 5,
        .composition_log_size = 4,
        .composition_log_split = 1,
        .identity_sha256 = .{1} ** 32,
    };
    for (0..4) |tree| {
        const count: u8 = if (tree == 2) 2 else 1;
        columns[tree][0] = .{ .log_size = 4, .sample_count = count, .samples = .{ .current, .previous } };
        geometry.columns[tree] = &columns[tree];
        points[tree] = .{ point, previous };
        point_columns[tree][0] = points[tree][0..count];
        point_trees[tree] = &point_columns[tree];
        log_trees[tree] = &logs[tree];
    }
    var values = [_]QM31{QM31.zero()} ** 6;
    var capture = .{
        .sampled_points = &point_trees,
        .column_log_sizes = &log_trees,
        .sampled_values = @as([]QM31, values[0..5]),
        .oods_seed = seed,
    };
    try validateCaptureGeometry(&geometry, &capture, 1);
    capture.sampled_values = &values;
    try std.testing.expectError(error.InvalidBaseCaptureGeometry, validateCaptureGeometry(&geometry, &capture, 1));
    capture.sampled_values = values[0..5];
    logs[2][0] += 1;
    try std.testing.expectError(error.InvalidBaseCaptureGeometry, validateCaptureGeometry(&geometry, &capture, 1));
    logs[2][0] -= 1;
    points[2][1] = point;
    try std.testing.expectError(error.InvalidBaseCaptureGeometry, validateCaptureGeometry(&geometry, &capture, 1));
    points[2][1] = previous;
    try validateCaptureGeometry(&geometry, &capture, 1);
}
