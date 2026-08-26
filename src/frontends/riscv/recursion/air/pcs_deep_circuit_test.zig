//! Native differential and mutation gates for the exact row-24 circuit.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const CirclePointQM31 = stwo_core.circle.CirclePointQM31;
const TreeVec = stwo_core.pcs.TreeVec;
const circuit = @import("pcs_deep_circuit.zig");
const input = @import("pcs_deep_input_witness.zig");

const TREE_0_LOGS = [_]u32{ 4, 3 };
const TREE_1_LOGS = [_]u32{4};
const TREES = [_]circuit.TreeProfile{
    .{ .column_log_sizes = &TREE_0_LOGS },
    .{ .column_log_sizes = &TREE_1_LOGS },
};
const SAMPLE_LAYOUTS = [_]circuit.SamplePointLayout{
    .current_previous,
    .none,
    .current,
};
const PROFILE = circuit.Profile{
    .trees = &TREES,
    .sample_layouts = &SAMPLE_LAYOUTS,
    .lifting_log_size = 5,
    .log_blowup_factor = 1,
    .query_count = 2,
};
const LEGACY_PROFILE_DIGEST = digestFromHex(
    "5f09c85ec7740797e2484932d802136d57d26e456a1338386cfe5aebb06076bb",
);
const LEGACY_CIRCUIT_DIGEST = digestFromHex(
    "8a85e52909132ddbc857b03bda59cb37f8de331d2423af354d1dedf87c0371a4",
);

test "R-012 PCS-DEEP circuit seals exact profile and row-24 input order" {
    var built = try circuit.build(std.testing.allocator, PROFILE);
    defer built.deinit();
    try built.validate();
    try std.testing.expectEqualSlices(u8, &LEGACY_PROFILE_DIGEST, &built.profile_digest);
    try std.testing.expectEqualSlices(u8, &LEGACY_CIRCUIT_DIGEST, &built.identity_digest);

    try std.testing.expectEqual(@as(usize, 99), built.bindings.len);
    try std.testing.expectEqual(@as(usize, 67), built.outputs.len);
    try std.testing.expect(built.nodes.len > built.bindings.len);
    const lane_profile = try PROFILE.laneProfile();
    for (built.bindings, 0..) |binding, binding_index| {
        const expected = (try input.expectedSource(lane_profile, binding_index)).?;
        try std.testing.expect(std.meta.eql(expected, binding.source));
    }

    const scratch = try std.testing.allocator.alloc(u32, built.nodes.len);
    defer std.testing.allocator.free(scratch);
    const uses = try circuit.computeUseCountsInto(&built, scratch);
    try std.testing.expect(uses[built.bindings[0].node_id] > 0);
    try std.testing.expect(uses[built.bindings[1].node_id] > 0);

    built.profile_digest[0] ^= 1;
    try std.testing.expectError(error.ProfileIdentityMismatch, built.validate());
    built.profile_digest[0] ^= 1;
    try built.validate();

    const original_layout = built.sample_layouts[0];
    built.sample_layouts[0] = .previous_current;
    try std.testing.expectError(error.ProfileIdentityMismatch, built.validate());
    built.sample_layouts[0] = original_layout;
    try built.validate();
}

test "R-012 PCS-DEEP circuit is differential with native friAnswers" {
    const sampled_values = [_]QM31{ secure(101), secure(107), secure(109) };
    const queried_values = [_]M31{
        M31.fromCanonical(11),
        M31.fromCanonical(13),
        M31.fromCanonical(17),
        M31.fromCanonical(19),
        M31.fromCanonical(23),
        M31.fromCanonical(29),
    };
    const oods_seed = secure(37);
    const deep_randomness = secure(41);
    const raw_queries = [_]M31{
        M31.fromCanonical(3),
        M31.fromCanonical(17),
    };

    var native_answers = try nativeAnswers(
        .current_previous,
        sampled_values,
        queried_values,
        oods_seed,
        deep_randomness,
        raw_queries,
    );
    defer std.testing.allocator.free(native_answers);

    var built = try circuit.build(std.testing.allocator, PROFILE);
    defer built.deinit();
    var evaluation = try built.evaluate(std.testing.allocator, .{
        .active = true,
        .sampled_values = &sampled_values,
        .queried_values = &queried_values,
        .oods_seed = oods_seed,
        .deep_randomness = deep_randomness,
        .raw_queries = &raw_queries,
        .answers = native_answers,
    });
    defer evaluation.deinit();
    try evaluation.validateAgainst(&built);

    const input_values = try std.testing.allocator.alloc(M31, built.bindings.len);
    defer std.testing.allocator.free(input_values);
    try built.inputValuesInto(&evaluation, input_values);
    try std.testing.expect(input_values[0].isOne());
    try std.testing.expect(input_values[1].eql(sampled_values[0].toM31Array()[0]));

    native_answers[0] = native_answers[0].add(QM31.one());
    try std.testing.expectError(
        error.UnsatisfiedCircuit,
        built.evaluate(std.testing.allocator, .{
            .active = true,
            .sampled_values = &sampled_values,
            .queried_values = &queried_values,
            .oods_seed = oods_seed,
            .deep_randomness = deep_randomness,
            .raw_queries = &raw_queries,
            .answers = native_answers,
        }),
    );
}

test "R-012 PCS-DEEP binds both native two-point orders exactly" {
    const oods_seed = secure(131);
    const deep_randomness = secure(137);
    const raw_queries = [_]M31{
        M31.fromCanonical(7),
        M31.fromCanonical(23),
    };
    const queried_values = [_]M31{
        M31.fromCanonical(31),
        M31.fromCanonical(37),
        M31.fromCanonical(41),
        M31.fromCanonical(43),
        M31.fromCanonical(47),
        M31.fromCanonical(53),
    };

    for ([_]circuit.SamplePointLayout{
        .current_previous,
        .previous_current,
    }) |pair_layout| {
        const layouts = [_]circuit.SamplePointLayout{
            pair_layout,
            .none,
            .current,
        };
        const profile = circuit.Profile{
            .trees = &TREES,
            .sample_layouts = &layouts,
            .lifting_log_size = PROFILE.lifting_log_size,
            .log_blowup_factor = PROFILE.log_blowup_factor,
            .query_count = PROFILE.query_count,
        };
        const sampled_values = switch (pair_layout) {
            // The values retain exact point order; their distinct seeds make
            // an accidental normalization observable.
            .current_previous => [_]QM31{ secure(101), secure(103), secure(107) },
            .previous_current => [_]QM31{ secure(103), secure(101), secure(107) },
            .none, .current => unreachable,
        };
        try expectNativeBatchOracle(
            pair_layout,
            sampled_values,
            oods_seed,
            deep_randomness,
        );
        const native_answers = try nativeAnswers(
            pair_layout,
            sampled_values,
            queried_values,
            oods_seed,
            deep_randomness,
            raw_queries,
        );
        defer std.testing.allocator.free(native_answers);

        var built = try circuit.build(std.testing.allocator, profile);
        defer built.deinit();
        var evaluation = try built.evaluate(std.testing.allocator, .{
            .active = true,
            .sampled_values = &sampled_values,
            .queried_values = &queried_values,
            .oods_seed = oods_seed,
            .deep_randomness = deep_randomness,
            .raw_queries = &raw_queries,
            .answers = native_answers,
        });
        defer evaluation.deinit();
        try evaluation.validateAgainst(&built);

        if (pair_layout == .previous_current) {
            var swapped_values = sampled_values;
            std.mem.swap(QM31, &swapped_values[0], &swapped_values[1]);
            try std.testing.expectError(
                error.UnsatisfiedCircuit,
                built.evaluate(std.testing.allocator, .{
                    .active = true,
                    .sampled_values = &swapped_values,
                    .queried_values = &queried_values,
                    .oods_seed = oods_seed,
                    .deep_randomness = deep_randomness,
                    .raw_queries = &raw_queries,
                    .answers = native_answers,
                }),
            );
        }
    }

    const reverse_layouts = [_]circuit.SamplePointLayout{
        .previous_current,
        .none,
        .current,
    };
    const reverse_profile = circuit.Profile{
        .trees = &TREES,
        .sample_layouts = &reverse_layouts,
        .lifting_log_size = PROFILE.lifting_log_size,
        .log_blowup_factor = PROFILE.log_blowup_factor,
        .query_count = PROFILE.query_count,
    };
    try std.testing.expect(!std.mem.eql(
        u8,
        &PROFILE.identityDigest(),
        &reverse_profile.identityDigest(),
    ));
}

test "R-012 PCS-DEEP rejects incomplete layout geometry and witness cursors" {
    try std.testing.expectEqual(@as(usize, 3), try PROFILE.sampleCount());
    try std.testing.expectEqual(@as(usize, 4), try PROFILE.termCount());

    const missing_layouts = circuit.Profile{
        .trees = &TREES,
        .sample_layouts = SAMPLE_LAYOUTS[0..2],
        .lifting_log_size = PROFILE.lifting_log_size,
        .log_blowup_factor = PROFILE.log_blowup_factor,
        .query_count = PROFILE.query_count,
    };
    try std.testing.expectError(error.ColumnCountMismatch, missing_layouts.validate());

    const no_samples = [_]circuit.SamplePointLayout{.none} ** SAMPLE_LAYOUTS.len;
    const empty_profile = circuit.Profile{
        .trees = &TREES,
        .sample_layouts = &no_samples,
        .lifting_log_size = PROFILE.lifting_log_size,
        .log_blowup_factor = PROFILE.log_blowup_factor,
        .query_count = PROFILE.query_count,
    };
    try std.testing.expectError(error.InvalidProfile, empty_profile.validate());

    const oversized_query_profile = circuit.Profile{
        .trees = &TREES,
        .sample_layouts = &SAMPLE_LAYOUTS,
        .lifting_log_size = PROFILE.lifting_log_size,
        .log_blowup_factor = PROFILE.log_blowup_factor,
        .query_count = stwo_core.fields.m31.Modulus,
    };
    try std.testing.expectError(
        error.InvalidProfile,
        oversized_query_profile.validate(),
    );

    var fail_first_allocation = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        circuit.build(fail_first_allocation.allocator(), PROFILE),
    );

    var built = try circuit.build(std.testing.allocator, PROFILE);
    defer built.deinit();
    const short_samples = [_]QM31{ secure(1), secure(2) };
    const queried_values = [_]M31{M31.zero()} ** 6;
    const raw_queries = [_]M31{M31.zero()} ** 2;
    const answers = [_]QM31{QM31.zero()} ** 2;
    try std.testing.expectError(
        error.InvalidWitness,
        built.evaluate(std.testing.allocator, .{
            .active = true,
            .sampled_values = &short_samples,
            .queried_values = &queried_values,
            .oods_seed = secure(3),
            .deep_randomness = secure(5),
            .raw_queries = &raw_queries,
            .answers = &answers,
        }),
    );
}

test "R-012 PCS-DEEP inactive lane has defined inverses and zero public inputs" {
    const sampled_values = [_]QM31{QM31.zero()} ** 3;
    const queried_values = [_]M31{M31.zero()} ** 6;
    const raw_queries = [_]M31{M31.zero()} ** 2;
    const answers = [_]QM31{QM31.zero()} ** 2;
    var built = try circuit.build(std.testing.allocator, PROFILE);
    defer built.deinit();
    var evaluation = try built.evaluate(std.testing.allocator, .{
        .active = false,
        .sampled_values = &sampled_values,
        .queried_values = &queried_values,
        .oods_seed = QM31.zero(),
        .deep_randomness = QM31.zero(),
        .raw_queries = &raw_queries,
        .answers = &answers,
    });
    defer evaluation.deinit();
    try evaluation.validateAgainst(&built);
    for (built.bindings) |binding|
        try std.testing.expect(evaluation.values[binding.node_id].isZero());

    const operation_node = for (built.nodes, 0..) |node, node_id| switch (node.op) {
        .add, .sub, .mul, .neg, .inverse => break node_id,
        else => continue,
    } else unreachable;
    evaluation.values[operation_node] = evaluation.values[operation_node].add(QM31.one());
    try std.testing.expectError(error.InvalidWitness, built.validateEvaluationHot(&evaluation));
}

fn nativeAnswers(
    pair_layout: circuit.SamplePointLayout,
    sampled_values: [3]QM31,
    queried_values: [6]M31,
    oods_seed: QM31,
    deep_randomness: QM31,
    raw_queries: [2]M31,
) ![]QM31 {
    const oods = stwo_core.circle.secureFieldPointFromRandomSeed(oods_seed);
    const previous_step = stwo_core.poly.circle.CanonicCoset.new(4).step();
    const previous = oods.sub(.{
        .x = QM31.fromBase(previous_step.x),
        .y = QM31.fromBase(previous_step.y),
    });

    var log_tree_0 = TREE_0_LOGS;
    var log_tree_1 = TREE_1_LOGS;
    var log_trees = [_][]u32{ &log_tree_0, &log_tree_1 };

    var points_0_0 = switch (pair_layout) {
        .current_previous => [_]CirclePointQM31{ oods, previous },
        .previous_current => [_]CirclePointQM31{ previous, oods },
        .none, .current => unreachable,
    };
    var points_0_1 = [_]CirclePointQM31{};
    var points_1_0 = [_]CirclePointQM31{oods};
    var point_tree_0 = [_][]CirclePointQM31{ &points_0_0, &points_0_1 };
    var point_tree_1 = [_][]CirclePointQM31{&points_1_0};
    var point_trees = [_][][]CirclePointQM31{ &point_tree_0, &point_tree_1 };

    var sampled_0_0 = [_]QM31{ sampled_values[0], sampled_values[1] };
    var sampled_0_1 = [_]QM31{};
    var sampled_1_0 = [_]QM31{sampled_values[2]};
    var sampled_tree_0 = [_][]QM31{ &sampled_0_0, &sampled_0_1 };
    var sampled_tree_1 = [_][]QM31{&sampled_1_0};
    var sampled_trees = [_][][]QM31{ &sampled_tree_0, &sampled_tree_1 };

    var queried_0_0 = queried_values[0..2].*;
    var queried_0_1 = queried_values[2..4].*;
    var queried_1_0 = queried_values[4..6].*;
    var queried_tree_0 = [_][]M31{ &queried_0_0, &queried_0_1 };
    var queried_tree_1 = [_][]M31{&queried_1_0};
    var queried_trees = [_][][]M31{ &queried_tree_0, &queried_tree_1 };
    const positions = [_]usize{
        raw_queries[0].toU32(),
        raw_queries[1].toU32(),
    };

    return stwo_core.pcs.quotients.friAnswers(
        std.testing.allocator,
        TreeVec([]u32).initOwned(&log_trees),
        TreeVec([][]CirclePointQM31).initOwned(&point_trees),
        TreeVec([][]QM31).initOwned(&sampled_trees),
        deep_randomness,
        &positions,
        TreeVec([][]M31).initOwned(&queried_trees),
        PROFILE.lifting_log_size,
    );
}

/// Uses the native PCS sample expander and stable point grouper as the oracle
/// for periodicity placement, source order, and random-power assignment.
fn expectNativeBatchOracle(
    pair_layout: circuit.SamplePointLayout,
    sampled_values: [3]QM31,
    oods_seed: QM31,
    deep_randomness: QM31,
) !void {
    const oods = stwo_core.circle.secureFieldPointFromRandomSeed(oods_seed);
    const previous_step = stwo_core.poly.circle.CanonicCoset.new(4).step();
    const previous = oods.sub(.{
        .x = QM31.fromBase(previous_step.x),
        .y = QM31.fromBase(previous_step.y),
    });
    var points_0_0 = switch (pair_layout) {
        .current_previous => [_]CirclePointQM31{ oods, previous },
        .previous_current => [_]CirclePointQM31{ previous, oods },
        .none, .current => unreachable,
    };
    var points_0_1 = [_]CirclePointQM31{};
    var points_1_0 = [_]CirclePointQM31{oods};
    var point_tree_0 = [_][]CirclePointQM31{ &points_0_0, &points_0_1 };
    var point_tree_1 = [_][]CirclePointQM31{&points_1_0};
    var point_trees = [_][][]CirclePointQM31{ &point_tree_0, &point_tree_1 };

    var sampled_0_0 = [_]QM31{ sampled_values[0], sampled_values[1] };
    var sampled_0_1 = [_]QM31{};
    var sampled_1_0 = [_]QM31{sampled_values[2]};
    var sampled_tree_0 = [_][]QM31{ &sampled_0_0, &sampled_0_1 };
    var sampled_tree_1 = [_][]QM31{&sampled_1_0};
    var sampled_trees = [_][][]QM31{ &sampled_tree_0, &sampled_tree_1 };

    var log_tree_0 = TREE_0_LOGS;
    var log_tree_1 = TREE_1_LOGS;
    var log_trees = [_][]u32{ &log_tree_0, &log_tree_1 };
    var expanded = try stwo_core.pcs.quotients.buildSamplesWithRandomnessAndPeriodicity(
        std.testing.allocator,
        TreeVec([][]CirclePointQM31).initOwned(&point_trees),
        TreeVec([][]QM31).initOwned(&sampled_trees),
        TreeVec([]u32).initOwned(&log_trees),
        PROFILE.lifting_log_size,
        deep_randomness,
    );
    defer expanded.deinitDeep(std.testing.allocator);

    const periodic_step = stwo_core.poly.circle.CanonicCoset.new(
        PROFILE.lifting_log_size,
    ).step().repeatedDouble(TREE_0_LOGS[0]);
    const periodic_point = points_0_0[1].add(.{
        .x = QM31.fromBase(periodic_step.x),
        .y = QM31.fromBase(periodic_step.y),
    });
    const first_column = expanded.items[0][0];
    try std.testing.expectEqual(@as(usize, 3), first_column.len);
    try std.testing.expect(first_column[0].point.eql(periodic_point));
    try std.testing.expect(first_column[1].point.eql(points_0_0[0]));
    try std.testing.expect(first_column[2].point.eql(points_0_0[1]));
    try std.testing.expect(first_column[0].value.eql(sampled_values[1]));
    try std.testing.expect(first_column[1].value.eql(sampled_values[0]));
    try std.testing.expect(first_column[2].value.eql(sampled_values[1]));
    try std.testing.expect(first_column[0].random_coeff.eql(QM31.one()));
    try std.testing.expect(first_column[1].random_coeff.eql(deep_randomness));
    try std.testing.expect(first_column[2].random_coeff.eql(deep_randomness.square()));

    const batches = try stwo_core.pcs.quotients.buildColumnSampleBatchesFromParallelInputs(
        std.testing.allocator,
        TreeVec([][]CirclePointQM31).initOwned(&point_trees),
        TreeVec([][]QM31).initOwned(&sampled_trees),
        TreeVec([]u32).initOwned(&log_trees),
        PROFILE.lifting_log_size,
        deep_randomness,
    );
    defer stwo_core.pcs.quotients.ColumnSampleBatch.deinitSlice(
        std.testing.allocator,
        batches,
    );
    try std.testing.expectEqual(@as(usize, 3), batches.len);
    try std.testing.expect(batches[0].point.eql(periodic_point));
    try std.testing.expect(batches[1].point.eql(points_0_0[0]));
    try std.testing.expect(batches[2].point.eql(points_0_0[1]));
    const current_batch_index: usize = switch (pair_layout) {
        .current_previous => 1,
        .previous_current => 2,
        .none, .current => unreachable,
    };
    const other_batch_index: usize = if (current_batch_index == 1) 2 else 1;
    try std.testing.expectEqual(@as(usize, 1), batches[0].cols_vals_randpows.len);
    try std.testing.expectEqual(
        @as(usize, 2),
        batches[current_batch_index].cols_vals_randpows.len,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        batches[other_batch_index].cols_vals_randpows.len,
    );
    try std.testing.expectEqual(@as(usize, 0), batches[0].cols_vals_randpows[0].column_index);
    try std.testing.expectEqual(@as(usize, 0), batches[1].cols_vals_randpows[0].column_index);
    try std.testing.expectEqual(@as(usize, 0), batches[2].cols_vals_randpows[0].column_index);
    try std.testing.expectEqual(
        @as(usize, 2),
        batches[current_batch_index].cols_vals_randpows[1].column_index,
    );
    try std.testing.expect(batches[current_batch_index].cols_vals_randpows[1].random_coeff.eql(
        deep_randomness.square().mul(deep_randomness),
    ));
}

fn digestFromHex(comptime value: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch
        @compileError("invalid PCS-DEEP digest fixture");
    return result;
}

fn secure(seed: u32) QM31 {
    return QM31.fromU32Unchecked(seed, seed + 1, seed + 2, seed + 3);
}
