const std = @import("std");
const metal = @import("stwo_metal_backend").runtime;
const m31 = @import("stwo_core").fields.m31;
const blake2_merkle = @import("stwo_core").vcs_lifted.blake2_merkle;
const blake2_hash = @import("stwo_core").vcs.blake2_hash;
const merkle_prover = @import("stwo_prover_impl").vcs_lifted.prover;
const pcs_core = @import("stwo_core").pcs;
const MetalProverEngine = @import("stwo_metal_backend").prover_engine.MetalProverEngine;
const canonic = @import("stwo_core").poly.circle.canonic;
const circle_poly = @import("stwo_prover_impl").poly.circle.poly;
const twiddles = @import("stwo_prover_impl").poly.twiddles;
const core_fri = @import("stwo_core").fri;
const qm31 = @import("stwo_core").fields.qm31;
const line = @import("stwo_core").poly.line;
const prover_line = @import("stwo_prover_impl").line;
const MetalBackend = @import("stwo_metal_backend").commit_backend.MetalCommitBackend;
const metal_commit_policy = @import("stwo_metal_backend").commit_policy;
const eval_program = @import("stwo_cairo_frontend").witness.eval_program;
const eval_codegen = @import("../../../integrations/cairo_metal/eval_codegen.zig");
const circle_core = @import("stwo_core").circle;
const core_utils = @import("stwo_core").utils;
const blake2s_channel = @import("stwo_core").channel.blake2s;
const protocol_recipes = @import("stwo_metal_backend").protocol_recipes;
const arena_plan = @import("stwo_metal_backend").arena_plan;
const secure_column = @import("stwo_prover_impl").secure_column;
const secure_circle_poly = @import("stwo_prover_impl").poly.circle.secure_poly;
const cairo_arena_binding = @import("../../../integrations/cairo_metal/arena_binding.zig");
const cairo_oods = @import("../../../integrations/cairo_metal/oods.zig");
const cairo_quotient_inputs = @import("../../../integrations/cairo_metal/quotient_inputs.zig");
const cairo_quotient_reference = @import("../../../integrations/cairo_metal/quotient_reference.zig");

const M31 = m31.M31;
const Hasher = blake2_merkle.Blake2sMerkleHasher;
const PlainHasher = blake2_merkle.Blake2sPlainMerkleHasher;
const QM31 = qm31.QM31;

fn testResidentBinding(logical_id: u32, offset_words: u32, word_count: u32) arena_plan.Binding {
    return .{
        .logical_id = logical_id,
        .slot = logical_id,
        .offset_bytes = @as(u64, offset_words) * @sizeOf(u32),
        .size_bytes = @as(u64, word_count) * @sizeOf(u32),
        .materialization = .resident,
        .occupied = [_]u64{0} ** (arena_plan.max_ticks / 64),
    };
}

test "metal: prepared resident quotient combine matches canonical scalar formula" {
    const allocator = std.testing.allocator;
    const log_size: u32 = 6;
    const row_count: u32 = @as(u32, 1) << @intCast(log_size);
    var split = try canonic.CanonicCoset.new(log_size + 2).circleDomain().split(allocator, 2);
    defer split.deinit(allocator);
    const domain = split.subdomain;
    const sample_points = [_]circle_core.CirclePointQM31{
        circle_core.SECURE_FIELD_CIRCLE_GEN,
        circle_core.SECURE_FIELD_CIRCLE_GEN.double(),
    };
    const first_terms = [_]QM31{
        QM31.fromU32Unchecked(3, 5, 7, 11),
        QM31.fromU32Unchecked(13, 17, 19, 23),
    };
    const partial_logs = [_]u32{ 5, 6 };

    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(64 * 1024);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    const partial_offsets = [_]u32{ 0, 32, 96, 128, 192, 224, 288, 320 };
    for (0..partial_logs.len) |sample| {
        const length = @as(u32, 1) << @intCast(partial_logs[sample]);
        for (0..4) |coordinate| {
            const offset = partial_offsets[coordinate * partial_logs.len + sample];
            for (0..length) |row| {
                words[offset + row] = @intCast((sample * 100003 + coordinate * 65537 + row * 8191 + 29) % m31.Modulus);
            }
        }
    }
    const sample_offset: u32 = 512;
    for (sample_points, 0..) |point, sample| {
        const x = point.x.toM31Array();
        const y = point.y.toM31Array();
        const base = sample_offset + @as(u32, @intCast(sample)) * 8;
        for (0..4) |coordinate| words[base + coordinate] = x[coordinate].v;
        for (0..4) |coordinate| words[base + 4 + coordinate] = y[coordinate].v;
    }
    const linear_offset: u32 = 544;
    for (first_terms, 0..) |term, sample| {
        for (term.toM31Array(), 0..) |coordinate, index| {
            words[linear_offset + sample * 4 + index] = coordinate.v;
        }
    }
    const scratch_offset: u32 = 576;
    const output_offset: u32 = 1024;
    var prepared = try runtime.prepareQuotientCombine(
        &partial_offsets,
        &partial_logs,
        sample_offset,
        linear_offset,
        scratch_offset,
        output_offset,
        log_size,
        @intCast(domain.half_coset.initial_index.v),
        @intCast(domain.half_coset.step_size.v),
    );
    defer prepared.deinit();
    try std.testing.expect(try runtime.quotientCombinePrepared(arena, prepared) > 0);

    for (0..row_count) |row| {
        const point = domain.at(core_utils.bitReverseIndex(row, log_size));
        var expected = QM31.zero();
        for (sample_points, first_terms, partial_logs, 0..) |sample_point, first, partial_log, sample| {
            const denominator = sample_point.x.c0.subM31(point.x).mul(sample_point.y.c1).sub(
                sample_point.y.c0.subM31(point.y).mul(sample_point.x.c1),
            );
            const inverse = try denominator.inv();
            const log_ratio = log_size - partial_log;
            const lifted = (row >> @intCast(log_ratio + 1) << @intCast(1)) + (row & 1);
            var coordinates: [4]M31 = undefined;
            for (&coordinates, 0..) |*coordinate, index| {
                coordinate.* = M31.fromCanonical(words[partial_offsets[index * partial_logs.len + sample] + lifted]);
            }
            const numerator = QM31.fromM31Array(coordinates).sub(first.mulM31(point.y));
            expected = expected.add(numerator.mulCM31(inverse));
        }
        const actual = QM31.fromU32Unchecked(
            words[output_offset + row],
            words[output_offset + row_count + row],
            words[output_offset + 2 * row_count + row],
            words[output_offset + 3 * row_count + row],
        );
        try std.testing.expect(expected.eql(actual));
    }
}

test "metal: quotient recipe executes combine, interpolation, and LDE" {
    const allocator = std.testing.allocator;
    const subdomain_log: u32 = 6;
    const quotient_log: u32 = 8;
    const subdomain_rows: u32 = @as(u32, 1) << @intCast(subdomain_log);
    const quotient_rows: u32 = @as(u32, 1) << @intCast(quotient_log);
    var split = try canonic.CanonicCoset.new(quotient_log).circleDomain().split(
        allocator,
        quotient_log - subdomain_log,
    );
    defer split.deinit(allocator);
    const subdomain = split.subdomain;
    const quotient_domain = canonic.CanonicCoset.new(quotient_log).circleDomain();
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    var resident = arena_plan.ResidentArena{ .buffer = try runtime.allocateResidentBuffer(64 * 1024) };
    defer resident.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(resident.buffer.contents));

    const partials = [_]arena_plan.Binding{
        testResidentBinding(10, 0, subdomain_rows),
        testResidentBinding(11, 64, subdomain_rows),
        testResidentBinding(12, 128, subdomain_rows),
        testResidentBinding(13, 192, subdomain_rows),
    };
    const sample_points = testResidentBinding(14, 256, 8);
    const first_linear_terms = testResidentBinding(15, 264, 4);
    const denominator_scratch = testResidentBinding(16, 268, subdomain_rows * 2);
    const subdomain_values = testResidentBinding(17, 396, subdomain_rows * 4);
    const quotient_values = testResidentBinding(18, 652, quotient_rows * 4);
    const inverse_twiddles = testResidentBinding(19, 1676, subdomain_rows / 2);
    const forward_twiddles = testResidentBinding(20, 1708, @as(u32, 1) << @intCast(quotient_log + 1));

    for (partials, 0..) |partial, coordinate| {
        const base: usize = @intCast(partial.offset_bytes / 4);
        for (0..subdomain_rows) |row|
            words[base + row] = @intCast(1 + coordinate * 257 + row * 17);
    }
    const sample_point = circle_core.SECURE_FIELD_CIRCLE_GEN;
    for (sample_point.x.toM31Array(), 0..) |coordinate, index| words[256 + index] = coordinate.v;
    for (sample_point.y.toM31Array(), 0..) |coordinate, index| words[260 + index] = coordinate.v;
    @memset(words[264..268], 0);

    var subdomain_twiddles = try twiddles.precomputeM31(allocator, subdomain.half_coset);
    defer twiddles.deinitM31(allocator, &subdomain_twiddles);
    @memcpy(words[1676 .. 1676 + subdomain_twiddles.itwiddles.len], std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(subdomain_twiddles.itwiddles)));
    var quotient_twiddles = try twiddles.precomputeM31(allocator, circle_core.Coset.halfOdds(quotient_log + 1));
    defer twiddles.deinitM31(allocator, &quotient_twiddles);
    @memcpy(words[1708 .. 1708 + quotient_twiddles.twiddles.len], std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(quotient_twiddles.twiddles)));

    var expected_subdomain = try secure_column.SecureColumnByCoords.uninitialized(allocator, subdomain_rows);
    defer expected_subdomain.deinit(allocator);
    for (0..subdomain_rows) |row| {
        const point = subdomain.at(core_utils.bitReverseIndex(row, subdomain_log));
        const denominator = sample_point.x.c0.subM31(point.x).mul(sample_point.y.c1).sub(
            sample_point.y.c0.subM31(point.y).mul(sample_point.x.c1),
        );
        const inverse = try denominator.inv();
        const partial = QM31.fromU32Unchecked(
            words[partials[0].offset_bytes / 4 + row],
            words[partials[1].offset_bytes / 4 + row],
            words[partials[2].offset_bytes / 4 + row],
            words[partials[3].offset_bytes / 4 + row],
        );
        expected_subdomain.set(row, partial.mulCM31(inverse));
    }
    var expected_poly = try secure_circle_poly.interpolateFromEvaluation(
        allocator,
        subdomain,
        &expected_subdomain,
    );
    defer expected_poly.deinit(allocator);

    var recipe = try protocol_recipes.QuotientRecipe.init(
        allocator,
        &runtime,
        &resident,
        &partials,
        sample_points,
        first_linear_terms,
        denominator_scratch,
        subdomain_values,
        quotient_values,
        inverse_twiddles,
        forward_twiddles,
    );
    defer recipe.deinit();

    try recipe.execute();

    try std.testing.expect(recipe.accumulated_gpu_ms > 0);
    for (expected_poly.polys, 0..) |coordinate_poly, coordinate| {
        const expected = try coordinate_poly.evaluate(allocator, quotient_domain);
        defer allocator.free(@constCast(expected.values));
        const actual_offset = quotient_values.offset_bytes / 4 + coordinate * quotient_rows;
        for (expected.values, 0..) |expected_value, row| {
            try std.testing.expectEqual(expected_value.v, words[actual_offset + row]);
        }
    }
}

test "metal: fused resident FRI round matches scalar three-fold path" {
    const allocator = std.testing.allocator;
    const log_size: u32 = 6;
    const domain = canonic.CanonicCoset.new(log_size).circleDomain();
    var tree = try twiddles.precomputeM31(allocator, domain.half_coset);
    defer twiddles.deinitM31(allocator, &tree);
    var source = try MetalBackend.allocateSecureColumn(domain.size());
    defer source.deinit(allocator);
    for (source.columns, 0..) |column, coordinate| {
        for (column, 0..) |*value, row| {
            value.* = M31.fromCanonical(@intCast((coordinate * 65537 + row * 8191 + 43) % m31.Modulus));
        }
    }
    const alpha = QM31.fromU32Unchecked(7, 11, 13, 17);
    const first_domain = try line.LineDomain.init(circle_core.Coset.halfOdds(log_size - 1));
    const first_values = try allocator.alloc(QM31, first_domain.size());
    defer allocator.free(first_values);
    @memset(first_values, QM31.zero());
    var circle_workspace = try core_fri.FoldCircleWorkspace.init(allocator, first_values.len);
    defer circle_workspace.deinit(allocator);
    try core_fri.foldCircleColumnsIntoLineWithWorkspace(
        allocator,
        first_values,
        source.columns,
        domain,
        alpha,
        &circle_workspace,
    );
    var line_workspace = try core_fri.FoldLineWorkspace.init(allocator, first_values.len / 2);
    defer line_workspace.deinit(allocator);
    const second = try core_fri.foldLineSingleStep(
        allocator,
        first_values,
        first_domain,
        alpha.square(),
        &line_workspace,
    );
    defer allocator.free(second.values);
    const expected = try core_fri.foldLineSingleStep(
        allocator,
        second.values,
        second.domain,
        alpha.square().square(),
        &line_workspace,
    );
    defer allocator.free(expected.values);

    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(64 * 1024);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    const input_base: u32 = 0;
    const input_stride: u32 = @intCast(domain.size());
    for (source.columns, 0..) |column, coordinate| {
        const offset = input_base + @as(u32, @intCast(coordinate)) * input_stride;
        @memcpy(words[offset .. offset + column.len], std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(column)));
    }
    const twiddle_base: u32 = 512;
    @memcpy(words[twiddle_base .. twiddle_base + tree.itwiddles.len], std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(tree.itwiddles)));
    const alpha_base: u32 = 576;
    for (alpha.toM31Array(), 0..) |coordinate, index| words[alpha_base + index] = coordinate.v;
    const output_base: u32 = 640;
    const output_stride: u32 = 8;
    var prepared = try runtime.prepareFriRound(
        twiddle_base,
        @intCast(tree.itwiddles.len),
        input_base,
        input_stride,
        alpha_base,
        output_base,
        output_stride,
        @intCast(domain.size()),
        3,
        true,
    );
    defer prepared.deinit();
    try std.testing.expect(try runtime.friRoundPrepared(arena, prepared) > 0);
    for (expected.values, 0..) |value, row| {
        const coordinates = value.toM31Array();
        for (coordinates, 0..) |coordinate, index| {
            try std.testing.expectEqual(coordinate.v, words[output_base + index * output_stride + row]);
        }
    }
}

fn expectResidentFriLineRoundMatchesScalar(source_log_size: u32, fold_count: u32) !void {
    const allocator = std.testing.allocator;
    const twiddle_log_size: u32 = 8;
    const domain = try line.LineDomain.init(circle_core.Coset.halfOdds(source_log_size));
    var tree = try twiddles.precomputeM31(
        allocator,
        circle_core.Coset.halfOdds(twiddle_log_size),
    );
    defer twiddles.deinitM31(allocator, &tree);

    const source = try allocator.alloc(QM31, domain.size());
    defer allocator.free(source);
    for (source, 0..) |*value, row| {
        value.* = QM31.fromU32Unchecked(
            @intCast(3 + row * 17),
            @intCast(5 + row * 29),
            @intCast(7 + row * 43),
            @intCast(11 + row * 61),
        );
    }
    const alpha = QM31.fromU32Unchecked(19, 23, 31, 37);
    var workspace = try core_fri.FoldLineWorkspace.init(allocator, source.len / 2);
    defer workspace.deinit(allocator);
    const expected = try core_fri.foldLineNWithWorkspace(
        allocator,
        source,
        domain,
        alpha,
        &workspace,
        fold_count,
    );
    defer allocator.free(expected.values);

    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(64 * 1024);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    const input_base: u32 = 0;
    const input_stride: u32 = @intCast(source.len);
    for (source, 0..) |value, row| for (value.toM31Array(), 0..) |coordinate, index| {
        words[input_base + index * input_stride + row] = coordinate.v;
    };
    const alpha_base: u32 = 512;
    for (alpha.toM31Array(), 0..) |coordinate, index| words[alpha_base + index] = coordinate.v;
    const twiddle_base: u32 = 1024;
    @memcpy(
        words[twiddle_base .. twiddle_base + tree.itwiddles.len],
        std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(tree.itwiddles)),
    );
    const output_base: u32 = 2048;
    const output_stride: u32 = @intCast(expected.values.len);
    var prepared = try runtime.prepareFriRound(
        twiddle_base,
        @intCast(tree.itwiddles.len),
        input_base,
        input_stride,
        alpha_base,
        output_base,
        output_stride,
        @intCast(source.len),
        fold_count,
        false,
    );
    defer prepared.deinit();
    try std.testing.expect(try runtime.friRoundPrepared(arena, prepared) > 0);
    for (expected.values, 0..) |value, row| for (value.toM31Array(), 0..) |coordinate, index| {
        try std.testing.expectEqual(coordinate.v, words[output_base + index * output_stride + row]);
    };
}

test "metal: resident FRI line round selects the canonical twiddle subdomain" {
    try expectResidentFriLineRoundMatchesScalar(6, 3);
}

test "metal: resident FRI final two-fold round matches scalar path" {
    try expectResidentFriLineRoundMatchesScalar(3, 2);
}

test "metal: packed resident FRI tree matches lifted Blake2 root" {
    const evaluation_size: u32 = 8;
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(16 * 1024);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));

    const evaluation_base: u32 = 0;
    const coordinate_stride: u32 = evaluation_size;
    var coordinates: [4][evaluation_size]M31 = undefined;
    for (&coordinates, 0..) |*column, coordinate| {
        for (column, 0..) |*value, row| {
            value.* = M31.fromCanonical(@intCast(1 + coordinate * 101 + row * 17));
            words[evaluation_base + coordinate * coordinate_stride + row] = value.v;
        }
    }

    const leaf_offset: u32 = 128;
    const root_offset: u32 = 160;
    const layers = [_]u32{ leaf_offset, root_offset };
    var prepared = try runtime.prepareFriTree(
        evaluation_base,
        coordinate_stride,
        evaluation_size,
        2,
        &layers,
        Hasher.leafSeed(),
        Hasher.nodeSeed(),
        Hasher.domainPrefixBytes(),
    );
    defer prepared.deinit();
    try std.testing.expect(try runtime.friTreePrepared(arena, prepared) > 0);

    var leaves: [2]Hasher.Hash = undefined;
    for (&leaves, 0..) |*digest, leaf| {
        var message: [16]M31 = undefined;
        for (0..4) |offset| for (0..4) |coordinate| {
            message[coordinate + 4 * offset] = coordinates[coordinate][4 * leaf + offset];
        };
        var hasher = Hasher.defaultWithInitialState();
        hasher.updateLeaf(&message);
        digest.* = hasher.finalize();
    }
    const expected = Hasher.hashChildren(.{ .left = leaves[0], .right = leaves[1] });
    try std.testing.expectEqualSlices(
        u8,
        &expected,
        std.mem.asBytes(words[root_offset .. root_offset + 8]),
    );
}

test "metal: resident FRI final interpolation matches canonical line polynomial" {
    const allocator = std.testing.allocator;
    const domain = try line.LineDomain.init(circle_core.Coset.halfOdds(1));
    const values = [_]QM31{
        QM31.fromU32Unchecked(11, 13, 17, 19),
        QM31.fromU32Unchecked(23, 29, 31, 37),
    };
    var evaluation = try prover_line.LineEvaluation.initOwned(domain, try allocator.dupe(QM31, &values));
    var polynomial = try evaluation.interpolate(allocator);
    defer polynomial.deinit(allocator);
    const expected = polynomial.intoOrderedCoefficients();

    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(16 * 1024);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    const evaluation_base: u32 = 0;
    const stride: u32 = 2;
    for (values, 0..) |value, row| for (value.toM31Array(), 0..) |coordinate, index| {
        words[evaluation_base + index * stride + row] = coordinate.v;
    };
    const coefficient_base: u32 = 64;
    const error_offset: u32 = 80;
    const inverse_x = try domain.at(0).inv();
    var prepared = try runtime.prepareFriFinal(
        evaluation_base,
        stride,
        inverse_x.v,
        coefficient_base,
        error_offset,
    );
    defer prepared.deinit();
    try std.testing.expect(try runtime.friFinalPrepared(arena, prepared) > 0);
    for (expected, 0..) |coefficient, index| for (coefficient.toM31Array(), 0..) |coordinate, coordinate_index| {
        try std.testing.expectEqual(coordinate.v, words[coefficient_base + index * 4 + coordinate_index]);
    };
    try std.testing.expectEqual(@as(u32, @intFromBool(!expected[1].isZero())), words[error_offset]);
}

test "metal: FRI final-degree validation fails closed" {
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    var resident = arena_plan.ResidentArena{ .buffer = try runtime.allocateResidentBuffer(16 * 1024) };
    defer resident.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(resident.buffer.contents));
    const error_binding = testResidentBinding(1, 32, 1);
    var recipe = protocol_recipes.FriRecipe{
        .metal = &runtime,
        .arena = &resident,
        .rounds = undefined,
        .trees = undefined,
        .final = undefined,
        .roots = undefined,
        .initialized_rounds = 0,
        .initialized_trees = 0,
        .initialized_final = false,
        .final_degree_error = error_binding,
    };

    try std.testing.expectError(
        protocol_recipes.FriRecipe.FinalDegreeError.FinalDegreeNotComputed,
        recipe.validateFinalDegree(),
    );
    recipe.finalized = true;
    words[32] = 0;
    try recipe.validateFinalDegree();
    words[32] = 1;
    try std.testing.expectError(
        protocol_recipes.FriRecipe.FinalDegreeError.FinalDegreeExceeded,
        recipe.validateFinalDegree(),
    );
}

test "metal: resident Blake2s transcript matches host channel" {
    const allocator = std.testing.allocator;
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(16 * 1024);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    const state_base_24: u32 = 0;
    const state_base_25: u32 = 16;
    const source_base: u32 = 32;
    const secure_base_24: u32 = 128;
    const secure_base_25: u32 = 144;
    const query_base_24: u32 = 192;
    const query_base_25: u32 = 224;
    const source = [_]QM31{
        QM31.fromU32Unchecked(1, 2, 3, 4),
        QM31.fromU32Unchecked(5, 6, 7, 8),
        QM31.fromU32Unchecked(9, 10, 11, 12),
    };
    @memcpy(words[source_base .. source_base + 12], std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(&source)));

    var channel = blake2s_channel.Blake2sChannel{};
    channel.mixFelts(&source);
    const expected_secure = try channel.drawSecureFelts(allocator, 3);
    defer allocator.free(expected_secure);
    var expected_queries_24: [13]u32 = undefined;
    var expected_queries_25: [13]u32 = undefined;
    var produced: usize = 0;
    while (produced < expected_queries_24.len) {
        const draw = channel.drawU32s();
        for (draw) |word| {
            expected_queries_24[produced] = word & ((@as(u32, 1) << 24) - 1);
            expected_queries_25[produced] = word & ((@as(u32, 1) << 25) - 1);
            produced += 1;
            if (produced == expected_queries_24.len) break;
        }
    }

    _ = try runtime.transcriptInit(arena, state_base_24);
    _ = try runtime.transcriptInit(arena, state_base_25);
    _ = try runtime.transcriptMix(arena, state_base_24, source_base, 12);
    _ = try runtime.transcriptMix(arena, state_base_25, source_base, 12);
    _ = try runtime.transcriptDrawSecure(arena, state_base_24, secure_base_24, 3);
    _ = try runtime.transcriptDrawSecure(arena, state_base_25, secure_base_25, 3);
    _ = try runtime.transcriptDrawQueries(arena, state_base_24, query_base_24, 24, expected_queries_24.len);
    _ = try runtime.transcriptDrawQueries(arena, state_base_25, query_base_25, 25, expected_queries_25.len);
    try std.testing.expectEqualSlices(
        u32,
        std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(expected_secure)),
        words[secure_base_24 .. secure_base_24 + 12],
    );
    try std.testing.expectEqualSlices(
        u32,
        std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(expected_secure)),
        words[secure_base_25 .. secure_base_25 + 12],
    );
    try std.testing.expectEqualSlices(u32, &expected_queries_24, words[query_base_24 .. query_base_24 + expected_queries_24.len]);
    try std.testing.expectEqualSlices(u32, &expected_queries_25, words[query_base_25 .. query_base_25 + expected_queries_25.len]);
}
