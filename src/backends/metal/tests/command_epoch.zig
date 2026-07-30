const std = @import("std");
const runtime_mod = @import("../runtime.zig");
const m31 = @import("stwo_core").fields.m31;
const blake2_merkle = @import("stwo_core").vcs_lifted.blake2_merkle;
const canonic = @import("stwo_core").poly.circle.canonic;
const circle_poly = @import("stwo_prover_engine").poly.circle.poly;
const twiddles = @import("stwo_prover_engine").poly.twiddles;
const merkle_prover = @import("stwo_prover_engine").vcs_lifted.prover;

const M31 = m31.M31;
const Hasher = blake2_merkle.Blake2sMerkleHasher;
const PlainHasher = blake2_merkle.Blake2sPlainMerkleHasher;

test "metal: resident commitment epoch owns one submit and wait" {
    const allocator = std.testing.allocator;
    var runtime = try runtime_mod.Runtime.init();
    defer runtime.deinit();

    const base_log: u32 = 10;
    const extended_log: u32 = 11;
    const base_domain = canonic.CanonicCoset.new(base_log).circleDomain();
    const extended_domain = canonic.CanonicCoset.new(extended_log).circleDomain();
    var base_tree = try twiddles.precomputeM31(allocator, base_domain.half_coset);
    defer twiddles.deinitM31(allocator, &base_tree);
    var extended_tree = try twiddles.precomputeM31(allocator, extended_domain.half_coset);
    defer twiddles.deinitM31(allocator, &extended_tree);
    const base_twiddles = twiddles.TwiddleTree([]const M31).init(
        base_tree.root_coset,
        base_tree.twiddles,
        base_tree.itwiddles,
    );
    const extended_twiddles = twiddles.TwiddleTree([]const M31).init(
        extended_tree.root_coset,
        extended_tree.twiddles,
        extended_tree.itwiddles,
    );

    var inputs: [2][]M31 = undefined;
    var expected_coefficients: [2][]M31 = undefined;
    var expected_evaluations: [2][]M31 = undefined;
    defer for (&inputs) |column| allocator.free(column);
    defer for (&expected_coefficients) |column| allocator.free(column);
    defer for (&expected_evaluations) |column| allocator.free(column);
    for (&inputs, &expected_coefficients, &expected_evaluations, 0..) |*input, *coefficient, *evaluation, column_index| {
        input.* = try allocator.alloc(M31, base_domain.size());
        coefficient.* = try allocator.alloc(M31, base_domain.size());
        evaluation.* = try allocator.alloc(M31, extended_domain.size());
        for (input.*, 0..) |*value, row| {
            value.* = M31.fromCanonical(@intCast((column_index * 31337 + row * 7919 + 41) % m31.Modulus));
        }
        @memcpy(coefficient.*, input.*);
    }
    try circle_poly.interpolateBuffersWithTwiddles(&expected_coefficients, base_domain, base_twiddles);
    for (expected_coefficients, expected_evaluations) |coefficient, evaluation| {
        @memcpy(evaluation[0..coefficient.len], coefficient);
        @memset(evaluation[coefficient.len..], M31.zero());
    }
    try circle_poly.evaluateBuffersWithTwiddles(&expected_evaluations, extended_domain, extended_twiddles);

    const base_rows: u32 = @intCast(base_domain.size());
    const extended_rows: u32 = @intCast(extended_domain.size());
    const source_offsets = [_]u64{ 0, base_rows };
    const coefficient_offsets = [_]u64{ 2 * base_rows, 3 * base_rows };
    const evaluation_offsets = [_]u64{ 4 * base_rows, 4 * base_rows + extended_rows };
    const inverse_twiddle_offset: u32 = 4 * base_rows + 2 * extended_rows;
    const forward_twiddle_offset: u32 = inverse_twiddle_offset + @as(u32, @intCast(base_tree.itwiddles.len));
    var layer_cursor = std.mem.alignForward(
        u32,
        forward_twiddle_offset + @as(u32, @intCast(extended_tree.twiddles.len)),
        64,
    );
    var layer_offsets: [extended_log + 1]u32 = undefined;
    var layer_hashes: u32 = extended_rows;
    for (&layer_offsets) |*offset| {
        offset.* = layer_cursor;
        layer_cursor = std.mem.alignForward(u32, layer_cursor + layer_hashes * 8, 64);
        layer_hashes >>= 1;
    }

    var arena = try runtime.allocateResidentBuffer(@as(usize, layer_cursor) * @sizeOf(u32));
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    for (inputs, source_offsets) |column, offset_value| {
        const offset: usize = @intCast(offset_value);
        @memcpy(words[offset .. offset + column.len], std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(column)));
    }
    @memcpy(
        words[inverse_twiddle_offset .. inverse_twiddle_offset + base_tree.itwiddles.len],
        std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(base_tree.itwiddles)),
    );
    @memcpy(
        words[forward_twiddle_offset .. forward_twiddle_offset + extended_tree.twiddles.len],
        std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(extended_tree.twiddles)),
    );

    const scale = try M31.fromCanonical(base_rows).inv();
    var ifft = try runtime.prepareCircleIfft(
        &source_offsets,
        &coefficient_offsets,
        base_log,
        inverse_twiddle_offset,
        scale.v,
    );
    defer ifft.deinit();
    var lde = try runtime.prepareCircleLde(
        &coefficient_offsets,
        &evaluation_offsets,
        base_log,
        extended_log,
        forward_twiddle_offset,
    );
    defer lde.deinit();
    const merkle_offsets = [_]u32{
        @intCast(evaluation_offsets[0]),
        @intCast(evaluation_offsets[1]),
    };
    const merkle_logs = [_]u32{ extended_log, extended_log };
    var merkle = try runtime.prepareResidentMerkle(
        &merkle_offsets,
        &merkle_logs,
        extended_log,
        &layer_offsets,
        Hasher.leafSeed(),
        Hasher.nodeSeed(),
        Hasher.domainPrefixBytes(),
    );
    defer merkle.deinit();

    var epoch = try runtime.beginCommandEpoch(arena);
    defer epoch.deinit();
    try epoch.encodeCircleIfft(ifft);
    try epoch.encodeCircleLde(lde);
    try epoch.encodeResidentMerkle(merkle);
    try epoch.submit();
    try std.testing.expectError(runtime_mod.MetalError.CommandEpochFailed, epoch.submit());
    const stats = try epoch.wait();
    try std.testing.expectError(runtime_mod.MetalError.CommandEpochFailed, epoch.wait());
    try std.testing.expectError(runtime_mod.MetalError.CommandEpochFailed, epoch.encodeCircleLde(lde));

    try std.testing.expectEqual(@as(u64, 1), stats.command_buffers);
    try std.testing.expectEqual(@as(u64, 1), stats.wait_count);
    try std.testing.expectEqual(@as(u64, 0), stats.intermediate_wait_count);
    try std.testing.expectEqual(stats.compute_encoders, stats.dispatches);
    try std.testing.expectEqual(@as(u64, 0), stats.blit_encoders);
    try std.testing.expect(stats.gpu_milliseconds > 0);

    for (expected_coefficients, coefficient_offsets) |expected, offset_value| {
        const offset: usize = @intCast(offset_value);
        try std.testing.expectEqualSlices(
            u32,
            std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(expected)),
            words[offset .. offset + expected.len],
        );
    }
    for (expected_evaluations, evaluation_offsets) |expected, offset_value| {
        const offset: usize = @intCast(offset_value);
        try std.testing.expectEqualSlices(
            u32,
            std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(expected)),
            words[offset .. offset + expected.len],
        );
    }

    const cpu_columns = [_][]const M31{
        expected_evaluations[0],
        expected_evaluations[1],
    };
    const CpuTree = merkle_prover.MerkleProverLifted(Hasher);
    var cpu_tree = try CpuTree.commit(allocator, &cpu_columns);
    defer cpu_tree.deinit(allocator);
    const root_words = words[layer_offsets[layer_offsets.len - 1]..][0..8];
    try std.testing.expectEqualSlices(u8, &cpu_tree.root(), std.mem.sliceAsBytes(root_words));
}

test "metal: compact streaming commitment epoch preserves evaluations and root" {
    const allocator = std.testing.allocator;
    var runtime = try runtime_mod.Runtime.init();
    defer runtime.deinit();

    const small_base_log: u32 = 4;
    const small_eval_log: u32 = 5;
    const large_base_log: u32 = 6;
    const large_eval_log: u32 = 7;
    const column_group_width = 16;
    const column_count = column_group_width * 2;
    var small_base_tree = try twiddles.precomputeM31(allocator, canonic.CanonicCoset.new(small_base_log).circleDomain().half_coset);
    defer twiddles.deinitM31(allocator, &small_base_tree);
    var small_eval_tree = try twiddles.precomputeM31(allocator, canonic.CanonicCoset.new(small_eval_log).circleDomain().half_coset);
    defer twiddles.deinitM31(allocator, &small_eval_tree);
    var large_base_tree = try twiddles.precomputeM31(allocator, canonic.CanonicCoset.new(large_base_log).circleDomain().half_coset);
    defer twiddles.deinitM31(allocator, &large_base_tree);
    var large_eval_tree = try twiddles.precomputeM31(allocator, canonic.CanonicCoset.new(large_eval_log).circleDomain().half_coset);
    defer twiddles.deinitM31(allocator, &large_eval_tree);

    var small_coefficients: [column_group_width][1 << small_base_log]M31 = undefined;
    var small_evaluations: [column_group_width][1 << small_eval_log]M31 = undefined;
    var large_coefficients: [column_group_width][1 << large_base_log]M31 = undefined;
    var large_evaluations: [column_group_width][1 << large_eval_log]M31 = undefined;
    var small_coefficient_slices: [column_group_width][]M31 = undefined;
    var small_evaluation_slices: [column_group_width][]M31 = undefined;
    var large_coefficient_slices: [column_group_width][]M31 = undefined;
    var large_evaluation_slices: [column_group_width][]M31 = undefined;
    for (0..column_group_width) |column| {
        for (&small_coefficients[column], 0..) |*value, row|
            value.* = M31.fromCanonical(@intCast((column * 313 + row * 17 + 9) % m31.Modulus));
        for (&large_coefficients[column], 0..) |*value, row|
            value.* = M31.fromCanonical(@intCast(((column + column_group_width) * 313 + row * 17 + 9) % m31.Modulus));
        small_coefficient_slices[column] = &small_coefficients[column];
        small_evaluation_slices[column] = &small_evaluations[column];
        large_coefficient_slices[column] = &large_coefficients[column];
        large_evaluation_slices[column] = &large_evaluations[column];
    }
    try circle_poly.interpolateBuffersWithTwiddles(
        &small_coefficient_slices,
        canonic.CanonicCoset.new(small_base_log).circleDomain(),
        twiddles.TwiddleTree([]const M31).init(small_base_tree.root_coset, small_base_tree.twiddles, small_base_tree.itwiddles),
    );
    try circle_poly.interpolateBuffersWithTwiddles(
        &large_coefficient_slices,
        canonic.CanonicCoset.new(large_base_log).circleDomain(),
        twiddles.TwiddleTree([]const M31).init(large_base_tree.root_coset, large_base_tree.twiddles, large_base_tree.itwiddles),
    );
    for (small_coefficients, &small_evaluations) |coefficient, *evaluation| {
        @memcpy(evaluation[0..coefficient.len], &coefficient);
        @memset(evaluation[coefficient.len..], M31.zero());
    }
    for (large_coefficients, &large_evaluations) |coefficient, *evaluation| {
        @memcpy(evaluation[0..coefficient.len], &coefficient);
        @memset(evaluation[coefficient.len..], M31.zero());
    }
    try circle_poly.evaluateBuffersWithTwiddles(
        &small_evaluation_slices,
        canonic.CanonicCoset.new(small_eval_log).circleDomain(),
        twiddles.TwiddleTree([]const M31).init(small_eval_tree.root_coset, small_eval_tree.twiddles, small_eval_tree.itwiddles),
    );
    try circle_poly.evaluateBuffersWithTwiddles(
        &large_evaluation_slices,
        canonic.CanonicCoset.new(large_eval_log).circleDomain(),
        twiddles.TwiddleTree([]const M31).init(large_eval_tree.root_coset, large_eval_tree.twiddles, large_eval_tree.itwiddles),
    );

    var source_offsets: [column_count]u64 = undefined;
    var destination_offsets: [column_count]u32 = undefined;
    var source_logs: [column_count]u32 = undefined;
    var destination_logs: [column_count]u32 = undefined;
    var cursor: u32 = 0;
    for (0..column_count) |column| {
        source_offsets[column] = cursor;
        source_logs[column] = if (column < column_group_width) small_base_log else large_base_log;
        cursor += @as(u32, 1) << @intCast(source_logs[column]);
    }
    const twiddle_offset = cursor;
    cursor += @intCast(large_eval_tree.twiddles.len);
    for (0..column_count) |column| {
        destination_offsets[column] = cursor;
        destination_logs[column] = if (column < column_group_width) small_eval_log else large_eval_log;
        cursor += @as(u32, 1) << @intCast(destination_logs[column]);
    }
    const leaf_state = std.mem.alignForward(u32, cursor, 64);
    const lifting_rows: u32 = 1 << large_eval_log;
    const snapshot = leaf_state + lifting_rows * 8;
    cursor = snapshot + (@as(u32, 1) << small_eval_log) * 8;
    var parent_children: [large_eval_log]u32 = undefined;
    var parent_destinations: [large_eval_log]u32 = undefined;
    var parent_counts: [large_eval_log]u32 = undefined;
    var parent_count = lifting_rows / 2;
    for (0..large_eval_log) |level| {
        parent_children[level] = if (level == 0) leaf_state else parent_destinations[level - 1];
        parent_destinations[level] = cursor;
        parent_counts[level] = parent_count;
        cursor += parent_count * 8;
        parent_count /= 2;
    }

    var arena = try runtime.allocateResidentBuffer(@as(usize, cursor) * @sizeOf(u32));
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    for (0..column_count) |column| {
        const offset: usize = @intCast(source_offsets[column]);
        if (column < column_group_width) {
            const coefficient = &small_coefficients[column];
            @memcpy(words[offset .. offset + coefficient.len], std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(coefficient)));
        } else {
            const coefficient = &large_coefficients[column - column_group_width];
            @memcpy(words[offset .. offset + coefficient.len], std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(coefficient)));
        }
    }
    @memcpy(
        words[twiddle_offset .. twiddle_offset + large_eval_tree.twiddles.len],
        std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(large_eval_tree.twiddles)),
    );

    const small_twiddle_offset = twiddle_offset + @as(u32, @intCast(large_eval_tree.twiddles.len - small_eval_tree.twiddles.len));
    var small_lde = try runtime.prepareCompositionLde(
        source_offsets[0..column_group_width],
        source_logs[0..column_group_width],
        destination_offsets[0..column_group_width],
        small_eval_log,
        small_twiddle_offset,
    );
    defer small_lde.deinit();
    var large_lde = try runtime.prepareCompositionLde(
        source_offsets[column_group_width..],
        source_logs[column_group_width..],
        destination_offsets[column_group_width..],
        large_eval_log,
        twiddle_offset,
    );
    defer large_lde.deinit();
    var snapshot_copy = try runtime.prepareArenaCopies(&.{.{
        .source_word_offset = leaf_state,
        .destination_word_offset = snapshot,
        .word_count = (@as(u32, 1) << small_eval_log) * 8,
    }});
    defer snapshot_copy.deinit();
    var parent_chain = try runtime.prepareMerkleParentChain(
        &parent_children,
        &parent_destinations,
        &parent_counts,
        PlainHasher.nodeSeed(),
        PlainHasher.domainPrefixBytes(),
    );
    defer parent_chain.deinit();

    var epoch = try runtime.beginCommandEpoch(arena);
    defer epoch.deinit();
    try epoch.encodeCompositionLde(small_lde);
    try epoch.encodeCompactLeaf(
        destination_offsets[0..column_group_width],
        destination_logs[0..column_group_width],
        leaf_state,
        small_eval_log,
        leaf_state,
        small_eval_log,
        0,
        false,
        0,
        PlainHasher.leafSeed(),
    );
    try epoch.encodeArenaCopy(snapshot_copy);
    try epoch.encodeCompositionLde(large_lde);
    try epoch.encodeCompactLeaf(
        destination_offsets[column_group_width..],
        destination_logs[column_group_width..],
        snapshot,
        small_eval_log,
        leaf_state,
        large_eval_log,
        column_group_width,
        true,
        0,
        PlainHasher.leafSeed(),
    );
    try epoch.encodeMerkleParentChain(parent_chain);
    try epoch.submit();
    const stats = try epoch.wait();

    try std.testing.expectEqual(@as(u64, 1), stats.command_buffers);
    try std.testing.expectEqual(@as(u64, 1), stats.wait_count);
    try std.testing.expectEqual(@as(u64, 0), stats.intermediate_wait_count);
    try std.testing.expectEqual(@as(u64, 17), stats.compute_encoders);
    try std.testing.expectEqual(@as(u64, 1), stats.blit_encoders);
    try std.testing.expectEqual(@as(u64, 17), stats.dispatches);
    try std.testing.expectEqual(@as(u64, 5), 6 - stats.command_buffers);
    try std.testing.expectEqual(@as(u64, 5), 6 - stats.wait_count);
    try std.testing.expect(stats.gpu_milliseconds > 0);

    var cpu_columns: [column_count][]const M31 = undefined;
    for (0..column_count) |column| {
        const expected = if (column < column_group_width)
            small_evaluations[column][0..]
        else
            large_evaluations[column - column_group_width][0..];
        cpu_columns[column] = expected;
        const offset: usize = @intCast(destination_offsets[column]);
        try std.testing.expectEqualSlices(
            u32,
            std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(expected)),
            words[offset .. offset + expected.len],
        );
    }
    const CpuTree = merkle_prover.MerkleProverLifted(PlainHasher);
    var cpu_tree = try CpuTree.commit(allocator, &cpu_columns);
    defer cpu_tree.deinit(allocator);
    const root_words = words[parent_destinations[parent_destinations.len - 1]..][0..8];
    try std.testing.expectEqualSlices(u8, &cpu_tree.root(), std.mem.sliceAsBytes(root_words));
}

test "metal: command epoch retains a prepared plan through completion" {
    var runtime = try runtime_mod.Runtime.init();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(4096);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    for (words[0..16], 0..) |*word, index| word.* = @intCast(index * 17 + 3);

    var copy = try runtime.prepareArenaCopies(&.{.{
        .source_word_offset = 0,
        .destination_word_offset = 64,
        .word_count = 16,
    }});
    var copy_live = true;
    defer if (copy_live) copy.deinit();
    var epoch = try runtime.beginCommandEpoch(arena);
    defer epoch.deinit();
    try epoch.encodeArenaCopy(copy);
    copy.deinit();
    copy_live = false;
    try epoch.submit();
    const stats = try epoch.wait();

    try std.testing.expectEqual(@as(u64, 1), stats.command_buffers);
    try std.testing.expectEqual(@as(u64, 1), stats.wait_count);
    try std.testing.expectEqual(@as(u64, 1), stats.blit_encoders);
    try std.testing.expectEqualSlices(u32, words[0..16], words[64..80]);
}

test "metal: fused parent tail retains its plan and materializes every layer" {
    var runtime = try runtime_mod.Runtime.init();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(4096);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    var children: [8]Hasher.Hash = undefined;
    for (&children, 0..) |*hash, child| {
        for (hash, 0..) |*byte, index| byte.* = @intCast((child * 37 + index * 13 + 11) & 0xff);
    }
    @memcpy(std.mem.sliceAsBytes(words[0 .. children.len * 8]), std.mem.sliceAsBytes(&children));

    var middle: [4]Hasher.Hash = undefined;
    for (&middle, 0..) |*hash, index|
        hash.* = Hasher.hashChildrenWithSeed(Hasher.nodeSeed(), .{ .left = children[index * 2], .right = children[index * 2 + 1] });
    var upper: [2]Hasher.Hash = undefined;
    for (&upper, 0..) |*hash, index|
        hash.* = Hasher.hashChildrenWithSeed(Hasher.nodeSeed(), .{ .left = middle[index * 2], .right = middle[index * 2 + 1] });
    const root = Hasher.hashChildrenWithSeed(Hasher.nodeSeed(), .{ .left = upper[0], .right = upper[1] });

    const middle_offset: u32 = 128;
    const upper_offset: u32 = 192;
    const root_offset: u32 = 224;
    var plan = try runtime.prepareMerkleParentChain(
        &.{ 0, middle_offset, upper_offset },
        &.{ middle_offset, upper_offset, root_offset },
        &.{ 4, 2, 1 },
        Hasher.nodeSeed(),
        Hasher.domainPrefixBytes(),
    );
    var plan_live = true;
    defer if (plan_live) plan.deinit();
    var epoch = try runtime.beginCommandEpoch(arena);
    defer epoch.deinit();
    try epoch.encodeMerkleParentChain(plan);
    plan.deinit();
    plan_live = false;
    try epoch.submit();
    const stats = try epoch.wait();

    try std.testing.expectEqual(@as(u64, 1), stats.compute_encoders);
    try std.testing.expectEqual(@as(u64, 1), stats.dispatches);
    try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(&middle), std.mem.sliceAsBytes(words[middle_offset .. middle_offset + middle.len * 8]));
    try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(&upper), std.mem.sliceAsBytes(words[upper_offset .. upper_offset + upper.len * 8]));
    try std.testing.expectEqualSlices(u8, &root, std.mem.sliceAsBytes(words[root_offset .. root_offset + 8]));
}

test "metal: generic parent chain reduces independent bottom subtrees in one grid" {
    const allocator = std.testing.allocator;
    var runtime = try runtime_mod.Runtime.init();
    defer runtime.deinit();
    const leaf_count = 2048;
    const level_count = 11;
    const children = try allocator.alloc(Hasher.Hash, leaf_count);
    defer allocator.free(children);
    for (children, 0..) |*hash, child| {
        for (hash, 0..) |*byte, index| byte.* = @intCast((child * 29 + index * 17 + 5) & 0xff);
    }
    var expected: [level_count][]Hasher.Hash = undefined;
    var expected_level_count: usize = 0;
    defer for (expected[0..expected_level_count]) |level| allocator.free(level);
    var previous: []const Hasher.Hash = children;
    for (&expected) |*level| {
        level.* = try allocator.alloc(Hasher.Hash, previous.len / 2);
        expected_level_count += 1;
        for (level.*, 0..) |*hash, index|
            hash.* = Hasher.hashChildrenWithSeed(Hasher.nodeSeed(), .{ .left = previous[index * 2], .right = previous[index * 2 + 1] });
        previous = level.*;
    }

    var child_offsets: [level_count]u32 = undefined;
    var destination_offsets: [level_count]u32 = undefined;
    var parent_counts: [level_count]u32 = undefined;
    var cursor: u32 = leaf_count * 8;
    for (0..level_count) |level| {
        child_offsets[level] = if (level == 0) 0 else destination_offsets[level - 1];
        destination_offsets[level] = cursor;
        parent_counts[level] = @intCast(expected[level].len);
        cursor += parent_counts[level] * 8;
    }
    var arena = try runtime.allocateResidentBuffer(@as(usize, cursor) * @sizeOf(u32));
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    @memcpy(std.mem.sliceAsBytes(words[0 .. children.len * 8]), std.mem.sliceAsBytes(children));
    var plan = try runtime.prepareMerkleParentChain(
        &child_offsets,
        &destination_offsets,
        &parent_counts,
        Hasher.nodeSeed(),
        Hasher.domainPrefixBytes(),
    );
    defer plan.deinit();
    var epoch = try runtime.beginCommandEpoch(arena);
    defer epoch.deinit();
    try epoch.encodeMerkleParentChain(plan);
    try epoch.submit();
    const stats = try epoch.wait();

    try std.testing.expectEqual(@as(u64, 1), stats.compute_encoders);
    try std.testing.expectEqual(@as(u64, 2), stats.dispatches);
    for (expected, destination_offsets) |level, offset|
        try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(level), std.mem.sliceAsBytes(words[offset .. offset + level.len * 8]));

    // Reuse the leaf range as one half of a ping-pong chain.  The global
    // dispatch barriers make this legal, but one multi-threadgroup grid
    // would race a destination writer against another group's initial read.
    // Preparation must therefore retain the conservative per-level schedule.
    const alternate_offset: u32 = leaf_count * 8;
    var aliased_children: [level_count]u32 = undefined;
    var aliased_destinations: [level_count]u32 = undefined;
    for (0..level_count) |level| {
        aliased_children[level] = if (level == 0) 0 else aliased_destinations[level - 1];
        aliased_destinations[level] = if (level & 1 == 0) alternate_offset else 0;
    }
    var aliased_plan = try runtime.prepareMerkleParentChain(
        &aliased_children,
        &aliased_destinations,
        &parent_counts,
        Hasher.nodeSeed(),
        Hasher.domainPrefixBytes(),
    );
    defer aliased_plan.deinit();
    var aliased_epoch = try runtime.beginCommandEpoch(arena);
    defer aliased_epoch.deinit();
    try aliased_epoch.encodeMerkleParentChain(aliased_plan);
    try aliased_epoch.submit();
    const aliased_stats = try aliased_epoch.wait();
    // Nine global levels plus the existing two-level top tail.
    try std.testing.expectEqual(@as(u64, 1), aliased_stats.compute_encoders);
    try std.testing.expectEqual(@as(u64, level_count - 1), aliased_stats.dispatches);
    try std.testing.expectEqualSlices(
        u8,
        std.mem.sliceAsBytes(expected[level_count - 1]),
        std.mem.sliceAsBytes(words[alternate_offset .. alternate_offset + 8]),
    );
}

test "metal: parent chain preparation and arena bounds fail closed" {
    var runtime = try runtime_mod.Runtime.init();
    defer runtime.deinit();
    try std.testing.expectError(
        runtime_mod.MetalError.CommitmentFailed,
        runtime.prepareMerkleParentChain(&.{0}, &.{32}, &.{0}, Hasher.nodeSeed(), Hasher.domainPrefixBytes()),
    );

    var arena = try runtime.allocateResidentBuffer(256);
    defer arena.deinit();
    var plan = try runtime.prepareMerkleParentChain(&.{48}, &.{0}, &.{4}, Hasher.nodeSeed(), Hasher.domainPrefixBytes());
    defer plan.deinit();
    var epoch = try runtime.beginCommandEpoch(arena);
    defer epoch.deinit();
    try std.testing.expectError(runtime_mod.MetalError.CommandEpochFailed, epoch.encodeMerkleParentChain(plan));
    try std.testing.expectEqual(runtime_mod.CommandEpoch.State.failed, epoch.state);
    try std.testing.expectError(runtime_mod.MetalError.CommandEpochFailed, epoch.submit());
}

test "metal: empty command epoch fails closed before submission" {
    var runtime = try runtime_mod.Runtime.init();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(4096);
    defer arena.deinit();
    var epoch = try runtime.beginCommandEpoch(arena);
    defer epoch.deinit();
    try std.testing.expectError(runtime_mod.MetalError.CommandEpochFailed, epoch.submit());
    try std.testing.expectEqual(runtime_mod.CommandEpoch.State.failed, epoch.state);
}
