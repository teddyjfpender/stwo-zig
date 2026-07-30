//! Metal circle-transform and composition-finalization conformance tests.

const std = @import("std");
const metal = @import("stwo_metal_backend").runtime;
const m31 = @import("stwo_core").fields.m31;
const canonic = @import("stwo_core").poly.circle.canonic;
const circle_poly = @import("stwo_prover_engine").poly.circle.poly;
const twiddles = @import("stwo_prover_engine").poly.twiddles;
const blake2_merkle = @import("stwo_core").vcs_lifted.blake2_merkle;
const merkle_prover = @import("stwo_prover_engine").vcs_lifted.prover;

const M31 = m31.M31;
const Hasher = blake2_merkle.Blake2sMerkleHasher;

test "metal: batched circle IFFT and RFFT match CPU" {
    const allocator = std.testing.allocator;
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();

    for ([_]u32{ 3, 8, 12 }) |log_size| {
        const domain = canonic.CanonicCoset.new(log_size).circleDomain();
        var tree = try twiddles.precomputeM31(allocator, domain.half_coset);
        defer twiddles.deinitM31(allocator, &tree);

        var cpu: [3][]M31 = undefined;
        var gpu: [3][]M31 = undefined;
        defer for (&cpu) |column| allocator.free(column);
        defer for (&gpu) |column| allocator.free(column);
        for (0..cpu.len) |column_index| {
            cpu[column_index] = try allocator.alloc(M31, domain.size());
            gpu[column_index] = try allocator.alloc(M31, domain.size());
            for (cpu[column_index], 0..) |*value, row| {
                value.* = M31.fromCanonical(@intCast((column_index * 3571 + row * 7919 + 23) % m31.Modulus));
            }
            @memcpy(gpu[column_index], cpu[column_index]);
        }

        const const_tree = twiddles.TwiddleTree([]const M31).init(tree.root_coset, tree.twiddles, tree.itwiddles);
        try circle_poly.interpolateBuffersWithTwiddles(&cpu, domain, const_tree);
        _ = try runtime.transformCircle(allocator, &gpu, tree.itwiddles, log_size, true);
        for (cpu, gpu) |cpu_column, gpu_column| {
            try std.testing.expectEqualSlices(M31, cpu_column, gpu_column);
        }

        try circle_poly.evaluateBuffersWithTwiddles(&cpu, domain, const_tree);
        _ = try runtime.transformCircle(allocator, &gpu, tree.twiddles, log_size, false);
        for (cpu, gpu) |cpu_column, gpu_column| {
            try std.testing.expectEqualSlices(M31, cpu_column, gpu_column);
        }
    }
}

test "metal: fused circle LDE matches CPU" {
    const allocator = std.testing.allocator;
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();

    const base_log_size: u32 = 12;
    const extended_log_size: u32 = 13;
    const base_domain = canonic.CanonicCoset.new(base_log_size).circleDomain();
    const extended_domain = canonic.CanonicCoset.new(extended_log_size).circleDomain();
    var base_tree = try twiddles.precomputeM31(allocator, base_domain.half_coset);
    defer twiddles.deinitM31(allocator, &base_tree);
    var extended_tree = try twiddles.precomputeM31(allocator, extended_domain.half_coset);
    defer twiddles.deinitM31(allocator, &extended_tree);

    var cpu_base: [3][]M31 = undefined;
    var cpu_extended: [3][]M31 = undefined;
    var gpu_base: [3][]M31 = undefined;
    var gpu_extended: [3][]M31 = undefined;
    defer for (&cpu_base) |column| allocator.free(column);
    defer for (&cpu_extended) |column| allocator.free(column);
    defer for (&gpu_base) |column| allocator.free(column);
    defer for (&gpu_extended) |column| allocator.free(column);
    for (0..cpu_base.len) |column_index| {
        cpu_base[column_index] = try allocator.alloc(M31, base_domain.size());
        cpu_extended[column_index] = try allocator.alloc(M31, extended_domain.size());
        gpu_base[column_index] = try allocator.alloc(M31, base_domain.size());
        gpu_extended[column_index] = try allocator.alloc(M31, extended_domain.size());
        for (cpu_base[column_index], 0..) |*value, row| {
            value.* = M31.fromCanonical(@intCast((column_index * 65537 + row * 8191 + 31) % m31.Modulus));
        }
        @memcpy(gpu_base[column_index], cpu_base[column_index]);
    }

    const base_const_tree = twiddles.TwiddleTree([]const M31).init(base_tree.root_coset, base_tree.twiddles, base_tree.itwiddles);
    const extended_const_tree = twiddles.TwiddleTree([]const M31).init(extended_tree.root_coset, extended_tree.twiddles, extended_tree.itwiddles);
    try circle_poly.interpolateBuffersWithTwiddles(&cpu_base, base_domain, base_const_tree);
    for (cpu_base, cpu_extended) |base, extended| {
        @memcpy(extended[0..base.len], base);
        @memset(extended[base.len..], M31.zero());
    }
    try circle_poly.evaluateBuffersWithTwiddles(&cpu_extended, extended_domain, extended_const_tree);

    _ = try runtime.transformCircleLde(
        allocator,
        &gpu_base,
        &gpu_base,
        &gpu_extended,
        base_tree.itwiddles,
        extended_tree.twiddles,
        base_log_size,
        extended_log_size,
    );
    for (cpu_base, gpu_base) |cpu_column, gpu_column| try std.testing.expectEqualSlices(M31, cpu_column, gpu_column);
    for (cpu_extended, gpu_extended) |cpu_column, gpu_column| try std.testing.expectEqualSlices(M31, cpu_column, gpu_column);
}

test "metal: forced combined circle LDE and Merkle matches generic path" {
    const allocator = std.testing.allocator;
    const backing_allocator = std.heap.page_allocator;
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();

    const column_count = 64;
    const base_log_size: u32 = 16;
    const extended_log_size = base_log_size + 1;
    const base_len = @as(usize, 1) << @intCast(base_log_size);
    const extended_len = @as(usize, 1) << @intCast(extended_log_size);
    const base_domain = canonic.CanonicCoset.new(base_log_size).circleDomain();
    const extended_domain = canonic.CanonicCoset.new(extended_log_size).circleDomain();
    var base_tree = try twiddles.precomputeM31(allocator, base_domain.half_coset);
    defer twiddles.deinitM31(allocator, &base_tree);
    var extended_tree = try twiddles.precomputeM31(allocator, extended_domain.half_coset);
    defer twiddles.deinitM31(allocator, &extended_tree);

    const base_words = column_count * base_len;
    const page_words = std.heap.pageSize() / @sizeOf(M31);
    const extended_stride = extended_len + page_words + 16;
    const extended_span = (column_count - 1) * extended_stride + extended_len;
    const transform_words = std.mem.alignForward(usize, extended_span, page_words);
    const metal_base_backing = try backing_allocator.alloc(M31, base_words);
    defer backing_allocator.free(metal_base_backing);
    const metal_extended_backing = try backing_allocator.alloc(M31, transform_words);
    defer backing_allocator.free(metal_extended_backing);
    const cpu_base_backing = try allocator.alloc(M31, base_words);
    defer allocator.free(cpu_base_backing);
    const cpu_extended_backing = try allocator.alloc(M31, column_count * extended_len);
    defer allocator.free(cpu_extended_backing);

    var source_columns: [column_count][]const M31 = undefined;
    var metal_base: [column_count][]M31 = undefined;
    var metal_extended: [column_count][]M31 = undefined;
    var cpu_base: [column_count][]M31 = undefined;
    var cpu_extended: [column_count][]M31 = undefined;
    for (0..column_count) |column_index| {
        metal_base[column_index] = metal_base_backing[column_index * base_len ..][0..base_len];
        source_columns[column_index] = metal_base[column_index];
        metal_extended[column_index] = metal_extended_backing[column_index * extended_stride ..][0..extended_len];
        cpu_base[column_index] = cpu_base_backing[column_index * base_len ..][0..base_len];
        cpu_extended[column_index] = cpu_extended_backing[column_index * extended_len ..][0..extended_len];
        for (metal_base[column_index], 0..) |*value, row| {
            value.* = M31.fromCanonical(@intCast(
                (column_index * 104729 + row * 8191 + 43) % m31.Modulus,
            ));
        }
        @memcpy(cpu_base[column_index], metal_base[column_index]);
    }

    const base_const_tree = twiddles.TwiddleTree([]const M31).init(
        base_tree.root_coset,
        base_tree.twiddles,
        base_tree.itwiddles,
    );
    const extended_const_tree = twiddles.TwiddleTree([]const M31).init(
        extended_tree.root_coset,
        extended_tree.twiddles,
        extended_tree.itwiddles,
    );
    try circle_poly.interpolateBuffersWithTwiddles(&cpu_base, base_domain, base_const_tree);
    for (cpu_base, cpu_extended) |base, extended| {
        @memcpy(extended[0..base.len], base);
        @memset(extended[base.len..], M31.zero());
    }
    try circle_poly.evaluateBuffersWithTwiddles(
        &cpu_extended,
        extended_domain,
        extended_const_tree,
    );

    var result = try runtime.transformCircleLdeAndCommit(
        allocator,
        &source_columns,
        &metal_base,
        &metal_extended,
        metal_extended_backing,
        0,
        extended_stride,
        base_tree.itwiddles,
        extended_tree.twiddles,
        base_log_size,
        extended_log_size,
        Hasher.leafSeed(),
        Hasher.nodeSeed(),
        Hasher.domainPrefixBytes(),
    );
    defer result.tree.deinit();
    try std.testing.expect(result.gpu_ms > 0);
    for (cpu_base, metal_base) |expected, actual| {
        try std.testing.expectEqualSlices(M31, expected, actual);
    }
    for (cpu_extended, metal_extended) |expected, actual| {
        try std.testing.expectEqualSlices(M31, expected, actual);
    }

    var generic_columns: [column_count][]const M31 = undefined;
    for (cpu_extended, 0..) |column, index| generic_columns[index] = column;
    var generic_tree = try merkle_prover.MerkleProverLifted(Hasher).commit(
        allocator,
        &generic_columns,
    );
    defer generic_tree.deinit(allocator);
    const metal_root = try result.tree.root();
    const generic_root: [32]u8 = @bitCast(generic_tree.root());
    try std.testing.expectEqualSlices(u8, &generic_root, &metal_root.hash);
}

test "metal: prepared sparse coefficient LDE matches CPU" {
    const allocator = std.testing.allocator;
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    const base_log_size: u32 = 10;
    const extended_log_size: u32 = 11;
    const base_domain = canonic.CanonicCoset.new(base_log_size).circleDomain();
    const extended_domain = canonic.CanonicCoset.new(extended_log_size).circleDomain();
    var base_tree = try twiddles.precomputeM31(allocator, base_domain.half_coset);
    defer twiddles.deinitM31(allocator, &base_tree);
    var extended_tree = try twiddles.precomputeM31(allocator, extended_domain.half_coset);
    defer twiddles.deinitM31(allocator, &extended_tree);
    const extended_const_tree = twiddles.TwiddleTree([]const M31).init(extended_tree.root_coset, extended_tree.twiddles, extended_tree.itwiddles);

    var coefficients: [2][]M31 = undefined;
    var expected: [2][]M31 = undefined;
    defer for (&coefficients) |column| allocator.free(column);
    defer for (&expected) |column| allocator.free(column);
    const base_const_tree = twiddles.TwiddleTree([]const M31).init(base_tree.root_coset, base_tree.twiddles, base_tree.itwiddles);
    for (0..2) |column_index| {
        coefficients[column_index] = try allocator.alloc(M31, base_domain.size());
        expected[column_index] = try allocator.alloc(M31, extended_domain.size());
        for (coefficients[column_index], 0..) |*value, row| {
            value.* = M31.fromCanonical(@intCast((column_index * 31337 + row * 7919 + 17) % m31.Modulus));
        }
    }
    try circle_poly.interpolateBuffersWithTwiddles(&coefficients, base_domain, base_const_tree);
    for (coefficients, expected) |source, destination| {
        @memcpy(destination[0..source.len], source);
        @memset(destination[source.len..], M31.zero());
    }
    try circle_poly.evaluateBuffersWithTwiddles(&expected, extended_domain, extended_const_tree);

    var arena = try runtime.allocateResidentBuffer(128 * 1024);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    const source_offsets = [_]u64{ 0, 4096 };
    const destination_offsets = [_]u64{ 8192, 16384 };
    const twiddle_offset: u32 = 24576;
    for (coefficients, source_offsets) |column, offset| {
        @memcpy(words[offset .. offset + column.len], std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(column)));
    }
    @memcpy(words[twiddle_offset .. twiddle_offset + extended_tree.twiddles.len], std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(extended_tree.twiddles)));
    var plan = try runtime.prepareCircleLde(&source_offsets, &destination_offsets, base_log_size, extended_log_size, twiddle_offset);
    defer plan.deinit();
    _ = try runtime.circleLdePrepared(arena, plan);
    for (expected, destination_offsets) |column, offset| {
        const actual_bytes = std.mem.sliceAsBytes(words[offset .. offset + column.len]);
        const actual: []align(@alignOf(M31)) const u8 = @alignCast(actual_bytes);
        try std.testing.expectEqualSlices(M31, column, std.mem.bytesAsSlice(M31, actual));
    }
}

test "metal: prepared sparse evaluation IFFT matches CPU" {
    const allocator = std.testing.allocator;
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    const log_size: u32 = 10;
    const domain = canonic.CanonicCoset.new(log_size).circleDomain();
    var tree = try twiddles.precomputeM31(allocator, domain.half_coset);
    defer twiddles.deinitM31(allocator, &tree);
    const const_tree = twiddles.TwiddleTree([]const M31).init(tree.root_coset, tree.twiddles, tree.itwiddles);

    var evaluations: [2][]M31 = undefined;
    var expected: [2][]M31 = undefined;
    defer for (&evaluations) |column| allocator.free(column);
    defer for (&expected) |column| allocator.free(column);
    for (0..evaluations.len) |column_index| {
        evaluations[column_index] = try allocator.alloc(M31, domain.size());
        expected[column_index] = try allocator.alloc(M31, domain.size());
        for (evaluations[column_index], 0..) |*value, row| {
            value.* = M31.fromCanonical(@intCast((column_index * 2137 + row * 65537 + 29) % m31.Modulus));
        }
        @memcpy(expected[column_index], evaluations[column_index]);
    }
    try circle_poly.interpolateBuffersWithTwiddles(&expected, domain, const_tree);

    var arena = try runtime.allocateResidentBuffer(64 * 1024);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    const source_offsets = [_]u64{ 0, 2048 };
    const destination_offsets = [_]u64{ 4096, 8192 };
    const twiddle_offset: u32 = 12288;
    for (evaluations, source_offsets) |column, offset| {
        const word_offset: usize = @intCast(offset);
        @memcpy(words[word_offset .. word_offset + column.len], std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(column)));
    }
    @memcpy(words[twiddle_offset .. twiddle_offset + tree.itwiddles.len], std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(tree.itwiddles)));
    const scale = try M31.fromCanonical(@intCast(domain.size())).inv();
    var plan = try runtime.prepareCircleIfft(&source_offsets, &destination_offsets, log_size, twiddle_offset, scale.v);
    defer plan.deinit();
    _ = try runtime.circleIfftPrepared(arena, plan);
    for (expected, destination_offsets) |column, offset| {
        const word_offset: usize = @intCast(offset);
        const actual_bytes = std.mem.sliceAsBytes(words[word_offset .. word_offset + column.len]);
        const actual: []align(@alignOf(M31)) const u8 = @alignCast(actual_bytes);
        try std.testing.expectEqualSlices(M31, column, std.mem.bytesAsSlice(M31, actual));
    }
}

fn expectPreparedSparseIfftDeterministic(log_size: u32, repetitions: usize) !void {
    const allocator = std.testing.allocator;
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    const domain = canonic.CanonicCoset.new(log_size).circleDomain();
    const rows = domain.size();
    var tree = try twiddles.precomputeM31(allocator, domain.half_coset);
    defer twiddles.deinitM31(allocator, &tree);
    const const_tree = twiddles.TwiddleTree([]const M31).init(
        tree.root_coset,
        tree.twiddles,
        tree.itwiddles,
    );

    var evaluations: [2][]M31 = undefined;
    var expected: [2][]M31 = undefined;
    defer for (&evaluations) |column| allocator.free(column);
    defer for (&expected) |column| allocator.free(column);
    for (&evaluations, &expected, 0..) |*evaluation, *coefficient, column_index| {
        evaluation.* = try allocator.alloc(M31, rows);
        coefficient.* = try allocator.alloc(M31, rows);
        for (evaluation.*, 0..) |*value, row| value.* = M31.fromCanonical(
            @intCast((column_index * 0x1f123 + row * 0x10101 + row * row * 17 + 29) % m31.Modulus),
        );
        @memcpy(coefficient.*, evaluation.*);
    }
    try circle_poly.interpolateBuffersWithTwiddles(&expected, domain, const_tree);

    const source_offsets = [_]u64{ 0, rows };
    const destination_offsets = [_]u64{ 2 * rows, 3 * rows };
    const twiddle_offset: u32 = @intCast(4 * rows);
    const arena_words = 4 * rows + tree.itwiddles.len;
    var arena = try runtime.allocateResidentBuffer(arena_words * @sizeOf(u32));
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    @memcpy(
        words[twiddle_offset .. twiddle_offset + tree.itwiddles.len],
        std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(tree.itwiddles)),
    );
    const scale = try M31.fromCanonical(@intCast(rows)).inv();
    var plan = try runtime.prepareCircleIfft(
        &source_offsets,
        &destination_offsets,
        log_size,
        twiddle_offset,
        scale.v,
    );
    defer plan.deinit();

    for (0..repetitions) |_| {
        for (evaluations, source_offsets) |column, offset| {
            const start: usize = @intCast(offset);
            @memcpy(
                words[start .. start + rows],
                std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(column)),
            );
        }
        _ = try runtime.circleIfftPrepared(arena, plan);
        for (expected, destination_offsets) |column, offset| {
            const start: usize = @intCast(offset);
            try std.testing.expectEqualSlices(
                u32,
                std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(column)),
                words[start .. start + rows],
            );
        }
    }
}

test "metal: prepared sparse evaluation IFFT is deterministic across command submissions" {
    // Log 10 is the smallest domain whose 512 butterflies span more than one
    // 256-thread group, so it exercises cross-group visibility at every layer.
    try expectPreparedSparseIfftDeterministic(10, 16);
}

test "metal: prepared sparse evaluation IFFT log-24 stress gate" {
    const allocator = std.testing.allocator;
    const enabled = std.process.getEnvVarOwned(
        allocator,
        "STWO_ZIG_METAL_IFFT_LOG24_STRESS",
    ) catch return error.SkipZigTest;
    defer allocator.free(enabled);
    if (!std.mem.eql(u8, enabled, "1")) return error.SkipZigTest;
    try expectPreparedSparseIfftDeterministic(24, 2);
}

fn expectPreparedCompositionFinalizeChainMatchesCpu(logs: []const u32, repetitions: usize) !void {
    const allocator = std.testing.allocator;
    if (logs.len < 3 or repetitions == 0) return error.InvalidTestFixture;
    for (logs[1..], logs[0 .. logs.len - 1]) |current, previous| {
        if (current <= previous) return error.InvalidTestFixture;
    }

    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    const max_log = logs[logs.len - 1];
    const max_rows = @as(usize, 1) << @intCast(max_log);
    const domain = canonic.CanonicCoset.new(max_log).circleDomain();
    var tree = try twiddles.precomputeM31(allocator, domain.half_coset);
    defer twiddles.deinitM31(allocator, &tree);
    const const_tree = twiddles.TwiddleTree([]const M31).init(
        tree.root_coset,
        tree.twiddles,
        tree.itwiddles,
    );

    const accumulator_offsets = try allocator.alloc(u32, logs.len);
    defer allocator.free(accumulator_offsets);
    var accumulator_words: usize = 0;
    for (logs, accumulator_offsets) |log_size, *offset| {
        offset.* = @intCast(accumulator_words);
        accumulator_words += 4 * (@as(usize, 1) << @intCast(log_size));
    }
    const initial = try allocator.alloc(u32, accumulator_words);
    defer allocator.free(initial);
    for (logs, accumulator_offsets, 0..) |log_size, offset, level| {
        const rows = @as(usize, 1) << @intCast(log_size);
        for (0..4) |coordinate| for (0..rows) |row| {
            initial[@as(usize, offset) + coordinate * rows + row] = @intCast(
                (level * 0x20b31 + coordinate * 0x1031 + row * 37 + row * row * 3 + 11) % m31.Modulus,
            );
        };
    }

    var lifted: [4][]M31 = undefined;
    defer for (&lifted) |column| allocator.free(column);
    const first_rows = @as(usize, 1) << @intCast(logs[0]);
    for (&lifted, 0..) |*column, coordinate| {
        column.* = try allocator.alloc(M31, first_rows);
        const start = @as(usize, accumulator_offsets[0]) + coordinate * first_rows;
        for (initial[start .. start + first_rows], column.*) |value, *destination|
            destination.* = M31.fromCanonical(value);
    }
    for (logs[1..], accumulator_offsets[1..]) |current_log, offset| {
        const previous_log: u32 = @intCast(std.math.log2_int(usize, lifted[0].len));
        const log_ratio = current_log - previous_log;
        const rows = @as(usize, 1) << @intCast(current_log);
        var next: [4][]M31 = undefined;
        var initialized: usize = 0;
        errdefer for (next[0..initialized]) |column| allocator.free(column);
        for (&next, 0..) |*column, coordinate| {
            column.* = try allocator.alloc(M31, rows);
            initialized += 1;
            const start = @as(usize, offset) + coordinate * rows;
            for (initial[start .. start + rows], column.*, 0..) |value, *destination, row| {
                const source = (row >> @intCast(log_ratio + 1) << 1) + (row & 1);
                destination.* = M31.fromCanonical(value).add(lifted[coordinate][source]);
            }
        }
        for (&lifted, &next) |*previous, column| {
            allocator.free(previous.*);
            previous.* = column;
        }
    }
    try circle_poly.interpolateBuffersWithTwiddles(&lifted, domain, const_tree);

    const twiddle_offset: u32 = @intCast(accumulator_words);
    const output_start = accumulator_words + tree.itwiddles.len;
    var output_offsets: [8]u32 = undefined;
    for (&output_offsets, 0..) |*offset, index| offset.* = @intCast(output_start + index * max_rows / 2);
    var arena = try runtime.allocateResidentBuffer((output_start + 4 * max_rows) * @sizeOf(u32));
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    @memcpy(
        words[twiddle_offset .. twiddle_offset + tree.itwiddles.len],
        std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(tree.itwiddles)),
    );
    const scale = try M31.fromCanonical(@intCast(max_rows)).inv();
    var plan = try runtime.prepareCompositionFinalize(
        accumulator_offsets,
        logs,
        twiddle_offset,
        output_offsets,
        scale.v,
    );
    defer plan.deinit();

    for (0..repetitions) |_| {
        @memcpy(words[0..initial.len], initial);
        _ = try runtime.compositionFinalizePrepared(arena, plan);
        for (0..8) |output| {
            const coordinate = output & 3;
            const half = output >> 2;
            const expected = lifted[coordinate][half * max_rows / 2 ..][0 .. max_rows / 2];
            const start: usize = output_offsets[output];
            try std.testing.expectEqualSlices(
                u32,
                std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(expected)),
                words[start .. start + max_rows / 2],
            );
        }
    }
}

test "metal: multi-level composition lift and IFFT is deterministic" {
    try expectPreparedCompositionFinalizeChainMatchesCpu(&.{ 3, 5, 7, 10 }, 16);
}

test "metal: multi-level composition finalize log-24 stress gate" {
    const allocator = std.testing.allocator;
    const enabled = std.process.getEnvVarOwned(
        allocator,
        "STWO_ZIG_METAL_IFFT_LOG24_STRESS",
    ) catch return error.SkipZigTest;
    defer allocator.free(enabled);
    if (!std.mem.eql(u8, enabled, "1")) return error.SkipZigTest;
    try expectPreparedCompositionFinalizeChainMatchesCpu(&.{ 5, 10, 17, 24 }, 2);
}

fn expectPreparedCompositionFinalizeMatchesCpu(previous_log: u32, current_log: u32) !void {
    const allocator = std.testing.allocator;
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    const previous_rows = @as(usize, 1) << @intCast(previous_log);
    const current_rows = @as(usize, 1) << @intCast(current_log);
    const domain = canonic.CanonicCoset.new(current_log).circleDomain();
    var tree = try twiddles.precomputeM31(allocator, domain.half_coset);
    defer twiddles.deinitM31(allocator, &tree);
    const const_tree = twiddles.TwiddleTree([]const M31).init(tree.root_coset, tree.twiddles, tree.itwiddles);
    var expected: [4][]M31 = undefined;
    defer for (&expected) |column| allocator.free(column);
    const previous_offset: u32 = 0;
    const current_offset: u32 = @intCast(4 * previous_rows);
    const twiddle_offset: u32 = current_offset + @as(u32, @intCast(4 * current_rows));
    const output_start: u32 = twiddle_offset + @as(u32, @intCast(tree.itwiddles.len));
    var output_offsets: [8]u32 = undefined;
    for (&output_offsets, 0..) |*offset, index| offset.* = output_start + @as(u32, @intCast(index * current_rows / 2));
    var arena = try runtime.allocateResidentBuffer((@as(usize, output_start) + 8 * current_rows / 2) * 4);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    for (0..4) |coordinate| {
        expected[coordinate] = try allocator.alloc(M31, current_rows);
        for (0..previous_rows) |row| words[@as(usize, previous_offset) + coordinate * previous_rows + row] = @intCast((coordinate * 1237 + row * 17 + 3) % m31.Modulus);
        for (0..current_rows) |row| {
            const value: u32 = @intCast((coordinate * 3571 + row * 29 + 11) % m31.Modulus);
            words[@as(usize, current_offset) + coordinate * current_rows + row] = value;
            const lifted = (row >> @intCast(current_log - previous_log + 1) << 1) + (row & 1);
            expected[coordinate][row] = M31.fromCanonical(value).add(M31.fromCanonical(words[@as(usize, previous_offset) + coordinate * previous_rows + lifted]));
        }
    }
    try circle_poly.interpolateBuffersWithTwiddles(&expected, domain, const_tree);
    @memcpy(words[@as(usize, twiddle_offset) .. @as(usize, twiddle_offset) + tree.itwiddles.len], std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(tree.itwiddles)));
    const scale = try M31.fromCanonical(@intCast(current_rows)).inv();
    var plan = try runtime.prepareCompositionFinalize(
        &.{ previous_offset, current_offset },
        &.{ previous_log, current_log },
        twiddle_offset,
        output_offsets,
        scale.v,
    );
    defer plan.deinit();
    const gpu_ms = try runtime.compositionFinalizePrepared(arena, plan);
    try std.testing.expect(gpu_ms > 0);
    for (0..8) |output| {
        const coordinate = output & 3;
        const half = output >> 2;
        const source = expected[coordinate][half * current_rows / 2 ..][0 .. current_rows / 2];
        const output_offset: usize = output_offsets[output];
        const actual_bytes = std.mem.sliceAsBytes(words[output_offset .. output_offset + current_rows / 2]);
        const actual: []align(@alignOf(M31)) const u8 = @alignCast(actual_bytes);
        try std.testing.expectEqualSlices(M31, source, std.mem.bytesAsSlice(M31, actual));
    }
}

test "metal: prepared composition lift interpolate and split matches CPU" {
    try expectPreparedCompositionFinalizeMatchesCpu(8, 10);
}

test "metal: prepared composition finalize matches CPU above SIMD transpose threshold" {
    try expectPreparedCompositionFinalizeMatchesCpu(13, 17);
}
