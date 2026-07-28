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
const cairo_metal = @import("stwo_cairo_metal_integration");
const eval_codegen = cairo_metal.eval_codegen;
const circle_core = @import("stwo_core").circle;
const core_utils = @import("stwo_core").utils;
const blake2s_channel = @import("stwo_core").channel.blake2s;
const protocol_recipes = @import("stwo_metal_backend").protocol_recipes;
const arena_plan = @import("stwo_metal_backend").arena_plan;
const secure_column = @import("stwo_prover_impl").secure_column;
const secure_circle_poly = @import("stwo_prover_impl").poly.circle.secure_poly;
const cairo_arena_binding = cairo_metal.arena_binding;
const cairo_oods = cairo_metal.oods;
const cairo_quotient_inputs = cairo_metal.quotient_inputs;
const cairo_quotient_reference = cairo_metal.quotient_reference;

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

test "metal: sparse LDE reads the canonical suffix of a larger twiddle tower" {
    const allocator = std.testing.allocator;
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    const base_log: u32 = 9;
    const eval_log: u32 = 10;
    const tower_log: u32 = 13;
    var base_tree = try twiddles.precomputeM31(allocator, canonic.CanonicCoset.new(base_log).circleDomain().half_coset);
    defer twiddles.deinitM31(allocator, &base_tree);
    var eval_tree = try twiddles.precomputeM31(allocator, canonic.CanonicCoset.new(eval_log).circleDomain().half_coset);
    defer twiddles.deinitM31(allocator, &eval_tree);
    var tower = try twiddles.precomputeM31(allocator, canonic.CanonicCoset.new(tower_log).circleDomain().half_coset);
    defer twiddles.deinitM31(allocator, &tower);
    const coefficients = try allocator.alloc(M31, @as(usize, 1) << base_log);
    defer allocator.free(coefficients);
    const expected = try allocator.alloc(M31, @as(usize, 1) << eval_log);
    defer allocator.free(expected);
    for (coefficients, 0..) |*value, row| value.* = M31.fromCanonical(@intCast((row * 7919 + 17) % m31.Modulus));
    const base_const = twiddles.TwiddleTree([]const M31).init(base_tree.root_coset, base_tree.twiddles, base_tree.itwiddles);
    const eval_const = twiddles.TwiddleTree([]const M31).init(eval_tree.root_coset, eval_tree.twiddles, eval_tree.itwiddles);
    var coefficient_columns = [_][]M31{coefficients};
    try circle_poly.interpolateBuffersWithTwiddles(&coefficient_columns, canonic.CanonicCoset.new(base_log).circleDomain(), base_const);
    @memcpy(expected[0..coefficients.len], coefficients);
    @memset(expected[coefficients.len..], M31.zero());
    var expected_columns = [_][]M31{expected};
    try circle_poly.evaluateBuffersWithTwiddles(&expected_columns, canonic.CanonicCoset.new(eval_log).circleDomain(), eval_const);
    const source: u32 = 0;
    const destination: u32 = 2048;
    const tower_offset: u32 = 4096;
    var arena = try runtime.allocateResidentBuffer(65536);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    @memcpy(words[source .. source + coefficients.len], std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(coefficients)));
    @memcpy(words[tower_offset .. tower_offset + tower.twiddles.len], std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(tower.twiddles)));
    const suffix = tower_offset + @as(u32, @intCast(tower.twiddles.len - eval_tree.twiddles.len));
    var lde = try runtime.prepareCompositionLde(&.{source}, &.{base_log}, &.{destination}, eval_log, suffix);
    defer lde.deinit();
    _ = try runtime.compositionLdePrepared(arena, lde);
    try std.testing.expectEqualSlices(u32, std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(expected)), words[destination .. destination + expected.len]);
}

test "metal: radix-4 sparse LDE matches deterministic CPU domains" {
    const allocator = std.testing.allocator;
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    var prng = std.Random.DefaultPrng.init(0x5241_4449_5834_4c44);
    const random = prng.random();

    for ([_][2]u32{ .{ 10, 13 }, .{ 11, 14 } }) |logs| {
        const base_log = logs[0];
        const eval_log = logs[1];
        const base_len = @as(usize, 1) << @intCast(base_log);
        const eval_len = @as(usize, 1) << @intCast(eval_log);
        var base_tree = try twiddles.precomputeM31(
            allocator,
            canonic.CanonicCoset.new(base_log).circleDomain().half_coset,
        );
        defer twiddles.deinitM31(allocator, &base_tree);
        var eval_tree = try twiddles.precomputeM31(
            allocator,
            canonic.CanonicCoset.new(eval_log).circleDomain().half_coset,
        );
        defer twiddles.deinitM31(allocator, &eval_tree);
        const coefficients = try allocator.alloc(m31.M31, base_len);
        defer allocator.free(coefficients);
        for (coefficients) |*value|
            value.* = m31.M31.fromCanonical(random.int(u32) % m31.Modulus);
        var coefficient_columns = [_][]m31.M31{coefficients};
        const base_const = twiddles.TwiddleTree([]const m31.M31).init(
            base_tree.root_coset,
            base_tree.twiddles,
            base_tree.itwiddles,
        );
        try circle_poly.interpolateBuffersWithTwiddles(
            &coefficient_columns,
            canonic.CanonicCoset.new(base_log).circleDomain(),
            base_const,
        );

        const expected = try allocator.alloc(m31.M31, eval_len);
        defer allocator.free(expected);
        @memcpy(expected[0..base_len], coefficients);
        @memset(expected[base_len..], m31.M31.zero());
        var expected_columns = [_][]m31.M31{expected};
        const eval_const = twiddles.TwiddleTree([]const m31.M31).init(
            eval_tree.root_coset,
            eval_tree.twiddles,
            eval_tree.itwiddles,
        );
        try circle_poly.evaluateBuffersWithTwiddles(
            &expected_columns,
            canonic.CanonicCoset.new(eval_log).circleDomain(),
            eval_const,
        );

        const source: u32 = 0;
        const twiddle_offset: u32 = @intCast(base_len);
        const destination_word = base_len + eval_tree.twiddles.len;
        const destination: u32 = @intCast(destination_word);
        var arena = try runtime.allocateResidentBuffer(
            (destination_word + eval_len) * @sizeOf(u32),
        );
        defer arena.deinit();
        const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
        @memcpy(words[source .. source + base_len], std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(coefficients)));
        @memcpy(
            words[twiddle_offset .. twiddle_offset + eval_tree.twiddles.len],
            std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(eval_tree.twiddles)),
        );
        var lde = try runtime.prepareCompositionLdeConfigured(
            &.{source},
            &.{base_log},
            &.{destination},
            eval_log,
            twiddle_offset,
            .{ .radix4 = true },
        );
        defer lde.deinit();
        _ = try runtime.compositionLdePrepared(arena, lde);
        try std.testing.expectEqualSlices(
            u32,
            std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(expected)),
            words[destination_word .. destination_word + eval_len],
        );
    }
}

test "metal: sparse LDE matches Rust seq_4 reference" {
    const allocator = std.testing.allocator;
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    const base_log: u32 = 4;
    const eval_log: u32 = 5;
    const coefficients_u32 = [_]u32{ 1073741831, 0, 1943228410, 0, 380597802, 0, 142783525, 0, 2147221503, 0, 69204140, 0, 1551296076, 0, 1518526074, 4 };
    const expected = [_]u32{ 863170483, 863203251, 1007143128, 1007175896, 465131302, 465164070, 1722190238, 1722223006, 1856766077, 1856798845, 946856874, 946889642, 55834652, 55867420, 1672710822, 1672743590, 1641251221, 1641218453, 600224473, 600191705, 58867736, 58834968, 1334657298, 1334624530, 200854279, 200821511, 1606816039, 1606783271, 493042739, 493009971, 506868288, 506835520 };
    var eval_tree = try twiddles.precomputeM31(allocator, canonic.CanonicCoset.new(eval_log).circleDomain().half_coset);
    defer twiddles.deinitM31(allocator, &eval_tree);
    var arena = try runtime.allocateResidentBuffer(4096);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    @memcpy(words[0..coefficients_u32.len], &coefficients_u32);
    @memcpy(words[128 .. 128 + eval_tree.twiddles.len], std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(eval_tree.twiddles)));
    var lde = try runtime.prepareCompositionLde(&.{0}, &.{base_log}, &.{256}, eval_log, 128);
    defer lde.deinit();
    _ = try runtime.compositionLdePrepared(arena, lde);
    try std.testing.expectEqualSlices(u32, &expected, words[256 .. 256 + expected.len]);
}

test "metal: execution tables split compact little-endian values into 9-bit columns" {
    var runtime = try metal.Runtime.initFull();
    defer runtime.deinit();
    const rows: u32 = 16;
    const source_offset: u32 = 0;
    var offsets: [28]u32 = undefined;
    for (&offsets, 0..) |*offset, limb| offset.* = 64 + @as(u32, @intCast(limb)) * rows;
    var arena = try runtime.allocateResidentBuffer((64 + 28 * rows) * 4);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    const values = [_][8]u32{
        .{ 0xffffffff, 0x01234567, 0x89abcdef, 0x76543210, 1, 2, 3, 4 },
        .{ 511, 0, 0, 0, 0, 0, 0, 0 },
    };
    @memcpy(words[source_offset .. source_offset + values.len * 8], std.mem.bytesAsSlice(u32, std.mem.asBytes(&values)));
    _ = try runtime.executionTableSplit(arena, source_offset, values.len, rows, 8, &offsets);
    for (0..rows) |row| {
        var bit: usize = 0;
        for (offsets) |offset| {
            var expected: u32 = 0;
            if (row < values.len) {
                const word = bit / 32;
                const shift: u5 = @intCast(bit % 32);
                expected = values[row][word] >> shift;
                if (shift > 23 and word + 1 < 8) expected |= values[row][word + 1] << @intCast(32 - @as(u6, shift));
                expected &= 0x1ff;
            }
            try std.testing.expectEqual(expected, words[offset + row]);
            bit += 9;
        }
    }
}

test "metal: prepared sparse Merkle leaves match committed tree" {
    const allocator = std.testing.allocator;
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    const log_sizes = [_]u32{ 10, 9, 10, 8, 9, 10, 7, 10, 8, 10, 9, 10, 6, 10, 9, 10, 8 };
    var owned: [log_sizes.len][]M31 = undefined;
    var initialized: usize = 0;
    defer for (owned[0..initialized]) |column| allocator.free(column);
    var gpu_columns: [log_sizes.len][]const u32 = undefined;
    var total_words: u32 = 0;
    for (log_sizes, 0..) |log_size, column_index| {
        const column = try allocator.alloc(M31, @as(usize, 1) << @intCast(log_size));
        owned[column_index] = column;
        initialized += 1;
        for (column, 0..) |*value, row| value.* = M31.fromCanonical(@intCast((column_index * 7919 + row * 104729 + 17) % m31.Modulus));
        gpu_columns[column_index] = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(column));
        total_words += @intCast(column.len);
    }
    var reference = try runtime.commitColumns(
        allocator,
        &gpu_columns,
        &log_sizes,
        10,
        Hasher.leafSeed(),
        Hasher.nodeSeed(),
        Hasher.domainPrefixBytes(),
    );
    defer reference.deinit();
    const reference_layers = try reference.copyLayers(&runtime, allocator, 10);
    defer allocator.free(reference_layers);

    const destination_offset = std.mem.alignForward(u32, total_words, 64);
    const scratch_offset = destination_offset + 1024 * 8;
    var arena = try runtime.allocateResidentBuffer(@as(usize, scratch_offset + 512 * 8) * 4);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    var column_offsets: [log_sizes.len]u32 = undefined;
    var next: u32 = 0;
    for (owned, &column_offsets) |column, *offset| {
        offset.* = next;
        @memcpy(words[next .. next + column.len], std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(column)));
        next += @intCast(column.len);
    }
    var order: [log_sizes.len]usize = undefined;
    for (&order, 0..) |*index, value| index.* = value;
    std.sort.heap(usize, &order, log_sizes, struct {
        fn lessThan(sizes: [log_sizes.len]u32, lhs: usize, rhs: usize) bool {
            return sizes[lhs] < sizes[rhs] or (sizes[lhs] == sizes[rhs] and lhs < rhs);
        }
    }.lessThan);
    var sorted_offsets: [log_sizes.len]u32 = undefined;
    var sorted_logs: [log_sizes.len]u32 = undefined;
    for (order, 0..) |source, destination| {
        sorted_offsets[destination] = column_offsets[source];
        sorted_logs[destination] = log_sizes[source];
    }
    var plan = try runtime.prepareMerkleLeaves(&sorted_offsets, &sorted_logs, 10, destination_offset, Hasher.leafSeed(), Hasher.domainPrefixBytes());
    defer plan.deinit();
    const gpu_ms = try runtime.merkleLeavesPrepared(arena, plan);
    try std.testing.expect(gpu_ms > 0);
    try std.testing.expectEqualSlices(
        u8,
        std.mem.sliceAsBytes(reference_layers[reference_layers.len - 1024 ..]),
        std.mem.sliceAsBytes(words[destination_offset .. destination_offset + 1024 * 8]),
    );
    var layer_offsets: [11]u32 = undefined;
    for (&layer_offsets, 0..) |*offset, level| offset.* = if (level % 2 == 0) destination_offset else scratch_offset;
    var resident = try runtime.prepareResidentMerkle(
        &sorted_offsets,
        &sorted_logs,
        10,
        &layer_offsets,
        Hasher.leafSeed(),
        Hasher.nodeSeed(),
        Hasher.domainPrefixBytes(),
    );
    defer resident.deinit();
    _ = try runtime.residentMerklePrepared(arena, resident);
    try std.testing.expectEqualSlices(u8, &reference_layers[0], std.mem.sliceAsBytes(words[layer_offsets[10] .. layer_offsets[10] + 8]));
}
