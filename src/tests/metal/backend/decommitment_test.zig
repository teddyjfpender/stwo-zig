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

test "metal: resident decommit query preparation matches canonical mapping" {
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(16 * 1024);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    const raw_base: u32 = 0;
    const unique_base: u32 = 64;
    const unique_count_base: u32 = 120;
    const tree_base: u32 = 128;
    const tree_count_base: u32 = 184;
    const expanded_base: u32 = 192;
    const expanded_count_base: u32 = 320;
    const walk_base: u32 = 328;
    const walk_count_base: u32 = 456;
    const assembly_base: u32 = 3150;
    const assembly_capacity: u32 = 946;
    const raw = [_]u32{ 0x101, 7, 7, 33, 2, 0x1ff, 65, 16, 17, 18, 19 };
    @memcpy(words[raw_base .. raw_base + raw.len], &raw);
    _ = try runtime.decommitNormalizeQueries(arena, raw_base, raw.len, 8, unique_base, unique_count_base, 12, assembly_base, assembly_capacity);
    try std.testing.expectEqual(@as(u32, 10), words[unique_count_base]);
    try std.testing.expectEqualSlices(u32, &.{ 1, 2, 7, 16, 17, 18, 19, 33, 65, 255 }, words[unique_base .. unique_base + 10]);
    try std.testing.expectEqualSlices(u32, &.{ 0x44575453, 1, 12, raw.len, 10, 200, 211, 221 }, words[assembly_base .. assembly_base + 8]);
    try std.testing.expectEqualSlices(u32, &.{ 1, 7, 7, 33, 2, 255, 65, 16, 17, 18, 19 }, words[assembly_base + 200 .. assembly_base + 211]);

    _ = try runtime.decommitPrepareFriQueries(
        arena,
        unique_base,
        unique_count_base,
        raw.len,
        3,
        3,
        2,
        tree_base,
        tree_count_base,
        expanded_base,
        expanded_count_base,
        walk_base,
        walk_count_base,
    );
    try std.testing.expectEqual(@as(u32, 5), words[tree_count_base]);
    try std.testing.expectEqualSlices(u32, &.{ 0, 2, 4, 8, 31 }, words[tree_base .. tree_base + 5]);
    try std.testing.expectEqual(@as(u32, 24), words[expanded_count_base]);
    try std.testing.expectEqualSlices(u32, &.{ 0, 1, 2, 3, 4, 5, 6, 7 }, words[expanded_base .. expanded_base + 8]);
    try std.testing.expectEqual(@as(u32, 6), words[walk_count_base]);
    try std.testing.expectEqualSlices(u32, &.{ 0, 1, 2, 3, 6, 7 }, words[walk_base .. walk_base + 6]);

    _ = try runtime.decommitPrepareTraceQueries(
        arena,
        unique_base,
        unique_count_base,
        raw.len,
        24,
        21,
        21,
        2,
        tree_base,
        tree_count_base,
        walk_base,
        walk_count_base,
        expanded_base,
        expanded_count_base,
    );
    try std.testing.expectEqual(@as(u32, 10), words[tree_count_base]);
    try std.testing.expectEqualSlices(u32, &.{ 1, 0, 1, 2, 3, 2, 3, 5, 9, 31 }, words[tree_base .. tree_base + 10]);
    try std.testing.expectEqual(@as(u32, 7), words[walk_count_base]);
    try std.testing.expectEqualSlices(u32, &.{ 0, 1, 2, 3, 5, 9, 31 }, words[walk_base .. walk_base + 7]);
    try std.testing.expectEqual(@as(u32, 16), words[expanded_count_base]);
    try std.testing.expectEqualSlices(u32, &.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 28, 29, 30, 31 }, words[expanded_base .. expanded_base + 16]);

    const column_offsets_base: u32 = 480;
    const column_logs_base: u32 = 484;
    const trace_values_base: u32 = 1024;
    words[column_offsets_base] = 512;
    words[column_offsets_base + 1] = 0;
    words[column_offsets_base + 2] = 768;
    words[column_offsets_base + 3] = 0;
    words[column_logs_base] = 8;
    words[column_logs_base + 1] = 7;
    for (0..256) |row| words[512 + row] = @intCast(1000 + row);
    for (0..128) |row| words[768 + row] = @intCast(2000 + row);
    const sparse_hashes_base: u32 = 2000;
    _ = try runtime.decommitTraceGroup(
        arena,
        .{
            .column_offsets = column_offsets_base,
            .column_logs = column_logs_base,
            .queries = tree_base,
            .query_count_at = tree_count_base,
            .values = trace_values_base,
            .leaf_indices = expanded_base,
            .leaf_count_at = expanded_count_base,
            .output_hashes = sparse_hashes_base,
            .column_count = 2,
            .lifting_log = 8,
            .max_queries = raw.len,
            .first_column = 0,
            .stride = raw.len,
            .total_columns = 2,
            .max_leaf_count = raw.len << 2,
            .domain_prefix_bytes = PlainHasher.domainPrefixBytes(),
            .leaf_seed = PlainHasher.leafSeed(),
        },
    );
    for (words[tree_base .. tree_base + words[tree_count_base]], 0..) |query, index| {
        try std.testing.expectEqual(1000 + query, words[trace_values_base + index]);
        const lifted = ((query >> 2) << 1) + (query & 1);
        try std.testing.expectEqual(2000 + lifted, words[trace_values_base + raw.len + index]);
    }

    _ = try runtime.decommitPrepareFriQueries(
        arena,
        unique_base,
        unique_count_base,
        raw.len,
        3,
        3,
        2,
        tree_base,
        tree_count_base,
        expanded_base,
        expanded_count_base,
        walk_base,
        walk_count_base,
    );
    const coordinate_bases: u32 = 490;
    const fri_values_base: u32 = 3000;
    for (0..4) |coordinate| {
        words[coordinate_bases + coordinate * 2] = @intCast(1600 + coordinate * 256);
        words[coordinate_bases + coordinate * 2 + 1] = 0;
        for (0..256) |row| words[1600 + coordinate * 256 + row] = @intCast(coordinate * 1000 + row);
    }
    _ = try runtime.decommitGatherFriValues(
        arena,
        coordinate_bases,
        expanded_base,
        expanded_count_base,
        128,
        fri_values_base,
    );
    for (words[expanded_base .. expanded_base + words[expanded_count_base]], 0..) |position, index| {
        for (0..4) |coordinate| try std.testing.expectEqual(
            @as(u32, @intCast(coordinate * 1000)) + position,
            words[fri_values_base + index * 4 + coordinate],
        );
    }
    const retained_offsets: u32 = 3100;
    words[retained_offsets] = 0;
    words[retained_offsets + 1] = 0;
    words[retained_offsets + 2] = 2890;
    words[retained_offsets + 3] = 0;
    words[retained_offsets + 4] = 2922;
    words[retained_offsets + 5] = 0;
    for (0..32) |index| words[2890 + index] = @intCast(0x1000 + index);
    for (0..64) |index| words[2922 + index] = @intCast(0x2000 + index);
    _ = try runtime.decommitAssembleFri(
        arena,
        4,
        2,
        tree_base,
        tree_count_base,
        expanded_base,
        expanded_count_base,
        fri_values_base,
        walk_base,
        900,
        walk_count_base,
        retained_offsets,
        assembly_base,
        assembly_capacity,
    );
    try std.testing.expect(words[assembly_base + 7] > 221);
    try std.testing.expectEqual(@as(u32, 1), words[assembly_base + 8 + 4 * 16]);
    try std.testing.expectEqual(@as(u32, 4), words[assembly_base + 8 + 4 * 16 + 1]);
}

test "metal: trace sparse parents and assembly are resident and fail closed" {
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(64 * 1024);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    const counts: u32 = 100;
    const mapped: u32 = 128;
    const walk: u32 = 256;
    const scratch: u32 = 320;
    const values: u32 = 384;
    const sparse_indices: u32 = 512;
    const sparse_hashes: u32 = 640;
    const sparse_offsets: u32 = 800;
    const retained_offsets: u32 = 820;
    const retained_level_one: u32 = 832;
    const parent_indices: u32 = 900;
    const parent_hashes: u32 = 920;
    const assembly: u32 = 1024;
    const capacity: u32 = 2048;

    words[mapped] = 0;
    words[mapped + 1] = 1;
    words[counts + 1] = 2;
    words[walk] = 0;
    words[walk + 1] = 1;
    words[counts + 2] = 2;
    words[counts + 4] = 2;
    words[values] = 11;
    words[values + 1] = 12;
    words[sparse_indices] = 0;
    words[sparse_indices + 1] = 1;
    words[sparse_offsets] = 0;
    const column_offsets: u32 = 1180;
    const column_logs: u32 = 1184;
    const column_zero: u32 = 1200;
    const column_one: u32 = 1210;
    words[column_offsets] = column_zero;
    words[column_offsets + 1] = 0;
    words[column_offsets + 2] = column_one;
    words[column_offsets + 3] = 0;
    words[column_logs] = 2;
    words[column_logs + 1] = 2;
    for (0..4) |row| {
        words[column_zero + row] = @intCast(10 + row);
        words[column_one + row] = @intCast(20 + row);
    }
    _ = try runtime.decommitSparseLeaves(
        arena,
        column_offsets,
        column_logs,
        2,
        2,
        sparse_indices,
        counts + 4,
        2,
        sparse_hashes,
        PlainHasher.leafSeed(),
        PlainHasher.domainPrefixBytes(),
    );
    for (0..2) |row| {
        var leaf = PlainHasher.defaultWithInitialState();
        leaf.updateLeaf(&.{ M31.fromCanonical(@intCast(10 + row)), M31.fromCanonical(@intCast(20 + row)) });
        const expected = leaf.finalize();
        try std.testing.expectEqualSlices(
            u8,
            &expected,
            std.mem.sliceAsBytes(words[sparse_hashes + row * 8 .. sparse_hashes + (row + 1) * 8]),
        );
    }

    const streamed_offsets: u32 = 1500;
    const streamed_logs: u32 = 1570;
    const streamed_columns: u32 = 1620;
    const streamed_hashes: u32 = 1800;
    for (0..33) |column| {
        words[streamed_offsets + column * 2] = @intCast(streamed_columns + column * 4);
        words[streamed_offsets + column * 2 + 1] = 0;
        words[streamed_logs + column] = 2;
        for (0..4) |row| words[streamed_columns + column * 4 + row] = @intCast(100 + column * 10 + row);
    }
    _ = try runtime.decommitSparseLeafGroup(
        arena,
        streamed_offsets,
        streamed_logs,
        16,
        0,
        33,
        2,
        sparse_indices,
        counts + 4,
        2,
        streamed_hashes,
        PlainHasher.leafSeed(),
        PlainHasher.domainPrefixBytes(),
    );
    _ = try runtime.decommitSparseLeafGroup(
        arena,
        streamed_offsets + 32,
        streamed_logs + 16,
        16,
        16,
        33,
        2,
        sparse_indices,
        counts + 4,
        2,
        streamed_hashes,
        PlainHasher.leafSeed(),
        PlainHasher.domainPrefixBytes(),
    );
    _ = try runtime.decommitSparseLeafGroup(
        arena,
        streamed_offsets + 64,
        streamed_logs + 32,
        1,
        32,
        33,
        2,
        sparse_indices,
        counts + 4,
        2,
        streamed_hashes,
        PlainHasher.leafSeed(),
        PlainHasher.domainPrefixBytes(),
    );
    for (0..2) |row| {
        var evaluations: [33]M31 = undefined;
        for (&evaluations, 0..) |*value, column| value.* = M31.fromCanonical(@intCast(100 + column * 10 + row));
        var leaf = PlainHasher.defaultWithInitialState();
        leaf.updateLeaf(&evaluations);
        const expected = leaf.finalize();
        try std.testing.expectEqualSlices(
            u8,
            &expected,
            std.mem.sliceAsBytes(words[streamed_hashes + row * 8 .. streamed_hashes + (row + 1) * 8]),
        );
    }
    words[retained_offsets] = 0;
    words[retained_offsets + 1] = 0;
    words[retained_offsets + 2] = retained_level_one;
    words[retained_offsets + 3] = 0;
    for (0..16) |index| words[retained_level_one + index] = @intCast(0x200 + index);

    words[assembly] = 0x44575453;
    words[assembly + 1] = 1;
    words[assembly + 2] = 1;
    words[assembly + 7] = 24;
    _ = try runtime.decommitAssembleTrace(
        arena,
        0,
        0,
        2,
        1,
        1,
        mapped,
        counts + 1,
        70,
        walk,
        scratch,
        counts + 2,
        values,
        retained_offsets,
        sparse_indices,
        sparse_hashes,
        sparse_offsets,
        counts + 4,
        1,
        assembly,
        capacity,
    );
    try std.testing.expect(words[assembly + 7] > 24);
    try std.testing.expectEqual(@as(u32, 0), words[assembly + 8]);
    try std.testing.expect(words[assembly + 8 + 15] != 0);

    words[sparse_indices + 2] = 2;
    words[sparse_indices + 3] = 3;
    words[counts + 4] = 4;
    for (16..32) |index| words[sparse_hashes + index] = @intCast(0x100 + index);
    _ = try runtime.decommitSparseParent(
        arena,
        sparse_indices,
        sparse_hashes,
        counts + 4,
        4,
        parent_indices,
        parent_hashes,
        counts + 5,
        PlainHasher.nodeSeed(),
        PlainHasher.domainPrefixBytes(),
    );
    try std.testing.expectEqual(@as(u32, 2), words[counts + 5]);
    try std.testing.expectEqualSlices(u32, &.{ 0, 1 }, words[parent_indices .. parent_indices + 2]);
    var nonzero = false;
    for (words[parent_hashes .. parent_hashes + 16]) |word| nonzero = nonzero or word != 0;
    try std.testing.expect(nonzero);
}

test "metal: exact Cairo transcript controller binds resident ordinals" {
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    var resident = arena_plan.ResidentArena{ .buffer = try runtime.allocateResidentBuffer(16 * 1024) };
    defer resident.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(resident.buffer.contents));
    const occupied = [_]u64{0} ** (arena_plan.max_ticks / 64);
    const input_ordinals = [_]u32{ 1, 2, 3, 10, 11, 12, 13, 14, 15, 16, 20 };
    const input_lengths = [_]u32{ 4, 8, 8, 4, 4, 4, 4, 4, 8, 8, 8 };
    var inputs: [input_ordinals.len]protocol_recipes.TranscriptBinding = undefined;
    var next: u32 = 64;
    var channel = blake2s_channel.Blake2sChannel{};
    for (input_ordinals, input_lengths, &inputs) |binding_ordinal, length, *input| {
        for (0..length) |index| words[next + index] = @intCast(1 + binding_ordinal * 19 + index);
        channel.mixU32s(words[next .. next + length]);
        input.* = .{
            .ordinal = binding_ordinal,
            .binding = .{
                .logical_id = binding_ordinal,
                .slot = binding_ordinal,
                .offset_bytes = @as(u64, next) * 4,
                .size_bytes = @as(u64, length) * 4,
                .materialization = .resident,
                .occupied = occupied,
            },
        };
        next += length;
    }
    const state = arena_plan.Binding{
        .logical_id = 1000,
        .slot = 1000,
        .offset_bytes = 0,
        .size_bytes = 64,
        .materialization = .resident,
        .occupied = occupied,
    };
    const dummy_output = protocol_recipes.TranscriptBinding{
        .ordinal = 1,
        .binding = .{
            .logical_id = 1001,
            .slot = 1001,
            .offset_bytes = 1024,
            .size_bytes = 32,
            .materialization = .resident,
            .occupied = occupied,
        },
    };
    var recipe = try protocol_recipes.TranscriptRecipe.init(
        std.testing.allocator,
        &runtime,
        &resident,
        state,
        24,
        &inputs,
        &.{dummy_output},
    );
    defer recipe.deinit();
    try recipe.initialize();
    try recipe.bootstrapThroughBase();
    try std.testing.expectEqualSlices(u8, &channel.digest, std.mem.sliceAsBytes(words[0..8]));
    try std.testing.expectEqual(@as(u32, 0), words[8]);
}

test "metal: prepared fixed-table lookup batch matches scalar materialization" {
    var runtime = try metal.Runtime.initFull();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(32 * 1024);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    const rows: u32 = 64;
    const source_offsets = [_]u32{128};
    const multiplicity_offsets = [_]u32{ 256, 320, 384, 448 };
    const destination_offset: u32 = 1024;
    for (words[128 .. 128 + rows], 0..) |*value, row| value.* = @intCast(row * 7 + 3);
    for (multiplicity_offsets, 0..) |offset, column| {
        for (words[offset .. offset + rows], 0..) |*value, row| value.* = @intCast(column * 1000 + row);
    }
    const descriptors = [_]u32{
        0, 123, 0, 0,
        1, 0,   0, 0,
        2, 2,   0, 0,
        3, 3,   3, 1,
        4, 3,   3, 1,
        5, 3,   3, 1,
    };
    var fixed = try runtime.prepareFixedTable(&descriptors, &source_offsets, &multiplicity_offsets, destination_offset, rows);
    defer fixed.deinit();
    var batch = try runtime.prepareFixedTableBatch(&.{fixed});
    defer batch.deinit();
    _ = try runtime.fixedTableBatchPrepared(arena, batch);
    for (0..descriptors.len / 4) |output| for (0..rows) |row| {
        const descriptor = descriptors[output * 4 ..][0..4];
        const expected: u32 = switch (descriptor[0]) {
            0 => descriptor[1],
            1 => words[source_offsets[descriptor[1]] + row],
            2 => words[multiplicity_offsets[descriptor[1]] + row],
            3, 4, 5 => blk: {
                const column = descriptor[1];
                const a = ((column >> 1) << 3) | (@as(u32, @intCast(row)) >> 3);
                const b = ((column & 1) << 3) | (@as(u32, @intCast(row)) & 7);
                break :blk if (descriptor[0] == 3) a else if (descriptor[0] == 4) b else a ^ b;
            },
            else => unreachable,
        };
        try std.testing.expectEqual(expected, words[destination_offset + output * rows + row]);
    };
}
