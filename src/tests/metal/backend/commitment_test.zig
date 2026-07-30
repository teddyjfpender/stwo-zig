const std = @import("std");
const metal = @import("stwo_metal_backend").runtime;
const m31 = @import("stwo_core").fields.m31;
const blake2_merkle = @import("stwo_core").vcs_lifted.blake2_merkle;
const blake2_hash = @import("stwo_core").vcs.blake2_hash;
const merkle_prover = @import("stwo_prover_engine").vcs_lifted.prover;
const pcs_core = @import("stwo_core").pcs;
const MetalProverEngine = @import("stwo_metal_backend").prover_engine.MetalProverEngine;
const canonic = @import("stwo_core").poly.circle.canonic;
const circle_poly = @import("stwo_prover_engine").poly.circle.poly;
const twiddles = @import("stwo_prover_engine").poly.twiddles;
const core_fri = @import("stwo_core").fri;
const qm31 = @import("stwo_core").fields.qm31;
const line = @import("stwo_core").poly.line;
const prover_line = @import("stwo_prover_engine").line;
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
const secure_column = @import("stwo_prover_engine").secure_column;
const secure_circle_poly = @import("stwo_prover_engine").poly.circle.secure_poly;
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

test "metal: prepared sparse Merkle parent chain matches CPU" {
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(32 * 1024);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    const child_offset: u32 = 0;
    const middle_offset: u32 = 256;
    const root_offset: u32 = 512;
    var children: [16]Hasher.Hash = undefined;
    for (&children, 0..) |*hash, child| {
        for (hash, 0..) |*byte, index| byte.* = @intCast((child * 37 + index * 13 + 11) & 0xff);
    }
    @memcpy(std.mem.sliceAsBytes(words[child_offset .. child_offset + 16 * 8]), std.mem.sliceAsBytes(&children));
    var middle: [8]Hasher.Hash = undefined;
    for (&middle, 0..) |*hash, index| hash.* = Hasher.hashChildrenWithSeed(Hasher.nodeSeed(), .{ .left = children[index * 2], .right = children[index * 2 + 1] });
    var roots: [4]Hasher.Hash = undefined;
    for (&roots, 0..) |*hash, index| hash.* = Hasher.hashChildrenWithSeed(Hasher.nodeSeed(), .{ .left = middle[index * 2], .right = middle[index * 2 + 1] });
    var plan = try runtime.prepareMerkleParentChain(&.{ child_offset, middle_offset }, &.{ middle_offset, root_offset }, &.{ 8, 4 }, Hasher.nodeSeed(), Hasher.domainPrefixBytes());
    defer plan.deinit();
    _ = try runtime.merkleParentChainPrepared(arena, plan);
    try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(&middle), std.mem.sliceAsBytes(words[middle_offset .. middle_offset + 8 * 8]));
    try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(&roots), std.mem.sliceAsBytes(words[root_offset .. root_offset + 4 * 8]));
}

test "metal: prepared relation graph matches scalar logup" {
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(64 * 1024);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    const rows: u32 = 256;
    const source_offset: u32 = 0;
    const output_offsets = [_]u32{ 1024, 2048, 3072, 4096 };
    const alpha_offset: u32 = 5120;
    const z_offset: u32 = 5140;
    const scratch_offset: u32 = 5160;
    const claimed_offset: u32 = 5180;
    for (words[source_offset + rows .. source_offset + 2 * rows], 0..) |*value, row| value.* = @intCast(row + 1);
    const alphas = [_]QM31{
        QM31.fromU32Unchecked(3, 0, 0, 0),
        QM31.fromU32Unchecked(5, 0, 0, 0),
    };
    const z = QM31.fromU32Unchecked(7, 0, 0, 0);
    for (alphas, 0..) |alpha, index| {
        const coordinates = alpha.toM31Array();
        for (coordinates, 0..) |coordinate, coordinate_index| words[alpha_offset + index * 4 + coordinate_index] = coordinate.v;
    }
    for (z.toM31Array(), 0..) |coordinate, index| words[z_offset + index] = coordinate.v;
    const descriptor = [_]u32{
        1,
        0,
        0,
        2,
        11,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    };
    const geometry = [_]u32{
        0, 1, rows, 1, rows, 0, 0, 0, 0, claimed_offset,
    };
    var plan = try runtime.prepareRelation(
        &geometry,
        &.{source_offset},
        &descriptor,
        &output_offsets,
        1,
        alpha_offset,
        z_offset,
        scratch_offset,
    );
    defer plan.deinit();
    _ = try runtime.relationPrepared(arena, plan);
    var fractions: [rows]QM31 = undefined;
    var total = QM31.zero();
    for (&fractions, 0..) |*fraction, row| {
        const denominator = alphas[0].mulM31(M31.fromCanonical(11))
            .add(alphas[1].mulM31(M31.fromCanonical(@intCast(row + 1))))
            .sub(z);
        fraction.* = try denominator.inv();
        total = total.add(fraction.*);
    }
    const shift = total.mulM31(try M31.fromCanonical(rows).inv());
    var accumulated = QM31.zero();
    var expected: [rows]QM31 = undefined;
    for (0..rows) |scan_index| {
        const circle_index = if ((scan_index & 1) == 0) scan_index / 2 else rows - 1 - scan_index / 2;
        const row = @bitReverse(@as(u32, @intCast(circle_index))) >> (32 - @ctz(rows));
        accumulated = accumulated.add(fractions[row].sub(shift));
        expected[row] = accumulated;
    }
    for (expected, 0..) |value, row| {
        const coordinates = value.toM31Array();
        for (coordinates, output_offsets) |coordinate, offset| try std.testing.expectEqual(coordinate.v, words[offset + row]);
    }
    for (total.toM31Array(), 0..) |coordinate, index| try std.testing.expectEqual(coordinate.v, words[claimed_offset + index]);
}

test "metal: resident lifted Merkle root matches CPU" {
    const allocator = std.testing.allocator;
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();

    const log_sizes = [_]u32{ 10, 9, 10, 8, 9, 10, 7, 10, 8, 10, 9, 10, 6, 10, 9, 10, 8 };
    var owned: [log_sizes.len][]M31 = undefined;
    var initialized: usize = 0;
    defer {
        for (owned[0..initialized]) |column| allocator.free(column);
    }
    var cpu_columns: [log_sizes.len][]const M31 = undefined;
    var gpu_columns: [log_sizes.len][]const u32 = undefined;
    for (log_sizes, 0..) |log_size, column_index| {
        const column = try allocator.alloc(M31, @as(usize, 1) << @intCast(log_size));
        owned[column_index] = column;
        initialized += 1;
        for (column, 0..) |*value, row| {
            value.* = M31.fromCanonical(@intCast((column_index * 7919 + row * 104729 + 17) % m31.Modulus));
        }
        cpu_columns[column_index] = column;
        gpu_columns[column_index] = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(column));
    }

    const CpuTree = merkle_prover.MerkleProverLifted(Hasher);
    var cpu_tree = try CpuTree.commit(allocator, &cpu_columns);
    defer cpu_tree.deinit(allocator);

    var gpu_tree = try runtime.commitColumns(
        allocator,
        &gpu_columns,
        &log_sizes,
        10,
        Hasher.leafSeed(),
        Hasher.nodeSeed(),
        Hasher.domainPrefixBytes(),
    );
    defer gpu_tree.deinit();
    const result = try gpu_tree.root();

    try std.testing.expectEqualSlices(u8, &cpu_tree.root(), &result.hash);
    try std.testing.expect(result.gpu_ms > 0);

    const duplicate_leaves = [_]u32{ 3, 3, 1023 };
    const empty_indices = [_]u32{};
    const duplicate_root = [_]u32{ 0, 0 };
    const batch_requests = [_]struct {
        layer_log_size: u32,
        indices: []const u32,
    }{
        .{ .layer_log_size = 10, .indices = &duplicate_leaves },
        .{ .layer_log_size = 7, .indices = &empty_indices },
        .{ .layer_log_size = 0, .indices = &duplicate_root },
    };
    const batched_hashes = try gpu_tree.copyHashesBatch(allocator, &batch_requests);
    defer {
        for (batched_hashes) |hashes| allocator.free(hashes);
        allocator.free(batched_hashes);
    }
    try std.testing.expectEqual(@as(usize, 3), batched_hashes.len);
    for (batch_requests, batched_hashes) |request, hashes| {
        const individual = try gpu_tree.copyHashes(allocator, request.layer_log_size, request.indices);
        defer allocator.free(individual);
        try std.testing.expectEqualSlices([32]u8, individual, hashes);
    }
    const invalid_layer = [_]struct {
        layer_log_size: u32,
        indices: []const u32,
    }{.{ .layer_log_size = 11, .indices = &duplicate_root }};
    try std.testing.expectError(error.RootReadFailed, gpu_tree.copyHashesBatch(allocator, &invalid_layer));
    const invalid_shift = [_]struct {
        layer_log_size: u32,
        indices: []const u32,
    }{.{ .layer_log_size = 31, .indices = &duplicate_root }};
    try std.testing.expectError(error.RootReadFailed, gpu_tree.copyHashesBatch(allocator, &invalid_shift));
    const invalid_leaf = [_]u32{1024};
    const invalid_index = [_]struct {
        layer_log_size: u32,
        indices: []const u32,
    }{.{ .layer_log_size = 10, .indices = &invalid_leaf }};
    try std.testing.expectError(error.RootReadFailed, gpu_tree.copyHashesBatch(allocator, &invalid_index));

    const MetalTree = @import("stwo_metal_backend").merkle_tree.MetalMerkleTree(Hasher);
    var compatible_tree = try MetalTree.commit(&runtime, allocator, &cpu_columns);
    defer compatible_tree.deinit(allocator);
    try std.testing.expectEqualSlices(u8, &cpu_tree.root(), &compatible_tree.root());

    const query_positions = [_]usize{ 3, 255, 510 };
    var cpu_decommitment = try cpu_tree.decommit(allocator, &query_positions, &cpu_columns);
    defer cpu_decommitment.deinit(allocator);
    var metal_decommitment = try compatible_tree.decommit(allocator, &query_positions, &cpu_columns);
    defer metal_decommitment.deinit(allocator);

    for (cpu_decommitment.queried_values, metal_decommitment.queried_values) |cpu_values, metal_values| {
        try std.testing.expectEqualSlices(M31, cpu_values, metal_values);
    }
    const cpu_witness = cpu_decommitment.decommitment.decommitment.hash_witness;
    const metal_witness = metal_decommitment.decommitment.decommitment.hash_witness;
    try std.testing.expectEqual(cpu_witness.len, metal_witness.len);
    for (cpu_witness, metal_witness) |cpu_hash, metal_hash| {
        try std.testing.expectEqualSlices(u8, &cpu_hash, &metal_hash);
    }

    const cpu_layers = cpu_decommitment.decommitment.aux.all_node_values;
    const metal_layers = metal_decommitment.decommitment.aux.all_node_values;
    try std.testing.expectEqual(cpu_layers.len, metal_layers.len);
    for (cpu_layers, metal_layers) |cpu_layer, metal_layer| {
        try std.testing.expectEqual(cpu_layer.len, metal_layer.len);
        for (cpu_layer, metal_layer) |cpu_node, metal_node| {
            try std.testing.expectEqual(cpu_node.index, metal_node.index);
            try std.testing.expectEqualSlices(u8, &cpu_node.hash, &metal_node.hash);
        }
    }
}

test "metal: incremental leaf absorption matches monolithic lifted leaves" {
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    const lifting_log: u32 = 6;
    const rows: u32 = 1 << lifting_log;
    var arena = try runtime.allocateResidentBuffer(32768);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    var offsets: [20]u32 = undefined;
    var logs: [20]u32 = undefined;
    var cursor: u32 = 0;
    for (&offsets, &logs, 0..) |*offset, *log_size, column| {
        log_size.* = if (column < 16) 5 else 6;
        offset.* = cursor;
        const length = @as(u32, 1) << @intCast(log_size.*);
        for (words[cursor .. cursor + length], 0..) |*value, row| value.* = @intCast((column * 313 + row * 17 + 9) % m31.Modulus);
        cursor += length;
    }
    const monolithic: u32 = 4096;
    const incremental: u32 = monolithic + rows * 8;
    var leaves = try runtime.prepareMerkleLeaves(&offsets, &logs, lifting_log, monolithic, Hasher.leafSeed(), Hasher.domainPrefixBytes());
    defer leaves.deinit();
    _ = try runtime.merkleLeavesPrepared(arena, leaves);
    _ = try runtime.leafAbsorb(arena, offsets[0..16], logs[0..16], incremental, lifting_log, 0, false, Hasher.domainPrefixBytes(), Hasher.leafSeed());
    _ = try runtime.leafAbsorb(arena, offsets[16..20], logs[16..20], incremental, lifting_log, 16, true, Hasher.domainPrefixBytes(), Hasher.leafSeed());
    try std.testing.expectEqualSlices(u32, words[monolithic .. monolithic + rows * 8], words[incremental .. incremental + rows * 8]);
}

test "metal: compact leaf absorption expands mixed logs and preserves the Merkle root" {
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    const lifting_log: u32 = 8;
    const rows: u32 = 1 << lifting_log;
    var arena = try runtime.allocateResidentBuffer(128 * 1024);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    var offsets: [24]u32 = undefined;
    var logs: [24]u32 = undefined;
    var cursor: u32 = 0;
    for (&offsets, &logs, 0..) |*offset, *log_size, column| {
        log_size.* = if (column < 8)
            (if (column % 2 == 0) 4 else 5)
        else if (column < 16)
            (if (column % 2 == 0) 5 else 7)
        else
            (if (column % 2 == 0) 7 else 8);
        offset.* = cursor;
        const length = @as(u32, 1) << @intCast(log_size.*);
        for (words[cursor .. cursor + length], 0..) |*value, row|
            value.* = @intCast((column * 313 + row * 17 + 9) % m31.Modulus);
        cursor += length;
    }
    const full_state: u32 = 8192;
    const compact_state: u32 = full_state + rows * 8;
    const snapshot: u32 = compact_state + rows * 8;
    _ = try runtime.leafAbsorb(arena, offsets[0..8], logs[0..8], full_state, lifting_log, 0, false, Hasher.domainPrefixBytes(), Hasher.leafSeed());
    _ = try runtime.leafAbsorb(arena, offsets[8..16], logs[8..16], full_state, lifting_log, 8, false, Hasher.domainPrefixBytes(), Hasher.leafSeed());
    _ = try runtime.leafAbsorb(arena, offsets[16..24], logs[16..24], full_state, lifting_log, 16, true, Hasher.domainPrefixBytes(), Hasher.leafSeed());

    _ = try runtime.leafAbsorbCompact(arena, offsets[0..8], logs[0..8], compact_state, 5, compact_state, 5, 0, false, Hasher.domainPrefixBytes(), Hasher.leafSeed());
    {
        var copy = try runtime.prepareArenaCopies(&.{.{
            .source_word_offset = compact_state,
            .destination_word_offset = snapshot,
            .word_count = (1 << 5) * 8,
        }});
        defer copy.deinit();
        _ = try runtime.arenaCopyPrepared(arena, copy);
    }
    _ = try runtime.leafAbsorbCompact(arena, offsets[8..16], logs[8..16], snapshot, 5, compact_state, 7, 8, false, Hasher.domainPrefixBytes(), Hasher.leafSeed());
    {
        var copy = try runtime.prepareArenaCopies(&.{.{
            .source_word_offset = compact_state,
            .destination_word_offset = snapshot,
            .word_count = (1 << 7) * 8,
        }});
        defer copy.deinit();
        _ = try runtime.arenaCopyPrepared(arena, copy);
    }
    _ = try runtime.leafAbsorbCompact(arena, offsets[16..24], logs[16..24], snapshot, 7, compact_state, lifting_log, 16, true, Hasher.domainPrefixBytes(), Hasher.leafSeed());
    try std.testing.expectEqualSlices(u32, words[full_state .. full_state + rows * 8], words[compact_state .. compact_state + rows * 8]);

    var full_children: [8]u32 = undefined;
    var full_destinations: [8]u32 = undefined;
    var compact_children: [8]u32 = undefined;
    var compact_destinations: [8]u32 = undefined;
    var parent_counts: [8]u32 = undefined;
    var full_parent_cursor: u32 = 16384;
    var compact_parent_cursor: u32 = 20480;
    var parent_count = rows / 2;
    for (0..8) |level| {
        full_children[level] = if (level == 0) full_state else full_destinations[level - 1];
        compact_children[level] = if (level == 0) compact_state else compact_destinations[level - 1];
        full_destinations[level] = full_parent_cursor;
        compact_destinations[level] = compact_parent_cursor;
        parent_counts[level] = parent_count;
        full_parent_cursor += parent_count * 8;
        compact_parent_cursor += parent_count * 8;
        parent_count /= 2;
    }
    var full_chain = try runtime.prepareMerkleParentChain(&full_children, &full_destinations, &parent_counts, Hasher.nodeSeed(), Hasher.domainPrefixBytes());
    defer full_chain.deinit();
    var compact_chain = try runtime.prepareMerkleParentChain(&compact_children, &compact_destinations, &parent_counts, Hasher.nodeSeed(), Hasher.domainPrefixBytes());
    defer compact_chain.deinit();
    _ = try runtime.merkleParentChainPrepared(arena, full_chain);
    _ = try runtime.merkleParentChainPrepared(arena, compact_chain);
    try std.testing.expectEqualSlices(u32, words[full_destinations[7] .. full_destinations[7] + 8], words[compact_destinations[7] .. compact_destinations[7] + 8]);
}

test "metal: compact leaf absorption expands a partial final group to the full domain" {
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    const lifting_log: u32 = 8;
    const rows: u32 = 1 << lifting_log;
    var arena = try runtime.allocateResidentBuffer(64 * 1024);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    var offsets: [16]u32 = undefined;
    var logs: [16]u32 = undefined;
    var cursor: u32 = 0;
    for (&offsets, &logs, 0..) |*offset, *log_size, column| {
        log_size.* = if (column < 8)
            (if (column % 2 == 0) 4 else 5)
        else
            (if (column % 2 == 0) 6 else 7);
        offset.* = cursor;
        const length = @as(u32, 1) << @intCast(log_size.*);
        for (words[cursor .. cursor + length], 0..) |*value, row|
            value.* = @intCast((column * 199 + row * 29 + 3) % m31.Modulus);
        cursor += length;
    }
    const full_state: u32 = 4096;
    const compact_state: u32 = full_state + rows * 8;
    const snapshot: u32 = compact_state + rows * 8;
    _ = try runtime.leafAbsorb(arena, offsets[0..8], logs[0..8], full_state, lifting_log, 0, false, Hasher.domainPrefixBytes(), Hasher.leafSeed());
    _ = try runtime.leafAbsorb(arena, offsets[8..16], logs[8..16], full_state, lifting_log, 8, true, Hasher.domainPrefixBytes(), Hasher.leafSeed());
    _ = try runtime.leafAbsorbCompact(arena, offsets[0..8], logs[0..8], compact_state, 5, compact_state, 5, 0, false, Hasher.domainPrefixBytes(), Hasher.leafSeed());
    var copy = try runtime.prepareArenaCopies(&.{.{
        .source_word_offset = compact_state,
        .destination_word_offset = snapshot,
        .word_count = (1 << 5) * 8,
    }});
    defer copy.deinit();
    _ = try runtime.arenaCopyPrepared(arena, copy);
    _ = try runtime.leafAbsorbCompact(arena, offsets[8..16], logs[8..16], snapshot, 5, compact_state, lifting_log, 8, true, Hasher.domainPrefixBytes(), Hasher.leafSeed());
    try std.testing.expectEqualSlices(u32, words[full_state .. full_state + rows * 8], words[compact_state .. compact_state + rows * 8]);
}

test "metal: batched decommit FRI round matches three legacy submissions" {
    var runtime = try metal.Runtime.init();
    defer runtime.deinit();
    const arena_words: usize = 65536;
    var legacy = try runtime.allocateResidentBuffer(arena_words * @sizeOf(u32));
    defer legacy.deinit();
    var batched = try runtime.allocateResidentBuffer(arena_words * @sizeOf(u32));
    defer batched.deinit();

    const unique_base: u64 = 64;
    const tree_queries_base: u64 = 256;
    const expanded_base: u64 = 512;
    const walk_base: u64 = 1200;
    const count_base: u64 = 2000;
    const coordinate_bases: u64 = 2100;
    const values_base: u64 = 3000;
    const walk_scratch_base: u64 = 5500;
    const retained_offsets: u64 = 6200;
    const assembly_base: u64 = 8000;
    const assembly_capacity: u32 = 30000;
    const leaf_log: u32 = 4;
    const max_positions: u32 = 560;

    const Fixture = struct {
        fn populate(buffer: metal.ResidentBuffer) void {
            const words: [*]u32 = @ptrCast(@alignCast(buffer.contents));
            @memset(words[0..arena_words], 0);
            const queries = [_]u32{ 0, 1, 5, 6, 17, 31 };
            @memcpy(words[unique_base .. unique_base + queries.len], &queries);
            words[count_base] = queries.len;

            const coordinate_sources = [_]u32{ 2200, 2300, 2400, 2500 };
            for (coordinate_sources, 0..) |source, coordinate| {
                words[coordinate_bases + 2 * coordinate] = source;
                words[coordinate_bases + 2 * coordinate + 1] = 0;
                for (0..64) |row| words[source + row] = @intCast(1000 * coordinate + 17 * row + 3);
            }

            var retained_cursor: u32 = 6400;
            for (0..leaf_log + 1) |level| {
                words[retained_offsets + 2 * level] = retained_cursor;
                words[retained_offsets + 2 * level + 1] = 0;
                const hashes = @as(u32, 1) << @intCast(level);
                for (0..hashes * 8) |word| words[retained_cursor + word] =
                    @intCast(0x10000 + level * 0x1000 + word);
                retained_cursor += hashes * 8;
            }

            words[assembly_base] = 0x4457_5453;
            words[assembly_base + 1] = 1;
            words[assembly_base + 2] = 1;
            words[assembly_base + 7] = 24;
        }
    };
    Fixture.populate(legacy);
    Fixture.populate(batched);

    const legacy_gpu_ms =
        try runtime.decommitPrepareFriQueries(
            legacy,
            unique_base,
            count_base,
            70,
            0,
            2,
            2,
            tree_queries_base,
            count_base + 1,
            expanded_base,
            count_base + 3,
            walk_base,
            count_base + 2,
        ) +
        try runtime.decommitGatherFriValues(
            legacy,
            coordinate_bases,
            expanded_base,
            count_base + 3,
            max_positions,
            values_base,
        ) +
        try runtime.decommitAssembleFri(
            legacy,
            0,
            leaf_log,
            tree_queries_base,
            count_base + 1,
            expanded_base,
            count_base + 3,
            values_base,
            walk_base,
            walk_scratch_base,
            count_base + 2,
            retained_offsets,
            assembly_base,
            assembly_capacity,
        );

    const batched_gpu_ms = try runtime.decommitFriRound(batched, .{
        .unique_base = unique_base,
        .unique_count_base = count_base,
        .tree_queries_base = tree_queries_base,
        .tree_count_base = count_base + 1,
        .expanded_base = expanded_base,
        .expanded_count_base = count_base + 3,
        .walk_base = walk_base,
        .walk_count_base = count_base + 2,
        .coordinate_bases = coordinate_bases,
        .values_base = values_base,
        .walk_scratch_base = walk_scratch_base,
        .retained_offsets = retained_offsets,
        .assembly_base = assembly_base,
        .max_queries = 70,
        .cumulative_fold = 0,
        .fold_step = 2,
        .packed_log = 2,
        .max_positions = max_positions,
        .tree_index = 0,
        .leaf_log = leaf_log,
        .assembly_capacity = assembly_capacity,
    });
    try std.testing.expect(legacy_gpu_ms > 0);
    try std.testing.expect(batched_gpu_ms > 0);
    const legacy_words: [*]const u32 = @ptrCast(@alignCast(legacy.contents));
    const batched_words: [*]const u32 = @ptrCast(@alignCast(batched.contents));
    try std.testing.expectEqualSlices(u32, legacy_words[0..arena_words], batched_words[0..arena_words]);
}
