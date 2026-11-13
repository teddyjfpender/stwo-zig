//! Shared fixtures and independent relation oracles for this test owner.
//! FRI fold-to-next-tree transaction parity and submission accounting.

const std = @import("std");
const runtime_mod = @import("../runtime.zig");
const MetalBackend = @import("../commit_backend.zig").MetalCommitBackend;
const core_fri = @import("stwo_core").fri;
const core_utils = @import("stwo_core").utils;
const fields = @import("stwo_core").fields;
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const circle = @import("stwo_core").circle;
const line = @import("stwo_core").poly.line;
const canonic = @import("stwo_core").poly.circle.canonic;
const queries_mod = @import("stwo_core").queries;
const secure_column = @import("stwo_prover_engine").secure_column;
const prover_fri = @import("stwo_prover_engine").fri;
const merkle_prover = @import("stwo_prover_engine").vcs_lifted.prover;
const blake2_merkle = @import("stwo_core").vcs_lifted.blake2_merkle;
const channel_blake2s = @import("stwo_core").channel.blake2s;

const M31 = m31.M31;
const QM31 = qm31.QM31;
const MerkleChannel = blake2_merkle.Blake2sMerkleChannel;

pub fn checkLineCascade(comptime blake3: bool, comptime H: type, comptime MC: type, comptime C: type, comptime source_log: u32) !void {
    const params = comptime @import("../hash_domain.zig").directParameters(H).?;
    const cascade = if (blake3) runtime_mod.Runtime.foldBlake3FriLineCascadeWithReceipt else runtime_mod.Runtime.foldFriLineCascadeWithReceipt;
    const allocator = std.testing.allocator;
    var runtime = try runtime_mod.Runtime.init();
    defer runtime.deinit();

    const final_log: u32 = 1;
    const layer_count: usize = source_log - final_log;
    const source_count: usize = @as(usize, 1) << source_log;
    const final_count: usize = @as(usize, 1) << final_log;
    const domain = try line.LineDomain.init(circle.Coset.halfOdds(source_log));

    const source_values = try allocator.alloc(QM31, source_count);
    defer allocator.free(source_values);
    for (source_values, 0..) |*value, index| {
        value.* = QM31.fromU32Unchecked(
            @intCast((index * 17 + 3) % m31.Modulus),
            @intCast((index * 29 + 5) % m31.Modulus),
            @intCast((index * 43 + 7) % m31.Modulus),
            @intCast((index * 61 + 11) % m31.Modulus),
        );
    }

    var initial_channel = C{};
    initial_channel.mixU32s(&.{ 0x1234_5678, 0x9abc_def0, 0x55aa_00ff });
    _ = initial_channel.drawSecureFelt();
    var expected_channel = initial_channel;

    const expected_roots = try allocator.alloc(H.Hash, layer_count);
    defer allocator.free(expected_roots);
    var fold_workspace = try core_fri.FoldLineWorkspace.init(allocator, source_count / 2);
    defer fold_workspace.deinit(allocator);
    var expected_values = try allocator.dupe(QM31, source_values);
    defer allocator.free(expected_values);
    var expected_domain = domain;
    for (expected_roots) |*root| {
        var expected_coordinates = try secure_column.SecureColumnByCoords.fromSecureSlice(
            allocator,
            expected_values,
        );
        defer expected_coordinates.deinit(allocator);
        const expected_columns = [_][]const M31{
            expected_coordinates.columns[0],
            expected_coordinates.columns[1],
            expected_coordinates.columns[2],
            expected_coordinates.columns[3],
        };
        var expected_tree = try merkle_prover.MerkleProverLifted(H).commit(
            allocator,
            &expected_columns,
        );
        defer expected_tree.deinit(allocator);
        root.* = expected_tree.root();
        MC.mixRoot(&expected_channel, root.*);
        const alpha = expected_channel.drawSecureFelt();

        const destination_count = expected_values.len / 2;
        const x = fold_workspace.x_values[0..destination_count];
        const inverse_x = fold_workspace.inv_x_values[0..destination_count];
        for (x, 0..) |*value, index| {
            value.* = expected_domain.at(core_utils.bitReverseIndex(index << 1, expected_domain.logSize()));
        }
        try fields.batchInverseInPlace(M31, x, inverse_x);
        const folded = try core_fri.foldLineNWithWorkspace(
            allocator,
            expected_values,
            expected_domain,
            alpha,
            &fold_workspace,
            1,
        );
        allocator.free(expected_values);
        expected_values = folded.values;
        expected_domain = folded.domain;
    }

    // Exercise the actual backend boundary as well as the lower-level runtime.
    // Its channel serialization and tree ownership are separate obligations.
    var backend_source = try MetalBackend.allocateLineEvaluation(domain);
    defer backend_source.deinit(allocator);
    @memcpy(@constCast(backend_source.values), source_values);
    var backend_channel = initial_channel;
    var backend_result = (try MetalBackend.commitFriLineCascade(
        H,
        allocator,
        backend_source,
        &backend_channel,
        &fold_workspace,
        final_count,
        1,
        null,
        null,
    )) orelse return error.MissingBackendCascade;
    defer backend_result.deinit(allocator);
    for (backend_result.trees, expected_roots) |tree, root| {
        try std.testing.expectEqualSlices(u8, &root, &tree.root());
    }
    try std.testing.expectEqualSlices(u8, &expected_channel.digest, &backend_channel.digest);
    try std.testing.expectEqual(expected_channel.n_draws, backend_channel.n_draws);
    try std.testing.expectEqualSlices(QM31, expected_values, backend_result.last_layer_evaluation.values);

    var source = try runtime.allocateResidentBuffer(source_count * @sizeOf(QM31));
    defer source.deinit();
    const resident_source: [*]QM31 = @ptrCast(@alignCast(source.contents));
    @memcpy(resident_source[0..source_count], source_values);

    const coordinate_buffers = try allocator.alloc(runtime_mod.ResidentBuffer, layer_count);
    defer allocator.free(coordinate_buffers);
    var initialized_coordinates: usize = 0;
    defer for (coordinate_buffers[0..initialized_coordinates]) |*buffer| buffer.deinit();
    const coordinate_handles = try allocator.alloc(*anyopaque, layer_count);
    defer allocator.free(coordinate_handles);
    var current_count = source_count;
    for (coordinate_buffers, coordinate_handles) |*buffer, *handle| {
        buffer.* = try runtime.allocateResidentBuffer(current_count * 4 * @sizeOf(M31));
        initialized_coordinates += 1;
        handle.* = buffer.handle;
        current_count >>= 1;
    }
    var final_destination = try runtime.allocateResidentBuffer(final_count * @sizeOf(QM31));
    defer final_destination.deinit();

    var channel_state = [_]u32{0} ** (if (blake3) 11 else 10);
    for (0..8) |word| {
        channel_state[word] = std.mem.readInt(
            u32,
            initial_channel.digest[word * 4 ..][0..4],
            .little,
        );
    }
    channel_state[8] = @truncate(initial_channel.n_draws);
    const domain_coset = domain.coset();
    const result = try cascade(
        &runtime,
        allocator,
        source.handle,
        source_count,
        null,
        @intCast(domain_coset.initial_index.v),
        @intCast(domain_coset.step_size.v),
        coordinate_handles,
        final_destination.handle,
        params.leaf_seed,
        params.node_seed,
        params.domain_prefix_bytes,
        &channel_state,
    );
    defer {
        for (result.trees) |*tree| tree.deinit();
        allocator.free(result.trees);
    }

    try std.testing.expectEqual(@as(u64, 1), result.stats.command_buffers);
    try std.testing.expectEqual(@as(u64, 1), result.stats.wait_count);
    try std.testing.expectEqual(@as(u64, 1), result.stats.compute_encoders);
    if (source_log == 10) try std.testing.expectEqual(
        @as(u64, 20) + @as(u64, @intCast(layer_count)),
        result.stats.dispatches,
    );
    try std.testing.expectEqual(@as(u32, 2), result.inverse_generation_mask);
    for (result.trees, expected_roots) |tree, expected_root| {
        const actual_root = try tree.root();
        try std.testing.expectEqualSlices(u8, &expected_root, &actual_root.hash);
    }
    const actual_final: [*]QM31 = @ptrCast(@alignCast(final_destination.contents));
    try std.testing.expectEqualSlices(QM31, expected_values, actual_final[0..final_count]);
    for (0..8) |word| {
        try std.testing.expectEqual(
            std.mem.readInt(u32, expected_channel.digest[word * 4 ..][0..4], .little),
            channel_state[word],
        );
    }
    const actual_draws: u64 = @as(u64, channel_state[8]) | (if (blake3) @as(u64, channel_state[9]) << 32 else 0);
    try std.testing.expectEqual(@as(u64, expected_channel.n_draws), actual_draws);
    try std.testing.expectEqual(@as(u32, 0), channel_state[if (blake3) 10 else 9]);

    var repeat_channel_state = [_]u32{0} ** (if (blake3) 11 else 10);
    for (0..8) |word| {
        repeat_channel_state[word] = std.mem.readInt(
            u32,
            initial_channel.digest[word * 4 ..][0..4],
            .little,
        );
    }
    repeat_channel_state[8] = @truncate(initial_channel.n_draws);
    const repeat_result = try cascade(
        &runtime,
        allocator,
        source.handle,
        source_count,
        null,
        @intCast(domain_coset.initial_index.v),
        @intCast(domain_coset.step_size.v),
        coordinate_handles,
        final_destination.handle,
        params.leaf_seed,
        params.node_seed,
        params.domain_prefix_bytes,
        &repeat_channel_state,
    );
    defer {
        for (repeat_result.trees) |*tree| tree.deinit();
        allocator.free(repeat_result.trees);
    }
    // Ordinary unbudgeted calls own transient inverse buffers. A second call
    // regenerates them; cache hits require the separate shared-budget API.
    try std.testing.expectEqual(@as(u32, 2), repeat_result.inverse_generation_mask);
    try std.testing.expectEqual(result.stats.dispatches, repeat_result.stats.dispatches);
    for (repeat_result.trees, expected_roots) |tree, expected_root| {
        const actual_root = try tree.root();
        try std.testing.expectEqualSlices(u8, &expected_root, &actual_root.hash);
    }
    try std.testing.expectEqualSlices(QM31, expected_values, actual_final[0..final_count]);
    try std.testing.expectEqualSlices(u32, &channel_state, &repeat_channel_state);
}

pub const CpuFriReference = struct {
    pub fn MerkleTree(comptime H: type) type {
        return merkle_prover.MerkleProverLifted(H);
    }
    pub fn commitMerkle(comptime H: type, allocator: std.mem.Allocator, columns: []const []const M31) !MerkleTree(H) {
        return MerkleTree(H).commit(allocator, columns);
    }
};

pub fn checkCircleFri(comptime lazy: bool, comptime blake3: bool) !void {
    const allocator = std.testing.allocator;
    const b3 = if (blake3) @import("stwo_core").vcs_lifted.blake3_merkle else struct {
        pub const MerkleHasher = blake2_merkle.Blake2sMerkleHasher;
        pub const MerkleChannel = blake2_merkle.Blake2sMerkleChannel;
    };
    const C = if (blake3) @import("stwo_core").channel.blake3.Channel else channel_blake2s.Blake2sChannel;
    const Gpu = prover_fri.FriProver(MetalBackend, b3.MerkleHasher, b3.MerkleChannel);
    const Cpu = prover_fri.FriProver(CpuFriReference, b3.MerkleHasher, b3.MerkleChannel);
    const log_size = 14;
    const domain = canonic.CanonicCoset.new(log_size).circleDomain();
    const values = try allocator.alloc(QM31, domain.size());
    defer allocator.free(values);
    for (values, 0..) |*value, i| {
        const point = domain.at(core_utils.bitReverseIndex(i, log_size));
        value.* = QM31.fromU32Unchecked(point.x.v, point.y.v, point.x.add(point.y).v, 19);
    }
    const quotient_ops = @import("stwo_prover_engine").pcs.quotient_ops;
    const core = @import("stwo_core");
    const raw = try allocator.alloc(M31, domain.size());
    defer allocator.free(raw);
    for (raw, 0..) |*value, i| {
        const x = domain.at(core_utils.bitReverseIndex(i, log_size)).x;
        value.* = x.mul(x).mul(x);
    }
    const point = core.circle.SECURE_FIELD_CIRCLE_GEN.mul(7);
    var column_array = [_]quotient_ops.ColumnEvaluation{.{ .log_size = log_size, .values = raw }};
    var column_tree = [_][]const quotient_ops.ColumnEvaluation{&column_array};
    var points = [_]core.circle.CirclePointQM31{point};
    var point_columns = [_][]core.circle.CirclePointQM31{&points};
    var point_tree = [_][][]core.circle.CirclePointQM31{&point_columns};
    var samples = [_]QM31{point.x.mul(point.x).mul(point.x)};
    var sample_columns = [_][]QM31{&samples};
    var sample_tree = [_][][]QM31{&sample_columns};
    const ct = core.pcs.utils.TreeVec([]const quotient_ops.ColumnEvaluation).initOwned(&column_tree);
    const pt = core.pcs.utils.TreeVec([][]core.circle.CirclePointQM31).initOwned(&point_tree);
    const st = core.pcs.utils.TreeVec([][]QM31).initOwned(&sample_tree);
    const alpha = QM31.fromU32Unchecked(3, 5, 7, 11);
    var provider = try quotient_ops.LazyQuotientProvider.initForBackend(MetalBackend, allocator, ct, pt, st, alpha, log_size);
    defer provider.deinit(allocator);
    if (lazy) {
        var quotient = try quotient_ops.computeFriQuotients(allocator, ct, pt, st, alpha, log_size, 1);
        defer quotient.deinit(allocator);
        for (values, 0..) |*value, i| value.* = QM31.fromU32Unchecked(
            quotient.columns[0][i].v,
            quotient.columns[1][i].v,
            quotient.columns[2][i].v,
            quotient.columns[3][i].v,
        );
    }
    const cpu_column = try secure_column.SecureColumnByCoords.fromSecureSlice(allocator, values);
    const gpu_column = try MetalBackend.allocateSecureColumn(values.len);
    for (values, 0..) |value, i| {
        const words = value.toM31Array();
        for (0..4) |j| @constCast(gpu_column.columns[j])[i] = words[j];
    }
    var cpu_channel = C{};
    var gpu_channel = C{};
    const config = core_fri.FriConfig{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 2,
        .n_queries = 3,
        .fold_step = 1,
    };
    var cpu = try Cpu.commit(allocator, &cpu_channel, config, domain, cpu_column);
    const before = try MetalBackend.telemetrySnapshot();
    var gpu = if (lazy) blk: {
        var unused = gpu_column;
        unused.deinit(allocator);
        break :blk try Gpu.commitLazy(allocator, &gpu_channel, config, domain, &provider);
    } else try Gpu.commit(allocator, &gpu_channel, config, domain, gpu_column);
    const delta = (try MetalBackend.telemetrySnapshot()).delta(before);
    try std.testing.expectEqual(@as(u64, 1), delta.counters.metal_fri_fold_commit_epochs);
    try std.testing.expectEqualSlices(u8, &cpu_channel.digest, &gpu_channel.digest);
    try std.testing.expectEqual(cpu_channel.n_draws, gpu_channel.n_draws);
    try std.testing.expectEqualSlices(u8, &cpu.first_layer.merkle_tree.root(), &gpu.first_layer.merkle_tree.root());
    try std.testing.expectEqual(cpu.inner_layers.len, gpu.inner_layers.len);
    for (cpu.inner_layers, gpu.inner_layers) |expected, actual| {
        try std.testing.expectEqualSlices(u8, &expected.merkle_tree.root(), &actual.merkle_tree.root());
        for (expected.column.columns, actual.column.columns) |e, a| try std.testing.expectEqualSlices(M31, e, a);
    }
    var query_channel = gpu_channel;
    const raw_queries = try queries_mod.drawQueries(&query_channel, allocator, log_size, config.n_queries);
    defer allocator.free(raw_queries);
    var queries = try queries_mod.Queries.init(allocator, raw_queries, log_size);
    defer queries.deinit(allocator);
    var expected = try cpu.decommitOnQueries(allocator, queries);
    defer expected.deinit(allocator);
    var actual = try gpu.decommitOnQueries(allocator, queries);
    defer actual.deinit(allocator);
    try std.testing.expectEqualDeep(expected.proof, actual.proof);
    var verifier_channel = C{};
    var verifier = try core_fri.FriVerifier(b3.MerkleHasher, b3.MerkleChannel).commit(
        allocator,
        &verifier_channel,
        config,
        actual.proof,
        core_fri.CirclePolyDegreeBound.init(log_size - config.log_blowup_factor),
    );
    defer verifier.deinit(allocator);
    const verifier_positions = try verifier.sampleQueryPositions(allocator, &verifier_channel);
    defer allocator.free(verifier_positions);
    try std.testing.expectEqualSlices(usize, queries.positions, verifier_positions);
    const query_values = try allocator.alloc(QM31, verifier_positions.len);
    defer allocator.free(query_values);
    for (query_values, verifier_positions) |*value, index| value.* = values[index];
    try verifier.decommit(allocator, query_values);
    try std.testing.expectEqualSlices(u8, &query_channel.digest, &verifier_channel.digest);
    try std.testing.expectEqual(query_channel.n_draws, verifier_channel.n_draws);
}
