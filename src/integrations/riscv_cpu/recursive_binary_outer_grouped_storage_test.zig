const std = @import("std");
const core = @import("stwo_core");
const recursion = @import("stwo_riscv_frontend").recursion;
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const M31 = core.fields.m31.M31;
const support = @import("recursive_binary_outer_support.zig");

// Only column geometry is under test. Commitments below use the production
// circle FFT, PCS preparation and Poseidon Merkle implementations.
const Contract = struct {
    pub const PREPROCESSED_TREE_INDEX = 0;
    pub const MAIN_TREE_INDEX = 1;
    pub const INTERACTION_TREE_INDEX = 2;
    pub const Geometry = struct { log_size: u32, preprocessed_columns: usize = 12, main_columns: usize = 12, interaction_columns: usize = 12 };
    pub const Placement = struct { geometry: Geometry, preprocessed_offset: usize, main_offset: usize, interaction_offset: usize };
    pub const Manifest = struct { roster_rows: [6]usize = .{ 0, 1, 2, 3, 4, 5 }, roster_count: usize = 6, placements: [6]?Placement, total_preprocessed_columns: usize = 72, total_main_columns: usize = 72, total_interaction_columns: usize = 72 };
};
const Storage = support.TreeStorageForManifest(Contract);
fn fixture() Contract.Manifest {
    var result: Contract.Manifest = .{ .placements = undefined };
    for ([_]u32{ 4, 5, 4, 6, 5, 4 }, &result.placements, 0..) |log, *placement, index| placement.* = .{ .geometry = .{ .log_size = log }, .preprocessed_offset = 12 * index, .main_offset = 12 * index, .interaction_offset = 12 * index };
    return result;
}
fn fill(value: *Storage) void {
    for (value.columns, 0..) |column, index| {
        for (column, 0..) |*cell, row| cell.* = M31.fromCanonical(@intCast(1 + index * 73 + row * row + row));
    }
}

// Exercise the production arenaGroupRun branch with CPU arithmetic. This
// changes ownership policy only: no fake transform, commitment or receipt.
const AdoptingCpu = struct {
    pub const adopts_source_trace_arena = true;
    pub const combined_base_in_place = false;
    pub const combined_commit_min_columns = 0;
    pub const combined_commit_max_columns = std.math.maxInt(usize);
    pub const combinedCircleLdeSkippedForwardLayers = Cpu.combinedCircleLdeSkippedForwardLayers;
    pub const interpolateAndEvaluateCircleBuffers = Cpu.interpolateAndEvaluateCircleBuffers;
    pub const MerkleTree = Cpu.MerkleTree;
    pub const commitMerkle = Cpu.commitMerkle;
    pub const commitLazyMerkle = Cpu.commitLazyMerkle;
};
const Engine = recursion.engine.ProverEngineForBackend(AdoptingCpu);
const CpuEngine = recursion.engine.ProverEngineForBackend(Cpu);
const PCS: core.pcs.PcsConfig = .{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 3, .fold_step = 1 } };

test "Ethereum grouped tree storage keeps logical columns and stable physical runs" {
    const allocator = std.testing.allocator;
    const manifest = fixture();
    for (0..3) |tree| {
        var original = try Storage.init(allocator, &manifest, tree);
        defer original.deinit();
        var grouped = try Storage.initGroupedByLog(allocator, &manifest, tree);
        defer grouped.deinit();
        fill(&original);
        fill(&grouped);
        try std.testing.expectEqual(original.storage.len, grouped.storage.len);
        var physical: usize = 0;
        for (4..7) |log| for (grouped.evaluations, 0..) |column, index| {
            try std.testing.expectEqual(original.evaluations[index].log_size, column.log_size);
            try std.testing.expectEqualSlices(M31, original.columns[index], column.values);
            try std.testing.expectEqual(@intFromPtr(grouped.columns[index].ptr), @intFromPtr(column.values.ptr));
            if (column.log_size != log) continue;
            try std.testing.expectEqual(@intFromPtr(grouped.storage.ptr + physical), @intFromPtr(column.values.ptr));
            physical += column.values.len;
        };
        try std.testing.expectEqual(grouped.storage.len, physical);
        var original_at: usize = 0;
        for (original.evaluations) |column| {
            try std.testing.expectEqual(@intFromPtr(original.storage.ptr + original_at), @intFromPtr(column.values.ptr));
            original_at += column.values.len;
        }
    }
}

test "Ethereum grouped tree storage adopts coefficients with actual PCS root parity" {
    const allocator = std.testing.allocator;
    const manifest = fixture();
    var original = try Storage.init(allocator, &manifest, 0);
    defer original.deinit();
    var grouped = try Storage.initGroupedByLog(allocator, &manifest, 0);
    defer grouped.deinit();
    var cpu = try Storage.init(allocator, &manifest, 0);
    defer cpu.deinit();
    fill(&original);
    fill(&grouped);
    fill(&cpu);
    var addresses: [72]usize = undefined;
    for (grouped.columns, &addresses) |column, *address| address.* = @intFromPtr(column.ptr);
    const source_words = grouped.storage.len;
    var left = try Engine.init(allocator, PCS);
    defer Engine.deinit(&left, allocator);
    var right = try Engine.init(allocator, PCS);
    defer Engine.deinit(&right, allocator);
    var native = try CpuEngine.init(allocator, PCS);
    defer CpuEngine.deinit(&native, allocator);
    var left_channel = Engine.Channel{};
    var right_channel = Engine.Channel{};
    var native_channel = CpuEngine.Channel{};
    try original.commitWithEngine(Engine, &left, &left_channel);
    try grouped.commitWithEngine(Engine, &right, &right_channel);
    try cpu.commitWithEngine(CpuEngine, &native, &native_channel);
    try Engine.flushPendingCommit(&left, allocator, &left_channel);
    try Engine.flushPendingCommit(&right, allocator, &right_channel);
    try CpuEngine.flushPendingCommit(&native, allocator, &native_channel);
    const legacy = &left.trees.items[0];
    const adopted = &right.trees.items[0];
    try std.testing.expectEqualDeep(legacy.root(), adopted.root());
    try std.testing.expectEqualDeep(native.trees.items[0].root(), adopted.root());
    try std.testing.expectEqualDeep(left_channel, right_channel);
    try std.testing.expectEqual(@as(usize, 1), adopted.coefficient_backing_buffers.?.len);
    try std.testing.expectEqual(source_words, adopted.coefficient_backing_buffers.?[0].len);
    try std.testing.expect(legacy.coefficient_backing_buffers.?.len > 1);
    var extra_words: usize = 0;
    for (legacy.coefficient_backing_buffers.?) |buffer| extra_words += buffer.len;
    try std.testing.expect(extra_words > source_words);
    for (legacy.columns, adopted.columns, legacy.coefficients.?, adopted.coefficients.?, addresses) |before, after, before_coeff, after_coeff, address| {
        try std.testing.expectEqual(before.log_size, after.log_size);
        try std.testing.expectEqualSlices(M31, before.values, after.values);
        try std.testing.expectEqualSlices(M31, before_coeff.coefficients(), after_coeff.coefficients());
        try std.testing.expectEqual(address, @intFromPtr(after_coeff.coefficients().ptr));
    }
    std.debug.print("GROUPED_TREE_STORAGE actual_fft_merkle=true source_words={d} duplicate_coefficient_words_before={d} after=0\n", .{ source_words, extra_words - source_words });
}
