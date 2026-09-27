//! Bounded tiled BLAKE3 leaf generation from retained streaming PCS columns.
//! Each tile projects global lifted indices into its exact local circle-index
//! interval. Two compact state slabs and a bounded packed column window are staged;
//! no allocation is proportional to total witness width or full-domain state.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const shared = @import("../shared_runtime.zig");
const resident = @import("resident_operations.zig");
const M31 = core.fields.m31.M31;
const Hasher = core.vcs_lifted.blake3_merkle.MerkleHasher;
const scratch_budget: usize = 64 * 1024 * 1024;

pub fn tryCommit(comptime H: type, a: std.mem.Allocator, columns: []const []const M31) !?prover.vcs_lifted.prover.MerkleProverLifted(H) {
    if (comptime H != Hasher) return null;
    // Experimental until complete proofs and matched timings qualify the route.
    if (std.posix.getenv("STWO_ZIG_METAL_STREAM_LEAVES") == null or columns.len == 0) return null;
    var lease = try shared.acquireExisting();
    defer lease.deinit();
    return try commit(a, columns, lease.runtime, scratch_budget);
}

const Tree = prover.vcs_lifted.prover.MerkleProverLifted(Hasher);
fn commit(a: std.mem.Allocator, columns: []const []const M31, runtime: *@import("../runtime.zig").Runtime, budget: usize) !Tree {
    try @import("../execution_policy.zig").admitHost(.merkle_commit);
    const sorted = try Tree.sortColumnsByLogSizeAsc(a, columns);
    defer a.free(sorted);
    const global_log = sorted[sorted.len - 1].log_size;
    if (global_log >= 31 or columns.len > std.math.maxInt(u32)) return error.InvalidColumnSize;
    const stride = resident.blake3LeafStateWords(@intCast(columns.len));
    const words_per_row = 2 * stride + 16 + 8;
    const tile_log: u32 = @min(global_log, @as(u32, @intCast(std.math.log2_int(usize, budget / (@as(usize, words_per_row) * 4)))));
    const tile_rows = @as(usize, 1) << @intCast(tile_log);
    const stage_offset: u32 = @intCast(2 * stride * tile_rows);
    const output_offset: u32 = @intCast(stage_offset + 16 * tile_rows);
    const byte_count = words_per_row * tile_rows * 4;
    var arena = try runtime.allocateResidentBuffer(byte_count);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    const leaves = try a.alloc(Hasher.Hash, @as(usize, 1) << @intCast(global_log));
    var leaves_owned = true;
    errdefer if (leaves_owned) a.free(leaves);
    var gpu_ms: f64 = 0;
    var dispatches: usize = 0;
    var tile_base: usize = 0;
    while (tile_base < leaves.len) : (tile_base += tile_rows) {
        var first: usize = 0;
        var source_offset: u32 = 0;
        var source_log: u32 = 0;
        var slot: usize = 1;
        while (first < sorted.len) {
            var end = first;
            var stage_words: usize = 0;
            var offsets: [256]u32 = undefined;
            var logs: [256]u32 = undefined;
            // Pack small native domains together. A fixed sixteen-column
            // group would submit thousands of tiny kernels for narrow AIRs.
            while (end < sorted.len and end - first < offsets.len) {
                const column = sorted[end];
                const local = localColumn(global_log, tile_log, tile_base, column.log_size);
                const count = @as(usize, 1) << @intCast(local.log);
                if (stage_words + count > 16 * tile_rows) break;
                const index = end - first;
                offsets[index] = @intCast(stage_offset + stage_words);
                logs[index] = local.log;
                @memcpy(words[offsets[index]..][0..count], std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(column.values[local.start..][0..count])));
                stage_words += count;
                end += 1;
            }
            const final = end == sorted.len;
            const destination: u32 = if (final) output_offset else @intCast(slot * stride * tile_rows);
            const destination_log = logs[end - first - 1];
            gpu_ms += try runtime.blake3LeafAbsorbCompact(arena, offsets[0 .. end - first], logs[0 .. end - first], source_offset, source_log, destination, destination_log, @intCast(first), final, stride);
            dispatches += 1;
            source_offset = destination;
            source_log = destination_log;
            slot ^= 1;
            first = end;
        }
        @memcpy(std.mem.sliceAsBytes(leaves[tile_base..][0..tile_rows]), std.mem.sliceAsBytes(words[output_offset..][0 .. tile_rows * 8]));
    }
    // Parent layers
    // remain on the shared host implementation in this first bounded ingress.
    if (std.posix.getenv("STWO_RISCV_EXECUTION_PROFILE") != null)
        std.debug.print("METAL_STREAM_LEAVES columns={} log={} tile_log={} scratch_bytes={} dispatches={} gpu_ms={d:.3}\n", .{ columns.len, global_log, tile_log, byte_count, dispatches, gpu_ms });
    leaves_owned = false;
    return try Tree.fromOwnedLeaves(a, a, leaves);
}

const LocalColumn = struct { log: u32, start: usize };
fn localColumn(global_log: u32, tile_log: u32, tile_base: usize, column_log: u32) LocalColumn {
    return .{ .log = @max(1, column_log -| (global_log - tile_log)), .start = (tile_base >> @intCast(global_log - column_log + 1)) << 1 };
}

test "bounded Metal leaf tiles preserve global lifted column indices" {
    for (1..10) |global| {
        for (1..global + 1) |tile| {
            const rows = @as(usize, 1) << @intCast(tile);
            var base: usize = 0;
            while (base < @as(usize, 1) << @intCast(global)) : (base += rows) {
                for (1..global + 1) |column| {
                    const local = localColumn(@intCast(global), @intCast(tile), base, @intCast(column));
                    for (0..rows) |row| try std.testing.expectEqual((((base + row) >> @intCast(global - column + 1)) << 1) + (row & 1), local.start + ((row >> @intCast(tile - local.log + 1)) << 1) + (row & 1));
                }
            }
        }
    }
}

test "bounded Metal leaf tiles match every host Merkle layer across chunk and height boundaries" {
    const a = std.testing.allocator;
    var runtime = try @import("../runtime.zig").Runtime.init();
    defer runtime.deinit();
    for ([_]usize{ 33, 273, 1030 }) |count| {
        const columns = try a.alloc([]M31, count);
        defer a.free(columns);
        var initialized: usize = 0;
        defer for (columns[0..initialized]) |column| a.free(column);
        for (columns, 0..) |*column, index| {
            column.* = try a.alloc(M31, @as(usize, 1) << @intCast(1 + index % 7));
            initialized += 1;
            for (column.*, 0..) |*value, row| value.* = M31.fromU64(index * 397 + row * 47 + (row & 1) * 101);
        }
        var expected = try Tree.commit(a, columns);
        defer expected.deinit(a);
        // Force multiple leaf tiles even for this small real-device fixture.
        var actual = try commit(a, columns, &runtime, 4096);
        defer actual.deinit(a);
        try std.testing.expectEqual(expected.layers.len, actual.layers.len);
        for (expected.layers, actual.layers) |reference, candidate| try std.testing.expectEqualSlices(Hasher.Hash, reference, candidate);
    }
}
