//! Shared authenticated layer-cache admission for streaming and owned trees.
//! Cache policy remains with the caller that arms the external layer source.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const merkle = @import("../vcs_lifted/prover.zig");
const seam = @import("merkle_layer_cache.zig");

fn requestForSorted(
    comptime H: type,
    sorted: []const merkle.MerkleProverLifted(H).ColumnRef,
    logs: []u32,
) ?seam.Request {
    if (sorted.len == 0) return null;
    const log_size = sorted[sorted.len - 1].log_size;
    if (log_size < 1 or log_size > 30) return null;
    for (sorted, logs) |column, *entry| entry.* = column.log_size;
    return .{
        .hasher_tag = @typeName(H),
        .hash_bytes = @sizeOf(H.Hash),
        .log_size = log_size,
        .pruned_bottom_layers = if (log_size >= 20) 4 else 0,
        .column_log_sizes = logs,
    };
}

fn admits(source: seam.LayerSource, request: seam.Request) bool {
    const retained_log = request.log_size - request.pruned_bottom_layers;
    const hashes = (@as(u64, 1) << @intCast(retained_log + 1)) - 1;
    const bytes = std.math.mul(u64, hashes, request.hash_bytes) catch return false;
    return bytes <= source.max_payload_bytes;
}

pub fn loadSorted(
    comptime H: type,
    allocator: std.mem.Allocator,
    sorted: []const merkle.MerkleProverLifted(H).ColumnRef,
) ?merkle.MerkleProverLifted(H) {
    const source = seam.armed() orelse return null;
    const Tree = merkle.MerkleProverLifted(H);
    const logs = allocator.alloc(u32, sorted.len) catch return null;
    defer allocator.free(logs);
    const request = requestForSorted(H, sorted, logs) orelse return null;
    if (!admits(source, request)) return null;
    const layers = Tree.allocateLayersPruned(
        allocator,
        request.log_size,
        request.pruned_bottom_layers,
    ) catch return null;
    var adopted = false;
    defer if (!adopted) Tree.freeLayers(allocator, layers);
    const views = allocator.alloc([]u8, layers.len) catch return null;
    defer allocator.free(views);
    for (layers, views) |layer, *view| view.* = std.mem.sliceAsBytes(layer);
    if (!source.load(source.ctx, request, views)) return null;
    if (!topLayersRederive(H, layers)) return null;
    adopted = true;
    return Tree.fromLayers(allocator, layers);
}

pub fn loadColumns(
    comptime H: type,
    allocator: std.mem.Allocator,
    columns: []const []const M31,
) ?merkle.MerkleProverLifted(H) {
    if (seam.armed() == null) return null;
    const sorted = merkle.MerkleProverLifted(H).sortColumnsByLogSizeAsc(
        allocator,
        columns,
    ) catch return null;
    defer allocator.free(sorted);
    return loadSorted(H, allocator, sorted);
}

pub fn storeSorted(
    comptime H: type,
    allocator: std.mem.Allocator,
    sorted: []const merkle.MerkleProverLifted(H).ColumnRef,
    tree: merkle.MerkleProverLifted(H),
) void {
    const source = seam.armed() orelse return;
    const logs = allocator.alloc(u32, sorted.len) catch return;
    defer allocator.free(logs);
    const request = requestForSorted(H, sorted, logs) orelse return;
    if (!admits(source, request)) return;
    if (tree.layers.len != @as(usize, request.log_size) + 1) return;
    const views = allocator.alloc([]const u8, tree.layers.len) catch return;
    defer allocator.free(views);
    for (tree.layers, views, 0..) |layer, *view, index|
        view.* = if (index > request.log_size - request.pruned_bottom_layers)
            &.{}
        else
            std.mem.sliceAsBytes(layer);
    source.store(source.ctx, request, views);
}

/// Device readers export only retained upper layers in bounded chunks. This
/// runs solely for an armed fixed-data commit, never for witness trees.
pub fn storeReader(
    comptime H: type,
    allocator: std.mem.Allocator,
    columns: []const []const M31,
    reader: anytype,
) void {
    if (captureAndStoreReader(H, allocator, columns, reader)) |captured| {
        var owned = captured;
        owned.deinit(allocator);
    }
}

/// Retains freshly computed device upper layers so the caller may release
/// the full hash tree before later proving stages. Store failures do not
/// invalidate the device-produced layers. Returns an independent owned tree.
pub fn captureAndStoreReader(
    comptime H: type,
    allocator: std.mem.Allocator,
    columns: []const []const M31,
    reader: anytype,
) ?merkle.MerkleProverLifted(H) {
    const source = seam.armed() orelse return null;
    const Tree = merkle.MerkleProverLifted(H);
    const sorted = Tree.sortColumnsByLogSizeAsc(allocator, columns) catch return null;
    defer allocator.free(sorted);
    const logs = allocator.alloc(u32, sorted.len) catch return null;
    defer allocator.free(logs);
    const request = requestForSorted(H, sorted, logs) orelse return null;
    if (!admits(source, request) or reader.maxLogSize() != request.log_size) return null;
    if (comptime @TypeOf(reader) == Tree) {
        storeSorted(H, allocator, sorted, reader);
        return null;
    }
    const layers = Tree.allocateLayersPruned(
        allocator,
        request.log_size,
        request.pruned_bottom_layers,
    ) catch return null;
    var adopted = false;
    defer if (!adopted) Tree.freeLayers(allocator, layers);
    const chunk_limit = 1 << 16;
    const indices = allocator.alloc(u32, @min(chunk_limit, @as(usize, 1) <<
        @intCast(request.log_size - request.pruned_bottom_layers))) catch return null;
    defer allocator.free(indices);
    for (layers, 0..) |layer, log| {
        var start: usize = 0;
        while (start < layer.len) {
            const count = @min(indices.len, layer.len - start);
            for (indices[0..count], 0..) |*index, offset|
                index.* = @intCast(start + offset);
            const hashes = reader.readHashes(allocator, @intCast(log), indices[0..count]) catch return null;
            defer allocator.free(hashes);
            if (hashes.len != count) return null;
            @memcpy(layer[start..][0..count], hashes);
            start += count;
        }
    }
    const captured = Tree.fromLayers(allocator, layers);
    storeSorted(H, allocator, sorted, captured);
    adopted = true;
    return captured;
}

/// Re-derive the upper layers to refuse internally inconsistent artifacts.
fn topLayersRederive(comptime H: type, layers: []const []H.Hash) bool {
    const spot_check_limit: usize = 4096;
    if (layers.len < 2) return false;
    var index: usize = 0;
    while (index + 1 < layers.len and layers[index].len <= spot_check_limit) : (index += 1) {
        const parents = layers[index];
        const children = layers[index + 1];
        if (children.len != parents.len * 2) return false;
        for (parents, 0..) |parent, position| {
            const recomputed = H.hashChildren(.{
                .left = children[2 * position],
                .right = children[2 * position + 1],
            });
            if (!std.mem.eql(u8, std.mem.asBytes(&parent), std.mem.asBytes(&recomputed)))
                return false;
        }
    }
    return index > 0;
}

test {
    _ = @import("merkle_cached_tree_test.zig");
}
