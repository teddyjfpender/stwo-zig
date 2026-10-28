//! Proof-free parent Tree0 tables whose rows depend only on admitted manifest
//! geometry. Both the current producer and the key-only compiler use this path.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const manifest_mod = @import("detached_parent_components_v1.zig").manifest_mod;
const framework = @import("air/framework_interaction.zig");
const range = @import("air/range_check_8_8_bridge.zig");

pub fn fillFromManifest(manifest: *const manifest_mod.Manifest, destination: [][]M31) !void {
    try manifest.validate();
    if (destination.len != manifest.total_preprocessed_columns)
        return error.DetachedParentDestinationMismatch;
    const poseidon = manifest.placements[34] orelse return error.DetachedParentManifestMismatch;
    const range_placement = manifest.placements[35] orelse return error.DetachedParentManifestMismatch;
    if (poseidon.geometry.preprocessed_columns != 1 or
        poseidon.geometry.log_size >= @bitSizeOf(usize) or
        poseidon.preprocessed_offset >= destination.len or
        range_placement.geometry.preprocessed_columns != 3 or
        range_placement.geometry.log_size != range.LOG_SIZE or
        range_placement.preprocessed_offset + 3 > destination.len)
        return error.DetachedParentDestinationMismatch;

    const first = destination[poseidon.preprocessed_offset];
    if (first.len != @as(usize, 1) << @intCast(poseidon.geometry.log_size))
        return error.DetachedParentDestinationMismatch;
    @memset(first, M31.zero());
    first[framework.committedRow(0, poseidon.geometry.log_size)] = M31.one();

    const columns = destination[range_placement.preprocessed_offset..][0..3];
    for (columns) |column| {
        if (column.len != range.TABLE_SIZE) return error.DetachedParentDestinationMismatch;
        @memset(column, M31.zero());
    }
    columns[0][range.committedRow(0)] = M31.one();
    for (0..range.TABLE_SIZE) |logical| {
        const row = range.committedRow(logical);
        columns[1][row] = M31.fromCanonical(@intCast(logical & 255));
        columns[2][row] = M31.fromCanonical(@intCast(logical >> 8));
    }
}
