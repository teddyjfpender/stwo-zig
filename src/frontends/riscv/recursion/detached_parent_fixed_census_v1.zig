//! Diagnostic census of the exact columns committed in a detached parent's
//! Tree 0. A proof-free recipe must match every digest, not merely the root.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const manifest_mod = @import("detached_parent_components_v1.zig").manifest_mod;

pub fn print(manifest: *const manifest_mod.Manifest, columns: [][]M31) !void {
    try manifest.validate();
    if (columns.len != manifest.total_preprocessed_columns)
        return error.DetachedParentDestinationMismatch;
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const placement = manifest.placements[row] orelse
            return error.DetachedParentManifestMismatch;
        const offset: usize = placement.preprocessed_offset;
        const count: usize = placement.geometry.preprocessed_columns;
        if (offset + count > columns.len)
            return error.DetachedParentDestinationMismatch;
        const digest = try digestColumns(
            columns[offset..][0..count],
            @as(usize, 1) << @intCast(placement.geometry.log_size),
        );
        std.debug.print(
            "DETACHED_PARENT_FIXED_CENSUS row={d} log_size={d} columns={d} sha256={s}\n",
            .{ row, placement.geometry.log_size, count, std.fmt.bytesToHex(digest, .lower) },
        );
    }
}

fn digestColumns(columns: [][]M31, expected_len: usize) ![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var length_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &length_bytes, columns.len, .little);
    hash.update(&length_bytes);
    for (columns) |column| {
        if (column.len != expected_len) return error.DetachedParentDestinationMismatch;
        std.mem.writeInt(u64, &length_bytes, column.len, .little);
        hash.update(&length_bytes);
        for (column) |word| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word.toU32(), .little);
            hash.update(&bytes);
        }
    }
    return hash.finalResult();
}

test "fixed-row census binds every column, length and value" {
    const zero = M31.zero();
    const one = M31.one();
    var first = [_]M31{ zero, one };
    var second = [_]M31{ one, zero };
    var columns = [_][]M31{ &first, &second };
    const original = try digestColumns(&columns, 2);
    second[1] = one;
    try std.testing.expect(!std.meta.eql(original, try digestColumns(&columns, 2)));
    try std.testing.expectError(
        error.DetachedParentDestinationMismatch,
        digestColumns(&columns, 1),
    );
}
