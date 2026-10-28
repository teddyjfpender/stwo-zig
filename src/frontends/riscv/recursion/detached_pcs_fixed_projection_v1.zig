//! Materialize PCS/FRI fixed columns from key-derived preprocessing rows.
//! Witness values and parameter words are deliberately absent from this API.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const framework = @import("air/framework_interaction.zig");

pub fn fillPair(comptime Air: type, left: anytype, right: anytype, log_size: u32, destination: []const []M31) !void {
    if (log_size >= @bitSizeOf(usize) or destination.len != Air.PREPROCESSED_COLUMN_COUNT)
        return error.DetachedPcsFixedDestinationMismatch;
    const height: usize = @as(usize, 1) << @intCast(log_size);
    for (destination) |column| if (column.len != height)
        return error.DetachedPcsFixedDestinationMismatch;
    var left_count: usize = 0;
    var right_count: usize = 0;
    for (left) |row| left_count += @intFromBool(row.verifier_id == 1);
    for (right) |row| right_count += @intFromBool(row.verifier_id == 2);
    if (left_count > height or right_count > height - left_count)
        return error.DetachedPcsFixedDestinationMismatch;
    for (destination) |column| @memset(column, M31.zero());
    var logical: usize = 0;
    for (left) |row| {
        if (row.verifier_id != 1) continue;
        const fixed = row.values();
        const committed = framework.committedRow(logical, log_size);
        for (destination, fixed) |column, word| column[committed] = word;
        logical += 1;
    }
    for (right) |row| {
        if (row.verifier_id != 2) continue;
        const fixed = row.values();
        const committed = framework.committedRow(logical, log_size);
        for (destination, fixed) |column, word| column[committed] = word;
        logical += 1;
    }
}
