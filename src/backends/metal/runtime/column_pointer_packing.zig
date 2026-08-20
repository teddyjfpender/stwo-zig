//! Exact, allocation-free packing of per-job resident column pointers.

const std = @import("std");

pub const Error = error{DestinationTooSmall};

pub fn pack(
    destination: [][*]const u32,
    cursor: *usize,
    columns: anytype,
) Error!void {
    if (cursor.* > destination.len or
        columns.len > destination.len - cursor.*)
    {
        return error.DestinationTooSmall;
    }
    const end = cursor.* + columns.len;
    for (columns, destination[cursor.*..end]) |column, *pointer|
        pointer.* = @ptrCast(column.values.ptr);
    cursor.* = end;
}

test "column pointer packing preserves unequal base and lookup job boundaries" {
    const Column = struct { values: []const u32 };
    var values: [15]u32 = undefined;
    for (&values, 0..) |*value, index| value.* = @intCast(index);
    var columns: [15]Column = undefined;
    for (&columns, 0..) |*column, index|
        column.* = .{ .values = values[index..][0..1] };

    var base: [5][*]const u32 = undefined;
    var base_cursor: usize = 0;
    try pack(&base, &base_cursor, columns[0..2]);
    try pack(&base, &base_cursor, columns[2..5]);
    try std.testing.expectEqual(base.len, base_cursor);
    for (base, columns[0..5]) |actual, expected|
        try std.testing.expectEqual(@intFromPtr(expected.values.ptr), @intFromPtr(actual));

    var lookup_main: [5][*]const u32 = undefined;
    var lookup_main_cursor: usize = 0;
    try pack(&lookup_main, &lookup_main_cursor, columns[5..6]);
    try pack(&lookup_main, &lookup_main_cursor, columns[6..10]);
    try std.testing.expectEqual(lookup_main.len, lookup_main_cursor);
    for (lookup_main, columns[5..10]) |actual, expected|
        try std.testing.expectEqual(@intFromPtr(expected.values.ptr), @intFromPtr(actual));

    var interaction: [5][*]const u32 = undefined;
    var interaction_cursor: usize = 0;
    try pack(&interaction, &interaction_cursor, columns[10..14]);
    try pack(&interaction, &interaction_cursor, columns[14..15]);
    try std.testing.expectEqual(interaction.len, interaction_cursor);
    for (interaction, columns[10..15]) |actual, expected|
        try std.testing.expectEqual(@intFromPtr(expected.values.ptr), @intFromPtr(actual));

    try std.testing.expectError(
        error.DestinationTooSmall,
        pack(&interaction, &interaction_cursor, columns[0..1]),
    );
}
