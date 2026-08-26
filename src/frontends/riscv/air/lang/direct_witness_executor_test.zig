const std = @import("std");
const subject = @import("direct_witness_executor.zig");

const column_count = 2;
const bad_row: u32 = 0xffff_ffff;

test "direct witness executor writes final storage and zeroes exact padding" {
    var protected: u64 = 0x1234;
    var first = [_]u32{99} ** 8;
    var second = [_]u32{77} ** 8;
    var columns = [_][]u32{ &first, &second };
    const rows = [_]u32{ 3, 5, 8 };

    try subject.generateMainInto(
        u32,
        u32,
        column_count,
        &columns,
        &rows,
        3,
        0,
        &protected,
        validateRow,
        writeRow,
    );

    try std.testing.expectEqualSlices(u32, &.{ 3, 5, 8, 0, 0, 0, 0, 0 }, &first);
    try std.testing.expectEqualSlices(u32, &.{ 6, 10, 16, 0, 0, 0, 0, 0 }, &second);
    try std.testing.expectEqual(@as(u64, 0x1234), protected);
}

test "direct witness executor rejects every fallible condition before mutation" {
    var protected: u64 = 0x5678;
    var first = [_]u32{41} ** 4;
    var second = [_]u32{43} ** 4;
    const original_first = first;
    const original_second = second;
    var columns = [_][]u32{ &first, &second };
    const invalid_rows = [_]u32{ 1, bad_row };

    try std.testing.expectError(error.InvalidTraceRow, subject.generateMainInto(
        u32,
        u32,
        column_count,
        &columns,
        &invalid_rows,
        2,
        0,
        &protected,
        validateRow,
        writeRow,
    ));
    try std.testing.expectEqualSlices(u32, &original_first, &first);
    try std.testing.expectEqualSlices(u32, &original_second, &second);

    columns[1] = second[0..3];
    try std.testing.expectError(error.InvalidTraceShape, subject.generateMainInto(
        u32,
        u32,
        column_count,
        &columns,
        &.{1},
        2,
        0,
        &protected,
        validateRow,
        writeRow,
    ));
    try std.testing.expectEqualSlices(u32, &original_first, &first);
    try std.testing.expectEqualSlices(u32, &original_second, &second);
}

test "direct witness executor rejects input destination and protected aliases" {
    var protected: u64 = 0;
    var shared = [_]u32{ 2, 3, 5, 7 };
    var separate = [_]u32{ 11, 13, 17, 19 };
    var columns = [_][]u32{ &shared, &separate };

    try std.testing.expectError(error.AliasedInput, subject.generateMainInto(
        u32,
        u32,
        column_count,
        &columns,
        shared[0..2],
        2,
        0,
        &protected,
        validateRow,
        writeRow,
    ));

    columns[1] = &shared;
    try std.testing.expectError(error.AliasedDestination, subject.generateMainInto(
        u32,
        u32,
        column_count,
        &columns,
        &.{1},
        2,
        0,
        &protected,
        validateRow,
        writeRow,
    ));

    columns = .{ &shared, &separate };
    try std.testing.expectError(error.AliasedDestination, subject.generateMainInto(
        u32,
        u32,
        column_count,
        &columns,
        &.{1},
        2,
        0,
        &shared,
        validateRow,
        writeRow,
    ));
}

fn validateRow(row: u32) subject.Error!void {
    if (row == bad_row) return error.InvalidTraceRow;
}

fn writeRow(columns: *[column_count][]u32, index: usize, row: u32) void {
    columns[0][index] = row;
    columns[1][index] = row * 2;
}
