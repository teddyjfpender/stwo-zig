//! Test-only device proof that dependent same-output dispatches require and
//! obey an explicit buffer barrier. Production runtime code is not imported.

const std = @import("std");

extern fn stwo_zig_metal_test_composition_dispatch_barrier(
    mode: u32,
    reverse: bool,
    result: [*]u32,
    row_count: u32,
) bool;

extern fn stwo_zig_metal_test_wide_column_offsets(
    wide_offsets: *[4]u64,
    wrapped_offsets: *[4]u32,
) bool;

test "Metal composition same-output dispatches are order independent with a buffer barrier" {
    var barrier_forward: [256]u32 = undefined;
    var barrier_reverse: [256]u32 = undefined;
    var encoder_boundary: [256]u32 = undefined;
    try std.testing.expect(stwo_zig_metal_test_composition_dispatch_barrier(
        0,
        false,
        &barrier_forward,
        barrier_forward.len,
    ));
    try std.testing.expect(stwo_zig_metal_test_composition_dispatch_barrier(
        0,
        true,
        &barrier_reverse,
        barrier_reverse.len,
    ));
    try std.testing.expect(stwo_zig_metal_test_composition_dispatch_barrier(
        1,
        false,
        &encoder_boundary,
        encoder_boundary.len,
    ));
    try std.testing.expectEqualSlices(
        u32,
        &[_]u32{18} ** barrier_forward.len,
        &barrier_forward,
    );
    try std.testing.expectEqualSlices(u32, &barrier_forward, &barrier_reverse);
    try std.testing.expectEqualSlices(u32, &barrier_forward, &encoder_boundary);
}

test "Metal generated column offsets keep 254 255 256 and 339 distinct at log 24" {
    var wide_offsets: [4]u64 = undefined;
    var wrapped_offsets: [4]u32 = undefined;
    try std.testing.expect(stwo_zig_metal_test_wide_column_offsets(
        &wide_offsets,
        &wrapped_offsets,
    ));
    const columns = [_]u64{ 254, 255, 256, 339 };
    for (columns, 0..) |column, index| {
        try std.testing.expectEqual((column << 24) + 7, wide_offsets[index]);
    }
    try std.testing.expectEqual(@as(u32, 254) << 24 | 7, wrapped_offsets[0]);
    try std.testing.expectEqual(@as(u32, 255) << 24 | 7, wrapped_offsets[1]);
    try std.testing.expectEqual(@as(u32, 7), wrapped_offsets[2]);
    try std.testing.expectEqual(@as(u32, 83) << 24 | 7, wrapped_offsets[3]);
    try std.testing.expect(wide_offsets[2] != wrapped_offsets[2]);
    try std.testing.expect(wide_offsets[3] != wrapped_offsets[3]);
}
