const std = @import("std");
const abi = @import("opstack_frontend_component").guest_abi;

/// Kona guest linker layout (`guests/opstack/kona/guest/linker.ld`): 16 MiB
/// window at 0x0080_0000, stack 0x01C0_0000..0x02C0_0000, heap from the stack top.
const kona = abi.Symbols{ .input_start = 0x00800000, .input_end = 0x01800000, .halt_flag = 0x01800000, .output_len = 0x01800004, .output_data = 0x01800008, .output_end = 0x01C00000, .stack_bottom = 0x01C00000, .stack_top = 0x02C00000, .heap_start = 0x02C00000, .heap_end = 0x10000000 };

fn withWindow(window: u64) abi.Symbols {
    var s = kona;
    s.input_end = s.input_start + window;
    s.halt_flag = s.input_end;
    s.output_len = s.halt_flag + 4;
    s.output_data = s.halt_flag + 8;
    s.output_end = s.halt_flag + 0x400000;
    s.stack_bottom = s.output_end;
    s.stack_top = s.stack_bottom + abi.STACK_BYTES;
    s.heap_start = s.stack_top;
    s.heap_end = s.heap_start + 0x1000000;
    return s;
}

test "guest abi: windows 4..32 MiB admitted, 64 MiB rejected" {
    for ([_]u64{ 4, 8, 16, 32 }) |mib| {
        const s = withWindow(mib * 1024 * 1024);
        try std.testing.expectEqual(@as(?u64, mib * 1024 * 1024), abi.inputWindow(s));
        try std.testing.expectEqual(mib * 1024 * 1024, try abi.validate(s, 1));
    }
    try std.testing.expectEqual(@as(?u64, null), abi.inputWindow(withWindow(64 * 1024 * 1024)));
    try std.testing.expectEqual(@as(?u64, null), abi.inputWindow(withWindow(2 * 1024 * 1024)));
    try std.testing.expectEqual(@as(?u64, null), abi.inputWindow(withWindow(6 * 1024 * 1024)));
}

test "guest abi: Kona linker layout is admitted" {
    try std.testing.expectEqual(@as(u64, 16 * 1024 * 1024), try abi.validate(kona, 1));
}

test "guest abi: input must be nonempty and fit the window less its prefix" {
    try std.testing.expectError(error.InvalidGuestIoLayout, abi.validate(kona, 0));
    try std.testing.expectEqual(@as(u64, 16 * 1024 * 1024), try abi.validate(kona, 16 * 1024 * 1024 - 4));
    try std.testing.expectError(error.InvalidGuestIoLayout, abi.validate(kona, 16 * 1024 * 1024 - 3));
}

test "guest abi: every control-page and stack relation is enforced" {
    const mutations = [_]struct { field: []const u8, delta: i64 }{
        .{ .field = "halt_flag", .delta = 4 },
        .{ .field = "output_len", .delta = 4 },
        .{ .field = "output_data", .delta = 8 },
        .{ .field = "output_end", .delta = 16 },
        .{ .field = "stack_top", .delta = 16 },
        .{ .field = "heap_start", .delta = -16 },
        .{ .field = "heap_start", .delta = 1 },
    };
    inline for (mutations) |m| {
        var s = kona;
        @field(s, m.field) = @intCast(@as(i64, @intCast(@field(s, m.field))) + m.delta);
        try std.testing.expectError(error.InvalidGuestIoLayout, abi.validate(s, 1));
    }
}
