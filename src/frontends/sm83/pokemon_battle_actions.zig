//! Public joypad schedule captured by pinned PE-AGI `battle_trace.c`.

const std = @import("std");
const action_schedule = @import("action_schedule.zig");
const joypad = @import("runner/joypad.zig");

const FRAME_STEP: u32 = 10;
const FRAME_TICKS: u64 = 139_810;

pub const EVENT_COUNT: usize = eventCount(770, 2450);
pub const PROOF_FAST_EVENT_COUNT: usize = eventCount(350, 1030);
pub const ACTIONS: [EVENT_COUNT]action_schedule.Action = build(770, 2450);
pub const PROOF_FAST_ACTIONS: [PROOF_FAST_EVENT_COUNT]action_schedule.Action =
    build(350, 1030);
/// PE-AGI records Boolean A-button state; the runner commits hardware P1 bits.
pub const BENCHMARK_ACTIONS = [_]action_schedule.Action{
    .{ .mcycle = 6_165_930, .pressed = joypad.Key.a.mask() },
    .{ .mcycle = 6_166_336, .pressed = 0 },
    .{ .mcycle = 6_166_723, .pressed = joypad.Key.a.mask() },
    .{ .mcycle = 6_291_448, .pressed = 0 },
    .{ .mcycle = 6_291_693, .pressed = joypad.Key.a.mask() },
    .{ .mcycle = 6_354_743, .pressed = 0 },
    .{ .mcycle = 6_354_988, .pressed = joypad.Key.a.mask() },
    .{ .mcycle = 6_401_360, .pressed = 0 },
    .{ .mcycle = 6_401_747, .pressed = joypad.Key.a.mask() },
    .{ .mcycle = 6_483_197, .pressed = 0 },
    .{ .mcycle = 6_483_442, .pressed = joypad.Key.a.mask() },
    .{ .mcycle = 6_546_482, .pressed = 0 },
    .{ .mcycle = 6_546_727, .pressed = joypad.Key.a.mask() },
    .{ .mcycle = 6_592_933, .pressed = 0 },
    .{ .mcycle = 6_593_320, .pressed = joypad.Key.a.mask() },
    .{ .mcycle = 6_674_050, .pressed = 0 },
    .{ .mcycle = 6_674_295, .pressed = joypad.Key.a.mask() },
    .{ .mcycle = 6_736_238, .pressed = 0 },
    .{ .mcycle = 6_736_483, .pressed = joypad.Key.a.mask() },
    .{ .mcycle = 6_810_461, .pressed = 0 },
    .{ .mcycle = 6_810_848, .pressed = joypad.Key.a.mask() },
    .{ .mcycle = 6_890_953, .pressed = 0 },
    .{ .mcycle = 6_891_198, .pressed = joypad.Key.a.mask() },
    .{ .mcycle = 6_954_238, .pressed = 0 },
    .{ .mcycle = 6_954_483, .pressed = joypad.Key.a.mask() },
    .{ .mcycle = 7_066_632, .pressed = 0 },
    .{ .mcycle = 7_067_019, .pressed = joypad.Key.a.mask() },
    .{ .mcycle = 7_087_846, .pressed = 0 },
    .{ .mcycle = 7_088_233, .pressed = joypad.Key.a.mask() },
    .{ .mcycle = 7_396_294, .pressed = 0 },
    .{ .mcycle = 7_396_681, .pressed = joypad.Key.a.mask() },
    .{ .mcycle = 7_402_164, .pressed = 0 },
    .{ .mcycle = 7_402_551, .pressed = joypad.Key.a.mask() },
};

fn eventCount(comptime first: u32, comptime last: u32) usize {
    return (last - first) / FRAME_STEP + 1;
}

fn build(comptime first: u32, comptime last: u32) [eventCount(first, last)]action_schedule.Action {
    var result: [eventCount(first, last)]action_schedule.Action = undefined;
    for (&result, 0..) |*action, index| {
        const frame_index = first + @as(u32, @intCast(index)) * FRAME_STEP;
        action.* = .{
            .mcycle = eventMcycle(frame_index),
            .pressed = pressedMask(frame_index),
        };
    }
    return result;
}

test "proof-fast action schedule starts by releasing captured A" {
    try std.testing.expectEqual(@as(usize, 69), PROOF_FAST_ACTIONS.len);
    try std.testing.expectEqual(
        action_schedule.Action{ .mcycle = 6_134_164, .pressed = 0 },
        PROOF_FAST_ACTIONS[0],
    );
    try std.testing.expectEqual(
        action_schedule.Action{ .mcycle = 18_018_014, .pressed = 0 },
        PROOF_FAST_ACTIONS[PROOF_FAST_ACTIONS.len - 1],
    );

    const masks = [_]u8{
        0,
        joypad.Key.start.mask(),
        0,
        joypad.Key.a.mask(),
    };
    for (PROOF_FAST_ACTIONS, 0..) |action, index| {
        if (index != 0)
            try std.testing.expect(
                PROOF_FAST_ACTIONS[index - 1].mcycle < action.mcycle,
            );
        try std.testing.expectEqual(masks[index % masks.len], action.pressed);
    }
}

test "benchmark action schedule is exact alternating accepted polls" {
    try std.testing.expectEqual(@as(usize, 33), BENCHMARK_ACTIONS.len);
    try std.testing.expectEqual(@as(u32, 6_165_930), BENCHMARK_ACTIONS[0].mcycle);
    try std.testing.expectEqual(@as(u32, 7_402_551), BENCHMARK_ACTIONS[32].mcycle);
    for (BENCHMARK_ACTIONS, 0..) |action, index| {
        if (index != 0)
            try std.testing.expect(BENCHMARK_ACTIONS[index - 1].mcycle < action.mcycle);
        const expected = if (index & 1 == 0) joypad.Key.a.mask() else 0;
        try std.testing.expectEqual(expected, action.pressed);
    }
}

fn eventMcycle(frame_index: u32) u32 {
    const ticks = (@as(u64, frame_index) + 1) * FRAME_TICKS;
    return @intCast((ticks + 7) / 8);
}

fn pressedMask(frame_index: u32) u8 {
    return switch (frame_index % 40) {
        10, 30 => 0,
        20 => joypad.Key.a.mask(),
        0 => joypad.Key.start.mask(),
        else => unreachable,
    };
}

test "pinned battle action schedule is complete and canonical" {
    try std.testing.expectEqual(@as(usize, 169), ACTIONS.len);
    try std.testing.expectEqual(
        action_schedule.Action{ .mcycle = 13_474_189, .pressed = 0 },
        ACTIONS[0],
    );
    try std.testing.expectEqual(
        action_schedule.Action{ .mcycle = 42_834_289, .pressed = 0 },
        ACTIONS[ACTIONS.len - 1],
    );

    const masks = [_]u8{
        0,
        joypad.Key.a.mask(),
        0,
        joypad.Key.start.mask(),
    };
    for (ACTIONS, 0..) |action, index| {
        if (index != 0)
            try std.testing.expect(ACTIONS[index - 1].mcycle < action.mcycle);
        try std.testing.expectEqual(masks[index % masks.len], action.pressed);
    }
}
