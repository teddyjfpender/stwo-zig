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
