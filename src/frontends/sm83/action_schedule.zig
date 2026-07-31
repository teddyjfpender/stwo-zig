//! Canonical public-input commitment for timestamped joypad actions.

const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Action = struct {
    mcycle: u32,
    pressed: u8,
};

pub const Error = error{
    InvalidSegmentRange,
    TooManyActions,
    ActionOutOfSegment,
    NonIncreasingActionTime,
};

pub const Digest = [Sha256.digest_length]u8;

const domain_tag = "stwo-zig/sm83/action-schedule/v1\x00";

pub fn validate(
    initial_mcycle: u32,
    final_mcycle: u32,
    actions: []const Action,
) Error!void {
    if (initial_mcycle >= final_mcycle)
        return error.InvalidSegmentRange;
    _ = std.math.cast(u32, actions.len) orelse
        return error.TooManyActions;

    var previous: ?u32 = null;
    for (actions) |action| {
        if (action.mcycle < initial_mcycle or
            action.mcycle >= final_mcycle)
            return error.ActionOutOfSegment;
        if (previous) |prior| {
            if (action.mcycle <= prior)
                return error.NonIncreasingActionTime;
        }
        previous = action.mcycle;
    }
}

pub fn digest(
    initial_mcycle: u32,
    final_mcycle: u32,
    actions: []const Action,
) Error!Digest {
    try validate(initial_mcycle, final_mcycle, actions);
    const count = std.math.cast(u32, actions.len) orelse
        return error.TooManyActions;

    var hasher = Sha256.init(.{});
    hasher.update(domain_tag);
    updateU32(&hasher, initial_mcycle);
    updateU32(&hasher, final_mcycle);
    updateU32(&hasher, count);
    for (actions) |action| {
        var record: [5]u8 = undefined;
        std.mem.writeInt(u32, record[0..4], action.mcycle, .little);
        record[4] = action.pressed;
        hasher.update(&record);
    }

    var result: Digest = undefined;
    hasher.final(&result);
    return result;
}

fn updateU32(hasher: *Sha256, value: u32) void {
    var encoded: [4]u8 = undefined;
    std.mem.writeInt(u32, &encoded, value, .little);
    hasher.update(&encoded);
}
