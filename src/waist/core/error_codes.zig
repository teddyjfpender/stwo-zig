const std = @import("std");

/// Diagnostic metadata only; never part of a proof or transcript.
pub const Class = enum { invalid_input, verification_failed, resource_exhausted, unsupported, internal };
pub const Entry = struct { tag: []const u8, code: u16, class: Class, since: []const u8 };

pub const table = [_]Entry{
    .{ .tag = "InvalidLastLayerDegreeBound", .code = 0x1001, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "InvalidBlowupFactor", .code = 0x1002, .class = .invalid_input, .since = "1.0.0-rc.2" },
};

pub fn fromFriConfig(err: @import("fri/config.zig").FriConfig.Error) Entry {
    return switch (err) {
        error.InvalidLastLayerDegreeBound => table[0],
        error.InvalidBlowupFactor => table[1],
    };
}

pub fn lookup(code: u16) ?Entry {
    for (table) |entry| if (entry.code == code) return entry;
    return null;
}

test "api signature: boundary metadata uses u16 codes and stable class tags" {
    try std.testing.expect(@typeInfo(Entry).@"struct".fields[1].type == u16);
    const names = [_][]const u8{ "invalid_input", "verification_failed", "resource_exhausted", "unsupported", "internal" };
    try std.testing.expectEqual(names.len, std.meta.fields(Class).len);
    inline for (std.meta.fields(Class), 0..) |field, i| try std.testing.expectEqualStrings(names[i], field.name);
}

test "core FRI configuration diagnostics retain exact typed origin and meanings" {
    const F = @import("fri/config.zig").FriConfig;
    try std.testing.expect(@typeInfo(@TypeOf(fromFriConfig)).@"fn".params[0].type.? == F.Error);
    const invalid_degree = F.init(11, 1, 70) catch |err| {
        const entry = fromFriConfig(err);
        try std.testing.expectEqual(@as(u16, 0x1001), entry.code);
        try std.testing.expectEqualStrings("InvalidLastLayerDegreeBound", entry.tag);
        try std.testing.expectEqual(Class.invalid_input, entry.class);
        try std.testing.expectEqualStrings("1.0.0-rc.2", entry.since);
        try std.testing.expectEqualStrings(entry.tag, lookup(entry.code).?.tag);
        return;
    };
    _ = invalid_degree;
    return error.ExpectedRejection;
}

test "core FRI configuration codes reject foreign IDs without changing admission" {
    const F = @import("fri/config.zig").FriConfig;
    try std.testing.expectError(error.InvalidBlowupFactor, F.init(0, 0, 70));
    try std.testing.expectEqual(@as(u16, 0x1002), fromFriConfig(error.InvalidBlowupFactor).code);
    try std.testing.expectEqualStrings("InvalidBlowupFactor", fromFriConfig(error.InvalidBlowupFactor).tag);
    try std.testing.expectEqual(Class.invalid_input, fromFriConfig(error.InvalidBlowupFactor).class);
    try std.testing.expectEqualStrings("1.0.0-rc.2", fromFriConfig(error.InvalidBlowupFactor).since);
    try std.testing.expectEqual(@as(u32, 1), (try F.init(0, 1, 70)).log_blowup_factor);
    for ([_]u16{ 0, 0x1000, 0x1003, 0x2001, 0x4001, 0x5002, 65535 }) |code| try std.testing.expect(lookup(code) == null);
}
