const std = @import("std");

/// Diagnostic metadata only; never part of a proof or transcript.
pub const Class = enum { invalid_input, verification_failed, resource_exhausted, unsupported, internal };
pub const Entry = struct { tag: []const u8, code: u16, class: Class, since: []const u8 };

test "api signature: boundary metadata uses u16 codes and stable class tags" {
    try std.testing.expect(@typeInfo(Entry).@"struct".fields[1].type == u16);
    const names = [_][]const u8{ "invalid_input", "verification_failed", "resource_exhausted", "unsupported", "internal" };
    try std.testing.expectEqual(names.len, std.meta.fields(Class).len);
    inline for (std.meta.fields(Class), 0..) |field, i| try std.testing.expectEqualStrings(names[i], field.name);
}
