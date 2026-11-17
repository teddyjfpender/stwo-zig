//! Optional arena-origin diagnostics; the runner retains the primary failure report.
const std = @import("std");

pub fn emitTo(writer: anytype, entry: anytype) void {
    var storage: [192]u8 = undefined;
    const line = std.fmt.bufPrint(&storage, "{{\"schema\":\"backend_arena_rejection_v1\",\"provider\":\"stwo_backend_contracts\",\"origin\":\"arena_plan.build\",\"code\":{d},\"class\":\"{s}\"}}\n", .{ entry.code, @tagName(entry.class) }) catch return;
    writer.writeAll(line) catch {};
}

test "arena process diagnostic is bounded and optional writer failure is ignored" {
    const Class = enum { resource_exhausted };
    const entry = .{ .code = @as(u16, 0x2008), .class = Class.resource_exhausted };
    var buffer: [192]u8 = undefined;
    var writer = std.Io.Writer.fixed(&buffer);
    emitTo(&writer, entry);
    try std.testing.expectEqualStrings("{\"schema\":\"backend_arena_rejection_v1\",\"provider\":\"stwo_backend_contracts\",\"origin\":\"arena_plan.build\",\"code\":8200,\"class\":\"resource_exhausted\"}\n", writer.buffered());
    const Failing = struct {
        calls: usize = 0,
        pub fn writeAll(self: *@This(), _: []const u8) error{DiagnosticUnavailable}!void {
            self.calls += 1;
            return error.DiagnosticUnavailable;
        }
    };
    var failure = Failing{};
    emitTo(&failure, entry);
    try std.testing.expectEqual(@as(usize, 1), failure.calls);
}
