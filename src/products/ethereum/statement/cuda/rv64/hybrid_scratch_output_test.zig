const std = @import("std");
const owner = @import("hybrid_scratch_output.zig");
const a = std.testing.allocator;

test "hybrid scratch derives only existing producer output with optional security prefix" {
    for ([_][:0]const u8{ "produce-candidate", "produce-control" }) |mode| {
        const args = [_][:0]const u8{ "driver", mode, "config", "-", "owned output", "0", "resources" };
        const directory = (try owner.directory(a, &args)).?;
        defer a.free(directory);
        try std.testing.expectEqualStrings("owned output/.gpu-hybrid", directory);
    }
    const selected = [_][:0]const u8{ "driver", "--security-profile", "not-parsed-by-scratch", "produce-candidate", "config", "-", "/owned-output", "0", "resources" };
    const directory = (try owner.directory(a, &selected)).?;
    defer a.free(directory);
    try std.testing.expectEqualStrings("/owned-output/.gpu-hybrid", directory);
}

test "hybrid scratch leaves canonical nonproducer and invalid CLI ownership to CPU dispatcher" {
    const cases = [_][]const [:0]const u8{
        &.{ "driver", "describe-candidate" },
        &.{ "driver", "verify-candidate", "config", "out", "1024" },
        &.{ "driver", "capture", "config", "-", "0", "resources" },
        &.{ "driver", "produce-candidate", "config", "-", "out", "0" },
        &.{ "driver", "bogus", "config", "-", "out", "0", "resources" },
        &.{ "driver", "--security-profile" },
    };
    var fail = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    for (cases) |args| try std.testing.expectEqual(@as(?[]u8, null), try owner.directory(fail.allocator(), args));
    try std.testing.expectEqual(@as(usize, 0), fail.allocated_bytes);
}
