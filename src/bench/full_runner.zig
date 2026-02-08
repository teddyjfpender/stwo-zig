const std = @import("std");

pub const FAMILY_NAMES = [_][]const u8{
    "bit_rev",
    "eval_at_point",
    "barycentric_eval_at_point",
    "eval_at_point_by_folding",
    "fft",
    "field",
    "fri",
    "lookups",
    "merkle",
    "prefix_sum",
    "pcs",
};

pub fn listFamilies(writer: anytype) !void {
    const rendered = try std.json.Stringify.valueAlloc(std.heap.page_allocator, FAMILY_NAMES, .{});
    defer std.heap.page_allocator.free(rendered);
    try writer.writeAll(rendered);
    try writer.writeAll("\n");
}

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var mode: ?[]const u8 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (!std.mem.startsWith(u8, arg, "--")) return error.InvalidArgument;
        if (i + 1 >= args.len) return error.MissingArgumentValue;
        const value = args[i + 1];
        i += 1;
        if (std.mem.eql(u8, arg, "--mode")) {
            mode = value;
        } else {
            return error.InvalidArgument;
        }
    }

    const selected_mode = mode orelse return error.MissingMode;
    if (std.mem.eql(u8, selected_mode, "list-families")) {
        try listFamilies(std.fs.File.stdout());
        return;
    }
    return error.InvalidMode;
}

test "bench full runner: family list is stable and unique" {
    try std.testing.expectEqual(@as(usize, 11), FAMILY_NAMES.len);
    for (FAMILY_NAMES, 0..) |lhs, i| {
        for (FAMILY_NAMES[(i + 1)..]) |rhs| {
            try std.testing.expect(!std.mem.eql(u8, lhs, rhs));
        }
    }
}
