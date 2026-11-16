//! Own only this request's files inside the producer's already-claimed output.
const std = @import("std");
pub const Kind = enum { pcs, composition };
pub const Request = struct {
    allocator: std.mem.Allocator,
    input: []u8,
    output: []u8,
    pub fn init(a: std.mem.Allocator, directory: []const u8, kind: Kind, ordinal: u64) !Request {
        if (directory.len == 0) return error.MissingHybridProducerOutput;
        const input = try std.fmt.allocPrint(a, "{s}/{s}-{d}.{s}", .{ directory, @tagName(kind), ordinal, if (kind == .pcs) "input" else "in" });
        errdefer a.free(input);
        const output = try std.fmt.allocPrint(a, "{s}/{s}-{d}.{s}", .{ directory, @tagName(kind), ordinal, if (kind == .pcs) "output" else "out" });
        errdefer a.free(output);
        // Do not recursively create the producer's OUT: its dispatcher owns it.
        std.fs.cwd().makeDir(directory) catch |err| switch (err) {
            error.PathAlreadyExists => {},
            else => return err,
        };
        var in = try std.fs.cwd().createFile(input, .{ .exclusive = true });
        in.close();
        errdefer std.fs.cwd().deleteFile(input) catch {};
        var out = try std.fs.cwd().createFile(output, .{ .exclusive = true });
        out.close();
        return .{ .allocator = a, .input = input, .output = output };
    }
    pub fn deinit(self: *Request, remove_files: bool) void {
        if (remove_files) {
            std.fs.cwd().deleteFile(self.input) catch {};
            std.fs.cwd().deleteFile(self.output) catch {};
        }
        self.allocator.free(self.input);
        self.allocator.free(self.output);
        self.* = undefined;
    }
};
test {
    _ = @import("subprocess_scratch_test.zig");
}
