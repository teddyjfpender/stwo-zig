//! Concrete source views shared by the R6 and R7 root pipelines. Every view,
//! including shape, sampled-value and local-proof buffers, is borrowed only
//! for a synchronous visitor call. A visitor must compile/copy before returning.
const std = @import("std");
const C = @import("../rv64_recursion/om31_poseidon/common.zig");
pub const View = union(enum) {
    cpu: @import("pure_p2_cpu_leaf_test.zig").ShapeView,
    catalog: @import("pure_p2_truth_leaf_test.zig").View,
    local_catalog: @import("truth_local_gkr/leaf_test.zig").View,
    miller: @import("pure_p2_tower_leaf_test.zig").View,
    local_miller: @import("miller_local_gkr/leaf_test.zig").View,
};
/// The adapter owns the allocation until take() transfers custody. On any
/// callback error the adapter still releases an untaken template exactly once.
pub const Template = struct {
    bytes: ?[]u8,
    pub fn take(self: *Template) ?[]u8 {
        const bytes = self.bytes;
        self.bytes = null;
        return bytes;
    }
    pub fn deinit(self: *Template, a: std.mem.Allocator) void {
        if (self.bytes) |bytes| a.free(bytes);
        self.bytes = null;
    }
};
pub const Pending = struct {
    ordinal: usize,
    main: [36]u8,
    receipt: ?[36]u8,
    claims: []const C.O,
    view: View,
    template: *Template,
    kind: []const u8,
};
pub const Sink = struct {
    context: ?*anyopaque,
    accept: *const fn (?*anyopaque, std.mem.Allocator, Pending) anyerror!void,
    pub fn run(self: Sink, a: std.mem.Allocator, pending: Pending) !void {
        return self.accept(self.context, a, pending);
    }
};
pub const SourceSink = struct {
    context: ?*anyopaque,
    accept: *const fn (?*anyopaque, std.mem.Allocator, usize, View) anyerror!void,
    pub fn run(self: SourceSink, a: std.mem.Allocator, ordinal: usize, view: View) !void {
        return self.accept(self.context, a, ordinal, view);
    }
};

test "OP root source template token linear take and failure custody" {
    const a = std.testing.allocator;
    var token = Template{ .bytes = try a.dupe(u8, "source-owned-template") };
    const owned = token.take() orelse return error.MissingTestTemplate;
    defer a.free(owned);
    try std.testing.expect(token.take() == null);
    token.deinit(a);
    token.deinit(a);
    try std.testing.expectEqualStrings("source-owned-template", owned);
    // An unsuccessful visitor has not taken custody; adapter cleanup owns it.
    var untaken = Template{ .bytes = try a.dupe(u8, "retained-on-error") };
    untaken.deinit(a);
    try std.testing.expect(untaken.bytes == null);
}
