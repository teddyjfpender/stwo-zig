//! Typed row sink for a bounded initial-RW shared-path proof chunk.
const std = @import("std");
pub const g = @import("../recursion/air/blake3_g_call.zig");
pub const xor = @import("../recursion/air/blake3_xor_call.zig");
pub const boundary = @import("../recursion/air/blake3_boundary.zig");
pub const route = @import("../recursion/air/blake3_byte_route.zig");
pub const private = @import("../recursion/air/blake3_private_word.zig");
pub const bridge = @import("../recursion/air/blake3_input_bridge.zig");

pub const Rows = struct {
    allocator: std.mem.Allocator,
    g_rows: std.ArrayList(g.Row) = .empty,
    xor_rows: std.ArrayList(xor.Row) = .empty,
    boundary_rows: std.ArrayList(boundary.Row) = .empty,
    route_rows: std.ArrayList(route.Row) = .empty,
    private_rows: std.ArrayList(private.Row) = .empty,
    bridge_rows: std.ArrayList(bridge.Row) = .empty,

    pub fn init(a: std.mem.Allocator) Rows { return .{ .allocator = a }; }
    pub fn deinit(self: *Rows) void {
        self.g_rows.deinit(self.allocator);
        self.xor_rows.deinit(self.allocator);
        self.boundary_rows.deinit(self.allocator);
        self.route_rows.deinit(self.allocator);
        self.private_rows.deinit(self.allocator);
        self.bridge_rows.deinit(self.allocator);
        self.* = undefined;
    }
    pub fn append(self: *Rows, comptime Air: type, rows: []const Air.Row) !void {
        const target = if (Air == g) &self.g_rows else if (Air == xor) &self.xor_rows else if (Air == boundary) &self.boundary_rows else if (Air == route) &self.route_rows else if (Air == private) &self.private_rows else if (Air == bridge) &self.bridge_rows else @compileError("unknown RW hash component");
        try target.appendSlice(self.allocator, rows);
    }
};
