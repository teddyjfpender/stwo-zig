const std = @import("std");
const P = @import("protocol.zig");
pub const Encoded = struct {
    bytes: []u8,
    request: P.Old.Request,
    claims: P.Old.Claims,
    pub fn deinit(self: *Encoded, a: std.mem.Allocator) void {
        a.free(self.bytes);
        a.free(self.request.memory.initial);
        a.free(self.request.memory.terminal);
    }
};
