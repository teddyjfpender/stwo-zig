//! Bounded producer-only CPU metadata parking DURING ordered capture. No key,
//! public statement, source geometry, transcript or source-suite admission changes.
const std = @import("std");
const Capture = @import("../pure_p2_op_capture.zig");
const Parking = @import("../pure_p2_cpu_metadata_parking.zig");
const Store = @import("../pure_p2_retained_main.zig").Store;
const Native = @import("../../word16_execution/prepared.zig").Prepared;
pub const Owner = struct {
    store: *Store,
    tokens: [256]?Parking.Token = @splat(null),
    count: usize = 0,
    bytes: usize = 0,
    pub fn deinit(self: *Owner) void {
        for (self.tokens[0..self.count]) |*token| if (token.*) |*value| value.deinit();
        self.count = 0;
    }
    pub fn hooks(self: *Owner) Capture.Hooks {
        return .{ .context = self, .completed = completed };
    }
    fn completed(raw: ?*anyopaque, ordinal: usize, native: *Native) !void {
        const self: *Owner = @ptrCast(@alignCast(raw orelse return error.OpCaptureCustodyContext));
        if (ordinal != self.count or self.count >= self.tokens.len) return error.OpCaptureCustodyOrder;
        const cpu = if (native.cpu) |*value| value else return error.PreparedExecutionConsumed;
        const bytes = try std.math.add(usize, self.bytes, try Parking.roundedBytes(cpu));
        // park is failure-atomic: allocation/I/O/quota errors retain CPU owner.
        self.tokens[self.count] = try Parking.park(self.store, cpu);
        self.bytes = bytes;
        self.count += 1;
    }
    /// Borrowed until native proof completion. This owner closes files after
    /// the worker sources have released every restored heap view.
    pub fn slice(self: *Owner) []?Parking.Token {
        return self.tokens[0..self.count];
    }
};
