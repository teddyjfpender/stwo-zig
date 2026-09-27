//! Cooperative cancellation between owned proof instances. A callback never
//! borrows or consumes PCS state; failure uses the producer's normal cleanup.
pub const Boundary = struct {
    context: *anyopaque,
    check: *const fn (*anyopaque) anyerror!void,
    pub fn require(self: ?Boundary) !void {
        if (self) |boundary| try boundary.check(boundary.context);
    }
};
