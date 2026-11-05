const std = @import("std");
const Raw = @import("channel/raw_mod_m31.zig");
test "observer PCS copy handoff requires the authoritative channel object" {
    const Sink = struct {
        calls: usize = 0,
        checkpoint: ?Raw.Om31Checkpoint = null,
        fn start(_: *anyopaque, _: Raw.Om31Checkpoint) void {}
        fn record(_: *anyopaque, _: Raw.Om31Event, _: Raw.Om31Checkpoint) void {}
        fn before(raw: *anyopaque, value: Raw.Om31Checkpoint) !void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.calls += 1;
            self.checkpoint = value;
        }
        fn finish(_: *anyopaque) !void {}
        fn destroy(_: *anyopaque) void {}
    };
    var channel = Raw.Om31Channel.init();
    channel.mixU32s(&.{1, 2, 3});
    _ = channel.drawSecureFelt();
    var sink = Sink{};
    var observer = Raw.Om31Observer{ .context = &sink, .target = &channel, .start = Sink.start, .record = Sink.record, .before_pcs = Sink.before, .finish = Sink.finish, .destroy = Sink.destroy };
    const previous = Raw.om31_observer;
    defer Raw.om31_observer = previous;
    Raw.om31_observer = &observer;
    var copy = channel;
    try Raw.beforeDeviceOm31Pcs(&copy);
    try std.testing.expectEqual(@as(usize, 0), sink.calls);
    try std.testing.expect(observer.target != null);
    try Raw.beforeDeviceOm31Pcs(&channel);
    try std.testing.expectEqual(@as(usize, 1), sink.calls);
    try std.testing.expectEqualDeep(Raw.om31Checkpoint(&channel), sink.checkpoint.?);
    try std.testing.expect(observer.target == null);
    try Raw.beforeDeviceOm31Pcs(&channel);
    try std.testing.expectEqual(@as(usize, 1), sink.calls);
}
