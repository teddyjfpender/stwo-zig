const std = @import("std");
const Backend = @import("blake2s_backend.zig");
const Observer = @import("blake2s_observer.zig");
const Capture = struct {
    events: [8]Observer.Event = undefined,
    count: usize = 0,
    fn record(raw: *anyopaque, event: Observer.Event) void {
        const self: *Capture = @ptrCast(@alignCast(raw));
        std.debug.assert(self.count < self.events.len);
        self.events[self.count] = event;
        self.count += 1;
    }
};
test "sampled Blake observer records pre-compression words counters and final flags without changing the digest" {
    var capture = Capture{};
    const previous = Observer.observer;
    const previous_phase = Observer.phase;
    defer {
        Observer.observer = previous;
        Observer.phase = previous_phase;
    }
    Observer.observer = .{ .context = &capture, .before_compress = Capture.record };
    Observer.phase = .sampled_values_mix;
    var bytes: [160]u8 = undefined;
    for (&bytes, 0..) |*b, i| b.* = @truncate(i);
    var hasher = Backend.Blake2sHasher.initWithMode(.scalar);
    hasher.update(bytes[0..32]);
    hasher.update(bytes[32..96]);
    hasher.update(bytes[96..]);
    const actual = hasher.finalize();
    var expected: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(&bytes, &expected, .{});
    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(@as(usize, 3), capture.count);
    try std.testing.expectEqual(@as(u32, 0x6a09e667 ^ 0x01010020), capture.events[0].h[0]);
    for (capture.events[0..3], 0..) |event, i| {
        try std.testing.expectEqual(@as(u32, @intCast(@min((i + 1) * 64, bytes.len))), event.t0);
        try std.testing.expectEqual(@as(u32, 0), event.t1);
        try std.testing.expectEqual(if (i == 2) std.math.maxInt(u32) else @as(u32, 0), event.final_word);
        var block: [64]u8 = @splat(0);
        const start = i * 64;
        const len = @min(64, bytes.len - start);
        @memcpy(block[0..len], bytes[start..][0..len]);
        for (event.message, 0..) |word, j| try std.testing.expectEqual(std.mem.readInt(u32, block[j * 4 ..][0..4], .little), word);
    }
}
test "sampled Blake observer ignores other phases and stays isolated between host threads" {
    var capture = Capture{};
    const previous = Observer.observer;
    const previous_phase = Observer.phase;
    defer {
        Observer.observer = previous;
        Observer.phase = previous_phase;
    }
    Observer.observer = .{ .context = &capture, .before_compress = Capture.record };
    Observer.phase = .none;
    var h = Backend.Blake2sHasher.init();
    h.update("unobserved");
    _ = h.finalize();
    try std.testing.expectEqual(@as(usize, 0), capture.count);
    const Worker = struct {
        fn run() !void {
            try std.testing.expect(Observer.observer == null);
            try std.testing.expectEqual(Observer.Phase.none, Observer.phase);
        }
    };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{});
    thread.join();
    Observer.phase = .sampled_values_mix;
    var observed = Backend.Blake2sHasher.init();
    observed.update("observed");
    _ = observed.finalize();
    try std.testing.expectEqual(@as(usize, 1), capture.count);
}
