const std = @import("std");
const Lane = @import("prover/block_v5_joined_request_lane_v1.zig").Lane;
const Cache = @import("prover/block_v5_native_recursive_setup_cache_v1.zig").ForBackend(@import("stwo_cpu_backend").CpuBackend);
const Prepared = @import("recursion/block_v5_recursive_public_bus_v1.zig").Prepared;
fn cached(cache: *Cache, rows: *Prepared) anyerror!Cache.Proved {
    return cache.provePrepared(rows);
}
fn consuming(cache: *Cache, rows: *Prepared) anyerror!Cache.Proved {
    return cache.provePreparedConsuming(rows);
}
fn destroy(cache: *Cache) void {
    cache.deinit();
}

test "joined request lane actual canonical native setup cache callbacks compile without invocation" {
    inline for (.{ &cached, &consuming, &destroy }) |callback| std.mem.doNotOptimizeAway(callback);
}

test "joined request lane reuses one thread and preserves caller-owned results across failures" {
    var lane = Lane{};
    defer lane.shutdown() catch unreachable;
    const Request = struct {
        thread: ?std.Thread.Id = null,
        expected: ?std.Thread.Id = null,
        failure: ?anyerror = null,
        fail: bool = false,
        value: usize = 0,
        fn run(raw: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.thread = std.Thread.getCurrentId();
            if (self.expected) |id| if (id != self.thread.?) {
                self.failure = error.RequestThreadChanged;
                return;
            };
            if (self.fail) self.failure = error.SyntheticRequestFailure else self.value += 1;
        }
    };
    var request = Request{};
    try lane.run(&request, Request.run, 256 * 1024);
    try std.testing.expect(request.thread.? != std.Thread.getCurrentId());
    request.expected = request.thread;
    for (0..16) |_| try lane.run(&request, Request.run, 256 * 1024);
    request.fail = true;
    try lane.run(&request, Request.run, 256 * 1024);
    try std.testing.expectEqual(error.SyntheticRequestFailure, request.failure.?);
    request.fail = false;
    request.failure = null;
    try lane.run(&request, Request.run, 256 * 1024);
    try std.testing.expectEqual(@as(usize, 18), request.value);
    try std.testing.expectEqual(@as(u64, 1), lane.snapshot().starts);
    try std.testing.expectEqual(@as(u64, 19), lane.snapshot().completed);
    try std.testing.expect(!lane.snapshot().active);
}

test "joined request lane busy shutdown and second request cannot release an in-flight borrow" {
    var lane = Lane{};
    defer lane.shutdown() catch unreachable;
    const Request = struct {
        lane: *Lane,
        mutex: std.Thread.Mutex = .{},
        condition: std.Thread.Condition = .{},
        started: bool = false,
        release: bool = false,
        joined: bool = false,
        fn callback(raw: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.mutex.lock();
            defer self.mutex.unlock();
            self.started = true;
            self.condition.broadcast();
            while (!self.release) self.condition.wait(&self.mutex);
            self.joined = true;
        }
        fn caller(self: *@This()) void {
            self.lane.run(self, callback, 256 * 1024) catch @panic("request failed");
        }
    };
    var request = Request{ .lane = &lane };
    const caller = try std.Thread.spawn(.{}, Request.caller, .{&request});
    request.mutex.lock();
    while (!request.started) request.condition.wait(&request.mutex);
    request.mutex.unlock();
    try std.testing.expect(lane.snapshot().active);
    try std.testing.expectError(error.RequestLaneBusy, lane.run(&request, Request.callback, 256 * 1024));
    try std.testing.expectError(error.RequestLaneBusy, lane.shutdown());
    request.mutex.lock();
    request.release = true;
    request.condition.broadcast();
    request.mutex.unlock();
    caller.join();
    try std.testing.expect(request.joined);
    try lane.shutdown();
    try std.testing.expect(lane.snapshot().closed);
    try std.testing.expectEqual(@as(u64, 1), lane.snapshot().completed);
}

test "joined request lane rejects callback reentrancy without deadlocking the worker" {
    var lane = Lane{};
    defer lane.shutdown() catch unreachable;
    const Request = struct {
        lane: *Lane,
        failure: ?anyerror = null,
        fn callback(raw: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.lane.run(raw, callback, 256 * 1024) catch |err| {
                self.failure = err;
                return;
            };
        }
    };
    var request = Request{ .lane = &lane };
    try lane.run(&request, Request.callback, 256 * 1024);
    try std.testing.expectEqual(error.RequestLaneBusy, request.failure.?);
    try std.testing.expectEqual(@as(u64, 1), lane.snapshot().completed);
}

test "joined request lane never starts for empty work and cannot restart after joined shutdown" {
    var lane = Lane{};
    try lane.shutdown();
    try lane.shutdown();
    try std.testing.expectEqual(@as(u64, 0), lane.snapshot().starts);
    var calls: usize = 0;
    const Request = struct {
        fn callback(raw: *anyopaque) void {
            const count: *usize = @ptrCast(@alignCast(raw));
            count.* += 1;
        }
    };
    try std.testing.expectError(error.RequestLaneClosed, lane.run(&calls, Request.callback, 256 * 1024));
    try std.testing.expectEqual(@as(usize, 0), calls);
}
