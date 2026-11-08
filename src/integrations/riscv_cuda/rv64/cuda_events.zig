//! CUDA stream timing only. Resolve after the owner's existing completion join;
//! recording and querying these spans never introduces a synchronization.
const std = @import("std");
pub const Api = struct {
    create: *const fn (*?*anyopaque, u32) callconv(.c) c_int,
    record: *const fn (*anyopaque, *anyopaque) callconv(.c) c_int,
    elapsed: *const fn (*f32, *anyopaque, *anyopaque) callconv(.c) c_int,
    destroy: *const fn (*anyopaque) callconv(.c) c_int,
    pub fn load(library: *std.DynLib) !Api {
        return .{
            .create = library.lookup(@FieldType(Api, "create"), "stwo_rv64_event_create") orelse return error.MissingCudaTimingSymbol,
            .record = library.lookup(@FieldType(Api, "record"), "stwo_rv64_event_record") orelse return error.MissingCudaTimingSymbol,
            .elapsed = library.lookup(@FieldType(Api, "elapsed"), "stwo_rv64_event_elapsed") orelse return error.MissingCudaTimingSymbol,
            .destroy = library.lookup(@FieldType(Api, "destroy"), "stwo_rv64_event_destroy") orelse return error.MissingCudaTimingSymbol,
        };
    }
};
pub const Span = enum { ingress, base_fft, relation_draws, projection, traversal, readback };
pub fn RecorderFor(comptime SpanType: type) type {
    return struct {
        const Self = @This();
        api: *const Api,
        events: [2 * std.meta.fields(SpanType).len]?*anyopaque = @splat(null),
        pub fn init(api: *const Api) !Self {
            var out = Self{ .api = api };
            errdefer out.deinit();
            for (&out.events) |*event| if (api.create(event, 0) != 0 or event.* == null) return error.CudaTimingFailed;
            return out;
        }
        pub fn deinit(self: *Self) void {
            for (self.events) |event| if (event) |p| {
                _ = self.api.destroy(p);
            };
            self.events = @splat(null);
        }
        pub fn mark(self: *Self, span: SpanType, end: bool, stream: *anyopaque) !void {
            const event = self.events[2 * @as(usize, @intFromEnum(span)) + @intFromBool(end)] orelse return error.CudaTimingFailed;
            if (self.api.record(event, stream) != 0) return error.CudaTimingFailed;
        }
        pub fn milliseconds(self: *Self, span: SpanType) !f32 {
            var result: f32 = 0;
            const at = 2 * @as(usize, @intFromEnum(span));
            if (self.api.elapsed(&result, self.events[at].?, self.events[at + 1].?) != 0 or !std.math.isFinite(result) or result < 0) return error.CudaTimingFailed;
            return result;
        }
    };
}
pub const Recorder = RecorderFor(Span);

test "stream timing is nonblocking and unavailable events fail closed" {
    const Fake = struct {
        fn create(out: *?*anyopaque, flags: u32) callconv(.c) c_int {
            std.debug.assert(flags == 0);
            out.* = @ptrFromInt(16);
            return 0;
        }
        fn record(_: *anyopaque, stream: *anyopaque) callconv(.c) c_int {
            std.debug.assert(@intFromPtr(stream) == 32);
            return 0;
        }
        fn elapsed(out: *f32, _: *anyopaque, _: *anyopaque) callconv(.c) c_int {
            out.* = 2.5;
            return 0;
        }
        fn notReady(_: *f32, _: *anyopaque, _: *anyopaque) callconv(.c) c_int {
            return 34;
        }
        fn destroy(_: *anyopaque) callconv(.c) c_int {
            return 0;
        }
    };
    const api = Api{ .create = Fake.create, .record = Fake.record, .elapsed = Fake.elapsed, .destroy = Fake.destroy };
    var recorder = try Recorder.init(&api);
    defer recorder.deinit();
    inline for (comptime std.enums.values(Span)) |span| {
        try recorder.mark(span, false, @ptrFromInt(32));
        try recorder.mark(span, true, @ptrFromInt(32));
        try std.testing.expectEqual(@as(f32, 2.5), try recorder.milliseconds(span));
    }
    var pending = api;
    pending.elapsed = Fake.notReady;
    var incomplete = try Recorder.init(&pending);
    defer incomplete.deinit();
    try std.testing.expectError(error.CudaTimingFailed, incomplete.milliseconds(.traversal));
}
