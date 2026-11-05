//! Borrow an existing GPU session inside its synchronous owner-thread callback.
//! A slice carries the session token and allocation generation. Every pointer
//! is checked against the session's scoped lease registry before kernel launch.
const std = @import("std");
const Runtime = @import("stwo_cuda_backend").runtime;
const Native = @import("pcs_native_abi.zig");
pub const Api = struct {
    allocate: Native.LeaseAllocate,
    release: Native.LeaseRelease,
    validate_range: Native.LeaseValidateRange,
    upload: Native.Upload,
    download: Native.Download,
    sync: Native.Sync,
    lane_stream: Native.LaneStream,
};
pub const Context = struct {
    session: *anyopaque,
    native_context: *anyopaque,
    token: u64,
    scope: [8]u32,
    api: *const Api,
    active: bool = true,
    uploaded_bytes: usize = 0,
    pub const Lane = struct { owner: usize, index: u32 };
    pub fn prepareKernelEnqueue(self: *Context) !void {
        if (!self.active or self.token == 0) return error.StageNotActive;
    }
    pub fn lane(self: *Context, index: u32) !Lane {
        try self.prepareKernelEnqueue();
        var stream: ?*anyopaque = null;
        if (self.api.lane_stream(self.native_context, index, &stream) != 0 or stream == null) return error.InvalidLane;
        return .{ .owner = @intFromPtr(self.native_context), .index = index };
    }
    pub fn validateLane(self: *Context, value: Lane) !void {
        try self.prepareKernelEnqueue();
        if (value.owner != @intFromPtr(self.native_context)) return error.InvalidLane;
    }
    pub fn deviceSlicePointer(self: *Context, comptime T: type, value: Runtime.column.DeviceSlice(T), count: usize) ![*]T {
        try self.prepareKernelEnqueue();
        if (@sizeOf(T) % 4 != 0) @compileError("session slices use whole native words");
        if (value.owner != self.token or value.generation == 0 or value.address == 0 or value.address % @alignOf(T) != 0 or count == 0 or count > value.len) return error.InvalidDeviceAddress;
        const words = try std.math.mul(usize, count, @sizeOf(T) / 4);
        if (self.api.validate_range(self.session, @ptrFromInt(value.address), words, self.token, value.generation, &self.scope) != 0) return error.InvalidDeviceAddress;
        return @ptrFromInt(value.address);
    }
    pub fn allocate(self: *Context, words: usize, kind: u32) !Native.Lease {
        try self.prepareKernelEnqueue();
        if (words == 0 or kind > 3) return error.InvalidDeviceAddress;
        var lease = Native.Lease{};
        if (self.api.allocate(self.session, words, kind, &self.scope, &lease) != 0) return error.CudaAllocationFailed;
        errdefer _ = self.api.release(self.session, &lease);
        _ = try self.borrow(lease);
        return lease;
    }
    pub fn borrow(self: *Context, lease: Native.Lease) !Runtime.column.DeviceSlice(u32) {
        if (lease.reserved != 0 or lease.kind > 3 or lease.words == null) return error.InvalidDeviceAddress;
        const value = Runtime.column.DeviceSlice(u32){ .address = @intFromPtr(lease.words.?), .len = std.math.cast(usize, lease.count) orelse return error.SizeOverflow, .owner = std.math.cast(usize, lease.context_token) orelse return error.SizeOverflow, .generation = lease.generation };
        _ = try self.deviceSlicePointer(u32, value, value.len);
        return value;
    }
    pub fn release(self: *Context, lease: *Native.Lease) !void {
        _ = try self.borrow(lease.*);
        if (self.api.release(self.session, lease) != 0) return error.CudaReleaseFailed;
    }
    pub fn upload(self: *Context, destination: Runtime.column.DeviceSlice(u32), values: []const u32) !void {
        const out = try self.deviceSlicePointer(u32, destination, values.len);
        const bytes = try std.math.mul(usize, values.len, 4);
        const total = try std.math.add(usize, self.uploaded_bytes, bytes);
        if (self.api.upload(self.native_context, @ptrCast(out), values.ptr, bytes) != 0) return error.CudaUploadFailed;
        self.uploaded_bytes = total;
    }
    /// Join once after metadata ingress before kernels on another lane. There
    /// are no synchronizations inside the numerical traversal itself.
    pub fn join(self: *Context) !void {
        try self.prepareKernelEnqueue();
        if (self.api.sync(self.native_context) != 0) return error.CudaJoinFailed;
    }
    pub fn download(self: *Context, source: Runtime.column.DeviceSlice(u32), values: []u32) !void {
        const from = try self.deviceSlicePointer(u32, source, values.len);
        if (self.api.download(self.native_context, values.ptr, @ptrCast(from), try std.math.mul(usize, values.len, 4)) != 0) return error.CudaDownloadFailed;
    }
};

test "borrowed session slices bind token generation range and proof namespace" {
    const State = struct {
        fn validate(_: *anyopaque, pointer: [*]const u32, words: u64, token: u64, generation: u64, scope: *const [8]u32) callconv(.c) c_int {
            const address = @intFromPtr(pointer);
            if (token != 3 or generation != 4 or !std.mem.allEqual(u32, scope, 7) or address < 4096 or address > 8192 or words > (8192 - address) / 4) return 1;
            return 0;
        }
        fn stream(_: *anyopaque, index: u32, out: *?*anyopaque) callconv(.c) c_int {
            if (index > 1) return 1;
            out.* = @ptrFromInt(16);
            return 0;
        }
    };
    const api = Api{ .validate_range = State.validate, .lane_stream = State.stream, .allocate = undefined, .release = undefined, .upload = undefined, .download = undefined, .sync = undefined };
    var context = Context{ .session = @ptrFromInt(1), .native_context = @ptrFromInt(16384), .token = 3, .scope = @splat(7), .api = &api };
    const lease = Native.Lease{ .context_token = 3, .generation = 4, .words = @ptrFromInt(4096), .count = 1024, .kind = 1 };
    const source = try context.borrow(lease);
    const sub = try source.sub(512, 512);
    try std.testing.expectEqual(@as(usize, 6144), @intFromPtr(try context.deviceSlicePointer(u32, sub, 512)));
    const lane = try context.lane(1);
    try std.testing.expectEqual(@as(usize, 16384), lane.owner);
    try context.validateLane(lane);
    var bad = source;
    bad.generation += 1;
    try std.testing.expectError(error.InvalidDeviceAddress, context.deviceSlicePointer(u32, bad, 1));
    bad = source;
    bad.owner += 1;
    try std.testing.expectError(error.InvalidDeviceAddress, context.deviceSlicePointer(u32, bad, 1));
    bad = source;
    bad.address += 4096;
    try std.testing.expectError(error.InvalidDeviceAddress, context.deviceSlicePointer(u32, bad, 1));
    context.scope[0] += 1;
    try std.testing.expectError(error.InvalidDeviceAddress, context.borrow(lease));
    context.scope[0] -= 1;
    context.active = false;
    try std.testing.expectError(error.StageNotActive, context.borrow(lease));
}
