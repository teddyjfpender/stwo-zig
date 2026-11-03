//! OM31 raw-Blake channel scheduling. No numerical feedback crosses the host.
//! A checked terminal snapshot is necessary before proof publication.
const std = @import("std");
const runtime = @import("stwo_cuda_backend").runtime;
const abi = @import("abi.zig");
const Slice = runtime.column.DeviceSlice(u32);
pub const Snapshot = extern struct {
    digest: [8]u32,
    draws: u32,
    cursor: u32,
    status: u32,
    reserved: u32,
    chain: u64,
    padding: [2]u32,
    pub fn validate(self: Snapshot, cursor: u32, chain: u64) !void {
        if (self.status != 0 or self.cursor != cursor or self.chain != chain or self.reserved != 0 or self.padding[0] != 0 or self.padding[1] != 0) return error.InvalidDeviceTranscript;
    }
};
comptime {
    if (@sizeOf(Snapshot) != 64 or @offsetOf(Snapshot, "chain") != 48) @compileError("OM31 channel snapshot ABI mismatch");
}
pub const NativeCommands = Commands(runtime.NativeContext, abi);
pub fn Commands(comptime Context: type, comptime Api: type) type {
    return struct {
        const Self = @This();
        context: *Context,
        lane_index: u32,
        state: Slice,
        step: u32 = 0,
        chain: u64 = 0,
        initialized: bool = false,
        poisoned: bool = false,
        fn handle(self: *Self) !*anyopaque {
            if (self.poisoned) return error.JobPoisoned;
            if (comptime @hasDecl(Context, "prepareKernelEnqueue")) try self.context.prepareKernelEnqueue();
            const lane = try self.context.lane(self.lane_index);
            try self.context.validateLane(lane);
            return @ptrFromInt(lane.owner);
        }
        fn statePointer(self: *Self) ![*]u32 {
            if (self.state.address % @alignOf(Snapshot) != 0) return error.InvalidDeviceAddress;
            return self.context.deviceSlicePointer(u32, self.state, abi.channel_state_words);
        }
        fn finish(self: *Self, status: c_int) !void {
            if (status != 0) {
                self.poisoned = true;
                return error.CudaEnqueueFailed;
            }
            if (comptime @hasDecl(Context, "recordKernels")) self.context.recordKernels(1) catch |err| {
                self.poisoned = true;
                return err;
            };
        }
        pub fn initialize(self: *Self, seed: Slice, chain: u64) !void {
            if (self.initialized) return error.ChannelAlreadyInitialized;
            const owner = try self.handle();
            try self.finish(Api.stwo_rv64_channel_init_on(owner, self.lane_index, try self.statePointer(), try self.context.deviceSlicePointer(u32, seed, 9), chain));
            self.initialized = true;
            self.chain = chain;
        }
        fn begin(self: *Self) !*anyopaque {
            const owner = try self.handle();
            if (!self.initialized) return error.ChannelNotInitialized;
            if (self.step == std.math.maxInt(u32)) return error.TranscriptStepOverflow;
            return owner;
        }
        pub fn mix(self: *Self, input: ?Slice, field: bool, next: u64, boundary: Slice) !void {
            const count = if (input) |s| s.len else 0;
            if (count > (std.math.maxInt(u32) - 32) / 4) return error.InvalidGeometry;
            const owner = try self.begin();
            const source: ?[*]const u32 = if (count == 0) null else try self.context.deviceSlicePointer(u32, input.?, count);
            try self.finish(Api.stwo_rv64_channel_mix_on(owner, self.lane_index, try self.statePointer(), self.step, self.chain, next, source, @intCast(count), @intFromBool(field), try self.context.deviceSlicePointer(u32, boundary, abi.channel_state_words)));
            self.step += 1;
            self.chain = next;
        }
        pub fn draw(self: *Self, count: u32, output: Slice, next: u64, boundary: Slice) !void {
            if (count == 0 or count > 1 << 20) return error.InvalidGeometry;
            const owner = try self.begin();
            try self.finish(Api.stwo_rv64_channel_draw_on(owner, self.lane_index, try self.statePointer(), self.step, self.chain, next, count, try self.context.deviceSlicePointer(u32, output, @as(usize, count) * 8), try self.context.deviceSlicePointer(u32, boundary, abi.channel_state_words)));
            self.step += 1;
            self.chain = next;
        }
        pub fn drawQueries(self: *Self, log: u32, count: u32, output: Slice, next: u64, boundary: Slice) !void {
            if (log == 0 or log > 28 or count == 0 or count > 1024) return error.InvalidGeometry;
            const owner = try self.begin();
            try self.finish(Api.stwo_rv64_channel_queries_on(owner, self.lane_index, try self.statePointer(), self.step, self.chain, next, log, count, try self.context.deviceSlicePointer(u32, output, count), try self.context.deviceSlicePointer(u32, boundary, abi.channel_state_words)));
            self.step += 1;
            self.chain = next;
        }
        pub fn validateCompleted(self: *const Self, snapshot: Snapshot) !void {
            if (self.poisoned or !self.initialized) return error.JobPoisoned;
            try snapshot.validate(self.step, self.chain);
        }
    };
}
