//! Ordered asynchronous capacity leaves from genuinely fresh owned captures.
//! No native replay, warm PCS or source proof survives enqueueProof.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Native = @import("block_v5_native_capacity_proof_v1.zig");
const Prepared = @import("block_v5_native_capacity_recursive_admission_v1.zig").Prepared;
const Stage = @import("block_v5_native_capacity_recursive_stage_v1.zig");
const Owned = @import("block_v5_owned_ordered_queue_v1.zig");
const Boundary = @import("block_v5_proof_boundary_v1.zig").Boundary;
pub const Options = Owned.Options;
pub const Statistics = Owned.Statistics;
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Self = @This();
        const Leaf = Stage.ForBackend(Backend);
        const Queue = Owned.ForPayload(Native.VerifiedCapture);
        a: std.mem.Allocator,
        /// All independent shape/public/catalog/seal arrays survive finish.
        prepared: []const Prepared,
        options: Leaf.Options,
        sink: Stage.Sink,
        queue: *Queue,
        pub fn start(a: std.mem.Allocator, pool: *engine.work_pool.WorkPool, prepared: []const Prepared, options: Leaf.Options, sink: Stage.Sink, queue_options: Options, external: ?Boundary) !*Self {
            const expected = std.math.cast(u32, prepared.len) orelse return error.InvalidV5CapacityLeafQueueCount;
            const self = try a.create(Self);
            errdefer a.destroy(self);
            // Do not validate every Prepared here: each genuine capture/public
            // path revalidates its complete immutable admission before use.
            self.* = .{ .a = a, .prepared = prepared, .options = options, .sink = sink, .queue = undefined };
            self.queue = try Queue.start(a, pool, expected, .{ .context = self, .run = publish, .destroy = destroy }, queue_options, external);
            return self;
        }
        pub fn deinit(self: *Self) void {
            self.queue.deinit();
            self.a.destroy(self);
        }
        pub fn abort(self: *Self) void {
            self.queue.abort();
        }
        pub fn finish(self: *Self) !Statistics {
            return self.queue.finish();
        }
        pub fn requireHealthy(self: *Self) !void {
            try self.queue.requireHealthy();
            if (self.options.boundary) |boundary_| try boundary_.check(boundary_.context);
        }
        pub fn boundary(self: *Self) Boundary {
            return .{ .context = self, .check = checkBoundary };
        }
        fn checkBoundary(raw: *anyopaque) !void {
            const self: *Self = @ptrCast(@alignCast(raw));
            try self.requireHealthy();
        }
        pub fn snapshot(self: *Self) Statistics {
            return self.queue.snapshot();
        }
        /// Called while original native proof is live. Backpressure precedes
        /// verification allocations; capture is transferred exactly once.
        pub fn enqueueProof(self: *Self, index: u32, proof: *const Native.Proof) !void {
            try self.queue.waitForSlot(index);
            if (index >= self.prepared.len or self.prepared[index].index != index) return error.InvalidV5CapacityLeafQueueOrder;
            var options = self.options;
            options.boundary = self.boundary();
            var capture = try Leaf.captureNative(self.a, proof, &self.prepared[index], options);
            var owns = true;
            defer if (owns) capture.deinit();
            try self.queue.submit(index, &capture);
            owns = false;
        }
        fn publish(raw: *anyopaque, index: u32, capture: *Native.VerifiedCapture) !void {
            const self: *Self = @ptrCast(@alignCast(raw));
            if (index >= self.prepared.len or self.prepared[index].index != index) return error.InvalidV5CapacityLeafQueueOrder;
            var options = self.options;
            options.boundary = self.boundary();
            try Leaf.publishFromVerifiedCapture(self.a, capture, &self.prepared[index], options, self.sink);
        }
        fn destroy(_: *anyopaque, capture: *Native.VerifiedCapture) void {
            capture.deinit();
        }
    };
}
