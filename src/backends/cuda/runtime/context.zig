//! Proof-owned CUDA stream, pool, opaque buffers, and transfer accounting.

const std = @import("std");
const native_api = @import("../abi/runtime.zig");
const graph_execution = @import("graph_execution.zig");
const persistent_allocation = @import("persistent_allocation.zig");
const runtime_error = @import("error.zig");
const telemetry = @import("telemetry.zig");

pub const NativeContext = ContextFor(native_api);
pub const CreateOptions = native_api.ContextOptions;

pub fn ContextFor(comptime Api: type) type {
    return struct {
        const Self = @This();
        const max_allocations = 256;
        const Allocation = struct {
            address: usize = 0,
            bytes: usize = 0,
            generation: u64 = 0,
        };

        handle: ?*anyopaque,
        stream: *anyopaque,
        device: u32,
        lane_count: u32,
        identity: u64 = 0,
        owner_thread_id: std.Thread.Id = 0,
        lanes: [native_api.max_context_lanes]?*anyopaque = @splat(null),
        dependency_capacity: u32 = 0,
        dependencies: [native_api.max_context_dependencies]DependencySlot = @splat(.{}),
        live_dependencies: usize = 0,
        live_buffers: usize = 0,
        allocations: [max_allocations]Allocation =
            [_]Allocation{.{}} ** max_allocations,
        next_allocation_generation: u64 = 1,
        persistent_buffers: usize = 0,
        persistent_bytes: usize = 0,
        active_stage: ?telemetry.Stage = null,
        next_stage_index: usize = 0,
        synchronized: bool = true,
        capture_active: bool = false,
        teardown_pending: bool = false,
        counters: telemetry.Counters = .{},

        pub const Construction = union(enum) {
            ready: Self,
            released: void,
            failed: struct { cause: runtime_error.Error, teardown: ?Self = null },

            /// A failed cleanup still owns its native control node. On another
            /// teardown error the outcome remains intact for explicit retry.
            pub fn deinit(self: *Construction) runtime_error.Error!void {
                switch (self.*) {
                    .ready => |*owner| {
                        try owner.abort();
                        self.* = .released;
                    },
                    .released => {},
                    .failed => |*failure| if (failure.teardown) |*owner| {
                        try owner.abort();
                        failure.teardown = null;
                    },
                }
            }
        };

        pub const DependencySlot = struct {
            generation: u64 = 0,
            producer_lane: u32 = 0,
            active: bool = false,
        };
        pub const Lane = struct {
            owner: usize,
            context_identity: u64,
            index: u32,
            stream: *anyopaque,
        };
        pub const Dependency = struct {
            owner: usize,
            token: native_api.DependencyToken,
        };

        pub const Buffer = struct {
            pointer: [*]u32,
            words: usize,
            owner: usize,
            generation: u64,

            pub fn bytes(self: Buffer) runtime_error.Error!usize {
                return std.math.mul(usize, self.words, @sizeOf(u32)) catch
                    error.SizeOverflow;
            }
        };

        pub fn open() runtime_error.Error!Self {
            var raw_handle: ?*anyopaque = null;
            runtime_error.check(Api.stwo_exec_context_create(&raw_handle)) catch |err| {
                // Legacy error-union API has no failure-owner return channel.
                // Retry cleanup if the native constructor retained one; new
                // selected-device callers must use the owned outcome below.
                if (raw_handle) |handle| _ = Api.stwo_exec_context_destroy(handle);
                return err;
            };
            return finishOpen(raw_handle, .{});
        }

        /// Resource ownership only: compiled scheduled lanes remain disabled.
        /// A selected device becomes current on this owner thread on success.
        pub fn openOptions(options: CreateOptions) Construction {
            options.validate() catch |err| return .{ .failed = .{ .cause = err } };
            if (comptime @hasDecl(Api, "stwo_exec_context_create_options")) {
                var raw_handle: ?*anyopaque = null;
                runtime_error.check(Api.stwo_exec_context_create_options(&options, &raw_handle)) catch |err| {
                    return .{ .failed = .{ .cause = err, .teardown = if (raw_handle) |handle| teardownOnly(handle) else null } };
                };
                const handle = raw_handle orelse return .{ .failed = .{ .cause = error.NullExecutionContext } };
                const owner = readOpen(handle, options) catch |err| {
                    runtime_error.check(Api.stwo_exec_context_destroy(handle)) catch {
                        return .{ .failed = .{ .cause = err, .teardown = teardownOnly(handle) } };
                    };
                    return .{ .failed = .{ .cause = err } };
                };
                return .{ .ready = owner };
            } else return .{ .failed = .{ .cause = error.InvalidState } };
        }

        fn teardownOnly(handle: *anyopaque) Self {
            return .{ .handle = handle, .stream = undefined, .device = undefined, .lane_count = 0, .owner_thread_id = std.Thread.getCurrentId(), .teardown_pending = true };
        }

        fn finishOpen(raw_handle: ?*anyopaque, options: CreateOptions) runtime_error.Error!Self {
            const handle = raw_handle orelse return error.NullExecutionContext;
            errdefer _ = Api.stwo_exec_context_destroy(handle);
            return readOpen(handle, options);
        }

        fn readOpen(handle: *anyopaque, options: CreateOptions) runtime_error.Error!Self {
            var raw_stream: ?*anyopaque = null;
            try runtime_error.check(Api.stwo_exec_context_stream(handle, &raw_stream));
            const stream = raw_stream orelse return error.NullExecutionStream;
            var device: c_int = -1;
            try runtime_error.check(Api.stwo_exec_context_device(handle, &device));
            if (device < 0 or (options.device_ordinal != native_api.current_device and options.device_ordinal != @as(u32, @intCast(device)))) return error.InvalidDeviceOrdinal;
            var lane_count: u32 = 0;
            try runtime_error.check(Api.stwo_exec_context_lane_count(handle, &lane_count));
            if (lane_count != options.lane_count) return error.InvalidExecutionLaneCount;
            var result = Self{
                .handle = handle,
                .stream = stream,
                .device = @intCast(device),
                .lane_count = lane_count,
                .owner_thread_id = std.Thread.getCurrentId(),
                .dependency_capacity = options.dependency_capacity,
            };
            result.lanes[0] = stream;
            if (comptime @hasDecl(Api, "stwo_exec_context_identity")) {
                try runtime_error.check(Api.stwo_exec_context_identity(handle, &result.identity));
                if (result.identity == 0) return error.ContextMismatch;
            }
            if (comptime @hasDecl(Api, "stwo_exec_context_lane_stream")) {
                for (0..lane_count) |index| {
                    var lane_stream: ?*anyopaque = null;
                    try runtime_error.check(Api.stwo_exec_context_lane_stream(handle, @intCast(index), &lane_stream));
                    result.lanes[index] = lane_stream orelse return error.NullExecutionStream;
                    if (index == 0 and result.lanes[index].? != stream) return error.ContextMismatch;
                    for (result.lanes[0..index]) |previous| {
                        if (previous == lane_stream) return error.ContextMismatch;
                    }
                }
            } else if (lane_count != 1 or options.dependency_capacity != 0) return error.InvalidExecutionLaneCount;
            return result;
        }

        /// The handle identifies real native stream ownership, not admitted
        /// scheduling capability. Callers must preserve this Context lifetime.
        pub fn lane(self: *Self, index: u32) runtime_error.Error!Lane {
            const handle = try self.requireHandle();
            if (self.capture_active or self.identity == 0) return error.InvalidState;
            if (index >= self.lane_count or index >= self.lanes.len) return error.InvalidExecutionLaneCount;
            const stream = self.lanes[index] orelse return error.NullExecutionStream;
            // A borrowed stream can enqueue work outside this wrapper. Keep
            // teardown fenced even when no wrapper launch counter changes.
            self.synchronized = false;
            return .{ .owner = @intFromPtr(handle), .context_identity = self.identity, .index = index, .stream = stream };
        }

        pub fn validateLane(self: *Self, selected: Lane) runtime_error.Error!void {
            const handle = try self.requireHandle();
            if (self.capture_active) return error.InvalidState;
            if (self.identity == 0 or selected.owner != @intFromPtr(handle) or selected.context_identity != self.identity) return error.ContextMismatch;
            if (selected.index >= self.lane_count or selected.index >= self.lanes.len) return error.InvalidExecutionLaneCount;
            if (self.lanes[selected.index] != selected.stream) return error.ContextMismatch;
        }

        pub fn validateDependency(self: *Self, dependency: Dependency) runtime_error.Error!void {
            const handle = try self.requireHandle();
            if (self.capture_active) return error.InvalidState;
            const token = dependency.token;
            if (self.identity == 0 or dependency.owner != @intFromPtr(handle) or token.context_identity != self.identity or token.generation == 0) return error.ContextMismatch;
            if (token.slot >= self.dependency_capacity or token.slot >= self.dependencies.len or token.producer_lane >= self.lane_count) return error.ContextMismatch;
            const admitted = self.dependencies[token.slot];
            if (!admitted.active or admitted.generation != token.generation or admitted.producer_lane != token.producer_lane) return error.ContextMismatch;
        }

        pub fn recordDependency(self: *Self, producer: Lane, slot: u32) runtime_error.Error!Dependency {
            try self.validateLane(producer);
            if (self.active_stage == null) return error.StageNotActive;
            if (slot >= self.dependency_capacity or slot >= self.dependencies.len) return error.InvalidExecutionLaneCount;
            const previous = self.dependencies[slot];
            if (previous.active) return error.InvalidState;
            if (previous.generation == std.math.maxInt(u64)) return error.SizeOverflow;
            if (comptime @hasDecl(Api, "stwo_exec_context_dependency_record")) {
                var token: native_api.DependencyToken = undefined;
                try runtime_error.check(Api.stwo_exec_context_dependency_record(try self.requireHandle(), producer.index, slot, &token));
                self.synchronized = false;
                if (token.context_identity != self.identity or token.slot != slot or token.producer_lane != producer.index or token.generation != previous.generation + 1) return error.ContextMismatch;
                self.dependencies[slot] = .{ .generation = token.generation, .producer_lane = producer.index, .active = true };
                self.live_dependencies += 1;
                return .{ .owner = producer.owner, .token = token };
            } else return error.InvalidState;
        }

        pub fn waitDependency(self: *Self, consumer: Lane, dependency: Dependency) runtime_error.Error!void {
            try self.validateLane(consumer);
            try self.validateDependency(dependency);
            if (self.active_stage == null) return error.StageNotActive;
            if (comptime @hasDecl(Api, "stwo_exec_context_dependency_wait")) {
                try runtime_error.check(Api.stwo_exec_context_dependency_wait(try self.requireHandle(), consumer.index, &dependency.token));
                self.synchronized = false;
            } else return error.InvalidState;
        }

        /// Terminal retirement synchronizes every producer and waiter lane
        /// before native event reuse. It is not a nonblocking reclamation API.
        pub fn releaseDependency(self: *Self, dependency: *Dependency) runtime_error.Error!void {
            try self.validateDependency(dependency.*);
            if (self.live_dependencies == 0) return error.InvalidState;
            if (comptime @hasDecl(Api, "stwo_exec_context_dependency_release")) {
                try runtime_error.check(Api.stwo_exec_context_dependency_release(try self.requireHandle(), &dependency.token));
                self.dependencies[dependency.token.slot].active = false;
                self.live_dependencies -= 1;
                self.synchronized = true;
                self.counters.sync(self.active_stage);
                dependency.* = .{ .owner = 0, .token = .{ .context_identity = 0, .generation = 0, .slot = 0, .producer_lane = 0 } };
            } else return error.InvalidState;
        }

        fn resetDependencies(self: *Self) runtime_error.Error!void {
            const handle = try self.requireHandle();
            if (self.capture_active) return error.InvalidState;
            if (comptime @hasDecl(Api, "stwo_exec_context_dependencies_reset")) {
                try runtime_error.check(Api.stwo_exec_context_dependencies_reset(handle));
                for (&self.dependencies) |*slot| slot.active = false;
                self.live_dependencies = 0;
                self.synchronized = true;
            } else if (self.live_dependencies != 0 or self.lane_count != 1) return error.InvalidState;
        }

        pub fn close(self: *Self) runtime_error.Error!void {
            const handle = try self.requireControl();
            if (self.teardown_pending) {
                try runtime_error.check(Api.stwo_exec_context_destroy(handle));
                self.handle = null;
                return;
            }
            if (self.live_dependencies != 0) return error.InvalidState;
            if (self.live_buffers != 0) return error.DeviceBufferLive;
            if (self.active_stage != null) return error.StageAlreadyActive;
            if (self.capture_active) return error.InvalidState;
            if (!self.synchronized) try self.sync();
            self.teardown_pending = true;
            try runtime_error.check(Api.stwo_exec_context_destroy(handle));
            self.handle = null;
        }

        pub fn beginProof(self: *Self) runtime_error.Error!void {
            _ = try self.requireHandle();
            if (self.live_buffers != self.persistent_buffers)
                return error.DeviceBufferLive;
            if (self.active_stage != null) return error.StageAlreadyActive;
            if (!self.synchronized or self.capture_active or self.live_dependencies != 0)
                return error.InvalidState;
            self.next_stage_index = 0;
            self.counters = .{};
            self.counters.persistent_bytes = @intCast(self.persistent_bytes);
            self.counters.peak_live_bytes = @intCast(self.persistent_bytes);
        }

        /// Returns a failed proof to an empty synchronized context without
        /// destroying process-owned streams, events, or the memory pool.
        pub fn abortProof(self: *Self) runtime_error.Error!void {
            _ = try self.requireHandle();
            var first_error: ?runtime_error.Error = null;
            if (self.capture_active) {
                if (@hasDecl(Api, "stwo_graph_capture_abort")) {
                    graph_execution.abort(Api, self) catch |err| {
                        first_error = err;
                    };
                } else {
                    first_error = error.InvalidState;
                }
                self.capture_active = false;
            }
            if (self.active_stage != null and
                @hasDecl(Api, "stwo_exec_context_nvtx_pop"))
            {
                runtime_error.check(Api.stwo_exec_context_nvtx_pop(
                    self.handle.?,
                )) catch |err| {
                    first_error = err;
                };
            }
            // Abort all pending producer/waiter uses before queuing frees on
            // coordination stream 0. Failure retains buffers for safe retry.
            try self.resetDependencies();
            while (self.live_buffers != self.persistent_buffers) {
                const index = self.live_buffers - 1;
                const allocation = self.allocations[index];
                if (allocation.address != 0) {
                    runtime_error.check(Api.stwo_exec_context_free_u32(
                        self.handle.?,
                        @ptrFromInt(allocation.address),
                    )) catch |err| return first_error orelse err;
                    self.synchronized = false;
                    self.counters.free(self.active_stage, allocation.bytes);
                }
                self.live_buffers = index;
                self.allocations[index] = .{};
            }
            if (!self.synchronized) {
                self.sync() catch |err| {
                    if (first_error == null) first_error = err;
                };
            }
            self.active_stage = null;
            self.next_stage_index = 0;
            if (first_error) |err| return err;
        }

        /// Best-effort failure cleanup for a partially executed proof.
        ///
        /// Unlike `close`, this deliberately accepts an active stage and live
        /// allocations. Every allocation registered by this context is queued
        /// for release before destroying the stream and its isolated pool.
        pub fn abort(self: *Self) runtime_error.Error!void {
            const handle = try self.requireControl();
            if (self.teardown_pending) {
                try runtime_error.check(Api.stwo_exec_context_destroy(handle));
                self.handle = null;
                return;
            }
            var first_error: ?runtime_error.Error = null;
            try self.abortProof();
            var persistent_free_enqueued = false;
            while (self.live_buffers != 0) {
                const index = self.live_buffers - 1;
                const allocation = self.allocations[index];
                if (allocation.address != 0) {
                    if (allocation.bytes > self.persistent_bytes) return error.InvalidState;
                    runtime_error.check(Api.stwo_exec_context_free_u32(
                        handle,
                        @ptrFromInt(allocation.address),
                    )) catch |err| return first_error orelse err;
                    persistent_free_enqueued = true;
                    self.persistent_bytes -= allocation.bytes;
                }
                self.live_buffers = index;
                self.persistent_buffers = index;
                self.allocations[index] = .{};
            }
            self.persistent_buffers = 0;
            self.persistent_bytes = 0;
            if (persistent_free_enqueued) {
                runtime_error.check(Api.stwo_exec_context_sync(handle)) catch |err| {
                    if (first_error == null) first_error = err;
                };
            }
            if (first_error) |err| return err;
            self.teardown_pending = true;
            try runtime_error.check(Api.stwo_exec_context_destroy(handle));
            self.handle = null;
            if (first_error) |err| return err;
        }

        pub fn beginStage(
            self: *Self,
            stage: telemetry.Stage,
        ) runtime_error.Error!void {
            const handle = try self.requireHandle();
            if (self.active_stage != null) return error.StageAlreadyActive;
            if (self.next_stage_index >= telemetry.all_stages.len or
                telemetry.all_stages[self.next_stage_index] != stage)
            {
                return error.StageOrderViolation;
            }
            if (self.next_stage_index == 0) {
                if (@hasDecl(Api, "stwo_exec_context_timing_begin")) {
                    var capacity: u32 = 0;
                    try runtime_error.check(Api.stwo_exec_context_timing_begin(
                        handle,
                        &capacity,
                    ));
                    if (capacity < telemetry.stage_count)
                        return error.InvalidExecutionLaneCount;
                }
            }
            if (@hasDecl(Api, "stwo_exec_context_nvtx_push")) {
                try runtime_error.check(Api.stwo_exec_context_nvtx_push(
                    handle,
                    stageLabel(stage),
                ));
            }
            self.active_stage = stage;
        }

        pub fn endStage(
            self: *Self,
            stage: telemetry.Stage,
        ) runtime_error.Error!void {
            const active = self.active_stage orelse return error.StageNotActive;
            if (active != stage) return error.StageOrderViolation;
            const stage_counters = self.counters.stages[stage.index()];
            if (stage.requiresKernel() and
                stage_counters.kernel_launches == 0 and
                stage_counters.graph_launches == 0)
            {
                return error.KernelPathUnused;
            }
            const handle = try self.requireHandle();
            if (@hasDecl(Api, "stwo_exec_context_timing_mark"))
                try runtime_error.check(Api.stwo_exec_context_timing_mark(handle));
            if (@hasDecl(Api, "stwo_exec_context_nvtx_pop"))
                try runtime_error.check(Api.stwo_exec_context_nvtx_pop(handle));
            self.counters.complete(stage);
            self.active_stage = null;
            self.next_stage_index += 1;
        }

        pub fn stagesComplete(self: Self) bool {
            return self.active_stage == null and
                self.next_stage_index == telemetry.all_stages.len and
                self.counters.stagesCompleteExactlyOnce();
        }

        pub fn allocate(self: *Self, words: usize) runtime_error.Error!Buffer {
            if (self.active_stage != .ingress)
                return error.AllocationOutsideIngress;
            const buffer = try persistent_allocation.allocateRegistered(
                Api,
                self,
                words,
            );
            self.counters.allocation(self.active_stage, try buffer.bytes());
            return buffer;
        }

        pub fn allocateManaged(self: *Self, words: usize) runtime_error.Error!Buffer {
            if (self.active_stage != .ingress)
                return error.AllocationOutsideIngress;
            const buffer = try persistent_allocation.allocateRegisteredManaged(
                Api,
                self,
                words,
            );
            self.counters.allocation(self.active_stage, try buffer.bytes());
            return buffer;
        }

        /// Creates a fixed-address process allocation while the context is
        /// idle. Persistent allocations form a protected registry prefix.
        pub fn allocatePersistent(
            self: *Self,
            words: usize,
        ) runtime_error.Error!Buffer {
            _ = try self.requireHandle();
            return persistent_allocation.allocate(Api, self, words);
        }

        pub fn allocatePersistentManaged(
            self: *Self,
            words: usize,
        ) runtime_error.Error!Buffer {
            _ = try self.requireHandle();
            return persistent_allocation.allocateManaged(Api, self, words);
        }

        pub fn allocateRaw(
            self: *Self,
            words: usize,
            out: *?[*]u32,
        ) runtime_error.Error!void {
            try runtime_error.check(Api.stwo_exec_context_alloc_u32(
                try self.requireHandle(),
                words,
                out,
            ));
        }

        pub fn allocateRawManaged(
            self: *Self,
            words: usize,
            out: *?[*]u32,
        ) runtime_error.Error!void {
            if (comptime @hasDecl(Api, "stwo_exec_context_alloc_managed_u32")) {
                try runtime_error.check(Api.stwo_exec_context_alloc_managed_u32(
                    try self.requireHandle(),
                    words,
                    out,
                ));
            } else return error.InvalidState;
        }

        pub fn prefetchManagedSlice(
            self: *Self,
            comptime F: type,
            source: anytype,
            to_device: bool,
        ) runtime_error.Error!void {
            if (self.active_stage == null) return error.StageNotActive;
            if (source.len == 0) return error.SizeOverflow;
            const pointer = try self.deviceSlicePointer(F, source, source.len);
            const bytes = std.math.mul(usize, source.len, @sizeOf(F)) catch
                return error.SizeOverflow;
            if (comptime @hasDecl(Api, "stwo_exec_context_prefetch_managed")) {
                try runtime_error.check(Api.stwo_exec_context_prefetch_managed(
                    try self.requireHandle(),
                    pointer,
                    bytes,
                    @intFromBool(to_device),
                ));
                self.synchronized = false;
            } else return error.InvalidState;
        }

        pub fn freeRaw(self: *Self, pointer: [*]u32) c_int {
            const handle = self.requireHandle() catch return -1;
            return Api.stwo_exec_context_free_u32(handle, pointer);
        }

        pub fn free(self: *Self, buffer: *Buffer) runtime_error.Error!void {
            const handle = try self.requireOwner(buffer.*);
            const allocation_index = try self.exactAllocation(buffer.*);
            if (allocation_index < self.persistent_buffers)
                return error.InvalidState;
            try runtime_error.check(Api.stwo_exec_context_free_u32(handle, buffer.pointer));
            self.synchronized = false;
            self.counters.free(self.active_stage, try buffer.bytes());
            self.live_buffers -= 1;
            self.allocations[allocation_index] = self.allocations[self.live_buffers];
            self.allocations[self.live_buffers] = .{};
            buffer.words = 0;
            buffer.owner = 0;
            buffer.generation = 0;
        }

        pub fn freePersistent(
            self: *Self,
            buffer: *Buffer,
        ) runtime_error.Error!void {
            _ = try self.requireHandle();
            try persistent_allocation.free(Api, self, buffer);
        }

        pub fn upload(
            self: *Self,
            destination: Buffer,
            source: []const u32,
        ) runtime_error.Error!void {
            if (self.active_stage != .ingress)
                return error.HostWriteOutsideIngress;
            if (source.len > destination.words) return error.SizeOverflow;
            const handle = try self.requireOwner(destination);
            const bytes = std.math.mul(usize, source.len, @sizeOf(u32)) catch
                return error.SizeOverflow;
            try runtime_error.check(Api.stwo_exec_context_memcpy_h2d_async(
                handle,
                destination.pointer,
                source.ptr,
                bytes,
            ));
            self.synchronized = false;
            self.counters.h2d(self.active_stage, bytes);
        }

        pub fn uploadSlice(
            self: *Self,
            comptime F: type,
            destination: anytype,
            source: []const F,
        ) runtime_error.Error!void {
            if (self.active_stage != .ingress)
                return error.HostWriteOutsideIngress;
            const pointer = try self.deviceSlicePointer(
                F,
                destination,
                source.len,
            );
            const bytes = std.math.mul(usize, source.len, @sizeOf(F)) catch
                return error.SizeOverflow;
            try runtime_error.check(Api.stwo_exec_context_memcpy_h2d_async(
                try self.requireHandle(),
                pointer,
                source.ptr,
                bytes,
            ));
            self.synchronized = false;
            self.counters.h2d(self.active_stage, bytes);
        }

        pub fn copyDevice(
            self: *Self,
            destination: Buffer,
            source: Buffer,
            words: usize,
        ) runtime_error.Error!void {
            if (words > destination.words or words > source.words) return error.SizeOverflow;
            const handle = try self.requireOwner(destination);
            _ = try self.requireOwner(source);
            const bytes = std.math.mul(usize, words, @sizeOf(u32)) catch
                return error.SizeOverflow;
            try runtime_error.check(Api.stwo_exec_context_memcpy_d2d_async(
                handle,
                destination.pointer,
                source.pointer,
                bytes,
            ));
            self.synchronized = false;
            self.counters.d2d(self.active_stage, bytes);
        }

        /// Copies exact, independently validated resident subranges.
        ///
        /// Arena slices remain slices: callers cannot forge whole-allocation
        /// Buffer handles merely to assemble a proof output.
        pub fn copyDeviceSlice(
            self: *Self,
            comptime F: type,
            destination: anytype,
            source: anytype,
        ) runtime_error.Error!void {
            if (self.active_stage == null) return error.StageNotActive;
            if (destination.len == 0 or destination.len != source.len)
                return error.SizeOverflow;
            const destination_pointer = try self.deviceSlicePointer(
                F,
                destination,
                destination.len,
            );
            const source_pointer = try self.deviceSlicePointer(
                F,
                source,
                source.len,
            );
            const bytes = std.math.mul(
                usize,
                destination.len,
                @sizeOf(F),
            ) catch return error.SizeOverflow;
            const destination_end = std.math.add(
                usize,
                destination.address,
                bytes,
            ) catch return error.SizeOverflow;
            const source_end = std.math.add(
                usize,
                source.address,
                bytes,
            ) catch return error.SizeOverflow;
            if (destination.address < source_end and
                source.address < destination_end)
            {
                return error.OverlappingDeviceRange;
            }
            try runtime_error.check(Api.stwo_exec_context_memcpy_d2d_async(
                try self.requireHandle(),
                destination_pointer,
                source_pointer,
                bytes,
            ));
            self.synchronized = false;
            self.counters.d2d(self.active_stage, bytes);
        }

        /// Enqueues one exact byte-zero operation on the proof-owned stream.
        pub fn zeroDeviceSlice(
            self: *Self,
            comptime F: type,
            destination: anytype,
        ) runtime_error.Error!void {
            const stage = self.active_stage orelse return error.StageNotActive;
            if (destination.len == 0) return error.SizeOverflow;
            const pointer = try self.deviceSlicePointer(
                F,
                destination,
                destination.len,
            );
            const bytes = std.math.mul(
                usize,
                destination.len,
                @sizeOf(F),
            ) catch return error.SizeOverflow;
            try runtime_error.check(Api.stwo_exec_context_memset_async(
                try self.requireHandle(),
                @ptrCast(pointer),
                0,
                bytes,
            ));
            self.synchronized = false;
            self.counters.memset(stage, bytes);
        }

        pub fn devicePointer(
            self: *Self,
            buffer: Buffer,
            minimum_words: usize,
        ) runtime_error.Error![*]u32 {
            _ = try self.requireOwner(buffer);
            if (minimum_words == 0 or buffer.words < minimum_words)
                return error.SizeOverflow;
            return buffer.pointer;
        }

        pub fn deviceSlicePointer(
            self: *Self,
            comptime F: type,
            slice: anytype,
            minimum_elements: usize,
        ) runtime_error.Error![*]F {
            const handle = try self.requireHandle();
            if (minimum_elements == 0 or slice.len < minimum_elements or
                slice.owner != @intFromPtr(handle) or slice.generation == 0 or
                slice.address == 0 or slice.address % @alignOf(F) != 0)
            {
                return error.InvalidDeviceAddress;
            }
            const bytes = std.math.mul(
                usize,
                minimum_elements,
                @sizeOf(F),
            ) catch return error.SizeOverflow;
            const end = std.math.add(usize, slice.address, bytes) catch
                return error.SizeOverflow;
            var resident = false;
            for (self.allocations[0..self.live_buffers]) |allocation| {
                if (allocation.generation != slice.generation) continue;
                const allocation_end = std.math.add(
                    usize,
                    allocation.address,
                    allocation.bytes,
                ) catch return error.SizeOverflow;
                if (slice.address >= allocation.address and end <= allocation_end) {
                    resident = true;
                    break;
                }
            }
            if (!resident) return error.InvalidDeviceAddress;
            return @ptrFromInt(slice.address);
        }

        pub fn requireStage(
            self: *Self,
            expected: telemetry.Stage,
        ) runtime_error.Error!void {
            _ = try self.requireHandle();
            if (self.active_stage != expected) return error.StageOrderViolation;
        }

        /// The sole host-read API. It reads one exact arena subrange at the
        /// final proof boundary, so intermediate code cannot acquire a generic
        /// device download.
        pub fn readProofSlice(
            self: *Self,
            comptime F: type,
            destination: []F,
            source: anytype,
        ) runtime_error.Error!void {
            const stage = self.active_stage orelse
                return error.HostReadOutsideProofAssembly;
            if (stage != .proof_assembly)
                return error.HostReadOutsideProofAssembly;
            if (destination.len != source.len) return error.SizeOverflow;
            const pointer = try self.deviceSlicePointer(F, source, destination.len);
            const bytes = std.math.mul(usize, destination.len, @sizeOf(F)) catch
                return error.SizeOverflow;
            try runtime_error.check(Api.stwo_exec_context_memcpy_d2h_async(
                try self.requireHandle(),
                destination.ptr,
                pointer,
                bytes,
            ));
            self.synchronized = false;
            self.counters.proofRead(stage, bytes);
        }

        pub fn fill(
            self: *Self,
            destination: Buffer,
            value: u32,
        ) runtime_error.Error!void {
            const handle = try self.requireOwner(destination);
            try runtime_error.check(Api.stwo_exec_context_fill_u32_async(
                handle,
                destination.pointer,
                value,
                destination.words,
            ));
            self.synchronized = false;
            self.counters.fill(self.active_stage, destination.words);
        }

        pub fn joinLanes(self: *Self) runtime_error.Error!void {
            const handle = try self.requireHandle();
            try runtime_error.check(Api.stwo_exec_context_join_all_lanes(handle));
            self.synchronized = true;
            self.counters.join(self.active_stage, self.lane_count);
            self.counters.sync(self.active_stage);
            if (@hasDecl(Api, "stwo_exec_context_timing_elapsed")) {
                var elapsed_ms: [telemetry.stage_count]f32 = undefined;
                var count: u32 = 0;
                try runtime_error.check(Api.stwo_exec_context_timing_elapsed(
                    handle,
                    &elapsed_ms,
                    elapsed_ms.len,
                    &count,
                ));
                if (count != elapsed_ms.len) return error.InvalidState;
                self.counters.recordDeviceTimings(&elapsed_ms) catch
                    return error.InvalidState;
            }
        }

        pub fn sync(self: *Self) runtime_error.Error!void {
            try runtime_error.check(Api.stwo_exec_context_sync(try self.requireHandle()));
            self.synchronized = true;
            self.counters.sync(self.active_stage);
        }

        pub fn poolCurrent(self: *Self) runtime_error.Error!struct {
            used: usize,
            reserved: usize,
        } {
            var used: usize = 0;
            var reserved: usize = 0;
            try runtime_error.check(Api.stwo_exec_context_pool_current(
                try self.requireHandle(),
                &used,
                &reserved,
            ));
            return .{ .used = used, .reserved = reserved };
        }

        pub fn memoryInfo(self: *Self) runtime_error.Error!struct {
            free: usize,
            total: usize,
        } {
            var available: usize = 0;
            var total: usize = 0;
            try runtime_error.check(Api.stwo_exec_context_memory_info(
                try self.requireHandle(),
                &available,
                &total,
            ));
            if (total == 0 or available > total)
                return error.InvalidDeviceMemorySnapshot;
            return .{ .free = available, .total = total };
        }

        pub fn recordKernels(self: *Self, count: u64) runtime_error.Error!void {
            _ = try self.requireHandle();
            if (count == 0) return error.KernelPathUnused;
            const stage = self.active_stage orelse return error.StageNotActive;
            self.synchronized = false;
            self.counters.kernels(stage, count);
        }

        pub fn recordGraphs(self: *Self, count: u64) runtime_error.Error!void {
            _ = try self.requireHandle();
            if (count == 0) return error.KernelPathUnused;
            const stage = self.active_stage orelse return error.StageNotActive;
            self.synchronized = false;
            self.counters.graphs(stage, count);
        }

        fn requireControl(self: *Self) runtime_error.Error!*anyopaque {
            if (self.owner_thread_id == 0 or self.owner_thread_id != std.Thread.getCurrentId()) return error.ThreadOwnershipViolation;
            return self.handle orelse error.ContextClosed;
        }

        fn requireHandle(self: *Self) runtime_error.Error!*anyopaque {
            const handle = try self.requireControl();
            if (self.teardown_pending) return error.InvalidState;
            return handle;
        }

        fn stageLabel(stage: telemetry.Stage) [*:0]const u8 {
            return switch (stage) {
                .ingress => "stwo.cuda.ingress",
                .trace_generation => "stwo.cuda.trace_generation",
                .trace_commit => "stwo.cuda.trace_commit",
                .constraint_evaluation => "stwo.cuda.constraint_evaluation",
                .oods => "stwo.cuda.oods",
                .quotient => "stwo.cuda.quotient",
                .fri_commit => "stwo.cuda.fri_commit",
                .pow => "stwo.cuda.pow",
                .decommit => "stwo.cuda.decommit",
                .proof_assembly => "stwo.cuda.proof_assembly",
            };
        }

        fn requireOwner(self: *Self, buffer: Buffer) runtime_error.Error!*anyopaque {
            const handle = try self.requireHandle();
            if (buffer.words == 0 or buffer.owner != @intFromPtr(handle) or
                buffer.generation == 0)
                return error.ContextMismatch;
            return handle;
        }

        fn exactAllocation(
            self: *Self,
            buffer: Buffer,
        ) runtime_error.Error!usize {
            const bytes = try buffer.bytes();
            const address = @intFromPtr(buffer.pointer);
            for (self.allocations[0..self.live_buffers], 0..) |allocation, index| {
                if (allocation.address == address and
                    allocation.bytes == bytes and
                    allocation.generation == buffer.generation)
                {
                    return index;
                }
            }
            return error.ContextMismatch;
        }
    };
}

test "context owns buffers and accounts only explicit transfers" {
    const Fake = struct {
        var handle_word: u8 = 0;
        var stream_word: u8 = 0;
        var device_words: [16]u32 = [_]u32{0} ** 16;
        var sync_calls: usize = 0;
        var managed_allocations: usize = 0;
        var managed_prefetches: usize = 0;

        fn stwo_exec_context_create(out: *?*anyopaque) c_int {
            out.* = &handle_word;
            return 0;
        }
        fn stwo_exec_context_destroy(_: *anyopaque) c_int {
            return 0;
        }
        fn stwo_exec_context_stream(_: *anyopaque, out: *?*anyopaque) c_int {
            out.* = &stream_word;
            return 0;
        }
        fn stwo_exec_context_device(_: *anyopaque, out: *c_int) c_int {
            out.* = 0;
            return 0;
        }
        fn stwo_exec_context_lane_count(_: *anyopaque, out: *u32) c_int {
            // Legacy create() uses the one-lane default in ContextOptions.
            out.* = 1;
            return 0;
        }
        fn stwo_exec_context_alloc_u32(_: *anyopaque, _: usize, out: *?[*]u32) c_int {
            out.* = &device_words;
            return 0;
        }
        fn stwo_exec_context_alloc_managed_u32(_: *anyopaque, _: usize, out: *?[*]u32) c_int {
            managed_allocations += 1;
            out.* = &device_words;
            return 0;
        }
        fn stwo_exec_context_prefetch_managed(_: *anyopaque, _: *const anyopaque, _: usize, _: c_int) c_int {
            managed_prefetches += 1;
            return 0;
        }
        fn stwo_exec_context_free_u32(_: *anyopaque, _: [*]u32) c_int {
            return 0;
        }
        fn stwo_exec_context_memcpy_h2d_async(
            _: *anyopaque,
            _: *anyopaque,
            _: *const anyopaque,
            _: usize,
        ) c_int {
            return 0;
        }
        fn stwo_exec_context_memcpy_d2d_async(
            _: *anyopaque,
            _: *anyopaque,
            _: *const anyopaque,
            _: usize,
        ) c_int {
            return 0;
        }
        fn stwo_exec_context_memcpy_d2h_async(
            _: *anyopaque,
            _: *anyopaque,
            _: *const anyopaque,
            _: usize,
        ) c_int {
            return 0;
        }
        fn stwo_exec_context_fill_u32_async(
            _: *anyopaque,
            _: [*]u32,
            _: u32,
            _: usize,
        ) c_int {
            return 0;
        }
        fn stwo_exec_context_join_all_lanes(_: *anyopaque) c_int {
            return 0;
        }
        fn stwo_exec_context_sync(_: *anyopaque) c_int {
            sync_calls += 1;
            return 0;
        }
        fn stwo_exec_context_pool_current(
            _: *anyopaque,
            used: *usize,
            reserved: *usize,
        ) c_int {
            used.* = 0;
            reserved.* = 4096;
            return 0;
        }
    };

    const Context = ContextFor(Fake);
    var context = try Context.open();
    try context.beginStage(.ingress);
    var managed = try context.allocateManaged(4);
    try std.testing.expectEqual(@as(usize, 1), Fake.managed_allocations);
    try context.prefetchManagedSlice(u32, .{
        .address = @intFromPtr(managed.pointer),
        .len = managed.words,
        .owner = managed.owner,
        .generation = managed.generation,
    }, false);
    try std.testing.expectEqual(@as(usize, 1), Fake.managed_prefetches);
    try context.free(&managed);
    var buffer = try context.allocate(16);
    try context.upload(buffer, &.{ 1, 2, 3, 4 });
    try context.fill(buffer, 7);
    const owned_slice = .{
        .address = @intFromPtr(buffer.pointer),
        .len = buffer.words,
        .owner = buffer.owner,
        .generation = buffer.generation,
    };
    try std.testing.expectEqual(
        @intFromPtr(buffer.pointer),
        @intFromPtr(try context.deviceSlicePointer(u32, owned_slice, 16)),
    );
    try context.uploadSlice(u32, owned_slice, &.{ 5, 6, 7, 8 });
    const source_slice = .{
        .address = owned_slice.address,
        .len = 4,
        .owner = owned_slice.owner,
        .generation = owned_slice.generation,
    };
    const destination_slice = .{
        .address = owned_slice.address + 8 * @sizeOf(u32),
        .len = 4,
        .owner = owned_slice.owner,
        .generation = owned_slice.generation,
    };
    try context.copyDeviceSlice(u32, destination_slice, source_slice);
    const overlapping_slice = .{
        .address = owned_slice.address + 2 * @sizeOf(u32),
        .len = 4,
        .owner = owned_slice.owner,
        .generation = owned_slice.generation,
    };
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        context.copyDeviceSlice(u32, overlapping_slice, source_slice),
    );
    var oversized_slice = owned_slice;
    oversized_slice.len = 17;
    try std.testing.expectError(
        error.InvalidDeviceAddress,
        context.deviceSlicePointer(u32, oversized_slice, 17),
    );
    var foreign_slice = owned_slice;
    foreign_slice.owner += 1;
    try std.testing.expectError(
        error.InvalidDeviceAddress,
        context.deviceSlicePointer(u32, foreign_slice, 1),
    );
    try context.endStage(.ingress);
    try context.beginStage(.trace_generation);
    try context.recordKernels(1);
    try context.endStage(.trace_generation);
    try context.beginStage(.trace_commit);
    try context.recordKernels(3);
    try context.endStage(.trace_commit);
    try std.testing.expectError(
        error.StageOrderViolation,
        context.beginStage(.proof_assembly),
    );
    inline for (.{
        telemetry.Stage.constraint_evaluation,
        telemetry.Stage.oods,
        telemetry.Stage.quotient,
        telemetry.Stage.fri_commit,
        telemetry.Stage.pow,
        telemetry.Stage.decommit,
    }) |stage| {
        try context.beginStage(stage);
        try context.recordKernels(1);
        try context.endStage(stage);
    }
    try context.beginStage(.proof_assembly);
    var proof_words: [4]u32 = undefined;
    var proof_slice = owned_slice;
    proof_slice.len = proof_words.len;
    try context.readProofSlice(u32, &proof_words, proof_slice);
    try context.free(&buffer);
    try std.testing.expectError(
        error.InvalidDeviceAddress,
        context.deviceSlicePointer(u32, owned_slice, 1),
    );
    try context.endStage(.proof_assembly);
    try context.close();
    try std.testing.expectEqual(@as(u64, 64), context.counters.peak_live_bytes);
    try std.testing.expectEqual(@as(u64, 32), context.counters.h2d_bytes);
    try std.testing.expectEqual(@as(u64, 16), context.counters.d2d_bytes);
    try std.testing.expectEqual(@as(u64, 16), context.counters.d2h_proof_bytes);
    try std.testing.expectEqual(@as(u64, 1), context.counters.d2h_proof_operations);
    try std.testing.expectEqual(@as(usize, 1), Fake.sync_calls);
    try std.testing.expectEqual(@as(u64, 1), context.counters.sync_calls);
    try std.testing.expect(context.counters.isResident());
    try std.testing.expect(context.counters.stagesCompleteExactlyOnce());
}
