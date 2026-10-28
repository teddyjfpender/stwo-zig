//! Bounded full-plan-keyed fixed-address arena and CUDA graph cache.

const std = @import("std");
const arena_module = @import("arena.zig");
const graph_execution = @import("graph_execution.zig");
const runtime_error = @import("error.zig");
const telemetry = @import("telemetry.zig");

pub const prepared_capacity: usize = 4;

pub fn CacheFor(comptime Api: type, comptime Context: type) type {
    const Arena = arena_module.ArenaFor(Context);
    const CachedGraph = struct {
        handle: *anyopaque,
        replay: telemetry.StageCounters,
    };
    const Prepared = struct {
        allocator: std.mem.Allocator,
        cache_key: [32]u8,
        plan: arena_module.Plan,
        arena: Arena,
        graphs: [telemetry.stage_count]?CachedGraph =
            [_]?CachedGraph{null} ** telemetry.stage_count,
        active_leases: u32 = 0,
        last_used: u64,
    };

    return struct {
        const Self = @This();

        entries: [prepared_capacity]?Prepared =
            [_]?Prepared{null} ** prepared_capacity,
        clock: u64 = 0,
        hits: u64 = 0,
        misses: u64 = 0,
        prepared_hits: u64 = 0,
        prepared_misses: u64 = 0,
        evictions: u64 = 0,

        pub fn prepare(
            self: *Self,
            context: *Context,
            allocator: std.mem.Allocator,
            cache_key: [32]u8,
            owned_plan: arena_module.Plan,
        ) runtime_error.Error!void {
            var plan = owned_plan;
            errdefer plan.deinit(allocator);
            if (self.find(cache_key)) |index| {
                self.prepared_hits = increment(self.prepared_hits) catch
                    return error.InvalidState;
                self.touch(index) catch return error.InvalidState;
                plan.deinit(allocator);
                return;
            }
            self.prepared_misses = increment(self.prepared_misses) catch
                return error.InvalidState;

            const arena_bytes = std.math.mul(
                usize,
                plan.total_words,
                @sizeOf(u32),
            ) catch return error.SizeOverflow;
            if (arena_module.compactDeviceProfileEnabled()) {
                const memory = try context.memoryInfo();
                try arena_module.requireCompactDeviceCapacity(memory.total, arena_bytes);
            }
            var destination = self.emptyIndex();
            while (destination == null or
                !try hasMemory(context, arena_bytes))
            {
                const victim = self.lruUnpinned() orelse {
                    if (self.anyPinned()) return error.PreparedCacheBusy;
                    if (destination != null and
                        arena_module.managedOversubscriptionEnabled()) break;
                    return error.InsufficientDeviceMemory;
                };
                try self.destroyEntry(context, victim);
                self.evictions = increment(self.evictions) catch
                    return error.InvalidState;
                destination = victim;
            }

            const last_used = self.nextTick() catch
                return error.InvalidState;
            const managed = arena_module.forceManagedArena() or
                !try hasMemory(context, arena_bytes);
            if (std.posix.getenv("STWO_CUDA_MEMORY_PHASES") != null)
                std.debug.print("cuda prepared arena mode={s} bytes={}\n", .{
                    if (managed) @as([]const u8, "managed") else "device",
                    arena_bytes,
                });
            const resident_arena = if (managed)
                try Arena.initPersistentManaged(context, &plan)
            else
                try Arena.initPersistent(context, &plan);
            self.entries[destination.?] = .{
                .allocator = allocator,
                .cache_key = cache_key,
                .plan = plan,
                .arena = resident_arena,
                .last_used = last_used,
            };
        }

        pub fn acquireArena(
            self: *Self,
            cache_key: [32]u8,
        ) runtime_error.Error!*Arena {
            const index = self.find(cache_key) orelse return error.InvalidState;
            const prepared = &self.entries[index].?;
            prepared.active_leases = std.math.add(
                u32,
                prepared.active_leases,
                1,
            ) catch return error.InvalidState;
            self.touch(index) catch {
                prepared.active_leases -= 1;
                return error.InvalidState;
            };
            return &prepared.arena;
        }

        pub fn releaseArena(
            self: *Self,
            cache_key: [32]u8,
        ) runtime_error.Error!void {
            const index = self.find(cache_key) orelse return error.InvalidState;
            const prepared = &self.entries[index].?;
            if (prepared.active_leases == 0) return error.InvalidState;
            prepared.active_leases -= 1;
            self.touch(index) catch return error.InvalidState;
        }

        pub fn hasGraph(
            self: *Self,
            cache_key: [32]u8,
            stage: telemetry.Stage,
        ) runtime_error.Error!bool {
            const prepared = try self.requireLive(cache_key);
            return prepared.graphs[stage.index()] != null;
        }

        pub fn beginCapture(
            self: *Self,
            context: *Context,
            cache_key: [32]u8,
            stage: telemetry.Stage,
        ) runtime_error.Error!void {
            const prepared = try self.requireLive(cache_key);
            if (context.active_stage != stage or
                prepared.graphs[stage.index()] != null)
            {
                return error.InvalidState;
            }
            try graph_execution.begin(Api, context);
        }

        pub fn finishCaptureAndLaunch(
            self: *Self,
            context: *Context,
            cache_key: [32]u8,
            stage: telemetry.Stage,
        ) runtime_error.Error!void {
            const prepared = try self.requireLive(cache_key);
            if (context.active_stage != stage or
                prepared.graphs[stage.index()] != null)
            {
                return error.InvalidState;
            }
            const replay = context.counters.stages[stage.index()];
            const graph = try graph_execution.finish(
                Api,
                context,
                replay.kernel_launches,
            );
            prepared.graphs[stage.index()] = .{
                .handle = graph,
                .replay = replay,
            };
            graph_execution.launchCaptured(Api, context, graph) catch |err| {
                prepared.graphs[stage.index()] = null;
                runtime_error.check(Api.stwo_graph_destroy(graph)) catch {};
                return err;
            };
            self.misses = increment(self.misses) catch
                return error.InvalidState;
        }

        pub fn launch(
            self: *Self,
            context: *Context,
            cache_key: [32]u8,
            stage: telemetry.Stage,
        ) runtime_error.Error!void {
            const prepared = try self.requireLive(cache_key);
            if (context.active_stage != stage) return error.InvalidState;
            const graph = prepared.graphs[stage.index()] orelse
                return error.InvalidState;
            graph_execution.launchReplay(
                Api,
                context,
                graph.handle,
                graph.replay,
            ) catch |err| {
                prepared.graphs[stage.index()] = null;
                runtime_error.check(Api.stwo_graph_destroy(graph.handle)) catch {};
                return err;
            };
            self.hits = increment(self.hits) catch
                return error.InvalidState;
        }

        pub fn abortCapture(
            _: *Self,
            context: *Context,
        ) runtime_error.Error!void {
            try graph_execution.abort(Api, context);
        }

        pub fn contains(self: *const Self, cache_key: [32]u8) bool {
            return self.find(cache_key) != null;
        }

        pub fn deinit(
            self: *Self,
            context: *Context,
        ) runtime_error.Error!void {
            if (self.anyPinned()) return error.PreparedCacheBusy;
            var first_error: ?runtime_error.Error = null;
            for (&self.entries, 0..) |*entry, index| {
                if (entry.* == null) continue;
                self.destroyEntry(context, index) catch |err| {
                    if (first_error == null) first_error = err;
                };
            }
            if (first_error) |err| return err;
        }

        fn destroyEntry(
            self: *Self,
            context: *Context,
            index: usize,
        ) runtime_error.Error!void {
            var prepared = &self.entries[index].?;
            if (prepared.active_leases != 0) return error.PreparedCacheBusy;
            var first_error: ?runtime_error.Error = null;
            for (&prepared.graphs) |*entry| {
                if (entry.*) |graph| {
                    graph_execution.destroy(
                        Api,
                        context,
                        graph.handle,
                    ) catch |err| {
                        if (first_error == null) first_error = err;
                    };
                    entry.* = null;
                }
            }
            prepared.arena.deinitPersistent(context) catch |err| {
                if (first_error == null) first_error = err;
            };
            prepared.plan.deinit(prepared.allocator);
            self.entries[index] = null;
            if (first_error) |err| return err;
        }

        fn requireLive(
            self: *Self,
            cache_key: [32]u8,
        ) runtime_error.Error!*Prepared {
            const index = self.find(cache_key) orelse return error.InvalidState;
            const prepared = &self.entries[index].?;
            if (prepared.active_leases == 0) return error.InvalidState;
            return prepared;
        }

        fn find(self: *const Self, cache_key: [32]u8) ?usize {
            for (self.entries, 0..) |entry, index| {
                const prepared = entry orelse continue;
                if (std.mem.eql(u8, &prepared.cache_key, &cache_key))
                    return index;
            }
            return null;
        }

        fn emptyIndex(self: *const Self) ?usize {
            for (self.entries, 0..) |entry, index| {
                if (entry == null) return index;
            }
            return null;
        }

        fn lruUnpinned(self: *const Self) ?usize {
            var result: ?usize = null;
            var oldest: u64 = std.math.maxInt(u64);
            for (self.entries, 0..) |entry, index| {
                const prepared = entry orelse continue;
                if (prepared.active_leases == 0 and
                    prepared.last_used < oldest)
                {
                    oldest = prepared.last_used;
                    result = index;
                }
            }
            return result;
        }

        fn anyPinned(self: *const Self) bool {
            for (self.entries) |entry| {
                const prepared = entry orelse continue;
                if (prepared.active_leases != 0) return true;
            }
            return false;
        }

        fn touch(self: *Self, index: usize) error{Overflow}!void {
            self.entries[index].?.last_used = try self.nextTick();
        }

        fn nextTick(self: *Self) error{Overflow}!u64 {
            self.clock = try increment(self.clock);
            return self.clock;
        }

        fn hasMemory(
            context: *Context,
            arena_bytes: usize,
        ) runtime_error.Error!bool {
            const memory = try context.memoryInfo();
            // cudaMemGetInfo excludes pages retained by our private async
            // pool. An evicted arena remains reusable there, so looking only
            // at driver-free bytes falsely rejects a differently sized next
            // request even when its allocation fits on this device.
            const reusable = if (@hasDecl(Api, "stwo_exec_context_pool_current")) blk: {
                const pool = try context.poolCurrent();
                if (pool.used > pool.reserved) return error.InvalidState;
                break :blk pool.reserved - pool.used;
            } else 0;
            const usable_free = usableMemory(
                memory.free,
                memory.total,
                reusable,
                arena_module.deviceMemorySafetyReserveBytes(),
            );
            return arena_bytes <= usable_free;
        }
    };
}

fn usableMemory(driver_free: usize, total: usize, pool_reusable: usize, reserve: usize) usize {
    const available = @min(total, std.math.add(usize, driver_free, pool_reusable) catch std.math.maxInt(usize));
    return available - @min(available, reserve);
}

test "arena admission counts reusable async pool pages" {
    const gib: usize = 1 << 30;
    const reserve = 256 * 1024 * 1024;
    try std.testing.expect(usableMemory(45 * gib, 140 * gib, 93 * gib, reserve) >= 98 * gib);
    try std.testing.expect(usableMemory(45 * gib, 140 * gib, 93 * gib, reserve) < 139 * gib);
    try std.testing.expect(usableMemory(45 * gib, 140 * gib, 0, reserve) < 98 * gib);
}

fn increment(value: u64) error{Overflow}!u64 {
    return std.math.add(u64, value, 1);
}
