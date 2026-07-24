//! Full-plan-keyed fixed-address arena and CUDA graph cache.

const std = @import("std");
const arena_module = @import("arena.zig");
const graph_execution = @import("graph_execution.zig");
const runtime_error = @import("error.zig");
const telemetry = @import("telemetry.zig");

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
    };

    return struct {
        const Self = @This();

        prepared: ?Prepared = null,
        hits: u64 = 0,
        misses: u64 = 0,

        pub fn prepare(
            self: *Self,
            context: *Context,
            allocator: std.mem.Allocator,
            cache_key: [32]u8,
            owned_plan: arena_module.Plan,
        ) runtime_error.Error!void {
            var plan = owned_plan;
            if (self.prepared) |prepared| {
                if (std.mem.eql(u8, &prepared.cache_key, &cache_key)) {
                    plan.deinit(allocator);
                    return;
                }
                try self.deinit(context);
            }
            errdefer plan.deinit(allocator);
            const arena_bytes = std.math.mul(
                usize,
                plan.total_words,
                @sizeOf(u32),
            ) catch return error.SizeOverflow;
            const memory = try context.memoryInfo();
            const reserve: usize = 256 * 1024 * 1024;
            const usable_free = memory.free - @min(memory.free, reserve);
            if (arena_bytes > usable_free)
                return error.InsufficientDeviceMemory;
            const resident_arena = try Arena.initPersistent(context, &plan);
            self.prepared = .{
                .allocator = allocator,
                .cache_key = cache_key,
                .plan = plan,
                .arena = resident_arena,
            };
        }

        pub fn arena(
            self: *Self,
            cache_key: [32]u8,
        ) runtime_error.Error!*Arena {
            const prepared = try self.require(cache_key);
            return &prepared.arena;
        }

        pub fn hasGraph(
            self: *Self,
            cache_key: [32]u8,
            stage: telemetry.Stage,
        ) runtime_error.Error!bool {
            const prepared = try self.require(cache_key);
            return prepared.graphs[stage.index()] != null;
        }

        pub fn beginCapture(
            self: *Self,
            context: *Context,
            cache_key: [32]u8,
            stage: telemetry.Stage,
        ) runtime_error.Error!void {
            const prepared = try self.require(cache_key);
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
            const prepared = try self.require(cache_key);
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
            self.misses = std.math.add(u64, self.misses, 1) catch
                return error.InvalidState;
        }

        pub fn launch(
            self: *Self,
            context: *Context,
            cache_key: [32]u8,
            stage: telemetry.Stage,
        ) runtime_error.Error!void {
            const prepared = try self.require(cache_key);
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
            self.hits = std.math.add(u64, self.hits, 1) catch
                return error.InvalidState;
        }

        pub fn abortCapture(
            _: *Self,
            context: *Context,
        ) runtime_error.Error!void {
            try graph_execution.abort(Api, context);
        }

        pub fn deinit(
            self: *Self,
            context: *Context,
        ) runtime_error.Error!void {
            if (self.prepared == null) return;
            var prepared = &self.prepared.?;
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
            self.prepared = null;
            if (first_error) |err| return err;
        }

        fn require(
            self: *Self,
            cache_key: [32]u8,
        ) runtime_error.Error!*Prepared {
            if (self.prepared) |*prepared| {
                if (!std.mem.eql(u8, &prepared.cache_key, &cache_key))
                    return error.InvalidState;
                return prepared;
            }
            return error.InvalidState;
        }
    };
}
