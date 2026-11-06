//! Per-class CUDA graph cache for the OuterNodeJob enqueue sequence
//! (ZisK pil2-stark src/utils/cuda_graph_cache.cuh: capture threshold,
//! per-device memory budget charged at instantiation, blacklist on any
//! capture/instantiate/launch failure). One cache per DeviceWorker; it is
//! driven only by that worker's thread, so it needs no lock.
//!
//! Differences from ZisK, both forced by per-node buffers:
//!  * every warm node re-records its body under capture and the cached
//!    executable is rebound with cudaGraphExecUpdate (pointer rebind per
//!    node: staged inputs, slab, channel state and arena placement may all
//!    move). Recording costs host enqueue time but no GPU time; the GPU sees
//!    one graph launch instead of ~150 dependent launches.
//!  * the key is (class, placement): top/bottom placements have different
//!    arena addresses and therefore separate executables.
//! A failed capture re-runs the body directly: capture records without
//! executing, so the body has not happened yet. The body must be
//! re-runnable (outer_job.zig resets its node-local allocations).
const std = @import("std");

pub const Api = struct {
    begin: *const fn (*anyopaque) callconv(.c) c_int,
    end: *const fn (*anyopaque, *?*anyopaque) callconv(.c) c_int,
    instantiate: *const fn (*anyopaque, *?*anyopaque, *u64) callconv(.c) c_int,
    update: *const fn (*anyopaque, *anyopaque, *u32) callconv(.c) c_int,
    launch: *const fn (*anyopaque, *anyopaque) callconv(.c) c_int,
    nodes: *const fn (*anyopaque, *u64, *u64) callconv(.c) c_int,
    destroy_graph: *const fn (*anyopaque) callconv(.c) void,
    destroy_exec: *const fn (*anyopaque) callconv(.c) void,
    pub fn load(lib: *std.DynLib) !Api {
        var api: Api = undefined;
        inline for (.{ .{ "begin", "stwo_rv64_outer_graph_begin" }, .{ "end", "stwo_rv64_outer_graph_end" }, .{ "instantiate", "stwo_rv64_outer_graph_instantiate" }, .{ "update", "stwo_rv64_outer_graph_update" }, .{ "launch", "stwo_rv64_outer_graph_launch" }, .{ "nodes", "stwo_rv64_outer_graph_nodes" }, .{ "destroy_graph", "stwo_rv64_outer_graph_destroy_graph" }, .{ "destroy_exec", "stwo_rv64_outer_graph_destroy_exec" } }) |entry| {
            @field(api, entry[0]) = lib.lookup(@FieldType(Api, entry[0]), entry[1]) orelse return error.MissingOuterGraphSymbol;
        }
        return api;
    }
};

pub const Policy = struct {
    /// Sightings of a key before it is captured. Default 2: the first node of
    /// a class runs direct (any lazy one-time wrapper init happens outside a
    /// capture), the second is captured. STWO_RV64_M8_OUTER_GRAPH_THRESHOLD.
    threshold: u32 = 2,
    /// Device bytes all executables of this worker may hold. 0 disables
    /// capture. STWO_RV64_M8_OUTER_GRAPH_BUDGET_MB (default 256 MiB).
    budget_bytes: u64 = 256 << 20,
    /// STWO_RV64_M8_OUTER_GRAPH=0 disables graphs (direct enqueue).
    enabled: bool = true,
    pub fn fromEnv() Policy {
        var p = Policy{};
        if (std.posix.getenv("STWO_RV64_M8_OUTER_GRAPH")) |v| p.enabled = !std.mem.eql(u8, v, "0");
        if (std.posix.getenv("STWO_RV64_M8_OUTER_GRAPH_THRESHOLD")) |v| p.threshold = @max(1, std.fmt.parseInt(u32, v, 10) catch p.threshold);
        if (std.posix.getenv("STWO_RV64_M8_OUTER_GRAPH_BUDGET_MB")) |v| p.budget_bytes = (std.fmt.parseInt(u64, v, 10) catch (p.budget_bytes >> 20)) << 20;
        return p;
    }
};

pub const Key = struct {
    class: [32]u8,
    placement: u8,
};

pub const Outcome = enum { direct, captured, rebound, reinstantiated, fallback };

pub const Report = struct {
    outcome: Outcome,
    /// Kernel nodes in the recorded graph (launches one graph launch replaces).
    kernel_nodes: u64 = 0,
    total_nodes: u64 = 0,
    /// Host-API launches this node issued: 1 for a graph launch, else the body's.
    launches: u32 = 0,
};

const Entry = struct { exec: *anyopaque, bytes: u64, kernel_nodes: u64, total_nodes: u64 };

pub const Cache = struct {
    allocator: std.mem.Allocator,
    api: Api,
    policy: Policy,
    entries: std.AutoHashMapUnmanaged(Key, Entry) = .empty,
    sightings: std.AutoHashMapUnmanaged(Key, u32) = .empty,
    blacklist: std.AutoHashMapUnmanaged(Key, void) = .empty,
    used_bytes: u64 = 0,
    budget_spent: bool = false,

    pub fn init(a: std.mem.Allocator, api: Api, policy: Policy) Cache {
        return .{ .allocator = a, .api = api, .policy = policy, .budget_spent = !policy.enabled or policy.budget_bytes == 0 };
    }
    pub fn deinit(self: *Cache) void {
        var it = self.entries.valueIterator();
        while (it.next()) |entry| self.api.destroy_exec(entry.exec);
        self.entries.deinit(self.allocator);
        self.sightings.deinit(self.allocator);
        self.blacklist.deinit(self.allocator);
        self.* = undefined;
    }
    fn ban(self: *Cache, key: Key, why: []const u8) void {
        std.log.warn("OUTER_GRAPH blacklist class={x} placement={d} reason={s}", .{ key.class[0..8], key.placement, why });
        if (self.entries.fetchRemove(key)) |old| {
            self.api.destroy_exec(old.value.exec);
            self.used_bytes -= old.value.bytes;
        }
        self.blacklist.put(self.allocator, key, {}) catch {};
    }
    fn wantCapture(self: *Cache, key: Key) !bool {
        if (self.blacklist.contains(key)) return false;
        if (self.entries.contains(key)) return true;
        if (self.budget_spent) return false;
        const seen = try self.sightings.getOrPut(self.allocator, key);
        if (!seen.found_existing) seen.value_ptr.* = 0;
        seen.value_ptr.* += 1;
        return seen.value_ptr.* >= self.policy.threshold;
    }
    /// Runs `body.enqueue()` on `stream`, through a graph when warm.
    /// `body` must provide `enqueue(self) !u32` (host-API launches issued)
    /// and `reset(self) void` (drop node-local allocations of a recorded but
    /// discarded attempt, before a direct re-run).
    pub fn run(self: *Cache, key: Key, stream: *anyopaque, body: anytype) !Report {
        if (!(try self.wantCapture(key))) return .{ .outcome = .direct, .launches = try body.enqueue() };
        if (self.api.begin(stream) != 0) {
            self.ban(key, "begin");
            return .{ .outcome = .fallback, .launches = try body.enqueue() };
        }
        _ = body.enqueue() catch |err| {
            var discarded: ?*anyopaque = null;
            _ = self.api.end(stream, &discarded);
            if (discarded) |g| self.api.destroy_graph(g);
            return err;
        };
        var graph: ?*anyopaque = null;
        if (self.api.end(stream, &graph) != 0 or graph == null) {
            self.ban(key, "capture");
            body.reset();
            return .{ .outcome = .fallback, .launches = try body.enqueue() };
        }
        defer self.api.destroy_graph(graph.?);
        var kernels: u64 = 0;
        var total: u64 = 0;
        _ = self.api.nodes(graph.?, &kernels, &total);
        var outcome: Outcome = .captured;
        if (self.entries.getPtr(key)) |entry| {
            var updated: u32 = 0;
            if (self.api.update(entry.exec, graph.?, &updated) == 0 and updated == 1) {
                if (self.api.launch(entry.exec, stream) != 0) {
                    self.ban(key, "launch");
                    body.reset();
                    return .{ .outcome = .fallback, .launches = try body.enqueue() };
                }
                return .{ .outcome = .rebound, .kernel_nodes = kernels, .total_nodes = total, .launches = 1 };
            }
            // Topology changed: drop the old executable and instantiate anew.
            self.api.destroy_exec(entry.exec);
            self.used_bytes -= entry.bytes;
            _ = self.entries.remove(key);
            outcome = .reinstantiated;
        }
        var exec: ?*anyopaque = null;
        var charged: u64 = 0;
        if (self.api.instantiate(graph.?, &exec, &charged) != 0 or exec == null) {
            self.ban(key, "instantiate");
            body.reset();
            return .{ .outcome = .fallback, .launches = try body.enqueue() };
        }
        if (charged == std.math.maxInt(u64) or self.used_bytes + charged > self.policy.budget_bytes) {
            // Unknown or over-budget cost: never keep it; this device stops capturing.
            self.api.destroy_exec(exec.?);
            self.budget_spent = true;
            std.log.warn("OUTER_GRAPH budget spent used={d} next={d} budget={d}", .{ self.used_bytes, charged, self.policy.budget_bytes });
            body.reset();
            return .{ .outcome = .fallback, .launches = try body.enqueue() };
        }
        if (self.api.launch(exec.?, stream) != 0) {
            self.api.destroy_exec(exec.?);
            self.ban(key, "first-launch");
            body.reset();
            return .{ .outcome = .fallback, .launches = try body.enqueue() };
        }
        try self.entries.put(self.allocator, key, .{ .exec = exec.?, .bytes = charged, .kernel_nodes = kernels, .total_nodes = total });
        self.used_bytes += charged;
        return .{ .outcome = outcome, .kernel_nodes = kernels, .total_nodes = total, .launches = 1 };
    }
};

// ---------------------------------------------------------------------------
const testing = std.testing;
const FakeCuda = struct {
    var capturing = false;
    var recorded: u32 = 0;
    var executed: u32 = 0;
    var graphs_live: i32 = 0;
    var execs_live: i32 = 0;
    var fail_end = false;
    var refuse_update = false;
    var charge: u64 = 1 << 20;
    var token: u8 = 0;
    fn begin(_: *anyopaque) callconv(.c) c_int {
        capturing = true;
        return 0;
    }
    fn end(_: *anyopaque, g: *?*anyopaque) callconv(.c) c_int {
        capturing = false;
        if (fail_end) {
            g.* = null;
            return 1;
        }
        graphs_live += 1;
        g.* = &token;
        return 0;
    }
    fn instantiate(_: *anyopaque, x: *?*anyopaque, c: *u64) callconv(.c) c_int {
        execs_live += 1;
        x.* = &token;
        c.* = charge;
        return 0;
    }
    fn update(_: *anyopaque, _: *anyopaque, ok: *u32) callconv(.c) c_int {
        ok.* = @intFromBool(!refuse_update);
        return 0;
    }
    fn launch(_: *anyopaque, _: *anyopaque) callconv(.c) c_int {
        executed += 1;
        return 0;
    }
    fn nodes(_: *anyopaque, k: *u64, t: *u64) callconv(.c) c_int {
        k.* = 150;
        t.* = 170;
        return 0;
    }
    fn destroyGraph(_: *anyopaque) callconv(.c) void {
        graphs_live -= 1;
    }
    fn destroyExec(_: *anyopaque) callconv(.c) void {
        execs_live -= 1;
    }
    const api = Api{ .begin = begin, .end = end, .instantiate = instantiate, .update = update, .launch = launch, .nodes = nodes, .destroy_graph = destroyGraph, .destroy_exec = destroyExec };
};
const Body = struct {
    resets: u32 = 0,
    fn enqueue(_: *Body) !u32 {
        if (FakeCuda.capturing) FakeCuda.recorded += 1 else FakeCuda.executed += 1;
        return 150;
    }
    fn reset(self: *Body) void {
        self.resets += 1;
    }
};

test "graph cache: direct below threshold, capture once warm, rebind per node, blacklist on failure" {
    var cache = Cache.init(testing.allocator, FakeCuda.api, .{ .threshold = 2 });
    defer cache.deinit();
    var body = Body{};
    var stream: u8 = 0;
    const key = Key{ .class = @splat(7), .placement = 0 };
    try testing.expectEqual(Outcome.direct, (try cache.run(key, &stream, &body)).outcome);
    const captured = try cache.run(key, &stream, &body);
    try testing.expectEqual(Outcome.captured, captured.outcome);
    try testing.expectEqual(@as(u32, 1), captured.launches);
    try testing.expectEqual(@as(u64, 150), captured.kernel_nodes);
    try testing.expectEqual(Outcome.rebound, (try cache.run(key, &stream, &body)).outcome);
    try testing.expectEqual(@as(u32, 3), FakeCuda.executed); // 1 direct + 2 graph launches
    try testing.expectEqual(@as(i32, 0), FakeCuda.graphs_live);
    try testing.expectEqual(@as(i32, 1), FakeCuda.execs_live);
    // Topology change re-instantiates in place.
    FakeCuda.refuse_update = true;
    try testing.expectEqual(Outcome.reinstantiated, (try cache.run(key, &stream, &body)).outcome);
    FakeCuda.refuse_update = false;
    try testing.expectEqual(@as(i32, 1), FakeCuda.execs_live);
    // A failed capture blacklists the key and re-runs the body directly.
    const other = Key{ .class = @splat(8), .placement = 1 };
    _ = try cache.run(other, &stream, &body);
    FakeCuda.fail_end = true;
    const failed = try cache.run(other, &stream, &body);
    FakeCuda.fail_end = false;
    try testing.expectEqual(Outcome.fallback, failed.outcome);
    try testing.expectEqual(@as(u32, 1), body.resets);
    try testing.expectEqual(Outcome.direct, (try cache.run(other, &stream, &body)).outcome);
    // Over budget: never kept, device stops capturing.
    FakeCuda.charge = 1 << 40;
    const third = Key{ .class = @splat(9), .placement = 0 };
    _ = try cache.run(third, &stream, &body);
    try testing.expectEqual(Outcome.fallback, (try cache.run(third, &stream, &body)).outcome);
    try testing.expect(cache.budget_spent);
    try testing.expectEqual(@as(i32, 1), FakeCuda.execs_live);
    FakeCuda.charge = 1 << 20;
}
