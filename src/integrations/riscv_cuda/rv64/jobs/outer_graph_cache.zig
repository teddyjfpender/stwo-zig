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
    /// Device bytes all executables of this worker may hold; the least
    /// recently launched executables are evicted to admit a new one. 0
    /// disables capture. STWO_RV64_M8_OUTER_GRAPH_BUDGET_MB (default 256 MiB).
    budget_bytes: u64 = 256 << 20,
    /// Requests a key may go unused before its executable, sighting count or
    /// blacklist entry is dropped (the cache lives for the whole service and
    /// keys follow block shapes). 0 = never age.
    /// STWO_RV64_M8_OUTER_GRAPH_IDLE_REQUESTS (default 4).
    idle_requests: u32 = 4,
    /// STWO_RV64_M8_OUTER_GRAPH=0 disables graphs (direct enqueue).
    enabled: bool = true,
    pub fn fromEnv() !Policy {
        return .{};
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
    /// Host launch calls, including calls made while recording (even a
    /// discarded recording) and the graph launch attempt. A re-recorded
    /// graph saves device submissions, not host enqueue work.
    launches: u32 = 0,
    recording_launches: u32 = 0,
};

const Entry = struct { exec: *anyopaque, bytes: u64, kernel_nodes: u64, total_nodes: u64, last_use: u64, request: u64 };
const Seen = struct { count: u32, request: u64 };

pub const Cache = struct {
    allocator: std.mem.Allocator,
    api: Api,
    policy: Policy,
    entries: std.AutoHashMapUnmanaged(Key, Entry) = .empty,
    sightings: std.AutoHashMapUnmanaged(Key, Seen) = .empty,
    /// Key -> request it was banned in (aged out like the entries).
    blacklist: std.AutoHashMapUnmanaged(Key, u64) = .empty,
    used_bytes: u64 = 0,
    disabled: bool = false,
    /// Launch clock (LRU order) and the request generation the worker thread
    /// last saw; `noteRequest` (any thread) advances `request_signal`.
    tick: u64 = 0,
    request: u64 = 0,
    request_signal: std.atomic.Value(u64) = .init(0),
    evictions: u64 = 0,
    aged: u64 = 0,

    pub fn init(a: std.mem.Allocator, api: Api, policy: Policy) Cache {
        return .{ .allocator = a, .api = api, .policy = policy, .disabled = !policy.enabled or policy.budget_bytes == 0 };
    }
    pub fn deinit(self: *Cache) void {
        var it = self.entries.valueIterator();
        while (it.next()) |entry| self.api.destroy_exec(entry.exec);
        self.entries.deinit(self.allocator);
        self.sightings.deinit(self.allocator);
        self.blacklist.deinit(self.allocator);
        self.* = undefined;
    }
    /// A new request begins (any thread; the worker thread ages on its next run).
    pub fn noteRequest(self: *Cache) void {
        _ = self.request_signal.fetchAdd(1, .release);
    }
    /// Worker thread: drop executables, sightings and bans idle for more than
    /// `policy.idle_requests` requests. An executable destroyed while a launch
    /// of it is still in flight is freed on completion (cuGraphExecDestroy).
    fn age(self: *Cache) void {
        const now = self.request_signal.load(.acquire);
        if (now == self.request) return;
        self.request = now;
        const idle = self.policy.idle_requests;
        if (idle == 0) return;
        const stale = struct {
            fn f(last: u64, current: u64, limit: u32) bool {
                return current > last and current - last > limit;
            }
        }.f;
        var keys: std.ArrayListUnmanaged(Key) = .empty;
        defer keys.deinit(self.allocator);
        {
            var it = self.entries.iterator();
            while (it.next()) |kv| if (stale(kv.value_ptr.request, now, idle)) keys.append(self.allocator, kv.key_ptr.*) catch return;
        }
        for (keys.items) |key| {
            const old = self.entries.fetchRemove(key).?;
            self.api.destroy_exec(old.value.exec);
            self.used_bytes -= old.value.bytes;
            self.aged += 1;
        }
        keys.clearRetainingCapacity();
        {
            var it = self.sightings.iterator();
            while (it.next()) |kv| if (stale(kv.value_ptr.request, now, idle)) keys.append(self.allocator, kv.key_ptr.*) catch return;
        }
        for (keys.items) |key| _ = self.sightings.remove(key);
        keys.clearRetainingCapacity();
        {
            var it = self.blacklist.iterator();
            while (it.next()) |kv| if (stale(kv.value_ptr.*, now, idle)) keys.append(self.allocator, kv.key_ptr.*) catch return;
        }
        for (keys.items) |key| _ = self.blacklist.remove(key);
    }
    fn ban(self: *Cache, key: Key, why: []const u8) void {
        std.log.warn("OUTER_GRAPH blacklist class={x} placement={d} reason={s}", .{ key.class[0..8], key.placement, why });
        if (self.entries.fetchRemove(key)) |old| {
            self.api.destroy_exec(old.value.exec);
            self.used_bytes -= old.value.bytes;
        }
        self.blacklist.put(self.allocator, key, self.request) catch {};
    }
    fn wantCapture(self: *Cache, key: Key) !bool {
        if (self.disabled) return false;
        if (self.blacklist.contains(key)) return false;
        if (self.entries.contains(key)) return true;
        const seen = try self.sightings.getOrPut(self.allocator, key);
        if (!seen.found_existing) seen.value_ptr.* = .{ .count = 0, .request = self.request };
        seen.value_ptr.count +|= 1;
        seen.value_ptr.request = self.request;
        return seen.value_ptr.count >= self.policy.threshold;
    }
    /// Evict least recently launched executables until `bytes` more fit.
    fn makeRoom(self: *Cache, bytes: u64) void {
        while (self.used_bytes + bytes > self.policy.budget_bytes) {
            var victim: ?Key = null;
            var oldest: u64 = std.math.maxInt(u64);
            var it = self.entries.iterator();
            while (it.next()) |kv| if (kv.value_ptr.last_use < oldest) {
                oldest = kv.value_ptr.last_use;
                victim = kv.key_ptr.*;
            };
            const v = victim orelse return;
            const old = self.entries.fetchRemove(v).?;
            self.api.destroy_exec(old.value.exec);
            self.used_bytes -= old.value.bytes;
            self.evictions += 1;
        }
    }
    /// Runs `body.enqueue()` on `stream`, through a graph when warm.
    /// `body` must provide `enqueue(self) !u32` (host-API launches issued)
    /// and `reset(self) void` (drop node-local allocations of a recorded but
    /// discarded attempt, before a direct re-run).
    pub fn run(self: *Cache, key: Key, stream: *anyopaque, body: anytype) !Report {
        self.age();
        self.tick += 1;
        if (!(try self.wantCapture(key))) return .{ .outcome = .direct, .launches = try body.enqueue() };
        if (self.api.begin(stream) != 0) {
            self.ban(key, "begin");
            return .{ .outcome = .fallback, .launches = try body.enqueue() };
        }
        const recorded = body.enqueue() catch |err| {
            var discarded: ?*anyopaque = null;
            _ = self.api.end(stream, &discarded);
            if (discarded) |g| self.api.destroy_graph(g);
            return err;
        };
        var graph: ?*anyopaque = null;
        if (self.api.end(stream, &graph) != 0 or graph == null) {
            self.ban(key, "capture");
            body.reset();
            return .{ .outcome = .fallback, .launches = recorded +| try body.enqueue(), .recording_launches = recorded };
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
                    return .{ .outcome = .fallback, .launches = recorded +| 1 +| try body.enqueue(), .recording_launches = recorded };
                }
                entry.last_use = self.tick;
                entry.request = self.request;
                return .{ .outcome = .rebound, .kernel_nodes = kernels, .total_nodes = total, .launches = recorded +| 1, .recording_launches = recorded };
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
            return .{ .outcome = .fallback, .launches = recorded +| try body.enqueue(), .recording_launches = recorded };
        }
        if (charged == std.math.maxInt(u64) or charged > self.policy.budget_bytes) {
            // Unknown cost, or one executable larger than the whole budget:
            // never kept, this key runs direct (until its ban ages out).
            self.api.destroy_exec(exec.?);
            self.ban(key, if (charged == std.math.maxInt(u64)) "charge-unknown" else "exceeds-budget");
            body.reset();
            return .{ .outcome = .fallback, .launches = recorded +| try body.enqueue(), .recording_launches = recorded };
        }
        self.makeRoom(charged);
        if (self.api.launch(exec.?, stream) != 0) {
            self.api.destroy_exec(exec.?);
            self.ban(key, "first-launch");
            body.reset();
            return .{ .outcome = .fallback, .launches = recorded +| 1 +| try body.enqueue(), .recording_launches = recorded };
        }
        try self.entries.put(self.allocator, key, .{ .exec = exec.?, .bytes = charged, .kernel_nodes = kernels, .total_nodes = total, .last_use = self.tick, .request = self.request });
        self.used_bytes += charged;
        return .{ .outcome = outcome, .kernel_nodes = kernels, .total_nodes = total, .launches = recorded +| 1, .recording_launches = recorded };
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
    try testing.expectEqual(@as(u32, 151), captured.launches);
    try testing.expectEqual(@as(u32, 150), captured.recording_launches);
    try testing.expectEqual(@as(u64, 150), captured.kernel_nodes);
    const rebound = try cache.run(key, &stream, &body);
    try testing.expectEqual(Outcome.rebound, rebound.outcome);
    try testing.expectEqual(@as(u32, 151), rebound.launches);
    try testing.expectEqual(@as(u32, 150), rebound.recording_launches);
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
    try testing.expectEqual(@as(u32, 300), failed.launches);
    try testing.expectEqual(@as(u32, 150), failed.recording_launches);
    try testing.expectEqual(@as(u32, 1), body.resets);
    try testing.expectEqual(Outcome.direct, (try cache.run(other, &stream, &body)).outcome);
    // One executable larger than the whole budget: never kept, only that key is banned.
    FakeCuda.charge = 1 << 40;
    const third = Key{ .class = @splat(9), .placement = 0 };
    _ = try cache.run(third, &stream, &body);
    try testing.expectEqual(Outcome.fallback, (try cache.run(third, &stream, &body)).outcome);
    try testing.expectEqual(@as(i32, 1), FakeCuda.execs_live);
    FakeCuda.charge = 1 << 20;
    try testing.expectEqual(Outcome.rebound, (try cache.run(key, &stream, &body)).outcome);
}

test "graph cache: over budget evicts the least recently launched executable; new keys keep capturing" {
    FakeCuda.execs_live = 0;
    FakeCuda.graphs_live = 0;
    FakeCuda.charge = 1 << 20;
    // Room for exactly 3 executables of 1 MiB.
    var cache = Cache.init(testing.allocator, FakeCuda.api, .{ .threshold = 1, .budget_bytes = 3 << 20, .idle_requests = 0 });
    defer cache.deinit();
    var body = Body{};
    var stream: u8 = 0;
    var k: u8 = 0;
    while (k < 10) : (k += 1) {
        const key = Key{ .class = @splat(k), .placement = 0 };
        try testing.expectEqual(Outcome.captured, (try cache.run(key, &stream, &body)).outcome);
        // Key 0 stays hot: rebound after every new key.
        if (k != 0) try testing.expectEqual(Outcome.rebound, (try cache.run(.{ .class = @splat(0), .placement = 0 }, &stream, &body)).outcome);
        try testing.expect(cache.used_bytes <= 3 << 20);
    }
    try testing.expectEqual(@as(usize, 3), cache.entries.count());
    try testing.expect(cache.entries.contains(.{ .class = @splat(0), .placement = 0 }));
    try testing.expectEqual(@as(u64, 7), cache.evictions);
    try testing.expectEqual(@as(i32, 3), FakeCuda.execs_live);
}

test "graph cache: executables, sightings and bans idle for more than idle_requests requests age out" {
    FakeCuda.execs_live = 0;
    FakeCuda.graphs_live = 0;
    FakeCuda.charge = 1 << 20;
    var cache = Cache.init(testing.allocator, FakeCuda.api, .{ .threshold = 1, .idle_requests = 2 });
    defer cache.deinit();
    var body = Body{};
    var stream: u8 = 0;
    const old = Key{ .class = @splat(1), .placement = 0 };
    const hot = Key{ .class = @splat(2), .placement = 0 };
    const banned = Key{ .class = @splat(3), .placement = 0 };
    _ = try cache.run(old, &stream, &body);
    FakeCuda.fail_end = true;
    try testing.expectEqual(Outcome.fallback, (try cache.run(banned, &stream, &body)).outcome);
    FakeCuda.fail_end = false;
    var r: u32 = 0;
    while (r < 3) : (r += 1) {
        cache.noteRequest();
        _ = try cache.run(hot, &stream, &body);
        // Still within the idle window after 2 requests.
        if (r < 2) try testing.expect(cache.entries.contains(old));
    }
    try testing.expect(!cache.entries.contains(old));
    try testing.expect(!cache.blacklist.contains(banned));
    try testing.expect(cache.entries.contains(hot));
    try testing.expectEqual(@as(u64, 1), cache.aged);
    try testing.expectEqual(@as(i32, 1), FakeCuda.execs_live);
    // An aged-out ban captures again.
    try testing.expectEqual(Outcome.captured, (try cache.run(banned, &stream, &body)).outcome);
}
