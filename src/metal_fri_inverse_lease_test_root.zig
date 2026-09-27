//! Device-free same-budget inverse concurrency. No device/proof is invoked.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Budget = engine.host_budget_allocator.SharedHostBudget;
const Inverses = @import("backends/metal/runtime/fri_inverse_cache_budget_v1.zig");
const Key = Inverses.Key;
const Counter = std.atomic.Value(usize);
const Resource = struct {
    id: usize,
    destroyed: *Counter,
    pub fn deinit(self: *Resource) void {
        _ = self.destroyed.fetchAdd(1, .seq_cst);
        self.* = undefined;
    }
};
const Factory = struct {
    created: *Counter,
    destroyed: *Counter,
    fail_at: usize = 0,
    oom_at: usize = 0,
    pub fn create(self: Factory, _: Key, _: usize) !Resource {
        const id = self.created.fetchAdd(1, .seq_cst) + 1;
        if (id == self.fail_at) return error.InverseFactoryFailed;
        if (id == self.oom_at) return error.OutOfMemory;
        return .{ .id = id, .destroyed = self.destroyed };
    }
};
const Cache = Inverses.Cache(Resource);
fn circle(count: u32) Key {
    const log = std.math.log2_int(u32, count);
    return .{ .runtime = 1, .count = count, .layers = 1, .initial = @as(u32, 1) << @intCast(29 - log), .step = @as(u32, 1) << @intCast(31 - log), .kind = .circle };
}
const Completion = struct {
    joins: usize = 0,
    cancels: usize = 0,
    fail: bool = false,
    fn join(context: ?*anyopaque) anyerror!void {
        const self: *Completion = @ptrCast(@alignCast(context.?));
        self.joins += 1;
        if (self.fail) return error.InvalidDeviceStatus;
    }
    fn cancel(context: ?*anyopaque) anyerror!void {
        const self: *Completion = @ptrCast(@alignCast(context.?));
        self.cancels += 1;
    }
    fn pending(self: *Completion) engine.shared_external_memory.Completion {
        return .pending(self, join, cancel);
    }
};

test "FRI leases: same-key readers overlap and drain is busy until both finish" {
    const owner = try Budget.create(std.testing.allocator, 128);
    defer owner.destroy();
    var created = Counter.init(0);
    var destroyed = Counter.init(0);
    const factory = Factory{ .created = &created, .destroyed = &destroyed };
    var cache: Cache = .{};
    var cold = try cache.begin(owner.allocator(), .{ circle(4), null }, factory);
    try cold.complete();
    var first = try cache.begin(owner.allocator(), .{ circle(4), null }, factory);
    var second = try cache.begin(owner.allocator(), .{ circle(4), null }, factory);
    try std.testing.expect(first.resource(.circle).? == second.resource(.circle).?);
    try std.testing.expect(!first.needsGeneration(.circle) and !second.needsGeneration(.circle));
    try std.testing.expectError(error.RuntimeBusy, cache.drain(owner.allocator()));
    first.abort();
    try std.testing.expectError(error.RuntimeBusy, cache.drain(owner.allocator()));
    try std.testing.expectEqual(@as(usize, 1), second.resource(.circle).?.id);
    try second.complete();
    try cache.drain(owner.allocator());
    try std.testing.expectEqual(@as(usize, 1), created.load(.seq_cst));
    try std.testing.expectEqual(@as(usize, 1), destroyed.load(.seq_cst));
}

test "FRI leases: replacement cannot mutate or release an older live reader" {
    const owner = try Budget.create(std.testing.allocator, 1024);
    defer owner.destroy();
    var created = Counter.init(0);
    var destroyed = Counter.init(0);
    const factory = Factory{ .created = &created, .destroyed = &destroyed };
    var cache: Cache = .{};
    var initial = try cache.begin(owner.allocator(), .{ circle(4), null }, factory);
    try initial.complete();
    var reader = try cache.begin(owner.allocator(), .{ circle(4), null }, factory);
    const old = reader.resource(.circle).?;
    const old_id = old.id;
    var replacement = try cache.begin(owner.allocator(), .{ circle(8), null }, factory);
    try std.testing.expectEqual(@as(usize, 48), owner.snapshot().external_live_bytes);
    try replacement.complete();
    try std.testing.expectEqual(old_id, old.id);
    try std.testing.expectEqual(@as(usize, 0), destroyed.load(.seq_cst));
    var newest = try cache.begin(owner.allocator(), .{ circle(8), null }, factory);
    try std.testing.expect(!newest.needsGeneration(.circle));
    reader.abort();
    // A completed older geometry is still reusable after its last reader.
    try std.testing.expectEqual(@as(usize, 0), destroyed.load(.seq_cst));
    try std.testing.expectEqual(@as(usize, 48), owner.snapshot().external_live_bytes);
    var old_hit = try cache.begin(owner.allocator(), .{ circle(4), null }, factory);
    try std.testing.expect(!old_hit.needsGeneration(.circle));
    try std.testing.expectEqual(old_id, old_hit.resource(.circle).?.id);
    old_hit.abort();
    newest.abort();
    try cache.drain(owner.allocator());
    try std.testing.expectEqual(created.load(.seq_cst), destroyed.load(.seq_cst));
}

test "FRI leases: private racing proposals publish only successful checked work" {
    const owner = try Budget.create(std.testing.allocator, 128);
    defer owner.destroy();
    var created = Counter.init(0);
    var destroyed = Counter.init(0);
    const factory = Factory{ .created = &created, .destroyed = &destroyed };
    var cache: Cache = .{};
    var failed = try cache.begin(owner.allocator(), .{ circle(4), null }, factory);
    var winner = try cache.begin(owner.allocator(), .{ circle(4), null }, factory);
    try std.testing.expect(failed.needsGeneration(.circle) and winner.needsGeneration(.circle));
    const winner_id = winner.resource(.circle).?.id;
    var failure = Completion{ .fail = true };
    try failed.bindCompletion(failure.pending());
    try winner.complete();
    try std.testing.expectError(error.InvalidDeviceStatus, failed.complete());
    try std.testing.expectEqual(@as(usize, 1), failure.joins);
    var retained = try cache.begin(owner.allocator(), .{ circle(4), null }, factory);
    try std.testing.expectEqual(winner_id, retained.resource(.circle).?.id);
    retained.abort();
    var cancelled = try cache.begin(owner.allocator(), .{ circle(8), null }, factory);
    var cancellation: Completion = .{};
    try cancelled.bindCompletion(cancellation.pending());
    var moved = cancelled.take();
    cancelled.abort();
    moved.abort();
    moved.abort();
    try std.testing.expectEqual(@as(usize, 1), cancellation.cancels);
    try cache.drain(owner.allocator());
    try std.testing.expectEqual(created.load(.seq_cst), destroyed.load(.seq_cst));
}

test "FRI leases: concurrent duplicate generation is charged and safely deduplicated" {
    const owner = try Budget.create(std.testing.allocator, 256);
    defer owner.destroy();
    const working = try owner.allocator().alloc(u8, 224);
    defer owner.allocator().free(working);
    var created = Counter.init(0);
    var destroyed = Counter.init(0);
    const factory = Factory{ .created = &created, .destroyed = &destroyed };
    var cache: Cache = .{};
    var first = try cache.begin(owner.allocator(), .{ circle(4), null }, factory);
    var duplicate = try cache.begin(owner.allocator(), .{ circle(4), null }, factory);
    try std.testing.expectEqual(@as(usize, 32), owner.snapshot().external_live_bytes);
    try std.testing.expectError(error.OutOfMemory, cache.begin(owner.allocator(), .{ circle(4), null }, factory));
    try first.complete();
    try duplicate.complete();
    try std.testing.expectEqual(@as(usize, 16), owner.snapshot().external_live_bytes);
    try std.testing.expectEqual(@as(usize, 1), destroyed.load(.seq_cst));
    try cache.drain(owner.allocator());
}

test "FRI leases: all key fields are admitted and factory rollback preserves existing readers" {
    const owner = try Budget.create(std.testing.allocator, 128);
    defer owner.destroy();
    var created = Counter.init(0);
    var destroyed = Counter.init(0);
    const factory = Factory{ .created = &created, .destroyed = &destroyed };
    var cache: Cache = .{};
    var first = try cache.begin(owner.allocator(), .{ circle(4), null }, factory);
    try first.complete();
    var reader = try cache.begin(owner.allocator(), .{ circle(4), null }, factory);
    var wrong_runtime = circle(4);
    wrong_runtime.runtime = 2;
    try std.testing.expectError(error.InvalidFriInverseCacheRuntime, cache.begin(owner.allocator(), .{ wrong_runtime, null }, factory));
    var changed = circle(4);
    changed.initial *= 3;
    var changed_domain = try cache.begin(owner.allocator(), .{ changed, null }, factory);
    try std.testing.expect(changed_domain.needsGeneration(.circle));
    changed_domain.abort();
    const before = created.load(.seq_cst);
    try std.testing.expectError(error.InverseFactoryFailed, cache.begin(owner.allocator(), .{ circle(8), null }, Factory{ .created = &created, .destroyed = &destroyed, .fail_at = before + 1 }));
    try std.testing.expectEqual(@as(usize, 1), reader.resource(.circle).?.id);
    try std.testing.expectEqual(@as(usize, 16), owner.snapshot().external_live_bytes);
    reader.abort();
    try cache.drain(owner.allocator());
    try std.testing.expectEqual(created.load(.seq_cst) - 1, destroyed.load(.seq_cst));
}

test "FRI leases: bounded reader admission and original owner release preserve lifetime" {
    const owner = try Budget.create(std.testing.allocator, 128);
    var created = Counter.init(0);
    var destroyed = Counter.init(0);
    const factory = Factory{ .created = &created, .destroyed = &destroyed };
    var cache: Cache = .{};
    var first = try cache.begin(owner.allocator(), .{ circle(4), null }, factory);
    try first.complete();
    var users: [Inverses.Limits.max_transactions]Cache.Transaction = undefined;
    var started: usize = 0;
    defer for (users[0..started]) |*user| user.abort();
    for (&users) |*user| {
        var acquired = try cache.begin(owner.allocator(), .{ circle(4), null }, factory);
        user.* = acquired.take();
        started += 1;
    }
    try std.testing.expectError(error.FriInverseCacheCapacityExceeded, cache.begin(owner.allocator(), .{ circle(4), null }, factory));
    owner.destroy();
    for (&users) |*user| user.abort();
    started = 0;
    // Idle entries themselves retain the budget until an explicit drain.
    try cache.drain(owner.allocator());
    try std.testing.expectEqual(@as(usize, 1), destroyed.load(.seq_cst));
}

test "FRI leases: checked completions overlap on the same admitted inverse buffer" {
    const owner = try Budget.create(std.testing.allocator, 128);
    defer owner.destroy();
    var created = Counter.init(0);
    var destroyed = Counter.init(0);
    const factory = Factory{ .created = &created, .destroyed = &destroyed };
    var cache: Cache = .{};
    var first = try cache.begin(owner.allocator(), .{ circle(4), null }, factory);
    try first.complete();
    const Overlap = struct {
        entered: Counter = Counter.init(0),
        failed: std.atomic.Value(bool) = .init(false),
        fn join(context: ?*anyopaque) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            _ = self.entered.fetchAdd(1, .seq_cst);
            var timer = try std.time.Timer.start();
            while (self.entered.load(.seq_cst) != 2) {
                if (timer.read() > 5 * std.time.ns_per_s) {
                    self.failed.store(true, .seq_cst);
                    return error.SerializedInverseCompletion;
                }
                std.Thread.yield() catch {};
            }
        }
        fn work(target: *Cache, a: std.mem.Allocator, provider: Factory, overlap: *@This()) void {
            var current = target.begin(a, .{ circle(4), null }, provider) catch {
                overlap.failed.store(true, .seq_cst);
                return;
            };
            current.bindCompletion(.pending(overlap, join, null)) catch unreachable;
            current.complete() catch {
                overlap.failed.store(true, .seq_cst);
            };
        }
    };
    var overlap: Overlap = .{};
    const left = try std.Thread.spawn(.{}, Overlap.work, .{ &cache, owner.allocator(), factory, &overlap });
    const right = std.Thread.spawn(.{}, Overlap.work, .{ &cache, owner.allocator(), factory, &overlap }) catch |err| {
        left.join();
        return err;
    };
    left.join();
    right.join();
    try std.testing.expect(!overlap.failed.load(.seq_cst));
    try std.testing.expectEqual(@as(usize, 2), overlap.entered.load(.seq_cst));
    try std.testing.expectEqual(@as(usize, 1), created.load(.seq_cst));
    try cache.drain(owner.allocator());
}

test "FRI leases: a full immutable entry set cannot evict active domains" {
    const owner = try Budget.create(std.testing.allocator, 256);
    defer owner.destroy();
    var created = Counter.init(0);
    var destroyed = Counter.init(0);
    const factory = Factory{ .created = &created, .destroyed = &destroyed };
    var cache: Cache = .{};
    var readers: [Inverses.Limits.max_entries]Cache.Transaction = undefined;
    var started: usize = 0;
    defer for (readers[0..started]) |*reader| reader.abort();
    for (&readers, 0..) |*reader, index| {
        var domain = circle(4);
        domain.initial *= @as(u32, @intCast(2 * index + 1));
        var proposal = try cache.begin(owner.allocator(), .{ domain, null }, factory);
        try proposal.complete();
        var acquired = try cache.begin(owner.allocator(), .{ domain, null }, factory);
        reader.* = acquired.take();
        started += 1;
    }
    try std.testing.expectEqual(@as(usize, Inverses.Limits.max_entries * 16), owner.snapshot().external_live_bytes);
    var excess = try cache.begin(owner.allocator(), .{ circle(8), null }, factory);
    try excess.complete();
    // Checked work succeeds, but its buffer is not cached by evicting readers.
    try std.testing.expectEqual(@as(usize, 1), destroyed.load(.seq_cst));
    for (&readers, 0..) |*reader, index| try std.testing.expectEqual(index + 1, reader.resource(.circle).?.id);
    var uncached = try cache.begin(owner.allocator(), .{ circle(8), null }, factory);
    try std.testing.expect(uncached.needsGeneration(.circle));
    uncached.abort();
    for (&readers) |*reader| reader.abort();
    started = 0;
    try cache.drain(owner.allocator());
    try std.testing.expectEqual(created.load(.seq_cst), destroyed.load(.seq_cst));
}

test "FRI leases: factory OOM releases only private reservations and borrowed readers" {
    const owner = try Budget.create(std.testing.allocator, 128);
    defer owner.destroy();
    var created = Counter.init(0);
    var destroyed = Counter.init(0);
    const factory = Factory{ .created = &created, .destroyed = &destroyed };
    var cache: Cache = .{};
    var warmed = try cache.begin(owner.allocator(), .{ circle(4), null }, factory);
    try warmed.complete();
    var held = try cache.begin(owner.allocator(), .{ circle(4), null }, factory);
    var line_key = circle(8);
    line_key.kind = .line;
    line_key.layers = 2;
    try std.testing.expectError(error.OutOfMemory, cache.begin(owner.allocator(), .{ circle(4), line_key }, Factory{ .created = &created, .destroyed = &destroyed, .oom_at = 2 }));
    try std.testing.expectEqual(@as(usize, 16), owner.snapshot().external_live_bytes);
    try std.testing.expectEqual(@as(usize, 1), held.resource(.circle).?.id);
    try std.testing.expectError(error.RuntimeBusy, cache.drain(owner.allocator()));
    held.abort();
    try cache.drain(owner.allocator());
    try std.testing.expectEqual(@as(usize, 1), destroyed.load(.seq_cst));
}

test "FRI leases: cold resource factories can overlap before private publication" {
    const owner = try Budget.create(std.testing.allocator, 128);
    defer owner.destroy();
    var created = Counter.init(0);
    var destroyed = Counter.init(0);
    var cache: Cache = .{};
    const ParallelFactory = struct {
        entered: Counter = .init(0),
        failed: std.atomic.Value(bool) = .init(false),
        created: *Counter,
        destroyed: *Counter,
        pub fn create(self: *@This(), _: Key, _: usize) !Resource {
            _ = self.entered.fetchAdd(1, .seq_cst);
            var timer = try std.time.Timer.start();
            while (self.entered.load(.seq_cst) != 2) {
                if (timer.read() > 5 * std.time.ns_per_s) {
                    self.failed.store(true, .seq_cst);
                    return error.SerializedInverseFactory;
                }
                std.Thread.yield() catch {};
            }
            return .{ .id = self.created.fetchAdd(1, .seq_cst) + 1, .destroyed = self.destroyed };
        }
        fn work(target: *Cache, a: std.mem.Allocator, factory: *@This()) void {
            var transaction = target.begin(a, .{ circle(4), null }, factory) catch {
                factory.failed.store(true, .seq_cst);
                return;
            };
            transaction.complete() catch {
                factory.failed.store(true, .seq_cst);
            };
        }
    };
    var factory = ParallelFactory{ .created = &created, .destroyed = &destroyed };
    const first = try std.Thread.spawn(.{}, ParallelFactory.work, .{ &cache, owner.allocator(), &factory });
    const second = std.Thread.spawn(.{}, ParallelFactory.work, .{ &cache, owner.allocator(), &factory }) catch |err| {
        first.join();
        return err;
    };
    first.join();
    second.join();
    try std.testing.expect(!factory.failed.load(.seq_cst));
    try std.testing.expectEqual(@as(usize, 2), created.load(.seq_cst));
    try std.testing.expectEqual(@as(usize, 1), destroyed.load(.seq_cst));
    try std.testing.expectEqual(@as(usize, 16), owner.snapshot().external_live_bytes);
    try cache.drain(owner.allocator());
}

test "FRI leases: changing layer count or step requires a distinct inverse" {
    const owner = try Budget.create(std.testing.allocator, 128);
    defer owner.destroy();
    var created = Counter.init(0);
    var destroyed = Counter.init(0);
    const factory = Factory{ .created = &created, .destroyed = &destroyed };
    var cache: Cache = .{};
    var original = circle(8);
    original.kind = .line;
    var initial = try cache.begin(owner.allocator(), .{ null, original }, factory);
    try initial.complete();
    var retained = try cache.begin(owner.allocator(), .{ null, original }, factory);
    var changed = original;
    changed.layers = 2;
    var layer = try cache.begin(owner.allocator(), .{ null, changed }, factory);
    try std.testing.expect(layer.needsGeneration(.line));
    layer.abort();
    changed = original;
    changed.step *= 3;
    var step = try cache.begin(owner.allocator(), .{ null, changed }, factory);
    try std.testing.expect(step.needsGeneration(.line));
    step.abort();
    retained.abort();
    try cache.drain(owner.allocator());
    try std.testing.expectEqual(created.load(.seq_cst), destroyed.load(.seq_cst));
}

test "FRI LRU: alternating actual circle and line geometries reuse admitted resources" {
    const owner = try Budget.create(std.testing.allocator, 1024);
    defer owner.destroy();
    var created = Counter.init(0);
    var destroyed = Counter.init(0);
    const factory = Factory{ .created = &created, .destroyed = &destroyed };
    var cache: Cache = .{};
    var low_line = circle(8);
    low_line.kind = .line;
    low_line.layers = 2;
    var high_line = circle(16);
    high_line.kind = .line;
    high_line.layers = 2;
    const keys = [2][2]?Key{ .{ circle(4), low_line }, .{ circle(8), high_line } };
    var ids: [2][2]usize = undefined;
    for (0..8) |round| {
        for (keys, 0..) |pair, index| {
            var transaction = try cache.begin(owner.allocator(), pair, factory);
            if (round == 0) {
                try std.testing.expect(transaction.needsGeneration(.circle) and transaction.needsGeneration(.line));
                ids[index] = .{ transaction.resource(.circle).?.id, transaction.resource(.line).?.id };
            } else {
                try std.testing.expect(!transaction.needsGeneration(.circle) and !transaction.needsGeneration(.line));
                try std.testing.expectEqual(ids[index][0], transaction.resource(.circle).?.id);
                try std.testing.expectEqual(ids[index][1], transaction.resource(.line).?.id);
            }
            try transaction.complete();
        }
    }
    try std.testing.expectEqual(@as(usize, 4), created.load(.seq_cst));
    try std.testing.expectEqual(@as(usize, 120), owner.snapshot().external_live_bytes);
    try cache.drain(owner.allocator());
    try std.testing.expectEqual(created.load(.seq_cst), destroyed.load(.seq_cst));
}

test "FRI LRU: ninth geometry evicts least recently used idle entry" {
    const owner = try Budget.create(std.testing.allocator, 2048);
    defer owner.destroy();
    var created = Counter.init(0);
    var destroyed = Counter.init(0);
    const factory = Factory{ .created = &created, .destroyed = &destroyed };
    var cache: Cache = .{};
    var domains: [9]Key = undefined;
    for (&domains, 0..) |*domain, index| {
        domain.* = circle(8);
        domain.initial *= @as(u32, @intCast(2 * index + 1));
    }
    for (domains[0..8]) |domain| {
        var transaction = try cache.begin(owner.allocator(), .{ domain, null }, factory);
        try transaction.complete();
    }
    var most_recent = try cache.begin(owner.allocator(), .{ domains[0], null }, factory);
    const recent_id = most_recent.resource(.circle).?.id;
    most_recent.abort();
    var ninth = try cache.begin(owner.allocator(), .{ domains[8], null }, factory);
    try ninth.complete();
    try std.testing.expectEqual(@as(usize, 1), destroyed.load(.seq_cst));
    try std.testing.expectEqual(@as(usize, 256), owner.snapshot().external_live_bytes);
    var recent_hit = try cache.begin(owner.allocator(), .{ domains[0], null }, factory);
    try std.testing.expect(!recent_hit.needsGeneration(.circle));
    try std.testing.expectEqual(recent_id, recent_hit.resource(.circle).?.id);
    recent_hit.abort();
    var oldest_miss = try cache.begin(owner.allocator(), .{ domains[1], null }, factory);
    try std.testing.expect(oldest_miss.needsGeneration(.circle));
    oldest_miss.abort();
    try cache.drain(owner.allocator());
    try std.testing.expectEqual(created.load(.seq_cst), destroyed.load(.seq_cst));
}

test "FRI LRU: pressure eviction is explicit while live readers survive failed factories" {
    const owner = try Budget.create(std.testing.allocator, 512);
    defer owner.destroy();
    var created = Counter.init(0);
    var destroyed = Counter.init(0);
    const factory = Factory{ .created = &created, .destroyed = &destroyed };
    var cache: Cache = .{};
    var small = try cache.begin(owner.allocator(), .{ circle(4), null }, factory);
    try small.complete();
    var idle = try cache.begin(owner.allocator(), .{ circle(8), null }, factory);
    try idle.complete();
    var held = try cache.begin(owner.allocator(), .{ circle(4), null }, factory);
    const held_id = held.resource(.circle).?.id;
    const working = try owner.allocator().alloc(u8, 448);
    var working_alive = true;
    defer if (working_alive) owner.allocator().free(working);
    var changed = circle(8);
    changed.initial *= 3;
    try std.testing.expectError(error.InverseFactoryFailed, cache.begin(owner.allocator(), .{ changed, null }, Factory{ .created = &created, .destroyed = &destroyed, .fail_at = 3 }));
    // Reclaiming the idle32-byte buffer admitted the miss without overcharging.
    // It is not restored after failure, while the live16-byte buffer is intact.
    try std.testing.expectEqual(@as(usize, 1), destroyed.load(.seq_cst));
    try std.testing.expectEqual(held_id, held.resource(.circle).?.id);
    try std.testing.expectEqual(@as(usize, 16), owner.snapshot().external_live_bytes);
    try std.testing.expect(!owner.snapshot().exceeded);
    owner.allocator().free(working);
    working_alive = false;
    var evicted_miss = try cache.begin(owner.allocator(), .{ circle(8), null }, factory);
    try std.testing.expect(evicted_miss.needsGeneration(.circle));
    evicted_miss.abort();
    held.abort();
    var still_admitted = try cache.begin(owner.allocator(), .{ circle(4), null }, factory);
    try std.testing.expect(!still_admitted.needsGeneration(.circle));
    still_admitted.abort();
    try cache.drain(owner.allocator());
    try std.testing.expectEqual(created.load(.seq_cst) - 1, destroyed.load(.seq_cst));
}

test "FRI LRU: reservation pressure can reclaim idle bytes for valid larger work" {
    const owner = try Budget.create(std.testing.allocator, 512);
    defer owner.destroy();
    var created = Counter.init(0);
    var destroyed = Counter.init(0);
    const factory = Factory{ .created = &created, .destroyed = &destroyed };
    var cache: Cache = .{};
    for ([_]Key{ circle(4), circle(8) }) |key| {
        var transaction = try cache.begin(owner.allocator(), .{ key, null }, factory);
        try transaction.complete();
    }
    const working = try owner.allocator().alloc(u8, 448);
    defer owner.allocator().free(working);
    var larger = try cache.begin(owner.allocator(), .{ circle(16), null }, factory);
    try std.testing.expectEqual(@as(usize, 2), destroyed.load(.seq_cst));
    try std.testing.expectEqual(@as(usize, 512), owner.snapshot().live_bytes);
    try larger.complete();
    try std.testing.expectEqual(@as(usize, 64), owner.snapshot().external_live_bytes);
    try std.testing.expect(!owner.snapshot().exceeded);
    var hit = try cache.begin(owner.allocator(), .{ circle(16), null }, factory);
    try std.testing.expect(!hit.needsGeneration(.circle));
    hit.abort();
    try cache.drain(owner.allocator());
}

test "FRI LRU: oversized idle inverses remain private without weakening proof admission" {
    const owner = try Budget.create(std.testing.allocator, 128);
    defer owner.destroy();
    var created = Counter.init(0);
    var destroyed = Counter.init(0);
    const factory = Factory{ .created = &created, .destroyed = &destroyed };
    var cache: Cache = .{};
    for (0..2) |_| {
        var transaction = try cache.begin(owner.allocator(), .{ circle(8), null }, factory);
        try std.testing.expect(transaction.needsGeneration(.circle));
        try transaction.complete();
        try std.testing.expectEqual(@as(usize, 0), owner.snapshot().external_live_bytes);
    }
    try std.testing.expectEqual(@as(usize, 2), destroyed.load(.seq_cst));
    try cache.drain(owner.allocator());
}

test "FRI LRU: large fused circle and line pair fits intentional idle ceilings" {
    const mib: usize = 1024 * 1024;
    const gib: usize = 1024 * mib;
    try std.testing.expectEqual(@as(usize, 256 * mib), Inverses.Limits.idleBytesForOwner(40 * gib));
    try std.testing.expectEqual(@as(usize, 128 * mib), Inverses.Limits.idleBytesForOwner(gib));
    for ([_]u32{ 1 << 24, 1 << 25 }) |count| {
        const circle_key = circle(count);
        var line_key = circle_key;
        line_key.kind = .line;
        line_key.layers = std.math.log2_int(u32, count);
        const pair_bytes = try std.math.add(usize, try circle_key.bytes(), try line_key.bytes());
        try std.testing.expect(pair_bytes <= Inverses.Limits.idleBytesForOwner(40 * gib));
        try std.testing.expectEqual(@as(usize, count) * 8 - 4, pair_bytes);
    }
    try std.testing.expectEqual(@as(usize, 0), Inverses.Limits.idleBytesForOwner(7));
    try std.testing.expectEqual(@as(usize, 8), Inverses.Limits.idleBytesForOwner(64));
}

test "FRI LRU: pressure publication on another thread preserves a live reader" {
    const owner = try Budget.create(std.testing.allocator, 512);
    defer owner.destroy();
    var created = Counter.init(0);
    var destroyed = Counter.init(0);
    const factory = Factory{ .created = &created, .destroyed = &destroyed };
    var cache: Cache = .{};
    for ([_]Key{ circle(4), circle(8) }) |key| {
        var cold = try cache.begin(owner.allocator(), .{ key, null }, factory);
        try cold.complete();
    }
    var held = try cache.begin(owner.allocator(), .{ circle(4), null }, factory);
    const reader = held.resource(.circle).?;
    const id = reader.id;
    const working = try owner.allocator().alloc(u8, 448);
    defer owner.allocator().free(working);
    const Worker = struct {
        fn work(target: *Cache, a: std.mem.Allocator, provider: Factory, failed: *std.atomic.Value(bool)) void {
            var changed = circle(8);
            changed.initial *= 3;
            var transaction = target.begin(a, .{ changed, null }, provider) catch {
                failed.store(true, .seq_cst);
                return;
            };
            transaction.complete() catch {
                failed.store(true, .seq_cst);
            };
        }
    };
    var failed: std.atomic.Value(bool) = .init(false);
    const worker = try std.Thread.spawn(.{}, Worker.work, .{ &cache, owner.allocator(), factory, &failed });
    worker.join();
    try std.testing.expect(!failed.load(.seq_cst));
    try std.testing.expectEqual(id, reader.id);
    try std.testing.expectEqual(@as(usize, 1), destroyed.load(.seq_cst));
    try std.testing.expectEqual(@as(usize, 48), owner.snapshot().external_live_bytes);
    held.abort();
    try cache.drain(owner.allocator());
    try std.testing.expectEqual(created.load(.seq_cst), destroyed.load(.seq_cst));
}
