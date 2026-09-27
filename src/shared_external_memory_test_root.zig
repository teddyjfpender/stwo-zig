//! Device-free external ownership and shared heap/device admission tests.
const std = @import("std");
const external = @import("prover/shared_external_memory_v1.zig");
const Budget = external.SharedBudget;

test "shared external: heap and external bytes compete at the exact boundary" {
    const owner = try Budget.create(std.testing.allocator, 48);
    defer owner.destroy();
    const a = owner.allocator();
    const heap = try a.alloc(u8, 16);
    defer a.free(heap);
    var reservation = try owner.reserveExternal(32);
    defer reservation.deinit();
    const full = owner.snapshot();
    try std.testing.expectEqual(@as(usize, 48), full.live_bytes);
    try std.testing.expectEqual(@as(usize, 16), full.host_live_bytes);
    try std.testing.expectEqual(@as(usize, 32), full.external_live_bytes);
    try std.testing.expectError(error.OutOfMemory, a.alloc(u8, 1));
    try std.testing.expectError(error.OutOfMemory, owner.reserveExternal(1));
    try std.testing.expectError(error.OutOfMemory, reservation.resize(33));
    try std.testing.expectEqual(full.live_bytes, owner.snapshot().live_bytes);
    try reservation.resize(8);
    const next = try a.alloc(u8, 24);
    a.free(next);
    const shrunk = owner.snapshot();
    try std.testing.expectEqual(@as(usize, 48), shrunk.peak_live_bytes);
    try std.testing.expectEqual(@as(usize, 40), shrunk.peak_host_bytes);
    try std.testing.expectEqual(@as(usize, 32), shrunk.peak_external_bytes);
}

test "shared external: resident extent requires the actual charged local owner" {
    const first = try Budget.create(std.testing.allocator, 16);
    defer first.destroy();
    const second = try Budget.create(std.testing.allocator, 16);
    defer second.destroy();
    var charged = try first.reserveExternal(8);
    defer charged.deinit();
    try charged.requireOwner(first.allocator(), 8);
    try std.testing.expectError(error.InvalidExternalReservationOwner, charged.requireOwner(first.allocator(), 9));
    try std.testing.expectError(error.InvalidExternalReservationOwner, charged.requireOwner(second.allocator(), 8));
    try std.testing.expectError(error.InvalidExternalReservationOwner, charged.requireOwner(std.testing.allocator, 8));
    var moved = charged.take();
    defer moved.deinit();
    try std.testing.expectError(error.InvalidExternalReservationOwner, charged.requireOwner(first.allocator(), 0));
    try moved.requireOwner(first.allocator(), 8);
    var unbudgeted = Budget.ExternalReservation.unbudgeted(8);
    defer unbudgeted.deinit();
    try std.testing.expectError(error.InvalidExternalReservationOwner, unbudgeted.requireOwner(first.allocator(), 8));
}

test "shared external: overflow rollback and consuming lease survive root release" {
    const owner = try Budget.create(std.testing.allocator, std.math.maxInt(usize));
    var reservation = try owner.reserveExternal(std.math.maxInt(usize));
    var retained = reservation.take();
    reservation.deinit();
    try std.testing.expectError(error.OutOfMemory, owner.reserveExternal(1));
    try std.testing.expectError(error.OutOfMemory, owner.allocator().alloc(u8, 1));
    owner.destroy();
    try retained.resize(7);
    try std.testing.expectEqual(@as(usize, 7), retained.owner.?.snapshot().external_live_bytes);
    retained.deinit();
    retained.deinit();
}

test "shared external: host resize cannot grow past an external reservation" {
    var storage: [128]u8 = undefined;
    var child = std.heap.FixedBufferAllocator.init(&storage);
    // The control object uses the testing allocator; the bounded heap child
    // is switched before any user allocation so resize is predictably in place.
    const owner = try Budget.create(std.testing.allocator, 32);
    defer owner.destroy();
    owner.bounded.child = child.allocator();
    const a = owner.allocator();
    var bytes = try a.alloc(u8, 8);
    defer a.free(bytes);
    var reservation = try owner.reserveExternal(16);
    defer reservation.deinit();
    try std.testing.expect(a.resize(bytes, 16));
    bytes.len = 16;
    try std.testing.expect(!a.resize(bytes, 17));
    try std.testing.expectEqual(@as(usize, 32), owner.snapshot().live_bytes);
    try reservation.resize(8);
    bytes = a.remap(bytes, 24).?;
    try std.testing.expectEqual(@as(usize, 32), owner.snapshot().live_bytes);
    try std.testing.expect(a.remap(bytes, 25) == null);
}

test "shared external: heap and external admissions serialize under contention" {
    const owner = try Budget.create(std.testing.allocator, 16);
    defer owner.destroy();
    const Group = struct {
        owner: *Budget,
        attempted: std.Thread.Semaphore = .{},
        release: std.Thread.ResetEvent = .{},
        successes: std.atomic.Value(usize) = .init(0),
        fn run(self: *@This(), host: bool) void {
            var bytes: ?[]u8 = null;
            var reservation = Budget.ExternalReservation.empty();
            if (host) {
                bytes = self.owner.allocator().alloc(u8, 8) catch null;
            } else {
                reservation = self.owner.reserveExternal(8) catch .empty();
            }
            if (bytes != null or reservation.bytes != 0) _ = self.successes.fetchAdd(1, .monotonic);
            self.attempted.post();
            self.release.wait();
            if (bytes) |held| self.owner.allocator().free(held);
            reservation.deinit();
        }
    };
    var group = Group{ .owner = owner };
    var threads: [8]std.Thread = undefined;
    var spawned: usize = 0;
    defer {
        group.release.set();
        for (threads[0..spawned]) |thread| thread.join();
    }
    for (&threads, 0..) |*thread, index| {
        thread.* = try std.Thread.spawn(.{}, Group.run, .{ &group, index % 2 == 0 });
        spawned += 1;
    }
    for (0..threads.len) |_| group.attempted.wait();
    try std.testing.expectEqual(@as(usize, 2), group.successes.load(.acquire));
    try std.testing.expectEqual(@as(usize, 16), owner.snapshot().live_bytes);
}

const Fake = struct {
    owner: *Budget,
    joins: usize = 0,
    cancels: usize = 0,
    destroys: usize = 0,
    charge_at_destroy: usize = 0,
    factory_calls: usize = 0,
    terminal: bool = false,
    fail_join: bool = false,
    fail_factory: bool = false,
    retained: usize = 8,
    const Resource = struct {
        state: *Fake,
        pub fn deinit(self: *@This()) void {
            std.debug.assert(self.state.terminal);
            self.state.charge_at_destroy = self.state.owner.snapshot().external_live_bytes;
            self.state.destroys += 1;
        }
    };
    fn factory(self: *Fake, _: usize) !external.Product(Resource) {
        self.factory_calls += 1;
        if (self.fail_factory) return error.FactoryFailure;
        self.terminal = false;
        return .{ .resource = .{ .state = self }, .retained_bytes = self.retained, .completion = .pending(self, join, cancel) };
    }
    fn join(context: ?*anyopaque) !void {
        const self: *Fake = @ptrCast(@alignCast(context.?));
        self.joins += 1;
        self.terminal = true;
        if (self.fail_join) return error.DeviceInvalidStatus;
    }
    fn cancel(context: ?*anyopaque) !void {
        const self: *Fake = @ptrCast(@alignCast(context.?));
        self.cancels += 1;
        self.terminal = true;
    }
};

test "shared external: factory rollback and invalid completion never admit a result" {
    const owner = try Budget.create(std.testing.allocator, 32);
    defer owner.destroy();
    var fake = Fake{ .owner = owner, .fail_factory = true };
    try std.testing.expectError(error.FactoryFailure, external.createPrivate(Fake.Resource, owner.allocator(), 32, .require_shared_budget, &fake, Fake.factory));
    try std.testing.expectEqual(@as(usize, 0), owner.snapshot().live_bytes);
    fake.fail_factory = false;
    fake.fail_join = true;
    var resource = try external.createPrivate(Fake.Resource, owner.allocator(), 32, .require_shared_budget, &fake, Fake.factory);
    try std.testing.expectError(error.ExternalResourceNotChecked, resource.checked());
    try std.testing.expectError(error.ExternalResourceNotChecked, resource.take());
    try std.testing.expectError(error.DeviceInvalidStatus, resource.complete());
    try std.testing.expectError(error.ExternalResourceNotChecked, resource.checked());
    resource.deinit();
    resource.deinit();
    try std.testing.expectEqual(@as(usize, 1), fake.joins);
    try std.testing.expectEqual(@as(usize, 0), fake.cancels);
    try std.testing.expectEqual(@as(usize, 1), fake.destroys);
    try std.testing.expectEqual(@as(usize, 32), fake.charge_at_destroy);
    try std.testing.expectEqual(@as(usize, 0), owner.snapshot().live_bytes);
}

test "shared external: factory retained extent cannot exceed preallocation admission" {
    const owner = try Budget.create(std.testing.allocator, 32);
    defer owner.destroy();
    var fake = Fake{ .owner = owner, .retained = 40 };
    try std.testing.expectError(error.ExternalExtentExceedsReservation, external.createPrivate(Fake.Resource, owner.allocator(), 32, .require_shared_budget, &fake, Fake.factory));
    try std.testing.expectEqual(@as(usize, 1), fake.cancels);
    try std.testing.expectEqual(@as(usize, 1), fake.destroys);
    try std.testing.expectEqual(@as(usize, 32), fake.charge_at_destroy);
    try std.testing.expectEqual(@as(usize, 0), owner.snapshot().live_bytes);
}

test "shared external: pending scratch envelope shrinks only after join and moves once" {
    const owner = try Budget.create(std.testing.allocator, 32);
    defer owner.destroy();
    var fake = Fake{ .owner = owner };
    var resource = try external.createPrivate(Fake.Resource, owner.allocator(), 32, .require_shared_budget, &fake, Fake.factory);
    try std.testing.expectEqual(@as(usize, 32), owner.snapshot().external_live_bytes);
    try resource.complete();
    try std.testing.expectEqual(@as(usize, 8), owner.snapshot().external_live_bytes);
    _ = try resource.checked();
    var moved = try resource.take();
    resource.deinit();
    try std.testing.expectError(error.ExternalResourceNotChecked, resource.take());
    moved.deinit();
    try std.testing.expectEqual(@as(usize, 1), fake.joins);
    try std.testing.expectEqual(@as(usize, 1), fake.destroys);
    try std.testing.expectEqual(@as(usize, 8), fake.charge_at_destroy);
    try std.testing.expectEqual(@as(usize, 0), owner.snapshot().external_live_bytes);
    var cancelled = try external.createPrivate(Fake.Resource, owner.allocator(), 32, .require_shared_budget, &fake, Fake.factory);
    cancelled.deinit();
    try std.testing.expectEqual(@as(usize, 1), fake.cancels);
    try std.testing.expectEqual(@as(usize, 2), fake.destroys);
}

test "shared external: unsupported allocator rejects before device factory" {
    const owner = try Budget.create(std.testing.allocator, 32);
    defer owner.destroy();
    var fake = Fake{ .owner = owner };
    try std.testing.expectError(error.SharedExternalBudgetRequired, external.createPrivate(Fake.Resource, std.testing.allocator, 8, .require_shared_budget, &fake, Fake.factory));
    try std.testing.expectEqual(@as(usize, 0), fake.factory_calls);
    var resource = try external.createPrivate(Fake.Resource, std.testing.allocator, 8, .explicit_unbudgeted, &fake, Fake.factory);
    resource.deinit();
}

test "shared external: failed or cancelled device owners survive original root release" {
    for ([_]bool{ false, true }) |invalid| {
        const owner = try Budget.create(std.testing.allocator, 32);
        var fake = Fake{ .owner = owner, .fail_join = invalid };
        var resource = try external.createPrivate(Fake.Resource, owner.allocator(), 32, .require_shared_budget, &fake, Fake.factory);
        owner.destroy();
        if (invalid) {
            try std.testing.expectError(error.DeviceInvalidStatus, resource.complete());
        } else {
            try resource.cancel();
        }
        resource.deinit();
        try std.testing.expectEqual(@as(usize, 1), fake.destroys);
        try std.testing.expectEqual(@as(usize, 32), fake.charge_at_destroy);
        try std.testing.expectEqual(@as(usize, 1), fake.joins + fake.cancels);
    }
}

test "shared external: no-copy host lease is charged once and outlives root owner" {
    const owner = try Budget.create(std.testing.allocator, 32);
    var fake = Fake{ .owner = owner, .retained = 0 };
    const Host = struct {
        allocator: std.mem.Allocator,
        bytes: []u8,
        references: usize = 1,
        fn retain(context: *anyopaque) !void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.references += 1;
        }
        fn release(context: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.references -= 1;
            if (self.references == 0) self.allocator.free(self.bytes);
        }
    };
    var host = Host{ .allocator = owner.allocator(), .bytes = try owner.allocator().alloc(u8, 32) };
    var alias = try external.createAlias(Fake.Resource, .{ .allocator = host.allocator, .bytes = host.bytes.len, .context = &host, .retain = Host.retain, .release = Host.release }, .require_shared_budget, &fake, Fake.factory);
    try std.testing.expectEqual(@as(usize, 32), owner.snapshot().host_live_bytes);
    try std.testing.expectEqual(@as(usize, 0), owner.snapshot().external_live_bytes);
    Host.release(&host);
    owner.destroy();
    alias.deinit();
    try std.testing.expectEqual(@as(usize, 0), host.references);
    try std.testing.expectEqual(@as(usize, 1), fake.cancels);
    try std.testing.expectEqual(@as(usize, 1), fake.destroys);
}
