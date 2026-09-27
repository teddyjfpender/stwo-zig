//! No device, backend dispatch, STARK or execution segment is invoked.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Budget = engine.host_budget_allocator.SharedHostBudget;
const Extent = @import("backends/metal/runtime/fri_budget_v1.zig");
const Arena = @import("backends/metal/runtime/fri_reservation_owner_v1.zig");
const Inverses = @import("backends/metal/runtime/fri_inverse_cache_budget_v1.zig");
const Key = Inverses.Key;
const Resource = struct {
    id: usize,
    destroyed: *usize,
    terminal: *bool,
    pub fn deinit(self: *Resource) void {
        std.debug.assert(self.terminal.*);
        self.destroyed.* += 1;
        self.* = undefined;
    }
};
const Factory = struct {
    created: *usize,
    destroyed: *usize,
    terminal: *bool,
    fail_at: usize = std.math.maxInt(usize),
    pub fn create(self: Factory, _: Key, _: usize) !Resource {
        self.created.* += 1;
        if (self.created.* == self.fail_at) return error.InverseFactoryFailed;
        return .{ .id = self.created.*, .destroyed = self.destroyed, .terminal = self.terminal };
    }
};
const Completion = struct {
    terminal: *bool,
    cancellations: usize = 0,
    joins: usize = 0,
    fail: bool = false,
    fn join(context: ?*anyopaque) anyerror!void {
        const self: *Completion = @ptrCast(@alignCast(context.?));
        self.joins += 1;
        self.terminal.* = true;
        if (self.fail) return error.InvalidDeviceStatus;
    }
    fn cancel(context: ?*anyopaque) anyerror!void {
        const self: *Completion = @ptrCast(@alignCast(context.?));
        self.cancellations += 1;
        self.terminal.* = true;
    }
    fn pending(self: *Completion) engine.shared_external_memory.Completion {
        return engine.shared_external_memory.Completion.pending(self, join, cancel);
    }
};
const Cache = Inverses.Cache(Resource);
fn circle(count: u32) Key {
    const log = std.math.log2_int(u32, count);
    return .{ .runtime = 1, .count = count, .layers = 1, .initial = @as(u32, 1) << @intCast(29 - log), .step = @as(u32, 1) << @intCast(31 - log), .kind = .circle };
}
fn line(count: u32, layers: u32) Key {
    var key = circle(count);
    key.layers = layers;
    key.kind = .line;
    return key;
}

test "FRI budget: cascade framing and folded ownership extents are exact" {
    try std.testing.expectEqual(@as(usize, 16), try Extent.secureValues(1));
    try std.testing.expectEqual(@as(usize, 6), try Extent.inverseCount(8, 2));
    const small = try Extent.cascade(2, 1);
    try std.testing.expectEqual(@as(usize, 320), small.retained_bytes);
    try std.testing.expectEqual(@as(usize, 384), small.peak_bytes);
    const nested = try Extent.cascade(8, 3);
    try std.testing.expectEqual(@as(usize, 1600), nested.retained_bytes);
    try std.testing.expectEqual(@as(usize, 1760), nested.peak_bytes);
    const folded = try Extent.foldedCommit(8, 2);
    try std.testing.expectEqual(@as(usize, 96), folded.retained_bytes);
    try std.testing.expectEqual(@as(usize, 280), folded.peak_bytes);
    try std.testing.expectError(error.InvalidFriBudgetGeometry, Extent.cascade(8, 4));
    try std.testing.expectError(error.InvalidFriBudgetGeometry, Extent.secureValues(3));
    try std.testing.expectError(error.InvalidFriBudgetGeometry, Extent.inverseCount(8, 0));
}

test "FRI budget: shared arena survives root and releases one charge at last tree" {
    const owner = try Budget.create(std.testing.allocator, 1024);
    const a = owner.allocator();
    var charge = try owner.reserveExternal(128);
    var first = try Arena.Owner.create(a, &charge);
    var second = try first.retain();
    var third = try second.retain();
    try std.testing.expectEqual(@as(usize, 128), owner.snapshot().external_live_bytes);
    owner.destroy();
    var moved = first.take();
    first.deinit();
    moved.deinit();
    second.deinit();
    try third.requireOwner(a, 128);
    try std.testing.expectEqual(@as(usize, 128), third.owner.?.reservation.owner.?.snapshot().external_live_bytes);
    third.deinit();
    third.deinit();
}

test "FRI budget: shared owner rejects foreign allocation before consumption" {
    const owner = try Budget.create(std.testing.allocator, 1024);
    defer owner.destroy();
    var charge = try owner.reserveExternal(128);
    defer charge.deinit();
    try std.testing.expectError(error.InvalidExternalReservationOwner, Arena.Owner.create(std.testing.allocator, &charge));
    try charge.requireOwner(owner.allocator(), 128);
}

test "FRI budget: inverse cache retains exact hits and drains typed owners" {
    const owner = try Budget.create(std.testing.allocator, 512);
    defer owner.destroy();
    var created: usize = 0;
    var destroyed: usize = 0;
    var terminal = true;
    const factory = Factory{ .created = &created, .destroyed = &destroyed, .terminal = &terminal };
    var cache: Cache = .{};
    var cold = try cache.begin(owner.allocator(), .{ circle(4), line(8, 2) }, factory);
    try std.testing.expect(cold.needsGeneration(.circle));
    try std.testing.expect(cold.needsGeneration(.line));
    const id = cold.resource(.line).?.id;
    try cold.complete();
    try std.testing.expectEqual(@as(usize, 40), owner.snapshot().external_live_bytes);
    var hit = try cache.begin(owner.allocator(), .{ circle(4), line(8, 2) }, factory);
    try std.testing.expect(!hit.needsGeneration(.line));
    try std.testing.expectEqual(id, hit.resource(.line).?.id);
    hit.abort();
    try std.testing.expectEqual(@as(usize, 2), created);
    try std.testing.expectEqual(@as(usize, 0), destroyed);
    try cache.drain(owner.allocator());
    try std.testing.expectEqual(@as(usize, 2), destroyed);
    try std.testing.expectEqual(@as(usize, 0), owner.snapshot().live_bytes);
}

test "FRI budget: replacement overlap and checked cancellation preserve old cache" {
    const owner = try Budget.create(std.testing.allocator, 512);
    defer owner.destroy();
    // Keep only 72 bytes available while preserving the production idle policy.
    const working = try owner.allocator().alloc(u8, 440);
    defer owner.allocator().free(working);
    var created: usize = 0;
    var destroyed: usize = 0;
    var terminal = true;
    const factory = Factory{ .created = &created, .destroyed = &destroyed, .terminal = &terminal };
    var cache: Cache = .{};
    var first = try cache.begin(owner.allocator(), .{ circle(4), line(8, 2) }, factory);
    const initial_id = first.resource(.circle).?.id;
    try first.complete();
    // Idle LRU entries may be evicted under pressure; these live readers must
    // survive failure/cancellation and preserve the original overlap test.
    var held = try cache.begin(owner.allocator(), .{ circle(4), line(8, 2) }, factory);
    defer held.abort();
    try std.testing.expectError(error.OutOfMemory, cache.begin(owner.allocator(), .{ circle(16), null }, factory));
    try std.testing.expectEqual(@as(usize, 2), created);
    var cancelled = try cache.begin(owner.allocator(), .{ circle(8), null }, factory);
    try std.testing.expectEqual(@as(usize, 72), owner.snapshot().external_live_bytes);
    terminal = false;
    var completion = Completion{ .terminal = &terminal };
    try cancelled.bindCompletion(completion.pending());
    cancelled.abort();
    try std.testing.expectEqual(@as(usize, 1), completion.cancellations);
    try std.testing.expectEqual(@as(usize, 0), completion.joins);
    try std.testing.expectEqual(@as(usize, 40), owner.snapshot().external_live_bytes);
    var retained = try cache.begin(owner.allocator(), .{ circle(4), null }, factory);
    try std.testing.expectEqual(initial_id, retained.resource(.circle).?.id);
    retained.abort();
    var replacement = try cache.begin(owner.allocator(), .{ circle(8), null }, factory);
    try replacement.complete();
    held.abort();
    try std.testing.expectEqual(@as(usize, 48), owner.snapshot().external_live_bytes);
    try std.testing.expectEqual(@as(usize, 512), owner.snapshot().peak_live_bytes);
    try cache.drain(owner.allocator());
    try std.testing.expectEqual(created, destroyed);
}

test "FRI budget: multi-buffer factory failure rolls back reservations and reader leases" {
    const owner = try Budget.create(std.testing.allocator, 512);
    defer owner.destroy();
    var created: usize = 0;
    var destroyed: usize = 0;
    var terminal = true;
    var cache: Cache = .{};
    try std.testing.expectError(error.InverseFactoryFailed, cache.begin(owner.allocator(), .{ circle(4), line(8, 2) }, Factory{ .created = &created, .destroyed = &destroyed, .terminal = &terminal, .fail_at = 2 }));
    try std.testing.expectEqual(@as(usize, 1), destroyed);
    try std.testing.expectEqual(@as(usize, 0), owner.snapshot().live_bytes);
    var next = try cache.begin(owner.allocator(), .{ circle(4), null }, Factory{ .created = &created, .destroyed = &destroyed, .terminal = &terminal });
    next.abort();
    try std.testing.expectEqual(@as(usize, 0), owner.snapshot().live_bytes);
}

test "FRI budget: foreign budget and runtime mismatch cannot borrow cached inverses" {
    const first = try Budget.create(std.testing.allocator, 512);
    defer first.destroy();
    const second = try Budget.create(std.testing.allocator, 512);
    defer second.destroy();
    var created: usize = 0;
    var destroyed: usize = 0;
    var terminal = true;
    const factory = Factory{ .created = &created, .destroyed = &destroyed, .terminal = &terminal };
    var cache: Cache = .{};
    var ready = try cache.begin(first.allocator(), .{ circle(4), null }, factory);
    try ready.complete();
    try std.testing.expectError(error.FriInverseCacheBudgetConflict, cache.begin(second.allocator(), .{ circle(4), null }, factory));
    try std.testing.expectError(error.SharedExternalBudgetRequired, cache.begin(std.testing.allocator, .{ circle(4), null }, factory));
    var foreign = circle(4);
    foreign.runtime = 2;
    try std.testing.expectError(error.InvalidFriInverseCacheRuntime, cache.begin(first.allocator(), .{ foreign, null }, factory));
    try std.testing.expectEqual(@as(usize, 1), created);
    try cache.drain(first.allocator());
}

test "FRI budget: pending cache abort survives original allocator owner release" {
    const owner = try Budget.create(std.testing.allocator, 512);
    var created: usize = 0;
    var destroyed: usize = 0;
    var terminal = true;
    var cache: Cache = .{};
    var pending = try cache.begin(owner.allocator(), .{ circle(4), line(8, 2) }, Factory{ .created = &created, .destroyed = &destroyed, .terminal = &terminal });
    owner.destroy();
    pending.abort();
    pending.abort();
    try std.testing.expectEqual(@as(usize, 2), destroyed);
}

test "FRI budget: failed checked completion cannot publish a generated inverse" {
    const owner = try Budget.create(std.testing.allocator, 512);
    defer owner.destroy();
    var created: usize = 0;
    var destroyed: usize = 0;
    var terminal = true;
    var cache: Cache = .{};
    var pending = try cache.begin(owner.allocator(), .{ circle(4), line(8, 2) }, Factory{ .created = &created, .destroyed = &destroyed, .terminal = &terminal });
    terminal = false;
    var completion = Completion{ .terminal = &terminal, .fail = true };
    try pending.bindCompletion(completion.pending());
    try std.testing.expectError(error.InvalidDeviceStatus, pending.complete());
    pending.abort();
    try std.testing.expectEqual(@as(usize, 1), completion.joins);
    try std.testing.expectEqual(@as(usize, 0), completion.cancellations);
    try std.testing.expectEqual(@as(usize, 2), destroyed);
    try std.testing.expect(cache.entries[0] == null and cache.entries[1] == null);
    try std.testing.expectEqual(@as(usize, 0), owner.snapshot().external_live_bytes);
}

test "FRI budget: domain admission rejects active poles and matches scalar coordinates" {
    const core = @import("stwo_core");
    const domain = @import("backends/metal/runtime/fri_domain_admission_v1.zig");
    for (1..8) |log| {
        const count = @as(u32, 1) << @intCast(log);
        const coset = core.circle.Coset.halfOdds(@intCast(log));
        for ([_]core.circle.Coset{ coset, coset.conjugate() }) |candidate| {
            try domain.requireDomain(@intCast(candidate.initial_index.v), @intCast(candidate.step_size.v), count, 1, true);
            try domain.requireDomain(@intCast(candidate.initial_index.v), @intCast(candidate.step_size.v), count, @intCast(log), false);
            var current = candidate;
            var values = count / 2;
            for (0..log) |_| {
                for (0..values) |i| try std.testing.expect(!current.at(i).x.isZero());
                current = current.double();
                values /= 2;
            }
            for (0..count) |i| try std.testing.expect(!candidate.at(i).y.isZero());
        }
    }
    var pole = circle(8);
    pole.initial = 0;
    try std.testing.expectError(error.FriInverseDomainPole, pole.bytes());
    pole = line(8, 2);
    pole.initial = 1 << 29;
    try std.testing.expectError(error.FriInverseDomainPole, pole.bytes());
    pole = line(8, 1);
    pole.step = 0;
    try std.testing.expectError(error.InvalidFriInverseDomain, pole.bytes());
    try std.testing.expectEqual(@as(usize, 4), try circle(1).bytes());
}

test "FRI budget: every requested inverse domain is admitted before factory work" {
    const owner = try Budget.create(std.testing.allocator, 80);
    defer owner.destroy();
    var created: usize = 0;
    var destroyed: usize = 0;
    var terminal = true;
    var cache: Cache = .{};
    var pole = line(8, 2);
    pole.initial = 1 << 29;
    try std.testing.expectError(error.FriInverseDomainPole, cache.begin(owner.allocator(), .{ circle(4), pole }, Factory{ .created = &created, .destroyed = &destroyed, .terminal = &terminal }));
    try std.testing.expectEqual(@as(usize, 0), created);
    try std.testing.expectEqual(@as(usize, 0), owner.snapshot().live_bytes);
}

fn arenaAllocationFailure(a: std.mem.Allocator) !void {
    const owner = try Budget.create(a, 1024);
    defer owner.destroy();
    var reservation = try owner.reserveExternal(128);
    defer reservation.deinit();
    var reference = try Arena.Owner.create(owner.allocator(), &reservation);
    defer reference.deinit();
    try std.testing.expectEqual(@as(usize, 128), owner.snapshot().external_live_bytes);
}
test "FRI budget: control allocation failures retain or release the correct charge" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, arenaAllocationFailure, .{});
}

test "FRI budget: resident storage uses owner context and preserves real device handle" {
    const Storage = @import("stwo_backend_contracts").resident_storage.ResidentStorage;
    const Context = struct {
        seen: *usize,
        expected: *anyopaque,
        fn legacy(_: *anyopaque) void {
            unreachable;
        }
        fn destroy(context: *anyopaque, handle: *anyopaque) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            std.debug.assert(self.expected == handle);
            self.seen.* += 1;
        }
    };
    var handle: usize = 0;
    var seen: usize = 0;
    var context = Context{ .seen = &seen, .expected = &handle };
    const storage = Storage{ .handle = &handle, .destroyFn = Context.legacy, .owner_context = &context, .destroyContextFn = Context.destroy };
    try std.testing.expect(storage.handle == @as(*anyopaque, @ptrCast(&handle)));
    storage.deinit();
    try std.testing.expectEqual(@as(usize, 1), seen);
}

test "FRI budget: contending cache transactions reuse the same admitted buffers" {
    const owner = try Budget.create(std.testing.allocator, 512);
    defer owner.destroy();
    var created: usize = 0;
    var destroyed: usize = 0;
    var terminal = true;
    const factory = Factory{ .created = &created, .destroyed = &destroyed, .terminal = &terminal };
    var cache: Cache = .{};
    var first = try cache.begin(owner.allocator(), .{ circle(4), line(8, 2) }, factory);
    try first.complete();
    const Worker = struct {
        fn work(target: *Cache, a: std.mem.Allocator, provider: Factory) void {
            for (0..256) |_| {
                var current = target.begin(a, .{ circle(4), line(8, 2) }, provider) catch unreachable;
                std.debug.assert(!current.needsGeneration(.circle) and !current.needsGeneration(.line));
                current.complete() catch unreachable;
            }
        }
    };
    var threads: [4]std.Thread = undefined;
    var started: usize = 0;
    errdefer {
        for (threads[0..started]) |thread| thread.join();
        cache.drain(owner.allocator()) catch unreachable;
    }
    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, Worker.work, .{ &cache, owner.allocator(), factory });
        started += 1;
    }
    for (threads) |thread| thread.join();
    started = 0;
    try std.testing.expectEqual(@as(usize, 2), created);
    try std.testing.expectEqual(@as(usize, 40), owner.snapshot().external_live_bytes);
    try cache.drain(owner.allocator());
    try std.testing.expectEqual(created, destroyed);
}

// Device-free stand-in for the local tree destructor; the tested enclosing
// FRIProver.deinit is the actual production implementation.
const TeardownTree = struct {
    ref: Arena.Ref,
    pub fn deinit(self: *TeardownTree, _: std.mem.Allocator) void {
        self.ref.deinit();
    }
    pub fn root() void {}
    pub fn decommit() void {}
    pub fn maxLogSize() void {}
    pub fn readHashes() void {}
};
const TeardownBackend = struct {
    pub fn MerkleTree(comptime _: type) type {
        return TeardownTree;
    }
    pub fn commitMerkle(comptime _: type, _: std.mem.Allocator, _: []const []const @import("stwo_core").fields.m31.M31) anyerror!TeardownTree {
        return error.DeviceDispatchForbiddenInFixture;
    }
};
test "FRI budget: actual prover teardown keeps heap arrays alive after root owner release" {
    const core = @import("stwo_core");
    const Hash = core.vcs_lifted.blake3_merkle.MerkleHasher;
    const Prover = engine.fri.FriProver(TeardownBackend, Hash, core.vcs_lifted.blake3_merkle.MerkleChannel);
    const config = try core.fri.FriConfig.init(0, 1, 4);
    const inner_domain = try core.poly.line.LineDomain.init(core.circle.Coset.halfOdds(0));
    const owner = try Budget.create(std.testing.allocator, 4096);
    var owns_root = true;
    defer if (owns_root) owner.destroy();
    const a = owner.allocator();
    var reservation = try owner.reserveExternal(128);
    defer reservation.deinit();
    var arena = try Arena.Owner.create(a, &reservation);
    defer arena.deinit();
    var first_column = try engine.secure_column.SecureColumnByCoords.zeros(a, 2);
    var first_moved = false;
    defer if (!first_moved) first_column.deinit(a);
    const layers = try a.alloc(Prover.InnerLayerProver, 1);
    var layers_moved = false;
    defer if (!layers_moved) a.free(layers);
    var inner_column = try engine.secure_column.SecureColumnByCoords.zeros(a, 1);
    var inner_moved = false;
    defer if (!inner_moved) inner_column.deinit(a);
    const coefficients = try a.alloc(core.fields.qm31.QM31, 1);
    var coefficients_moved = false;
    defer if (!coefficients_moved) a.free(coefficients);
    coefficients[0] = core.fields.qm31.QM31.zero();
    var inner_ref = try arena.retain();
    defer inner_ref.deinit();
    layers[0] = .{ .domain = inner_domain, .column = inner_column, .merkle_tree = .{ .ref = inner_ref.take() } };
    inner_moved = true;
    var prover = Prover{ .config = config, .first_layer = .{ .domain = core.poly.circle.canonic.CanonicCoset.new(1).circleDomain(), .column = first_column, .merkle_tree = .{ .ref = arena.take() } }, .inner_layers = layers, .last_layer_poly = core.poly.line.LinePoly.initOwned(coefficients) };
    first_moved = true;
    layers_moved = true;
    coefficients_moved = true;
    owner.destroy();
    owns_root = false;
    prover.deinit(a);
}

test "FRI budget: concurrent arena references keep a single external charge" {
    const owner = try Budget.create(std.testing.allocator, 1024);
    defer owner.destroy();
    var reservation = try owner.reserveExternal(128);
    defer reservation.deinit();
    var reference = try Arena.Owner.create(owner.allocator(), &reservation);
    defer reference.deinit();
    const Worker = struct {
        fn work(value: *const Arena.Ref) void {
            for (0..1024) |_| {
                var retained = value.retain() catch unreachable;
                retained.deinit();
            }
        }
    };
    var threads: [4]std.Thread = undefined;
    var started: usize = 0;
    errdefer for (threads[0..started]) |thread| thread.join();
    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, Worker.work, .{&reference});
        started += 1;
    }
    for (threads) |thread| thread.join();
    started = 0;
    try std.testing.expectEqual(@as(usize, 1), reference.owner.?.references.load(.acquire));
    try std.testing.expectEqual(@as(usize, 128), owner.snapshot().external_live_bytes);
}

test "FRI budget: explicit ordinary policy preserves original allocator and source ownership" {
    const policy = @import("backends/metal/runtime/fri_allocation_policy_v1.zig");
    const a = std.testing.allocator;
    const source = try a.alloc(u8, 31);
    defer a.free(source);
    @memset(source, 7);
    try std.testing.expectEqual(policy.Policy.explicit_unbudgeted, policy.ordinaryMetal(a));
    try std.testing.expectError(error.SharedExternalBudgetRequired, policy.Binding.init(a, .require_shared_budget));
    const binding = try policy.Binding.init(a, .explicit_unbudgeted);
    var reservation = try binding.reserve(128);
    defer reservation.deinit();
    try std.testing.expect(reservation.active and reservation.owner == null);
    var arena = try Arena.Owner.createWithPolicy(a, &reservation, .explicit_unbudgeted);
    var moved = arena.take();
    arena.deinit();
    try moved.requireOwner(a, 128);
    moved.deinit();
    try std.testing.expectEqual(@as(u8, 7), source[30]);
    const output = try a.alloc(u8, 19);
    defer a.free(output);
    @memset(output, 9);
}

test "FRI budget: explicit ordinary option cannot bypass a supplied shared cap" {
    const policy = @import("backends/metal/runtime/fri_allocation_policy_v1.zig");
    const owner = try Budget.create(std.testing.allocator, 16);
    defer owner.destroy();
    const binding = try policy.Binding.init(owner.allocator(), .explicit_unbudgeted);
    try std.testing.expectEqual(policy.Policy.require_shared_budget, binding.policy);
    var reservation = try binding.reserve(16);
    defer reservation.deinit();
    try std.testing.expectEqual(owner, reservation.owner.?);
    try std.testing.expectError(error.OutOfMemory, binding.reserve(1));
    try binding.require(owner.allocator(), &reservation, 16);
    try std.testing.expectEqual(@as(usize, 16), owner.snapshot().external_live_bytes);
}

test "FRI budget: uncapped owner binds extent and source allocator independently" {
    const policy = @import("backends/metal/runtime/fri_allocation_policy_v1.zig");
    var first_bytes: [64]u8 = undefined;
    var second_bytes: [64]u8 = undefined;
    var first = std.heap.FixedBufferAllocator.init(&first_bytes);
    var second = std.heap.FixedBufferAllocator.init(&second_bytes);
    const origin = try policy.Binding.init(first.allocator(), .explicit_unbudgeted);
    const borrower = try policy.Binding.init(second.allocator(), .explicit_unbudgeted);
    var token = try origin.reserve(32);
    defer token.deinit();
    try origin.require(first.allocator(), &token, 32);
    try std.testing.expectError(error.InvalidFriAllocatorBinding, origin.require(second.allocator(), &token, 32));
    try std.testing.expectError(error.InvalidFriAllocatorBinding, origin.require(first.allocator(), &token, 31));
    try origin.requireBorrowed(borrower, &token, 32);
    const budget = try Budget.create(std.testing.allocator, 64);
    defer budget.destroy();
    const strict = try policy.Binding.init(budget.allocator(), .require_shared_budget);
    try std.testing.expectError(error.InvalidFriAllocatorBinding, origin.requireBorrowed(strict, &token, 32));
    var charged = try strict.reserve(32);
    defer charged.deinit();
    try std.testing.expectError(error.InvalidFriAllocatorBinding, strict.requireBorrowed(borrower, &charged, 32));
}

test "FRI budget: ordinary inverse buffers are ephemeral after checked completion" {
    const Transient = @import("backends/metal/runtime/fri_inverse_transient_v1.zig").Transient(Resource);
    var created: usize = 0;
    var destroyed: usize = 0;
    var terminal = true;
    const factory = Factory{ .created = &created, .destroyed = &destroyed, .terminal = &terminal };
    var owned = try Transient.init(std.testing.allocator, .{ circle(4), line(8, 2) }, factory);
    try std.testing.expect(owned.needsGeneration(.circle) and owned.needsGeneration(.line));
    terminal = false;
    var completion = Completion{ .terminal = &terminal };
    try owned.bindCompletion(completion.pending());
    try owned.complete();
    owned.abort();
    try std.testing.expectEqual(@as(usize, 1), completion.joins);
    try std.testing.expectEqual(@as(usize, 2), destroyed);
    try std.testing.expect(owned.resource(.circle) == null);
    var next = try Transient.init(std.testing.allocator, .{ circle(4), line(8, 2) }, factory);
    defer next.abort();
    try std.testing.expect(next.needsGeneration(.circle));
    try std.testing.expectEqual(@as(usize, 4), created);
}

test "FRI budget: ephemeral inverse failure and cancellation release only after terminal work" {
    const Transient = @import("backends/metal/runtime/fri_inverse_transient_v1.zig").Transient(Resource);
    var created: usize = 0;
    var destroyed: usize = 0;
    var terminal = true;
    try std.testing.expectError(error.InverseFactoryFailed, Transient.init(std.testing.allocator, .{ circle(4), line(8, 2) }, Factory{ .created = &created, .destroyed = &destroyed, .terminal = &terminal, .fail_at = 2 }));
    try std.testing.expectEqual(@as(usize, 1), destroyed);
    var source = try Transient.init(std.testing.allocator, .{ circle(4), line(8, 2) }, Factory{ .created = &created, .destroyed = &destroyed, .terminal = &terminal });
    var moved = source.take();
    source.abort();
    terminal = false;
    var completion = Completion{ .terminal = &terminal };
    try moved.bindCompletion(completion.pending());
    moved.abort();
    moved.abort();
    try std.testing.expectEqual(@as(usize, 1), completion.cancellations);
    try std.testing.expectEqual(@as(usize, 3), destroyed);
}

test "FRI budget: ephemeral inverse route rejects shared budgets and active poles before factory" {
    const Transient = @import("backends/metal/runtime/fri_inverse_transient_v1.zig").Transient(Resource);
    const owner = try Budget.create(std.testing.allocator, 64);
    defer owner.destroy();
    var created: usize = 0;
    var destroyed: usize = 0;
    var terminal = true;
    const factory = Factory{ .created = &created, .destroyed = &destroyed, .terminal = &terminal };
    try std.testing.expectError(error.InvalidFriUnbudgetedPolicy, Transient.init(owner.allocator(), .{ circle(4), null }, factory));
    var pole = line(8, 2);
    pole.initial = 1 << 29;
    try std.testing.expectError(error.FriInverseDomainPole, Transient.init(std.testing.allocator, .{ circle(4), pole }, factory));
    try std.testing.expectEqual(@as(usize, 0), created);
    try std.testing.expectEqual(@as(usize, 0), owner.snapshot().live_bytes);
}

test "FRI budget: host compatibility ingress requires ordinary exact coordinate shape" {
    const policy = @import("backends/metal/runtime/fri_allocation_policy_v1.zig");
    try std.testing.expectEqual(@as(usize, 8), try policy.ordinaryHostIngress(std.testing.allocator, false, .{ 8, 8, 8, 8 }));
    try std.testing.expectError(error.InvalidFriResidentOwner, policy.ordinaryHostIngress(std.testing.allocator, false, .{ 8, 8, 7, 8 }));
    try std.testing.expectError(error.InvalidFriBudgetGeometry, policy.ordinaryHostIngress(std.testing.allocator, false, .{ 3, 3, 3, 3 }));
    try std.testing.expectError(error.InvalidFriUnbudgetedPolicy, policy.ordinaryHostIngress(std.testing.allocator, true, .{ 8, 8, 8, 8 }));
    const owner = try Budget.create(std.testing.allocator, 64);
    defer owner.destroy();
    try std.testing.expectError(error.InvalidFriUnbudgetedPolicy, policy.ordinaryHostIngress(owner.allocator(), false, .{ 8, 8, 8, 8 }));
    try std.testing.expectEqual(@as(usize, 0), owner.snapshot().live_bytes);
}
