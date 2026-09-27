const std = @import("std");
const engine = @import("stwo_prover_engine");
const Scope = @import("backends/metal/runtime/external_allocation_admission_v1.zig").Scope;
const Budget = engine.host_budget_allocator.SharedHostBudget;

const Factory = struct {
    allocations: usize = 0,
    destroyed: usize = 0,
    fn create(self: *Factory, scope: *Scope, bytes: usize) !void {
        if (!Scope.callback(scope, bytes)) return scope.failure orelse error.AdmissionRejected;
        self.allocations += 1;
    }
    fn joinedDestroy(self: *Factory, scope: *Scope, bytes: usize) !void {
        self.destroyed += 1;
        try scope.releaseJoined(bytes);
    }
};

test "external scratch: strict admission precedes factory and failure remains sticky" {
    const owner = try Budget.create(std.testing.allocator, 256);
    defer owner.destroy();
    var scope = try Scope.init(owner.allocator(), .explicit_unbudgeted);
    defer scope.deinit();
    var factory = Factory{};
    try factory.create(&scope, 160);
    try std.testing.expectError(error.OutOfMemory, factory.create(&scope, 97));
    try std.testing.expectEqual(@as(usize, 1), factory.allocations);
    try std.testing.expectEqual(@as(usize, 160), owner.snapshot().external_live_bytes);
    try factory.joinedDestroy(&scope, 160);
    try std.testing.expectError(error.OutOfMemory, factory.create(&scope, 1));
    try std.testing.expectEqual(@as(usize, 1), factory.allocations);
}

test "external scratch: buffered groups share combined heap and private copy cap" {
    const owner = try Budget.create(std.testing.allocator, 384);
    defer owner.destroy();
    const a = owner.allocator();
    const heap = try a.alloc(u8, 64);
    defer a.free(heap);
    var scope = try Scope.init(a, .require_shared_budget);
    defer scope.deinit();
    var factory = Factory{};
    try factory.create(&scope, 128);
    try factory.create(&scope, 192);
    try std.testing.expectEqual(@as(usize, 320), owner.snapshot().external_live_bytes);
    try std.testing.expectError(error.OutOfMemory, factory.create(&scope, 1));
    try std.testing.expectEqual(@as(usize, 2), factory.allocations);
    try factory.joinedDestroy(&scope, 128);
    try std.testing.expectEqual(@as(usize, 192), owner.snapshot().external_live_bytes);
    try factory.joinedDestroy(&scope, 192);
    try std.testing.expectEqual(@as(usize, 0), owner.snapshot().external_live_bytes);
}

test "external scratch: bounded joined waves retain persistent scratch without cumulative growth" {
    const owner = try Budget.create(std.testing.allocator, 160);
    defer owner.destroy();
    var scope = try Scope.init(owner.allocator(), .require_shared_budget);
    defer scope.deinit();
    var factory = Factory{};
    try factory.create(&scope, 64);
    for (0..128) |_| {
        try factory.create(&scope, 96);
        try std.testing.expectEqual(@as(usize, 160), owner.snapshot().external_live_bytes);
        try factory.joinedDestroy(&scope, 96);
        try std.testing.expectEqual(@as(usize, 64), owner.snapshot().external_live_bytes);
    }
    try std.testing.expectError(error.ExternalAdmissionReleaseExtent, scope.releaseJoined(65));
    try std.testing.expectEqual(@as(usize, 64), owner.snapshot().external_live_bytes);
    try factory.joinedDestroy(&scope, 64);
    try std.testing.expectEqual(@as(usize, 129), factory.destroyed);
}

test "external scratch: zero-charge joined scope retains original heap allocator lifetime" {
    const owner = try Budget.create(std.testing.allocator, 512);
    const a = owner.allocator();
    const heap = try a.alloc(u8, 64);
    var scope = try Scope.init(a, .require_shared_budget);
    try scope.admit(128);
    owner.destroy();
    try scope.releaseAfterJoin();
    try scope.validateAllocator(a);
    a.free(heap);
    scope.deinit();
    scope.deinit();
    try std.testing.expectError(error.ExternalAdmissionClosed, scope.admit(1));
}

test "external scratch: foreign owner and ordinary allocator cannot rebind live scope" {
    const one = try Budget.create(std.testing.allocator, 512);
    defer one.destroy();
    const two = try Budget.create(std.testing.allocator, 512);
    defer two.destroy();
    var scope = try Scope.init(one.allocator(), .explicit_unbudgeted);
    defer scope.deinit();
    try scope.validateAllocator(one.allocator());
    try std.testing.expectError(error.ExternalAdmissionAllocatorMismatch, scope.validateAllocator(two.allocator()));
    try std.testing.expectError(error.ExternalAdmissionAllocatorMismatch, scope.validateAllocator(std.testing.allocator));
    try std.testing.expectEqual(@as(usize, 0), one.snapshot().external_live_bytes);
    try std.testing.expectEqual(@as(usize, 0), two.snapshot().external_live_bytes);
}

test "external scratch: explicit uncapped compatibility checks overflow and strict policy" {
    try std.testing.expectError(error.SharedExternalBudgetRequired, Scope.init(std.testing.allocator, .require_shared_budget));
    var scope = try Scope.init(std.testing.allocator, .explicit_unbudgeted);
    defer scope.deinit();
    try scope.admit(std.math.maxInt(usize));
    try std.testing.expectError(error.Overflow, scope.admit(1));
    try scope.releaseAfterJoin();
    try std.testing.expectError(error.Overflow, scope.admit(1));
}

test "external scratch: allocator-less ordinary compatibility never admits a shared-budget bypass" {
    var ordinary = try Scope.init(std.heap.c_allocator, .explicit_unbudgeted);
    defer ordinary.deinit();
    try ordinary.validateOrdinaryCompatibility(std.testing.allocator);
    const one = try Budget.create(std.testing.allocator, 256);
    defer one.destroy();
    const two = try Budget.create(std.testing.allocator, 256);
    defer two.destroy();
    try std.testing.expectError(error.ExternalAdmissionAllocatorMismatch, ordinary.validateOrdinaryCompatibility(one.allocator()));
    var strict = try Scope.init(one.allocator(), .explicit_unbudgeted);
    defer strict.deinit();
    try strict.validateOrdinaryCompatibility(one.allocator());
    try std.testing.expectError(error.ExternalAdmissionAllocatorMismatch, strict.validateOrdinaryCompatibility(two.allocator()));
    try std.testing.expectError(error.ExternalAdmissionAllocatorMismatch, strict.validateOrdinaryCompatibility(std.testing.allocator));
}
