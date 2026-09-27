//! Device-free contracts for actual sampled dispatch receipts and wave bounds.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const sampled = @import("backends/metal/runtime/sampled_dispatch_budget_v1.zig");
const Budget = engine.host_budget_allocator.SharedHostBudget;
const Scope = sampled.Scope;

fn receipt(scope: *const Scope, submitted: u64, joined: u64) sampled.Receipt {
    var result = scope.receipt;
    result.submitted = submitted;
    result.joined = joined;
    return result;
}

test "sampled budget: joined streaming waves share heap cap and retain persistent outputs" {
    const owner = try Budget.create(std.testing.allocator, 192);
    defer owner.destroy();
    const a = owner.allocator();
    const output = try a.alloc(u8, 32);
    defer a.free(output);
    var scope = try Scope.init(a, .require_shared_budget);
    defer scope.deinit();
    try scope.apply(32, .device); // Persistent output/basis buffer.
    for (0..128) |_| {
        try scope.apply(96, .device);
        try scope.apply(32, .native_payload); // Coexists with its device copy.
        try std.testing.expectEqual(@as(usize, 192), owner.snapshot().live_bytes);
        // Native task metadata is no longer borrowed after its device copy.
        try scope.apply(32, .release_native_payload);
        // The mock synchronous command is terminal before wave destruction.
        try scope.apply(96, .release_device);
        try std.testing.expectEqual(@as(usize, 32), owner.snapshot().external_live_bytes);
    }
    try scope.apply(32, .release_device);
    try scope.finish(true, receipt(&scope, 128, 128));
    try std.testing.expectEqual(@as(u64, 160), scope.receipt.external_peak_bytes);
    try std.testing.expectEqual(@as(u64, 257), scope.receipt.owned_allocations);
    try std.testing.expectEqual(@as(usize, 32), owner.snapshot().live_bytes);
}

test "sampled budget: partial factory failure preserves sticky OOM through joined cleanup" {
    const owner = try Budget.create(std.testing.allocator, 128);
    defer owner.destroy();
    var scope = try Scope.init(owner.allocator(), .explicit_unbudgeted);
    defer scope.deinit();
    try std.testing.expect(Scope.callback(&scope, 96, @intFromEnum(sampled.Operation.device)));
    try std.testing.expect(!Scope.callback(&scope, 33, @intFromEnum(sampled.Operation.native_payload)));
    // Failure did not publish the rejected constructor into the receipt.
    try std.testing.expectEqual(@as(u64, 0), scope.receipt.native_live_bytes);
    try std.testing.expectEqual(@as(u64, 1), scope.receipt.owned_allocations);
    try std.testing.expect(Scope.callback(&scope, 96, @intFromEnum(sampled.Operation.release_device)));
    try std.testing.expectEqual(@as(usize, 0), owner.snapshot().external_live_bytes);
    try std.testing.expectError(error.OutOfMemory, scope.finish(false, receipt(&scope, 0, 0)));
    try std.testing.expectError(error.InvalidSampledBudgetOperation, scope.finish(true, receipt(&scope, 1, 1)));
}

test "sampled budget: ordinary aliases are explicit and shared allocators always reject guessed custody" {
    try std.testing.expectError(error.SharedExternalBudgetRequired, Scope.init(std.testing.allocator, .require_shared_budget));
    var ordinary = try Scope.init(std.testing.allocator, .explicit_unbudgeted);
    defer ordinary.deinit();
    try ordinary.apply(4096, .borrowed_alias);
    try ordinary.apply(4096, .release_borrowed_alias);
    try ordinary.finish(true, receipt(&ordinary, 1, 1));
    try std.testing.expectEqual(@as(u64, 4096), ordinary.receipt.alias_peak_bytes);
    try std.testing.expectEqual(@as(u64, 0), ordinary.receipt.external_peak_bytes);
    const owner = try Budget.create(std.testing.allocator, 128);
    defer owner.destroy();
    var strict = try Scope.init(owner.allocator(), .explicit_unbudgeted);
    defer strict.deinit();
    try std.testing.expect(!strict.allowsUnownedAliases());
    try std.testing.expectError(error.UnauthenticatedSampledAlias, strict.apply(4096, .borrowed_alias));
    try std.testing.expectEqual(@as(usize, 0), owner.snapshot().external_live_bytes);
}

test "sampled budget: exact allocator and owner survive original owner release through heap cleanup" {
    const owner = try Budget.create(std.testing.allocator, 256);
    const a = owner.allocator();
    const output = try a.alloc(u8, 64);
    var scope = try Scope.init(a, .require_shared_budget);
    try scope.apply(128, .device);
    owner.destroy();
    try scope.validateAllocator(a);
    try std.testing.expectError(error.ExternalAdmissionAllocatorMismatch, scope.validateAllocator(std.testing.allocator));
    try scope.apply(128, .release_device);
    try scope.finish(true, receipt(&scope, 1, 1));
    a.free(output); // Zero-charge scope retains the allocator owner here.
    scope.deinit();
    scope.deinit();
}

test "sampled budget: cancellation and malformed command receipts cannot promote outputs" {
    var cancelled = try Scope.init(std.testing.allocator, .explicit_unbudgeted);
    defer cancelled.deinit();
    try cancelled.apply(64, .device);
    try cancelled.apply(64, .release_device);
    try std.testing.expectError(error.SampledDispatchFailed, cancelled.finish(false, receipt(&cancelled, 1, 1)));
    try std.testing.expectError(error.InvalidSampledBudgetOperation, cancelled.finish(true, receipt(&cancelled, 1, 1)));
    var unjoined = try Scope.init(std.testing.allocator, .explicit_unbudgeted);
    defer unjoined.deinit();
    try std.testing.expectError(error.InvalidSampledBudgetReceipt, unjoined.finish(true, receipt(&unjoined, 2, 1)));
    var changed = try Scope.init(std.testing.allocator, .explicit_unbudgeted);
    defer changed.deinit();
    var forged = receipt(&changed, 1, 1);
    forged.device_peak_bytes = 1;
    try std.testing.expectError(error.InvalidSampledBudgetReceipt, changed.finish(true, forged));
}

test "sampled budget: release extent and callback overflow fail closed" {
    var scope = try Scope.init(std.testing.allocator, .explicit_unbudgeted);
    defer scope.deinit();
    try scope.apply(std.math.maxInt(usize), .borrowed_alias);
    try std.testing.expect(!Scope.callback(&scope, 1, @intFromEnum(sampled.Operation.borrowed_alias)));
    try scope.apply(std.math.maxInt(usize), .release_borrowed_alias);
    try std.testing.expectError(error.Overflow, scope.finish(false, receipt(&scope, 0, 0)));
    var extent = try Scope.init(std.testing.allocator, .explicit_unbudgeted);
    defer extent.deinit();
    try extent.apply(16, .device);
    try std.testing.expectError(error.InvalidSampledBudgetRelease, extent.apply(17, .release_device));
    try std.testing.expectEqual(@as(u64, 16), extent.receipt.device_live_bytes);
    try extent.apply(16, .release_device);
    try std.testing.expectEqual(@as(usize, 88), @sizeOf(sampled.Receipt));
}

test "sampled budget: persistent constructor extents preserve constant and streamed branches" {
    var geometry = sampled.CoefficientGeometry{ .coefficient_words = 8, .factor_words = 4, .tasks = 2, .basis_tasks = 1, .basis_values = 8, .outputs = 2 };
    try std.testing.expectEqual(@as(usize, 264), try sampled.coefficientBaseBytes(geometry));
    geometry = .{ .coefficient_words = 1, .factor_words = 0, .tasks = 1, .basis_tasks = 1, .basis_values = 1, .outputs = 1 };
    try std.testing.expectEqual(@as(usize, 76), try sampled.coefficientBaseBytes(geometry));
    geometry = .{ .coefficient_words = 16 * 1024 * 1024, .factor_words = 4, .tasks = 2, .basis_tasks = 1, .basis_values = 8, .outputs = 2 };
    try std.testing.expectEqual(@as(usize, 236), try sampled.coefficientBaseBytes(geometry));
    geometry.coefficient_words -= 1;
    try std.testing.expectEqual(@as(usize, 64 * 1024 * 1024 + 228), try sampled.coefficientBaseBytes(geometry));
    geometry.outputs = std.math.maxInt(u32);
    try std.testing.expectError(error.InvalidSampledBudgetGeometry, sampled.coefficientBaseBytes(geometry));
}

test "sampled budget: byte thresholds join before copies including oversized single columns" {
    const mib = 1024 * 1024;
    const policy = sampled.stream_policy;
    try std.testing.expect(policy.acceptsNext(8 * mib, 8 * mib)); // 64 MiB in words.
    try std.testing.expect(!policy.acceptsNext(16 * mib, 1));
    try std.testing.expect(!policy.acceptsNext(32 * mib, 1)); // Oversized column stays alone.
    try std.testing.expect(!try policy.requiresJoin(192 * mib - 40, 3, 64 * mib, 20));
    try std.testing.expect(try policy.requiresJoin(192 * mib - 39, 3, 64 * mib, 20));
    try std.testing.expect(try policy.requiresJoin(1, 1, 256 * mib, 1));
    try std.testing.expect(!try policy.requiresJoin(0, 0, 512 * mib, 20));
    try std.testing.expect(try policy.requiresJoin(512 * mib, 1, 4, 20));
    try std.testing.expect(try policy.requiresJoin(0, 128, 4, 20));
    try std.testing.expectError(error.Overflow, policy.requiresJoin(0, 1, std.math.maxInt(usize), 1));
}

test "sampled budget: resident barycentric scratch accounts numeric payload and private buffers once" {
    // Sixteen domain values, two columns in one run, three points and six
    // output values. Borrowed PCS input buffers are not new private scratch.
    const owner = try Budget.create(std.testing.allocator, 962);
    defer owner.destroy();
    const a = owner.allocator();
    const prepared = try a.alloc(u8, 80);
    defer a.free(prepared);
    var scope = try Scope.init(a, .require_shared_budget);
    defer scope.deinit();
    const native_extents = [_]usize{ 16, 16, 8, 6 }; // Offsets/runs/group offsets/written roster.
    const device_extents = [_]usize{ 16, 8, 128, 256, 256, 32, 32, 12, 96 };
    for (native_extents) |bytes| try scope.apply(bytes, .native_payload);
    for (device_extents) |bytes| try scope.apply(bytes, .device);
    try std.testing.expectEqual(@as(usize, 962), owner.snapshot().live_bytes);
    try std.testing.expectEqual(@as(u64, 836), scope.receipt.device_live_bytes);
    try std.testing.expectEqual(@as(u64, 46), scope.receipt.native_live_bytes);
    // A terminal command/pole rejection destroys all scratch, but does not
    // admit a successful output even though all reservations were returned.
    for (device_extents) |bytes| try scope.apply(bytes, .release_device);
    for (native_extents) |bytes| try scope.apply(bytes, .release_native_payload);
    try std.testing.expectError(error.SampledDispatchFailed, scope.finish(false, receipt(&scope, 1, 1)));
    try std.testing.expectEqual(@as(usize, 80), owner.snapshot().live_bytes);
}
