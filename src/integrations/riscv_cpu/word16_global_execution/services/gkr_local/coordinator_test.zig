const std = @import("std");
const F = @import("coordinator_fixture.zig");
const Original = @import("../fixture.zig");
const C = @import("coordinator.zig");
const E = @import("execution.zig");
const W = @import("worker_protocol.zig");
const a = std.testing.allocator;
test "complete two-CPU K ADD DOUBLE OM-GKR services execution proves and fresh receiver independently closes all globals" {
    var fixture = try F.Case.init(a);
    defer fixture.deinit();
    const first = try fixture.verify(a);
    try std.testing.expect(first.completed);
    try std.testing.expectEqual(@as(u64, 7), first.total_steps);
    try std.testing.expectEqual(@as(usize, 5), first.physical_proofs);
    var fresh = try F.Keys.init(a);
    defer fresh.deinit();
    const expected = Original.expectedFor(fresh.cpus[0].materials.program.identity);
    const accepted = try fixture.bundle.verify(a, &fresh.pointers(), &fresh.truths(), expected, try F.config());
    try std.testing.expectEqualDeep(first, accepted);
    var wrong = expected;
    wrong.final_pc += 4;
    if (fixture.bundle.verify(a, &fresh.pointers(), &fresh.truths(), wrong, try F.config())) |_| return error.AcceptedWrongExpectedEndpoint else |_| {}
    const before = fixture.bundle.truths[0].claims[3];
    fixture.bundle.truths[0].claims[3] = before.add(W.O.one());
    if (fixture.verify(a)) |_| return error.AcceptedMutatedPureGlobalDebt else |_| {}
    fixture.bundle.truths[0].claims[3] = before;
    std.mem.swap(@TypeOf(fixture.bundle.cpus[0]), &fixture.bundle.cpus[0], &fixture.bundle.cpus[1]);
    if (fixture.verify(a)) |_| return error.AcceptedSwappedCpuProofs else |_| {}
    std.mem.swap(@TypeOf(fixture.bundle.cpus[0]), &fixture.bundle.cpus[0], &fixture.bundle.cpus[1]);
    const byte = fixture.bundle.stage_one_bytes[0];
    fixture.bundle.stage_one_bytes[0] ^= 1;
    if (fixture.verify(a)) |_| return error.AcceptedMalformedManifest else |_| {}
    fixture.bundle.stage_one_bytes[0] = byte;
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const path = try temp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var store = try C.Store.initParked(path, 128 << 20);
    defer store.deinit();
    var parked = try F.Case.initWithOptions(a, .{ .gkr_budget = 2 << 30, .retained_store = &store, .max_workers = 32, .schedule = .{ .lanes = 1, .workers_per_lane = 2, .memory_cap_bytes = 4 << 30 } });
    defer parked.deinit();
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_bytes);
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_mapped_bytes);
    try std.testing.expect(store.stats().total_bytes > 0);
    try std.testing.expectEqualSlices(u8, fixture.bundle.stage_one_bytes, parked.bundle.stage_one_bytes);
    for (fixture.bundle.cpus, parked.bundle.cpus) |x, y| {
        try std.testing.expectEqualSlices(u8, x.bytes, y.bytes);
        try std.testing.expectEqualDeep(x.claims, y.claims);
    }
    for (fixture.bundle.truths, parked.bundle.truths) |x, y| {
        try std.testing.expectEqualSlices(u8, x.bytes, y.bytes);
        try std.testing.expectEqualDeep(x.claims, y.claims);
    }
    const parked_fresh = try parked.bundle.verify(a, &fresh.pointers(), &fresh.truths(), expected, try F.config());
    try std.testing.expectEqualDeep(first, parked_fresh);
    const missing = fixture.bundle.truths[0..2];
    try std.testing.expectError(error.InvalidWideServicesProofInventory, E.verify(a, &fresh.pointers(), &fresh.truths(), fixture.bundle.requests, expected, try F.config(), fixture.bundle.stage_one_bytes, fixture.bundle.cpus, missing));
}
test "bounded coordinator refuses large inventory before consuming native traces" {
    var captured = try Original.Captured.init(a);
    defer captured.deinit();
    var keys = try F.Keys.init(a);
    defer keys.deinit();
    const expected = Original.expectedFor(captured.program.identity);
    try std.testing.expectError(error.BoundedWideCoordinatorLimit, C.produce(a, &keys.pointers(), &keys.truths(), &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expected, try F.config(), .{ .max_workers = 4 }));
    try std.testing.expect(captured.native[0].cpu != null);
    try std.testing.expectError(error.BoundedWideCoordinatorRetainedLimit, C.produce(a, &keys.pointers(), &keys.truths(), &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expected, try F.config(), .{ .max_retained_frontend_bytes = 1, .gkr_budget = 2 << 30 }));
    try std.testing.expect(captured.native[0].cpu != null);
}

test "parking admission is explicit and later worker failure releases every earlier parked owner" {
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const path = try temp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var mapped = try C.Store.init(path, 128 << 20);
    defer mapped.deinit();
    try std.testing.expectError(error.BoundedWideCoordinatorLimit, (C.Options{ .max_workers = 32 }).validate(25));
    try std.testing.expectError(error.WideCoordinatorRequiresParkingAdmission, (C.Options{ .max_workers = 32, .retained_store = &mapped, .schedule = .{ .memory_cap_bytes = 4 << 30 } }).validate(25));
    var store = try C.Store.initParked(path, 128 << 20);
    defer store.deinit();
    try std.testing.expectError(error.WideCoordinatorRequiresParkingAdmission, (C.Options{ .max_workers = 32, .retained_store = &store }).validate(25));
    const options = C.Options{ .gkr_budget = 2 << 30, .max_workers = 32, .retained_store = &store, .schedule = .{ .lanes = 1, .workers_per_lane = 2, .memory_cap_bytes = 4 << 30 } };
    try options.validate(25);
    var captured = try Original.Captured.init(a);
    defer captured.deinit();
    var keys = try F.Keys.init(a);
    defer keys.deinit();
    captured.advice.secp[1][0][0].pointer += 8;
    try std.testing.expectError(error.InvalidWord16SecpCall, C.produce(a, &keys.pointers(), &keys.truths(), &.{ &captured.native[0], &captured.native[1] }, &captured.advice, Original.expectedFor(captured.program.identity), try F.config(), options));
    try std.testing.expect(store.stats().total_bytes > 0);
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_bytes);
    try std.testing.expectEqual(@as(usize, 0), store.stats().live_mapped_bytes);
}
