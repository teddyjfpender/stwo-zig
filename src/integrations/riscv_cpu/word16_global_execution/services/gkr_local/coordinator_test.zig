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
    var store = try C.Store.initFullyParked(path, 128 << 20);
    defer store.deinit();
    var timings: [5]C.WorkerTiming = undefined;
    var parked = try F.Case.initWithOptions(a, .{ .gkr_budget = 2 << 30, .retained_store = &store, .max_workers = 32, .schedule = .{ .lanes = 2, .workers_per_lane = 2, .memory_cap_bytes = 4 << 30 }, .worker_timings = &timings });
    defer parked.deinit();
    for (timings, 0..) |t, i| {
        try std.testing.expect(t.stage1_completed and t.stage2_completed);
        try std.testing.expect(t.stage1_ns >= t.source_ns + t.seal_native_and_gkr_ns + t.metadata_retire_ns + t.spill_ns);
        try std.testing.expect(t.stage2_ns >= t.restore_ns + t.native_complete_ns);
        try std.testing.expect(t.actual_main_merkle_bytes > 0);
        if (i < 2) {
            try std.testing.expect(t.gkr_ns > 0);
            try std.testing.expect(t.seal_native_and_gkr_ns >= t.main_commit_ns + t.gkr_ns);
        } else try std.testing.expectEqual(@as(u64, 0), t.gkr_ns);
    }
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

test "phase task admission retires only numerical GKR scratch and preserves PCS global and retained payloads" {
    const R = @import("retention_plan.zig");
    const plan = R.RetentionPlan{ .coefficient_bytes = 2 << 30, .gkr_peak_bytes = 24 << 30, .stage1_task_bytes = 27 << 30, .stage2_task_bytes = 7 << 30, .parked_retained_bytes = 1 << 30 };
    const tasks = try R.taskEstimates(plan, 8 << 30);
    try std.testing.expectEqual(@as(u64, 28 << 30), tasks.stage1);
    try std.testing.expectEqual(@as(u64, 12 << 30), tasks.stage2);
    try std.testing.expect(tasks.stage2 >= plan.stage2_task_bytes);
    try std.testing.expectEqual(@as(usize, 1 << 30), plan.parked_retained_bytes);
    try std.testing.expectError(error.MissingWideGlobalBudget, R.taskEstimates(plan, 0));
    try std.testing.expectError(error.Overflow, R.taskEstimates(.{ .coefficient_bytes = std.math.maxInt(usize) }, 1));
    const wide_inter = try R.taskEstimates(.{ .coefficient_bytes = 2 << 30, .binding_bytes = 1 << 30, .global_output_bytes = 5 << 30, .global_scratch_bytes = 4096 }, 8 << 30);
    try std.testing.expectEqual(@as(u64, (16 << 30) + 4096), wide_inter.stage2);
    const needs_more = try R.taskEstimates(.{ .coefficient_bytes = 1, .stage2_task_bytes = 100 }, 1);
    try std.testing.expectEqual(@as(u64, 100), needs_more.stage2);
}
