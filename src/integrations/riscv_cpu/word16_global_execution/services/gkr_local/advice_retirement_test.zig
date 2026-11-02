const std = @import("std");
const F = @import("coordinator_fixture.zig");
const Original = @import("../fixture.zig");
const C = @import("coordinator.zig");
const Owned = @import("../../ethereum/capture_ownership.zig");
const a = std.testing.allocator;
test "ordinary memory advice retires after seal with exact five proofs and fresh global closure" {
    const options = C.Options{ .gkr_budget = 2 << 30, .schedule = .{ .lanes = 2, .workers_per_lane = 2, .memory_cap_bytes = 4 << 30 } };
    var baseline = try F.Case.initWithOptions(a, options);
    defer baseline.deinit();
    var captured = try Original.Captured.init(a);
    defer captured.deinit();
    const before = Owned.advice(&captured.advice);
    const native_before = Owned.native(&captured.native[0]);
    try std.testing.expect(before.ordinary_events > 0 and native_before.cpu_metadata > 0 and native_before.family_facts > 0);
    var keys = try F.Keys.init(a);
    defer keys.deinit();
    const expected = Original.expectedFor(captured.program.identity);
    var admit_options = options;
    admit_options.consume_memory_events = true;
    admit_options.max_retained_frontend_bytes = 1;
    try std.testing.expectError(error.BoundedWideCoordinatorRetainedLimit, C.produce(a, &keys.pointers(), &keys.truths(), &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expected, try F.config(), admit_options));
    try std.testing.expectEqual(before.ordinary_events, Owned.advice(&captured.advice).ordinary_events);
    try std.testing.expect(captured.native[0].cpu != null);
    var consuming = options;
    consuming.consume_memory_events = true;
    var timings: [5]C.WorkerTiming = @splat(.{});
    consuming.worker_timings = &timings;
    var bundle = try C.produce(a, &keys.pointers(), &keys.truths(), &.{ &captured.native[0], &captured.native[1] }, &captured.advice, expected, try F.config(), consuming);
    defer bundle.deinit(a);
    const after = Owned.advice(&captured.advice);
    try std.testing.expectEqual(@as(usize, 0), after.ordinary_events);
    try std.testing.expectEqual(before.service_calls, after.service_calls);
    try std.testing.expectEqual(before.public_cells, after.public_cells);
    try std.testing.expectEqual(@as(usize, 0), Owned.native(&captured.native[0]).total());
    try std.testing.expectEqual(@as(usize, 0), Owned.native(&captured.native[1]).total());
    try std.testing.expectEqual(before.ordinary_events, timings[0].retired_memory_event_bytes + timings[1].retired_memory_event_bytes);
    for (timings) |timing| try std.testing.expect(timing.completed_worker_retired);
    for (bundle.cpus, baseline.bundle.cpus) |proof, original| try std.testing.expectEqualSlices(u8, original.bytes, proof.bytes);
    for (bundle.truths, baseline.bundle.truths) |proof, original| try std.testing.expectEqualSlices(u8, original.bytes, proof.bytes);
    try std.testing.expectEqualSlices(u8, baseline.bundle.stage_one_bytes, bundle.stage_one_bytes);
    var fresh = try F.Keys.init(a);
    defer fresh.deinit();
    const verified = try bundle.verify(a, &fresh.pointers(), &fresh.truths(), expected, try F.config());
    try std.testing.expect(verified.completed and verified.physical_proofs == 5);
    // Repeated explicit retirement is harmless; outer deinit owns empty slots.
    try std.testing.expectEqual(@as(usize, 0), try captured.advice.retireEvents(0));
    const Event = @import("stwo_riscv_frontend").rv64_air.memory.load_store_v2.native.Event;
    std.debug.print("CAPTURE_OWNERSHIP event_size={d} cpu_metadata_size={d} retired_events={d} prepared_payload_after=0 bytes_exact=true fresh=true\n", .{ @sizeOf(Event), @sizeOf(@import("../../../word16_execution/cpu_source.zig").Metadata), before.ordinary_events });
}
test "ordinary memory advice retires completed ordinals before later failed stage cleanup" {
    var captured = try Original.Captured.init(a);
    defer captured.deinit();
    var keys = try F.Keys.init(a);
    defer keys.deinit();
    captured.advice.secp[1][0][0].pointer += 8;
    try std.testing.expectError(error.InvalidWord16SecpCall, C.produce(a, &keys.pointers(), &keys.truths(), &.{ &captured.native[0], &captured.native[1] }, &captured.advice, Original.expectedFor(captured.program.identity), try F.config(), .{ .gkr_budget = 2 << 30, .consume_memory_events = true }));
    try std.testing.expectEqual(@as(usize, 0), captured.advice.events[0].len);
    try std.testing.expect(captured.advice.keccak[0].len == 1 and captured.advice.secp[1][0].len == 1);
    try std.testing.expectError(error.InvalidCombinedOrdinal, captured.advice.retireEvents(2));
}

const FailAfterRetirement = struct {
    child: std.mem.Allocator,
    retired: *const bool,
    fn allocator(self: *@This()) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        if (self.retired.*) return null;
        return self.child.rawAlloc(len, alignment, ra);
    }
    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) bool {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        return !self.retired.* and self.child.rawResize(memory, alignment, len, ra);
    }
    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, len: usize, ra: usize) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        if (self.retired.*) return null;
        return self.child.rawRemap(memory, alignment, len, ra);
    }
    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.child.rawFree(memory, alignment, ra);
    }
};

test "ordinary memory advice retires and completed worker cleanup survives a later stage-two allocation failure" {
    var timings: [5]C.WorkerTiming = @splat(.{});
    // Serial stage two makes the first completed owner an exact failure point.
    // The allocator refuses new owners only after CPU0's joined proof and
    // deinit; all free operations continue through the original allocator.
    var failing = FailAfterRetirement{ .child = a, .retired = &timings[0].completed_worker_retired };
    var captured = try Original.Captured.init(failing.allocator());
    defer captured.deinit();
    var keys = try F.Keys.init(failing.allocator());
    defer keys.deinit();
    try std.testing.expectError(error.OutOfMemory, C.produce(failing.allocator(), &keys.pointers(), &keys.truths(), &.{ &captured.native[0], &captured.native[1] }, &captured.advice, Original.expectedFor(captured.program.identity), try F.config(), .{ .gkr_budget = 2 << 30, .consume_memory_events = true, .worker_timings = &timings }));
    try std.testing.expect(timings[0].completed_worker_retired and timings[0].stage2_completed);
    try std.testing.expect(!timings[1].stage2_completed);
    try std.testing.expectEqual(@as(usize, 0), Owned.advice(&captured.advice).ordinary_events);
}
