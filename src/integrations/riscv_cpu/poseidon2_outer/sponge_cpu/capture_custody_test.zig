//! Producer-only ownership controls; no STARK proving or source-key setup.
const std = @import("std");
const E = @import("stwo_prover_engine");
const Custody = @import("capture_custody.zig");
const Events = @import("event_custody.zig");
const Native = @import("../../word16_execution/prepared.zig").Prepared;
const Store = @import("../pure_p2_retained_main.zig").Store;

test "detached actual small native event custody preserves zero then nonzero shard ordinals" {
    const a = std.testing.allocator;
    // Genuine OP executor/capture: first shard has only service retirements,
    // second has one ordinary LD. No partially initialized Prepared objects.
    var captured = try @import("../../word16_global_execution/services/sponge_fixture.zig").Captured.initForOp(a);
    defer captured.deinit();
    try std.testing.expectEqual(@as(u32, 0), captured.native[0].raw_counts.memory);
    try std.testing.expectEqual(@as(u32, 1), captured.native[1].raw_counts.memory);
    const saved = captured.advice.events[1][0];
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try tmp.dir.realpathAlloc(a, ".");
    defer a.free(path);
    var store = try Store.init(a, path, 1 << 20, 1 << 20);
    defer store.deinit();
    var custody = Custody.Owner{ .store = &store, .park_metadata = false, .park_events = true };
    defer custody.deinit();
    const hooks = custody.hooks();
    try hooks.validate();
    for (&captured.native, 0..) |*native, ordinal| try hooks.events.?(hooks.context, ordinal, native, &captured.advice.events[ordinal]);
    try std.testing.expectEqual(@as(usize, 2), custody.event_count);
    try std.testing.expect(custody.events[0] == null);
    try std.testing.expect(custody.events[1] != null);
    try std.testing.expectEqual(@as(usize, 0), captured.advice.events[1].len);
    const reserved = store.reserved;
    try std.testing.expect(reserved > 0);
    try hooks.prepare_events.?(hooks.context, 0, &captured.native[0], &captured.advice.events[0]);
    try hooks.release_events.?(hooks.context, 0, &captured.native[0], &captured.advice.events[0]);
    try hooks.prepare_events.?(hooks.context, 1, &captured.native[1], &captured.advice.events[1]);
    try std.testing.expectEqualDeep(saved, captured.advice.events[1][0]);
    try std.testing.expectError(error.OpCaptureCustodyCoverage, hooks.prepare_events.?(hooks.context, 1, &captured.native[1], &captured.advice.events[1]));
    try hooks.release_events.?(hooks.context, 1, &captured.native[1], &captured.advice.events[1]);
    try std.testing.expectEqual(reserved, store.reserved);
    // A null token cannot stand in for a nonempty source shard.
    const held = custody.events[1].?;
    custody.events[1] = null;
    try std.testing.expectError(error.OpCaptureCustodyCoverage, hooks.prepare_events.?(hooks.context, 1, &captured.native[1], &captured.advice.events[1]));
    custody.events[1] = held;
    // Leave a restored allocation owned by Captured; token teardown must not
    // free it or require it to stay parked. This models planning error cleanup.
    try hooks.prepare_events.?(hooks.context, 1, &captured.native[1], &captured.advice.events[1]);
    custody.deinit();
    try std.testing.expectEqual(@as(usize, 0), store.reserved);
    try std.testing.expectEqualDeep(saved, captured.advice.events[1][0]);
}

const Phase = enum { prepare, release };
const Failure = struct {
    custody: *Custody.Owner,
    phase: Phase,
    restored: bool = false,
    fn park(raw: ?*anyopaque, ordinal: usize, native: *Native, events: *[]Events.Event) !void {
        const self: *Failure = @ptrCast(@alignCast(raw.?));
        const hooks = self.custody.hooks();
        try hooks.events.?(hooks.context, ordinal, native, events);
    }
    fn prepare(raw: ?*anyopaque, ordinal: usize, native: *Native, events: *[]Events.Event) !void {
        const self: *Failure = @ptrCast(@alignCast(raw.?));
        const hooks = self.custody.hooks();
        try hooks.prepare_events.?(hooks.context, ordinal, native, events);
        if (events.len != 0) {
            self.restored = true;
            if (self.phase == .prepare) return error.IntentionalEventPrepareFailure;
        }
    }
    fn release(raw: ?*anyopaque, ordinal: usize, native: *Native, events: *[]Events.Event) !void {
        const self: *Failure = @ptrCast(@alignCast(raw.?));
        if (events.len != 0 and self.phase == .release) return error.IntentionalEventReleaseFailure;
        const hooks = self.custody.hooks();
        try hooks.release_events.?(hooks.context, ordinal, native, events);
    }
};

test "detached actual small native planning prepare and release failures free restored event owners" {
    const config_path = std.posix.getenv("STWO_OP_DETACHED_CONFIG") orelse return error.SkipZigTest;
    const raw = try std.fs.cwd().readFileAlloc(std.testing.allocator, config_path, 16384);
    defer std.testing.allocator.free(raw);
    const parsed = try std.json.parseFromSlice(@import("../../rv64_ethereum_request.zig").Config, std.testing.allocator, raw, .{});
    defer parsed.deinit();
    if (parsed.value.max_steps > 10_000_000) return error.SmallCapturePlanControlRequired;
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 32 << 30);
    defer budget.destroy();
    inline for (.{ Phase.prepare, Phase.release }) |phase| {
        {
            const a = budget.allocator();
            var tmp = std.testing.tmpDir(.{});
            defer tmp.cleanup();
            const path = try tmp.dir.realpathAlloc(a, ".");
            defer a.free(path);
            var store = try Store.init(a, path, 1 << 30, 1 << 30);
            defer store.deinit();
            var custody = Custody.Owner{ .store = &store, .park_metadata = false, .park_events = true };
            defer custody.deinit();
            var failure = Failure{ .custody = &custody, .phase = phase };
            var timer = try std.time.Timer.start();
            const expected = if (phase == .prepare) error.IntentionalEventPrepareFailure else error.IntentionalEventReleaseFailure;
            try std.testing.expectError(expected, @import("../pure_p2_op_capture_plan.zig").Owner.init(a, parsed.value, .op_target_b4_q72_p0_fold4_v1, .{ .local_truth = true, .truth_limits = .{ .live_bytes = 8 << 30, .main_bytes = 2 << 30, .interaction_bytes = 4 << 30, .gkr_bytes = 12 << 30 }, .detached_sponge = true, .capture_hooks = .{ .context = &failure, .events = Failure.park, .prepare_events = Failure.prepare, .release_events = Failure.release } }, &timer));
            try std.testing.expect(failure.restored);
            try std.testing.expect(custody.event_bytes > 0);
            custody.deinit();
            try std.testing.expectEqual(@as(usize, 0), store.reserved);
        }
        try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
        try std.testing.expectEqual(@as(usize, 0), budget.snapshot().external_live_bytes);
    }
}
