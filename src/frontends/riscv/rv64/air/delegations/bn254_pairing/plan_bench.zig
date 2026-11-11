//! Explicit bounded real composite plan benchmark; no witness/GP/STARK.
const std = @import("std");
const L = @import("lowering.zig");
fn word(h: *std.crypto.hash.sha2.Sha256, value: u32) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    h.update(&bytes);
}
fn digest(plan: *const L.Program) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    word(&h, plan.value_count);
    for (plan.stages) |stage| {
        for (stage.coefficients) |c| word(&h, @bitCast(c));
        for (stage.input) |id| word(&h, id);
        word(&h, stage.writer);
    }
    for (plan.hints) |hint| {
        word(&h, hint.writer);
        word(&h, hint.source_writer);
        word(&h, @intFromEnum(hint.kind));
        word(&h, hint.denominator);
    }
    for (plan.events) |event| {
        word(&h, @intFromEnum(event.kind));
        word(&h, @intCast(event.index));
    }
    for (plan.source_to_new) |id| word(&h, id);
    for (plan.assertions) |a| {
        word(&h, a.id);
        word(&h, a.value);
    }
    for (plan.fanout) |n| word(&h, n);
    return h.finalResult();
}
fn pass(allocator: std.mem.Allocator, reference: bool) !struct { ns: u64, hash: [32]u8, allocations: usize, bytes: usize } {
    var tracking = std.testing.FailingAllocator.init(allocator, .{});
    var timer = try std.time.Timer.start();
    var plan = if (reference) try L.Program.initReferenceForTesting(tracking.allocator()) else try L.Program.init(tracking.allocator());
    const ns = timer.read();
    const hash = digest(&plan);
    plan.deinit();
    try std.testing.expectEqual(tracking.allocations, tracking.deallocations);
    try std.testing.expectEqual(tracking.allocated_bytes, tracking.freed_bytes);
    return .{ .ns = ns, .hash = hash, .allocations = tracking.allocations, .bytes = tracking.allocated_bytes };
}
test "MAC12 complete plan direct allocation interleaved bounded benchmark" {
    const marker = std.process.getEnvVarOwned(std.testing.allocator, "STWO_MAC12_PLAN_BENCH") catch |err| {
        if (err == error.EnvironmentVariableNotFound) return error.SkipZigTest;
        return err;
    };
    defer std.testing.allocator.free(marker);
    var deadline = try std.time.Timer.start();
    for ([_]std.mem.Allocator{ std.testing.allocator, std.heap.smp_allocator }, [_][]const u8{ "testing", "smp" }) |allocator, label| {
        const warm = try pass(allocator, true);
        var times: [4]u64 = undefined;
        for ([_]bool{ true, false, false, true }, 0..) |reference, i| {
            if (deadline.read() > 30 * std.time.ns_per_s) return error.BoundedPlanBuildDeadline;
            const result = try pass(allocator, reference);
            try std.testing.expectEqualSlices(u8, &warm.hash, &result.hash);
            times[i] = result.ns;
            std.debug.print("OP_MAC12_PLAN_BENCH allocator={s} index={d} mode={s} seconds={d:.6} allocations={d} allocated_bytes={d} metadata_sha256={s}\n", .{ label, i, if (reference) "allocating_reference" else "direct_into", @as(f64, @floatFromInt(result.ns)) / 1e9, result.allocations, result.bytes, std.fmt.bytesToHex(result.hash, .lower) });
        }
        const reference = @as(f64, @floatFromInt(times[0] + times[3])) / 2e9;
        const direct = @as(f64, @floatFromInt(times[1] + times[2])) / 2e9;
        std.debug.print("OP_MAC12_PLAN_SUMMARY allocator={s} reference_seconds={d:.6} direct_seconds={d:.6} speedup={d:.3}\n", .{ label, reference, direct, reference / direct });
    }
}
