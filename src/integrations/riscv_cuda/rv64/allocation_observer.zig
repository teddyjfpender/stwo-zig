//! Opt-in allocator diagnostic. Boundaries host-join owner lanes and invalidate
//! latency timing. Stable node identity omits MAIN, which is rebound at commit.
const std = @import("std");
const Begin = *const fn (*anyopaque, *const [8]u32, u32, u32, u32, u32) callconv(.c) c_int;
const End = *const fn (*anyopaque) callconv(.c) c_int;
pub const Stage = enum(u32) { main_witness = 1, main_commit = 2, inter_witness = 3, inter_commit = 4, composition = 5, pcs_metadata = 6, retirement = 15, fixed_commit = 16, fixed_ingress = 17, fixed_adoption = 18, native_gkr = 19, native_binding = 20, native_main_replay = 21 };
pub fn enabled() bool {
    return if (std.posix.getenv("STWO_RV64_ALLOCATION_OBSERVER")) |v| std.mem.eql(u8, v, "1") else false;
}
pub fn stableKey(scope: anytype) [8]u32 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo/rv64/allocator-node/v1\x00");
    hash.update(&scope.statement);
    hash.update(&scope.fixed);
    var ordinal: [4]u8 = undefined;
    std.mem.writeInt(u32, &ordinal, scope.ordinal, .little);
    hash.update(&ordinal);
    const digest = hash.finalResult();
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    return result;
}
pub const Range = struct {
    raw: *anyopaque,
    close: ?End = null,
    pub fn begin(library: *std.DynLib, raw: *anyopaque, scope: anytype, domain: u32, stage: Stage, lane: u32) !Range {
        if (!enabled()) return .{ .raw = raw };
        const capability = library.lookup(*const fn () callconv(.c) c_int, "stwo_exec_context_allocation_observer_capability_v1") orelse return error.MissingAllocationObserver;
        if (capability() != 1) return error.MissingAllocationObserver;
        const start = library.lookup(Begin, "stwo_exec_context_allocation_observer_begin_v1") orelse return error.MissingAllocationObserver;
        const close = library.lookup(End, "stwo_exec_context_allocation_observer_end_v1") orelse return error.MissingAllocationObserver;
        const key = stableKey(scope);
        if (start(raw, &key, scope.ordinal, domain, @intFromEnum(stage), lane) != 0) return error.AllocationObserverBeginFailed;
        return .{ .raw = raw, .close = close };
    }
    pub fn deinit(self: *Range) void {
        if (self.close) |close| {
            const status = close(self.raw);
            if (status != 0) std.debug.print("GPU_NODE_ALLOC_CLOSE_FAILED status={} coverage_valid=0\n", .{status});
            self.close = null;
        }
    }
};

fn keyText(key: [8]u32) [64]u8 {
    var result: [64]u8 = undefined;
    for (key, 0..) |word, i| _ = std.fmt.bufPrint(result[i * 8 ..][0..8], "{x:0>8}", .{word}) catch unreachable;
    return result;
}
/// Emit the existing planner inputs verbatim; this does not alter any bound.
/// temporary is the stage envelope, not an amount to add to retained_after.
pub fn model(scope: anytype, domain: u32, stage: Stage, temporary: anytype, retained_after: anytype, successor: anytype) void {
    if (!enabled()) return;
    const key = keyText(stableKey(scope));
    std.debug.print("GPU_NODE_ALLOC_MODEL ordinal={} domain={} stage={s} key={s} stage_additional_large={} stage_additional_small={} retained_after_large={} retained_after_small={} successor_large={} successor_small={} model_changed=0\n", .{ scope.ordinal, domain, @tagName(stage), &key, temporary.large, temporary.small, retained_after.large, retained_after.small, successor.large, successor.small });
}
/// Record an authenticated authority handoff; setup bytes remain shared rather
/// than being charged physically to every node using an immutable alias.
pub fn fixedLink(provisional: anytype, final: anytype, alias_words: u64) void {
    if (!enabled()) return;
    const before = keyText(stableKey(provisional));
    const after = keyText(stableKey(final));
    std.debug.print("GPU_NODE_ALLOC_FIXED_LINK ordinal={} provisional_key={s} final_key={s} fixed_coefficient_alias_requested_bytes={} shared_setup=1 physical_alias_charge=0\n", .{ final.ordinal, &before, &after, alias_words * 4 });
}
