//! New-mode Keccak geometry is chosen from source GKR checkpoint storage and
//! whole-worker limits. Other families retain their original ordered plan.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const T = @import("../word16_global_execution/services/types.zig");
const Wire = @import("../word16_global_execution/services/wire.zig");
const Old = @import("../word16_global_execution/ethereum/plan.zig");
const Local = @import("truth_local_gkr/resource.zig");
const Security = @import("truth_local_gkr/security.zig");
pub fn declarations(a: std.mem.Allocator, total: [T.FAMILIES]u32, config: core.pcs.PcsConfig, limits: anytype, available_workers: usize) ![]Wire.TruthDeclaration {
    var non_keccak = total;
    non_keccak[0] = 0;
    const others = try Old.truthsForServiceCounts(a, non_keccak, .{}, 18);
    defer a.free(others);
    const profile_word = Wire.keccakProfileWord(.triple_v2);
    const capacity = if (total[0] != 0) try Local.maxKeccak(config, profile_word, limits) else null;
    const shards = if (capacity) |cap| try std.math.divCeil(usize, total[0], cap.calls) else 0;
    const required = try std.math.add(usize, shards, others.len);
    if (required > available_workers) return error.OpNativeTruthShardCapacity;
    var out: std.ArrayList(Wire.TruthDeclaration) = .empty;
    errdefer out.deinit(a);
    try out.ensureTotalCapacity(a, required);
    var next: u32 = 1;
    if (capacity) |cap| while (next <= total[0]) {
        const calls: u32 = @min(cap.calls, total[0] - next + 1);
        const rows = try std.math.mul(u32, try std.math.divCeil(u32, calls, 2), A.crypto.keccak.layout.ROWS_PER_PAIR);
        const log = @max(5, std.math.log2_int_ceil(u32, @max(32, rows)));
        const d = Wire.TruthDeclaration{ .family = .keccak, .first_id = next, .calls = calls, .logs = .{ log, profile_word } };
        try (try Local.derive(d, config)).admit(limits);
        out.appendAssumeCapacity(d);
        next = try std.math.add(u32, next, calls);
    };
    for (others) |d| {
        // Secp uses the old independent product/linear roster. Refuse an
        // oversized selected local child before any key/witness allocation.
        if (Security.eligible(d)) try (try Local.derive(d, config)).admit(limits);
        out.appendAssumeCapacity(d);
    }
    return out.toOwnedSlice(a);
}
test "OP heavy truth-local planner shards by checkpoint budget and preserves every source ID" {
    const a = std.testing.allocator;
    const config = @import("pure_p2_worker_protocol.zig").Profile.op_target_b4_q72_p0_fold4_v1.config();
    const limits = struct { live_bytes: usize = 8 << 30, main_bytes: usize = 2 << 30, interaction_bytes: usize = 4 << 30, gkr_bytes: usize = 12 << 30 }{};
    const total = [T.FAMILIES]u32{ 15121, 3237, 2760, 952, 33117, 19465, 31908, 331163, 0, 0, 0, 0 };
    const old = try Old.truthsForServiceCounts(a, total, .{}, 18);
    defer a.free(old);
    try std.testing.expectError(error.OpTruthLocalBudget, (try Local.derive(old[0], config)).admit(limits));
    const selected = try declarations(a, total, config, limits, 256 - 57 - 22);
    defer a.free(selected);
    try std.testing.expectEqual(@as(usize, 16), selected.len);
    const calls = [_]u32{ 4518, 4518, 4518, 1567 };
    const logs = [_]u32{ 16, 16, 16, 15 };
    var next: u32 = 1;
    for (selected[0..4], calls, logs) |d, count, log| {
        try std.testing.expect(d.family == .keccak);
        try std.testing.expectEqual(next, d.first_id);
        try std.testing.expectEqual(count, d.calls);
        try std.testing.expectEqual(log, d.logs[0]);
        try (try Local.derive(d, config)).admit(limits);
        next += count;
    }
    try std.testing.expectEqual(@as(u32, 15122), next);
    try std.testing.expectEqualDeep(old[1..], selected[4..]);
    try std.testing.expectError(error.OpNativeTruthShardCapacity, declarations(a, total, config, limits, 15));
    var tiny = limits;
    tiny.gkr_bytes = 1;
    try std.testing.expectError(error.OpTruthLocalBudget, declarations(a, total, config, tiny, 256));
}
