//! Exact-owner FRI folds with explicit budget-bound GPU inverse buffers.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const runtime = @import("../runtime.zig");
const cache = @import("fri_inverse_cache_v1.zig");
const columns = @import("fri_columns_v1.zig");
const Storage = @import("stwo_backend_contracts").resident_storage.ResidentStorage;
extern fn stwo_zig_metal_fri_resident_fold_v1(*anyopaque, *anyopaque, *anyopaque, *anyopaque, u32, u32, u32, u32, bool, *const [4]u32, *f64, [*]u8, usize) bool;

pub fn fold(a: std.mem.Allocator, metal: *runtime.Runtime, source: Storage, destination: Storage, count: u32, kind: cache.Key.Kind, initial: u32, step: u32, alpha: core.fields.qm31.QM31) !runtime.FriCircleFoldResult {
    return foldWithPolicy(a, metal, source, destination, count, kind, initial, step, alpha, .require_shared_budget);
}
pub fn foldWithPolicy(a: std.mem.Allocator, metal: *runtime.Runtime, source: Storage, destination: Storage, count: u32, kind: cache.Key.Kind, initial: u32, step: u32, alpha: core.fields.qm31.QM31, policy: @import("fri_allocation_policy_v1.zig").Policy) !runtime.FriCircleFoldResult {
    _ = try @import("fri_allocation_policy_v1.zig").Binding.init(a, policy);
    const extent = @import("fri_budget_v1.zig");
    if (count < 2) return error.InvalidFriBudgetGeometry;
    try columns.requireBorrowedStorage(a, source, try extent.secureValues(count), policy);
    try columns.requireStorage(a, destination, try extent.secureValues(count / 2));
    const key = cache.Key{ .runtime = @intFromPtr(metal.handle), .count = if (kind == .circle) count / 2 else count, .layers = 1, .initial = initial, .step = step, .kind = kind };
    var inverses = try cache.beginWithPolicy(a, metal, .{ if (kind == .circle) key else null, if (kind == .line) key else null }, policy);
    defer inverses.abort();
    const generated = inverses.needsGeneration(kind);
    const coordinates = alpha.toM31Array();
    const alpha_words = [4]u32{ coordinates[0].v, coordinates[1].v, coordinates[2].v, coordinates[3].v };
    var ms: f64 = 0;
    var message: [1024]u8 = @splat(0);
    if (!stwo_zig_metal_fri_resident_fold_v1(metal.handle, source.handle, destination.handle, inverses.handle(kind) orelse unreachable, count, if (kind == .circle) 0 else 1, initial, step, generated, &alpha_words, &ms, &message, message.len)) return error.FriResidentFoldFailed;
    try inverses.complete();
    return .{ .gpu_ms = ms, .inverse_generated = generated };
}
