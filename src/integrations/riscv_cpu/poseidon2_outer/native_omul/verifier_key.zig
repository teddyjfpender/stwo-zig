//! Retire prover-only data after independently constructing an R6 authority.
//! Verification retains source-derived roots, complete geometry, bound AIR and
//! semantic identity. No producer key/root is imported by this transition.
const K = @import("authority.zig");

/// Idempotent. The resulting key supports native verification, recursive
/// statement construction and parent-key derivation, but cannot prove.
pub fn retireProverData(key: *K.Key) void {
    const base = &key.base;
    if (base.fixed_tree) |*tree| tree.deinit(base.allocator);
    base.fixed_tree = null;
    base.fixed.deinit();
    base.fixed = .{ .allocator = base.allocator, .values = &.{} };
    base.allocator.free(base.usage);
    base.usage = &.{};
}
