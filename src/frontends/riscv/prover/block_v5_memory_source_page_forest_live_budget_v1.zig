//! Independent PAGE fold live-memory lane under the caller's aggregate budget.
//! Metadata and scratch caps are siblings. A returned root's real summary lease
//! retains this allocator after the local coordinator drops its reference;
//! Built still tears the borrowed root down before its stable metadata Owner.
const std = @import("std");
pub const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
pub fn create(backing: std.mem.Allocator, metadata: *Budget, max_live_bytes: usize) !*Budget {
    if (max_live_bytes == 0) return error.InvalidPageForestLiveBudget;
    const metadata_allocator = metadata.allocator();
    if (backing.ptr == metadata_allocator.ptr and backing.vtable == metadata_allocator.vtable) return error.PageForestLiveBudgetUsesMetadata;
    // Identifiable aggregate backing is retained by the same existing kernel.
    // Non-budget allocators preserve their original borrowed lifetime contract.
    return Budget.createRetainingParent(backing, max_live_bytes);
}
