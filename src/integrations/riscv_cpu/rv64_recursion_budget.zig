//! Exact allocator ancestry admitted by the ready-lane recursion route.
//! Recycler backing allocations (including idle rounded blocks and metadata)
//! stay charged to the synchronized shared budget. This does not unwrap an
//! arbitrary allocator or create an independent budget with a second cap.
const std = @import("std");
const Recycler = @import("rv64_large_block_recycler.zig").LargeBlockRecycler;

/// Borrowed owner. Caller must keep the allocator/recycler alive until every
/// lane joins; execution separately retains this owner across that interval.
/// One known recycler over a DIRECT budget is supported, never recursive walks.
pub fn require(comptime Budget: type, a: std.mem.Allocator) !*Budget {
    if (Budget.fromAllocator(a)) |owner| return owner;
    if (Recycler.fromAllocator(a)) |recycler| {
        if (Budget.fromAllocator(recycler.child)) |owner| return owner;
    }
    return error.SharedRecursionBudgetRequired;
}
