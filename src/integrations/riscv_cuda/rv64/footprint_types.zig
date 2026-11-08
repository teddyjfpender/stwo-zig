//! Device-memory footprint vocabulary shared by the stage cost models, the
//! runtime memory owner and the PCS allocation cost. Pure values: no ledger,
//! no runtime, no GPU. Formerly declared by the retired admission planner.
const std = @import("std");
pub const chunk_bytes: u64 = 32 << 20;
pub const small_slab_bytes: u64 = 512 << 20;
pub const small_threshold: u64 = 4 << 20;
pub const small_alignment: u64 = 512;
pub const external_budget: u64 = 4 << 30;
pub const physical_limit: u64 = 28_000_000_000;
/// Separate small-slab occupancy and physical large chunks. Inputs are allocation
/// sizes, never aggregate cell masses: each large allocation rounds separately.
pub const Footprint = struct {
    large: u64 = 0,
    small: u64 = 0,
    pub fn allocation(bytes: u64) !Footprint {
        if (bytes == 0) return .{};
        const unit = if (bytes < small_threshold) small_alignment else chunk_bytes;
        const aligned = (try std.math.add(u64, bytes, unit - 1)) & ~(unit - 1);
        return if (bytes < small_threshold) .{ .small = aligned } else .{ .large = aligned };
    }
    pub fn allocations(sizes: anytype) !Footprint {
        var out: Footprint = .{};
        for (sizes) |bytes| out = try out.add(try allocation(bytes));
        return out;
    }
    pub fn add(a: Footprint, b: Footprint) !Footprint {
        return .{ .large = try std.math.add(u64, a.large, b.large), .small = try std.math.add(u64, a.small, b.small) };
    }
    pub fn max(a: Footprint, b: Footprint) Footprint {
        return .{ .large = @max(a.large, b.large), .small = @max(a.small, b.small) };
    }
    pub fn contains(a: Footprint, b: Footprint) bool {
        return a.large >= b.large and a.small >= b.small;
    }
};
pub const Domain = enum { immutable_setup, native_packet, recursion_node, gkr_packet };
pub const Stage = enum { setup, witness, trace_commit, interaction, composition, pcs, gkr, retire };
pub const ProgressKey = struct { statement: [32]u8, fixed: [32]u8, ordinal: u32 };
pub fn progressKey(scope: anytype) ProgressKey {
    return .{ .statement = scope.statement, .fixed = scope.fixed, .ordinal = scope.ordinal };
}

test "allocation rounding separates small slab and large chunks" {
    try std.testing.expectEqual(Footprint{ .small = 512 }, try Footprint.allocation(1));
    try std.testing.expectEqual(Footprint{ .large = chunk_bytes }, try Footprint.allocation(small_threshold));
    try std.testing.expectEqual(Footprint{}, try Footprint.allocation(0));
}
