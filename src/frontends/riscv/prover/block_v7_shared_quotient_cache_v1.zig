//! One leased, bounded MAIN evaluation LRU for a complete original proof. This owns
//! no statement/key authority and never survives the joined core-proof call.
const std = @import("std");
const Shared = @import("block_v5_quotient_column_cache_v1.zig");
const Leased = @import("block_v7_leased_quotient_cache_v1.zig");
pub const DEFAULT_RETAINED_BYTES = Shared.VALUE_LIMIT;
/// Explicit request-controlled ceiling, still charged to the enclosing proof
/// allocator. This is not a reservation and cannot bypass its smaller budget.
pub const MAX_RETAINED_BYTES: usize = 2 * 1024 * 1024 * 1024;
pub const Stats = struct { recovered_columns: usize = 0, reused_columns: usize = 0, retained_bytes: usize = 0, requested_columns: usize = 0, passthrough_columns: usize = 0, capacity_misses: usize = 0, evicted_columns: usize = 0 };

pub const Owner = struct {
    backing: std.mem.Allocator,
    synchronized: std.heap.ThreadSafeAllocator,
    cache: Leased.Cache,

    /// The backing is the same concurrent allocator used by the STARK core,
    /// never the component metadata arena. The extra wrapper serializes cache
    /// scratch allocation and has a stable address for its entire lifetime.
    /// Zero disables caching without altering any evaluator/validation path.
    pub fn create(backing: std.mem.Allocator, retained_limit: usize) !?*Owner {
        return createWithUsage(backing, retained_limit, true);
    }
    pub fn createWithUsage(backing: std.mem.Allocator, retained_limit: usize, track_usage: bool) !?*Owner {
        if (retained_limit > MAX_RETAINED_BYTES) return error.InvalidV7QuotientCacheBudget;
        if (retained_limit == 0) return null;
        const self = try backing.create(Owner);
        errdefer backing.destroy(self);
        self.backing = backing;
        self.synchronized = .{ .child_allocator = backing };
        self.cache = try Leased.Cache.initBounded(self.synchronized.allocator(), retained_limit, Shared.ENTRY_LIMIT);
        self.cache.track_usage = track_usage;
        return self;
    }
    /// Call after all domain evaluators have joined. Committed source columns
    /// are immutable while this owner can be read; pointer keys are deliberately
    /// not an authority to reuse evaluations across proofs or mutable witnesses.
    pub fn destroy(self: *Owner) void {
        self.cache.deinit();
        const backing = self.backing;
        backing.destroy(self);
    }
    pub fn stats(self: *Owner) Stats {
        self.cache.mutex.lock();
        defer self.cache.mutex.unlock();
        return .{ .recovered_columns = self.cache.recovered_columns, .reused_columns = self.cache.reused_columns, .retained_bytes = self.cache.reserved_bytes, .requested_columns = self.cache.requested_columns, .passthrough_columns = self.cache.passthrough_columns, .capacity_misses = self.cache.capacity_misses, .evicted_columns = self.cache.evicted_columns };
    }
};
