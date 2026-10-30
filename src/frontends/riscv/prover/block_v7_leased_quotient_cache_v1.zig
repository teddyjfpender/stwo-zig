//! Bounded, proof-local LRU for immutable MAIN evaluations. Every consumer owns
//! a lease; pending producers and waiters pin entries before dropping the lock.
//! Capacity pressure never waits for readers: it falls back to local recovery.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Recovery = @import("block_v5_quotient_column_cache_v1.zig");
const M = core.fields.m31.M31;
const Poly = engine.air.component_prover.Poly;
const Twiddles = engine.poly.twiddles.TwiddleTree([]const M);
pub const Policy = Recovery.Policy;
const Entry = struct {
    key: Recovery.Key = undefined,
    state: enum { empty, pending, ready, failed } = .empty,
    values: []M = &.{},
    failure: ?anyerror = null,
    references: usize = 0,
    touched: u64 = 0,
};
pub const Lease = struct {
    values: []const M,
    owner: ?*Cache = null,
    index: usize = 0,
    /// Move-only by convention, like owned slices. Release the stored lease
    /// exactly once after the last row read, including evaluator error paths.
    pub fn release(self: *Lease) void {
        const owner = self.owner orelse return;
        owner.mutex.lock();
        defer owner.mutex.unlock();
        const entry = &owner.entries[self.index];
        std.debug.assert(entry.state == .ready and entry.references != 0);
        entry.references -= 1;
        entry.touched = owner.tick();
        self.owner = null;
        self.values = &.{};
    }
};
pub const Cache = struct {
    a: std.mem.Allocator,
    entries: []Entry,
    value_limit: usize,
    reserved_bytes: usize = 0,
    clock: u64 = 0,
    recovered_columns: usize = 0,
    reused_columns: usize = 0,
    evicted_columns: usize = 0,
    track_usage: bool = false,
    requested_columns: usize = 0,
    passthrough_columns: usize = 0,
    capacity_misses: usize = 0,
    mutex: std.Thread.Mutex = .{},
    changed: std.Thread.Condition = .{},
    pub fn initBounded(a: std.mem.Allocator, value_limit: usize, entry_limit: usize) !Cache {
        const entries = try a.alloc(Entry, entry_limit);
        @memset(entries, .{});
        return .{ .a = a, .entries = entries, .value_limit = value_limit };
    }
    /// Sources outlive this cache; all evaluators and leases must be joined.
    pub fn deinit(self: *Cache) void {
        for (self.entries) |entry| {
            std.debug.assert(entry.state != .pending and entry.references == 0);
            if (entry.state == .ready) self.a.free(entry.values);
        }
        self.a.free(self.entries);
        self.* = undefined;
    }
    fn tick(self: *Cache) u64 {
        // Saturation only degrades recency ordering after 2^64 accesses; it
        // cannot change values, lifetime safety or the strict retained cap.
        self.clock +|= 1;
        return self.clock;
    }
    pub fn get(self: *Cache, policy: Policy, poly: Poly, trace_log: u32, eval_log: u32, twiddles: ?Twiddles) !?Lease {
        const prepared = try Recovery.prepareSource(policy, poly, trace_log, eval_log);
        if (prepared == .passthrough) {
            if (self.track_usage) {
                self.mutex.lock();
                self.requested_columns += 1;
                self.passthrough_columns += 1;
                self.mutex.unlock();
            }
            return .{ .values = prepared.passthrough };
        }
        const key = prepared.recovery.key;
        const bytes = prepared.recovery.byte_count;
        self.mutex.lock();
        if (self.track_usage) self.requested_columns += 1;
        for (self.entries, 0..) |*entry, index| if (entry.state != .empty and std.meta.eql(entry.key, key)) {
            // Waiters pin BEFORE releasing the lock: completed values cannot
            // be evicted between producer broadcast and waiter reacquisition.
            entry.references += 1;
            while (entry.state == .pending) self.changed.wait(&self.mutex);
            if (entry.failure) |failure| {
                entry.references -= 1;
                self.mutex.unlock();
                return failure;
            }
            entry.touched = self.tick();
            self.reused_columns += 1;
            const result = Lease{ .values = entry.values, .owner = self, .index = index };
            self.mutex.unlock();
            return result;
        };
        var available: ?usize = null;
        if (bytes <= self.value_limit) while (true) {
            var victim: ?usize = null;
            for (self.entries, 0..) |entry, index| {
                if (entry.state == .empty) {
                    if (available == null) available = index;
                } else if (entry.state != .pending and entry.references == 0) {
                    if (victim == null or entry.touched < self.entries[victim.?].touched) victim = index;
                }
            }
            if (available != null and bytes <= self.value_limit - self.reserved_bytes) break;
            const index = victim orelse break;
            const entry = &self.entries[index];
            if (entry.state == .ready) {
                self.reserved_bytes -= entry.values.len * @sizeOf(M);
                self.a.free(entry.values);
                self.evicted_columns += 1;
            }
            entry.* = .{};
            available = index;
        };
        if (available == null or bytes > self.value_limit - self.reserved_bytes) {
            if (self.track_usage) self.capacity_misses += 1;
            self.mutex.unlock();
            return null;
        }
        const index = available.?;
        self.entries[index] = .{ .key = key, .state = .pending, .references = 1, .touched = self.tick() };
        self.reserved_bytes += bytes;
        self.mutex.unlock();
        const values = Recovery.recover(self.a, policy, poly, trace_log, eval_log, twiddles) catch |failure| {
            self.mutex.lock();
            const entry = &self.entries[index];
            entry.failure = failure;
            entry.state = .failed;
            entry.references -= 1;
            self.reserved_bytes -= bytes;
            self.changed.broadcast();
            self.mutex.unlock();
            return failure;
        };
        self.mutex.lock();
        const entry = &self.entries[index];
        entry.values = values;
        entry.state = .ready;
        entry.touched = self.tick();
        self.recovered_columns += 1;
        self.changed.broadcast();
        self.mutex.unlock();
        return .{ .values = values, .owner = self, .index = index };
    }
};
