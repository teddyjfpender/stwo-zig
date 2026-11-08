//! Bounded immutable host FFT/FRI data. No statement, channel, opening point,
//! root, sampled value, coefficient or query position enters this cache.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const F = @import("fri.zig");
const C = @import("../rv64_pcs_fixture_main.zig");
const M = core.fields.m31.M31;
const Key = struct { source_eval_log: u32, fri: [32]u8 };
const Entry = struct {
    key: Key,
    forward: []M,
    fri_descriptions: []u32,
    fri_coordinates: []M,
    bytes: usize,
    pins: usize = 0,
    age: u64 = 0,
    fn deinit(self: *Entry, a: std.mem.Allocator) void {
        a.free(self.forward);
        a.free(self.fri_descriptions);
        a.free(self.fri_coordinates);
        a.destroy(self);
    }
};
/// The fixed entry count bounds metadata too. The byte cap covers retained
/// arrays and entry headers, not the existing cold arithmetic scratch or RSS.
pub const Cache = struct {
    pub const max_entries = 8;
    pub const default_bytes = 128 << 20;
    allocator: std.mem.Allocator,
    limit: usize,
    retained_bytes: usize = 0,
    entries: [max_entries]?*Entry = @splat(null),
    mutex: std.Thread.Mutex = .{},
    clock: u64 = 0,
    hits: u64 = 0,
    misses: u64 = 0,
    bypasses: u64 = 0,
    evictions: u64 = 0,
    pub fn init(a: std.mem.Allocator, bytes: usize) Cache {
        return .{ .allocator = a, .limit = bytes };
    }
    pub const Stats = struct { hits: u64, misses: u64, bypasses: u64, evictions: u64, retained_bytes: usize, limit: usize };
    pub fn stats(self: *Cache) Stats {
        self.mutex.lock();
        defer self.mutex.unlock();
        return .{ .hits = self.hits, .misses = self.misses, .bypasses = self.bypasses, .evictions = self.evictions, .retained_bytes = self.retained_bytes, .limit = self.limit };
    }
    pub fn deinit(self: *Cache) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (&self.entries) |*slot| if (slot.*) |entry| {
            std.debug.assert(entry.pins == 0);
            entry.deinit(self.allocator);
            slot.* = null;
        };
        self.retained_bytes = 0;
    }
    pub const Borrow = struct {
        cache: *Cache,
        entry: *Entry,
        pub fn forward(self: Borrow) []const M {
            return self.entry.forward;
        }
        pub fn descriptions(self: Borrow) []const u32 {
            return self.entry.fri_descriptions;
        }
        pub fn coordinates(self: Borrow) []const M {
            return self.entry.fri_coordinates;
        }
        pub fn release(self: Borrow) void {
            self.cache.mutex.lock();
            defer self.cache.mutex.unlock();
            std.debug.assert(self.entry.pins != 0);
            self.entry.pins -= 1;
        }
    };
    fn key(log: u32, plan: F.Plan) !Key {
        try plan.validate();
        if (log == 0 or log > plan.initial_log) return error.InvalidPcsGeometryCacheKey;
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("rv64/canonical-host-pcs-fft-fri/v1\x00");
        var word: [4]u8 = undefined;
        for ([_]u32{ plan.initial_log, plan.terminal_count, @intCast(plan.len) }) |value| {
            std.mem.writeInt(u32, &word, value, .little);
            h.update(&word);
        }
        for (plan.layers[0..plan.len]) |layer| for ([_]u32{ layer.count, layer.fold_step, layer.leaf_log, layer.shift }) |value| {
            std.mem.writeInt(u32, &word, value, .little);
            h.update(&word);
        };
        return .{ .source_eval_log = log, .fri = h.finalResult() };
    }
    fn requiredBytes(log: u32, plan: F.Plan) !usize {
        _ = try key(log, plan);
        var coordinates: usize = 0;
        for (plan.layers[0..plan.len], 0..) |layer, li| {
            var count: usize = layer.count;
            for (0..layer.fold_step) |step| {
                const half = count / 2;
                coordinates += if (li == 0 and step == 0) (half + 3) / 4 * 2 else half;
                count /= 2;
            }
        }
        return @sizeOf(Entry) + 4 * ((@as(usize, 1) << @intCast(log - 1)) + plan.len * 8 + coordinates);
    }
    fn build(self: *Cache, k: Key, plan: F.Plan, bytes: usize) !*Entry {
        const a = self.allocator;
        const entry = try a.create(Entry);
        errdefer a.destroy(entry);
        var tw = try engine.poly.twiddles.precomputeM31(a, core.poly.circle.canonic.CanonicCoset.new(k.source_eval_log).circleDomain().half_coset);
        errdefer engine.poly.twiddles.deinitM31(a, &tw);
        var descriptions: std.ArrayList(u32) = .empty;
        defer descriptions.deinit(a);
        var coordinates: std.ArrayList(M) = .empty;
        defer coordinates.deinit(a);
        try C.friMetadataWithAllocator(a, plan, &descriptions, &coordinates);
        const owned_descriptions = try descriptions.toOwnedSlice(a);
        errdefer a.free(owned_descriptions);
        const owned_coordinates = try coordinates.toOwnedSlice(a);
        a.free(tw.itwiddles);
        entry.* = .{ .key = k, .forward = tw.twiddles, .fri_descriptions = owned_descriptions, .fri_coordinates = owned_coordinates, .bytes = bytes };
        std.debug.assert(bytes == @sizeOf(Entry) + 4 * (entry.forward.len + entry.fri_descriptions.len + entry.fri_coordinates.len));
        return entry;
    }
    /// A miss that cannot fit beside pinned entries bypasses this cache; the
    /// caller keeps the existing uncached path. Failed cold construction leaves
    /// every admitted entry and pin unchanged.
    pub fn acquire(self: *Cache, log: u32, plan: F.Plan) !?Borrow {
        const k = try key(log, plan);
        const bytes = try requiredBytes(log, plan);
        self.mutex.lock();
        defer self.mutex.unlock();
        self.clock +%= 1;
        for (self.entries) |slot| if (slot) |entry| {
            if (std.meta.eql(entry.key, k)) {
                entry.pins += 1;
                entry.age = self.clock;
                self.hits += 1;
                return .{ .cache = self, .entry = entry };
            }
        };
        self.misses += 1;
        var pinned_bytes: usize = 0;
        var pinned_entries: usize = 0;
        for (self.entries) |slot| if (slot) |entry| {
            if (entry.pins != 0) {
                pinned_bytes += entry.bytes;
                pinned_entries += 1;
            }
        };
        if (bytes > self.limit or pinned_bytes > self.limit - bytes or pinned_entries == max_entries) {
            self.bypasses += 1;
            return null;
        }
        const candidate = try self.build(k, plan, bytes);
        errdefer candidate.deinit(self.allocator);
        while (true) {
            var empty: ?usize = null;
            var victim: ?usize = null;
            for (self.entries, 0..) |slot, i| {
                if (slot) |entry| {
                    if (entry.pins == 0 and (victim == null or entry.age < self.entries[victim.?].?.age)) victim = i;
                } else empty = i;
            }
            if (empty != null and self.retained_bytes <= self.limit - bytes) {
                candidate.pins = 1;
                candidate.age = self.clock;
                self.entries[empty.?] = candidate;
                self.retained_bytes += bytes;
                return .{ .cache = self, .entry = candidate };
            }
            const index = victim orelse unreachable; // proved by pinned admission
            const retired = self.entries[index].?;
            self.retained_bytes -= retired.bytes;
            self.entries[index] = null;
            retired.deinit(self.allocator);
            self.evictions += 1;
        }
    }
};
