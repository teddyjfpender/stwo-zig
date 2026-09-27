//! Worker-scoped, two-entry cache of immutable authenticated PCS graphs.
//! The budget bounds retained payload, not transient construction or live leases.
const std = @import("std");
const circuit = @import("pcs_deep_circuit_circuit.zig");
const Prepared = @import("pcs_deep_circuit_prepared.zig").Prepared;

pub const Cache = struct {
    allocator: std.mem.Allocator,
    byte_budget: usize,
    entries: [2]?Prepared = .{ null, null },
    next: usize = 0,
    retained_bytes: usize = 0,
    builds: usize = 0,
    hits: usize = 0,

    pub fn init(allocator: std.mem.Allocator, byte_budget: usize) Cache {
        return .{ .allocator = allocator, .byte_budget = byte_budget };
    }
    pub fn deinit(self: *Cache) void {
        for (&self.entries) |*entry| if (entry.*) |*plan| plan.deinit();
        self.* = undefined;
    }
    fn evict(self: *Cache, index: usize) void {
        if (self.entries[index]) |*old| {
            self.retained_bytes -= old.retainedBytes();
            old.deinit();
            self.entries[index] = null;
        }
    }
    pub fn acquire(self: *Cache, profile: circuit.Profile) circuit.Error!Prepared {
        try profile.validate();
        for (&self.entries) |*entry| if (entry.*) |*plan| {
            if (equalProfiles(plan.profile(), profile)) {
                self.hits += 1;
                return plan.retain();
            }
        };
        var plan = try Prepared.init(self.allocator, profile);
        self.builds += 1;
        const bytes = plan.retainedBytes();
        if (bytes > self.byte_budget) return plan;
        self.evict(self.next);
        if (self.retained_bytes > self.byte_budget - bytes)
            self.evict((self.next + 1) % self.entries.len);
        self.entries[self.next] = plan.retain();
        self.retained_bytes += bytes;
        self.next = (self.next + 1) % self.entries.len;
        return plan;
    }
};

fn equalProfiles(a: circuit.Profile, b: circuit.Profile) bool {
    if (a.lifting_log_size != b.lifting_log_size or a.log_blowup_factor != b.log_blowup_factor or
        a.query_count != b.query_count or a.trees.len != b.trees.len or
        !std.mem.eql(circuit.SamplePointLayout, a.sample_layouts, b.sample_layouts) or
        !std.mem.eql(u32, a.mask_log_sizes, b.mask_log_sizes)) return false;
    for (a.trees, b.trees) |left, right| {
        if (!std.mem.eql(u32, left.column_log_sizes, right.column_log_sizes)) return false;
    }
    return true;
}

const test_trees = [_]circuit.TreeProfile{.{ .column_log_sizes = &.{3} }};
const test_profile = circuit.Profile{ .trees = &test_trees, .sample_layouts = &.{.current_previous}, .lifting_log_size = 4, .log_blowup_factor = 1, .query_count = 2 };

test "PCS graph cache leases survive eviction and owner destruction" {
    const allocator = std.testing.allocator;
    var cache = Cache.init(allocator, 1 << 20);
    var first = try cache.acquire(test_profile);
    defer first.deinit();
    var hit = try cache.acquire(test_profile);
    defer hit.deinit();
    try std.testing.expect(first.handle == hit.handle);
    var changed = test_profile;
    changed.query_count = 3;
    var second = try cache.acquire(changed);
    defer second.deinit();
    changed.query_count = 4;
    var third = try cache.acquire(changed);
    defer third.deinit();
    try std.testing.expect(cache.retained_bytes <= cache.byte_budget);
    try std.testing.expectEqual(@as(usize, 1), cache.hits);
    cache.deinit();
    try first.validate();
    var evaluated = try first.evaluateInactive(allocator);
    defer evaluated.deinit();
    try first.validateEvaluation(&evaluated);
    var reference = try Prepared.init(allocator, test_profile);
    defer reference.deinit();
    try std.testing.expectEqualDeep(reference.view(), first.view());
    try second.validate();
    try third.validate();
}

test "PCS graph cache compares complete ordered profiles and disables at zero bytes" {
    var cache = Cache.init(std.testing.allocator, 1 << 20);
    defer cache.deinit();
    var original = try cache.acquire(test_profile);
    defer original.deinit();
    var changed = test_profile;
    changed.sample_layouts = &.{.previous_current};
    var reordered = try cache.acquire(changed);
    defer reordered.deinit();
    try std.testing.expect(original.handle != reordered.handle);
    try std.testing.expect(!equalProfiles(test_profile, changed));
    changed = test_profile;
    changed.trees = &.{.{ .column_log_sizes = &.{2} }};
    try std.testing.expect(!equalProfiles(test_profile, changed));
    changed = test_profile;
    changed.log_blowup_factor = 2;
    try std.testing.expect(!equalProfiles(test_profile, changed));
    changed = test_profile;
    changed.lifting_log_size = 5;
    try std.testing.expect(!equalProfiles(test_profile, changed));
    var disabled = Cache.init(std.testing.allocator, 0);
    defer disabled.deinit();
    var a = try disabled.acquire(test_profile);
    defer a.deinit();
    var b = try disabled.acquire(test_profile);
    defer b.deinit();
    try std.testing.expect(a.handle != b.handle);
    try std.testing.expectEqual(@as(usize, 0), disabled.retained_bytes);
    try std.testing.expectEqual(@as(usize, 2), disabled.builds);
}

test "PCS graph cache constructor allocation failures release all owners" {
    const Test = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var cache = Cache.init(allocator, 1 << 20);
            defer cache.deinit();
            var plan = try cache.acquire(test_profile);
            defer plan.deinit();
            var other = test_profile;
            other.query_count = 3;
            var lease = try cache.acquire(other);
            defer lease.deinit();
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Test.run, .{});
}
