//! Request-local, source-owned downstream envelopes. MAIN rebind changes no
//! key: statement/fixed/ordinal remain independently authenticated. The caller
//! registers the whole class before allocating its first witness; a missing or
//! conflicting class refuses admission rather than guessing zero headroom.
const std = @import("std");
const A = @import("global_admission.zig");
pub const Step = enum { source, main_commit, native_gkr, interaction, inter_commit, composition, pcs };
pub const Key = A.ProgressKey;
pub const Plan = struct {
    identity: [32]u8,
    gpu_costs_known: bool,
    /// Additional retained+temporary consumer envelope, independently rounded
    /// and max-composed across future stages while this scope remains alive.
    after: [std.meta.fields(Step).len]A.Footprint,
};
pub const Registry = struct {
    mutex: std.Thread.Mutex = .{},
    entries: std.AutoHashMapUnmanaged(Key, Plan) = .empty,
    pub fn put(self: *Registry, allocator: std.mem.Allocator, key: Key, plan: Plan) !void {
        if (!plan.gpu_costs_known or std.mem.allEqual(u8, &plan.identity, 0) or std.mem.allEqual(u8, &key.statement, 0) or std.mem.allEqual(u8, &key.fixed, 0)) return error.GpuClassProgressUnavailable;
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.entries.get(key)) |old| {
            if (!std.meta.eql(old, plan)) return error.GpuClassProgressChanged;
            return;
        }
        try self.entries.putNoClobber(allocator, key, plan);
    }
    pub fn get(self: *Registry, key: Key, step: Step) !A.Footprint {
        self.mutex.lock();
        defer self.mutex.unlock();
        const plan = self.entries.get(key) orelse return error.GpuClassProgressUnavailable;
        return plan.after[@intFromEnum(step)];
    }
    pub fn clear(self: *Registry) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.entries.clearRetainingCapacity();
    }
    pub fn deinit(self: *Registry, allocator: std.mem.Allocator) void {
        self.entries.deinit(allocator);
    }
};
test "class envelopes refuse unknown conflicting and foreign scope plans" {
    const a = std.testing.allocator;
    var registry = Registry{};
    defer registry.deinit(a);
    const key = Key{ .statement = @splat(1), .fixed = @splat(2), .ordinal = 3 };
    var plan = Plan{ .identity = @splat(4), .gpu_costs_known = true, .after = @splat(.{ .large = A.chunk_bytes, .small = 512 }) };
    try std.testing.expectError(error.GpuClassProgressUnavailable, registry.get(key, .main_commit));
    try registry.put(a, key, plan);
    try registry.put(a, key, plan);
    try std.testing.expectEqual(plan.after[1], try registry.get(key, .main_commit));
    plan.after[1].large += A.chunk_bytes;
    try std.testing.expectError(error.GpuClassProgressChanged, registry.put(a, key, plan));
    var foreign = key;
    foreign.ordinal += 1;
    try std.testing.expectError(error.GpuClassProgressUnavailable, registry.get(foreign, .pcs));
    plan.gpu_costs_known = false;
    try std.testing.expectError(error.GpuClassProgressUnavailable, registry.put(a, foreign, plan));
    registry.clear();
    try std.testing.expectError(error.GpuClassProgressUnavailable, registry.get(key, .main_commit));
}
