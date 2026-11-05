//! Request-local, source-owned downstream envelopes. MAIN rebind changes no
//! key: statement/fixed/ordinal remain independently authenticated. The caller
//! registers the whole class before allocating its first witness; a missing or
//! conflicting class refuses admission rather than guessing zero headroom.
const std = @import("std");
const A = @import("global_admission.zig");
pub const Step = enum { source, main_commit, native_gkr, interaction, inter_commit, composition, pcs };
pub const Key = A.ProgressKey;
pub const Phase = enum { pre_global, post_global };
pub const After = [std.meta.fields(Step).len]A.Footprint;
pub const Plan = struct {
    identity: [32]u8,
    gpu_costs_known: bool,
    /// Additional retained+temporary consumer envelope, independently rounded
    /// and max-composed across future stages while this scope remains alive.
    after: After,
    /// Native stage one cannot consume globally challenged phases until the
    /// complete ordered manifest exists. Outer classes default to full mode.
    pre_global_after: ?After = null,
};
pub const Registry = struct {
    const Entry = struct { plan: Plan, phase: Phase, drain_pending: bool = false };
    mutex: std.Thread.Mutex = .{},
    entries: std.AutoHashMapUnmanaged(Key, Entry) = .empty,
    pub fn put(self: *Registry, allocator: std.mem.Allocator, key: Key, plan: Plan) !void {
        if (!plan.gpu_costs_known or std.mem.allEqual(u8, &plan.identity, 0) or std.mem.allEqual(u8, &key.statement, 0) or std.mem.allEqual(u8, &key.fixed, 0)) return error.GpuClassProgressUnavailable;
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.entries.get(key)) |old| {
            if (!std.meta.eql(old.plan, plan)) return error.GpuClassProgressChanged;
            return;
        }
        try self.entries.putNoClobber(allocator, key, .{ .plan = plan, .phase = if (plan.pre_global_after != null) .pre_global else .post_global });
    }
    pub fn get(self: *Registry, key: Key, step: Step) !A.Footprint {
        self.mutex.lock();
        defer self.mutex.unlock();
        const entry = self.entries.get(key) orelse return error.GpuClassProgressUnavailable;
        if (entry.phase == .pre_global) {
            switch (step) {
                .interaction, .inter_commit, .composition, .pcs => return error.GlobalChallengePhaseRequired,
                else => {},
            }
            return entry.plan.pre_global_after.?[@intFromEnum(step)];
        }
        return entry.plan.after[@intFromEnum(step)];
    }
    pub fn phase(self: *Registry, key: Key) !Phase {
        self.mutex.lock();
        defer self.mutex.unlock();
        return (self.entries.get(key) orelse return error.GpuClassProgressUnavailable).phase;
    }
    /// Host eligibility only: no physical bytes or planner promises are freed
    /// or installed here. The first post-global stage reserves atomically.
    pub fn armGlobal(self: *Registry, key: Key) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const entry = self.entries.getPtr(key) orelse return error.GpuClassProgressUnavailable;
        const changed = entry.phase == .pre_global;
        entry.phase = .post_global;
        if (changed) entry.drain_pending = true;
        return changed;
    }
    pub fn takeGlobalDrain(self: *Registry, key: Key) !bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const entry = self.entries.getPtr(key) orelse return error.GpuClassProgressUnavailable;
        const pending = entry.drain_pending;
        entry.drain_pending = false;
        return pending;
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

test "native global futures arm lazily and never reopen or overwrite the class" {
    const a = std.testing.allocator;
    var registry = Registry{};
    defer registry.deinit(a);
    const key = Key{ .statement = @splat(1), .fixed = @splat(2), .ordinal = 0 };
    var full: After = @splat(.{});
    full[@intFromEnum(Step.main_commit)] = try A.Footprint.allocation(19 << 30);
    full[@intFromEnum(Step.interaction)] = try A.Footprint.allocation(12 << 30);
    const pre: After = @splat(.{});
    const plan = Plan{ .identity = @splat(3), .gpu_costs_known = true, .after = full, .pre_global_after = pre };
    try registry.put(a, key, plan);
    try std.testing.expectEqual(Phase.pre_global, try registry.phase(key));
    try std.testing.expectEqual(A.Footprint{}, try registry.get(key, .main_commit));
    try std.testing.expectError(error.GlobalChallengePhaseRequired, registry.get(key, .interaction));
    try std.testing.expect(!try registry.takeGlobalDrain(key));
    try std.testing.expect(try registry.armGlobal(key));
    try std.testing.expect(try registry.takeGlobalDrain(key));
    try std.testing.expect(!try registry.takeGlobalDrain(key));
    try registry.put(a, key, plan);
    try std.testing.expectEqual(Phase.post_global, try registry.phase(key));
    try std.testing.expectEqual(full[@intFromEnum(Step.interaction)], try registry.get(key, .interaction));
    try std.testing.expect(!try registry.armGlobal(key));
    try std.testing.expect(!try registry.takeGlobalDrain(key));
}

test "parked truth cannot reserve an ineligible 19GiB future and block the global barrier" {
    const a = std.testing.allocator;
    var planner = try A.Planner.init(a, &.{0}, .g22);
    defer planner.deinit();
    const truth_key = Key{ .statement = @splat(1), .fixed = @splat(2), .ordinal = 4 };
    const truth_owner = A.Owner{ .request = 1, .domain = .native_packet, .ordinal = 4 };
    const cpu_owner = A.Owner{ .request = 2, .domain = .native_packet, .ordinal = 0 };
    const actual_truth = try A.Footprint.allocation(2 << 30);
    const stale_future = try A.Footprint.allocation(19 << 30);
    const truth = (try planner.tryBegin(0, .{ .owner = truth_owner, .progress_key = truth_key, .known = true, .host_known = true, .stage = .witness, .retained_new = actual_truth, .successor = stale_future })).token.?;
    try planner.complete(truth, actual_truth, stale_future);
    const next_cpu = A.Demand{ .owner = cpu_owner, .known = true, .host_known = true, .stage = .witness, .retained_new = try A.Footprint.allocation(5 << 30) };
    try std.testing.expectEqual(A.Reason.capacity_pressure, (try planner.tryBegin(0, next_cpu)).reason);
    const before = try planner.snapshot(0);
    // The parked phase advances this scope's future promise only. Its actual
    // physical truth retention remains charged until checked destruction.
    const parked = (try planner.tryBegin(0, .{ .owner = truth_owner, .progress_key = truth_key, .known = true, .host_known = true, .stage = .retire })).token.?;
    try planner.complete(parked, .{}, .{});
    const after = try planner.snapshot(0);
    try std.testing.expectEqual(before.retained, after.retained);
    try std.testing.expectEqual(actual_truth, after.retained);
    try std.testing.expectEqual(A.Footprint{}, after.successor);
    const cpu = try planner.tryBegin(0, next_cpu);
    try std.testing.expectEqual(A.Reason.admitted, cpu.reason);
    try planner.complete(cpu.token.?, .{}, .{});
    try planner.release(truth);
}
