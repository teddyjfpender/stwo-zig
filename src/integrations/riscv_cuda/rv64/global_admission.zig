//! One capacity ledger per physical GPU, shared by native/recursion/GKR owners.
//! Costs describe actual allocations, including retirement until physical free.
//! A future-workspace claim preserves progress headroom while its source lives.
//! This module never grows the arena, chooses a proof profile or waits on a GPU.
const std = @import("std");
pub const chunk_bytes: u64 = 32 << 20;
pub const small_slab_bytes: u64 = 512 << 20;
pub const small_threshold: u64 = 4 << 20;
pub const small_alignment: u64 = 512;
pub const external_budget: u64 = 4 << 30;
pub const physical_limit: u64 = 28_000_000_000;
pub const Preset = enum(u8) {
    g16 = 16,
    g18 = 18,
    g20 = 20,
    g22 = 22,
    pub fn arenaBytes(self: Preset) u64 {
        return @as(u64, @intFromEnum(self)) << 30;
    }
    pub fn parse(text: []const u8) !Preset {
        inline for (std.meta.fields(Preset)) |f| {
            const p: Preset = @enumFromInt(f.value);
            if (std.mem.eql(u8, text, std.fmt.comptimePrint("{d}G", .{f.value}))) return p;
        }
        return error.StaticArenaPresetRequired;
    }
};
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
    pub fn allocations(sizes: []const u64) !Footprint {
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
pub const Owner = struct { request: u64, domain: Domain, ordinal: u32 };
pub const Demand = struct {
    owner: Owner,
    stage: Stage,
    /// New allocations that remain after this stage. Existing live owners are
    /// already charged by their tokens; do not count them here a second time.
    retained_new: Footprint = .{},
    /// Additional simultaneous temporary allocations, INCLUDING decoded input,
    /// metadata, twiddles and all workspace, separately rounded per allocation.
    temporary: Footprint = .{},
    /// Largest successor scratch envelope while this new retained owner lives.
    /// This is max-combined, because wide stages serialize on this physical GPU.
    successor: Footprint = .{},
    known: bool = false,
};
pub const Token = struct { physical: u32, id: u64 };
pub const Reason = enum { admitted, wide_stage_busy, capacity_pressure, request_exceeds_static_arena, unknown_cost };
pub const Decision = struct { reason: Reason, token: ?Token = null, required: Footprint = .{}, capacity: Footprint };
pub const Snapshot = struct { physical: u32, retained: Footprint, active_temporary: Footprint, successor: Footprint, required: Footprint, capacity: Footprint, owners: usize, active: bool };
const Entry = struct { demand: Demand, active: bool };
const Device = struct { physical: u32, entries: std.AutoHashMapUnmanaged(u64, Entry) = .{}, active: ?u64 = null };
pub const Planner = struct {
    allocator: std.mem.Allocator,
    preset: Preset,
    devices: []Device,
    mutex: std.Thread.Mutex = .{},
    next_id: u64 = 1,
    pub fn init(a: std.mem.Allocator, ids: []const u32, preset: Preset) !Planner {
        if (ids.len == 0 or preset.arenaBytes() + external_budget > physical_limit) return error.InvalidStaticArena;
        const devices = try a.alloc(Device, ids.len);
        errdefer a.free(devices);
        for (ids, 0..) |id, i| {
            for (ids[0..i]) |prior| if (prior == id) return error.DuplicatePhysicalGpu;
            devices[i] = .{ .physical = id };
        }
        return .{ .allocator = a, .preset = preset, .devices = devices };
    }
    pub fn deinit(self: *Planner) void {
        for (self.devices) |*d| {
            std.debug.assert(d.entries.count() == 0);
            d.entries.deinit(self.allocator);
        }
        self.allocator.free(self.devices);
        self.* = undefined;
    }
    fn device(self: *Planner, physical: u32) !*Device {
        for (self.devices) |*d| if (d.physical == physical) return d;
        return error.UnknownPhysicalGpu;
    }
    pub fn capacity(self: *const Planner) Footprint {
        return .{ .large = self.preset.arenaBytes() - small_slab_bytes, .small = small_slab_bytes };
    }
    fn collect(self: *const Planner, d: *const Device) !Snapshot {
        var retained: Footprint = .{};
        var temporary: Footprint = .{};
        var successor: Footprint = .{};
        var it = d.entries.valueIterator();
        while (it.next()) |entry| {
            retained = try retained.add(entry.demand.retained_new);
            successor = successor.max(entry.demand.successor);
            if (entry.active) temporary = try temporary.add(entry.demand.temporary);
        }
        return .{ .physical = d.physical, .retained = retained, .active_temporary = temporary, .successor = successor, .required = try retained.add(temporary.max(successor)), .capacity = self.capacity(), .owners = d.entries.count(), .active = d.active != null };
    }
    pub fn snapshot(self: *Planner, physical: u32) !Snapshot {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.collect(try self.device(physical));
    }
    /// Nonblocking. The scheduler retries after a retirement; NEVER wait inside
    /// a GPU owner callback. No reservation means no device mutation is allowed.
    pub fn tryBegin(self: *Planner, physical: u32, demand: Demand) !Decision {
        self.mutex.lock();
        defer self.mutex.unlock();
        const d = try self.device(physical);
        const cap = self.capacity();
        if (!demand.known) return .{ .reason = .unknown_cost, .capacity = cap };
        const alone = try demand.retained_new.add(demand.temporary.max(demand.successor));
        if (!cap.contains(alone)) return .{ .reason = .request_exceeds_static_arena, .required = alone, .capacity = cap };
        const live = try self.collect(d);
        const required = try (try live.retained.add(demand.retained_new)).add(live.successor.max(demand.temporary).max(demand.successor));
        if (d.active != null) return .{ .reason = .wide_stage_busy, .required = required, .capacity = cap };
        if (!cap.contains(required)) return .{ .reason = .capacity_pressure, .required = required, .capacity = cap };
        const id = self.next_id;
        self.next_id = try std.math.add(u64, self.next_id, 1);
        try d.entries.putNoClobber(self.allocator, id, .{ .demand = demand, .active = true });
        d.active = id;
        return .{ .reason = .admitted, .token = .{ .physical = physical, .id = id }, .required = required, .capacity = cap };
    }
    /// Call only after temporary allocations are actually freed AND joined.
    /// Committed retention includes retired coefficient owners and cache owners.
    pub fn complete(self: *Planner, token: Token, retained: Footprint, successor: Footprint) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const d = try self.device(token.physical);
        const entry = d.entries.getPtr(token.id) orelse return error.StaleAdmissionToken;
        if (d.active != token.id or !entry.active) return error.AdmissionNotActive;
        if (!entry.demand.retained_new.contains(retained) or !entry.demand.successor.contains(successor)) return error.UnreservedRetention;
        d.active = null;
        if (retained.large == 0 and retained.small == 0 and successor.large == 0 and successor.small == 0) {
            _ = d.entries.remove(token.id);
            return;
        }
        entry.demand.retained_new = retained;
        entry.demand.temporary = .{};
        entry.demand.successor = successor;
        entry.active = false;
    }
    /// Retirement acknowledgement comes from actual last-owner destruction,
    /// never from logical scope end while native buffers remain pinned.
    pub fn release(self: *Planner, token: Token) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const d = try self.device(token.physical);
        const entry = d.entries.get(token.id) orelse return error.StaleAdmissionToken;
        if (entry.active) return error.AdmissionStillActive;
        _ = d.entries.remove(token.id);
    }
    /// A physical arena snapshot must include ALL contexts and retired owners.
    /// This rejects incomplete accounting; it does not silently adopt zero cost.
    pub fn assertCoversActual(self: *Planner, physical: u32, actual: Footprint) !void {
        const s = try self.snapshot(physical);
        const allocated = try s.retained.add(s.active_temporary);
        if (!allocated.contains(actual)) return error.UntrackedDeviceAllocation;
    }
};
const test_owner = Owner{ .request = 1, .domain = .native_packet, .ordinal = 0 };
test "native retention cannot consume the GKR successor headroom" {
    var p = try Planner.init(std.testing.allocator, &.{ 0, 1 }, .g22);
    defer p.deinit();
    const keep = try Footprint.allocation(6 << 30);
    const future = try Footprint.allocation(15 << 30);
    const first = try p.tryBegin(0, .{ .owner = test_owner, .known = true, .stage = .witness, .retained_new = keep, .successor = future });
    try std.testing.expectEqual(Reason.admitted, first.reason);
    try p.complete(first.token.?, keep, future);
    const second = try p.tryBegin(0, .{ .owner = test_owner, .known = true, .stage = .witness, .retained_new = try Footprint.allocation(1 << 30), .successor = future });
    try std.testing.expectEqual(Reason.capacity_pressure, second.reason);
    const consumer = try p.tryBegin(0, .{ .owner = test_owner, .known = true, .stage = .gkr, .temporary = future });
    try std.testing.expectEqual(Reason.admitted, consumer.reason);
    try p.complete(consumer.token.?, .{}, .{});
    try p.release(first.token.?);
}
test "physical devices independent; active and stale tickets fail closed" {
    var p = try Planner.init(std.testing.allocator, &.{ 0, 1 }, .g22);
    defer p.deinit();
    const a = try p.tryBegin(0, .{ .owner = test_owner, .known = true, .stage = .pcs, .temporary = try Footprint.allocation(1 << 30) });
    try std.testing.expectEqual(Reason.wide_stage_busy, (try p.tryBegin(0, .{ .owner = test_owner, .known = true, .stage = .gkr })).reason);
    const b = try p.tryBegin(1, .{ .owner = test_owner, .known = true, .stage = .gkr });
    try p.complete(b.token.?, .{}, .{});
    try std.testing.expectError(error.AdmissionStillActive, p.release(a.token.?));
    try p.complete(a.token.?, .{}, .{});
    try std.testing.expectError(error.StaleAdmissionToken, p.complete(a.token.?, .{}, .{}));
}
test "unknown costs, physical rounding, small slab and untracked owners" {
    var p = try Planner.init(std.testing.allocator, &.{0}, .g22);
    defer p.deinit();
    try std.testing.expectEqual(Reason.unknown_cost, (try p.tryBegin(0, .{ .owner = test_owner, .stage = .gkr, .known = false })).reason);
    try std.testing.expectEqual(@as(u64, chunk_bytes), (try Footprint.allocation(small_threshold)).large);
    try std.testing.expectEqual(@as(u64, 512), (try Footprint.allocation(1)).small);
    try std.testing.expectError(error.UntrackedDeviceAllocation, p.assertCoversActual(0, .{ .large = chunk_bytes }));
    try std.testing.expectEqual(Reason.request_exceeds_static_arena, (try p.tryBegin(0, .{ .owner = test_owner, .known = true, .stage = .gkr, .temporary = .{ .small = small_slab_bytes + 512 } })).reason);
    try std.testing.expectError(error.StaticArenaPresetRequired, Preset.parse("1"));
}
