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
pub const Coverage = enum { native_source, native_trace, native_interaction, native_composition, native_pcs, native_gkr, recursion_source, recursion_trace, recursion_interaction, recursion_composition, recursion_pcs, outer_gkr, immutable, retirement, host_preparation };
pub const coverage_all: u64 = (1 << std.meta.fields(Coverage).len) - 1;
pub const coverage_gpu: u64 = coverage_all & ~(@as(u64, 1) << @intFromEnum(Coverage.host_preparation));
/// GPU overlap needs complete GPU envelopes. Host/RSS qualification is a
/// separate capability; observe_only never relabels an unknown host estimate.
pub const HostPolicy = enum { require_bounds, observe_only };
pub const Domain = enum { immutable_setup, native_packet, recursion_node, gkr_packet };
pub const Stage = enum { setup, witness, trace_commit, interaction, composition, pcs, gkr, retire };
pub const Owner = struct { request: u64, domain: Domain, ordinal: u32 };
pub const ProgressKey = struct { statement: [32]u8, fixed: [32]u8, ordinal: u32 };
pub fn progressKey(scope: anytype) ProgressKey {
    return .{ .statement = scope.statement, .fixed = scope.fixed, .ordinal = scope.ordinal };
}
pub const Demand = struct {
    owner: Owner,
    /// Stable logical proof identity; MAIN-root rebind does not change it.
    /// Advancing its source-owned class plan replaces older FUTURE promises,
    /// while observed physical retention and retirement tokens remain intact.
    progress_key: ?ProgressKey = null,
    stage: Stage,
    /// New allocations that remain after this stage. Existing live owners are
    /// already charged by their tokens; do not count them here a second time.
    retained_new: Footprint = .{},
    /// Observed-runtime mode keeps retained_new=0. This bound reserves the
    /// stage's NEW retained allocations beside its downstream envelope before
    /// launch; actual retention is still counted only by the joined snapshot.
    stage_retained_upper: Footprint = .{},
    /// Additional simultaneous temporary allocations, INCLUDING decoded input,
    /// metadata, twiddles and all workspace, separately rounded per allocation.
    temporary: Footprint = .{},
    /// Whole successor envelope while this owner lives: consumer retained_new
    /// PLUS its maximum subsequent scratch; not scratch alone.
    /// This is max-combined, because wide stages serialize on this physical GPU.
    successor: Footprint = .{},
    known: bool = false,
    host_peak_bytes: u64 = 0,
    host_known: bool = false,
};
pub const Token = struct { physical: u32, id: u64 };
pub const Reason = enum { admitted, wide_stage_busy, capacity_pressure, request_exceeds_static_arena, unknown_cost, host_capacity_pressure, runtime_poisoned };
pub const Decision = struct { reason: Reason, token: ?Token = null, required: Footprint = .{}, capacity: Footprint };
pub const Snapshot = struct { physical: u32, retained: Footprint, active_temporary: Footprint, successor: Footprint, required: Footprint, capacity: Footprint, owners: usize, active: bool };
const Entry = struct { demand: Demand, active: bool, entered: bool = false };
const Device = struct { physical: u32, entries: std.AutoHashMapUnmanaged(u64, Entry) = .{}, active: ?u64 = null, observed: Footprint = .{}, observed_initialized: bool = false, runtime_configured: bool = false, poisoned: bool = false, coverage: u64 = 0, stage_gate: std.Thread.Mutex = .{} };
pub const Planner = struct {
    allocator: std.mem.Allocator,
    preset: Preset,
    devices: []Device,
    mutex: std.Thread.Mutex = .{},
    next_id: u64 = 1,
    generation: u64 = 0,
    changed: std.Thread.Condition = .{},
    required_coverage: u64 = coverage_all,
    host_capacity_bytes: u64 = 20 << 30,
    host_policy: HostPolicy = .require_bounds,
    observed_host_rss_bytes: u64 = 0,
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
    /// Terminal teardown only, after the pool has joined and destroyed EVERY
    /// native context on these physical GPUs. This is not a recovery/retry API.
    /// An interrupted active permit cannot complete, but its actual allocations
    /// have now been destroyed by the native context destructors.
    pub fn poolDestroyed(self: *Planner) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.devices) |*d| {
            d.entries.clearRetainingCapacity();
            d.active = null;
            d.observed = .{};
            d.runtime_configured = false;
            d.poisoned = true;
        }
        self.notifyLocked();
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
        return self.collectForProgress(d, null);
    }
    fn collectForProgress(self: *const Planner, d: *const Device, advancing: ?ProgressKey) !Snapshot {
        var retained: Footprint = d.observed;
        var temporary: Footprint = .{};
        var successor: Footprint = .{};
        var it = d.entries.valueIterator();
        while (it.next()) |entry| {
            retained = try retained.add(entry.demand.retained_new);
            const replaced = if (advancing) |key| if (entry.demand.progress_key) |old| std.meta.eql(key, old) else false else false;
            if (!replaced) successor = successor.max(entry.demand.successor);
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
        if (d.poisoned) return .{ .reason = .runtime_poisoned, .capacity = cap };
        if (!demand.known or (self.host_policy == .require_bounds and !demand.host_known)) return .{ .reason = .unknown_cost, .capacity = cap };
        var host_required = try std.math.add(u64, self.observed_host_rss_bytes, demand.host_peak_bytes);
        for (self.devices) |*other| {
            var iterator = other.entries.valueIterator();
            while (iterator.next()) |entry| if (entry.active) {
                host_required = try std.math.add(u64, host_required, entry.demand.host_peak_bytes);
            };
        }
        if (self.host_policy == .require_bounds and host_required > self.host_capacity_bytes) return .{ .reason = .host_capacity_pressure, .capacity = cap };
        const additional = demand.temporary.max(try demand.stage_retained_upper.add(demand.successor));
        const alone = try demand.retained_new.add(additional);
        if (!cap.contains(alone)) return .{ .reason = .request_exceeds_static_arena, .required = alone, .capacity = cap };
        const live = try self.collectForProgress(d, demand.progress_key);
        const next_and_other_progress = try demand.stage_retained_upper.add(live.successor.max(demand.successor));
        const required = try (try live.retained.add(demand.retained_new)).add(demand.temporary.max(next_and_other_progress));
        if (d.active != null) return .{ .reason = .wide_stage_busy, .required = required, .capacity = cap };
        if (!cap.contains(required)) return .{ .reason = .capacity_pressure, .required = required, .capacity = cap };
        const id = self.next_id;
        self.next_id = try std.math.add(u64, self.next_id, 1);
        try d.entries.putNoClobber(self.allocator, id, .{ .demand = demand, .active = true });
        // Reserve the advancing phase without discarding the previous
        // promise. An attempt may yield before ever entering its GPU owner.
        d.active = id;
        return .{ .reason = .admitted, .token = .{ .physical = physical, .id = id }, .required = required, .capacity = cap };
    }
    fn commitEnteredLocked(d: *Device, token: Token) !void {
        const entry = d.entries.getPtr(token.id) orelse return error.StaleAdmissionToken;
        if (d.active != token.id or !entry.active) return error.AdmissionNotActive;
        if (entry.entered) return;
        entry.entered = true;
        if (entry.demand.progress_key) |key| {
            var older = d.entries.valueIterator();
            while (older.next()) |old| if (!old.active) {
                if (old.demand.progress_key) |previous| {
                    if (std.meta.eql(key, previous)) old.demand.successor = .{};
                }
            };
        }
    }
    /// Commit phase replacement only after successful physical owner entry.
    /// No allocation occurs here and old physical owners retain their tokens.
    pub fn commitEntered(self: *Planner, token: Token) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        try commitEnteredLocked(try self.device(token.physical), token);
    }
    /// No owner mutation happened. Remove this attempt alone: old promises and
    /// observed physical retention are exactly unchanged, including busy retry.
    pub fn cancelUnentered(self: *Planner, token: Token) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const d = try self.device(token.physical);
        const entry = d.entries.get(token.id) orelse return error.StaleAdmissionToken;
        if (d.active != token.id or !entry.active) return error.AdmissionNotActive;
        if (entry.entered) return error.AdmissionOwnerAlreadyEntered;
        _ = d.entries.remove(token.id);
        d.active = null;
        self.notifyLocked();
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
        // Direct model callers attest completed work here. Runtime unentered
        // attempts use cancelUnentered instead, preserving the old promise.
        try commitEnteredLocked(d, token);
        d.active = null;
        self.notifyLocked();
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
        self.notifyLocked();
    }
    /// A physical arena snapshot must include ALL contexts and retired owners.
    /// This rejects incomplete accounting; it does not silently adopt zero cost.
    pub fn assertCoversActual(self: *Planner, physical: u32, actual: Footprint) !void {
        const s = try self.snapshot(physical);
        const allocated = try s.retained.add(s.active_temporary);
        if (!allocated.contains(actual)) return error.UntrackedDeviceAllocation;
    }
    fn notifyLocked(self: *Planner) void {
        self.generation +%= 1;
        self.changed.broadcast();
    }
    pub fn epoch(self: *Planner) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.generation;
    }
    /// Host scheduler only: caller holds NO owner/phase/cache lock.
    pub fn waitForChange(self: *Planner, previous: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (self.generation == previous) self.changed.wait(&self.mutex);
    }
    /// Capacity wait with a no-progress bound. Spurious condition wakeups do
    /// not renew the deadline; an actual ledger generation change does.
    pub fn waitForChangeWithin(self: *Planner, previous: u64, timeout_ns: u64) !bool {
        var timer = try std.time.Timer.start();
        self.mutex.lock();
        defer self.mutex.unlock();
        while (self.generation == previous) {
            const remaining = timeout_ns -| timer.read();
            if (remaining == 0) return false;
            self.changed.timedWait(&self.mutex, remaining) catch |err| switch (err) {
                error.Timeout => return self.generation != previous,
            };
        }
        return true;
    }
    pub fn notifyResourceRelease(self: *Planner) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.notifyLocked();
    }
    pub fn poisonPhysical(self: *Planner, physical: u32) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const d = self.device(physical) catch return;
        d.poisoned = true;
        self.notifyLocked();
    }
    pub fn healthy(self: *Planner, physical: u32) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        const d = self.device(physical) catch return false;
        return !d.poisoned;
    }
    pub fn registerCoverage(self: *Planner, physical: u32, actor: Coverage) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        (try self.device(physical)).coverage |= @as(u64, 1) << @intFromEnum(actor);
    }
    pub fn schedulingEnabled(self: *Planner) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.devices) |d| if (!d.runtime_configured or d.poisoned or d.coverage & self.required_coverage != self.required_coverage) return false;
        return true;
    }
    pub fn observeHostRss(self: *Planner, bytes: u64) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.observed_host_rss_bytes = bytes;
    }
    pub fn stageGate(self: *Planner, physical: u32) !*std.Thread.Mutex {
        return &(try self.device(physical)).stage_gate;
    }
    pub fn allConfigured(self: *Planner) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.devices) |d| if (!d.runtime_configured or d.poisoned) return false;
        return true;
    }
    pub fn markConfigured(self: *Planner, physical: u32) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        (try self.device(physical)).runtime_configured = true;
    }
    /// Called under the external physical stage gate. Actual global retained
    /// bytes are observed once, not separately charged per session/alias.
    pub fn observeIdle(self: *Planner, physical: u32, actual: Footprint) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const d = try self.device(physical);
        if (d.active != null) return error.AdmissionStillActive;
        var it = d.entries.valueIterator();
        while (it.next()) |e| if (e.demand.retained_new.large != 0 or e.demand.retained_new.small != 0) return error.MixedAdmissionAccounting;
        if (!d.observed_initialized) {
            if (actual.large != 0 or actual.small != 0) return error.UntrackedDeviceAllocation;
            d.observed_initialized = true;
        } else if (!d.observed.contains(actual)) return error.UntrackedDeviceAllocation;
        d.observed = actual;
    }
    pub fn completeObserved(self: *Planner, token: Token, actual: Footprint, successor: Footprint) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        const d = try self.device(token.physical);
        const e = d.entries.getPtr(token.id) orelse return error.StaleAdmissionToken;
        if (d.active != token.id or !e.active) return error.AdmissionNotActive;
        if (e.demand.retained_new.large != 0 or e.demand.retained_new.small != 0) return error.MixedAdmissionAccounting;
        const envelope = try d.observed.add(e.demand.temporary);
        if (!envelope.contains(actual)) return error.UnreservedRetention;
        if (!e.demand.successor.contains(successor)) return error.UnreservedRetention;
        try commitEnteredLocked(d, token);
        d.observed = actual;
        d.observed_initialized = true;
        d.active = null;
        self.notifyLocked();
        if (successor.large == 0 and successor.small == 0) {
            _ = d.entries.remove(token.id);
            return;
        }
        e.demand.temporary = .{};
        e.demand.successor = successor;
        e.active = false;
    }
};
const test_owner = Owner{ .request = 1, .domain = .native_packet, .ordinal = 0 };
test "native retention cannot consume the GKR successor headroom" {
    var p = try Planner.init(std.testing.allocator, &.{ 0, 1 }, .g22);
    defer p.deinit();
    const keep = try Footprint.allocation(6 << 30);
    const future = try Footprint.allocation(15 << 30);
    const first = try p.tryBegin(0, .{ .owner = test_owner, .known = true, .host_known = true, .stage = .witness, .retained_new = keep, .successor = future });
    try std.testing.expectEqual(Reason.admitted, first.reason);
    try p.complete(first.token.?, keep, future);
    const second = try p.tryBegin(0, .{ .owner = test_owner, .known = true, .host_known = true, .stage = .witness, .retained_new = try Footprint.allocation(1 << 30), .successor = future });
    try std.testing.expectEqual(Reason.capacity_pressure, second.reason);
    const consumer = try p.tryBegin(0, .{ .owner = test_owner, .known = true, .host_known = true, .stage = .gkr, .temporary = future });
    try std.testing.expectEqual(Reason.admitted, consumer.reason);
    try p.complete(consumer.token.?, .{}, .{});
    try p.release(first.token.?);
}
test "physical devices independent; active and stale tickets fail closed" {
    var p = try Planner.init(std.testing.allocator, &.{ 0, 1 }, .g22);
    defer p.deinit();
    const a = try p.tryBegin(0, .{ .owner = test_owner, .known = true, .host_known = true, .stage = .pcs, .temporary = try Footprint.allocation(1 << 30) });
    try std.testing.expectEqual(Reason.wide_stage_busy, (try p.tryBegin(0, .{ .owner = test_owner, .known = true, .host_known = true, .stage = .gkr })).reason);
    const b = try p.tryBegin(1, .{ .owner = test_owner, .known = true, .host_known = true, .stage = .gkr });
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
    try std.testing.expectEqual(Reason.request_exceeds_static_arena, (try p.tryBegin(0, .{ .owner = test_owner, .known = true, .host_known = true, .stage = .gkr, .temporary = .{ .small = small_slab_bytes + 512 } })).reason);
    try std.testing.expectError(error.StaticArenaPresetRequired, Preset.parse("1"));
}

test "host frontier charged globally and unavailable costs refused" {
    var p = try Planner.init(std.testing.allocator, &.{ 0, 1 }, .g22);
    defer p.deinit();
    p.observeHostRss(8 << 30);
    const d = try p.tryBegin(0, .{ .owner = test_owner, .stage = .gkr, .known = true, .host_known = true, .host_peak_bytes = 16 << 30 });
    try std.testing.expectEqual(Reason.host_capacity_pressure, d.reason);
    try std.testing.expectEqual(Reason.unknown_cost, (try p.tryBegin(0, .{ .owner = test_owner, .stage = .gkr, .known = true })).reason);
}

test "native usize allocation list uses exact arena bucket charges" {
    const sizes: []const usize = &.{ 1, 4 << 20 };
    const fp = try Footprint.allocations(sizes);
    try std.testing.expectEqual(@as(u64, 512), fp.small);
    try std.testing.expectEqual(chunk_bytes, fp.large);
}

test "terminal pool destruction retires interrupted claims only after actual owner teardown" {
    var p = try Planner.init(std.testing.allocator, &.{0}, .g22);
    defer p.deinit();
    _ = try p.tryBegin(0, .{ .owner = test_owner, .known = true, .host_known = true, .stage = .witness, .temporary = try Footprint.allocation(1 << 30) });
    p.poisonPhysical(0);
    try std.testing.expectEqual(@as(usize, 1), (try p.snapshot(0)).owners);
    // The caller here models successful destruction of all native contexts.
    p.poolDestroyed();
    try std.testing.expectEqual(@as(usize, 0), (try p.snapshot(0)).owners);
    try std.testing.expect(!p.healthy(0));
    try std.testing.expect(!p.schedulingEnabled());
}

test "GPU-only admission preserves unknown host status and all GPU refusal gates" {
    var p = try Planner.init(std.testing.allocator, &.{0}, .g22);
    defer p.deinit();
    p.host_policy = .observe_only;
    p.required_coverage = coverage_gpu;
    p.observeHostRss(p.host_capacity_bytes + 1);
    try std.testing.expectEqual(Reason.unknown_cost, (try p.tryBegin(0, .{ .owner = test_owner, .stage = .trace_commit })).reason);
    const demand = Demand{ .owner = test_owner, .stage = .trace_commit, .known = true, .host_known = false, .temporary = try Footprint.allocation(4 << 20) };
    const decision = try p.tryBegin(0, demand);
    try std.testing.expectEqual(Reason.admitted, decision.reason);
    try std.testing.expect(!p.devices[0].entries.get(decision.token.?.id).?.demand.host_known);
    try p.complete(decision.token.?, .{}, .{});
    var oversized = demand;
    oversized.temporary.large = p.capacity().large + chunk_bytes;
    try std.testing.expectEqual(Reason.request_exceeds_static_arena, (try p.tryBegin(0, oversized)).reason);
    try p.markConfigured(0);
    inline for (std.meta.fields(Coverage)) |field| {
        if (field.value != @intFromEnum(Coverage.host_preparation)) try p.registerCoverage(0, @enumFromInt(field.value));
    }
    try std.testing.expect(p.schedulingEnabled());
    p.required_coverage = coverage_all;
    try std.testing.expect(!p.schedulingEnabled());
}

test "phase advance replaces only its future promise and keeps physical owners charged" {
    var p = try Planner.init(std.testing.allocator, &.{0}, .g22);
    defer p.deinit();
    const key = ProgressKey{ .statement = @splat(1), .fixed = @splat(2), .ordinal = 3 };
    const first = (try p.tryBegin(0, .{ .owner = test_owner, .progress_key = key, .stage = .witness, .known = true, .host_known = true, .temporary = try Footprint.allocation(6 << 30), .stage_retained_upper = try Footprint.allocation(6 << 30), .successor = try Footprint.allocation(14 << 30) })).token.?;
    try p.completeObserved(first, try Footprint.allocation(6 << 30), try Footprint.allocation(14 << 30));
    var other_key = key;
    other_key.ordinal += 1;
    const other = try p.tryBegin(0, .{ .owner = test_owner, .progress_key = other_key, .stage = .witness, .known = true, .host_known = true, .temporary = try Footprint.allocation(2 << 30), .stage_retained_upper = try Footprint.allocation(2 << 30) });
    try std.testing.expectEqual(Reason.capacity_pressure, other.reason);
    try std.testing.expectEqual(try Footprint.allocation(14 << 30), p.devices[0].entries.get(first.id).?.demand.successor);
    // Later immutable/coeff owners grow, while this proof's remaining work is
    // now smaller. Its old14GiB promise must not block a valid8GiB next phase.
    const next = (try p.tryBegin(0, .{ .owner = test_owner, .progress_key = key, .stage = .trace_commit, .known = true, .host_known = true, .temporary = try Footprint.allocation(8 << 30), .stage_retained_upper = try Footprint.allocation(2 << 30), .successor = try Footprint.allocation(4 << 30) })).token.?;
    try std.testing.expectEqual(try Footprint.allocation(14 << 30), p.devices[0].entries.get(first.id).?.demand.successor);
    try p.commitEntered(next);
    try std.testing.expectEqual(Footprint{}, p.devices[0].entries.get(first.id).?.demand.successor);
    try p.completeObserved(next, try Footprint.allocation(8 << 30), try Footprint.allocation(4 << 30));
    const snapshot = try p.snapshot(0);
    try std.testing.expectEqual(try Footprint.allocation(8 << 30), snapshot.retained);
    try std.testing.expectEqual(try Footprint.allocation(4 << 30), snapshot.successor);
    // Old tokens stay valid until their physical owner's checked destruction.
    try p.release(first);
    try p.release(next);
}

test "observed stage reserves retained growth plus downstream progress before allocation" {
    var p = try Planner.init(std.testing.allocator, &.{0}, .g22);
    defer p.deinit();
    const result = try p.tryBegin(0, .{ .owner = test_owner, .stage = .witness, .known = true, .host_known = true, .temporary = try Footprint.allocation(5 << 30), .stage_retained_upper = try Footprint.allocation(5 << 30), .successor = try Footprint.allocation(18 << 30) });
    try std.testing.expectEqual(Reason.request_exceeds_static_arena, result.reason);
    try std.testing.expectEqual(@as(usize, 0), (try p.snapshot(0)).owners);
}

test "bounded progress wait distinguishes a stalled ledger from a real generation change" {
    var planner = try Planner.init(std.testing.allocator, &.{0}, .g22);
    defer planner.deinit();
    const before = planner.epoch();
    try std.testing.expect(!try planner.waitForChangeWithin(before, 0));
    planner.notifyResourceRelease();
    try std.testing.expect(try planner.waitForChangeWithin(before, 0));
    const current = planner.epoch();
    // Exercise the actual timed condition path without mutating or dropping
    // any future claim merely because the selected worker is waiting.
    try std.testing.expect(!try planner.waitForChangeWithin(current, 1));
}

test "busy unentered GKR retry preserves numerical headroom until actual owner entry" {
    var p = try Planner.init(std.testing.allocator, &.{0}, .g22);
    defer p.deinit();
    const key = ProgressKey{ .statement = @splat(1), .fixed = @splat(2), .ordinal = 0 };
    const keep = try Footprint.allocation(6 << 30);
    const numerical = try Footprint.allocation(14 << 30);
    const project = try Footprint.allocation(4 << 30);
    const original = (try p.tryBegin(0, .{ .owner = test_owner, .progress_key = key, .stage = .trace_commit, .known = true, .host_known = true, .temporary = keep, .successor = numerical })).token.?;
    try p.completeObserved(original, keep, numerical);
    const next = Demand{ .owner = test_owner, .progress_key = key, .stage = .gkr, .known = true, .host_known = true, .temporary = try Footprint.allocation(8 << 30), .stage_retained_upper = try Footprint.allocation(2 << 30), .successor = project };
    const yielded = (try p.tryBegin(0, next)).token.?;
    try std.testing.expectEqual(numerical, p.devices[0].entries.get(original.id).?.demand.successor);
    try p.cancelUnentered(yielded);
    try std.testing.expectEqual(keep, (try p.snapshot(0)).retained);
    try std.testing.expectEqual(numerical, (try p.snapshot(0)).successor);
    var foreign_key = key;
    foreign_key.ordinal = 1;
    const blocked = try p.tryBegin(0, .{ .owner = test_owner, .progress_key = foreign_key, .stage = .witness, .known = true, .host_known = true, .temporary = try Footprint.allocation(3 << 30), .stage_retained_upper = try Footprint.allocation(3 << 30) });
    try std.testing.expectEqual(Reason.capacity_pressure, blocked.reason);
    const retry = (try p.tryBegin(0, next)).token.?;
    try p.commitEntered(retry);
    try std.testing.expectEqual(Footprint{}, p.devices[0].entries.get(original.id).?.demand.successor);
    try std.testing.expectError(error.AdmissionOwnerAlreadyEntered, p.cancelUnentered(retry));
    try p.completeObserved(retry, keep, project);
    try std.testing.expectEqual(keep, (try p.snapshot(0)).retained);
    try std.testing.expectEqual(project, (try p.snapshot(0)).successor);
    try p.release(original);
    try p.release(retry);
}
