//! Source-owned service-lifetime CPU setup, never request/transcript custody.
//! Entries bootstrap independently from pinned executable authority. No producer
//! root or key is an input. Immutable templates park once; request workers obtain
//! bounded phase-specific leases through the existing source-bound Store.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Full = @import("../rv64_full.zig");
const R = @import("../word16_global_execution/services/roster.zig");
const T = @import("../word16_global_execution/services/types.zig");
const Mat = @import("../word16_execution/setup.zig");
const Metadata = @import("../word16_execution/program_metadata.zig");
const Key = @import("pure_p2_fixed_key.zig").Key;
const Profile = @import("pure_p2_worker_protocol.zig").Profile;
const Store = @import("pure_p2_retained_main.zig").Store;
const Budget = engine.host_budget_allocator.SharedHostBudget;
pub const Limits = struct {
    heap_bytes: usize,
    disk_bytes: usize,
    mapped_bytes: usize,
    entries: usize,
    metadata_bytes: usize,
};
pub const Snapshot = struct {
    entries: usize,
    active_leases: usize,
    hits: u64,
    misses: u64,
    heap: Budget.Snapshot,
    parked_bytes: usize,
    mapped_bytes: usize,
    peak_mapped_bytes: usize,
};
const Entry = struct {
    lookup: [32]u8,
    source_profile: @import("stwo_riscv_frontend").rv64.execution_profile.Profile,
    source_control: @import("stwo_riscv_frontend").rv64_air.control_policy.Policy,
    setup: R.CpuSetup,
    key: Key,
    fn matches(self: *const Entry, source: *const Full.ProgramAuthority, g: Mat.Geometry, bridges: T.Logs, profile: Profile) bool {
        const program = &self.setup.materials.program;
        return profile == self.key.profile and self.source_profile == source.profile and self.source_control == source.control_policy and program.profile == source.rom_profile and std.meta.eql(g, self.setup.materials.geometry) and std.meta.eql(bridges, self.setup.bridges) and std.mem.eql(u32, program.words, source.words) and std.mem.eql(u64, program.addresses, source.program.addresses);
    }
};
const State = struct {
    budget: *Budget,
    store: Store,
    metadata: Metadata.Cache,
    limits: Limits,
    references: std.atomic.Value(usize) = .init(1),
    mutex: std.Thread.Mutex = .{},
    entries: std.ArrayList(*Entry) = .empty,
    active_leases: usize = 0,
    request_active: bool = false,
    hits: u64 = 0,
    misses: u64 = 0,
    fn release(self: *State) void {
        if (self.references.fetchSub(1, .acq_rel) != 1) return;
        const a = self.budget.allocator();
        for (self.entries.items) |entry| {
            entry.key.deinit();
            entry.setup.deinit();
            a.destroy(entry);
        }
        self.entries.deinit(a);
        self.metadata.deinit();
        if (self.store.reserved != 0 or self.store.mapped != 0 or self.active_leases != 0) @panic("OP setup cache custody leak");
        self.store.deinit();
        const budget = self.budget;
        a.destroy(self);
        budget.destroy();
    }
};
pub const Lease = struct {
    state: *State,
    entry: *Entry,
    pub fn setup(self: *const Lease) *const R.CpuSetup {
        return &self.entry.setup;
    }
    pub fn key(self: *const Lease) *const Key {
        return &self.entry.key;
    }
    pub fn deinit(self: *Lease) void {
        const state = self.state;
        state.mutex.lock();
        std.debug.assert(state.active_leases > 0);
        state.active_leases -= 1;
        state.mutex.unlock();
        self.* = undefined;
        state.release();
    }
};
pub const RequestLease = struct {
    state: *State,
    disk_bytes: usize,
    mapped_bytes: usize,
    pub fn deinit(self: *RequestLease) void {
        const state = self.state;
        state.mutex.lock();
        std.debug.assert(state.request_active);
        state.request_active = false;
        state.mutex.unlock();
        self.* = undefined;
        state.release();
    }
};
pub const Cache = struct {
    state: *State,
    /// The common parent budget accounts cache plus all concurrent requests.
    /// Neither cache storage nor restored FIXED mappings escape this budget.
    pub fn init(parent: std.mem.Allocator, path: []const u8, limits: Limits) !Cache {
        if (!Budget.isAllocator(parent)) return error.OpSetupCacheRequiresSharedHostBudget;
        if (limits.heap_bytes == 0 or limits.disk_bytes == 0 or limits.mapped_bytes == 0 or limits.metadata_bytes == 0 or limits.entries == 0 or limits.entries > 4096) return error.InvalidOpSetupCacheLimits;
        const budget = try Budget.createRetainingParent(parent, limits.heap_bytes);
        errdefer budget.destroy();
        const a = budget.allocator();
        const state = try a.create(State);
        errdefer a.destroy(state);
        var metadata = try Metadata.Cache.init(a, limits.metadata_bytes);
        errdefer metadata.deinit();
        state.* = .{ .budget = budget, .limits = limits, .metadata = metadata, .store = try Store.init(a, path, limits.disk_bytes, limits.mapped_bytes) };
        return .{ .state = state };
    }
    pub fn deinit(self: *Cache) void {
        const state = self.state;
        self.* = undefined;
        state.release();
    }
    pub fn requireParent(self: *const Cache, a: std.mem.Allocator) !void {
        if (self.state.budget.backing_owner != Budget.fromAllocator(a)) return error.OpSetupCacheBudgetMismatch;
    }
    /// One admitted request at a time. Reserving the configured immutable
    /// disk/map caps makes aggregate limits hold even if another class is added.
    /// Future concurrent request admission must subdivide this same quota.
    pub fn enterRequest(self: *Cache, a: std.mem.Allocator, disk: usize, mapped: usize) !RequestLease {
        try self.requireParent(a);
        const state = self.state;
        state.mutex.lock();
        defer state.mutex.unlock();
        if (state.request_active) return error.OpSetupCacheRequestBusy;
        if (disk <= state.limits.disk_bytes or mapped <= state.limits.mapped_bytes) return error.OpSetupCacheResourcePartition;
        state.request_active = true;
        _ = state.references.fetchAdd(1, .monotonic);
        return .{ .state = state, .disk_bytes = disk - state.limits.disk_bytes, .mapped_bytes = mapped - state.limits.mapped_bytes };
    }
    pub fn configuredLimits(self: *const Cache) Limits {
        return self.state.limits;
    }
    pub fn snapshot(self: *const Cache) Snapshot {
        const state = self.state;
        state.mutex.lock();
        defer state.mutex.unlock();
        state.store.mutex.lock();
        defer state.store.mutex.unlock();
        return .{ .entries = state.entries.items.len, .active_leases = state.active_leases, .hits = state.hits, .misses = state.misses, .heap = state.budget.snapshot(), .parked_bytes = state.store.reserved, .mapped_bytes = state.store.mapped, .peak_mapped_bytes = state.store.peak_mapped };
    }
    pub fn acquire(self: *Cache, source: *const Full.ProgramAuthority, g: Mat.Geometry, bridges: T.Logs, profile: Profile) !Lease {
        if (source.rom_profile != .ethereum_services_op_v1 or profile == .reference_b2_q24_p0) return error.UnqualifiedOpSetup;
        try g.validate();
        const state = self.state;
        state.mutex.lock();
        defer state.mutex.unlock();
        const a = state.budget.allocator();
        const lookup = try lookupIdentity(a, source, g, bridges, profile);
        for (state.entries.items) |entry| if (std.mem.eql(u8, &lookup, &entry.lookup) and entry.matches(source, g, bridges, profile)) {
            state.hits += 1;
            state.active_leases += 1;
            _ = state.references.fetchAdd(1, .monotonic);
            return .{ .state = state, .entry = entry };
        };
        if (state.entries.items.len == state.limits.entries) return error.OpSetupCacheEntryLimit;
        try state.entries.ensureUnusedCapacity(a, 1);
        const entry = try a.create(Entry);
        errdefer a.destroy(entry);
        var setup = try R.CpuSetup.initForOpWithAuthorityAndSuiteAndCaches(a, source, g, bridges, Mat.Suite.production(), .{ .program = &state.metadata });
        errdefer setup.deinit();
        // Own immutable executable views, not the request's Image/initial RAM.
        // No pointers into the request survive publication of this entry.
        try setup.materials.program.retainRawAuthority();
        var key = try Key.initForOpParked(a, &setup, profile, &state.store);
        errdefer key.deinit();
        try key.retireLegacySetup(&setup);
        entry.* = .{ .lookup = lookup, .source_profile = source.profile, .source_control = source.control_policy, .setup = setup, .key = key };
        state.entries.appendAssumeCapacity(entry);
        state.misses += 1;
        state.active_leases += 1;
        _ = state.references.fetchAdd(1, .monotonic);
        return .{ .state = state, .entry = entry };
    }
};
fn lookupIdentity(a: std.mem.Allocator, source: *const Full.ProgramAuthority, g: Mat.Geometry, bridges: T.Logs, profile: Profile) ![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("opstack-pure-p2/independent-setup-cache/v1\x00");
    hash.update(&source.program.identity);
    hash.update(&profile.identity());
    const encoded = try std.json.Stringify.valueAlloc(a, .{ .geometry = g, .bridges = bridges, .profile = source.profile, .rom_profile = source.rom_profile, .control = source.control_policy }, .{});
    defer a.free(encoded);
    hash.update(encoded);
    return hash.finalResult();
}
