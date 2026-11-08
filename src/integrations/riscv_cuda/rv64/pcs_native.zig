//! In-process PCS service. Coefficients are borrowed, never serialized to disk.
const std = @import("std");
const core = @import("stwo_core");
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
const Abi = @import("pcs_native_abi.zig");
const Export = @import("pcs_request_export.zig");
const Admission = @import("global_admission.zig");
const AdmissionRuntime = @import("admission_runtime.zig");
const AllocationCost = @import("pcs_allocation_cost.zig");
const Decode = @import("hybrid_pcs.zig");
const GnRecord = @import("outer_seed_record.zig");
const CachedColumn = struct { host: usize, tree: u32, column: usize, count: usize, log: u32, device: D.DeviceCoefficients };
const Cached = struct { scope: [8]u32, lease: Abi.Lease, columns: []CachedColumn, in_use: bool = false, extra: std.ArrayList(Abi.Lease) = .empty };
pub const BlockBudget = struct { device_bytes: u64, immutable_bytes: u64, max_scopes: usize };
const Setup = @import("immutable_setup.zig");
const LiveLeases = *const fn (*anyopaque, *[5]u64, *u64) callconv(.c) c_int;
/// M6 enqueue: a miss rebuilds 42-63 MB of host FFT/FRI geometry in ~0.48 s
/// on the device owner thread, i.e. on the GPU's critical path. The M5
/// default (128 MiB) held two shapes per GPU, so a resident service that
/// alternates blocks missed at the first leaf of every request [M]. 512 MiB
/// holds every M5 class shape (the cache keeps at most 8 entries). Immutable
/// geometry only; STWO_RV64_PCS_HOST_GEOMETRY_BYTES overrides (0 = M5 cap).
pub const resident_host_geometry_bytes: usize = 512 << 20;
fn hostGeometryBytes() usize {
    const text = std.posix.getenv("STWO_RV64_PCS_HOST_GEOMETRY_BYTES") orelse return resident_host_geometry_bytes;
    const bytes = std.fmt.parseInt(usize, text, 10) catch return resident_host_geometry_bytes;
    return if (bytes == 0) Export.GeometryCache.default_bytes else bytes;
}
/// Geometry-only source class plan; no transcript, coefficient data, GPU work
/// or context/cache locks. Roots and channel bytes do not affect allocations.
pub fn classAllocationPlan(a: std.mem.Allocator, request: D.Request, wide: bool, options: AllocationCost.Options) !AllocationCost.Plan {
    return Export.allocationPlan(a, request, wide, options);
}
/// Pass zero only for an independently resolved/pinned device FIXED forest.
/// A geometry-only request does not itself prove such a cache hit.
pub fn classAllocationPlanWithFixed(a: std.mem.Allocator, request: D.Request, wide: bool, options: AllocationCost.Options, fixed_cold_words: u64) !AllocationCost.Plan {
    var plan = try classAllocationPlan(a, request, wide, options);
    errdefer plan.deinit(a);
    try plan.includeFixedCold(a, fixed_cold_words);
    return plan;
}
pub const allocationOptions = AllocationCost.optionsFromEnv;
pub const Context = struct {
    early_allocations: @import("native_stage1_allocations.zig").Guard = .{},
    admission_progress: @import("admission_progress.zig").Registry = .{},
    admission: ?@import("admission_runtime.zig").Endpoint = null,
    admission_retention: @import("admission_retention.zig").Registry = .{},
    pcs_options: AllocationCost.Options = .{},
    /// Canonical domains never evict in the frozen C owner; a successful PCS
    /// publishes this fact and session destruction is the sole invalidation.
    pcs_domain_logs: std.atomic.Value(u32) = std.atomic.Value(u32).init(0),
    byte_cap: u64,
    wide_pcs_framing: bool = false,
    /// Immutable host FFT/FRI geometry only; request/transcript data never enter.
    host_geometry: Export.GeometryCache = Export.GeometryCache.init(std.heap.page_allocator, Export.GeometryCache.default_bytes),
    immutable_setup: ?*Setup.Cache = null,
    active_block: ?[32]u8 = null,
    cache_mutex: std.Thread.Mutex = .{},
    /// Count admission is separate from the native byte cap. Required device
    /// trees cannot be evicted across the global challenge barrier.
    max_retained_scopes: usize = 2,
    cache: std.ArrayList(Cached) = .empty,
    library: std.DynLib,
    session: *anyopaque,
    native_prove: Abi.Prove,
    release: Abi.Release,
    destroy: Abi.Destroy,
    last_error: Abi.Error,
    submit: Abi.Submit,
    lease_allocate: Abi.LeaseAllocate,
    lease_validate: Abi.LeaseValidate,
    lease_validate_range: Abi.LeaseValidateRange,
    lease_release: Abi.LeaseRelease,
    pub fn classAllocationOptions(self: *const Context, lifting_log: u32) !AllocationCost.Options {
        if (lifting_log > 28) return error.InvalidPcsCostGeometry;
        var result = self.pcs_options;
        result.domain_cached = (self.pcs_domain_logs.load(.acquire) & (@as(u32, 1) << @intCast(lifting_log))) != 0;
        if (self.admission != null) result.borrowed_trees = .{ false, true, true, true };
        return result;
    }
    pub fn registerAdmissionProgress(self: *Context, scope: D.Scope, plan: @import("admission_progress.zig").Plan) !void {
        return self.admission_progress.put(std.heap.page_allocator, .{ .statement = scope.statement, .fixed = scope.fixed, .ordinal = scope.ordinal }, plan);
    }
    pub fn admissionSuccessor(self: *Context, scope: D.Scope, step: @import("admission_progress.zig").Step) !@import("global_admission.zig").Footprint {
        return self.admission_progress.get(.{ .statement = scope.statement, .fixed = scope.fixed, .ordinal = scope.ordinal }, step);
    }
    pub fn admissionRetirementSuccessor(self: *Context, scope: D.Scope, step: @import("admission_progress.zig").Step) !?@import("global_admission.zig").Footprint {
        return self.admission_progress.retirement(@import("global_admission.zig").progressKey(scope), step);
    }
    pub fn armGlobalAdmission(self: *Context, scope: D.Scope) !bool {
        if (self.admission == null) return false;
        return self.admission_progress.armGlobal(@import("global_admission.zig").progressKey(scope));
    }
    pub fn admissionPreGlobal(self: *Context, scope: D.Scope) !bool {
        if (self.admission == null) return false;
        return (try self.admission_progress.phase(@import("global_admission.zig").progressKey(scope))) == .pre_global;
    }
    pub fn takeGlobalAdmissionDrain(self: *Context, scope: D.Scope) !bool {
        if (self.admission == null) return false;
        return self.admission_progress.takeGlobalDrain(@import("global_admission.zig").progressKey(scope));
    }
    pub fn attachGlobalAdmission(self: *Context, planner: *@import("global_admission.zig").Planner, physical: u32) !void {
        var endpoint = try @import("admission_runtime.zig").Endpoint.init(planner, physical, &self.library, self.session, self.submit);
        try endpoint.configure();
        self.admission = endpoint;
        try planner.registerCoverage(physical, .native_pcs);
        try planner.registerCoverage(physical, .recursion_pcs);
        // All GPU immutable misses run inside the same bounded source/TC/RC/
        // PCS tickets; unpermitted public uploads fail in the C guard. Scope
        // retirement uses checked joined callbacks and poisons on any failure.
        try planner.registerCoverage(physical, .immutable);
        try planner.registerCoverage(physical, .retirement);
    }
    /// Host caller completes an admitted stage and transfers future headroom
    /// to the final allocation scope (after any MAIN-root rebind).
    pub fn completeAdmission(self: *Context, permit: *@import("admission_runtime.zig").Permit, scope: D.Scope, successor: @import("global_admission.zig").Footprint) !void {
        const endpoint = self.admission orelse return error.MissingGlobalAdmissionEndpoint;
        if (permit.endpoint.session != self.session or permit.endpoint.planner != endpoint.planner or permit.endpoint.physical != endpoint.physical) return error.ForeignAdmissionOwner;
        const identity = @import("pcs_scope.zig").identity(scope);
        self.cache_mutex.lock();
        defer self.cache_mutex.unlock();
        if (successor.large != 0 or successor.small != 0) {
            var found = false;
            for (self.cache.items) |entry| if (std.mem.eql(u32, &entry.scope, &identity) and entry.lease.words != null) {
                found = true;
                break;
            };
            if (!found) {
                endpoint.planner.poisonPhysical(endpoint.physical);
                return error.MissingPhysicalRetentionOwner;
            }
        }
        try self.admission_retention.complete(std.heap.page_allocator, permit, identity, successor);
    }
    fn retireAdmissionScope(self: *Context, scope: [8]u32) !void {
        if (self.admission) |endpoint| self.admission_retention.retireAfterDestruction(endpoint.planner, scope) catch |err| {
            endpoint.planner.poisonPhysical(endpoint.physical);
            return err;
        };
    }

    /// Failure-only owner-thread diagnostics. Optional runtime exports keep
    /// older images usable; query failures must never replace the stage error.
    pub fn logMemoryFailure(self: *Context, native_context: *anyopaque, operation_label: []const u8) void {
        const Info = *const fn (*anyopaque, *usize, *usize) callconv(.c) c_int;
        var free: usize = 0;
        var total: usize = 0;
        var used: usize = 0;
        var reserved: usize = 0;
        var live: [5]u64 = @splat(0);
        var tracked: u64 = 0;
        const memory_status = if (self.library.lookup(Info, "stwo_exec_context_memory_info")) |query| query(native_context, &free, &total) else -1;
        const pool_status = if (self.library.lookup(Info, "stwo_exec_context_pool_current")) |query| query(native_context, &used, &reserved) else -1;
        const lease_status = if (self.library.lookup(LiveLeases, "stwo_rv64_gpu_session_live_leases")) |query| query(self.session, &live, &tracked) else -1;
        std.debug.print("GPU_MEMORY_FAILURE stage={s} cap_bytes={} memory_status={} free_bytes={} total_bytes={} pool_status={} pool_used_bytes={} pool_reserved_bytes={} lease_status={} tracked_bytes={} live_kinds={any}\n", .{ operation_label, self.byte_cap, memory_status, free, total, pool_status, used, reserved, lease_status, tracked, live });
    }
    pub fn enableImmutableSetup(self: *Context, bytes: u64) !void {
        if (bytes == 0 or bytes > self.byte_cap) return error.InvalidImmutableSetupBudget;
        if (self.immutable_setup) |cache| {
            if (cache.limit != bytes) return error.ImmutableSetupBudgetChanged;
            return;
        }
        const cache = try std.heap.page_allocator.create(Setup.Cache);
        errdefer std.heap.page_allocator.destroy(cache);
        cache.* = try Setup.Cache.init(&self.library, self.session, self.lease_allocate, self.lease_release, bytes);
        self.immutable_setup = cache;
    }
    /// Owner-thread callback: constants stay immutable; this request borrows a
    /// scoped alias. The cache owns the returned lease, never the caller.
    pub fn immutableWords(self: *Context, native_context: *anyopaque, scope: [8]u32, key: [8]u32, words: []const u32) !Abi.Lease {
        if (self.immutable_setup == null) try self.enableImmutableSetup(@min(self.byte_cap, 512 << 20));
        return self.immutable_setup.?.words(native_context, scope, key, words);
    }
    /// Owner-thread cold lookup avoids rebuilding authenticated constant words.
    pub fn immutableLookup(self: *Context, scope: [8]u32, key: [8]u32, count: u64) !?Abi.Lease {
        const cache = self.immutable_setup orelse return null;
        return cache.lookup(scope, key, count);
    }
    pub fn releaseImmutableScope(self: *Context, scope: [8]u32) !void {
        if (self.immutable_setup) |cache| try cache.releaseScope(scope);
    }
    pub fn immutableFixedColumn(self: *Context, scope: D.Scope, index: usize, original: D.Column) !?D.DeviceCoefficients {
        const cache = self.immutable_setup orelse return null;
        return cache.fixedColumn(scope, index, original);
    }
    pub fn releaseProvidedFixed(raw: *anyopaque, scope: D.Scope) !void {
        const self: *Context = @ptrCast(@alignCast(raw));
        try self.releaseImmutableScope(@import("pcs_scope.zig").identity(scope));
    }
    pub fn provideFixed(raw: *anyopaque, native_context: *anyopaque, scope: D.Scope, columns: []const D.Column) ![]const D.Column {
        const self: *Context = @ptrCast(@alignCast(raw));
        return self.immutableFixed(native_context, scope, columns);
    }
    pub fn immutableFixed(self: *Context, native_context: *anyopaque, scope: D.Scope, columns: []const D.Column) ![]const D.Column {
        if (self.immutable_setup == null) try self.enableImmutableSetup(@min(self.byte_cap, 512 << 20));
        return self.immutable_setup.?.fixed(native_context, scope, columns);
    }
    /// Free-only owner callback. Call outside physical transaction/stage/cache
    /// locks. Borrowed immutable entries remain pinned; no allocation or fake
    /// ledger credit is issued. The next V2 HOST snapshot observes stable frees.
    pub fn trimUnborrowedJoined(self: *Context, reason: []const u8) !u64 {
        const endpoint = self.admission orelse return 0;
        if (!endpoint.planner.healthy(endpoint.physical)) return error.PhysicalAdmissionPoisoned;
        const sync = self.library.lookup(Abi.Sync, "stwo_exec_context_sync") orelse return error.MissingGlobalAdmissionRuntime;
        const Job = struct {
            service: *Context,
            sync: Abi.Sync,
            reason: []const u8,
            freed: u64 = 0,
            failure: ?anyerror = null,
            fn run(raw: *anyopaque, _: u64, data: ?*anyopaque) callconv(.c) c_int {
                const job: *@This() = @ptrCast(@alignCast(data.?));
                if (job.sync(raw) != 0) {
                    job.failure = error.ImmutablePressureTrimJoinFailed;
                    return 1;
                }
                var before: u64 = 0;
                var after: u64 = 0;
                var before_entries: usize = 0;
                var after_entries: usize = 0;
                var before_users: u64 = 0;
                var after_users: u64 = 0;
                var borrowed_bytes: u64 = 0;
                if (job.service.immutable_setup) |cache| {
                    before = cache.bytes;
                    before_entries = cache.entries.items.len;
                    for (cache.entries.items) |entry| before_users += entry.users;
                    job.freed = cache.trimUnborrowed() catch |err| {
                        job.failure = err;
                        return 1;
                    };
                    after = cache.bytes;
                    after_entries = cache.entries.items.len;
                    for (cache.entries.items) |entry| {
                        after_users += entry.users;
                        if (entry.users != 0) borrowed_bytes += entry.lease.count * 4;
                    }
                }
                if (job.sync(raw) != 0) {
                    job.failure = error.ImmutablePressureTrimJoinFailed;
                    return 1;
                }
                if (before_users != after_users or before < after or before - after != job.freed) {
                    job.failure = error.ImmutablePressureTrimAccounting;
                    return 1;
                }
                std.debug.print("GPU_ADMISSION_CACHE_RECLAIM reason={s} owner={} logical_released_bytes={} before_bytes={} after_bytes={} before_entries={} after_entries={} before_users={} after_users={} remaining_borrowed_bytes={} joined=true\n", .{ job.reason, job.service.admission.?.owner_identity, job.freed, before, after, before_entries, after_entries, before_users, after_users, borrowed_bytes });
                return 0;
            }
        };
        var job = Job{ .service = self, .sync = sync, .reason = reason };
        if (self.submit(self.session, Job.run, &job) != 0) {
            endpoint.planner.poisonPhysical(endpoint.physical);
            return job.failure orelse error.ImmutablePressureTrimFailed;
        }
        if (job.freed != 0) endpoint.planner.notifyResourceRelease();
        return job.freed;
    }
    pub fn trimSourcePressure(self: *Context) !u64 {
        return self.trimUnborrowedJoined("source_pressure_self");
    }
    pub fn beginBlock(self: *Context, identity: [32]u8, budget: BlockBudget) !void {
        var gate: ?*std.Thread.Mutex = null;
        if (self.admission) |endpoint| {
            if (!endpoint.planner.healthy(endpoint.physical)) return error.PhysicalAdmissionPoisoned;
            gate = try endpoint.planner.stageGate(endpoint.physical);
            gate.?.lock();
        }
        defer if (gate) |locked| {
            locked.unlock();
            self.admission.?.planner.notifyResourceRelease();
        };
        if (self.active_block != null or self.cache.items.len != 0 or self.admission_retention.claims.items.len != 0) return error.ResidentBlockStillActive;
        if (budget.device_bytes != self.byte_cap) return error.ResidentDeviceBudgetChanged;
        try self.enableImmutableSetup(budget.immutable_bytes);
        try self.configureRetention(budget.max_scopes);
        try self.requireNoRequestLeases();
        if (try phaseCacheTrimEnabled()) {
            var trim = PhaseTrim{ .self = self };
            if (self.submit(self.session, PhaseTrim.run, &trim) != 0) {
                if (self.admission) |endpoint| endpoint.planner.poisonPhysical(endpoint.physical);
                return trim.failure orelse error.ResidentPhaseTrimFailed;
            }
            try self.requireNoRequestLeases();
            if (self.admission) |endpoint| {
                const actual = trim.after orelse return error.MissingPhaseTrimSnapshot;
                try actual.validate(endpoint);
                try endpoint.planner.observeIdle(endpoint.physical, actual.footprint());
            }
        }
        self.active_block = identity;
    }
    const PhaseTrim = struct {
        self: *Context,
        after: ?AdmissionRuntime.Snapshot = null,
        failure: ?anyerror = null,
        fn run(native_context: *anyopaque, _: u64, raw: ?*anyopaque) callconv(.c) c_int {
            const job: *@This() = @ptrCast(@alignCast(raw.?));
            const cache = job.self.immutable_setup orelse return 1;
            if (cache.borrows.items.len != 0) {
                job.failure = error.ImmutableSetupStillBorrowed;
                return 1;
            }
            const immutable = cache.trimUnborrowed() catch |err| {
                job.failure = err;
                return 1;
            };
            const Trim = *const fn (*anyopaque, *u64) callconv(.c) c_int;
            var pcs: u64 = 0;
            const trim = job.self.library.lookup(Trim, "stwo_rv64_gpu_session_trim_unused");
            if (trim) |call| if (call(job.self.session, &pcs) != 0) {
                job.failure = error.ResidentPhaseTrimFailed;
                return 1;
            };
            if (job.self.admission) |endpoint| {
                var after: AdmissionRuntime.Snapshot = .{};
                if (endpoint.api.snapshot(native_context, &after) != 0) {
                    job.failure = error.GlobalAdmissionSnapshotFailed;
                    return 1;
                }
                job.after = after;
            }
            std.debug.print("GPU_RESIDENT_PHASE_TRIM immutable_bytes={} pcs_idle_bytes={} pcs_trim_api={} graph_metadata_retained=true\n", .{ immutable, pcs, trim != null });
            return 0;
        }
    };
    pub fn endBlock(self: *Context, identity: [32]u8) !void {
        if (self.admission) |endpoint| if (!endpoint.planner.healthy(endpoint.physical)) return error.PhysicalAdmissionPoisoned;
        if (self.active_block == null or !std.mem.eql(u8, &self.active_block.?, &identity)) return error.ResidentBlockIdentityMismatch;
        if (self.cache.items.len != 0 or self.admission_retention.claims.items.len != 0) return error.ResidentBlockStillActive;
        try self.requireNoRequestLeases();
        self.active_block = null;
        self.admission_progress.clear();
        if (self.immutable_setup) |cache| std.debug.print("GPU_RESIDENT_SETUP device_bytes={} limit_bytes={} entries={} hits={} uploads={} evictions={} outstanding_aliases={}\n", .{ cache.bytes, cache.limit, cache.entries.items.len, cache.hits, cache.uploads, cache.evictions, cache.borrows.items.len });
    }
    const Audit = struct {
        self: *Context,
        failure: ?anyerror = null,
        fn run(_: *anyopaque, _: u64, raw: ?*anyopaque) callconv(.c) c_int {
            const job: *@This() = @ptrCast(@alignCast(raw.?));
            const query = job.self.library.lookup(LiveLeases, "stwo_rv64_gpu_session_live_leases") orelse {
                job.failure = error.MissingImmutableSetupCapability;
                return 1;
            };
            var counts: [5]u64 = @splat(0);
            var bytes: u64 = 0;
            if (query(job.self.session, &counts, &bytes) != 0 or counts[0] != 0 or counts[1] != 0 or counts[2] != 0 or counts[3] != 0) {
                job.failure = error.ResidentRequestLeasesStillLive;
                return 1;
            }
            if (job.self.immutable_setup) |cache| {
                if (cache.borrows.items.len != 0) {
                    job.failure = error.ImmutableSetupStillBorrowed;
                    return 1;
                }
                if (counts[4] != cache.entries.items.len or bytes != cache.bytes) {
                    job.failure = error.UntrackedImmutableSetupLease;
                    return 1;
                }
            } else if (counts[4] != 0 or bytes != 0) {
                job.failure = error.UntrackedImmutableSetupLease;
                return 1;
            }
            return 0;
        }
    };
    pub fn requireNoRequestLeases(self: *Context) !void {
        var audit = Audit{ .self = self };
        if (self.submit(self.session, Audit.run, &audit) != 0) return audit.failure orelse error.ResidentSessionAuditFailed;
    }
    /// Called on the native owner thread. Ownership transfers only on success;
    /// metadata is copied, coefficient buffers remain entirely on device.
    pub fn publishCoefficients(raw: *anyopaque, scope: [8]u32, lease: Abi.Lease, fixed: []const D.Column, main: []const D.Column, offsets: []const usize) !void {
        const self: *Context = @ptrCast(@alignCast(raw));
        if (lease.kind != 2 or lease.words == null or offsets.len != fixed.len + main.len or self.lease_validate(self.session, &lease, &scope) != 0) return error.InvalidRetainedCoefficientLease;
        const a = std.heap.page_allocator;
        const mapped = try a.alloc(CachedColumn, offsets.len);
        errdefer a.free(mapped);
        var total: u64 = 0;
        for (mapped, offsets, 0..) |*item, offset, i| {
            const column = if (i < fixed.len) fixed[i] else main[i - fixed.len];
            const count = column.coefficients.len;
            if (column.device != null or count == 0 or offset > lease.count or count > lease.count - offset) return error.InvalidRetainedCoefficientLease;
            item.* = .{ .host = @intFromPtr(column.coefficients.ptr), .tree = if (i < fixed.len) 0 else 1, .column = if (i < fixed.len) i else i - fixed.len, .count = count, .log = column.log_size, .device = .{ .words = lease.words.? + offset, .count = count, .context_token = lease.context_token, .generation = lease.generation } };
            total += count;
        }
        if (total != lease.count) return error.InvalidRetainedCoefficientLease;
        self.cache_mutex.lock();
        defer self.cache_mutex.unlock();
        for (self.cache.items) |entry| if (std.mem.eql(u32, &entry.scope, &scope)) return error.DuplicateRetainedCoefficientScope;
        // Keep at most two proofs' immutable columns. Pinned consumers cannot
        // be evicted while preparing/running PCS or resident composition.
        if (self.cache.items.len >= self.max_retained_scopes) {
            var victim: ?usize = null;
            for (self.cache.items, 0..) |entry, i| if (!entry.in_use) {
                victim = i;
                break;
            };
            const index = victim orelse return error.RetainedCoefficientAdmissionExceeded;
            var retired = self.cache.swapRemove(index);
            if (self.lease_release(self.session, &retired.lease) != 0) return error.InvalidRetainedCoefficientLease;
            for (retired.extra.items) |*extra| if (self.lease_release(self.session, extra) != 0) return error.InvalidRetainedCoefficientLease;
            retired.extra.deinit(a);
            a.free(retired.columns);
            try self.retireAdmissionScope(retired.scope);
        }
        try self.cache.append(a, .{ .scope = scope, .lease = lease, .columns = mapped });
    }
    /// Called inside the same owner-thread callback; transfers only on success.
    pub fn retainDeviceLease(self: *Context, scope: [8]u32, lease: Abi.Lease) !void {
        if (lease.kind != 2 or self.lease_validate(self.session, &lease, &scope) != 0) return error.InvalidRetainedCoefficientLease;
        self.cache_mutex.lock();
        defer self.cache_mutex.unlock();
        for (self.cache.items) |*entry| if (std.mem.eql(u32, &entry.scope, &scope)) {
            if (entry.lease.generation == lease.generation) return error.DuplicateRetainedCoefficientLease;
            for (entry.extra.items) |previous| if (previous.generation == lease.generation) return error.DuplicateRetainedCoefficientLease;
            try entry.extra.append(std.heap.page_allocator, lease);
            entry.in_use = true;
            return;
        };
        if (self.cache.items.len >= self.max_retained_scopes) return error.RetainedCoefficientAdmissionExceeded;
        try self.cache.append(std.heap.page_allocator, .{ .scope = scope, .lease = lease, .columns = &.{}, .in_use = true });
    }
    /// Adopt a complete set of already-owned INTER leases. Reserve all host
    /// metadata before moving claims or leases; failure preserves source custody.
    pub fn adoptInterLeases(self: *Context, scope: [8]u32, leases: []const Abi.Lease, claims: *@import("admission_retention.zig").Registry) !void {
        if (leases.len == 0) return error.InvalidRetainedCoefficientLease;
        for (leases, 0..) |lease, i| {
            if (lease.kind != 2 or self.lease_validate(self.session, &lease, &scope) != 0) return error.InvalidRetainedCoefficientLease;
            for (leases[0..i]) |previous| if (previous.generation == lease.generation) return error.DuplicateRetainedCoefficientLease;
        }
        const a = std.heap.page_allocator;
        self.cache_mutex.lock();
        defer self.cache_mutex.unlock();
        for (self.cache.items) |*entry| if (std.mem.eql(u32, &entry.scope, &scope)) {
            for (leases) |lease| {
                if (entry.lease.generation == lease.generation) return error.DuplicateRetainedCoefficientLease;
                for (entry.extra.items) |previous| if (previous.generation == lease.generation) return error.DuplicateRetainedCoefficientLease;
            }
            try entry.extra.ensureUnusedCapacity(a, leases.len);
            try claims.transferScopeTo(a, &self.admission_retention, scope);
            for (leases) |lease| entry.extra.appendAssumeCapacity(lease);
            entry.in_use = true;
            return;
        };
        if (self.cache.items.len >= self.max_retained_scopes) return error.RetainedCoefficientAdmissionExceeded;
        var extra: std.ArrayList(Abi.Lease) = .empty;
        errdefer extra.deinit(a);
        try extra.appendSlice(a, leases[1..]);
        try self.cache.ensureUnusedCapacity(a, 1);
        try claims.transferScopeTo(a, &self.admission_retention, scope);
        self.cache.appendAssumeCapacity(.{ .scope = scope, .lease = leases[0], .extra = extra, .columns = &.{}, .in_use = true });
    }
    /// Owner-thread only. Move one exact fixed coefficient lease into an
    /// already admitted MAIN scope, preserving its allocation/generation.
    /// All metadata capacity is admitted before native authority changes.
    pub fn promoteSingleRetained(self: *Context, old: [8]u32, next: [8]u32, rebind: Abi.LeaseRebind) !void {
        if (std.mem.eql(u32, &old, &next)) return error.InvalidFixedScopePromotion;
        self.cache_mutex.lock();
        defer self.cache_mutex.unlock();
        var source: ?usize = null;
        var destination: ?usize = null;
        for (self.cache.items, 0..) |entry, i| {
            if (std.mem.eql(u32, &entry.scope, &old)) source = i;
            if (std.mem.eql(u32, &entry.scope, &next)) destination = i;
        }
        const from = source orelse return error.MissingFixedCoefficientScope;
        const to = destination orelse return error.MissingMainCoefficientScope;
        const original = &self.cache.items[from];
        if (original.lease.kind != 2 or original.columns.len != 0 or original.extra.items.len != 0) return error.InvalidFixedCoefficientCustody;
        var lease = original.lease;
        if (self.lease_validate(self.session, &lease, &old) != 0) return error.InvalidRetainedCoefficientLease;
        try self.cache.items[to].extra.ensureUnusedCapacity(std.heap.page_allocator, 1);
        if (rebind(self.session, &lease, &old, &next) != 0) return error.InvalidFixedScopePromotion;
        self.cache.items[to].extra.appendAssumeCapacity(lease);
        var removed = self.cache.swapRemove(from);
        removed.extra.deinit(std.heap.page_allocator);
        std.heap.page_allocator.free(removed.columns);
        self.admission_retention.promoted(old, next);
    }
    /// Stable original tree/column identity survives retained MAIN remapping.
    pub fn retainedColumn(self: *Context, scope: [8]u32, tree: u32, index: usize, column: D.Column) ?D.DeviceCoefficients {
        self.cache_mutex.lock();
        defer self.cache_mutex.unlock();
        for (self.cache.items) |*entry| if (std.mem.eql(u32, &entry.scope, &scope)) {
            entry.in_use = true;
            for (entry.columns) |item| if (item.tree == tree and item.column == index and item.count == column.coefficients.len and item.log == column.log_size) return item.device;
        };
        return null;
    }
    pub fn retainedCoefficient(self: *Context, scope: [8]u32, column: D.Column) ?D.DeviceCoefficients {
        self.cache_mutex.lock();
        defer self.cache_mutex.unlock();
        for (self.cache.items) |*entry| if (std.mem.eql(u32, &entry.scope, &scope)) {
            entry.in_use = true;
            for (entry.columns) |item| if (item.host == @intFromPtr(column.coefficients.ptr) and item.count == column.coefficients.len and item.log == column.log_size) return item.device;
        };
        return null;
    }
    /// Drop only a sealed MAIN coefficient owner for deterministic replay.
    /// Call outside an owner callback. Compact inputs are independent leases;
    /// manifest roots and native proof obligations remain with the worker.
    pub fn discardRetainedMain(self: *Context, scope: D.Scope) !void {
        if (std.mem.allEqual(u8, &scope.main, 0)) return error.DeviceMainReplayMissing;
        const identity = @import("pcs_scope.zig").identity(scope);
        self.cache_mutex.lock();
        var index: ?usize = null;
        for (self.cache.items, 0..) |entry, i| if (std.mem.eql(u32, &entry.scope, &identity)) {
            index = i;
            break;
        };
        if (index == null) {
            self.cache_mutex.unlock();
            return error.DeviceMainReplayMissing;
        }
        const selected = &self.cache.items[index.?];
        if (selected.columns.len != 0 or selected.extra.items.len != 0 or selected.lease.kind != 2) {
            self.cache_mutex.unlock();
            return error.DeviceMainReplayHasOtherObligations;
        }
        const cached = self.cache.swapRemove(index.?);
        self.cache_mutex.unlock();
        var release_job = ReleaseJob{ .self = self, .scope = identity, .lease = cached.lease, .extra = &.{} };
        const status = self.submit(self.session, ReleaseJob.run, &release_job);
        var extra = cached.extra;
        extra.deinit(std.heap.page_allocator);
        std.heap.page_allocator.free(cached.columns);
        if (status != 0) {
            if (self.admission) |endpoint| endpoint.planner.poisonPhysical(endpoint.physical);
            return error.DeviceMainReplayReleaseFailed;
        }
        try self.retireAdmissionScope(identity);
        if (self.admission) |endpoint| endpoint.planner.notifyResourceRelease();
    }

    /// Terminal local proof cleanup, including failure before PCS submission.
    /// Call outside the owner callback only when no live stage borrows this
    /// proof scope. Idempotent after PCS has already released its own custody.
    pub fn finishProofScope(self: *Context, scope: D.Scope) void {
        self.releaseScope(@import("pcs_scope.zig").identity(scope));
    }
    pub fn finishProofScopeChecked(self: *Context, scope: D.Scope) !void {
        return self.releaseScopeChecked(@import("pcs_scope.zig").identity(scope));
    }
    fn releaseScope(self: *Context, scope: [8]u32) void {
        self.releaseScopeChecked(scope) catch {
            if (self.admission) |endpoint| endpoint.planner.poisonPhysical(endpoint.physical);
        };
    }
    fn releaseScopeChecked(self: *Context, scope: [8]u32) !void {
        defer if (self.admission) |endpoint| endpoint.planner.notifyResourceRelease();
        self.cache_mutex.lock();
        var index: ?usize = null;
        for (self.cache.items, 0..) |entry, i| if (std.mem.eql(u32, &entry.scope, &scope)) {
            index = i;
            break;
        };
        const entry: ?Cached = if (index) |i| self.cache.swapRemove(i) else null;
        self.cache_mutex.unlock();
        if (entry) |cached| {
            var release_job = ReleaseJob{ .self = self, .scope = scope, .lease = cached.lease, .extra = cached.extra.items };
            const release_status = self.submit(self.session, ReleaseJob.run, &release_job);
            // A poisoned context is terminal; destroy still owns any lease
            // that could not be released by the owner-thread callback.
            var extra = cached.extra;
            extra.deinit(std.heap.page_allocator);
            std.heap.page_allocator.free(cached.columns);
            if (release_status != 0) {
                if (self.admission) |endpoint| endpoint.planner.poisonPhysical(endpoint.physical);
                return error.DeviceScopeReleaseFailed;
            }
            try self.retireAdmissionScope(scope);
        } else if (self.immutable_setup != null) {
            var release_job = ReleaseJob{ .self = self, .scope = scope, .lease = null, .extra = &.{} };
            if (self.submit(self.session, ReleaseJob.run, &release_job) != 0) {
                if (self.admission) |endpoint| endpoint.planner.poisonPhysical(endpoint.physical);
                return error.DeviceScopeReleaseFailed;
            }
        }
    }
    const ReleaseJob = struct {
        self: *Context,
        scope: [8]u32,
        lease: ?Abi.Lease,
        extra: []const Abi.Lease,
        fn run(_: *anyopaque, _: u64, raw: ?*anyopaque) callconv(.c) c_int {
            const job: *@This() = @ptrCast(@alignCast(raw.?));
            if (job.lease) |*lease| if (job.self.lease_release(job.self.session, lease) != 0) return 1;
            for (job.extra) |lease| {
                var owned = lease;
                if (job.self.lease_release(job.self.session, &owned) != 0) return 1;
            }
            if (job.self.immutable_setup) |cache| cache.releaseScope(job.scope) catch return 1;
            return 0;
        }
    };
    pub fn init(path: []const u8, device: u32, capacity: u64) !Context {
        const pcs_options = try allocationOptions();
        var library = try std.DynLib.open(path);
        errdefer library.close();
        if (pcs_options.compact_eager) {
            const Capability = *const fn () callconv(.c) c_int;
            const capability = library.lookup(Capability, "stwo_rv64_compact_eager_state_capability") orelse return error.MissingCompactEagerPcsCapability;
            if (capability() != 1) return error.MissingCompactEagerPcsCapability;
        }
        if (pcs_options.phase_retirement) {
            const Capability = *const fn () callconv(.c) c_int;
            const capability = library.lookup(Capability, "stwo_rv64_pcs_phase_retirement_capability") orelse return error.MissingPcsPhaseRetirementCapability;
            if (capability() != 1) return error.MissingPcsPhaseRetirementCapability;
        }
        const create = library.lookup(Abi.Create, "stwo_rv64_pcs_native_create") orelse return error.MissingGpuPcsSymbol;
        const native_prove = library.lookup(Abi.Prove, "stwo_rv64_pcs_native_prove") orelse return error.MissingGpuPcsSymbol;
        const release = library.lookup(Abi.Release, "stwo_rv64_pcs_native_release") orelse return error.MissingGpuPcsSymbol;
        const destroy = library.lookup(Abi.Destroy, "stwo_rv64_pcs_native_destroy") orelse return error.MissingGpuPcsSymbol;
        const last_error = library.lookup(Abi.Error, "stwo_rv64_pcs_native_error") orelse return error.MissingGpuPcsSymbol;
        const submit = library.lookup(Abi.Submit, "stwo_rv64_gpu_session_submit") orelse return error.MissingGpuPcsSymbol;
        const lease_allocate = library.lookup(Abi.LeaseAllocate, "stwo_rv64_gpu_lease_allocate") orelse return error.MissingGpuPcsSymbol;
        const lease_validate = library.lookup(Abi.LeaseValidate, "stwo_rv64_gpu_lease_validate") orelse return error.MissingGpuPcsSymbol;
        const lease_validate_range = library.lookup(Abi.LeaseValidateRange, "stwo_rv64_gpu_lease_validate_range") orelse return error.MissingGpuPcsSymbol;
        const lease_release = library.lookup(Abi.LeaseRelease, "stwo_rv64_gpu_lease_release") orelse return error.MissingGpuPcsSymbol;
        var session: ?*anyopaque = null;
        if (create(device, capacity, &session) != 0 or session == null) return error.GpuPcsInitializationFailed;
        const Version = *const fn () callconv(.c) u32;
        const wide = if (library.lookup(Version, "stwo_rv64_pcs_request_version")) |version| version() >= 3 else false;
        return .{ .pcs_options = pcs_options, .byte_cap = capacity, .wide_pcs_framing = wide, .host_geometry = Export.GeometryCache.init(std.heap.page_allocator, hostGeometryBytes()), .library = library, .session = session.?, .native_prove = native_prove, .release = release, .destroy = destroy, .last_error = last_error, .submit = submit, .lease_allocate = lease_allocate, .lease_validate = lease_validate, .lease_validate_range = lease_validate_range, .lease_release = lease_release };
    }
    pub fn deinit(self: *Context) void {
        self.host_geometry.deinit();
        self.admission_progress.deinit(std.heap.page_allocator);
        while (self.cache.items.len != 0) self.releaseScope(self.cache.items[self.cache.items.len - 1].scope);
        self.cache.deinit(std.heap.page_allocator);
        if (self.immutable_setup) |cache| {
            var cleanup = SetupCleanup{ .self = self, .cache = cache };
            _ = self.submit(self.session, SetupCleanup.run, &cleanup);
            cache.freeMetadata();
            std.heap.page_allocator.destroy(cache);
        }
        if (self.destroy(self.session) != 0) @panic("GPU context failed to join before library close");
        self.admission_retention.contextDestroyed(if (self.admission) |endpoint| endpoint.planner else null) catch @panic("GPU retention claims failed to retire after context destruction");
        self.admission_retention.deinit(std.heap.page_allocator);
        self.library.close();
        self.* = undefined;
    }
    const SetupCleanup = struct {
        self: *Context,
        cache: *Setup.Cache,
        fn run(_: *anyopaque, _: u64, raw: ?*anyopaque) callconv(.c) c_int {
            const job: *@This() = @ptrCast(@alignCast(raw.?));
            while (job.cache.borrows.items.len != 0) job.cache.releaseScope(job.cache.borrows.items[0].scope) catch return 1;
            job.cache.deinit() catch return 1;
            return 0;
        }
    };
    pub fn configureRetention(self: *Context, limit: usize) !void {
        if (limit == 0 or limit > 64) return error.InvalidRetainedScopeLimit;
        self.cache_mutex.lock();
        defer self.cache_mutex.unlock();
        if (self.cache.items.len != 0) return error.RetentionPolicyAlreadyInUse;
        self.max_retained_scopes = limit;
    }
    pub fn stage(self: *Context) D.Stage {
        return .{ .context = self, .prove = prove };
    }
    const FixedJob = struct {
        self: *Context,
        scope: D.Scope,
        columns: []const D.Column,
        result: ?[]const D.Column = null,
        failure: ?anyerror = null,
        fn run(native_context: *anyopaque, _: u64, raw: ?*anyopaque) callconv(.c) c_int {
            const job: *@This() = @ptrCast(@alignCast(raw.?));
            job.result = job.self.immutableFixed(native_context, job.scope, job.columns) catch |err| {
                job.failure = err;
                return 1;
            };
            return 0;
        }
    };
    const ObserverBoundary = struct {
        context: *Context,
        scope: D.Scope,
        domain: D.AllocationObserverDomain,
        range: ?@import("allocation_observer.zig").Range = null,
        ending: bool = false,
        failure: ?anyerror = null,
        fn run(raw: *anyopaque, _: u64, user: ?*anyopaque) callconv(.c) c_int {
            const job: *@This() = @ptrCast(@alignCast(user orelse return 1));
            if (job.ending) {
                if (job.range) |*range| range.deinit();
                job.range = null;
            } else job.range = @import("allocation_observer.zig").Range.begin(&job.context.library, raw, job.scope, @intFromEnum(job.domain), .pcs_metadata, 1) catch |err| {
                job.failure = err;
                return 1;
            };
            return 0;
        }
    };
    const PcsBoundary = struct {
        permit: *AdmissionRuntime.Permit,
        ending: bool = false,
        context: ?*Context = null,
        request: ?*const D.Request = null,
        failure: ?anyerror = null,
        fn run(raw: *anyopaque, _: u64, user: ?*anyopaque) callconv(.c) c_int {
            const job: *@This() = @ptrCast(@alignCast(user orelse return 1));
            (if (job.ending) job.permit.leaveOwner(raw) else job.permit.enterOwner(raw)) catch |err| {
                job.failure = err;
                return 1;
            };
            if (!job.ending) if (job.request) |request| {
                const context = job.context orelse return 1;
                const scope = @import("pcs_scope.zig").identity(request.scope orelse return 1);
                for (request.trees) |tree| for (tree.columns) |column| if (column.device) |device| {
                    if (context.lease_validate_range(context.session, device.words, device.count, device.context_token, device.generation, &scope) != 0) {
                        job.failure = error.InvalidDevicePcsColumn;
                        return 1;
                    }
                };
            };
            return 0;
        }
    };
    fn closePcsPermit(self: *Context, permit: *AdmissionRuntime.Permit) !void {
        if (permit.entered and permit.after == null) {
            var boundary = PcsBoundary{ .permit = permit, .ending = true };
            if (self.submit(self.session, PcsBoundary.run, &boundary) != 0) return boundary.failure orelse error.GlobalPcsBoundaryFailed;
        }
        try permit.finish(.{});
    }
    fn validateSortedTree(a: std.mem.Allocator, tree: D.Tree, context_token: u64) !void {
        if (tree.columns.len == 0) return error.InvalidPcsBorrowPromise;
        const order = try a.alloc(usize, tree.columns.len);
        defer a.free(order);
        for (order, 0..) |*index, i| index.* = i;
        std.mem.sort(usize, order, tree.columns, struct {
            fn less(columns: []const D.Column, x: usize, y: usize) bool {
                return columns[x].log_size < columns[y].log_size or (columns[x].log_size == columns[y].log_size and x < y);
            }
        }.less);
        var next: usize = 0;
        var generation: u64 = 0;
        for (order, 0..) |index, i| {
            const device = tree.columns[index].device orelse return error.AdmissionRequiresSortedResidentCoefficients;
            if (device.context_token != context_token or device.generation == 0) return error.InvalidPcsBorrowPromise;
            const address = @intFromPtr(device.words);
            if (i != 0 and (address != next or device.generation != generation)) return error.InvalidPcsBorrowPromise;
            next = try std.math.add(usize, address, try std.math.mul(usize, @intCast(device.count), 4));
            generation = device.generation;
        }
    }
    fn prove(raw: *anyopaque, a: std.mem.Allocator, request: D.Request, channel: *D.Channel) !D.P.ExtendedCommitmentSchemeProof(D.H) {
        const self: *Context = @ptrCast(@alignCast(raw));
        var timer = try std.time.Timer.start();
        const scope = if (request.scope) |value| @import("pcs_scope.zig").identity(value) else [_]u32{0} ** 8;
        defer self.releaseScope(scope);
        var permit: ?AdmissionRuntime.Permit = null;
        if (self.admission) |*endpoint| {
            const own_scope = request.scope orelse return error.MissingResidentScope;
            // Validate live input shape on the host, independently of the
            // geometry-only class planner used before the first source stage.
            for (request.trees) |tree| for (tree.columns) |column| {
                if (column.log_size > 28) return error.InvalidDevicePcsColumn;
                const count = @as(u64, 1) << @intCast(column.log_size);
                if (column.device) |device| {
                    if (device.count != count or device.context_token == 0 or device.generation == 0) return error.InvalidDevicePcsColumn;
                } else if (column.coefficients.len != count) return error.InvalidDevicePcsColumn;
            };
            if (!std.meta.eql(self.pcs_options, try allocationOptions())) return error.PcsAllocationPolicyChanged;
            const options = try self.classAllocationOptions(request.lifting_log_size);
            for (request.trees, 0..) |tree, i| if (options.borrowed_trees[i]) try validateSortedTree(a, tree, endpoint.owner_identity);
            var fixed_cold_words: u64 = 0;
            if (self.immutable_setup != null and request.trees.len != 0) {
                var words: u64 = 0;
                var host = false;
                for (request.trees[0].columns) |column| {
                    words = try std.math.add(u64, words, @as(u64, 1) << @intCast(column.log_size));
                    host = host or column.device == null;
                }
                if (host) fixed_cold_words = words;
            }
            var cost = try classAllocationPlanWithFixed(a, request, self.wide_pcs_framing, options, fixed_cold_words);
            defer cost.deinit(a);
            if (cost.phase_retirement) std.debug.print("GPU_PCS_ALLOCATION_BOUND ordinal={} phased=true before_late_large={} survivors_large={} late_large={} selected_large={} before_late_small={} survivors_small={} late_small={} selected_small={} requested_sum_bytes={}\n", .{ own_scope.ordinal, cost.before_late_upper.large, cost.late_survivors_upper.large, cost.late_scratch_upper.large, cost.additional_upper.large, cost.before_late_upper.small, cost.late_survivors_upper.small, cost.late_scratch_upper.small, cost.additional_upper.small, cost.requested_upper_bytes });
            const envelope = cost.additional_upper;
            const retained_upper = cost.retained_after_upper;
            const successor = try self.admissionSuccessor(own_scope, .pcs);
            if (successor.large != 0 or successor.small != 0) return error.UnexpectedPcsSuccessor;
            @import("allocation_observer.zig").model(own_scope, @intFromEnum(request.allocation_observer_domain), .pcs_metadata, envelope, retained_upper, successor);
            permit = try endpoint.reserve(.{ .owner = .{ .request = std.mem.readInt(u64, own_scope.statement[0..8], .little), .domain = .native_packet, .ordinal = own_scope.ordinal }, .progress_key = Admission.progressKey(own_scope), .stage = .pcs, .stage_retained_upper = retained_upper, .temporary = envelope, .successor = successor, .known = true, .host_known = false });
            // The C admission guard deliberately spans several synchronous
            // owner jobs, including FIXED misses and the complete native PCS.
            // Host geometry work takes its locks only AFTER this reservation.
            var boundary = PcsBoundary{ .permit = &permit.?, .context = self, .request = &request };
            if (self.submit(self.session, PcsBoundary.run, &boundary) != 0) {
                permit.?.endpoint.planner.poisonPhysical(permit.?.endpoint.physical);
                return boundary.failure orelse error.GlobalPcsBoundaryFailed;
            }
        }
        errdefer if (permit) |*claim| if (!claim.closed) {
            self.closePcsPermit(claim) catch {
                claim.endpoint.planner.poisonPhysical(claim.endpoint.physical);
            };
        };
        var observed: ?ObserverBoundary = null;
        if (@import("allocation_observer.zig").enabled()) {
            observed = .{ .context = self, .scope = request.scope orelse return error.MissingResidentScope, .domain = request.allocation_observer_domain };
            if (self.submit(self.session, ObserverBoundary.run, &observed.?) != 0) return observed.?.failure orelse error.AllocationObserverBeginFailed;
        }
        defer if (observed) |*boundary| {
            boundary.ending = true;
            if (self.submit(self.session, ObserverBoundary.run, boundary) != 0) std.debug.print("GPU_NODE_ALLOC_CLOSE_FAILED phase=pcs coverage_valid=0\n", .{});
        };
        const trees = try a.dupe(D.Tree, request.trees);
        defer a.free(trees);
        var reused_columns: usize = 0;
        var reused_cells: usize = 0;
        var made: usize = 0;
        defer for (trees[0..made]) |tree| a.free(tree.columns);
        for (request.trees, trees, 0..) |tree, *replacement, tree_index| {
            const columns = try a.dupe(D.Column, tree.columns);
            replacement.columns = columns;
            made += 1;
            if (tree_index == 0 and self.immutable_setup != null and !@import("fixed_forest_policy.zig").isDeviceOnly(tree.columns)) {
                var fixed_job = FixedJob{ .self = self, .scope = request.scope orelse return error.MissingResidentScope, .columns = tree.columns };
                if (self.submit(self.session, FixedJob.run, &fixed_job) != 0) return fixed_job.failure orelse error.ImmutableSetupUploadFailed;
                @memcpy(columns, fixed_job.result orelse return error.InvalidImmutableFixedSource);
            }
            for (columns, 0..) |*column, column_index| if (column.device == null) {
                if (self.retainedColumn(scope, @intCast(tree_index), column_index, column.*)) |device| {
                    column.device = device;
                    reused_columns += 1;
                    reused_cells += column.coefficients.len;
                }
            };
        }
        var resident_request = request;
        resident_request.trees = trees;
        var prepared = try Export.prepareRequestWithFraming(a, resident_request, channel.*, &self.host_geometry, self.wide_pcs_framing);
        defer prepared.deinit(a);
        const prepare_ns = timer.read();
        const descriptor = prepared.descriptor();
        if (permit != null) {
            var strict = try AllocationCost.init(a, &descriptor, try self.classAllocationOptions(request.lifting_log_size));
            defer strict.deinit(a);
        }
        var result: Abi.Result = .{};
        if (self.native_prove(self.session, &descriptor, &result) != 0) {
            std.debug.print("GPU_PCS_NATIVE error={s}\n", .{self.last_error(self.session)});
            return error.GpuPcsFailed;
        }
        defer self.release(&result);
        _ = self.pcs_domain_logs.fetchOr(@as(u32, 1) << @intCast(request.lifting_log_size), .release);
        if (permit) |*claim| {
            // C runProve returned only after joined proof readback/reset. Its
            // result is host-owned; no GPU coefficient is read by decode.
            try self.releaseScopeChecked(scope);
            try self.closePcsPermit(claim);
        }
        if (result.words == null or result.count > (1 << 28)) return error.InvalidGpuPcsProof;
        // gn-node piece-harness recorder (default off; proof-neutral).
        if (GnRecord.dir() != null) GnRecord.pcsImage(prepared.metadata.shape, result.words.?[0..@intCast(result.count)]);
        if (GnRecord.liveSelected() catch false) GnRecord.Live.putPcs(prepared.metadata.shape, result.words.?[0..@intCast(result.count)]);
        var decoded = try Decode.decodeWords(a, prepared.metadata.shape, result.words.?[0..@intCast(result.count)]);
        errdefer decoded.proof.deinit(a);
        channel.* = decoded.channel;
        const host_geometry = self.host_geometry.stats();
        std.debug.print("GPU_PCS_NATIVE prepare_ns={} device_ns={} total_ns={} device_bytes={} retained_bytes={} coefficient_cells={} reused_columns={} reused_cells={} host_geometry_hits={} host_geometry_misses={} host_geometry_bytes={} host_geometry_cap={} host_geometry_bypasses={}\n", .{ prepare_ns, result.device_ns, timer.read(), result.requested_bytes, result.retained_bytes, prepared.metadata.coefficient_cells, reused_columns, reused_cells, host_geometry.hits, host_geometry.misses, host_geometry.retained_bytes, host_geometry.limit, host_geometry.bypasses });
        return .{ .proof = decoded.proof, .aux = .{ .unsorted_query_locations = &.{}, .trace_decommitment = core.pcs.TreeVec(core.vcs_lifted.verifier.MerkleDecommitmentLiftedAux(D.H)).initOwned(&.{}), .fri = .{ .first_layer = .{ .all_values = &.{}, .decommitment = .{ .all_node_values = &.{} } }, .inner_layers = &.{} } } };
    }
};

fn phaseCacheTrimEnabled() !bool {
    const value = std.posix.getenv("STWO_RV64_PHASE_CACHE_TRIM") orelse return false;
    if (std.mem.eql(u8, value, "0")) return false;
    if (std.mem.eql(u8, value, "1")) return true;
    return error.InvalidPhaseCacheTrimOption;
}
