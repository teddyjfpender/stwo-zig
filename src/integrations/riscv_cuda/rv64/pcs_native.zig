//! In-process PCS service. Coefficients are borrowed, never serialized to disk.
const std = @import("std");
const core = @import("stwo_core");
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
const Abi = @import("pcs_native_abi.zig");
const Export = @import("pcs_request_export.zig");
const Decode = @import("hybrid_pcs.zig");
const CachedColumn = struct { host: usize, tree: u32, column: usize, count: usize, log: u32, device: D.DeviceCoefficients };
const Cached = struct { scope: [8]u32, lease: Abi.Lease, columns: []CachedColumn, in_use: bool = false, extra: std.ArrayList(Abi.Lease) = .empty };
pub const BlockBudget = struct { device_bytes: u64, immutable_bytes: u64, max_scopes: usize };
const Setup = @import("immutable_setup.zig");
const LiveLeases = *const fn (*anyopaque, *[5]u64, *u64) callconv(.c) c_int;
pub const Context = struct {
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
    pub fn beginBlock(self: *Context, identity: [32]u8, budget: BlockBudget) !void {
        if (self.active_block != null or self.cache.items.len != 0) return error.ResidentBlockStillActive;
        if (budget.device_bytes != self.byte_cap) return error.ResidentDeviceBudgetChanged;
        try self.enableImmutableSetup(budget.immutable_bytes);
        try self.configureRetention(budget.max_scopes);
        try self.requireNoRequestLeases();
        self.active_block = identity;
    }
    pub fn endBlock(self: *Context, identity: [32]u8) !void {
        if (self.active_block == null or !std.mem.eql(u8, &self.active_block.?, &identity)) return error.ResidentBlockIdentityMismatch;
        if (self.cache.items.len != 0) return error.ResidentBlockStillActive;
        try self.requireNoRequestLeases();
        self.active_block = null;
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
    fn requireNoRequestLeases(self: *Context) !void {
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
        if (status != 0) return error.DeviceMainReplayReleaseFailed;
    }

    /// Terminal local proof cleanup, including failure before PCS submission.
    /// Call outside the owner callback only when no live stage borrows this
    /// proof scope. Idempotent after PCS has already released its own custody.
    pub fn finishProofScope(self: *Context, scope: D.Scope) void {
        self.releaseScope(@import("pcs_scope.zig").identity(scope));
    }
    fn releaseScope(self: *Context, scope: [8]u32) void {
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
            _ = self.submit(self.session, ReleaseJob.run, &release_job);
            // A poisoned context is terminal; destroy still owns any lease
            // that could not be released by the owner-thread callback.
            var extra = cached.extra;
            extra.deinit(std.heap.page_allocator);
            std.heap.page_allocator.free(cached.columns);
        } else if (self.immutable_setup != null) {
            var release_job = ReleaseJob{ .self = self, .scope = scope, .lease = null, .extra = &.{} };
            _ = self.submit(self.session, ReleaseJob.run, &release_job);
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
        var library = try std.DynLib.open(path);
        errdefer library.close();
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
        return .{ .byte_cap = capacity, .wide_pcs_framing = wide, .library = library, .session = session.?, .native_prove = native_prove, .release = release, .destroy = destroy, .last_error = last_error, .submit = submit, .lease_allocate = lease_allocate, .lease_validate = lease_validate, .lease_validate_range = lease_validate_range, .lease_release = lease_release };
    }
    pub fn deinit(self: *Context) void {
        self.host_geometry.deinit();
        while (self.cache.items.len != 0) self.releaseScope(self.cache.items[self.cache.items.len - 1].scope);
        self.cache.deinit(std.heap.page_allocator);
        if (self.immutable_setup) |cache| {
            var cleanup = SetupCleanup{ .self = self, .cache = cache };
            _ = self.submit(self.session, SetupCleanup.run, &cleanup);
            cache.freeMetadata();
            std.heap.page_allocator.destroy(cache);
        }
        if (self.destroy(self.session) != 0) @panic("GPU context failed to join before library close");
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
    fn prove(raw: *anyopaque, a: std.mem.Allocator, request: D.Request, channel: *D.Channel) !D.P.ExtendedCommitmentSchemeProof(D.H) {
        const self: *Context = @ptrCast(@alignCast(raw));
        var timer = try std.time.Timer.start();
        const scope = if (request.scope) |value| @import("pcs_scope.zig").identity(value) else [_]u32{0} ** 8;
        defer self.releaseScope(scope);
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
            if (tree_index == 0 and self.immutable_setup != null) {
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
        var result: Abi.Result = .{};
        if (self.native_prove(self.session, &descriptor, &result) != 0) {
            std.debug.print("GPU_PCS_NATIVE error={s}\n", .{self.last_error(self.session)});
            return error.GpuPcsFailed;
        }
        defer self.release(&result);
        if (result.words == null or result.count > (1 << 28)) return error.InvalidGpuPcsProof;
        var decoded = try Decode.decodeWords(a, prepared.metadata.shape, result.words.?[0..@intCast(result.count)]);
        errdefer decoded.proof.deinit(a);
        channel.* = decoded.channel;
        const host_geometry = self.host_geometry.stats();
        std.debug.print("GPU_PCS_NATIVE prepare_ns={} device_ns={} total_ns={} device_bytes={} retained_bytes={} coefficient_cells={} reused_columns={} reused_cells={} host_geometry_hits={} host_geometry_misses={} host_geometry_bytes={} host_geometry_cap={} host_geometry_bypasses={}\n", .{ prepare_ns, result.device_ns, timer.read(), result.requested_bytes, result.retained_bytes, prepared.metadata.coefficient_cells, reused_columns, reused_cells, host_geometry.hits, host_geometry.misses, host_geometry.retained_bytes, host_geometry.limit, host_geometry.bypasses });
        return .{ .proof = decoded.proof, .aux = .{ .unsorted_query_locations = &.{}, .trace_decommitment = core.pcs.TreeVec(core.vcs_lifted.verifier.MerkleDecommitmentLiftedAux(D.H)).initOwned(&.{}), .fri = .{ .first_layer = .{ .all_values = &.{}, .decommitment = .{ .all_node_values = &.{} } }, .inner_layers = &.{} } } };
    }
};
