//! In-process PCS service. Coefficients are borrowed, never serialized to disk.
const std = @import("std");
const core = @import("stwo_core");
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
const Abi = @import("pcs_native_abi.zig");
const Export = @import("pcs_request_export.zig");
const Decode = @import("hybrid_pcs.zig");
const CachedColumn = struct { host: usize, tree: u32, column: usize, count: usize, log: u32, device: D.DeviceCoefficients };
const Cached = struct { scope: [8]u32, lease: Abi.Lease, columns: []CachedColumn, in_use: bool = false, extra: std.ArrayList(Abi.Lease) = .empty };
pub const Context = struct {
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
            var release_job = ReleaseJob{ .self = self, .lease = cached.lease, .extra = cached.extra.items };
            _ = self.submit(self.session, ReleaseJob.run, &release_job);
            // A poisoned context is terminal; destroy still owns any lease
            // that could not be released by the owner-thread callback.
            var extra = cached.extra;
            extra.deinit(std.heap.page_allocator);
            std.heap.page_allocator.free(cached.columns);
        }
    }
    const ReleaseJob = struct {
        self: *Context,
        lease: Abi.Lease,
        extra: []const Abi.Lease,
        fn run(_: *anyopaque, _: u64, raw: ?*anyopaque) callconv(.c) c_int {
            const job: *@This() = @ptrCast(@alignCast(raw.?));
            if (job.self.lease_release(job.self.session, &job.lease) != 0) return 1;
            for (job.extra) |lease| {
                var owned = lease;
                if (job.self.lease_release(job.self.session, &owned) != 0) return 1;
            }
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
        return .{ .library = library, .session = session.?, .native_prove = native_prove, .release = release, .destroy = destroy, .last_error = last_error, .submit = submit, .lease_allocate = lease_allocate, .lease_validate = lease_validate, .lease_validate_range = lease_validate_range, .lease_release = lease_release };
    }
    pub fn deinit(self: *Context) void {
        while (self.cache.items.len != 0) self.releaseScope(self.cache.items[self.cache.items.len - 1].scope);
        self.cache.deinit(std.heap.page_allocator);
        if (self.destroy(self.session) != 0) @panic("GPU context failed to join before library close");
        self.library.close();
        self.* = undefined;
    }
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
        var prepared = try Export.prepareRequest(a, resident_request, channel.*);
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
        std.debug.print("GPU_PCS_NATIVE prepare_ns={} device_ns={} total_ns={} device_bytes={} retained_bytes={} coefficient_cells={} reused_columns={} reused_cells={}\n", .{ prepare_ns, result.device_ns, timer.read(), result.requested_bytes, result.retained_bytes, prepared.metadata.coefficient_cells, reused_columns, reused_cells });
        return .{ .proof = decoded.proof, .aux = .{ .unsorted_query_locations = &.{}, .trace_decommitment = core.pcs.TreeVec(core.vcs_lifted.verifier.MerkleDecommitmentLiftedAux(D.H)).initOwned(&.{}), .fri = .{ .first_layer = .{ .all_values = &.{}, .decommitment = .{ .all_node_values = &.{} } }, .inner_layers = &.{} } } };
    }
};
