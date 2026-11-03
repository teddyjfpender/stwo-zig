//! Scoped deferred binding ownership. Raw N/D stay on CUDA between numerical
//! traversal and native artifact admission; only eight P=N+etaD columns survive
//! that admission. Final Eq/prefix coefficients are device-only trace inputs.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Child = @import("stwo_riscv_cpu_integration").rv64_gkr_child;
const Frame = @import("projection_codegen.zig").Source.Frame;
const B = Child.DeviceBinding;
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
const Native = @import("pcs_native_abi.zig");
const SC = @import("session_context.zig");
const N = @import("runtime_api.zig");
const R = @import("resident.zig");
const A = @import("abi.zig");
const Slice = @import("stwo_cuda_backend").runtime.column.DeviceSlice(u32);
const Deferred = extern struct { n: A.Plane, d: A.Plane, output: A.Plane, metadata: [*]const u32, status: [*]u32, row_log: u32, lane_log: u32, reserved: [2]u32 = @splat(0) };
const Finalize = extern struct { projection: A.Plane, eq: A.Plane, output: A.Plane, metadata: [*]const u32, status: [*]u32, row_log: u32, reserved: [3]u32 = @splat(0) };
const DeferredFn = *const fn (*anyopaque, u32, *const Deferred) callconv(.c) c_int;
const FinalizeFn = *const fn (*anyopaque, u32, *const Finalize) callconv(.c) c_int;
const B2n = *const fn ([*]const u32, usize, [*]u32, usize, u32, u32, [*]const u32, u32, u32, *anyopaque, *u32) callconv(.c) c_int;
fn check(status: c_int) !void {
    if (status != 0) return error.CudaDeviceBindingFailed;
}
fn symbol(comptime T: type, library: *std.DynLib, name: [:0]const u8) !T {
    return library.lookup(T, name) orelse error.MissingCudaDeviceBindingSymbol;
}
comptime {
    if (@sizeOf(Deferred) != 104 or @sizeOf(Finalize) != 104) @compileError("deferred binding ABI changed");
}
pub const Pending = struct {
    scope: @TypeOf(@as(Child.NumericalStage.Request, undefined).scope),
    instances: []Frame.Instance,
    fractions: []R.Fraction,
    leases: []Native.Lease,
    state: Slice,
    state_words: [A.gkr_state_words]u32,
    layers: u32,
    chain: u64,
};
pub const Runtime = struct {
    allocator: std.mem.Allocator,
    session: *anyopaque,
    session_api: SC.Api,
    numerical: N.Api,
    submit: Native.Submit,
    deferred: DeferredFn,
    finish: FinalizeFn,
    b2n: B2n,
    mutex: std.Thread.Mutex = .{},
    locked_scope: ?@TypeOf(@as(Pending, undefined).scope) = null,
    pending: ?Pending = null,
    pub fn create(a: std.mem.Allocator, library: *std.DynLib, session: *anyopaque, session_api: SC.Api, numerical: N.Api) !*Runtime {
        const out = try a.create(Runtime);
        errdefer a.destroy(out);
        out.* = .{ .allocator = a, .session = session, .session_api = session_api, .numerical = numerical, .submit = try symbol(Native.Submit, library, "stwo_rv64_gpu_session_submit"), .deferred = try symbol(DeferredFn, library, "stwo_rv64_binding_deferred_on"), .finish = try symbol(FinalizeFn, library, "stwo_rv64_binding_finalize_on"), .b2n = try symbol(B2n, library, "stwo_ntt_b2n_columns_compact_on") };
        return out;
    }
    pub fn destroy(self: *Runtime) void {
        std.debug.assert(self.pending == null and self.locked_scope == null);
        const a = self.allocator;
        a.destroy(self);
    }
    pub fn acquire(self: *Runtime, scope: @TypeOf(@as(Pending, undefined).scope)) void {
        self.mutex.lock();
        std.debug.assert(self.pending == null);
        self.locked_scope = scope;
    }
    /// Consumes the pending leases on success. Metadata uses the runtime owner,
    /// never the Child budget address which can disappear on an abort path.
    pub fn install(self: *Runtime, scope: @TypeOf(@as(Pending, undefined).scope), instances: []const Frame.Instance, fractions: []const R.Fraction, leases: []const Native.Lease, state: Slice, words: [A.gkr_state_words]u32, layers: u32, chain: u64) !void {
        if (self.locked_scope == null or !std.meta.eql(self.locked_scope.?, scope) or self.pending != null) return error.DeviceBindingScopeMismatch;
        const own_instances = try self.allocator.dupe(Frame.Instance, instances);
        errdefer self.allocator.free(own_instances);
        const own_fractions = try self.allocator.dupe(R.Fraction, fractions);
        errdefer self.allocator.free(own_fractions);
        const own_leases = try self.allocator.dupe(Native.Lease, leases);
        self.pending = .{ .scope = scope, .instances = own_instances, .fractions = own_fractions, .leases = own_leases, .state = state, .state_words = words, .layers = layers, .chain = chain };
    }
    pub fn abort(self: *Runtime, scope: @TypeOf(@as(Pending, undefined).scope)) void {
        const locked = self.locked_scope orelse return;
        if (!std.meta.eql(locked, scope)) return;
        if (self.pending) |p| {
            var cleanup = Cleanup{ .runtime = self, .pending = p };
            _ = self.submit(self.session, Cleanup.callback, &cleanup);
            self.pending = null;
        }
        self.locked_scope = null;
        self.mutex.unlock();
    }
    /// Called after native partial verification and eta derivation. The call
    /// always retires the raw pending job on failure and releases its mutex.
    pub fn bind(self: *Runtime, a: std.mem.Allocator, request: B.Request) !B.Owner {
        var success = false;
        defer if (!success) self.abort(request.scope);
        const pending = self.pending orelse return error.DeviceBindingUnavailable;
        if (!std.meta.eql(pending.scope, request.scope)) return error.DeviceBindingScopeMismatch;
        const authority = try B.authority(request);
        try validateArtifact(pending, request);
        const owner = try self.allocator.create(Owner);
        owner.* = .{ .runtime = self, .pending = pending, .authority = authority, .receipt = request.receipt_digest };
        self.pending = null;
        errdefer Owner.release(owner);
        var call = Call{ .owner = owner, .kind = .project };
        const status = self.submit(self.session, Call.callback, &call);
        if (call.failure) |err| return err;
        try check(status);
        self.pending = null;
        self.locked_scope = null;
        self.mutex.unlock();
        success = true;
        _ = a;
        return .{ .context = owner, .scope = request.scope, .receipt_digest = request.receipt_digest, .authority_digest = owner.authority, .retained_bytes = owner.retainedBytes(), .finalize_fn = Owner.finalize, .release_fn = Owner.release };
    }
};
fn validateArtifact(pending: Pending, request: B.Request) !void {
    if (request.instances.len != pending.instances.len or request.artifact.ood_point.len != pending.layers) return error.DeviceBindingAuthorityMismatch;
    for (pending.instances, request.instances, 0..) |expected, actual, i| {
        if (!std.meta.eql(expected, actual) or request.artifact.n_variables_by_instance[i] != try actual.variables()) return error.DeviceBindingAuthorityMismatch;
        const claims = request.artifact.claims_to_verify_by_instance[i];
        if (claims.len != 2) return error.DeviceBindingAuthorityMismatch;
        for (claims, 0..) |value, c| for (value.toM31Array(), 0..) |word, k| if (word.v != pending.state_words[A.gkr_claims_word + 16 * i + 8 * c + k]) return error.DeviceBindingAuthorityMismatch;
    }
    for (request.artifact.ood_point, 0..) |value, i| for (value.toM31Array(), 0..) |word, k| if (word.v != pending.state_words[A.gkr_point_word + 8 * i + k]) return error.DeviceBindingAuthorityMismatch;
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    for (0..8) |i| std.mem.writeInt(u32, channel.inner.digest[4 * i ..][0..4], pending.state_words[i], .little);
    channel.inner.n_draws = pending.state_words[8];
    if (!channel.drawSecureFelt().eql(request.eta)) return error.DeviceBindingAuthorityMismatch;
}
const Cleanup = struct {
    runtime: *Runtime,
    pending: Pending,
    fn callback(ctx: *anyopaque, token: u64, raw: ?*anyopaque) callconv(.c) c_int {
        const self: *Cleanup = @ptrCast(@alignCast(raw.?));
        var context = makeContext(self.runtime, self.pending.scope, ctx, token);
        for (self.pending.leases) |lease| {
            var own = lease;
            context.release(&own) catch {};
        }
        self.runtime.allocator.free(self.pending.leases);
        self.runtime.allocator.free(self.pending.fractions);
        self.runtime.allocator.free(self.pending.instances);
        return 0;
    }
};
fn makeContext(runtime: *Runtime, scope: anytype, ctx: *anyopaque, token: u64) SC.Context {
    return .{ .session = runtime.session, .native_context = ctx, .token = token, .scope = @import("pcs_scope.zig").identity(scope), .api = &runtime.session_api };
}
const Owner = struct {
    runtime: *Runtime,
    pending: Pending,
    authority: [32]u8,
    receipt: [32]u8,
    projection: ?Native.Lease = null,
    coefficients: ?Native.Lease = null,
    fn retainedBytes(self: *Owner) usize {
        var n: usize = 0;
        for (self.pending.leases) |l| n += @intCast(l.count * 4);
        if (self.projection) |l| n += @intCast(l.count * 4);
        if (self.coefficients) |l| n += @intCast(l.count * 4);
        return n;
    }
    fn finalize(raw: *anyopaque, a: std.mem.Allocator, request: B.Request) !B.Completion {
        const self: *Owner = @ptrCast(@alignCast(raw));
        if (!std.mem.eql(u8, &self.authority, &(try B.authority(request)))) return error.DeviceBindingAuthorityMismatch;
        if (self.coefficients == null) {
            var call = Call{ .owner = self, .kind = .finalize };
            const status = self.runtime.submit(self.runtime.session, Call.callback, &call);
            if (call.failure) |err| return err;
            try check(status);
        }
        const lease = self.coefficients.?;
        const columns = try a.alloc(D.Column, self.pending.instances.len * 16);
        errdefer a.free(columns);
        var at: usize = 0;
        for (self.pending.instances, 0..) |instance, i| {
            const rows = try instance.rows();
            for (columns[i * 16 ..][0..16]) |*column| {
                column.* = .{ .log_size = instance.row_log, .device = .{ .words = lease.words.? + at, .count = rows, .context_token = lease.context_token, .generation = lease.generation } };
                at += rows;
            }
        }
        return .{ .columns = columns, .retained_bytes = self.retainedBytes() };
    }
    fn release(raw: *anyopaque) void {
        const self: *Owner = @ptrCast(@alignCast(raw));
        var call = Call{ .owner = self, .kind = .release };
        _ = self.runtime.submit(self.runtime.session, Call.callback, &call);
        self.runtime.allocator.destroy(self);
    }
};
const Call = struct {
    owner: *Owner,
    kind: enum { project, finalize, release },
    failure: ?anyerror = null,
    fn callback(ctx: *anyopaque, token: u64, raw: ?*anyopaque) callconv(.c) c_int {
        const self: *Call = @ptrCast(@alignCast(raw.?));
        self.run(ctx, token) catch |err| {
            self.failure = err;
            return 1;
        };
        return 0;
    }
    fn run(self: *Call, ctx: *anyopaque, token: u64) !void {
        const owner = self.owner;
        const runtime = owner.runtime;
        const a = runtime.allocator;
        var context = makeContext(runtime, owner.pending.scope, ctx, token);
        if (self.kind == .release) {
            if (owner.projection) |lease| {
                var v = lease;
                try context.release(&v);
            }
            if (owner.coefficients) |lease| {
                var v = lease;
                try context.release(&v);
            }
            var cleanup = Cleanup{ .runtime = runtime, .pending = owner.pending };
            _ = Cleanup.callback(ctx, token, &cleanup);
            return;
        }
        var temporary: std.ArrayList(Native.Lease) = .empty;
        defer {
            for (temporary.items) |*l| context.release(l) catch {};
            temporary.deinit(a);
        }
        const metadata = try alloc(a, &context, &temporary, 260 * 8, 0);
        const point = try alloc(a, &context, &temporary, 22 * 8, 0);
        const carry = try alloc(a, &context, &temporary, 22 * 16, 0);
        const seed = try alloc(a, &context, &temporary, 9, 0);
        const status = try alloc(a, &context, &temporary, 1, 0);
        try context.upload(status, &.{0});
        var total_rows: usize = 0;
        var max_log: u32 = 0;
        for (owner.pending.instances) |instance| {
            total_rows += try instance.rows();
            max_log = @max(max_log, instance.row_log);
        }
        var output_lease = try context.allocate(total_rows * (if (self.kind == .project) @as(usize, 8) else 16), if (self.kind == .project) 3 else 2);
        errdefer context.release(&output_lease) catch {};
        const output = try context.borrow(output_lease);
        var tw: Slice = undefined;
        var scratch: Slice = undefined;
        var claim: Slice = undefined;
        if (self.kind == .finalize) {
            var tree = try engine.poly.twiddles.precomputeM31(a, core.poly.circle.canonic.CanonicCoset.new(max_log).circleDomain().half_coset);
            defer engine.poly.twiddles.deinitM31(a, &tree);
            tw = try alloc(a, &context, &temporary, tree.itwiddles.len, 0);
            try context.upload(tw, @as([*]const u32, @ptrCast(tree.itwiddles.ptr))[0..tree.itwiddles.len]);
            const p = try @import("prefix_plan.zig").Plan.init(max_log);
            scratch = try alloc(a, &context, &temporary, p.scratch_words, 0);
            claim = try alloc(a, &context, &temporary, 8, 0);
        }
        try context.join();
        var stream: ?*anyopaque = null;
        try check(runtime.session_api.lane_stream(ctx, 1, &stream));
        var commands = R.Commands(SC.Context, N.Api){ .context = &context, .api = &runtime.numerical, .lane_index = 1 };
        var offset: usize = 0;
        for (owner.pending.instances, 0..) |instance, i| {
            const rows: u32 = @intCast(try instance.rows());
            const lane_log = try instance.laneLog();
            try commands.deriveBindingMetadata(owner.pending.state, metadata, point, carry, seed, status, @intCast(i), instance.row_log, lane_log, @intCast(owner.pending.instances.len), owner.pending.layers, owner.pending.chain);
            if (self.kind == .project) {
                const dest = try output.sub(offset, 8 * @as(usize, rows));
                const fraction = owner.pending.fractions[i];
                const job = Deferred{ .n = try fraction.n.bind(&context), .d = try fraction.d.bind(&context), .output = try (R.Plane{ .data = dest, .stride = rows, .coordinates = 8 }).bind(&context), .metadata = try context.deviceSlicePointer(u32, metadata, 260 * 8), .status = try context.deviceSlicePointer(u32, status, 1), .row_log = instance.row_log, .lane_log = lane_log };
                try check(runtime.deferred(ctx, 1, &job));
                offset += 8 * @as(usize, rows);
            } else {
                const eq = R.Plane{ .data = try output.sub(offset, 8 * @as(usize, rows)), .stride = rows, .coordinates = 8 };
                const prefix = R.Plane{ .data = try output.sub(offset + 8 * @as(usize, rows), 8 * @as(usize, rows)), .stride = rows, .coordinates = 8 };
                try commands.buildBindingEq(point, instance.row_log, eq, status);
                var projection_offset: usize = 0;
                for (owner.pending.instances[0..i]) |previous| projection_offset += 8 * try previous.rows();
                const projection = R.Plane{ .data = try (try context.borrow(owner.projection.?)).sub(projection_offset, 8 * @as(usize, rows)), .stride = rows, .coordinates = 8 };
                const job = Finalize{ .projection = try projection.bind(&context), .eq = try eq.bind(&context), .output = try prefix.bind(&context), .metadata = try context.deviceSlicePointer(u32, metadata, 260 * 8), .status = try context.deviceSlicePointer(u32, status, 1), .row_log = instance.row_log };
                try check(runtime.finish(ctx, 1, &job));
                try commands.scanPrefix(prefix, scratch, claim, status, instance.row_log, false);
                const half = @as(u32, 1) << @intCast(instance.row_log - 1);
                var launches: u32 = 0;
                const from = try context.deviceSlicePointer(u32, try output.sub(offset, 16 * @as(usize, rows)), 16 * @as(usize, rows));
                try check(runtime.b2n(from, rows, from, rows, instance.row_log, 16, try context.deviceSlicePointer(u32, try tw.sub(tw.len - half, half), half), half, half, stream.?, &launches));
                offset += 16 * @as(usize, rows);
            }
        }
        try context.join();
        var verdict: [1]u32 = undefined;
        try context.download(status, &verdict);
        try context.join();
        if (verdict[0] != 0) return error.DeviceBindingWitnessRejected;
        if (self.kind == .project) {
            const kept = try a.alloc(Native.Lease, 1);
            errdefer a.free(kept);
            var state_found = false;
            for (owner.pending.leases) |lease| if (lease.generation == owner.pending.state.generation) {
                kept[0] = lease;
                state_found = true;
            };
            if (!state_found) return error.DeviceBindingUnavailable;
            for (owner.pending.leases) |lease| if (lease.generation != owner.pending.state.generation) {
                var own = lease;
                try context.release(&own);
            };
            a.free(owner.pending.leases);
            owner.pending.leases = kept;
            a.free(owner.pending.fractions);
            owner.pending.fractions = &.{};
            owner.projection = output_lease;
        } else {
            var old = owner.projection.?;
            try context.release(&old);
            owner.projection = null;
            owner.coefficients = output_lease;
        }
    }
};
fn alloc(a: std.mem.Allocator, context: *SC.Context, leases: *std.ArrayList(Native.Lease), words: usize, kind: u32) !Slice {
    var lease = try context.allocate(words, kind);
    errdefer context.release(&lease) catch {};
    try leases.append(a, lease);
    return context.borrow(lease);
}

test "device binding runtime callbacks are typed without CUDA linkage" {
    _ = &Runtime.create;
    _ = &Runtime.bind;
}
