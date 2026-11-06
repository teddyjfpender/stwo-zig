//! Default-off trusted GPU FIXED precommit. Never used by CPU reception.
const std = @import("std");
const S = @import("outer_source.zig");
const O = @import("stwo_circuit_cpu_integration").om31;
const Dev = O.device_prove;
const Circuit = @import("stwo_circuit_frontend");
const PP = Circuit.common.preprocessed.PreprocessedCircuit;
const D = @import("stwo_prover_api").device_pcs;
const SC = @import("session_context.zig");
const Native = @import("pcs_native_abi.zig");
const Id = @import("pcs_scope.zig");
const Admission = @import("admission_runtime.zig");
const A = @import("global_admission.zig");
pub const Owner = struct {
    allocator: std.mem.Allocator,
    backend: *S.Context,
    pp: *const PP,
    scope: D.Scope,
    raw: Native.Lease = .{},
    inputs: [45]D.TraceColumn = undefined,
    tree: D.Tree = undefined,
    failure: ?anyerror = null,
    permit: ?*Admission.Permit = null,
    handoff: ?A.PrecommitHandoff = null,
    retained_upper: A.Footprint = .{},
    pub fn requireSourceFits(self: *Owner, demand: A.Demand) !void {
        const token = self.handoff orelse return;
        const endpoint = self.backend.service.admission orelse return error.MissingGlobalAdmissionEndpoint;
        try endpoint.planner.requirePrecommitConsumerFits(token, self.retained_upper, demand);
    }
    pub fn sourceEntered(self: *Owner, permit: *Admission.Permit) !void {
        const token = self.handoff orelse return;
        if (permit.endpoint.owner_identity != token.owner) return error.ForeignAdmissionOwner;
        try permit.endpoint.planner.completePrecommitHandoff(token, permit.token);
        self.handoff = null;
    }
    pub fn promote(self: *Owner, next: D.Scope) !void {
        if (!std.mem.eql(u8, &next.fixed, &self.tree.root) or next.ordinal != self.scope.ordinal or std.mem.allEqual(u8, &next.main, 0)) return error.InvalidFixedScopePromotion;
        var job = Promotion{ .owner = self, .next = next };
        const status = self.backend.service.submit(self.backend.service.session, Promotion.run, &job);
        if (job.failure) |err| return err;
        try S.checked(status);
        self.scope = next;
    }
    const Promotion = struct {
        owner: *Owner,
        next: D.Scope,
        failure: ?anyerror = null,
        fn run(_: *anyopaque, _: u64, data: ?*anyopaque) callconv(.c) c_int {
            const self: *@This() = @ptrCast(@alignCast(data.?));
            self.owner.backend.service.promoteSingleRetained(Id.identity(self.owner.scope), Id.identity(self.next), self.owner.backend.trace_commit.rebind) catch |err| {
                self.failure = err;
                return 1;
            };
            return 0;
        }
    };
    fn upload(raw: *anyopaque, token: u64, data: ?*anyopaque) callconv(.c) c_int {
        const self: *Owner = @ptrCast(@alignCast(data.?));
        if (self.permit) |permit| permit.enterOwner(raw) catch |err| {
            self.failure = err;
            return 1;
        };
        var observed = @import("allocation_observer.zig").Range.begin(&self.backend.service.library, raw, self.scope, 1, .fixed_ingress, 0) catch |err| {
            self.failure = err;
            return 1;
        };
        defer observed.deinit();
        self.uploadImpl(raw, token) catch |err| {
            self.failure = err;
            return 1;
        };
        return 0;
    }
    fn uploadImpl(self: *Owner, raw: *anyopaque, token: u64) !void {
        var ctx = SC.Context{ .session = self.backend.service.session, .native_context = raw, .token = token, .scope = Id.identity(self.scope), .api = &self.backend.api };
        defer ctx.active = false;
        var count: usize = 0;
        for (self.pp.columns) |column| count = try std.math.add(usize, count, column.values.len);
        self.raw = try ctx.allocate(count, 0);
        var at: usize = 0;
        for (self.pp.columns, &self.inputs) |column, *out| {
            if (column.values.len == 0 or !std.math.isPowerOfTwo(column.values.len)) return error.InvalidOuterFixedGeometry;
            const words: []const u32 = @ptrCast(column.values);
            try S.checked(self.backend.api.upload(raw, self.raw.words.? + at, words.ptr, words.len * 4));
            out.* = .{ .log_size = column.logSize(), .encoding = .evaluations, .device = .{ .words = self.raw.words.? + at, .count = words.len, .context_token = self.raw.context_token, .generation = self.raw.generation } };
            at += words.len;
        }
        try ctx.join();
    }
    /// M5 platform: MAIN generation of this node re-reads exactly these PP
    /// evaluations through the immutable cache under
    /// `immutableKey(scope with fixed = this tree's root, column)`. The root
    /// commits to these very words, so adopting the resident copy (one device
    /// copy per column) before dropping it replaces a second host upload of
    /// the whole forest. Best effort: any failure leaves the cache unchanged
    /// and MAIN generation uploads as before.
    fn adopt(raw: *anyopaque, _: u64, data: ?*anyopaque) callconv(.c) c_int {
        const self: *Owner = @ptrCast(@alignCast(data.?));
        var observed = @import("allocation_observer.zig").Range.begin(&self.backend.service.library, raw, self.scope, 1, .fixed_adoption, 0) catch |err| {
            self.failure = err;
            std.debug.print("GPU_NODE_ALLOC_COVERAGE_GAP reason=fixed_adoption_begin error={s}\n", .{@errorName(err)});
            return 1;
        };
        defer observed.deinit();
        if (self.raw.words == null) return 0;
        const cache = self.backend.service.immutable_setup orelse return 0;
        if (std.process.hasEnvVarConstant("STWO_RV64_OUTER_FIXED_ADOPT_OFF")) return 0;
        var root_scope = self.scope;
        root_scope.fixed = self.tree.root;
        const source_scope = Id.identity(self.scope);
        defer _ = cache.sync(raw); // one host join for the whole forest
        for (self.inputs, 0..) |input, i| {
            const device = input.device orelse return 0;
            const adopted = cache.adoptDevice(raw, source_scope, @import("outer_source_main.zig").immutableKey(root_scope, i), device.words, device.count, device.context_token, device.generation, false) catch return 0;
            if (!adopted) return 0;
        }
        return 0;
    }
    fn dropRaw(_: *anyopaque, _: u64, data: ?*anyopaque) callconv(.c) c_int {
        const self: *Owner = @ptrCast(@alignCast(data.?));
        if (self.raw.words != null) return self.backend.service.lease_release(self.backend.service.session, &self.raw);
        return 0;
    }
    fn prepare(raw: *anyopaque, a: std.mem.Allocator, key: *const O.prove.Authority, graph: *const Circuit.builder.Context(O.protocol.Q), scope: D.Scope) !Dev.Source {
        const self: *Owner = @ptrCast(@alignCast(raw));
        if (key.pp != self.pp or !key.device_fixed or !std.mem.eql(u8, &key.fixedRoot(), &self.tree.root) or scope.ordinal != self.scope.ordinal) return error.InvalidOuterFixedAuthority;
        try Dev.validateTree(&key.fixed_logs, self.tree);
        var alias_words: u64 = 0;
        for (self.tree.columns) |column| if (column.device) |device| {
            alias_words = try std.math.add(u64, alias_words, device.count);
        };
        @import("allocation_observer.zig").fixedLink(self.scope, scope, alias_words);
        return S.Context.prepareImpl(self.backend, a, key, &.{}, scope, graph, self);
    }
    fn release(raw: *anyopaque) void {
        const self: *Owner = @ptrCast(@alignCast(raw));
        const b = self.backend;
        var cleaned = b.service.submit(b.service.session, dropRaw, self) == 0;
        b.service.finishProofScopeChecked(self.scope) catch {
            cleaned = false;
        };
        // The logical handoff can be canceled only after every PP reader and
        // physical free has joined, including an upload/commit failure.
        if (self.handoff) |token| {
            const Join = struct {
                sync: Native.Sync,
                fn run(ctx: *anyopaque, _: u64, data: ?*anyopaque) callconv(.c) c_int {
                    const job: *@This() = @ptrCast(@alignCast(data.?));
                    return job.sync(ctx);
                }
            };
            var join = Join{ .sync = b.api.sync };
            cleaned = (b.service.submit(b.service.session, Join.run, &join) == 0) and cleaned;
            if (b.service.admission) |endpoint| {
                if (cleaned) endpoint.planner.cancelPrecommitHandoff(token) catch {
                    cleaned = false;
                };
            } else cleaned = false;
        }
        if (!cleaned) if (b.service.admission) |endpoint| endpoint.planner.poisonPhysical(endpoint.physical);
        b.mutex.lock();
        std.debug.assert(b.fixed_pending == self);
        b.fixed_pending = null;
        b.mutex.unlock();
        self.allocator.destroy(self);
    }
};
pub fn precommit(raw: *anyopaque, a: std.mem.Allocator, pp: *const PP, ordinal: u32) !Dev.PrecommittedFixed {
    const b: *S.Context = @ptrCast(@alignCast(raw));
    // All geometry comes from the actual PP owner. Reserve before any lane,
    // cache or owner mutex; no Source authority/progress registry exists yet.
    var logs: [45]u32 = undefined;
    var immutable_sizes: [45]usize = undefined;
    var words: usize = 0;
    for (pp.columns, &logs, &immutable_sizes) |column, *log, *bytes| {
        if (column.values.len == 0 or !std.math.isPowerOfTwo(column.values.len)) return error.InvalidOuterFixedGeometry;
        log.* = column.logSize();
        bytes.* = try std.math.mul(usize, column.values.len, 4);
        words = try std.math.add(usize, words, column.values.len);
    }
    const config = try O.protocol.targetConfig();
    // Idle siblings must shed their previous proof's unborrowed cache BEFORE
    // sleeping on this physical handoff. No peer-controller submission needed.
    if (b.service.admission != null) _ = try b.service.trimUnborrowedJoined("before_pp_handoff");
    var handoff: ?A.PrecommitHandoff = null;
    if (b.service.admission) |endpoint| handoff = try endpoint.planner.acquirePrecommitHandoff(endpoint.physical, endpoint.owner_identity);
    // No Owner/GPU storage exists yet. Once Owner takes this token below,
    // only its joined destruction or actual Source entry can release it.
    errdefer if (handoff) |token| b.service.admission.?.planner.cancelPrecommitHandoff(token) catch {
        b.service.admission.?.planner.poisonPhysical(token.physical);
    };
    var permit: ?Admission.Permit = null;
    if (b.service.admission) |endpoint| {
        var options = b.trace_commit.allocationOptions(config.fri_config.log_blowup_factor);
        options.logs = &logs;
        const tc = try @import("trace_commit_cost.zig").init(a, options);
        const raw_fixed = try A.Footprint.allocation(try std.math.mul(u64, words, 4));
        const coefficients = try A.Footprint.allocation(try std.math.mul(u64, tc.coefficient_words, 4));
        const adoption = try A.Footprint.allocations(&immutable_sizes);
        const commit_peak = try raw_fixed.add(try tc.footprint());
        const adopt_peak = try (try raw_fixed.add(coefficients)).add(adoption);
        permit = try endpoint.reserveDrain(.{ .owner = .{ .request = 0, .domain = .recursion_node, .ordinal = ordinal }, .stage = .trace_commit, .temporary = commit_peak.max(adopt_peak), .stage_retained_upper = try coefficients.add(adoption), .known = true, .host_known = false });
    }
    defer if (permit) |*value| if (!value.closed) closeAdmission(b, value) catch {
        value.endpoint.planner.poisonPhysical(value.endpoint.physical);
    };
    b.mutex.lock();
    var locked = true;
    defer if (locked) b.mutex.unlock();
    if (b.active != null or b.fixed_pending != null) return error.OuterProofAlreadyActive;
    b.fixed_nonce = try std.math.add(u64, b.fixed_nonce, 1);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("circuit/om31/provisional-fixed-owner/v1\x00");
    var word: [8]u8 = undefined;
    std.mem.writeInt(u64, &word, b.fixed_nonce, .little);
    hash.update(&word);
    const scope = D.Scope{ .statement = hash.finalResult(), .fixed = @splat(0), .main = @splat(0), .ordinal = ordinal };
    const self = try a.create(Owner);
    self.* = .{ .allocator = a, .backend = b, .pp = pp, .scope = scope, .permit = if (permit) |*value| value else null, .handoff = handoff, .retained_upper = if (permit) |value| value.demand.stage_retained_upper else .{} };
    handoff = null;
    b.fixed_pending = self;
    b.mutex.unlock();
    locked = false;
    errdefer Owner.release(self);
    const status = b.service.submit(b.service.session, Owner.upload, self);
    if (self.failure) |err| return err;
    try S.checked(status);
    const request = D.TraceCommitRequest{ .scope = scope, .config = config, .tree_index = 0, .columns = &self.inputs };
    self.tree = if (permit) |*value| try b.trace_commit.commitFixedAdmitted(a, request, value) else try b.trace_commit.commitFixed(a, request);
    _ = b.service.submit(b.service.session, Owner.adopt, self);
    try S.checked(b.service.submit(b.service.session, Owner.dropRaw, self));
    if (permit) |*value| try closeAdmission(b, value);
    self.permit = null;
    try Dev.validateTree(&logs, self.tree);
    return .{ .context = self, .controller = b.controller(), .tree = self.tree, .scope = scope, .prepare_from_circuit = Owner.prepare, .release = Owner.release };
}

fn closeAdmission(b: *S.Context, permit: *Admission.Permit) !void {
    if (permit.entered and permit.after == null) {
        const End = struct {
            permit: *Admission.Permit,
            sync: Native.Sync,
            failure: ?anyerror = null,
            fn run(raw: *anyopaque, _: u64, data: ?*anyopaque) callconv(.c) c_int {
                const self: *@This() = @ptrCast(@alignCast(data.?));
                S.checked(self.sync(raw)) catch |err| {
                    self.failure = err;
                    return 1;
                };
                self.permit.leaveOwner(raw) catch |err| {
                    self.failure = err;
                    return 1;
                };
                return 0;
            }
        };
        var end = End{ .permit = permit, .sync = b.api.sync };
        const status = b.service.submit(b.service.session, End.run, &end);
        if (end.failure) |err| return err;
        try S.checked(status);
    }
    try permit.finish(.{});
}
