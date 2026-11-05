//! Concrete RV64 resident-device routing. Native physical worker ordinals select
//! one GPU for every stage, including both sides of the global-manifest barrier.
//! Retained scope counts are explicit planning bounds, not semaphores: stage
//! one cannot wait for phase two to release memory before that barrier. The
//! native byte allocator independently enforces actual device residency.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const D = CPU.rv64_device_pcs;
const Child = CPU.rv64_gkr_child;
const Worker = CPU.rv64_gkr_cpu_worker;
const Items = CPU.rv64_gkr_cpu_components;
const Source = CPU.rv64_cpu_source;
const Proof = @import("stwo_prover_engine").lookups.gkr_verifier.ForField(D.O).GkrBatchProof;
const GkrScope = @TypeOf(@as(Child.NumericalStage.Request, undefined).scope);
const BindingRequest = if (@hasDecl(Child, "DeviceBinding")) Child.DeviceBinding.Request else void;
const BindingOwner = if (@hasDecl(Child, "DeviceBinding")) Child.DeviceBinding.Owner else void;
pub const MAX_DEVICES = 8;
pub const SCOPES_PER_DEVICE = 2;
pub const MAX_SCOPES_PER_DEVICE = 64;
pub const DEFAULT_BYTES: u64 = 24 * 1024 * 1024 * 1024;
pub const Config = struct {
    ids: []u32,
    caps: []u64,
    scope_limit: usize = SCOPES_PER_DEVICE,
    pub fn deinit(self: *Config, a: std.mem.Allocator) void {
        a.free(self.ids);
        a.free(self.caps);
        self.* = undefined;
    }
    /// Explicit lists are local CUDA ordinals after CUDA_VISIBLE_DEVICES.
    pub fn parse(a: std.mem.Allocator, devices: []const u8, byte_caps: ?[]const u8) !Config {
        var ids: std.ArrayList(u32) = .empty;
        defer ids.deinit(a);
        var parts = std.mem.splitScalar(u8, devices, ',');
        while (parts.next()) |part| {
            const text = std.mem.trim(u8, part, " \t");
            if (text.len == 0 or ids.items.len >= MAX_DEVICES) return error.InvalidResidentDeviceList;
            const id = std.fmt.parseInt(u32, text, 10) catch return error.InvalidResidentDeviceList;
            for (ids.items) |old| if (old == id) return error.DuplicateResidentDevice;
            try ids.append(a, id);
        }
        if (ids.items.len == 0) return error.InvalidResidentDeviceList;
        const caps = try a.alloc(u64, ids.items.len);
        errdefer a.free(caps);
        @memset(caps, DEFAULT_BYTES);
        if (byte_caps) |values| {
            var cap_parts = std.mem.splitScalar(u8, values, ',');
            var count: usize = 0;
            while (cap_parts.next()) |part| {
                if (count >= caps.len) return error.InvalidResidentDeviceCaps;
                const text = std.mem.trim(u8, part, " \t");
                caps[count] = std.fmt.parseInt(u64, text, 10) catch return error.InvalidResidentDeviceCaps;
                if (caps[count] == 0) return error.InvalidResidentDeviceCaps;
                count += 1;
            }
            if (count != caps.len) return error.InvalidResidentDeviceCaps;
        }
        return .{ .ids = try ids.toOwnedSlice(a), .caps = caps };
    }
    pub fn fromEnv(a: std.mem.Allocator) !Config {
        const ids = std.process.getEnvVarOwned(a, "STWO_RV64_GPU_DEVICES") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        defer if (ids) |value| a.free(value);
        const caps = std.process.getEnvVarOwned(a, "STWO_RV64_GPU_DEVICE_CAPS") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        defer if (caps) |value| a.free(value);
        var config = try parse(a, ids orelse "0", caps);
        errdefer config.deinit(a);
        const scopes = std.process.getEnvVarOwned(a, "STWO_RV64_GPU_RETAINED_SCOPES") catch |err| switch (err) {
            error.EnvironmentVariableNotFound => null,
            else => return err,
        };
        defer if (scopes) |value| a.free(value);
        if (scopes) |value| config.scope_limit = std.fmt.parseInt(usize, value, 10) catch return error.InvalidResidentScopeLimit;
        if (config.scope_limit == 0 or config.scope_limit > MAX_SCOPES_PER_DEVICE) return error.InvalidResidentScopeLimit;
        return config;
    }
    pub fn validatePlan(self: Config, cpu_workers: usize) !void {
        if (self.ids.len == 0 or self.ids.len > MAX_DEVICES or self.caps.len != self.ids.len or cpu_workers == 0) return error.InvalidResidentPlan;
        if (self.scope_limit == 0 or self.scope_limit > MAX_SCOPES_PER_DEVICE) return error.InvalidResidentScopeLimit;
        if (cpu_workers > self.scope_limit * self.ids.len) return error.InsufficientResidentCapacity;
        for (self.ids, self.caps, 0..) |id, cap, i| {
            if (cap == 0) return error.InvalidResidentDeviceCaps;
            for (self.ids[0..i]) |previous| if (id == previous) return error.DuplicateResidentDevice;
        }
    }
};
pub const Endpoint = struct {
    cpu_replay: ?CPU.rv64_gkr_cpu_replay.Stage = null,
    truth_source: ?CPU.rv64_gkr_truth_device_source.Stage = null,
    truth_composition: ?CPU.rv64_gkr_truth_device_composition.Stage = null,
    source: ?CPU.rv64_device_source_stage = null,
    global_interaction: ?Worker.DeviceGlobal.Stage = null,
    device: u32,
    byte_cap: u64,
    pcs: D.Stage,
    numerical: Child.NumericalStage,
    composition: Worker.ResidentCompositionStage,
    trace_commit: D.TraceCommitStage,
    projection: Source.ProjectionStage,
};
const Record = struct { scope: D.Scope, main_bound: bool };
const Phase = enum { capture, main, numerical, retained };
fn nativeScope(scope: GkrScope) D.Scope {
    return .{ .statement = scope.statement, .fixed = scope.fixed, .main = scope.main, .ordinal = scope.ordinal };
}
fn sameWorker(a: D.Scope, b: D.Scope) bool {
    return a.ordinal == b.ordinal and std.mem.eql(u8, &a.statement, &b.statement) and std.mem.eql(u8, &a.fixed, &b.fixed);
}
fn zeroRoot(root: [32]u8) bool {
    return std.mem.allEqual(u8, &root, 0);
}
pub const Router = struct {
    endpoints: []const Endpoint,
    planned_cpu_workers: usize,
    scope_limit: usize = SCOPES_PER_DEVICE,
    records: [MAX_DEVICES][MAX_SCOPES_PER_DEVICE]?Record = @splat(@splat(null)),
    mutex: std.Thread.Mutex = .{},
    pub fn init(endpoints: []const Endpoint, cpu_workers: usize) !Router {
        return initWithCapacity(endpoints, cpu_workers, SCOPES_PER_DEVICE);
    }
    pub fn initWithCapacity(endpoints: []const Endpoint, cpu_workers: usize, scope_limit: usize) !Router {
        if (scope_limit == 0 or scope_limit > MAX_SCOPES_PER_DEVICE) return error.InvalidResidentScopeLimit;
        if (endpoints.len == 0 or endpoints.len > MAX_DEVICES or cpu_workers == 0) return error.InvalidResidentPlan;
        if (cpu_workers > scope_limit * endpoints.len) return error.InsufficientResidentCapacity;
        for (endpoints, 0..) |endpoint, i| {
            if (endpoint.byte_cap == 0) return error.InvalidResidentDeviceCaps;
            for (endpoints[0..i]) |prior| if (prior.device == endpoint.device) return error.DuplicateResidentDevice;
        }
        return .{ .endpoints = endpoints, .planned_cpu_workers = cpu_workers, .scope_limit = scope_limit };
    }
    /// A new execution reuses the same physical endpoints only after every old
    /// CPU scope has closed. Truth ordinals are relative to this exact CPU count.
    pub fn replan(self: *Router, cpu_workers: usize) !void {
        if (cpu_workers == 0 or cpu_workers > self.endpoints.len * self.scope_limit) return error.InvalidResidentPlan;
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.records) |records| for (records) |record| if (record != null) return error.ResidentBlockStillActive;
        self.planned_cpu_workers = cpu_workers;
    }
    pub fn deviceFor(self: *const Router, ordinal: u32) u32 {
        return self.endpoints[ordinal % self.endpoints.len].device;
    }
    fn admit(self: *Router, scope: D.Scope, phase: Phase) !usize {
        if (scope.ordinal >= self.planned_cpu_workers) return error.UnplannedResidentWorker;
        if (zeroRoot(scope.statement) or zeroRoot(scope.fixed)) return error.MissingResidentScope;
        if ((phase == .numerical or phase == .retained) == zeroRoot(scope.main)) return error.InvalidResidentScopePhase;
        const index = scope.ordinal % self.endpoints.len;
        self.mutex.lock();
        defer self.mutex.unlock();
        var empty: ?usize = null;
        for (self.records[index][0..self.scope_limit], 0..) |*slot, slot_index| {
            if (slot.*) |record| {
                if (record.scope.ordinal != scope.ordinal) continue;
                if (!sameWorker(record.scope, scope)) return error.ResidentWorkerIdentityMismatch;
                if (record.main_bound and !std.mem.eql(u8, &record.scope.main, &scope.main)) return error.ResidentMainRootMismatch;
                if (!record.main_bound) {
                    if (phase == .retained) return error.MissingResidentMainRoot;
                    if (phase == .numerical) slot.* = .{ .scope = scope, .main_bound = true };
                }
                return index;
            } else if (empty == null) {
                empty = slot_index;
            }
        }
        if (phase == .retained) return error.MissingResidentAdmission;
        const free = empty orelse return error.InsufficientResidentCapacity;
        self.records[index][free] = .{ .scope = scope, .main_bound = phase == .numerical or phase == .retained };
        return index;
    }
    fn promote(self: *Router, scope: D.Scope, root: [32]u8) !void {
        if (zeroRoot(root)) return error.MissingResidentMainRoot;
        self.mutex.lock();
        defer self.mutex.unlock();
        for (&self.records[scope.ordinal % self.endpoints.len]) |*slot| if (slot.*) |record| {
            if (!sameWorker(record.scope, scope)) continue;
            if (record.main_bound) return error.ResidentMainAlreadyCommitted;
            var full = scope;
            full.main = root;
            slot.* = .{ .scope = full, .main_bound = true };
            return;
        };
        return error.MissingResidentAdmission;
    }
    fn drop(self: *Router, scope: D.Scope) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (&self.records[scope.ordinal % self.endpoints.len]) |*slot| if (slot.*) |record| {
            if (sameWorker(record.scope, scope) and (!record.main_bound or std.mem.eql(u8, &record.scope.main, &scope.main))) {
                slot.* = null;
                return;
            }
        };
    }
    pub fn pcsStage(self: *Router) D.Stage {
        return .{ .context = self, .prove = pcs };
    }
    pub fn truthPcsStage(self: *Router) D.Stage {
        return .{ .context = self, .prove = truthPcs };
    }
    pub fn numericalStage(self: *Router) Child.NumericalStage {
        var stage = Child.NumericalStage{ .context = self, .prove = numerical };
        if (comptime @hasField(Child.NumericalStage, "bind")) {
            var supported = true;
            for (self.endpoints) |endpoint| supported = supported and endpoint.numerical.bind != null;
            if (supported) stage.bind = bind;
        }
        if (comptime @hasField(Child.NumericalStage, "abort")) stage.abort = abort;
        if (comptime @hasField(Child.NumericalStage, "replay_binding")) stage.replay_binding = replayBinding;
        return stage;
    }
    fn replayBinding(raw: *anyopaque, a: std.mem.Allocator, request: Child.NumericalStage.Request, owner: *Child.DeviceBinding.Owner) !void {
        const self: *Router = @ptrCast(@alignCast(raw));
        const index = try self.admit(nativeScope(request.scope), .retained);
        const stage = self.endpoints[index].numerical;
        try (stage.replay_binding orelse return error.DeviceBindingReplayUnavailable)(stage.context, a, request, owner);
    }
    pub fn cpuReplayStage(self: *Router) CPU.rv64_gkr_cpu_replay.Stage {
        return .{ .context = self, .estimate = replayEstimate, .prepare = replayPrepare };
    }
    fn replayEstimate(raw: *anyopaque, request: CPU.rv64_device_source_stage.Request) !usize {
        const self: *Router = @ptrCast(@alignCast(raw));
        if (request.ordinal >= self.planned_cpu_workers) return error.UnplannedResidentWorker;
        const stage = self.endpoints[request.ordinal % self.endpoints.len].cpu_replay orelse return error.CpuReplayUnavailable;
        return stage.estimate(stage.context, request);
    }
    fn replayPrepare(raw: *anyopaque, a: std.mem.Allocator, request: CPU.rv64_device_source_stage.Request) !CPU.rv64_gkr_cpu_replay.Owner {
        const self: *Router = @ptrCast(@alignCast(raw));
        const index = try self.admit(request.scope, .capture);
        const stage = self.endpoints[index].cpu_replay orelse return error.CpuReplayUnavailable;
        return stage.prepare(stage.context, a, request);
    }
    pub fn compositionStage(self: *Router) Worker.ResidentCompositionStage {
        return .{ .context = self, .evaluate_and_commit = composition };
    }
    pub fn traceStage(self: *Router) D.TraceCommitStage {
        return .{ .context = self, .commit = traceCommit };
    }
    pub fn globalStage(self: *Router) Worker.DeviceGlobal.Stage {
        return .{ .context = self, .generate = globalWitness };
    }
    fn globalWitness(raw: *anyopaque, a: std.mem.Allocator, scope: D.Scope, item: Worker.DeviceGlobal.Item, shared: Worker.DeviceGlobal.Shared, budget: usize) !Worker.DeviceGlobal.Witness {
        const self: *Router = @ptrCast(@alignCast(raw));
        const index = try self.admit(scope, .retained);
        const stage = self.endpoints[index].global_interaction orelse return error.ResidentGlobalStageRequired;
        return stage.generate(stage.context, a, scope, item, shared, @min(budget, self.endpoints[index].byte_cap));
    }
    pub fn truthSourceStage(self: *Router) CPU.rv64_gkr_truth_device_source.Stage {
        return .{ .context = self, .prepare = truthPrepare, .retained_upper_bound = truthRetained };
    }
    fn truthRetained(raw: *anyopaque, request: CPU.rv64_gkr_truth_device_source.RetentionRequest) !CPU.rv64_gkr_truth_device_source.Retained {
        const self: *Router = @ptrCast(@alignCast(raw));
        if (request.expected.ordinal < self.planned_cpu_workers or zeroRoot(request.expected.statement) or zeroRoot(request.expected.fixed)) return error.InvalidTruthResidentScope;
        const endpoint = self.endpoints[request.expected.ordinal % self.endpoints.len];
        const stage = endpoint.truth_source orelse return error.ResidentTruthSourceRequired;
        const bound = stage.retained_upper_bound orelse return error.ResidentTruthRetainedContractRequired;
        return bound(stage.context, request);
    }
    fn truthPrepare(raw: *anyopaque, a: std.mem.Allocator, request: CPU.rv64_gkr_truth_device_source.Prepare) !CPU.rv64_gkr_truth_device_source.Owner {
        const self: *Router = @ptrCast(@alignCast(raw));
        if (request.expected.ordinal < self.planned_cpu_workers or zeroRoot(request.expected.statement) or zeroRoot(request.expected.fixed)) return error.InvalidTruthResidentScope;
        const endpoint = self.endpoints[request.expected.ordinal % self.endpoints.len];
        const stage = endpoint.truth_source orelse return error.ResidentTruthSourceRequired;
        var bounded = request;
        bounded.budget = @min(request.budget, endpoint.byte_cap);
        return stage.prepare(stage.context, a, bounded);
    }
    pub fn truthCompositionStage(self: *Router) CPU.rv64_gkr_truth_device_composition.Stage {
        return .{ .context = self, .evaluate_and_commit = truthComposition };
    }
    fn truthComposition(raw: *anyopaque, a: std.mem.Allocator, roles: CPU.rv64_gkr_truth_device_composition.Roles, alpha: D.O, log: u32, split: u32, total: usize, trace: *const anyopaque, scope: D.Scope) !D.Tree {
        const self: *Router = @ptrCast(@alignCast(raw));
        if (scope.ordinal < self.planned_cpu_workers or zeroRoot(scope.statement) or zeroRoot(scope.fixed) or zeroRoot(scope.main)) return error.InvalidTruthResidentScope;
        const endpoint = self.endpoints[scope.ordinal % self.endpoints.len];
        const stage = endpoint.truth_composition orelse return error.ResidentTruthCompositionRequired;
        return stage.evaluate_and_commit(stage.context, a, roles, alpha, log, split, total, trace, scope);
    }
    pub fn sourceStage(self: *Router) CPU.rv64_device_source_stage {
        return .{ .context = self, .build = sourceWitness };
    }
    fn sourceWitness(raw: *anyopaque, a: std.mem.Allocator, request: CPU.rv64_device_source_stage.Request) !CPU.rv64_services_roster.Sources {
        const self: *Router = @ptrCast(@alignCast(raw));
        const index = try self.admit(request.scope, .capture);
        errdefer self.drop(request.scope);
        const stage = self.endpoints[index].source orelse return error.ResidentFamilySourceRequired;
        return stage.invoke(a, request);
    }
    pub fn projectionStage(self: *Router) Source.ProjectionStage {
        return .{ .context = self, .project = projection };
    }
    fn abort(raw: *anyopaque, scope: GkrScope) void {
        const self: *Router = @ptrCast(@alignCast(raw));
        if (scope.ordinal >= self.planned_cpu_workers) return;
        const endpoint = self.endpoints[scope.ordinal % self.endpoints.len];
        if (comptime @hasField(Child.NumericalStage, "abort")) if (endpoint.numerical.abort) |callback| callback(endpoint.numerical.context, scope);
        self.drop(nativeScope(scope));
    }
    fn numerical(raw: *anyopaque, a: std.mem.Allocator, request: Child.NumericalStage.Request) !Proof {
        const self: *Router = @ptrCast(@alignCast(raw));
        const index = try self.admit(nativeScope(request.scope), .numerical);
        errdefer abort(raw, request.scope);
        var bounded = request;
        bounded.byte_cap = @intCast(@min(request.byte_cap, self.endpoints[index].byte_cap));
        const stage = self.endpoints[index].numerical;
        return stage.prove(stage.context, a, bounded);
    }
    fn bind(raw: *anyopaque, a: std.mem.Allocator, request: BindingRequest) !BindingOwner {
        if (comptime !@hasField(Child.NumericalStage, "bind")) return error.UnsupportedResidentBinding;
        const self: *Router = @ptrCast(@alignCast(raw));
        const index = try self.admit(nativeScope(request.scope), .retained);
        errdefer abort(raw, request.scope);
        const stage = self.endpoints[index].numerical;
        const callback = stage.bind orelse return error.UnsupportedResidentBinding;
        return callback(stage.context, a, request);
    }
    fn projection(raw: *anyopaque, source: *const Source.Source, scope: D.Scope) !Source.DeviceProjection {
        const self: *Router = @ptrCast(@alignCast(raw));
        const index = try self.admit(scope, .capture);
        errdefer self.drop(scope);
        const stage = self.endpoints[index].projection;
        return stage.project(stage.context, source, scope);
    }
    fn traceCommit(raw: *anyopaque, a: std.mem.Allocator, request: D.TraceCommitRequest) !D.Tree {
        const self: *Router = @ptrCast(@alignCast(raw));
        if (request.tree_index < 1 or request.tree_index > 2) return error.InvalidResidentTreeIndex;
        const index = try self.admit(request.scope, if (request.tree_index == 1) .main else .retained);
        errdefer self.drop(request.scope);
        const stage = self.endpoints[index].trace_commit;
        const result = try stage.commit(stage.context, a, request);
        if (request.tree_index == 1) try self.promote(request.scope, result.root);
        return result;
    }
    fn composition(raw: *anyopaque, a: std.mem.Allocator, items: []const Items.Item, alpha: D.O, log: u32, split: u32, total: usize, trace: *const anyopaque, scope: D.Scope) !D.Tree {
        const self: *Router = @ptrCast(@alignCast(raw));
        const index = try self.admit(scope, .retained);
        errdefer self.drop(scope);
        const stage = self.endpoints[index].composition;
        return stage.evaluate_and_commit(stage.context, a, items, alpha, log, split, total, trace, scope);
    }
    fn pcs(raw: *anyopaque, a: std.mem.Allocator, request: D.Request, channel: *D.Channel) !D.P.ExtendedCommitmentSchemeProof(D.H) {
        const self: *Router = @ptrCast(@alignCast(raw));
        const scope = request.scope orelse return error.MissingResidentScope;
        const index = try self.admit(scope, .retained);
        defer self.drop(scope);
        const stage = self.endpoints[index].pcs;
        return stage.prove(stage.context, a, request, channel);
    }
    /// G5 currently has no resident truth-MAIN custody. Its separately admitted
    /// native proof may use PCS on the ordinal-selected GPU without occupying
    /// a retained CPU slot; all ingress must remain host coefficients.
    fn truthPcs(raw: *anyopaque, a: std.mem.Allocator, request: D.Request, channel: *D.Channel) !D.P.ExtendedCommitmentSchemeProof(D.H) {
        const self: *Router = @ptrCast(@alignCast(raw));
        const scope = request.scope orelse return error.MissingResidentScope;
        if (scope.ordinal < self.planned_cpu_workers or zeroRoot(scope.statement) or zeroRoot(scope.fixed) or zeroRoot(scope.main)) return error.InvalidTruthResidentScope;
        for (request.trees, 0..) |tree, index| for (tree.columns) |column| {
            if (column.log_size < 3 or column.log_size > 28) return error.InvalidResidentTruthColumn;
            if (column.device) |device| {
                if (column.coefficients.len != 0 or device.context_token == 0 or device.generation == 0 or column.log_size < 3 or column.log_size > 28 or device.count != @as(u64, 1) << @intCast(column.log_size)) return error.InvalidResidentTruthColumn;
            } else if (index != 0 or column.coefficients.len != @as(usize, 1) << @intCast(column.log_size)) return error.ResidentTruthHostFallback;
        };
        const stage = self.endpoints[scope.ordinal % self.endpoints.len].pcs;
        return stage.prove(stage.context, a, request, channel);
    }
};

const Fake = struct {
    calls: [6]usize = @splat(0),
    byte_cap: usize = 0,
    fn pcs(raw: *anyopaque, _: std.mem.Allocator, _: D.Request, _: *D.Channel) !D.P.ExtendedCommitmentSchemeProof(D.H) {
        const self: *Fake = @ptrCast(@alignCast(raw));
        self.calls[0] += 1;
        return error.ProbeReached;
    }
    fn numerical(raw: *anyopaque, _: std.mem.Allocator, request: Child.NumericalStage.Request) !Proof {
        const self: *Fake = @ptrCast(@alignCast(raw));
        self.calls[1] += 1;
        self.byte_cap = request.byte_cap;
        return error.ProbeReached;
    }
    fn composition(raw: *anyopaque, _: std.mem.Allocator, _: []const Items.Item, _: D.O, _: u32, _: u32, _: usize, _: *const anyopaque, _: D.Scope) !D.Tree {
        const self: *Fake = @ptrCast(@alignCast(raw));
        self.calls[2] += 1;
        return .{ .root = @splat(9), .columns = &.{} };
    }
    fn trace(raw: *anyopaque, _: std.mem.Allocator, request: D.TraceCommitRequest) !D.Tree {
        const self: *Fake = @ptrCast(@alignCast(raw));
        self.calls[3] += 1;
        return .{ .root = @splat(@intCast(request.scope.ordinal + 1)), .columns = &.{} };
    }
    fn projection(raw: *anyopaque, _: *const Source.Source, _: D.Scope) !Source.DeviceProjection {
        const self: *Fake = @ptrCast(@alignCast(raw));
        self.calls[4] += 1;
        return .{ .columns = &.{}, .counts16 = &.{}, .counts8 = &.{}, .pair_counts = &.{} };
    }
    fn endpoint(self: *Fake, id: u32) Endpoint {
        return .{ .device = id, .byte_cap = 1024, .pcs = .{ .context = self, .prove = pcs }, .numerical = .{ .context = self, .prove = numerical }, .composition = .{ .context = self, .evaluate_and_commit = composition }, .trace_commit = .{ .context = self, .commit = trace }, .projection = .{ .context = self, .project = projection } };
    }
};
fn testScope(ordinal: u32) D.Scope {
    return .{ .statement = @splat(@intCast(ordinal + 1)), .fixed = @splat(7), .main = @splat(0), .ordinal = ordinal };
}
fn testConfig() !@import("stwo_core").pcs.PcsConfig {
    return .{ .pow_bits = 0, .fri_config = try @import("stwo_core").fri.ForField(D.O).FriConfig.init(0, 1, 2) };
}
fn testRequest(scope: ?D.Scope) !D.Request {
    return .{ .scope = scope, .config = try testConfig(), .lifting_log_size = 6, .trees = &.{}, .points = @import("stwo_core").pcs.TreeVec([][]D.Point).initOwned(&.{}) };
}

test "resident router config plans seven CPU workers on four devices before opening CUDA" {
    const a = std.testing.allocator;
    var config = try Config.parse(a, "0, 2,4,6", "1000,2000,3000,4000");
    defer config.deinit(a);
    try config.validatePlan(7);
    try std.testing.expectEqualSlices(u32, &.{ 0, 2, 4, 6 }, config.ids);
    try std.testing.expectEqual(@as(u64, 4000), config.caps[3]);
    try std.testing.expectError(error.InsufficientResidentCapacity, config.validatePlan(9));
    try std.testing.expectError(error.DuplicateResidentDevice, Config.parse(a, "0,0", null));
    try std.testing.expectError(error.InvalidResidentDeviceList, Config.parse(a, "0,", null));
    try std.testing.expectError(error.InvalidResidentDeviceCaps, Config.parse(a, "0,1", "1000"));
    var one = try Config.parse(a, "0", null);
    defer one.deinit(a);
    try std.testing.expectError(error.InsufficientResidentCapacity, one.validatePlan(7));
    try one.validatePlan(2);
}

test "explicit retention plans route seven MAIN obligations across one two or four GPUs" {
    for ([_]usize{ 1, 2, 4 }) |count| {
        var fake = [_]Fake{ .{}, .{}, .{}, .{} };
        const endpoints = [_]Endpoint{ fake[0].endpoint(0), fake[1].endpoint(1), fake[2].endpoint(2), fake[3].endpoint(3) };
        const limit = (7 + count - 1) / count;
        var router = try Router.initWithCapacity(endpoints[0..count], 7, limit);
        var scopes: [7]D.Scope = undefined;
        // All stage-one roots precede any phase-two consumer. A reduced GPU
        // count must never silently discard a still-live MAIN obligation.
        for (&scopes, 0..) |*scope, i| {
            scope.* = testScope(@intCast(i));
            _ = try router.admit(scope.*, .capture);
            try router.promote(scope.*, @splat(@intCast(i + 1)));
            scope.main = @splat(@intCast(i + 1));
        }
        for (scopes) |scope| {
            try std.testing.expectEqual(@as(usize, scope.ordinal) % count, try router.admit(scope, .retained));
            router.drop(scope);
        }
        try std.testing.expectError(error.InvalidResidentScopeLimit, Router.initWithCapacity(endpoints[0..count], 7, MAX_SCOPES_PER_DEVICE + 1));
    }
}

test "resident router keeps all seven worker stages on their GPU across the manifest barrier" {
    var fake = [_]Fake{ .{}, .{}, .{}, .{} };
    const endpoints = [_]Endpoint{ fake[0].endpoint(0), fake[1].endpoint(1), fake[2].endpoint(2), fake[3].endpoint(3) };
    var router = try Router.init(&endpoints, 7);
    const projection_stage = router.projectionStage();
    const trace_stage = router.traceStage();
    const composition_stage = router.compositionStage();
    const pcs_stage = router.pcsStage();
    var scopes: [7]D.Scope = undefined;
    for (&scopes, 0..) |*scope, i| {
        scope.* = testScope(@intCast(i));
        _ = try projection_stage.project(projection_stage.context, @ptrFromInt(4096), scope.*);
        const main = try trace_stage.commit(trace_stage.context, std.testing.allocator, .{ .scope = scope.*, .tree_index = 1, .config = try testConfig(), .columns = &.{} });
        scope.main = main.root;
        try std.testing.expectEqual(@as(u32, @intCast(i % 4)), router.deviceFor(scope.ordinal));
    }
    // Every MAIN is now retained. Complete out of order after the same manifest
    // barrier; no source or coefficient lease migrates to a different device.
    for (0..scopes.len) |step| {
        const scope = scopes[scopes.len - 1 - step];
        _ = try trace_stage.commit(trace_stage.context, std.testing.allocator, .{ .scope = scope, .tree_index = 2, .config = try testConfig(), .columns = &.{} });
        _ = try composition_stage.evaluate_and_commit(composition_stage.context, std.testing.allocator, &.{}, D.O.one(), 6, 1, 0, @ptrFromInt(4096), scope);
        var channel = D.Channel.init();
        try std.testing.expectError(error.ProbeReached, pcs_stage.prove(pcs_stage.context, std.testing.allocator, try testRequest(scope), &channel));
    }
    const expected = [_]usize{ 2, 2, 2, 1 };
    for (fake, expected) |device, count| {
        try std.testing.expectEqual(count, device.calls[0]);
        try std.testing.expectEqual(count, device.calls[2]);
        try std.testing.expectEqual(2 * count, device.calls[3]);
        try std.testing.expectEqual(count, device.calls[4]);
    }
    for (router.records) |slots| for (slots) |record| try std.testing.expect(record == null);
}

test "resident router rejects scope mutation missing admission and unplanned ordinals" {
    var fake = Fake{};
    const endpoints = [_]Endpoint{fake.endpoint(3)};
    var router = try Router.init(&endpoints, 2);
    var first = testScope(0);
    _ = try router.admit(first, .capture);
    try router.promote(first, @splat(9));
    first.main = @splat(9);
    var changed = first;
    changed.main[0] ^= 1;
    try std.testing.expectError(error.ResidentMainRootMismatch, router.admit(changed, .retained));
    changed = first;
    changed.statement[0] ^= 1;
    try std.testing.expectError(error.ResidentWorkerIdentityMismatch, router.admit(changed, .retained));
    var absent = testScope(1);
    absent.main = @splat(4);
    try std.testing.expectError(error.MissingResidentAdmission, router.admit(absent, .retained));
    try std.testing.expectError(error.UnplannedResidentWorker, router.admit(testScope(2), .capture));
    var channel = D.Channel.init();
    const stage = router.pcsStage();
    try std.testing.expectError(error.MissingResidentScope, stage.prove(stage.context, std.testing.allocator, try testRequest(null), &channel));
    try std.testing.expectEqual(@as(usize, 0), fake.calls[0]);
}

test "resident router bounds numerical workspace on the ordinal-selected endpoint" {
    var fake = [_]Fake{ .{}, .{} };
    const endpoints = [_]Endpoint{ fake[0].endpoint(5), fake[1].endpoint(7) };
    var router = try Router.init(&endpoints, 2);
    var scope = testScope(1);
    scope.main = @splat(9);
    const stage = router.numericalStage();
    try std.testing.expectError(error.ProbeReached, stage.prove(stage.context, std.testing.allocator, .{ .scope = .{ .statement = scope.statement, .fixed = scope.fixed, .main = scope.main, .ordinal = scope.ordinal }, .instances = &.{}, .challenges = @ptrFromInt(4096), .sources = &.{}, .native_source = null, .source_channel = D.Channel.init(), .channel = D.Channel.init(), .byte_cap = 4096 }));
    try std.testing.expectEqual(@as(usize, 0), fake[0].calls[1]);
    try std.testing.expectEqual(@as(usize, 1), fake[1].calls[1]);
    try std.testing.expectEqual(@as(usize, 1024), fake[1].byte_cap);
    try std.testing.expect(router.records[1][0] == null);
}

test "resident truth PCS routes scoped device columns without consuming CPU custody" {
    var fake = [_]Fake{ .{}, .{} };
    const endpoints = [_]Endpoint{ fake[0].endpoint(2), fake[1].endpoint(4) };
    var router = try Router.init(&endpoints, 2);
    var scope = testScope(3);
    scope.main = @splat(8);
    var channel = D.Channel.init();
    const stage = router.truthPcsStage();
    try std.testing.expectError(error.ProbeReached, stage.prove(stage.context, std.testing.allocator, try testRequest(scope), &channel));
    try std.testing.expectEqual(@as(usize, 1), fake[1].calls[0]);
    try std.testing.expect(router.records[1][0] == null);
    const device = [_]D.Column{.{ .log_size = 5, .device = .{ .words = @ptrFromInt(4096), .count = 32, .context_token = 1, .generation = 2 } }};
    const trees = [_]D.Tree{ .{ .root = @splat(3), .columns = &.{} }, .{ .root = @splat(3), .columns = &device } };
    var request = try testRequest(scope);
    request.trees = &trees;
    try std.testing.expectError(error.ProbeReached, stage.prove(stage.context, std.testing.allocator, request, &channel));
    try std.testing.expectEqual(@as(usize, 2), fake[1].calls[0]);
}

test "resident full-family source dispatch stays scoped and fails closed without factory" {
    var fake = [_]Fake{ .{}, .{} };
    var endpoints = [_]Endpoint{ fake[0].endpoint(1), fake[1].endpoint(3) };
    var router = try Router.initWithCapacity(&endpoints, 4, 2);
    const request = CPU.rv64_device_source_stage.Request{ .setup = @ptrFromInt(4096), .request = undefined, .native = @ptrFromInt(4096), .advice = @ptrFromInt(4096), .ordinal = 3, .first_ids = @splat(0), .scope = testScope(3) };
    const stage = router.sourceStage();
    try std.testing.expectError(error.ResidentFamilySourceRequired, stage.build(stage.context, std.testing.allocator, request));
    const Probe = struct {
        fn source(raw: *anyopaque, _: std.mem.Allocator, _: CPU.rv64_device_source_stage.Request) !CPU.rv64_services_roster.Sources {
            const state: *Fake = @ptrCast(@alignCast(raw));
            state.calls[5] += 1;
            return error.ProbeReached;
        }
    };
    endpoints[1].source = .{ .context = &fake[1], .build = Probe.source };
    try std.testing.expectError(error.ProbeReached, stage.build(stage.context, std.testing.allocator, request));
    try std.testing.expectEqual(@as(usize, 0), fake[0].calls[5]);
    try std.testing.expectEqual(@as(usize, 1), fake[1].calls[5]);
}
