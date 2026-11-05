//! One all-device CPU/service source assembly. Contributions write only their
//! setup-owned slots; the final validator rejects every missing/host column.
const std = @import("std");
const CPU = @import("stwo_riscv_cpu_integration");
const A = @import("stwo_riscv_frontend").rv64_air;
const D = CPU.rv64_device_pcs;
const Stage = CPU.rv64_device_source_stage;
pub const R = CPU.rv64_services_roster;
pub const T = CPU.rv64_services_types;
const Core = @import("core_witness.zig");
pub const Owner = struct { context: *anyopaque, release: *const fn (*anyopaque) void };
/// Valid empty matrix owners plus retained narrow service descriptors. Never
/// borrow setup.fixed: these native headers free their fixed slice on deinit.
pub const Headers = struct {
    keccak: @FieldType(R.Sources, "keccak") = null,
    add: @FieldType(R.Sources, "add") = null,
    double: @FieldType(R.Sources, "double") = null,
    sha256: @FieldType(R.Sources, "sha256") = null,
    arith256_mod: @FieldType(R.Sources, "arith256_mod") = null,
    curves: @FieldType(R.Sources, "curves") = @splat(null),
    bulk: @FieldType(R.Sources, "bulk") = @splat(null),
    sponge_plan: @FieldType(R.Sources, "sponge_plan") = null,
    sponge: @FieldType(R.Sources, "sponge") = @splat(null),
    ls_dword: @FieldType(R.Sources, "ls_dword") = @splat(null),
    zbb: @FieldType(R.Sources, "zbb") = null,
    pub fn deinit(self: *Headers, a: std.mem.Allocator) void {
        inline for (.{ "keccak", "add", "double", "sha256", "arith256_mod", "zbb" }) |name| if (@field(self, name)) |*s| s.deinit();
        inline for (.{ "curves", "bulk", "sponge", "ls_dword" }) |name| for (&@field(self, name)) |*item| if (item.*) |*s| s.deinit();
        if (self.sponge_plan) |plan| {
            plan.deinit(a);
            a.destroy(plan);
        }
        self.* = .{};
    }
};
/// Contributors add histogram counts on GPU and fill disjoint MAIN slots.
/// The optional returned owner contains only device allocations; Headers owns
/// its narrow host descriptors independently. Failure must clean local work.
pub const Contributor = struct {
    context: *anyopaque,
    format: *const fn (*anyopaque, std.mem.Allocator, Stage.Request, *Core.CoreProjection, *Headers, []D.TraceColumn) anyerror!?Owner,
};
pub const Context = struct {
    core: *Core.Context,
    contributors: []const Contributor,
    progress: ?*@import("native_progress.zig").Context = null,
    pub fn stage(self: *Context) Stage {
        return .{ .context = self, .build = build };
    }
    fn build(raw: *anyopaque, a: std.mem.Allocator, request: Stage.Request) !R.Sources {
        const self: *Context = @ptrCast(@alignCast(raw));
        const service = self.core.service;
        if (service.admission) |*endpoint| {
            const source = try (self.progress orelse return error.MissingNativeClassProgress).registerCpu(a, request);
            const A = @import("global_admission.zig");
            var retained: A.Footprint = .{};
            for (source.list()) |allocation| {
                if (allocation.release == .projection_join or allocation.owner == .commit_workspace or allocation.owner == .committed_coefficients) continue;
                retained = try retained.add(try A.Footprint.allocation(try std.math.mul(u64, allocation.words, 4)));
            }
            const successor = try service.admissionSuccessor(request.scope, .source);
            var permit = try endpoint.reserve(.{ .progress_key = A.progressKey(request.scope), .owner = .{ .request = std.mem.readInt(u64, request.scope.statement[0..8], .little), .domain = .native_packet, .ordinal = request.scope.ordinal }, .stage = .witness, .temporary = source.peak, .stage_retained_upper = retained, .successor = successor, .known = true, .host_known = false });
            var active = false;
            defer {
                if (active) SourceControl.invoke(service, &permit, false) catch {
                    endpoint.planner.poisonPhysical(endpoint.physical);
                };
                if (!permit.closed) permit.finish(.{}) catch {
                    endpoint.planner.poisonPhysical(endpoint.physical);
                };
            }
            try SourceControl.invoke(service, &permit, true);
            active = true;
            var result = try self.buildSource(a, request);
            errdefer result.deinit();
            try SourceControl.invoke(service, &permit, false);
            active = false;
            const owner: *CompleteOwner = @ptrCast(@alignCast(result.device_main.?.context));
            try owner.admission_retention.complete(a, &permit, @import("pcs_scope.zig").identity(request.scope), successor);
            return result;
        }
        return self.buildSource(a, request);
    }
    fn buildSource(self: *Context, a: std.mem.Allocator, request: Stage.Request) !R.Sources {
        const projection = try self.core.buildCore(a, request);
        errdefer projection.deinit();
        const logs = try request.setup.logs(a, 1);
        defer a.free(logs);
        const owner = try a.create(CompleteOwner);
        errdefer a.destroy(owner);
        owner.* = .{ .allocator = a, .core = projection, .scope = request.scope, .columns = try a.alloc(D.TraceColumn, logs.len) };
        errdefer a.free(owner.columns);
        errdefer owner.contributions.deinit(a);
        // A missing contribution is a hard admission failure, never an implicit
        // CPU implementation. log0 is invalid for every production MAIN role.
        @memset(owner.columns, .{ .log_size = 0, .encoding = .evaluations });
        if (projection.columns.len > owner.columns.len) return error.InvalidDeviceCoreWidth;
        @memcpy(owner.columns[0..projection.columns.len], projection.columns);
        var headers = Headers{};
        errdefer headers.deinit(a);
        errdefer for (owner.contributions.items) |c| c.release(c.context);
        for (self.contributors) |contribution| if (try contribution.format(contribution.context, a, request, projection, &headers, owner.columns)) |contributed| {
            owner.contributions.append(a, contributed) catch |err| {
                contributed.release(contributed.context);
                return err;
            };
        };
        try appendLocalExtensions(a, request, projection, &headers, owner.columns);
        try validateHeaders(request, &headers);
        try projection.finishTables();
        const device = CPU.rv64_device_main.Owner{ .context = owner, .scope = request.scope, .columns = owner.columns, .release_fn = CompleteOwner.release };
        try device.validate(request.scope, logs);
        var result = R.Sources{ .core = try projection.takeSource(), .device_generated = true, .device_main = device };
        inline for (std.meta.fields(Headers)) |field| @field(result, field.name) = @field(headers, field.name);
        return result;
    }
};
const SourceControl = struct {
    permit: *@import("admission_runtime.zig").Permit,
    begin: bool,
    sync: @import("pcs_native_abi.zig").Sync,
    failure: ?anyerror = null,
    fn callback(raw: *anyopaque, _: u64, data: ?*anyopaque) callconv(.c) c_int {
        const self: *SourceControl = @ptrCast(@alignCast(data.?));
        if (self.begin) self.permit.enterOwner(raw) catch |err| {
            self.failure = err;
            return 1;
        } else {
            if (self.sync(raw) != 0) return 1;
            self.permit.leaveOwner(raw) catch |err| {
                self.failure = err;
                return 1;
            };
        }
        return 0;
    }
    fn invoke(service: *@import("pcs_native.zig").Context, permit: *@import("admission_runtime.zig").Permit, begin: bool) !void {
        const sync = service.library.lookup(@import("pcs_native_abi.zig").Sync, "stwo_exec_context_sync") orelse return error.MissingNativeSourceSync;
        var control = SourceControl{ .permit = permit, .begin = begin, .sync = sync };
        if (service.submit(service.session, callback, &control) != 0) return control.failure orelse error.NativeSourceAdmissionControlFailed;
    }
};
fn validateHeaders(request: Stage.Request, headers: *const Headers) !void {
    const direct = [_]bool{ headers.keccak != null, headers.add != null, headers.double != null, headers.sha256 != null, headers.arith256_mod != null };
    for (0..T.FAMILIES) |k| {
        const present = if (k < direct.len) direct[k] else headers.curves[k - T.FIRST_CURVE] != null;
        if (present != (request.setup.bridges.at(@enumFromInt(k)) != null)) return error.IncompleteResidentBridgeHeaders;
    }
    for (T.bulk_kinds, 0..) |kind, k| if ((headers.bulk[k] != null) != (request.setup.bridges.bulk.at(kind) != null)) return error.IncompleteResidentBulkHeaders;
    for (T.sponge_kinds, 0..) |kind, k| if ((headers.sponge[k] != null) != (request.setup.bridges.sponge.at(kind) != null)) return error.IncompleteResidentSpongeHeaders;
    if ((headers.sponge_plan != null) != request.setup.bridges.sponge.any()) return error.IncompleteResidentSpongeHeaders;
}
fn appendLocalExtensions(a: std.mem.Allocator, request: Stage.Request, projection: *Core.CoreProjection, headers: *Headers, columns: []D.TraceColumn) !void {
    if (request.setup.bridges.zbb) |log| {
        const p = request.native;
        const generated = try projection.formatZbb(p.zbb.facts, p.zbb.weights, log);
        defer a.free(generated);
        const offset = request.setup.zbbOffset(1);
        if (offset + generated.len > columns.len) return error.InvalidDeviceZbbWidth;
        @memcpy(columns[offset..][0..generated.len], generated);
        var mass: u64 = 0;
        for (p.zbb.weights) |weight| mass = try std.math.add(u64, mass, weight);
        if (mass >= @import("stwo_core").fields.m31.Modulus) return error.DeviceFamilyMultiplicityMassExceeded;
        headers.zbb = .{ .allocator = a, .log_size = log, .fact_count = p.zbb.facts.len, .function_mass = @intCast(mass), .fixed = &.{}, .main = &.{}, .owns_main = true, .and_counts = &.{}, .metadata = &.{} };
    } else if (request.native.zbb.facts.len != 0) return error.MissingZbbComponent;
    const events = try CPU.rv64_memory_input.routedEvents(a, request.advice.events[request.ordinal], request.setup.bridges.ls_dword != null, true);
    defer a.free(events);
    const counts = try T.dwordCounts(request.setup.bridges, request.request.ls_dword);
    var at: usize = 0;
    for (counts, 0..) |count, k| if (request.setup.bridges.dwordLog(k)) |log| {
        if (at > events.len or count > events.len - at) return error.InvalidCombinedServiceCount;
        const generated = try projection.formatEncodedDword(events[at..][0..count], log);
        defer a.free(generated);
        const offset = request.setup.dwordOffset(k, 1);
        if (offset + generated.len > columns.len) return error.InvalidDeviceDwordWidth;
        @memcpy(columns[offset..][0..generated.len], generated);
        headers.ls_dword[k] = .{ .allocator = a, .log_size = log, .rows = count, .fixed = &.{}, .main = &.{}, .owns_main = true, .metadata = &.{}, .counts16 = &.{}, .counts8 = &.{} };
        at += count;
    };
    if (at != events.len) return error.InvalidCombinedServiceCount;
}
const CompleteOwner = struct {
    allocator: std.mem.Allocator,
    core: *Core.CoreProjection,
    scope: D.Scope,
    admission_retention: @import("admission_retention.zig").Registry = .{},
    columns: []D.TraceColumn,
    contributions: std.ArrayList(Owner) = .empty,
    fn release(raw: *anyopaque) void {
        const self: *CompleteOwner = @ptrCast(@alignCast(raw));
        const a = self.allocator;
        const service = self.core.backend.service;
        for (self.contributions.items) |c| c.release(c.context);
        self.contributions.deinit(a);
        self.core.deinit();
        if (service.admission) |endpoint| {
            const Join = struct {
                sync: @import("pcs_native_abi.zig").Sync,
                fn run(ctx: *anyopaque, _: u64, data: ?*anyopaque) callconv(.c) c_int {
                    const q: *@This() = @ptrCast(@alignCast(data.?));
                    return q.sync(ctx);
                }
            };
            const sync = service.library.lookup(@import("pcs_native_abi.zig").Sync, "stwo_exec_context_sync");
            var joined = false;
            if (sync) |f| {
                var q = Join{ .sync = f };
                joined = service.submit(service.session, Join.run, &q) == 0;
            }
            if (joined and endpoint.planner.healthy(endpoint.physical)) {
                self.admission_retention.retireAfterDestruction(endpoint.planner, @import("pcs_scope.zig").identity(self.scope)) catch {
                    endpoint.planner.poisonPhysical(endpoint.physical);
                };
            } else endpoint.planner.poisonPhysical(endpoint.physical);
            if (!endpoint.planner.healthy(endpoint.physical)) self.admission_retention.abandonToPoisonedPool(endpoint.planner) catch @panic("native Source admission retirement lost custody");
            endpoint.planner.notifyResourceRelease();
        }
        self.admission_retention.deinit(a);
        a.free(self.columns);
        a.destroy(self);
    }
};
test "resident all-family source assembly has no host fallback" {
    std.mem.doNotOptimizeAway(&Context.build);
}
