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
    pub fn stage(self: *Context) Stage {
        return .{ .context = self, .build = build };
    }
    fn build(raw: *anyopaque, a: std.mem.Allocator, request: Stage.Request) !R.Sources {
        const self: *Context = @ptrCast(@alignCast(raw));
        const projection = try self.core.buildCore(a, request);
        errdefer projection.deinit();
        const logs = try request.setup.logs(a, 1);
        defer a.free(logs);
        const owner = try a.create(CompleteOwner);
        errdefer a.destroy(owner);
        owner.* = .{ .allocator = a, .core = projection, .columns = try a.alloc(D.TraceColumn, logs.len) };
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
    var split = try CPU.rv64_services_pipeline.splitEvents(a, request.advice.events[request.ordinal], request.setup.bridges.ls_dword != null);
    defer split.deinit(a);
    const counts = try T.dwordCounts(request.setup.bridges, request.request.ls_dword);
    var at: usize = 0;
    for (counts, 0..) |count, k| if (request.setup.bridges.dwordLog(k)) |log| {
        const generated = try projection.formatDword(split.dword[at..][0..count], log);
        defer a.free(generated);
        const offset = request.setup.dwordOffset(k, 1);
        if (offset + generated.len > columns.len) return error.InvalidDeviceDwordWidth;
        @memcpy(columns[offset..][0..generated.len], generated);
        headers.ls_dword[k] = .{ .allocator = a, .log_size = log, .rows = count, .fixed = &.{}, .main = &.{}, .owns_main = true, .metadata = &.{}, .counts16 = &.{}, .counts8 = &.{} };
        at += count;
    };
    if (at != split.dword.len) return error.InvalidCombinedServiceCount;
}
const CompleteOwner = struct {
    allocator: std.mem.Allocator,
    core: *Core.CoreProjection,
    columns: []D.TraceColumn,
    contributions: std.ArrayList(Owner) = .empty,
    fn release(raw: *anyopaque) void {
        const self: *CompleteOwner = @ptrCast(@alignCast(raw));
        const a = self.allocator;
        for (self.contributions.items) |c| c.release(c.context);
        self.contributions.deinit(a);
        self.core.deinit();
        a.free(self.columns);
        a.destroy(self);
    }
};
test "resident all-family source assembly has no host fallback" {
    std.mem.doNotOptimizeAway(&Context.build);
}
