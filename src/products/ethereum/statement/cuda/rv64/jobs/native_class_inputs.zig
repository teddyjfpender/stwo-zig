//! Canonical worker/input conversion and Stage-1 geometry preparation.
const Plan = @import("native_class_inventory.zig").Plan;
const CPU = @import("stwo_riscv_cpu_integration");
const CW = CPU.rv64_gkr_cpu_worker;
const Child = CPU.rv64_gkr_child;
const Class = @import("native_class_build.zig").Class;
const DP = CPU.rv64_device_pcs;
const Env = @import("native_class_build.zig").Env;
const Inputs = @import("native_class_build.zig").Inputs;
const M = core.fields.m31.M31;
const Manifest = CPU.rv64_gkr_manifest;
const NB = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_binding;
const NC = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_commit;
const NG = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_gkr;
const NP = @import("stwo_riscv_cuda_integration").rv64.execution.jobs.native_pcs;
const NativeSources = @import("native_class_build.zig").NativeSources;
const O = core.fields.om31.OM31;
const Pending = @import("native_class_build.zig").Pending;
const Request = @import("native_class_build.zig").Request;
const Setup = @import("native_class_build.zig").Setup;
const Shared = @import("native_class_build.zig").Shared;
const coefficientWords = @import("native_class_fingerprint.zig").coefficientWords;
const core = @import("stwo_core");
const std = @import("std");

pub fn stubSource(setup: *const Setup, request: Request) NativeSources {
    var s: NativeSources = undefined;
    s.device_generated = false;
    s.device_main = null;
    s.core.cpu.u8_pairs = setup.materials.geometry.cpu_u8_pairs;
    s.core.cpu.compact = setup.materials.geometry.cpu_compact_decode;
    s.core.cpu.epoch = request.base.epoch;
    s.core.cpu.public = request.base.cpu;
    s.sponge = @splat(null);
    for (&s.sponge, 0..) |*slot, k| if (setup.bridges.sponge.at(@enumFromInt(k)) != null) {
        slot.* = @as(@typeInfo(@TypeOf(slot.*)).optional.child, undefined);
        slot.*.?.first_id = request.sponge.first_id;
    };
    return s;
}

/// Placeholder local-GKR artifact of the instance shapes (zero claims, a fixed
/// non-degenerate point, zero challenges): the framing builders read only its shape (claims per
/// instance, variable counts); the values are per request (semantic patch).
pub fn placeholderPending(a: std.mem.Allocator, instances: []const NG.Instance) !Pending {
    const n = instances.len;
    const vars = try a.alloc(usize, n);
    errdefer a.free(vars);
    var max: usize = 0;
    for (instances, vars) |inst, *v| {
        v.* = @intCast(try inst.variables());
        max = @max(max, v.*);
    }
    const point = try a.alloc(O, max);
    errdefer a.free(point);
    // Never 0 or 1 (MleEvalPoint refuses a degenerate coordinate).
    for (point, 0..) |*p, i| p.* = O.fromBase(M.fromCanonical(@intCast(2 + i)));
    const claims = try a.alloc([]O, n);
    errdefer a.free(claims);
    var made: usize = 0;
    errdefer for (claims[0..made]) |c| a.free(c);
    for (claims) |*c| {
        c.* = try a.alloc(O, 2);
        @memset(c.*, O.zero());
        made += 1;
    }
    var challenges = std.mem.zeroes(@FieldType(Pending, "challenges"));
    var next: u32 = 1000;
    fillFelts(@TypeOf(challenges), &challenges, &next);
    return .{ .artifact = .{ .ood_point = point, .claims_to_verify_by_instance = claims, .n_variables_by_instance = vars }, .challenges = challenges, .eta = O.fromBase(M.fromCanonical(999)), .digest = @splat(0) };
}

/// Placeholder shared challenges: distinct nonzero felts (a zero challenge
/// could hit an inverse in the role metadata; values are per request).
pub fn placeholderShared() Shared {
    var s = std.mem.zeroes(Shared);
    var next: u32 = 2000;
    fillFelts(Shared, &s, &next);
    return s;
}

/// Every OM31 felt reachable through struct fields / arrays of `v` gets a
/// distinct nonzero base value (next, next+1, ...).
pub fn fillFelts(comptime T: type, v: *T, next: *u32) void {
    if (T == O) {
        v.* = O.fromBase(M.fromCanonical(next.*));
        next.* += 1;
        return;
    }
    switch (@typeInfo(T)) {
        .@"struct" => |st| inline for (st.fields) |f| fillFelts(f.type, &@field(v.*, f.name), next),
        .array => |arr| for (v) |*x| fillFelts(arr.child, x, next),
        else => {},
    }
}

pub fn stage1FromNumerical(env: *const Env, request: Child.NumericalStage.Request) !*Class {
    const a = env.a;
    const native = request.native_source orelse return error.NativeGkrSourceRequired;
    const cl = try a.create(Class);
    errdefer a.destroy(cl);
    cl.* = .{ .a = a, .gkr = undefined, .instances = &.{}, .fixed_shapes = &.{}, .main_shapes = &.{}, .fixed_host = &.{}, .fixed_storage = &.{}, .fixed_root = request.scope.fixed, .beta = env.config.fri_config.log_blowup_factor, .comp_log = 0, .split = 0, .total = 0, .mask_log = 0, .claim_count = 0, .bind_plan = undefined };
    cl.instances = try a.dupe(NG.Instance, request.instances);
    errdefer a.free(cl.instances);
    var words: usize = 0;
    for (request.native_fixed_columns) |c| {
        if (c.device != null) return error.HybridExpectsHostFixed;
        words += c.coefficients.len;
    }
    cl.fixed_storage = try a.alloc(u32, words);
    errdefer a.free(cl.fixed_storage);
    cl.fixed_host = try a.alloc([]const u32, request.native_fixed_columns.len);
    errdefer a.free(cl.fixed_host);
    cl.fixed_shapes = try a.alloc(NC.Shape, request.native_fixed_columns.len);
    errdefer a.free(cl.fixed_shapes);
    var at: usize = 0;
    for (request.native_fixed_columns, cl.fixed_host, cl.fixed_shapes) |c, *h, *sh| {
        const w = coefficientWords(c.coefficients);
        @memcpy(cl.fixed_storage[at..][0..w.len], w);
        h.* = cl.fixed_storage[at..][0..w.len];
        sh.* = .{ .log_size = c.log_size, .encoding = .coefficients };
        at += w.len;
    }
    cl.main_shapes = try a.alloc(NC.Shape, request.native_main_columns.len);
    errdefer a.free(cl.main_shapes);
    for (request.native_main_columns, cl.main_shapes) |c, *sh| sh.* = .{ .log_size = c.log_size, .encoding = .evaluations };
    // The legacy call, on the class's own FIXED copy (the plan keeps views)
    // and the legacy request's MAIN device columns (shape only).
    const fixed_cols = try a.alloc(DP.Column, cl.fixed_host.len);
    defer a.free(fixed_cols);
    for (fixed_cols, cl.fixed_host, cl.fixed_shapes) |*c, h, sh| c.* = .{ .log_size = sh.log_size, .coefficients = @as([*]const M, @ptrCast(h.ptr))[0..h.len] };
    cl.gkr = try NG.Plan.init(a, env.catalogue, request.scope, request.instances, native, fixed_cols, request.native_main_columns, request.byte_cap, 0);
    errdefer cl.gkr.deinit();
    cl.bind_plan = try NB.Plan.init(a, request.instances, cl.gkr.traversal.layers);
    // capture_words: not a legacy input (the ring is GPU-native only); the
    // caller sets it from the class rows when comparing.
    return cl;
}

/// The inputs the hybrid had for one segment: the stage-two CpuWorker +
/// pending manifest (FIXED from the worker scheme, MAIN logs from the setup).
/// `fixed` must stay valid for the call (the worker's FIXED tree).
pub fn inputsFromWorker(a: std.mem.Allocator, worker: *const CW.CpuWorker, pending: *const Manifest.PendingManifest, ordinal: u32, fixed: []DP.Column, native: *const NativeSources) !struct { inputs: Inputs, main_logs: []u32 } {
    const fixed_coefficients = worker.scheme.trees.items[0].coefficients orelse return error.DeviceGkrCoefficientsRequired;
    if (fixed.len != fixed_coefficients.len) return error.GnShapeFixedShape;
    for (fixed_coefficients, fixed) |c, *d| d.* = .{ .log_size = c.logSize(), .coefficients = c.coefficients() };
    const main_logs = try worker.setup.logs(a, 1);
    const local = &(pending.entries[ordinal].local orelse return error.WideCpuLocalRequired);
    return .{ .main_logs = main_logs, .inputs = .{
        .ordinal = ordinal,
        .setup = worker.setup,
        .request = worker.request,
        .first = worker.first,
        .fixed = fixed,
        .fixed_root = worker.expected.fixed,
        .main_logs = main_logs,
        .instances = worker.instances,
        .native = native,
        .statement = worker.expected.statement,
        .main_root = worker.preparedMainRoot() catch @splat(0),
        .pending = local,
        .shared = pending.shared,
    } };
}

// ---------------------------------------------------------------------------
// From a warm capture (install; no CpuWorker)
// ---------------------------------------------------------------------------

pub fn buildStage1(env: *const Env, in: Inputs, cl: *Class) !void {
    const a = env.a;
    const scope = NG.Scope{ .statement = in.statement, .fixed = in.fixed_root, .main = in.main_root, .ordinal = in.ordinal };
    const fixed_cols = try a.alloc(DP.Column, cl.fixed_host.len);
    defer a.free(fixed_cols);
    for (fixed_cols, cl.fixed_host, cl.fixed_shapes) |*c, h, sh| c.* = .{ .log_size = sh.log_size, .coefficients = @as([*]const M, @ptrCast(h.ptr))[0..h.len] };
    // MAIN as device placeholders (the request's MAIN is device-resident).
    const main_cols = try a.alloc(DP.Column, in.main_logs.len);
    defer a.free(main_cols);
    for (main_cols, in.main_logs) |*c, l| c.* = NP.placeholderColumn(l);
    cl.gkr = try NG.Plan.init(a, env.catalogue, scope, in.instances, in.native, fixed_cols, main_cols, env.byte_cap, 0);
}
