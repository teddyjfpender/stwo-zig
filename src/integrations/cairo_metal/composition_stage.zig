//! Authenticated Cairo composition with bounded GPU placement.
//!
//! Components that fit the shared arena use native-height columns and GPU
//! lifting. Larger components stage exact masked row tiles, keeping that same
//! arena cap. The product authenticates one library exporting both readers.
//! Missing kernels remain declared host coverage. Unexpected dispatch errors
//! enter fallback telemetry and reject accelerated proof publication.

const std = @import("std");
const metal = @import("stwo_metal_backend").runtime;
const shared_runtime = @import("stwo_metal_backend").shared_runtime;
const telemetry = @import("stwo_metal_backend").telemetry;
const frontend = @import("stwo_cairo_frontend");
const prover = @import("stwo_prover_engine");
const codegen = @import("eval_codegen.zig");
const composition_aot = @import("composition_aot.zig");
const eval_arena = @import("composition_eval_arena.zig");
const tiled_arena = @import("composition_tiled_arena.zig");
const stored_arena = @import("composition_stored_arena.zig");

const composition = frontend.witness.composition_bundle;
const device_stage = frontend.proving.air.device_stage;
const M31 = @import("stwo_core").fields.m31.M31;

const simd_null_column = frontend.proving.air.simd_evaluator.ResolvedColumn{
    .values = &.{},
    .shift_amt = 0,
};

comptime {
    if (@sizeOf(M31) != @sizeOf(u32)) @compileError("M31 is no longer one word");
}

/// Diagnostic devices are armed with `1`; the Metal product enables the stage
/// by default; the diagnostic setting does not override product placement.
pub const enable_env = "STWO_ZIG_COMPOSITION_DEVICE";
/// Overrides the metallib path. This is how the fail-closed test points the
/// product at a corrupted copy: it names a different artifact, it never relaxes
/// the digest policy. `composition_aot.policy_env` can name a digest only for
/// the diagnostic constructor; the product constructor ignores it.
pub const metallib_env = "STWO_ZIG_COMPOSITION_METALLIB";
/// The product's stored-domain artifact sits beside its AIR template library.
pub const metallib_leaf = "air_template_composition_bounded.metallib";

const AdmissionPolicy = enum {
    approved_product,
    process,
};

const Config = struct {
    /// A directory to look for the metallib in, derived from an asset path the
    /// product already resolves. Never owned.
    search_root: ?[]const u8 = null,
    admission_policy: AdmissionPolicy,
    enabled_by_default: bool = false,
};

var product_config: Config = .{ .admission_policy = .approved_product, .enabled_by_default = true };
var process_config: Config = .{ .admission_policy = .process };

/// Builds the product's injectable device. Product identity names the exact
/// stored-domain digest, so this route ignores the process digest policy.
pub fn productDevice(asset_path: ?[]const u8) device_stage.Device {
    product_config.search_root = asset_path;
    return .{ .context = &product_config, .open = openAdapter };
}

/// Builds a diagnostic injectable device. Tools retain the explicit process
/// digest override, but use storage distinct from the product constructor so a
/// diagnostic call cannot change the product admission policy.
pub fn device(asset_path: ?[]const u8) device_stage.Device {
    process_config.search_root = asset_path;
    return .{ .context = &process_config, .open = openAdapter };
}

/// Native placement avoids expansion for components that fit the arena. Larger
/// components use exact masked row tiles under the same authenticated library.
const ComponentPlan = union(enum) {
    native: stored_arena.Plan,
    tiled: tiled_arena.Plan,

    fn layout(self: ComponentPlan) eval_arena.Plan {
        return switch (self) {
            .native => |value| value.layout,
            .tiled => |value| value.layout,
        };
    }
    fn abi(self: ComponentPlan) codegen.TraceAbi {
        return switch (self) {
            .native => .stored_domain,
            .tiled => .tiled_domain,
        };
    }
    fn rows(self: ComponentPlan) u32 {
        return switch (self) {
            .native => |value| value.layout.eval_rows,
            .tiled => |value| value.tile_rows,
        };
    }
    fn baseParams(self: ComponentPlan) u32 {
        return switch (self) {
            .native => |value| value.base_params,
            .tiled => |value| value.base_params,
        };
    }
    fn deinit(self: *ComponentPlan, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .native => |*value| value.deinit(allocator),
            .tiled => |*value| value.deinit(allocator),
        }
        self.* = undefined;
    }
};

fn planComponent(allocator: std.mem.Allocator, component: composition.Component, logs: []const []u32, cap: u64) !ComponentPlan {
    var native = stored_arena.plan(allocator, component, logs) catch |err| {
        if (err != error.EvalArenaTooLarge) return err;
        return .{ .tiled = try tiled_arena.plan(allocator, component, cap) };
    };
    if (native.layout.words <= cap / @sizeOf(u32)) return .{ .native = native };
    native.deinit(allocator);
    return .{ .tiled = try tiled_arena.plan(allocator, component, cap) };
}

const Entry = struct {
    plan: ComponentPlan,
    plans: []metal.EvalPlan,
    /// The `plans` above, grouped so every part of this component encodes into
    /// one command buffer. Null until kernel resolution succeeds, and therefore
    /// non-null for exactly the accepted entries.
    batch: ?metal.EvalBatchPlan = null,

    fn deinit(self: *Entry, allocator: std.mem.Allocator) void {
        if (self.batch) |*batch| batch.deinit();
        for (self.plans) |*plan| plan.deinit();
        allocator.free(self.plans);
        self.plan.deinit(allocator);
        self.* = undefined;
    }
};

const Session = struct {
    allocator: std.mem.Allocator,
    /// Borrowed. The bundle outlives the prove call it was opened for, and this
    /// is what makes a request's component identity recoverable without the
    /// frontend having to carry an index.
    components: []const composition.Component,
    lease: shared_runtime.CallLease,
    library: metal.EvalLibrary,
    arena: metal.ResidentBuffer,
    words: []u32,
    /// One entry per bundle component; null where the component is not accepted.
    entries: []?Entry,
    resolved: []eval_arena.ResolvedScratch = &.{},
    expansion_twiddles: ?prover.poly.twiddles.TwiddleTree([]M31) = null,
    max_trace_log: u32 = 0,
    stage_ns: u64 = 0,
    staged_bytes: u64 = 0,
    native_staged_bytes: u64 = 0,
    tiled_staged_bytes: u64 = 0,
    dispatches: u64 = 0,
    /// Blocking submissions actually made. One per evaluated component, against
    /// the `dispatches` above which stay one per part; the gap between the two
    /// is what increment 3.12 bought and is why both are logged.
    submissions: u64 = 0,
    device_gpu_ms: f64 = 0,
};

fn openAdapter(
    context: *anyopaque,
    allocator: std.mem.Allocator,
    components: []const composition.Component,
    column_log_sizes: []const []u32,
) anyerror!?device_stage.Session {
    const self: *Config = @ptrCast(@alignCast(context));
    return open(self.*, allocator, components, column_log_sizes) catch |err| {
        recordWholeStageDecline(err);
        return null;
    };
}

// Deliberate negative tests assert rejection and telemetry without making the
// Zig test runner treat their expected diagnostic as an unexpected test error.
var expected_test_rejection = false;

fn recordWholeStageDecline(err: anyerror) void {
    // Both AOT admission wrappers already record and log rejection before
    // mapping it to this stage-local error. Every other armed-stage error is
    // recorded here exactly once before the frontend resumes host evaluation.
    if (err == error.CompositionAotAdmissionDeclined) return;
    telemetry.record(.cpu_composition_evaluation);
    if (@import("builtin").is_test and expected_test_rejection) return;
    std.log.err("device composition stage declined: {t}", .{err});
}

fn open(
    settings: Config,
    allocator: std.mem.Allocator,
    components: []const composition.Component,
    column_log_sizes: []const []u32,
) anyerror!?device_stage.Session {
    if (!settings.enabled_by_default) {
        const armed = std.posix.getenv(enable_env) orelse return null;
        if (!std.mem.eql(u8, armed, "1")) return null;
    }
    if (components.len == 0) return null;

    const path = try resolveMetallib(allocator, settings);
    defer allocator.free(path);
    // Integrity before load, and a rejection is terminal for this path.
    const admission = switch (settings.admission_policy) {
        .approved_product => composition_aot.authenticateBoundedForProduct(path),
        .process => composition_aot.authenticateFromProcess(allocator, path),
    } catch return error.CompositionAotAdmissionDeclined;
    std.log.info(
        "device composition metallib admitted: {s} ({s}, {d} bytes)",
        .{ admission.label orelse "pinned", &admission.measurement.hex(), admission.measurement.length },
    );

    var lease = try shared_runtime.acquireExisting();
    var lease_owned = true;
    defer if (lease_owned) lease.deinit();

    const accepts = try allocator.alloc(bool, components.len);
    errdefer allocator.free(accepts);
    @memset(accepts, false);

    const entries = try allocator.alloc(?Entry, components.len);
    errdefer allocator.free(entries);
    @memset(entries, null);
    var planned: usize = 0;
    errdefer for (entries[0..components.len]) |*entry| {
        if (entry.*) |*owned| owned.deinit(allocator);
    };

    var peak_words: u64 = 0;
    var max_columns: u32 = 0;
    for (components, entries) |component, *entry| {
        if (!eval_arena.expressible(component)) {
            std.log.info("composition host admission: {s}: unsupported geometry", .{component.label});
            continue;
        }
        var component_plan = planComponent(allocator, component, column_log_sizes, byteCap(settings)) catch |err| {
            std.log.info("composition host admission: {s}: plan {t}", .{ component.label, err });
            continue;
        };
        var plan_owned = true;
        defer if (plan_owned) component_plan.deinit(allocator);
        if (component_plan == .tiled)
            std.log.info("composition tiled admission: {s}: {d} rows per tile, {d} MiB arena", .{ component.label, component_plan.rows(), component_plan.layout().words * @sizeOf(u32) >> 20 });
        entry.* = .{ .plan = component_plan, .plans = &.{} };
        plan_owned = false;
        planned += 1;
        peak_words = @max(peak_words, component_plan.layout().words);
        max_columns = @max(max_columns, component_plan.layout().columns);
    }
    if (planned == 0) return error.NoExpressibleCompositionComponents;

    var library = try lease.runtime.loadEvalLibrary(path);
    var library_owned = true;
    defer if (library_owned) library.deinit();

    // Kernel resolution is the third admission gate and it is done here, once,
    // so that a component with an unresolvable part never reaches a dispatch.
    var accepted: usize = 0;
    for (components, entries, accepts) |component, *entry, *accepted_flag| {
        const ready = if (entry.*) |*owned| owned else continue;
        const plans = allocator.alloc(metal.EvalPlan, component.parts.len) catch continue;
        var resolved: usize = 0;
        for (component.parts, plans) |part, *plan| {
            const name = codegen.kernelNameFor(allocator, part.program.header.semantic_hash, ready.plan.abi()) catch break;
            defer allocator.free(name);
            plan.* = lease.runtime.prepareEvalFromLibrary(
                library,
                name,
                layoutFor(ready.plan, part.rc_base, part.program.header.domain_log_size),
            ) catch |err| {
                std.log.info("composition host admission: {s}: kernel {s}: {t}", .{ component.label, name, err });
                break;
            };
            resolved += 1;
        }
        if (resolved != component.parts.len) {
            for (plans[0..resolved]) |*plan| plan.deinit();
            allocator.free(plans);
            entry.*.?.deinit(allocator);
            entry.* = null;
            continue;
        }
        // Grouping is the fourth and last step of the same gate: a batch is a
        // retained list of the pipelines just resolved above, so it introduces
        // no kernel, no binding and no dispatch of its own, and a component
        // that cannot be grouped declines exactly as one that cannot resolve.
        const batch = lease.runtime.prepareEvalBatch(plans) catch {
            for (plans) |*plan| plan.deinit();
            allocator.free(plans);
            entry.*.?.deinit(allocator);
            entry.* = null;
            continue;
        };
        ready.plans = plans;
        ready.batch = batch;
        accepted_flag.* = true;
        accepted += 1;
    }
    if (accepted == 0) return error.NoAuthenticatedCompositionKernels;

    var arena = try lease.runtime.allocateResidentBuffer(peak_words * @sizeOf(u32));
    var arena_owned = true;
    defer if (arena_owned) arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));

    const resolved_scratch = try allocator.alloc(eval_arena.ResolvedScratch, max_columns);
    errdefer allocator.free(resolved_scratch);

    const session = try allocator.create(Session);
    errdefer allocator.destroy(session);
    var max_trace_log: u32 = 0;
    for (column_log_sizes) |logs| for (logs) |log| {
        max_trace_log = @max(max_trace_log, log);
    };
    session.* = .{
        .max_trace_log = max_trace_log,
        .allocator = allocator,
        .components = components,
        .lease = lease,
        .library = library,
        .arena = arena,
        .words = words[0..@intCast(peak_words)],
        .entries = entries,
        .resolved = resolved_scratch,
    };
    lease_owned = false;
    library_owned = false;
    arena_owned = false;

    std.log.info(
        "device composition stage open: {d}/{d} components accepted, arena {d} MiB",
        .{ accepted, components.len, (peak_words * @sizeOf(u32)) >> 20 },
    );
    return .{
        .context = session,
        .accepts = accepts,
        .evaluate = evaluateAdapter,
        .close = closeAdapter,
        .expansion = .{ .context = session, .run = expandTraceAdapter },
    };
}

fn layoutFor(stored: ComponentPlan, rc_base: u32, domain_log_size: u32) metal.EvalLayout {
    const plan = stored.layout();
    return .{
        .trace_offsets = plan.trace_offsets,
        .interaction_offsets = plan.interaction_offsets,
        .base_params = stored.baseParams(),
        .ext_params = plan.ext_params,
        .random_coeffs = plan.random_coeffs,
        .denom_inv = plan.denom_inv,
        .coordinates = plan.coordinates,
        .row_count = stored.rows(),
        .evaluation_log_size = if (stored == .tiled) @ctz(plan.eval_rows) else null,
        .trace_log_size = plan.trace_log_size,
        .domain_log_size = domain_log_size,
        .rc_base = rc_base,
    };
}

fn byteCap(settings: Config) u64 {
    if (settings.admission_policy == .approved_product)
        return eval_arena.default_byte_cap;
    const text = std.posix.getenv(eval_arena.byte_cap_env) orelse
        return eval_arena.default_byte_cap;
    return std.fmt.parseInt(u64, std.mem.trim(u8, text, " \t\r\n"), 10) catch
        eval_arena.default_byte_cap;
}

fn resolveMetallib(allocator: std.mem.Allocator, settings: Config) ![]u8 {
    if (std.posix.getenv(metallib_env)) |override|
        return allocator.dupe(u8, override);
    if (settings.search_root) |asset| {
        // Prefer the installed sibling of the resolved AIR template asset.
        if (std.fs.path.dirname(asset)) |leaf_dir| {
            const candidate = try std.fs.path.join(allocator, &.{ leaf_dir, metallib_leaf });
            errdefer allocator.free(candidate);
            std.fs.cwd().access(candidate, .{}) catch {
                allocator.free(candidate);
                return allocator.dupe(u8, default_metallib_path);
            };
            return candidate;
        }
    }
    return allocator.dupe(u8, default_metallib_path);
}

/// The in-tree location, used when no asset path was resolved or the sibling
/// lookup missed. Relative, because every proving path runs with the repository
/// root as its working directory.
const default_metallib_path = "vectors/cairo/official/" ++ metallib_leaf;

fn closeAdapter(context: *anyopaque) void {
    const self: *Session = @ptrCast(@alignCast(context));
    const allocator = self.allocator;
    if (self.expansion_twiddles) |*tree| prover.poly.twiddles.deinitM31(allocator, tree);
    if (self.stage_ns != 0) {
        const seconds = @as(f64, @floatFromInt(self.stage_ns)) / std.time.ns_per_s;
        std.log.info(
            "device composition: trace staging {d:.3} ms over {d} MiB " ++
                "(native {d} MiB, tiled {d} MiB; {d:.2} GB/s), " ++
                "{d} dispatches in {d} submissions, device {d:.3} ms",
            .{
                @as(f64, @floatFromInt(self.stage_ns)) / std.time.ns_per_ms,
                self.staged_bytes >> 20,
                self.native_staged_bytes >> 20,
                self.tiled_staged_bytes >> 20,
                @as(f64, @floatFromInt(self.staged_bytes)) / seconds / 1.0e9,
                self.dispatches,
                self.submissions,
                self.device_gpu_ms,
            },
        );
    }
    for (self.entries) |*entry| {
        if (entry.*) |*owned| owned.deinit(allocator);
    }
    allocator.free(self.entries);
    allocator.free(self.resolved);
    self.arena.deinit();
    self.library.deinit();
    self.lease.deinit();
    allocator.destroy(self);
}

fn evaluateAdapter(context: *anyopaque, request: *const device_stage.Request) anyerror!void {
    const self: *Session = @ptrCast(@alignCast(context));
    return evaluate(self, request) catch |err| {
        telemetry.record(.cpu_composition_evaluation);
        std.log.err("device composition evaluation declined: {t}", .{err});
        return err;
    };
}

fn evaluate(self: *Session, request: *const device_stage.Request) !void {
    const index = indexOf(self, request.captured) orelse return error.UnplannedComponent;
    const entry = &(self.entries[index] orelse return error.UnplannedComponent);
    const stored = entry.plan;
    const plan = stored.layout();
    const rows: usize = plan.eval_rows;

    // Resolve every read site once, exactly as the host evaluator does, so the
    // two paths read the same columns with identical domain shifts.
    var global: u32 = 0;
    for (0..plan.interactions) |interaction| {
        const count = if (interaction + 1 < plan.interactions)
            plan.bases[interaction + 1] - plan.bases[interaction]
        else
            plan.columns - plan.bases[interaction];
        for (0..count) |column| {
            const resolved = request.trace.resolve(
                request.trace.context,
                @intCast(interaction),
                @intCast(column),
            ) catch simd_null_column;
            // `M31` is a single-`u32` struct, so the product's committed column
            // is reinterpreted rather than copied before native staging.
            self.resolved[global] = .{
                .values = @as([*]const u32, @ptrCast(resolved.values.ptr))[0..resolved.values.len],
                .shift_amt = resolved.shift_amt,
            };
            global += 1;
        }
    }

    for (request.output) |destination|
        if (destination.len != rows) return error.InvalidOutputPlane;

    // Offsets, parameters, coefficients and denominators. Small blocks, written
    // after native staging succeeds.
    for (plan.bases, 0..) |base, slot|
        self.words[plan.interaction_offsets + slot] = base;
    for (0..plan.ext_param_count) |slot| {
        const value = if (slot < request.extension_parameters.len)
            request.extension_parameters[slot].toM31Array()
        else
            [_]M31{M31.zero()} ** 4;
        for (value, 0..) |coordinate, lane|
            self.words[plan.ext_params + 4 * slot + lane] = coordinate.v;
    }
    if (request.random_coefficients.len < plan.coefficient_count)
        return error.InvalidCoefficientVector;
    for (0..plan.coefficient_count) |slot| {
        const value = request.random_coefficients[slot].toM31Array();
        for (value, 0..) |coordinate, lane|
            self.words[plan.random_coeffs + 4 * slot + lane] = coordinate.v;
    }
    if (request.captured.denominator_inverses.len != plan.denominator_count)
        return error.InvalidDenominatorVector;
    @memcpy(
        self.words[plan.denom_inv .. plan.denom_inv + plan.denominator_count],
        request.captured.denominator_inverses,
    );
    switch (stored) {
        .native => |native| {
            var timer = try std.time.Timer.start();
            const bytes = try stored_arena.stage(self.words, native, self.resolved[0..plan.columns]);
            self.staged_bytes += bytes;
            self.native_staged_bytes += bytes;
            self.stage_ns += timer.read();
            for (plan.coordinates) |offset| @memset(self.words[offset..][0..rows], 0);
            try submit(self, entry);
            publish(request, self.words, plan.coordinates, rows);
        },
        .tiled => |tiled| {
            // The frontend may resume exact host evaluation after any error.
            // Collect results transactionally so a late failed tile never leaves
            // partial additions in that shared composition accumulator.
            const result = try self.allocator.alloc(u32, try std.math.mul(usize, rows, 4));
            defer self.allocator.free(result);
            var row_base: u32 = 0;
            var component_staged_bytes: u64 = 0;
            while (row_base < plan.eval_rows) : (row_base += tiled.tile_rows) {
                var timer = try std.time.Timer.start();
                const bytes = try tiled_arena.stage(self.words, tiled, self.resolved[0..plan.columns], row_base, tiled.tile_rows);
                self.staged_bytes += bytes;
                self.tiled_staged_bytes += bytes;
                component_staged_bytes += bytes;
                self.stage_ns += timer.read();
                for (plan.coordinates) |offset| @memset(self.words[offset..][0..tiled.tile_rows], 0);
                try submit(self, entry);
                for (plan.coordinates, 0..) |offset, lane|
                    @memcpy(result[lane * rows + row_base ..][0..tiled.tile_rows], self.words[offset..][0..tiled.tile_rows]);
            }
            const offsets = [4]u32{ 0, @intCast(rows), @intCast(2 * rows), @intCast(3 * rows) };
            publish(request, result, offsets, rows);
            std.log.info("composition tile staging: {s}: {d} MiB across {d} read sites", .{
                request.captured.label, component_staged_bytes >> 20, tiled.reads.len,
            });
        },
    }
}

fn submit(self: *Session, entry: *const Entry) !void {
    const batch = entry.batch orelse return error.UnplannedComponent;
    self.device_gpu_ms += try self.lease.runtime.evalBatchPrepared(self.arena, batch);
    self.submissions += 1;
    for (entry.plans) |_| {
        self.dispatches += 1;
        telemetry.record(.metal_composition_eval_dispatch);
    }
}

fn publish(request: *const device_stage.Request, words: []const u32, offsets: [4]u32, rows: usize) void {
    for (offsets, request.output) |offset, destination| {
        const source = words[offset..][0..rows];
        if (request.additive) {
            for (destination, source) |*value, word| value.* = value.*.add(M31.fromU32Unchecked(word));
        } else {
            for (destination, source) |*value, word| value.* = M31.fromU32Unchecked(word);
        }
    }
}

/// Identity, by address rather than by label: the frontend walks the same
/// bundle slice the session was opened with, so the request's `captured`
/// pointer is one of these elements.
fn indexOf(self: *Session, captured: *const composition.Component) ?usize {
    for (self.components, 0..) |*component, index| {
        if (component == captured) return index;
    }
    return null;
}

test "the enable switch and the path override are named, not guessed" {
    try std.testing.expectEqualStrings("STWO_ZIG_COMPOSITION_DEVICE", enable_env);
    try std.testing.expectEqualStrings("STWO_ZIG_COMPOSITION_METALLIB", metallib_env);
    try std.testing.expectEqualStrings(
        "air_template_composition_bounded.metallib",
        metallib_leaf,
    );
    try std.testing.expectEqualStrings(
        "vectors/cairo/official/air_template_composition_bounded.metallib",
        default_metallib_path,
    );
}

test "product and diagnostic constructors retain distinct admission policies" {
    const product = productDevice("/product/air_template_library_v1.json");
    const diagnostic = device("/diagnostic/air_template_library_v1.json");
    const product_settings: *const Config = @ptrCast(@alignCast(product.context));
    const diagnostic_settings: *const Config = @ptrCast(@alignCast(diagnostic.context));

    try std.testing.expect(product.context != diagnostic.context);
    try std.testing.expectEqual(AdmissionPolicy.approved_product, product_settings.admission_policy);
    try std.testing.expectEqual(AdmissionPolicy.process, diagnostic_settings.admission_policy);
    try std.testing.expect(product_settings.enabled_by_default);
    try std.testing.expect(!diagnostic_settings.enabled_by_default);
    try std.testing.expectEqualStrings(
        "/product/air_template_library_v1.json",
        product_settings.search_root.?,
    );
    try std.testing.expectEqualStrings(
        "/diagnostic/air_template_library_v1.json",
        diagnostic_settings.search_root.?,
    );
}

test "the default metallib path is the stored-domain entry in the approved manifest" {
    // The path the product resolves and the manifest entry that admits it must
    // not drift apart: a rename on one side has to fail here rather than at a
    // proof's admission gate.
    var found = false;
    for (composition_aot.approved_metallibs) |approved| {
        if (std.mem.eql(u8, approved.label, composition_aot.bounded_label))
            found = true;
    }
    try std.testing.expect(found);
    try std.testing.expect(std.mem.endsWith(u8, default_metallib_path, metallib_leaf));
}

test "armed whole-stage declines enter no-fallback evidence" {
    expected_test_rejection = true;
    defer expected_test_rejection = false;
    const empty_cache = metal.PipelineCacheStats.zero();
    const before = telemetry.capture(empty_cache).counters.cpu_composition_evaluations;
    recordWholeStageDecline(error.NoAuthenticatedCompositionKernels);
    const after = telemetry.capture(empty_cache).counters.cpu_composition_evaluations;
    try std.testing.expectEqual(before + 1, after);
}

/// Reconstruct only the current component's captured columns. Domain groups
/// share a native GPU FFT dispatch and retire when device evaluation joins.
fn expandTraceAdapter(raw: *anyopaque, a: std.mem.Allocator, requests: []const device_stage.trace_lease.ExpansionRequest) !void {
    const session: *Session = @ptrCast(@alignCast(raw));
    if (session.expansion_twiddles == null) {
        const domain = prover.poly.circle.CanonicCoset.new(session.max_trace_log).circleDomain();
        session.expansion_twiddles = try prover.poly.twiddles.precomputeM31(session.allocator, domain.half_coset);
    }
    const transform = session.expansion_twiddles.?;
    const order = try a.alloc(usize, requests.len);
    defer a.free(order);
    for (order, 0..) |*index, i| index.* = i;
    const Sort = struct {
        requests: []const device_stage.trace_lease.ExpansionRequest,
        fn less(self: @This(), left: usize, right: usize) bool {
            const l = self.requests[left].log_size;
            const r = self.requests[right].log_size;
            // The lease provides each domain in one contiguous owner. Preserve
            // its within-domain order so the runtime can borrow that owner.
            return l < r or (l == r and left < right);
        }
    };
    std.sort.heap(usize, order, Sort{ .requests = requests }, Sort.less);
    var next: usize = 0;
    while (next < order.len) {
        const log = requests[order[next]].log_size;
        if (log < 3) return error.UnsupportedNativeTraceExpansion;
        var end = next + 1;
        var bytes = try std.math.mul(usize, requests[order[next]].values.len, @sizeOf(M31));
        while (end < order.len and requests[order[end]].log_size == log) : (end += 1) {
            const extra = try std.math.mul(usize, requests[order[end]].values.len, @sizeOf(M31));
            if (try std.math.add(usize, bytes, extra) > 128 * 1024 * 1024) break;
            bytes += extra;
        }
        const buffers = try a.alloc([]M31, end - next);
        defer a.free(buffers);
        for (order[next..end], buffers) |index, *buffer| {
            const request = requests[index];
            @memcpy(request.values[0..request.coefficients.len], request.coefficients);
            @memset(request.values[request.coefficients.len..], M31.zero());
            buffer.* = request.values;
        }
        _ = try session.lease.runtime.transformCircle(a, buffers, (try transform.subtree(log - 1)).twiddles, log, false);
        telemetry.record(.metal_circle_transform_dispatch);
        next = end;
    }
}
