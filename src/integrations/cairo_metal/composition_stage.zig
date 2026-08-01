//! The Option-A device composition product hook.
//!
//! This is the module that finally puts a Cairo composition evaluation on the
//! device from the *product* prove path. Everything it relies on was measured
//! rather than assumed by increments 3.4-3.7:
//!
//! - the eleven-offset `EvalLayout` ABI, the interaction/global column
//!   indirection, the denominator index basis `row >> trace_log_size` and the
//!   `rc_base` coefficient offset (3.5 §6, verified on four real components
//!   including a 41-part and a 90-part one);
//! - the lifted-column identity map at evaluation-domain length, and therefore
//!   the *lift* this hook stages inputs through (3.5 §1, 3.7 §3-4);
//! - that the authenticated AOT metallib and a JIT library of the same source
//!   agree to within 0.4% in steady state, so no compiler discount applies
//!   (3.7 §1-2); and
//! - the steady-state cost model, 4.54 ns per row-part plus a 0.1763 ms
//!   per-dispatch floor (3.7 §2).
//!
//! ## Admission, and what "fail closed" means at each layer
//!
//! `open` is the only place a decision is made, and it makes three:
//!
//! 1. **The library.** The product constructor uses
//!    `composition_aot.authenticateEvalDomainForProduct`, pinned to the artifact
//!    named by product identity. The diagnostic constructor retains the process
//!    policy. A rejection declines the whole stage
//!    and the proof runs the unchanged host composition path. Once the stage is
//!    armed, that decline is counted as `cpu_composition_evaluation`; the Cairo
//!    product's no-fallback publication gate then rejects the result. The
//!    default, unarmed host placement remains a placement and records nothing.
//! 2. **The arena.** Every expressible component is planned
//!    (`composition_eval_arena.plan`) and the shared buffer is sized to the
//!    largest plan. A planning refusal or a plan over the byte cap declines the
//!    whole stage, before any allocation.
//! 3. **The kernels.** Every part of every planned component must resolve by
//!    `kernelName(semantic_hash)` out of the *authenticated* library. A
//!    component with an unresolvable part is dropped from the accepted set and
//!    evaluated on the host inside the stage — this is **declared coverage, not a
//!    fallback**, and it is the mechanism that lets a workload with one
//!    unexpressible component still measure the device stage on the rest.
//!    Against `air_template_composition_eval_domain_v1` (increment 3.13) the
//!    census is 46/46 components on all-opcodes, 28/29 on arithmetic-2m and
//!    31/32 on memory-7m: the two stragglers are single components whose parts
//!    the template library does not emit, and they are declared coverage rather
//!    than a decline precisely because the whole-stage refusal in the row below
//!    would otherwise make those two workloads unmeasurable.
//!
//! A dispatch that fails *after* admission held is the one genuinely unexpected
//! case: that proof started composition on the device and finished it on the
//! host, so it records `.cpu_composition_evaluation` and can no longer report
//! `accelerated_without_fallbacks`.
//!
//! ## The lift is the staging pass
//!
//! There is no separate upload. Writing each column's lifted, evaluation-domain
//! copy into the arena *is* the staging, and it is timed as its own
//! `composition_device_lift` span so the surcharge 3.7 priced at 19-28% of the
//! device stage is measured rather than projected. It parallelises per column
//! with no sharing, over the prover's existing work pool.

const std = @import("std");
const metal = @import("stwo_metal_backend").runtime;
const shared_runtime = @import("stwo_metal_backend").shared_runtime;
const telemetry = @import("stwo_metal_backend").telemetry;
const frontend = @import("stwo_cairo_frontend");
const prover = @import("stwo_prover_engine");
const codegen = @import("eval_codegen.zig");
const composition_aot = @import("composition_aot.zig");
const eval_arena = @import("composition_eval_arena.zig");

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

/// Set to `1` to arm the hook. **The default is still off after increment
/// 3.13**, but the reason changed and it is worth being exact about, because the
/// old reason is gone.
///
/// Through 3.12 the hook resolved against `vectors/cairo/sn_pie_2_composition.metallib`,
/// whose 271 kernels share *zero* semantic hashes with the 69 the AIR template
/// library emits (3.8 §1(b)); admission resolved nothing on any portfolio
/// workload and declined every time, so arming it bought nothing and cost a
/// measured 15-40 ms. Increment 3.13 repoints resolution at
/// `air_template_composition_eval_domain_v1`, which is minted from the template
/// library's own program bundles and *does* resolve — 46/46 on all-opcodes.
/// Arming it now buys the device composition stage.
///
/// The default remains off because flipping it is a promotion decision that
/// belongs to whoever reads 3.13's gate evidence, not to the increment that
/// produced the evidence. Off, the whole hook is one env-var read (0.029 ms) and
/// the proof is byte-identical to the predecessor, which is what makes the gate's
/// two arms a clean env-only pairing off one build.
pub const enable_env = "STWO_ZIG_COMPOSITION_DEVICE";
/// Overrides the metallib path. This is how the fail-closed test points the
/// product at a corrupted copy: it names a different artifact, it never relaxes
/// the digest policy. `composition_aot.policy_env` can name a digest only for
/// the diagnostic constructor; the product constructor ignores it.
pub const metallib_env = "STWO_ZIG_COMPOSITION_METALLIB";
/// The Option-A eval-domain library, which sits beside the AIR template library
/// it was minted from rather than a directory above it like the superseded SN2
/// artifact did.
pub const metallib_leaf = "air_template_composition_eval_domain.metallib";

const AdmissionPolicy = enum {
    approved_product,
    process,
};

const Config = struct {
    /// A directory to look for the metallib in, derived from an asset path the
    /// product already resolves. Never owned.
    search_root: ?[]const u8 = null,
    admission_policy: AdmissionPolicy,
};

var product_config: Config = .{ .admission_policy = .approved_product };
var process_config: Config = .{ .admission_policy = .process };

/// Builds the product's injectable device. Product identity names the exact
/// eval-domain digest, so this route ignores the process digest policy.
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

const Entry = struct {
    plan: eval_arena.Plan,
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
    lift_ns: u64 = 0,
    lifted_bytes: u64 = 0,
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
) anyerror!?device_stage.Session {
    const self: *Config = @ptrCast(@alignCast(context));
    return open(self.*, allocator, components) catch |err| {
        recordWholeStageDecline(err);
        return null;
    };
}

fn recordWholeStageDecline(err: anyerror) void {
    // Both AOT admission wrappers already record and log rejection before
    // mapping it to this stage-local error. Every other armed-stage error is
    // recorded here exactly once before the frontend resumes host evaluation.
    if (err == error.CompositionAotAdmissionDeclined) return;
    telemetry.record(.cpu_composition_evaluation);
    std.log.err("device composition stage declined: {t}", .{err});
}

fn open(
    settings: Config,
    allocator: std.mem.Allocator,
    components: []const composition.Component,
) anyerror!?device_stage.Session {
    const armed = std.posix.getenv(enable_env) orelse return null;
    if (!std.mem.eql(u8, armed, "1")) return null;
    if (components.len == 0) return null;

    const path = try resolveMetallib(allocator, settings);
    defer allocator.free(path);
    // Integrity before load, and a rejection is terminal for this path.
    const admission = switch (settings.admission_policy) {
        .approved_product => composition_aot.authenticateEvalDomainForProduct(path),
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
        if (!eval_arena.expressible(component)) continue;
        var component_plan = eval_arena.plan(allocator, component) catch continue;
        var plan_owned = true;
        defer if (plan_owned) component_plan.deinit(allocator);
        const bytes = component_plan.words * @sizeOf(u32);
        if (bytes > byteCap()) continue;
        entry.* = .{ .plan = component_plan, .plans = &.{} };
        plan_owned = false;
        planned += 1;
        peak_words = @max(peak_words, component_plan.words);
        max_columns = @max(max_columns, component_plan.columns);
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
            const name = codegen.kernelName(allocator, part.program.header.semantic_hash) catch break;
            defer allocator.free(name);
            plan.* = lease.runtime.prepareEvalFromLibrary(
                library,
                name,
                layoutFor(ready.plan, part.rc_base, part.program.header.domain_log_size),
            ) catch break;
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
    session.* = .{
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
    };
}

fn layoutFor(plan: eval_arena.Plan, rc_base: u32, domain_log_size: u32) metal.EvalLayout {
    return .{
        .trace_offsets = plan.trace_offsets,
        .interaction_offsets = plan.interaction_offsets,
        .base_params = 0,
        .ext_params = plan.ext_params,
        .random_coeffs = plan.random_coeffs,
        .denom_inv = plan.denom_inv,
        .coordinates = plan.coordinates,
        .row_count = plan.eval_rows,
        .trace_log_size = plan.trace_log_size,
        .domain_log_size = domain_log_size,
        .rc_base = rc_base,
    };
}

fn byteCap() u64 {
    const text = std.posix.getenv(eval_arena.byte_cap_env) orelse
        return eval_arena.default_byte_cap;
    return std.fmt.parseInt(u64, std.mem.trim(u8, text, " \t\r\n"), 10) catch
        eval_arena.default_byte_cap;
}

fn resolveMetallib(allocator: std.mem.Allocator, settings: Config) ![]u8 {
    if (std.posix.getenv(metallib_env)) |override|
        return allocator.dupe(u8, override);
    if (settings.search_root) |asset| {
        // The eval-domain metallib sits *beside* the AIR template library it was
        // minted from — both are `vectors/cairo/official/` — where the superseded
        // SN2 artifact sat one directory above it. So this is the asset's own
        // directory, not its parent.
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
    if (self.lift_ns != 0) {
        const seconds = @as(f64, @floatFromInt(self.lift_ns)) / std.time.ns_per_s;
        std.log.info(
            "device composition: lift {d:.3} ms over {d} MiB ({d:.2} GB/s), " ++
                "{d} dispatches in {d} submissions, device {d:.3} ms",
            .{
                @as(f64, @floatFromInt(self.lift_ns)) / std.time.ns_per_ms,
                self.lifted_bytes >> 20,
                @as(f64, @floatFromInt(self.lifted_bytes)) / seconds / 1.0e9,
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
    const plan = entry.plan;
    const rows: usize = plan.eval_rows;

    // Resolve every read site once, exactly as the host evaluator does, so the
    // two paths lift and read the same columns.
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
            // is reinterpreted rather than copied. The lift then reads exactly
            // the words the host evaluator reads.
            self.resolved[global] = .{
                .values = @as([*]const u32, @ptrCast(resolved.values.ptr))[0..resolved.values.len],
                .shift_amt = resolved.shift_amt,
            };
            global += 1;
        }
    }

    var timer = try std.time.Timer.start();
    try eval_arena.lift(
        self.words,
        plan,
        self.resolved[0..plan.columns],
        prover.work_pool.getGlobalPool(),
    );
    self.lift_ns += timer.read();
    self.lifted_bytes += @as(u64, plan.columns) * plan.eval_rows * @sizeOf(u32);

    // Offsets, parameters, coefficients and denominators. Small blocks, written
    // after the lift so a lift refusal costs nothing else.
    for (0..plan.columns) |column|
        self.words[plan.trace_offsets + column] = plan.columnOffset(@intCast(column));
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
    // The kernels accumulate into the coordinate words across parts, so the
    // planes start at zero and the host-side additive step happens on readback.
    for (plan.coordinates) |offset|
        @memset(self.words[offset .. offset + rows], 0);

    // One submission per component instead of one per part. Each part still gets
    // its own compute encoder and its own dispatch with the bindings baked at
    // prepare time, and command encoders within one command buffer run in
    // encode order, so the cross-part accumulation above is unaffected; what
    // goes away is the blocking round trip the 3.11 census priced at 0.169 ms.
    // This is the FRI quotient's "encode many, wait once" pattern
    // (`resident_fri_transaction.zig:163`), not a new one.
    const batch = entry.batch orelse return error.UnplannedComponent;
    self.device_gpu_ms += try self.lease.runtime.evalBatchPrepared(self.arena, batch);
    self.submissions += 1;
    for (entry.plans) |_| {
        self.dispatches += 1;
        telemetry.record(.metal_composition_eval_dispatch);
    }

    for (plan.coordinates, request.output) |offset, destination| {
        if (destination.len != rows) return error.InvalidOutputPlane;
        const source = self.words[offset .. offset + rows];
        if (request.additive) {
            for (destination, source) |*value, word|
                value.* = value.*.add(M31.fromU32Unchecked(word));
        } else {
            for (destination, source) |*value, word|
                value.* = M31.fromU32Unchecked(word);
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
        "air_template_composition_eval_domain.metallib",
        metallib_leaf,
    );
    try std.testing.expectEqualStrings(
        "vectors/cairo/official/air_template_composition_eval_domain.metallib",
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
    try std.testing.expectEqualStrings(
        "/product/air_template_library_v1.json",
        product_settings.search_root.?,
    );
    try std.testing.expectEqualStrings(
        "/diagnostic/air_template_library_v1.json",
        diagnostic_settings.search_root.?,
    );
}

test "the default metallib path is the eval-domain entry in the approved manifest" {
    // The path the product resolves and the manifest entry that admits it must
    // not drift apart: a rename on one side has to fail here rather than at a
    // proof's admission gate.
    var found = false;
    for (composition_aot.approved_metallibs) |approved| {
        if (std.mem.eql(u8, approved.label, "air_template_composition_eval_domain_v1"))
            found = true;
    }
    try std.testing.expect(found);
    try std.testing.expect(std.mem.endsWith(u8, default_metallib_path, metallib_leaf));
}

test "armed whole-stage declines enter no-fallback evidence" {
    const empty_cache = metal.PipelineCacheStats.zero();
    const before = telemetry.capture(empty_cache).counters.cpu_composition_evaluations;
    recordWholeStageDecline(error.NoAuthenticatedCompositionKernels);
    const after = telemetry.capture(empty_cache).counters.cpu_composition_evaluations;
    try std.testing.expectEqual(before + 1, after);
}
