//! Increment 3.7, step 1: does the authenticated AOT metallib actually run
//! slower than a JIT library of the same source?
//!
//! Increment 3.6 §6 finding 4 reported the AOT metallib at 1.0x-3.05x *slower*
//! than a JIT library built from the same codegen source, on the same four
//! components, in the same `metal-test` process. That is a 3x uncertainty on the
//! program's central number, because a product hook must load the authenticated
//! AOT library while every price in 3.6 was measured on JIT.
//!
//! But that evidence was not a controlled comparison, and this file is. 3.6's
//! AOT numbers came out of the increment 3.5 binding test and its JIT numbers
//! out of the 3.6 fusion sweep: **different arenas, different fill seeds,
//! different allocation histories, and a fixed order** (the binding test runs
//! first). Any of those confounds a 3x claim. So this test:
//!
//!   1. loads **both** libraries once, up front, from one runtime;
//!   2. builds **one** arena per component and fills it **once**, so both arms
//!      read byte-identical inputs from byte-identical addresses;
//!   3. prepares each arm's pipelines **once**, outside the timed region, so
//!      pipeline creation and the eval pipeline cache are not in the number;
//!   4. runs one untimed warmup per arm, then interleaves **A-B-B-A** for
//!      several blocks, reporting *every* sample so an order or warm-up effect
//!      is visible rather than averaged away;
//!   5. byte-compares the two arms' four QM31 coordinate planes on every row,
//!      so "the same kernel" is a verified claim and not an assumption about
//!      `semanticHash`.
//!
//! It also runs a third arm — the AOT library with a **fresh plan per dispatch**,
//! which is what the 3.5 binding test and the 3.6 sweep both did — to separate
//! "the offline compiler emits worse code" from "pipeline creation per dispatch
//! costs something".
//!
//! ## The staleness hypothesis is already excluded, offline
//!
//! `vectors/cairo/sn_pie_2_composition.metallib` was committed in `7123cc22`
//! (2026-07-11) and `eval_codegen.zig` has changed four times since. Running the
//! `metal-eval-source` emitter at `7123cc22` and at this head over the same
//! `sn_pie_2_composition.bin` gives 4,306,723 and 4,322,603 bytes of MSL for the
//! same plan hash `8fc4db5088697537` and the same 271 unique programs — and the
//! **entire** difference is the identifier rename `acc` -> `part_acc` that the
//! fusion work introduced so a fused kernel could hold a separate `cumulative`
//! accumulator. Normalising that one identifier makes the two emissions
//! byte-identical. So the AOT artifact is not stale in any sense a compiler can
//! observe, and this test does not need to chase that.
//!
//! `metal_source_emission_is_rename_stable_since_the_metallib_was_compiled`
//! below pins the surviving half of that claim in-tree: the emitter must keep
//! emitting exactly one accumulator identifier per part body, so a future change
//! that alters kernel *text* cannot masquerade as a rename.

const std = @import("std");

const metal = @import("stwo_metal_backend").runtime;
const cairo = @import("stwo_cairo_frontend");
const integration = @import("stwo_cairo_metal_integration");

const composition = cairo.witness.composition_bundle;
const codegen = integration.eval_codegen;
const composition_aot = integration.composition_aot;

const m31_modulus: u64 = (1 << 31) - 1;

const bundle_path = "vectors/cairo/sn_pie_2_composition.bin";
const metallib_path = "vectors/cairo/sn_pie_2_composition.metallib";

/// A-B-B-A blocks. Two gives four samples per arm, which is enough to see an
/// order effect; the components here are large enough that more is budget rather
/// than information.
const blocks: usize = 2;

/// Deterministic, canonical-range filler. Identical to the increment 3.5 and 3.6
/// fillers on purpose.
fn fill(words: []u32, seed: u64) void {
    var state = seed | 1;
    for (words) |*word| {
        state = state *% 6364136223846793005 +% 1442695040888963407;
        word.* = @intCast((state >> 33) % (m31_modulus - 1) + 1);
    }
}

fn columnCounts(
    allocator: std.mem.Allocator,
    component: composition.Component,
) ![]u32 {
    var interactions: u32 = 0;
    for (component.parts) |part|
        interactions = @max(interactions, part.program.header.n_interactions);
    const counts = try allocator.alloc(u32, interactions);
    @memset(counts, 0);
    for (component.parts) |part| {
        for (part.program.base_insts) |instruction| switch (instruction.op) {
            .trace_col, .preprocessed_col => {
                if (instruction.interaction >= counts.len)
                    return error.InvalidCompositionPart;
                counts[instruction.interaction] =
                    @max(counts[instruction.interaction], instruction.a + 1);
            },
            else => {},
        };
    }
    return counts;
}

const ArenaLayout = struct {
    trace_offsets: u32,
    interaction_offsets: u32,
    ext_params: u32,
    random_coeffs: u32,
    denom_inv: u32,
    coordinates: [4]u32,
    row_count: u32,
    trace_log: u32,
};

/// One arm: a library plus how it prepares plans.
const Arm = struct {
    name: []const u8,
    library: metal.EvalLibrary,
    /// When true, a plan is created and destroyed per dispatch — which is what
    /// increments 3.5 and 3.6 both did, and therefore what their numbers include.
    fresh_plan_per_dispatch: bool,
    /// Plans prepared once, used when `fresh_plan_per_dispatch` is false.
    plans: []metal.EvalPlan = &.{},
};

fn evalLayoutFor(
    layout: ArenaLayout,
    part: composition.Part,
) metal.EvalLayout {
    return .{
        .trace_offsets = layout.trace_offsets,
        .interaction_offsets = layout.interaction_offsets,
        .base_params = 0,
        .ext_params = layout.ext_params,
        .random_coeffs = layout.random_coeffs,
        .denom_inv = layout.denom_inv,
        .coordinates = layout.coordinates,
        .row_count = layout.row_count,
        .trace_log_size = layout.trace_log,
        .domain_log_size = part.program.header.domain_log_size,
        .rc_base = part.rc_base,
    };
}

/// Dispatches every part of `component` from `arm`'s library and returns the
/// summed `gpu_ms`. Zeroes the coordinate planes first: every kernel accumulates.
fn runArm(
    allocator: std.mem.Allocator,
    runtime: *metal.Runtime,
    arm: *Arm,
    component: composition.Component,
    layout: ArenaLayout,
    arena: metal.ResidentBuffer,
) !f64 {
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    for (layout.coordinates) |offset|
        @memset(words[offset .. offset + layout.row_count], 0);

    var gpu_ms: f64 = 0;
    if (arm.fresh_plan_per_dispatch) {
        for (component.parts) |part| {
            const name = try codegen.kernelName(allocator, part.program.header.semantic_hash);
            defer allocator.free(name);
            var plan = try runtime.prepareEvalFromLibrary(
                arm.library,
                name,
                evalLayoutFor(layout, part),
            );
            defer plan.deinit();
            gpu_ms += try runtime.evalPrepared(arena, plan);
        }
    } else {
        for (arm.plans) |plan| gpu_ms += try runtime.evalPrepared(arena, plan);
    }
    return gpu_ms;
}

fn preparePlans(
    allocator: std.mem.Allocator,
    runtime: *metal.Runtime,
    arm: *Arm,
    component: composition.Component,
    layout: ArenaLayout,
) !void {
    if (arm.fresh_plan_per_dispatch) return;
    const plans = try allocator.alloc(metal.EvalPlan, component.parts.len);
    var prepared: usize = 0;
    errdefer {
        for (plans[0..prepared]) |*plan| plan.deinit();
        allocator.free(plans);
    }
    for (component.parts, plans) |part, *plan| {
        const name = try codegen.kernelName(allocator, part.program.header.semantic_hash);
        defer allocator.free(name);
        plan.* = try runtime.prepareEvalFromLibrary(
            arm.library,
            name,
            evalLayoutFor(layout, part),
        );
        prepared += 1;
    }
    arm.plans = plans;
}

fn releasePlans(allocator: std.mem.Allocator, arm: *Arm) void {
    for (arm.plans) |*plan| plan.deinit();
    if (arm.plans.len != 0) allocator.free(arm.plans);
    arm.plans = &.{};
}

/// Emits the per-part source this component needs, exactly as the offline
/// producer would, and JIT-compiles it.
fn jitLibrary(
    allocator: std.mem.Allocator,
    runtime: *metal.Runtime,
    component: composition.Component,
) !struct { library: metal.EvalLibrary, source_bytes: usize, compile_ms: f64 } {
    var source = std.ArrayList(u8).empty;
    defer source.deinit(allocator);
    try source.appendSlice(allocator, codegen.preambleSource());

    var emitted = std.AutoHashMap(u64, void).init(allocator);
    defer emitted.deinit();
    for (component.parts) |part| {
        const entry = try emitted.getOrPut(part.program.header.semantic_hash);
        if (entry.found_existing) continue;
        const kernel = try codegen.generateKernel(allocator, part.program, false);
        defer allocator.free(kernel);
        try source.appendSlice(allocator, kernel);
    }

    var timer = try std.time.Timer.start();
    const library = try runtime.compileEvalLibrary(source.items);
    return .{
        .library = library,
        .source_bytes = source.items.len,
        .compile_ms = @as(f64, @floatFromInt(timer.read())) / std.time.ns_per_ms,
    };
}

const Samples = struct {
    values: [blocks * 2]f64 = @splat(0),
    count: usize = 0,

    fn push(self: *Samples, value: f64) void {
        self.values[self.count] = value;
        self.count += 1;
    }

    fn min(self: Samples) f64 {
        var result = self.values[0];
        for (self.values[0..self.count]) |value| result = @min(result, value);
        return result;
    }

    fn max(self: Samples) f64 {
        var result = self.values[0];
        for (self.values[0..self.count]) |value| result = @max(result, value);
        return result;
    }

    fn mean(self: Samples) f64 {
        var total: f64 = 0;
        for (self.values[0..self.count]) |value| total += value;
        return total / @as(f64, @floatFromInt(self.count));
    }
};

fn snapshot(
    allocator: std.mem.Allocator,
    words: [*]u32,
    layout: ArenaLayout,
) ![]u32 {
    const out = try allocator.alloc(u32, 4 * layout.row_count);
    for (layout.coordinates, 0..) |offset, plane|
        @memcpy(
            out[plane * layout.row_count .. (plane + 1) * layout.row_count],
            words[offset .. offset + layout.row_count],
        );
    return out;
}

fn compareComponent(
    allocator: std.mem.Allocator,
    runtime: *metal.Runtime,
    aot_library: metal.EvalLibrary,
    component: composition.Component,
    role: []const u8,
) !void {
    const eval_log = component.evaluation_log_size;
    const trace_log = component.trace_log_size;
    const row_count: u32 = @as(u32, 1) << @intCast(eval_log);
    const denominator_count: u32 = @as(u32, 1) << @intCast(eval_log - trace_log);

    const per_interaction = try columnCounts(allocator, component);
    defer allocator.free(per_interaction);
    const bases = try allocator.alloc(u32, per_interaction.len);
    defer allocator.free(bases);
    var total_columns: u32 = 0;
    for (per_interaction, bases) |count, *base| {
        base.* = total_columns;
        total_columns += count;
    }
    try std.testing.expect(total_columns > 0);

    var ext_param_count: u32 = 0;
    var coefficient_count: u32 = 0;
    for (component.parts) |part| {
        try std.testing.expectEqual(@as(u32, 0), part.program.header.n_base_params);
        ext_param_count = @max(ext_param_count, part.program.header.n_ext_params);
        coefficient_count = @max(
            coefficient_count,
            part.rc_base + part.program.header.n_constraints,
        );
    }

    var next: u32 = 0;
    const column_base = next;
    next += total_columns * row_count;
    const trace_offsets = next;
    next += total_columns;
    const interaction_offsets = next;
    next += @intCast(bases.len);
    const ext_params = next;
    next += 4 * ext_param_count;
    const random_coeffs = next;
    next += 4 * coefficient_count;
    const denom_inv = next;
    next += denominator_count;
    var coordinates: [4]u32 = undefined;
    for (&coordinates) |*offset| {
        offset.* = next;
        next += row_count;
    }

    var arena = try runtime.allocateResidentBuffer((@as(usize, next) + 1024) * @sizeOf(u32));
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    @memset(words[0..next], 0);

    fill(words[column_base .. column_base + total_columns * row_count], 0x5eed_1234);
    for (0..total_columns) |column|
        words[trace_offsets + column] = column_base + @as(u32, @intCast(column)) * row_count;
    for (bases, 0..) |base, index| words[interaction_offsets + index] = base;
    if (ext_param_count != 0)
        fill(words[ext_params .. ext_params + 4 * ext_param_count], 0xa11ce);
    fill(words[random_coeffs .. random_coeffs + 4 * coefficient_count], 0xb0b);
    fill(words[denom_inv .. denom_inv + denominator_count], 0xc0ffee);

    const layout = ArenaLayout{
        .trace_offsets = trace_offsets,
        .interaction_offsets = interaction_offsets,
        .ext_params = ext_params,
        .random_coeffs = random_coeffs,
        .denom_inv = denom_inv,
        .coordinates = coordinates,
        .row_count = row_count,
        .trace_log = trace_log,
    };

    const jit = try jitLibrary(allocator, runtime, component);
    var jit_library = jit.library;
    defer jit_library.deinit();

    var aot = Arm{ .name = "aot", .library = aot_library, .fresh_plan_per_dispatch = false };
    var jit_arm = Arm{ .name = "jit", .library = jit_library, .fresh_plan_per_dispatch = false };
    var aot_fresh = Arm{
        .name = "aot-fresh-plan",
        .library = aot_library,
        .fresh_plan_per_dispatch = true,
    };

    try preparePlans(allocator, runtime, &aot, component, layout);
    defer releasePlans(allocator, &aot);
    try preparePlans(allocator, runtime, &jit_arm, component, layout);
    defer releasePlans(allocator, &jit_arm);

    // Warmup, one per arm, excluded from the samples — but *reported*, because
    // the first pass over a freshly CPU-filled multi-gigabyte resident buffer is
    // the whole explanation for 3.6's spread and it deserves a number rather
    // than a hypothesis. `gpu_ms` is `GPUEndTime - GPUStartTime`, so whatever
    // the first dispatch pays to make those pages GPU-resident is inside it, and
    // it is paid by whichever arm happens to run first.
    const aot_warmup = try runArm(allocator, runtime, &aot, component, layout, arena);
    const aot_reference = try snapshot(allocator, words, layout);
    defer allocator.free(aot_reference);
    const jit_warmup = try runArm(allocator, runtime, &jit_arm, component, layout, arena);
    const jit_reference = try snapshot(allocator, words, layout);
    defer allocator.free(jit_reference);

    // The two libraries must be the same kernels. Without this the timing
    // comparison is meaningless, and `semanticHash` agreeing is a claim about
    // the *program*, not about the compiled artifact.
    for (aot_reference, jit_reference, 0..) |expected, found, index|
        if (expected != found) {
            std.debug.print(
                "LIBRARY_PARITY_MISMATCH component={s} word={d} aot={d} jit={d}\n",
                .{ component.label, index, expected, found },
            );
            return error.LibraryOutputMismatch;
        };

    var aot_samples = Samples{};
    var jit_samples = Samples{};
    var fresh_samples = Samples{};

    for (0..blocks) |block| {
        // A-B-B-A within each block, so a monotone drift cannot favour an arm.
        const a1 = try runArm(allocator, runtime, &aot, component, layout, arena);
        const b1 = try runArm(allocator, runtime, &jit_arm, component, layout, arena);
        const b2 = try runArm(allocator, runtime, &jit_arm, component, layout, arena);
        const a2 = try runArm(allocator, runtime, &aot, component, layout, arena);
        aot_samples.push(a1);
        aot_samples.push(a2);
        jit_samples.push(b1);
        jit_samples.push(b2);
        std.debug.print(
            "LIBRARY_PARITY_BLOCK role={s} component={s} block={d} " ++
                "aot_1={d:.4} jit_1={d:.4} jit_2={d:.4} aot_2={d:.4}\n",
            .{ role, component.label, block, a1, b1, b2, a2 },
        );
        // Every block re-checks the outputs, so a divergence that only appears
        // after repeated dispatch cannot hide.
        const after = try snapshot(allocator, words, layout);
        defer allocator.free(after);
        try std.testing.expectEqualSlices(u32, aot_reference, after);
    }

    // The third arm: same AOT library, plan created per dispatch. This is the
    // protocol increments 3.5 and 3.6 both used.
    _ = try runArm(allocator, runtime, &aot_fresh, component, layout, arena);
    for (0..blocks) |_| {
        fresh_samples.push(try runArm(allocator, runtime, &aot_fresh, component, layout, arena));
        fresh_samples.push(try runArm(allocator, runtime, &aot_fresh, component, layout, arena));
    }

    std.debug.print(
        "LIBRARY_PARITY role={s} component={s} rows={d} parts={d} columns={d} " ++
            "jit_source_bytes={d} jit_compile_ms={d:.2} " ++
            "aot_warmup={d:.4} jit_warmup={d:.4} warmup_over_steady={d:.4} " ++
            "aot_mean={d:.4} aot_min={d:.4} aot_max={d:.4} " ++
            "jit_mean={d:.4} jit_min={d:.4} jit_max={d:.4} " ++
            "aot_fresh_mean={d:.4} aot_fresh_min={d:.4} aot_fresh_max={d:.4} " ++
            "aot_over_jit={d:.4} fresh_over_reused={d:.4} byte_exact=true\n",
        .{
            role,                                      component.label,
            row_count,                                 component.parts.len,
            total_columns,                             jit.source_bytes,
            jit.compile_ms,                            aot_warmup,
            jit_warmup,                                aot_warmup / aot_samples.mean(),
            aot_samples.mean(),                        aot_samples.min(),
            aot_samples.max(),                         jit_samples.mean(),
            jit_samples.min(),                         jit_samples.max(),
            fresh_samples.mean(),                      fresh_samples.min(),
            fresh_samples.max(),                       aot_samples.mean() / jit_samples.mean(),
            fresh_samples.mean() / aot_samples.mean(),
        },
    );
}

fn eligible(component: composition.Component) bool {
    if (component.parts.len == 0) return false;
    if (component.evaluation_log_size <= component.trace_log_size) return false;
    if (component.evaluation_log_size < 3) return false;
    for (component.parts) |part| {
        if (part.program.header.n_base_params != 0) return false;
        if (part.program.header.domain_log_size != component.trace_log_size) return false;
    }
    return true;
}

// The emitter must keep emitting exactly one accumulator identifier per part
// body. This is the in-tree half of the offline finding recorded in the header:
// the only textual change to the per-part emission since the AOT metallib was
// compiled is `acc` -> `part_acc`, so the artifact is semantically current. A
// future change that alters the emitted *arithmetic* must not be able to pass
// as another rename, and this pins the shape the rename argument depends on.
test "metal: the per-part emission accumulates through exactly one named accumulator" {
    const allocator = std.testing.allocator;

    var bundle = try composition.Bundle.readFile(allocator, bundle_path);
    defer bundle.deinit();

    const part = bundle.components[0].parts[0];
    const kernel = try codegen.generateKernel(allocator, part.program, false);
    defer allocator.free(kernel);

    // One declaration, one seeded zero, and the denominator scaling reads it.
    try std.testing.expectEqual(
        @as(usize, 1),
        std.mem.count(u8, kernel, "Qm31 part_acc = { 0u, 0u, 0u, 0u };"),
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        std.mem.count(u8, kernel, "qm_mul_base(part_acc,"),
    );
    // The pre-rename identifier must not reappear: an emission carrying both
    // would mean two accumulators and the rename argument would not hold.
    try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, kernel, "Qm31 acc ="));
}

test "metal: the AOT metallib and a JIT library of the same source dispatch at the same speed" {
    const allocator = std.testing.allocator;

    var bundle = try composition.Bundle.readFile(allocator, bundle_path);
    defer bundle.deinit();

    const admission = try composition_aot.authenticate(metallib_path, .approved_manifest);
    try std.testing.expect(admission.label != null);

    var runtime = try metal.Runtime.initFull();
    defer runtime.deinit();
    var aot_library = try runtime.loadEvalLibrary(metallib_path);
    defer aot_library.deinit();

    // The four components 3.6's AOT-vs-JIT table reported, so the comparison is
    // against the same shapes that produced the 1.0x-3.05x spread, plus
    // `add_opcode_small` which is the shape the portfolio's composition work
    // actually lives in.
    const labels = [_][]const u8{
        "blake_round_sigma",
        "add_opcode",
        "add_opcode_small",
        "partial_ec_mul_generic",
    };

    for (labels) |label| {
        var found: ?composition.Component = null;
        for (bundle.components) |component| {
            if (!eligible(component)) continue;
            if (!std.mem.eql(u8, component.label, label)) continue;
            found = component;
            break;
        }
        const component = found orelse {
            std.debug.print("LIBRARY_PARITY_SKIP component={s} not_eligible\n", .{label});
            continue;
        };
        try compareComponent(allocator, &runtime, aot_library, component, label);
    }
}
