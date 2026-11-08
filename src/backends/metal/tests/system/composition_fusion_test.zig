//! Increment 3.6: pricing FUSED composition kernels.
//!
//! Increment 3.5 measured the checked-in per-part eval kernels as row-bound per
//! *part* (~5.6 ns x rows, flat in constraint count over 27-448), so a
//! multi-part component pays `rows x parts` and one 2^21-row 41-part component
//! costs 484 ms unfused against a 435.7 ms whole-stage host cost. Device
//! composition is therefore viable only if a component's parts collapse into
//! one (or few) dispatches.
//!
//! The fused emission itself already exists (`eval_codegen.generateFusedKernel`,
//! landed on `main` in `1dc983e3`/`154caf4b`). What did not exist is (a) any
//! byte-exactness evidence for it against the per-part dispatch sequence it
//! replaces, and (b) any price. This file supplies both, and it establishes the
//! part-structure facts the fusion contract rests on.
//!
//! ## The fusion contract, read out of the code
//!
//! `codegen/eval_program.validatePartSequence` admits a group only when every
//! part shares `n_interactions`, `n_base_params`, `n_ext_params` and
//! `domain_log_size` with the first, and when the `rc_base` sequence is exactly
//! contiguous: `part[i+1].rc_base == part[i].rc_base + part[i].n_constraints`.
//! `generateFusedKernel` then emits each part's body inline with a *relative*
//! coefficient offset `part.rc_base - group[0].rc_base`, hoists the single
//! denominator load, seeds one `cumulative` accumulator from the four
//! coordinate words, and stores it once. So the fused kernel is dispatched with
//! `rc_base = group[0].rc_base` and is a drop-in for the group's dispatches.
//!
//! Byte-exactness against the per-part sequence is therefore a claim about the
//! accumulation order, not about the arithmetic: per-part does
//! `coord += qm_mul_base(acc_i, denom)` k times against memory, fused does the
//! same k adds into a register and stores once. M31 addition is associative, so
//! the two must agree bit-for-bit — and this file is where that stops being an
//! argument.

const std = @import("std");
const core = @import("stwo_core");
const metal = @import("stwo_metal_backend").runtime;
const cairo = @import("stwo_cairo_frontend");
const integration = @import("stwo_cairo_metal_integration");

const composition = cairo.witness.composition_bundle;
const eval_program = cairo.witness.eval_program;
const simd_evaluator = cairo.proving.air.simd_evaluator;
const codegen = integration.eval_codegen;
const shared_codegen = cairo.codegen.eval_program;

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

const m31_modulus: u64 = (1 << 31) - 1;

const bundle_path = "vectors/cairo/sn_pie_2_composition.bin";

/// How long one grouping's Metal compile may take before the group-size sweep
/// stops climbing.
const compile_probe_budget_ms: f64 = 20_000;

/// Operations (base + extension instructions + constraint roots) a fused group
/// may reach before the sweep declines to compile it.
///
/// This exists because the fusion ceiling is not a device resource limit, it is
/// the Metal front end's appetite for one enormous straight-line function, and
/// a single compile cannot be preempted once started. An unbounded probe held
/// `MTLCompilerService` at 100% of a core for over seven minutes on a
/// five-part, ~10,000-operation group without completing. So the sweep declines
/// above the codegen's own sanctioned ceiling and reports the curve below it,
/// rather than making a test hostage to the compiler.
const fusion_probe_operation_ceiling: usize = codegen.max_fused_instruction_cap;

/// The components that dominate the *live* workloads' composition work, by
/// `rows x parts` computed from each workload's own proof claim against this
/// bundle's part counts: `add_opcode_small` carries 53.7% of arithmetic-2m and
/// 40.6% of memory-7m, `range_check_20` and `assert_eq_opcode` are the largest
/// single-part shapes. The increment 3.5 selection covered the SN2 bundle's
/// structural extremes, which turn out to be EC components that appear in
/// neither of the two workloads whose host stage the projection is measured
/// against — so the cost model needs these shapes measured directly.
const live_dominant_labels = [_][]const u8{
    "add_opcode_small",
    "range_check_20",
    "assert_eq_opcode",
};

// ---------------------------------------------------------------------------
// Part structure
// ---------------------------------------------------------------------------

// Why do components have parts at all, and can the parts of one component be
// fused? Both are properties of the serialized bundle, not of the codegen, so
// they have to be observed rather than assumed. This census prints the
// distribution and asserts the two facts every later test depends on: the whole
// bundle is fusable in principle (every component's part sequence passes
// `validatePartSequence`), and the shipping default fusion cap of 512 operations
// fuses nothing anywhere in the bundle, because it bounds a *group's* sum and
// the smallest adjacent pair already exceeds it.
test "metal: composition parts are uniformly sized and fusable in principle" {
    const allocator = std.testing.allocator;

    var bundle = try composition.Bundle.readFile(allocator, bundle_path);
    defer bundle.deinit();

    var total_parts: usize = 0;
    var multipart_components: usize = 0;
    var global_min_ops: usize = std.math.maxInt(usize);
    var global_max_ops: usize = 0;
    var global_ops: usize = 0;
    var fusable_components: usize = 0;
    var default_cap_dispatches: usize = 0;
    var smallest_pair_ops: usize = std.math.maxInt(usize);

    for (bundle.components) |component| {
        const parts = try allocator.alloc(shared_codegen.FusedPart, component.parts.len);
        defer allocator.free(parts);
        for (component.parts, parts) |part, *fused|
            fused.* = .{ .program = part.program, .rc_base = part.rc_base };

        var min_ops: usize = std.math.maxInt(usize);
        var max_ops: usize = 0;
        var ops: usize = 0;
        var constraints: u64 = 0;
        var previous_ops: ?usize = null;
        for (parts) |part| {
            const count = shared_codegen.fusionOperationCount(part.program);
            min_ops = @min(min_ops, count);
            max_ops = @max(max_ops, count);
            ops += count;
            constraints += part.program.header.n_constraints;
            if (previous_ops) |previous|
                smallest_pair_ops = @min(smallest_pair_ops, previous + count);
            previous_ops = count;
        }
        global_min_ops = @min(global_min_ops, min_ops);
        global_max_ops = @max(global_max_ops, max_ops);
        global_ops += ops;
        total_parts += parts.len;
        if (parts.len > 1) multipart_components += 1;

        // The fusion precondition for the *whole* component in one group.
        const fusable = if (shared_codegen.validatePartSequence(parts)) |_| true else |_| false;
        if (fusable) fusable_components += 1;

        // What the shipping default cap actually achieves on this component.
        var start: usize = 0;
        while (start < parts.len) {
            start = try codegen.fusionGroupEnd(
                parts,
                start,
                codegen.default_fused_instruction_cap,
            );
            default_cap_dispatches += 1;
        }

        std.debug.print(
            "FUSION_CENSUS component={s} eval_log={d} trace_log={d} parts={d} " ++
                "constraints={d} ops={d} ops_per_part_min={d} ops_per_part_max={d} " ++
                "whole_component_fusable={}\n",
            .{
                component.label,
                component.evaluation_log_size,
                component.trace_log_size,
                component.parts.len,
                constraints,
                ops,
                min_ops,
                max_ops,
                fusable,
            },
        );
    }

    std.debug.print(
        "FUSION_CENSUS_SUMMARY components={d} multipart={d} parts={d} ops={d} " ++
            "ops_per_part_min={d} ops_per_part_max={d} smallest_adjacent_pair_ops={d} " ++
            "fusable_components={d} default_cap={d} default_cap_dispatches={d} " ++
            "hard_cap={d}\n",
        .{
            bundle.components.len,
            multipart_components,
            total_parts,
            global_ops,
            global_min_ops,
            global_max_ops,
            smallest_pair_ops,
            fusable_components,
            codegen.default_fused_instruction_cap,
            default_cap_dispatches,
            codegen.max_fused_instruction_cap,
        },
    );

    // Every component of the authenticated bundle is fusable end to end: the
    // part boundaries carry no state the fused emission cannot reproduce.
    try std.testing.expectEqual(bundle.components.len, fusable_components);

    // The shipping default cap fuses *nothing* anywhere in this bundle. Not
    // because parts are large — the smallest is 28 operations — but because the
    // cap applies to a group's sum and the smallest adjacent pair in the bundle
    // already exceeds 512. So the fused emission that has been in the tree since
    // `1dc983e3` is unreachable at its own default, which is why
    // `metal-eval-source --fusion-cap 512` reports `dispatches=279->279`.
    try std.testing.expect(smallest_pair_ops > codegen.default_fused_instruction_cap);
    try std.testing.expectEqual(total_parts, default_cap_dispatches);
}

// ---------------------------------------------------------------------------
// Byte-exactness and pricing
// ---------------------------------------------------------------------------

/// Deterministic, canonical-range filler. Identical to the increment 3.5 smoke's
/// filler, on purpose: the two tests build the same arena from the same seeds, so
/// `fused == per-part` here composes with `per-part == host` there.
fn fill(words: []u32, seed: u64) void {
    var state = seed | 1;
    for (words) |*word| {
        state = state *% 6364136223846793005 +% 1442695040888963407;
        word.* = @intCast((state >> 33) % (m31_modulus - 1) + 1);
    }
}

const HostReader = struct {
    words: []const M31,
    offsets: []const u32,
    bases: []const u32,
    column_words: u32,
    shift_amt: std.math.Log2Int(usize),

    fn resolve(
        context: *const anyopaque,
        interaction: u8,
        column: u32,
    ) anyerror!simd_evaluator.ResolvedColumn {
        const self: *const HostReader = @ptrCast(@alignCast(context));
        if (interaction >= self.bases.len) return error.InvalidCompositionPart;
        const global = self.bases[interaction] + column;
        if (global >= self.offsets.len) return error.InvalidCompositionPart;
        const start = self.offsets[global];
        return .{
            .values = self.words[start .. start + self.column_words],
            .shift_amt = self.shift_amt,
        };
    }
};

const HostSink = struct {
    values: []QM31,

    pub fn accumulate(self: HostSink, row: usize, value: QM31) void {
        self.values[row] = self.values[row].add(value);
    }
};

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

/// The arena offsets one component's grouping sweep dispatches against. Same
/// shape as the increment 3.5 smoke's layout, so the two are comparable.
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

const Measurement = struct {
    group_size: usize,
    dispatches: usize,
    fused_kernels: usize,
    max_group_parts: usize,
    max_group_ops: usize,
    max_group_source_bytes: usize,
    compile_ms: f64,
    gpu_ms: f64,
};

/// Emits every kernel one grouping needs into a single source, compiles it once,
/// and dispatches the grouping. `group_size` 1 is the per-part baseline the
/// authenticated metallib implements today.
fn measureGrouping(
    allocator: std.mem.Allocator,
    runtime: *metal.Runtime,
    component: composition.Component,
    parts: []const shared_codegen.FusedPart,
    group_size: usize,
    layout: ArenaLayout,
    arena: metal.ResidentBuffer,
) !Measurement {
    var source = std.ArrayList(u8).empty;
    defer source.deinit(allocator);
    try source.appendSlice(allocator, codegen.preambleSource());

    var emitted_parts = std.AutoHashMap(u64, void).init(allocator);
    defer emitted_parts.deinit();
    var emitted_groups = std.AutoHashMap(u64, void).init(allocator);
    defer emitted_groups.deinit();

    var result = Measurement{
        .group_size = group_size,
        .dispatches = 0,
        .fused_kernels = 0,
        .max_group_parts = 0,
        .max_group_ops = 0,
        .max_group_source_bytes = 0,
        .compile_ms = 0,
        .gpu_ms = 0,
    };

    var start: usize = 0;
    while (start < parts.len) : (start += group_size) {
        const end = @min(start + group_size, parts.len);
        const group = parts[start..end];
        result.dispatches += 1;
        result.max_group_parts = @max(result.max_group_parts, group.len);
        var ops: usize = 0;
        for (group) |part| ops += shared_codegen.fusionOperationCount(part.program);
        result.max_group_ops = @max(result.max_group_ops, ops);
        if (group.len == 1) {
            const hash = group[0].program.header.semantic_hash;
            const entry = try emitted_parts.getOrPut(hash);
            if (!entry.found_existing) {
                const kernel = try codegen.generateKernel(allocator, group[0].program, false);
                defer allocator.free(kernel);
                result.max_group_source_bytes = @max(result.max_group_source_bytes, kernel.len);
                try source.appendSlice(allocator, kernel);
            }
        } else {
            const kernel = try codegen.generateFusedKernelUncapped(allocator, group, false);
            defer allocator.free(kernel);
            result.max_group_source_bytes = @max(result.max_group_source_bytes, kernel.len);
            const name = try codegen.fusedKernelNameUncapped(allocator, group);
            defer allocator.free(name);
            const entry = try emitted_groups.getOrPut(std.hash.Wyhash.hash(0, name));
            if (!entry.found_existing) {
                result.fused_kernels += 1;
                try source.appendSlice(allocator, kernel);
            }
        }
    }

    var timer = try std.time.Timer.start();
    var library = try runtime.compileEvalLibrary(source.items);
    defer library.deinit();
    result.compile_ms = @as(f64, @floatFromInt(timer.read())) / std.time.ns_per_ms;

    // Zero the candidate coordinate planes: every kernel accumulates.
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    for (layout.coordinates) |offset|
        @memset(words[offset .. offset + layout.row_count], 0);

    start = 0;
    while (start < parts.len) : (start += group_size) {
        const end = @min(start + group_size, parts.len);
        const group = parts[start..end];
        const name = if (group.len == 1)
            try codegen.kernelName(allocator, group[0].program.header.semantic_hash)
        else
            try codegen.fusedKernelNameUncapped(allocator, group);
        defer allocator.free(name);
        var plan = try runtime.prepareEvalFromLibrary(library, name, .{
            .trace_offsets = layout.trace_offsets,
            .interaction_offsets = layout.interaction_offsets,
            .base_params = 0,
            .ext_params = layout.ext_params,
            .random_coeffs = layout.random_coeffs,
            .denom_inv = layout.denom_inv,
            .coordinates = layout.coordinates,
            .row_count = layout.row_count,
            .trace_log_size = layout.trace_log,
            // Every part of a component shares one domain log size (asserted by
            // `validatePartSequence`), so the fused kernel needs no per-part
            // value here.
            .domain_log_size = group[0].program.header.domain_log_size,
            // The fused emission rebases every part's coefficient index onto the
            // group's first `rc_base`.
            .rc_base = group[0].rc_base,
        });
        defer plan.deinit();
        result.gpu_ms += try runtime.evalPrepared(arena, plan);
    }
    _ = component;
    return result;
}

/// Prices one component across a sweep of group sizes and requires every
/// grouping to be bit-identical to the per-part baseline.
fn priceComponent(
    allocator: std.mem.Allocator,
    runtime: *metal.Runtime,
    component: composition.Component,
    role: []const u8,
    host_check: bool,
) !void {
    const eval_log = component.evaluation_log_size;
    const trace_log = component.trace_log_size;
    const row_count: u32 = @as(u32, 1) << @intCast(eval_log);
    const denominator_count: u32 = @as(u32, 1) << @intCast(eval_log - trace_log);

    const parts = try allocator.alloc(shared_codegen.FusedPart, component.parts.len);
    defer allocator.free(parts);
    for (component.parts, parts) |part, *fused|
        fused.* = .{ .program = part.program, .rc_base = part.rc_base };

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
    var constraints: u64 = 0;
    for (parts) |part| {
        try std.testing.expectEqual(@as(u32, 0), part.program.header.n_base_params);
        ext_param_count = @max(ext_param_count, part.program.header.n_ext_params);
        coefficient_count = @max(
            coefficient_count,
            part.rc_base + part.program.header.n_constraints,
        );
        constraints += part.program.header.n_constraints;
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

    const baseline = try allocator.alloc(u32, 4 * row_count);
    defer allocator.free(baseline);

    var baseline_gpu_ms: f64 = 0;
    var largest_fused_parts: usize = 0;
    // Group sizes ascend by doubling, clamped to the part count, and the sweep
    // stops as soon as one grouping's Metal compile exceeds the probe budget.
    // That stopping rule is the max-k measurement: the ceiling on fusion is not
    // a documented resource limit, it is however long `MTLCompilerService` is
    // willing to spend on one enormous function, so the honest way to report it
    // is the curve up to where it became untestable.
    var requested: usize = 1;
    while (true) {
        const group_size = @min(requested, parts.len);

        // Decline before compiling, not after: one oversized Metal compile
        // cannot be interrupted.
        var widest_group_ops: usize = 0;
        var scan: usize = 0;
        while (scan < parts.len) : (scan += group_size) {
            var ops: usize = 0;
            for (parts[scan..@min(scan + group_size, parts.len)]) |part|
                ops += shared_codegen.fusionOperationCount(part.program);
            widest_group_ops = @max(widest_group_ops, ops);
        }
        if (group_size > 1 and widest_group_ops > fusion_probe_operation_ceiling) {
            std.debug.print(
                "FUSION_PRICE role={s} component={s} group_size={d} " ++
                    "max_group_ops={d} DECLINED_ABOVE_CEILING ceiling={d}\n",
                .{ role, component.label, group_size, widest_group_ops, fusion_probe_operation_ceiling },
            );
            break;
        }
        std.debug.print(
            "FUSION_ATTEMPT role={s} component={s} group_size={d} max_group_ops={d}\n",
            .{ role, component.label, group_size, widest_group_ops },
        );

        const measured = measureGrouping(
            allocator,
            runtime,
            component,
            parts,
            group_size,
            layout,
            arena,
        ) catch |err| {
            // A refusal is data, not a failure: the point of the sweep is to
            // find where fusion stops being possible. A wrong *answer* still
            // fails below.
            std.debug.print(
                "FUSION_PRICE role={s} component={s} group_size={d} REFUSED err={s}\n",
                .{ role, component.label, group_size, @errorName(err) },
            );
            if (group_size >= parts.len) break;
            requested *= 2;
            continue;
        };

        if (group_size == 1) {
            baseline_gpu_ms = measured.gpu_ms;
            for (coordinates, 0..) |offset, plane|
                @memcpy(
                    baseline[plane * row_count .. (plane + 1) * row_count],
                    words[offset .. offset + row_count],
                );
        } else {
            // Byte-exact against the per-part dispatch sequence: every row,
            // every coordinate.
            for (coordinates, 0..) |offset, plane|
                for (0..row_count) |row|
                    try std.testing.expectEqual(
                        baseline[plane * row_count + row],
                        words[offset + row],
                    );
            largest_fused_parts = @max(largest_fused_parts, measured.max_group_parts);
        }

        std.debug.print(
            "FUSION_PRICE role={s} component={s} rows={d} parts={d} constraints={d} " ++
                "group_size={d} dispatches={d} fused_kernels={d} max_group_parts={d} " ++
                "max_group_ops={d} max_group_source_bytes={d} compile_ms={d:.2} " ++
                "gpu_ms={d:.4} ns_per_row={d:.3} speedup_vs_per_part={d:.4}\n",
            .{
                role,                                                              component.label,
                row_count,                                                         parts.len,
                constraints,                                                       group_size,
                measured.dispatches,                                               measured.fused_kernels,
                measured.max_group_parts,                                          measured.max_group_ops,
                measured.max_group_source_bytes,                                   measured.compile_ms,
                measured.gpu_ms,                                                   measured.gpu_ms * std.time.ns_per_ms / @as(f64, @floatFromInt(row_count)),
                if (measured.gpu_ms > 0) baseline_gpu_ms / measured.gpu_ms else 0,
            },
        );

        if (group_size >= parts.len) break;
        if (measured.compile_ms > compile_probe_budget_ms) {
            std.debug.print(
                "FUSION_PRICE role={s} component={s} STOPPED_AT group_size={d} " ++
                    "compile_ms={d:.2} budget_ms={d:.0} untested_group_sizes_above=true\n",
                .{ role, component.label, group_size, measured.compile_ms, compile_probe_budget_ms },
            );
            break;
        }
        requested *= 2;
    }

    // The sweep must have actually exercised fusion wherever fusion applies.
    if (parts.len > 1) try std.testing.expect(largest_fused_parts >= 2);

    if (!host_check) return;

    // Anchor the fused result to the host evaluator directly, not only to the
    // per-part device baseline. Run on the whole-component grouping, which is
    // the one the pricing recommendation rests on.
    const ext_values = try allocator.alloc(QM31, ext_param_count);
    defer allocator.free(ext_values);
    for (ext_values, 0..) |*value, index| value.* = QM31.fromU32Unchecked(
        words[ext_params + 4 * index],
        words[ext_params + 4 * index + 1],
        words[ext_params + 4 * index + 2],
        words[ext_params + 4 * index + 3],
    );
    const coefficients = try allocator.alloc(QM31, coefficient_count);
    defer allocator.free(coefficients);
    for (coefficients, 0..) |*value, index| value.* = QM31.fromU32Unchecked(
        words[random_coeffs + 4 * index],
        words[random_coeffs + 4 * index + 1],
        words[random_coeffs + 4 * index + 2],
        words[random_coeffs + 4 * index + 3],
    );
    const host_words: []const M31 = @as([*]const M31, @ptrCast(words))[0..next];
    var reader = HostReader{
        .words = host_words,
        .offsets = words[trace_offsets .. trace_offsets + total_columns],
        .bases = words[interaction_offsets .. interaction_offsets + bases.len],
        .column_words = row_count,
        .shift_amt = 1,
    };
    const expected = try allocator.alloc(QM31, row_count);
    defer allocator.free(expected);
    @memset(expected, QM31.zero());
    var host_timer = try std.time.Timer.start();
    for (parts) |part| {
        try simd_evaluator.evaluatePart(allocator, part.program, .{
            .evaluation_log_size = eval_log,
            .trace_log_size = trace_log,
            .trace = .{ .context = @ptrCast(&reader), .resolve = HostReader.resolve },
            .extension_parameters = ext_values[0..part.program.header.n_ext_params],
            .random_coefficients = coefficients,
            .constraint_base = part.rc_base,
            .denominator_inverses = words[denom_inv .. denom_inv + denominator_count],
        }, HostSink{ .values = expected });
    }
    const host_ms = @as(f64, @floatFromInt(host_timer.read())) / std.time.ns_per_ms;

    // `words` still holds the last grouping in the sweep — the whole component
    // in one dispatch.
    for (0..row_count) |row| {
        const reference = expected[row].toM31Array();
        for (reference, coordinates) |coordinate, offset|
            try std.testing.expectEqual(coordinate.v, words[offset + row]);
    }
    std.debug.print(
        "FUSION_HOST_ANCHOR role={s} component={s} rows={d} parts={d} " ++
            "host_ms_debug={d:.2} byte_exact=true\n",
        .{ role, component.label, row_count, parts.len, host_ms },
    );
}

// The four components increment 3.5 covered, plus the smallest multi-part
// component in the bundle — which is the one where a fused kernel can be
// anchored against the host evaluator directly inside a sane test budget.
test "metal: fused composition kernels are byte-exact and priced against per-part dispatch" {
    const allocator = std.testing.allocator;

    var bundle = try composition.Bundle.readFile(allocator, bundle_path);
    defer bundle.deinit();

    var smallest: ?composition.Component = null;
    var dominant: ?composition.Component = null;
    var widest: ?composition.Component = null;
    var arithmetic: ?composition.Component = null;
    var smallest_multipart: ?composition.Component = null;
    var dominant_work: u64 = 0;
    var arithmetic_work: u64 = 0;
    for (bundle.components) |component| {
        if (!eligible(component)) continue;
        if (smallest == null or
            component.evaluation_log_size < smallest.?.evaluation_log_size)
            smallest = component;
        var constraints: u64 = 0;
        for (component.parts) |part| constraints += part.program.header.n_constraints;
        const work = (@as(u64, 1) << @intCast(component.evaluation_log_size)) * constraints;
        if (dominant == null or work > dominant_work) {
            dominant = component;
            dominant_work = work;
        }
        if (widest == null or component.parts.len > widest.?.parts.len)
            widest = component;
        if (isArithmeticComponent(component.label) and
            (arithmetic == null or work > arithmetic_work))
        {
            arithmetic = component;
            arithmetic_work = work;
        }
        if (component.parts.len > 1) {
            const better = smallest_multipart == null or
                component.evaluation_log_size < smallest_multipart.?.evaluation_log_size;
            if (better) smallest_multipart = component;
        }
    }

    var runtime = try metal.Runtime.initFull();
    defer runtime.deinit();

    // Ordered by decision relevance, cheapest first: the control, the shapes
    // that carry the live workloads, then increment 3.5's structural extremes.
    const cases = [_]struct {
        role: []const u8,
        component: ?composition.Component,
        host_check: bool,
    }{
        .{ .role = "small-control", .component = smallest, .host_check = true },
        .{
            .role = "host-anchored-multipart",
            .component = smallest_multipart,
            .host_check = true,
        },
        .{ .role = "arithmetic-dominant", .component = arithmetic, .host_check = false },
        .{ .role = "multipart", .component = widest, .host_check = false },
        .{ .role = "dominant", .component = dominant, .host_check = false },
    };

    // The shapes that actually carry the live workloads' composition work, first
    // because the projection rests on them.
    for (live_dominant_labels) |label| {
        var found: ?composition.Component = null;
        for (bundle.components) |component| {
            if (!eligible(component)) continue;
            if (!std.mem.eql(u8, component.label, label)) continue;
            found = component;
            break;
        }
        const component = found orelse return error.NoEligibleComponent;
        try priceComponent(allocator, &runtime, component, "live-dominant", false);
    }

    for (cases) |case| {
        const component = case.component orelse return error.NoEligibleComponent;
        try priceComponent(allocator, &runtime, component, case.role, case.host_check);
    }
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

fn isArithmeticComponent(label: []const u8) bool {
    const names = [_][]const u8{
        "memory_address_to_id",
        "memory_id_to_big",
        "memory_id_to_small",
        "add_opcode",
        "add_ap_opcode",
        "mul_opcode",
        "verify_instruction",
    };
    for (names) |name| if (std.mem.eql(u8, label, name)) return true;
    return false;
}
