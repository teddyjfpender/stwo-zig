//! Increment 3.10 part A: the Option-B (`stored_domain`) trace ABI, verified
//! byte-exact and priced.
//!
//! ## What Option B is and why it is worth a variant
//!
//! The compiled kernels of every library in the tree index a trace column
//! directly at evaluation-domain length (`arena[column_offset + row]`, increment
//! 3.7 §3). The product publishes columns at *trace*-domain length, so increment
//! 3.8's hook has to materialise a lifted `2^eval_log`-word copy of every column
//! before it can dispatch: 8.4 / 18.8 / 53.4 ms and 0.76 / 1.69 / 4.80 GB of
//! staging per proof on all-opcodes / arithmetic-2m / memory-7m (3.7 §4).
//!
//! Option B (3.7 §5) deletes that pass by giving the kernel the shift:
//!
//! ```
//! uint index = ((target >> arena[shift_base + global]) << 1) + (target & 1u);
//! return arena[arena[args.trace_offsets + global] + index];
//! ```
//!
//! where `shift_base + global` holds `simd_evaluator.ResolvedColumn.shift_amt`
//! for that global column — the *same* number `proving/air/component.zig:355`
//! hands the host evaluator. So host and device share one convention rather than
//! two related ones, which is the property this file checks.
//!
//! ## The layout choice, and why it needs no ABI change
//!
//! `shift_base` is `args.base_params + n_base_params`: the runtime
//! base-parameter block carries the program's own parameters first and one
//! `shift_amt` word per global column immediately after. `n_base_params` is a
//! compile-time constant of the program, so the table is addressable without a
//! twelfth `EvalLayout` offset, without a fifteenth kernel argument, and without
//! touching `resource_plans.evalArguments`, `bindings.zig` or
//! `dynamic_evaluation.m`. Every component in the tree currently has
//! `n_base_params == 0` (asserted below), so today the table simply starts at
//! `args.base_params`; putting the parameters *first* is what lets increment
//! 3.10 part B's parameterized programs use this ABI with no further change.
//!
//! ## Verification, and the geometry it runs at
//!
//! This is a **JIT** file: no offline Metal compiler exists on this host (3.7
//! §1), so every Option-B kernel here is compiled from the codegen's own source
//! at test time and dispatched against a JIT library. That is the same emitter
//! CI would compile, which is what makes the check meaningful.
//!
//! The five host-anchored roles are run at a **rescaled** geometry
//! (`trace_log = 6`, `eval_log = 7`, so `shift_amt = 2` — the product's own
//! shift). `semanticHash` does not hash `domain_log_size` (`witness/eval_program`
//! §284) and `setDomainLogSize` does not perturb it, so a rescaled part is the
//! *same kernel* by name and by emitted source; only the runtime arguments
//! differ. Rescaling is what makes a 90-part, 448-constraint component
//! host-anchorable at all: the host reference is a scalar-lane interpreter and
//! the 3.5 smoke's natural-geometry equivalents cost ~15 minutes. Rescaling
//! cannot hide an index-map error, because the index map is exactly what small
//! geometry exercises. The two components small enough to run at their natural
//! bundle geometry are additionally run there, unrescaled.
//!
//! Pricing (§3 of the increment) is separate and runs at natural geometry with
//! no host reference: Option-B kernels reading stored columns in place against
//! eval-domain kernels reading the lifted copy, both JIT, both in this process,
//! warmed before timing (3.7 §2's lesson: 3.6's "AOT-vs-JIT gap" was
//! first-dispatch cost on both sides).

const std = @import("std");
const core = @import("stwo_core");
const metal = @import("stwo_metal_backend").runtime;
const cairo = @import("stwo_cairo_frontend");
const integration = @import("stwo_cairo_metal_integration");

const composition = cairo.witness.composition_bundle;
const simd_evaluator = cairo.proving.air.simd_evaluator;
const codegen = integration.eval_codegen;

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

const m31_modulus: u64 = (1 << 31) - 1;
const bundle_path = "vectors/cairo/sn_pie_2_composition.bin";

/// Small enough that a scalar-lane host reference over 90 parts is seconds, and
/// large enough to be a multiple of `simd_evaluator.lane_count` with a nontrivial
/// shift and a two-entry denominator table.
const rescaled_trace_log: u32 = 6;
const rescaled_eval_log: u32 = 7;

fn fill(words: []u32, seed: u64) void {
    var state = seed | 1;
    for (words) |*word| {
        state = state *% 6364136223846793005 +% 1442695040888963407;
        word.* = @intCast((state >> 33) % (m31_modulus - 1) + 1);
    }
}

fn liftedIndex(position: usize, shift_amt: std.math.Log2Int(usize)) usize {
    return ((position >> shift_amt) << 1) + (position & 1);
}

fn liftColumn(
    destination: []u32,
    source: []const u32,
    shift_amt: std.math.Log2Int(usize),
) void {
    const stride: usize = @as(usize, 1) << shift_amt;
    std.debug.assert(destination.len == source.len * (stride / 2));
    var position: usize = 0;
    while (position < destination.len) : (position += stride) {
        const pair = liftedIndex(position, shift_amt);
        const low = source[pair];
        const high = source[pair + 1];
        var replica: usize = 0;
        while (replica < stride) : (replica += 2) {
            destination[position + replica] = low;
            destination[position + replica + 1] = high;
        }
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

/// Reads *trace-domain* columns at the product's own shift. Under Option B the
/// device reads the very same words at the very same shift, so this reference and
/// the device agree or the ABI is wrong.
const ProductReader = struct {
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
        const self: *const ProductReader = @ptrCast(@alignCast(context));
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

fn find(bundle: composition.Bundle, label: []const u8) ?composition.Component {
    for (bundle.components) |component| {
        if (!eligible(component)) continue;
        if (std.mem.eql(u8, component.label, label)) return component;
    }
    return null;
}

const Geometry = struct { trace_log: u32, eval_log: u32 };

fn naturalGeometry(component: composition.Component) Geometry {
    return .{
        .trace_log = component.trace_log_size,
        .eval_log = component.evaluation_log_size,
    };
}

const Placement = struct {
    trace_offsets: u32,
    interaction_offsets: u32,
    base_params: u32,
    ext_params: u32,
    random_coeffs: u32,
    denom_inv: u32,
    coordinates: [4]u32,
    total_columns: u32,
    interactions: u32,
    ext_param_count: u32,
    coefficient_count: u32,
    denominator_count: u32,
    eval_rows: u32,
    trace_rows: u32,
    shift_amt: std.math.Log2Int(usize),
    words: u32,
};

/// One contiguous arena plan. `stored` selects Option B's shape: columns at their
/// stored `2^trace_log` length plus a per-global-column `shift_amt` table in the
/// base-parameter block. `!stored` is the eval-domain shape: lifted
/// `2^eval_log`-word columns and no table.
fn plan(
    component: composition.Component,
    geometry: Geometry,
    bases: []const u32,
    total_columns: u32,
    stored: bool,
) Placement {
    const eval_rows: u32 = @as(u32, 1) << @intCast(geometry.eval_log);
    const trace_rows: u32 = @as(u32, 1) << @intCast(geometry.trace_log);
    var ext_param_count: u32 = 0;
    var coefficient_count: u32 = 0;
    for (component.parts) |part| {
        ext_param_count = @max(ext_param_count, part.program.header.n_ext_params);
        coefficient_count = @max(
            coefficient_count,
            part.rc_base + part.program.header.n_constraints,
        );
    }
    const column_words = if (stored) trace_rows else eval_rows;
    var next: u32 = 0;
    // Columns live at offset 0 in both shapes; only their length differs.
    next += total_columns * column_words;
    const trace_offsets = next;
    next += total_columns;
    const interaction_offsets = next;
    next += @intCast(bases.len);
    const base_params = next;
    if (stored) next += total_columns;
    const ext_params = next;
    next += 4 * ext_param_count;
    const random_coeffs = next;
    next += 4 * coefficient_count;
    const denom_inv = next;
    const denominator_count: u32 = @as(u32, 1) << @intCast(geometry.eval_log - geometry.trace_log);
    next += denominator_count;
    var coordinates: [4]u32 = undefined;
    for (&coordinates) |*offset| {
        offset.* = next;
        next += eval_rows;
    }
    return .{
        .trace_offsets = trace_offsets,
        .interaction_offsets = interaction_offsets,
        .base_params = base_params,
        .ext_params = ext_params,
        .random_coeffs = random_coeffs,
        .denom_inv = denom_inv,
        .coordinates = coordinates,
        .total_columns = total_columns,
        .interactions = @intCast(bases.len),
        .ext_param_count = ext_param_count,
        .coefficient_count = coefficient_count,
        .denominator_count = denominator_count,
        .eval_rows = eval_rows,
        .trace_rows = trace_rows,
        .shift_amt = @intCast(geometry.eval_log - geometry.trace_log + 1),
        .words = next,
    };
}

fn layoutFor(
    placement: Placement,
    part: composition.Part,
    geometry: Geometry,
) metal.EvalLayout {
    return .{
        .trace_offsets = placement.trace_offsets,
        .interaction_offsets = placement.interaction_offsets,
        .base_params = placement.base_params,
        .ext_params = placement.ext_params,
        .random_coeffs = placement.random_coeffs,
        .denom_inv = placement.denom_inv,
        .coordinates = placement.coordinates,
        .row_count = placement.eval_rows,
        .trace_log_size = geometry.trace_log,
        .domain_log_size = geometry.trace_log,
        .rc_base = part.rc_base,
    };
}

/// Dispatches one component under one ABI and returns the summed `gpu_ms`.
///
/// `trace_words` is the product's own trace-domain column store. Under
/// `.stored_domain` it is copied into the arena verbatim; under `.eval_domain` it
/// is lifted, and the lift is timed because it is the pass Option B deletes.
fn dispatch(
    allocator: std.mem.Allocator,
    runtime: *metal.Runtime,
    component: composition.Component,
    geometry: Geometry,
    abi: codegen.TraceAbi,
    bases: []const u32,
    trace_words: []const u32,
    placement: Placement,
    arena: metal.ResidentBuffer,
    lift_ms: *f64,
) !f64 {
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    @memset(words[0..placement.words], 0);
    const stored = abi == .stored_domain;
    const column_words = if (stored) placement.trace_rows else placement.eval_rows;

    var lift_timer = try std.time.Timer.start();
    for (0..placement.total_columns) |column| {
        const destination = words[column * column_words ..][0..column_words];
        const source = trace_words[column * placement.trace_rows ..][0..placement.trace_rows];
        if (stored)
            @memcpy(destination, source)
        else
            liftColumn(destination, source, placement.shift_amt);
    }
    lift_ms.* = @as(f64, @floatFromInt(lift_timer.read())) / std.time.ns_per_ms;

    for (0..placement.total_columns) |column|
        words[placement.trace_offsets + column] =
            @as(u32, @intCast(column)) * column_words;
    for (bases, 0..) |base, index| words[placement.interaction_offsets + index] = base;
    if (stored) {
        // The whole of Option B: one `shift_amt` per global column, the same
        // number the host evaluator is handed.
        for (0..placement.total_columns) |column|
            words[placement.base_params + column] = @intCast(placement.shift_amt);
    }
    if (placement.ext_param_count != 0)
        fill(words[placement.ext_params..][0 .. 4 * placement.ext_param_count], 0xa11ce);
    fill(words[placement.random_coeffs..][0 .. 4 * placement.coefficient_count], 0xb0b);
    fill(words[placement.denom_inv..][0..placement.denominator_count], 0xc0ffee);

    var gpu_ms: f64 = 0;
    for (component.parts) |part| {
        var program = part.program;
        program.header.domain_log_size = geometry.trace_log;
        const name = try codegen.kernelNameFor(
            allocator,
            program.header.semantic_hash,
            abi,
        );
        defer allocator.free(name);
        const source = try codegen.generateKernelFor(allocator, program, true, abi);
        defer allocator.free(source);
        var eval_plan = try runtime.prepareEval(
            source,
            name,
            layoutFor(placement, part, geometry),
        );
        defer eval_plan.deinit();
        gpu_ms += try runtime.evalPrepared(arena, eval_plan);
    }
    return gpu_ms;
}

/// Compares an Option-B dispatch against `simd_evaluator` reading the *same*
/// trace-domain columns at the *same* shift, with no lifted copy anywhere.
fn anchorOptionB(
    allocator: std.mem.Allocator,
    runtime: *metal.Runtime,
    component: composition.Component,
    geometry: Geometry,
    role: []const u8,
) !void {
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

    const placement = plan(component, geometry, bases, total_columns, true);
    const trace_words = try allocator.alloc(
        u32,
        @as(usize, total_columns) * placement.trace_rows,
    );
    defer allocator.free(trace_words);
    fill(trace_words, 0x5eed_1234);

    var arena = try runtime.allocateResidentBuffer(
        (@as(usize, placement.words) + 1024) * @sizeOf(u32),
    );
    defer arena.deinit();
    var lift_ms: f64 = 0;
    const gpu_ms = try dispatch(
        allocator,
        runtime,
        component,
        geometry,
        .stored_domain,
        bases,
        trace_words,
        placement,
        arena,
        &lift_ms,
    );
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));

    const ext_values = try allocator.alloc(QM31, placement.ext_param_count);
    defer allocator.free(ext_values);
    for (ext_values, 0..) |*value, index| value.* = QM31.fromU32Unchecked(
        words[placement.ext_params + 4 * index],
        words[placement.ext_params + 4 * index + 1],
        words[placement.ext_params + 4 * index + 2],
        words[placement.ext_params + 4 * index + 3],
    );
    const coefficients = try allocator.alloc(QM31, placement.coefficient_count);
    defer allocator.free(coefficients);
    for (coefficients, 0..) |*value, index| value.* = QM31.fromU32Unchecked(
        words[placement.random_coeffs + 4 * index],
        words[placement.random_coeffs + 4 * index + 1],
        words[placement.random_coeffs + 4 * index + 2],
        words[placement.random_coeffs + 4 * index + 3],
    );

    const column_offsets = try allocator.alloc(u32, total_columns);
    defer allocator.free(column_offsets);
    for (0..total_columns) |column|
        column_offsets[column] = @intCast(column * placement.trace_rows);
    const host_words: []const M31 =
        @as([*]const M31, @ptrCast(trace_words.ptr))[0..trace_words.len];
    var reader = ProductReader{
        .words = host_words,
        .offsets = column_offsets,
        .bases = bases,
        .column_words = placement.trace_rows,
        .shift_amt = placement.shift_amt,
    };
    const expected = try allocator.alloc(QM31, placement.eval_rows);
    defer allocator.free(expected);
    @memset(expected, QM31.zero());
    for (component.parts) |part| {
        var program = part.program;
        program.header.domain_log_size = geometry.trace_log;
        try simd_evaluator.evaluatePart(allocator, program, .{
            .evaluation_log_size = geometry.eval_log,
            .trace_log_size = geometry.trace_log,
            .trace = .{ .context = @ptrCast(&reader), .resolve = ProductReader.resolve },
            .extension_parameters = ext_values[0..program.header.n_ext_params],
            .random_coefficients = coefficients,
            .constraint_base = part.rc_base,
            .denominator_inverses = words[placement.denom_inv..][0..placement.denominator_count],
        }, HostSink{ .values = expected });
    }

    for (0..placement.eval_rows) |row| {
        const reference = expected[row].toM31Array();
        for (reference, placement.coordinates) |coordinate, offset|
            try std.testing.expectEqual(coordinate.v, words[offset + row]);
    }
    std.debug.print(
        "OPTION_B_ANCHOR role={s} component={s} parts={d} constraints={d} " ++
            "columns={d} trace_log={d} eval_log={d} shift_amt={d} " ++
            "trace_rows={d} eval_rows={d} host_lift_words=0 gpu_ms={d:.4} byte_exact=true\n",
        .{
            role,                 component.label,
            component.parts.len,  component.n_constraints,
            total_columns,        geometry.trace_log,
            geometry.eval_log,    placement.shift_amt,
            placement.trace_rows, placement.eval_rows,
            gpu_ms,
        },
    );
}

test "metal: option B reads product trace-domain columns byte-exactly, no lift" {
    const allocator = std.testing.allocator;
    var bundle = try composition.Bundle.readFile(allocator, bundle_path);
    defer bundle.deinit();

    // The layout choice depends on this: the shift table starts at
    // `base_params + n_base_params`, and every component in the tree has no base
    // parameters today, so it starts at `base_params`. If a parameterized
    // program ever lands, this assertion is where the layout is re-read.
    var eligible_components: usize = 0;
    for (bundle.components) |component| {
        if (!eligible(component)) continue;
        eligible_components += 1;
        for (component.parts) |part|
            try std.testing.expectEqual(@as(u32, 0), part.program.header.n_base_params);
    }
    try std.testing.expect(eligible_components > 0);

    var runtime = try metal.Runtime.initFull();
    defer runtime.deinit();

    // The five component roles increment 3.5 §2 and 3.6 §5 established as the
    // load-bearing ones, at rescaled geometry so the multi-part reference fits
    // the budget. Multi-part is the load-bearing case for the accumulator and
    // `rc_base` conventions; 90 parts is the load-bearing case for both.
    const roles = [_]struct { role: []const u8, label: []const u8 }{
        .{ .role = "1-part", .label = "blake_round_sigma" },
        .{ .role = "3-part", .label = "add_opcode" },
        .{ .role = "5-part", .label = "bitwise_builtin" },
        .{ .role = "41-part", .label = "partial_ec_mul_window_bits_18" },
        .{ .role = "90-part", .label = "partial_ec_mul_generic" },
    };
    const rescaled = Geometry{
        .trace_log = rescaled_trace_log,
        .eval_log = rescaled_eval_log,
    };
    var covered: usize = 0;
    for (roles) |entry| {
        const component = find(bundle, entry.label) orelse continue;
        try anchorOptionB(allocator, &runtime, component, rescaled, entry.role);
        covered += 1;
    }
    try std.testing.expectEqual(roles.len, covered);

    // And the two that are cheap enough to also anchor at their own bundle
    // geometry, so the rescaling is not the only geometry ever checked.
    for ([_][]const u8{ "blake_round_sigma", "bitwise_builtin" }) |label| {
        const component = find(bundle, label) orelse continue;
        try anchorOptionB(
            allocator,
            &runtime,
            component,
            naturalGeometry(component),
            "natural",
        );
    }
}

test "metal: option B prices against the eval-domain kernels on lifted input" {
    const allocator = std.testing.allocator;
    var bundle = try composition.Bundle.readFile(allocator, bundle_path);
    defer bundle.deinit();

    var runtime = try metal.Runtime.initFull();
    defer runtime.deinit();

    // Portfolio-shaped components at their own bundle geometry: 3.7 §2 measured
    // `add_opcode_small` and `add_opcode` at exactly arithmetic-2m's claimed log
    // sizes, so these two are the rows a projection can use without
    // extrapolation. `range_check_20` is the single-part control.
    const priced = [_][]const u8{ "add_opcode", "add_opcode_small", "range_check_20" };
    for (priced) |label| {
        const component = find(bundle, label) orelse continue;
        const geometry = naturalGeometry(component);

        const per_interaction = try columnCounts(allocator, component);
        defer allocator.free(per_interaction);
        const bases = try allocator.alloc(u32, per_interaction.len);
        defer allocator.free(bases);
        var total_columns: u32 = 0;
        for (per_interaction, bases) |count, *base| {
            base.* = total_columns;
            total_columns += count;
        }

        const stored_plan = plan(component, geometry, bases, total_columns, true);
        const lifted_plan = plan(component, geometry, bases, total_columns, false);
        const trace_words = try allocator.alloc(
            u32,
            @as(usize, total_columns) * stored_plan.trace_rows,
        );
        defer allocator.free(trace_words);
        fill(trace_words, 0x5eed_1234);

        const arena_words = @max(stored_plan.words, lifted_plan.words);
        var arena = try runtime.allocateResidentBuffer(
            (@as(usize, arena_words) + 1024) * @sizeOf(u32),
        );
        defer arena.deinit();

        // Warm both pipelines and both memory paths before timing: 3.7 §2
        // established that 3.6's apparent 3.05x ABI gap was first-dispatch cost.
        var scratch: f64 = 0;
        var stored_best: f64 = std.math.inf(f64);
        var lifted_best: f64 = std.math.inf(f64);
        var stored_lift_ms: f64 = 0;
        var lifted_lift_ms: f64 = 0;
        for (0..3) |sample| {
            const stored_ms = try dispatch(
                allocator,
                &runtime,
                component,
                geometry,
                .stored_domain,
                bases,
                trace_words,
                stored_plan,
                arena,
                &scratch,
            );
            if (sample != 0) {
                stored_best = @min(stored_best, stored_ms);
                stored_lift_ms = scratch;
            }
            const lifted_ms = try dispatch(
                allocator,
                &runtime,
                component,
                geometry,
                .eval_domain,
                bases,
                trace_words,
                lifted_plan,
                arena,
                &scratch,
            );
            if (sample != 0) {
                lifted_best = @min(lifted_best, lifted_ms);
                lifted_lift_ms = scratch;
            }
        }
        const stored_bytes = @as(u64, total_columns) * stored_plan.trace_rows * @sizeOf(u32);
        const lifted_bytes = @as(u64, total_columns) * lifted_plan.eval_rows * @sizeOf(u32);
        std.debug.print(
            "OPTION_B_PRICE component={s} parts={d} columns={d} trace_log={d} " ++
                "eval_log={d} eval_rows={d} stored_gpu_ms={d:.4} lifted_gpu_ms={d:.4} " ++
                "stored_over_lifted={d:.4} stored_stage_bytes={d} lifted_stage_bytes={d} " ++
                "stored_stage_ms={d:.3} lifted_stage_ms={d:.3}\n",
            .{
                component.label,           component.parts.len,
                total_columns,             geometry.trace_log,
                geometry.eval_log,         stored_plan.eval_rows,
                stored_best,               lifted_best,
                stored_best / lifted_best, stored_bytes,
                lifted_bytes,              stored_lift_ms,
                lifted_lift_ms,
            },
        );
    }
}
