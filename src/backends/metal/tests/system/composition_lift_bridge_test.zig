//! Increment 3.7, step 2: what a product-owned eval arena actually has to hold.
//!
//! The increment was scoped on the belief — inherited from increment 3.5 §6 and
//! restated in this increment's brief — that putting the eval inputs in a
//! product arena is **placement**: base columns are already arena-resident
//! (3.2/3.4), interaction columns are host-computed and would merely be *moved*,
//! and denominators and parameters are small appended blocks. That is true of
//! every block except the one that carries all the bytes, and this file is where
//! that stops being a belief.
//!
//! ## The device ABI wants a column length the product does not have
//!
//! The compiled kernels read a trace value as, from the emitted preamble,
//!
//! ```
//! inline uint trace_value(device uint *arena, constant EvalArgs &args,
//!                         uint interaction, uint column, uint row, int offset) {
//!     uint target = offset == 0 ? row
//!                 : offset_circle(row, args.domain_log_size, ctz(args.row_count), offset);
//!     uint global = arena[args.interaction_offsets + interaction] + column;
//!     return arena[arena[args.trace_offsets + global] + target];
//! }
//! ```
//!
//! `row` runs over the **evaluation** domain (`args.row_count = 2^eval_log`) and
//! indexes the column directly. So a column in the arena must be
//! `2^eval_log` words long. That is what increment 3.5 discovered when it fixed
//! the smoke's host reader to `shift_amt = 1`: `shift_amt = 1` *is* the identity,
//! and it is the identity precisely because the smoke's arena stored columns at
//! evaluation-domain length.
//!
//! The product does not. `pcs/scheme_views.polynomials` publishes
//! `Poly{ .log_size = column.log_size, .values = column.values }` straight off
//! the committed trees, so a base or interaction column is `2^trace_log` words —
//! half the length — and `proving/air/component.zig:355` therefore hands the host
//! evaluator `shift_amt = evaluation_log_size - column.log_size + 1 = 2`, not 1.
//!
//! So the product's columns and the authenticated metallib's ABI disagree on
//! column length by the blowup factor, and no amount of *placing* a
//! `2^trace_log`-word column at a planned offset fixes that. Either the arena
//! materialises a lifted `2^eval_log`-word copy, or the kernels learn the shift.
//!
//! ## What this file establishes
//!
//! 1. **The lift is the correct bridge, byte-exact.** For real components of the
//!    authenticated bundle, host trace-domain columns are lifted into an arena at
//!    evaluation-domain length, the AOT kernels are dispatched against it, and
//!    the result is compared against `simd_evaluator` reading the *same*
//!    trace-domain columns at the product's own `shift_amt = 2`. Byte-exact means
//!    the lift is exactly the product's lifting convention and the next increment
//!    can rely on it.
//! 2. **The lift's price**, measured, plus the volume each portfolio workload
//!    would have to lift — which is what decides whether option A (lift into the
//!    arena, works with the metallib that exists) or option B (teach the codegen
//!    the shift and re-mint the metallib in CI) is the right next increment.
//!
//! The lifting map, derived from `component_prover.Poly.at` and verified below:
//! with `s = eval_log - trace_log + 1`, evaluation position `p` reads trace index
//! `((p >> s) << 1) + (p & 1)`. At the bundle's uniform blowup of one that is
//! `p -> ((p >> 2) << 1) + (p & 1)`, i.e. each adjacent trace pair emitted twice:
//! `[t0,t1,t0,t1, t2,t3,t2,t3, ...]`. So it is a streaming 8-byte-granule
//! duplication, not a gather — which is why it is worth pricing rather than
//! assuming it is fatal.

const std = @import("std");
const core = @import("stwo_core");
const metal = @import("stwo_metal_backend").runtime;
const cairo = @import("stwo_cairo_frontend");
const integration = @import("stwo_cairo_metal_integration");

const composition = cairo.witness.composition_bundle;
const simd_evaluator = cairo.proving.air.simd_evaluator;
const codegen = integration.eval_codegen;
const composition_aot = integration.composition_aot;

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

const m31_modulus: u64 = (1 << 31) - 1;

const bundle_path = "vectors/cairo/sn_pie_2_composition.bin";
const metallib_path = "vectors/cairo/sn_pie_2_composition.metallib";

fn fill(words: []u32, seed: u64) void {
    var state = seed | 1;
    for (words) |*word| {
        state = state *% 6364136223846793005 +% 1442695040888963407;
        word.* = @intCast((state >> 33) % (m31_modulus - 1) + 1);
    }
}

/// The product's lifting map, read out of `component_prover.Poly.at`.
fn liftedIndex(position: usize, shift_amt: std.math.Log2Int(usize)) usize {
    return ((position >> shift_amt) << 1) + (position & 1);
}

/// Materialises one evaluation-domain column from one trace-domain column.
///
/// Written as the pair-duplication it is rather than as a per-position gather,
/// because the price this file reports is the price the product would pay and a
/// product would not write the gather.
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

test "metal: the lifting map matches the product's own column reader" {
    // Pinned against `Poly.at`'s expression rather than against a table, and
    // asserted at the two shifts the bundle can produce, so a change to either
    // side is caught here rather than in a proof digest.
    try std.testing.expectEqual(@as(usize, 0), liftedIndex(0, 2));
    try std.testing.expectEqual(@as(usize, 1), liftedIndex(1, 2));
    try std.testing.expectEqual(@as(usize, 0), liftedIndex(2, 2));
    try std.testing.expectEqual(@as(usize, 1), liftedIndex(3, 2));
    try std.testing.expectEqual(@as(usize, 2), liftedIndex(4, 2));
    try std.testing.expectEqual(@as(usize, 3), liftedIndex(5, 2));
    // Shift 1 is the identity, which is the convention the increment 3.5 smoke
    // established and the one the compiled kernels implement.
    for (0..16) |position|
        try std.testing.expectEqual(position, liftedIndex(position, 1));

    var source = [_]u32{ 10, 11, 12, 13, 14, 15, 16, 17 };
    var destination: [16]u32 = undefined;
    liftColumn(&destination, &source, 2);
    for (0..destination.len) |position|
        try std.testing.expectEqual(source[liftedIndex(position, 2)], destination[position]);
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

/// Reads *trace-domain* columns at the product's own shift. This is the
/// reference: if the device agrees with this, the lift is the product's lift.
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

/// Lifts one component's trace-domain columns into a device arena, dispatches the
/// authenticated kernels, and optionally anchors the result against the host
/// evaluator reading the trace-domain columns at the product's shift.
fn bridgeComponent(
    allocator: std.mem.Allocator,
    runtime: *metal.Runtime,
    library: metal.EvalLibrary,
    component: composition.Component,
    host_check: bool,
) !void {
    const eval_log = component.evaluation_log_size;
    const trace_log = component.trace_log_size;
    const eval_rows: u32 = @as(u32, 1) << @intCast(eval_log);
    const trace_rows: u32 = @as(u32, 1) << @intCast(trace_log);
    const denominator_count: u32 = @as(u32, 1) << @intCast(eval_log - trace_log);
    const shift_amt: std.math.Log2Int(usize) = @intCast(eval_log - trace_log + 1);

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
        ext_param_count = @max(ext_param_count, part.program.header.n_ext_params);
        coefficient_count = @max(
            coefficient_count,
            part.rc_base + part.program.header.n_constraints,
        );
    }

    // The product side: trace-domain columns, exactly the length and convention
    // `pcs/scheme_views.polynomials` publishes.
    const trace_words = try allocator.alloc(u32, @as(usize, total_columns) * trace_rows);
    defer allocator.free(trace_words);
    fill(trace_words, 0x5eed_1234);
    const trace_column_offsets = try allocator.alloc(u32, total_columns);
    defer allocator.free(trace_column_offsets);
    for (0..total_columns) |column|
        trace_column_offsets[column] = @intCast(column * trace_rows);

    // The device side: the same columns lifted to evaluation-domain length.
    var next: u32 = 0;
    const column_base = next;
    next += total_columns * eval_rows;
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
        next += eval_rows;
    }

    var arena = try runtime.allocateResidentBuffer((@as(usize, next) + 1024) * @sizeOf(u32));
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    @memset(words[0..next], 0);

    // *** The lift, timed. This is the cost the arena extension would add. ***
    var lift_timer = try std.time.Timer.start();
    for (0..total_columns) |column| {
        const destination = words[column_base + column * eval_rows ..][0..eval_rows];
        const source = trace_words[column * trace_rows ..][0..trace_rows];
        liftColumn(destination, source, shift_amt);
    }
    const lift_ns = lift_timer.read();
    const lift_ms = @as(f64, @floatFromInt(lift_ns)) / std.time.ns_per_ms;

    for (0..total_columns) |column|
        words[trace_offsets + column] = column_base + @as(u32, @intCast(column)) * eval_rows;
    for (bases, 0..) |base, index| words[interaction_offsets + index] = base;
    if (ext_param_count != 0)
        fill(words[ext_params .. ext_params + 4 * ext_param_count], 0xa11ce);
    fill(words[random_coeffs .. random_coeffs + 4 * coefficient_count], 0xb0b);
    fill(words[denom_inv .. denom_inv + denominator_count], 0xc0ffee);

    var gpu_ms: f64 = 0;
    for (component.parts) |part| {
        const name = try codegen.kernelName(allocator, part.program.header.semantic_hash);
        defer allocator.free(name);
        var plan = try runtime.prepareEvalFromLibrary(library, name, .{
            .trace_offsets = trace_offsets,
            .interaction_offsets = interaction_offsets,
            .base_params = 0,
            .ext_params = ext_params,
            .random_coeffs = random_coeffs,
            .denom_inv = denom_inv,
            .coordinates = coordinates,
            .row_count = eval_rows,
            .trace_log_size = trace_log,
            .domain_log_size = part.program.header.domain_log_size,
            .rc_base = part.rc_base,
        });
        defer plan.deinit();
        gpu_ms += try runtime.evalPrepared(arena, plan);
    }

    const lifted_words = @as(u64, total_columns) * eval_rows;
    const lift_gb_per_s = if (lift_ns == 0) 0 else @as(f64, @floatFromInt(lifted_words * @sizeOf(u32))) /
        @as(f64, @floatFromInt(lift_ns));

    std.debug.print(
        "LIFT_BRIDGE component={s} eval_log={d} trace_log={d} shift_amt={d} " ++
            "columns={d} trace_rows={d} eval_rows={d} parts={d} " ++
            "lifted_words={d} lift_ms={d:.3} lift_gb_per_s={d:.2} " ++
            "device_gpu_ms={d:.4} lift_over_device={d:.4}\n",
        .{
            component.label,  eval_log,
            trace_log,        shift_amt,
            total_columns,    trace_rows,
            eval_rows,        component.parts.len,
            lifted_words,     lift_ms,
            lift_gb_per_s,    gpu_ms,
            lift_ms / gpu_ms,
        },
    );

    if (!host_check) return;

    // The anchor that makes the lift a *product* claim: the host evaluator reads
    // the trace-domain columns at the product's own `shift_amt`, never sees the
    // lifted copy, and must agree with the device word for word.
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

    const host_words: []const M31 = @as([*]const M31, @ptrCast(trace_words.ptr))[0..trace_words.len];
    var reader = ProductReader{
        .words = host_words,
        .offsets = trace_column_offsets,
        .bases = words[interaction_offsets .. interaction_offsets + bases.len],
        .column_words = trace_rows,
        .shift_amt = shift_amt,
    };
    const expected = try allocator.alloc(QM31, eval_rows);
    defer allocator.free(expected);
    @memset(expected, QM31.zero());
    for (component.parts) |part| {
        try simd_evaluator.evaluatePart(allocator, part.program, .{
            .evaluation_log_size = eval_log,
            .trace_log_size = trace_log,
            .trace = .{ .context = @ptrCast(&reader), .resolve = ProductReader.resolve },
            .extension_parameters = ext_values[0..part.program.header.n_ext_params],
            .random_coefficients = coefficients,
            .constraint_base = part.rc_base,
            .denominator_inverses = words[denom_inv .. denom_inv + denominator_count],
        }, HostSink{ .values = expected });
    }

    for (0..eval_rows) |row| {
        const reference = expected[row].toM31Array();
        for (reference, coordinates) |coordinate, offset|
            try std.testing.expectEqual(coordinate.v, words[offset + row]);
    }
    std.debug.print(
        "LIFT_BRIDGE_HOST_ANCHOR component={s} rows={d} parts={d} " ++
            "product_shift_amt={d} byte_exact=true\n",
        .{ component.label, eval_rows, component.parts.len, shift_amt },
    );
}

test "metal: lifting product trace-domain columns reproduces the device ABI byte-exactly" {
    const allocator = std.testing.allocator;

    var bundle = try composition.Bundle.readFile(allocator, bundle_path);
    defer bundle.deinit();

    const admission = try composition_aot.authenticate(metallib_path, .approved_manifest);
    try std.testing.expect(admission.label != null);

    var runtime = try metal.Runtime.initFull();
    defer runtime.deinit();
    var library = try runtime.loadEvalLibrary(metallib_path);
    defer library.deinit();

    // Every eligible component in the bundle disagrees with the device ABI by
    // exactly the blowup factor. Assert that rather than leave it as prose: it is
    // the fact that turns "placement" into "placement plus a lift".
    var eligible_components: usize = 0;
    for (bundle.components) |component| {
        if (!eligible(component)) continue;
        eligible_components += 1;
        // The device reads at evaluation-domain length, so the product's shift is
        // never the identity the kernels assume.
        try std.testing.expect(component.evaluation_log_size > component.trace_log_size);
        try std.testing.expectEqual(
            @as(u32, 2),
            component.evaluation_log_size - component.trace_log_size + 1,
        );
        // The census a projection needs: how many columns each component's parts
        // actually reference, which is what a lift would have to materialise.
        // Log-size-independent (§6.2), so it composes with any workload's claim.
        const counts = try columnCounts(allocator, component);
        defer allocator.free(counts);
        var columns: u32 = 0;
        for (counts) |count| columns += count;
        std.debug.print(
            "LIFT_CENSUS component={s} trace_log={d} eval_log={d} parts={d} columns={d}\n",
            .{
                component.label,
                component.trace_log_size,
                component.evaluation_log_size,
                component.parts.len,
                columns,
            },
        );
    }
    try std.testing.expect(eligible_components > 0);
    std.debug.print(
        "LIFT_BRIDGE_ABI eligible_components={d} product_shift_amt=2 device_shift_amt=1 " ++
            "blowup_factor=2\n",
        .{eligible_components},
    );

    // Host-anchored on the two components small enough to run a scalar-lane
    // reference against inside the test budget — one single-part control and the
    // smallest multi-part component, which is where the accumulator and
    // coefficient-offset conventions live. Then priced on the shapes that carry
    // the portfolio, without the host reference.
    const anchored = [_][]const u8{ "blake_round_sigma", "bitwise_builtin" };
    const priced = [_][]const u8{ "add_opcode", "add_opcode_small" };

    for (anchored) |label| {
        const component = find(bundle, label) orelse continue;
        try bridgeComponent(allocator, &runtime, library, component, true);
    }
    for (priced) |label| {
        const component = find(bundle, label) orelse continue;
        try bridgeComponent(allocator, &runtime, library, component, false);
    }
}

fn find(bundle: composition.Bundle, label: []const u8) ?composition.Component {
    for (bundle.components) |component| {
        if (!eligible(component)) continue;
        if (std.mem.eql(u8, component.label, label)) return component;
    }
    return null;
}
