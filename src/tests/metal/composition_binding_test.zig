//! Phase 1 unlock: the digest-verified composition metallib bound against a
//! live resident arena, byte-compared against the host evaluator.
//!
//! This is a *test*, not a product hook. What it demonstrates is exactly the
//! binding the Phase 1 increment could not measure: one real Cairo component
//! part from the authenticated composition bundle, its kernel resolved by name
//! out of `vectors/cairo/sn_pie_2_composition.metallib` under the gating
//! admission policy, dispatched with `evalPrepared` against a resident arena
//! whose trace columns are laid out the way `trace_arena` lays them out, and
//! its four QM31 coordinate outputs compared word-for-word with
//! `proving/air/simd_evaluator` running the same `eval_program` on the host.
//!
//! Contract being pinned, read out of `eval_codegen.zig:553-557`:
//!   `arena[interaction_offsets + interaction]` -> global column base
//!   `arena[trace_offsets + global]`             -> that column's word offset
//!   column data is indexed by the *evaluation*-domain row
//!   `arena[denom_inv + (row >> trace_log_size)]` -> denominator inverse
//! The host reader is given the same columns at evaluation-domain length with
//! `shift_amt = 0`, so any disagreement is a real semantic disagreement and not
//! a layout convention mismatch.

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

/// Deterministic, canonical-range filler. Not random: the comparison must be
/// reproducible from the source alone.
fn fill(words: []u32, seed: u64) void {
    var state = seed | 1;
    for (words) |*word| {
        state = state *% 6364136223846793005 +% 1442695040888963407;
        word.* = @intCast((state >> 33) % (m31_modulus - 1) + 1);
    }
}

const Columns = struct {
    /// Word offset of each global column's data inside the arena.
    offsets: []u32,
    /// Number of columns each interaction contributes, in interaction order.
    per_interaction: []u32,
    /// Global base of each interaction.
    bases: []u32,
};

/// The part's own instruction stream is the authority on how many columns each
/// interaction has: a column the program never reads need not exist.
fn columnCounts(allocator: std.mem.Allocator, program: cairo.witness.eval_program.Program) ![]u32 {
    const counts = try allocator.alloc(u32, program.header.n_interactions);
    @memset(counts, 0);
    for (program.base_insts) |instruction| switch (instruction.op) {
        .trace_col, .preprocessed_col => {
            if (instruction.interaction >= counts.len) return error.InvalidCompositionPart;
            counts[instruction.interaction] =
                @max(counts[instruction.interaction], instruction.a + 1);
        },
        else => {},
    };
    return counts;
}

const HostReader = struct {
    words: []const M31,
    offsets: []const u32,
    bases: []const u32,

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
        return .{ .values = self.words[start..], .shift_amt = 0 };
    }
};

const HostSink = struct {
    values: []QM31,

    pub fn accumulate(self: HostSink, row: usize, value: QM31) void {
        self.values[row] = self.values[row].add(value);
    }
};

test "metal: the approved composition metallib matches the host evaluator on a live arena" {
    const allocator = std.testing.allocator;

    var bundle = try composition.Bundle.readFile(allocator, bundle_path);
    defer bundle.deinit();

    // Pick the smallest single-part component in the bundle. Smallest keeps the
    // arena inside a test-sized resident allocation; single-part keeps the
    // comparison against exactly one kernel rather than an accumulator order.
    var chosen: ?composition.Component = null;
    for (bundle.components) |component| {
        if (component.parts.len != 1) continue;
        if (chosen == null or component.evaluation_log_size < chosen.?.evaluation_log_size)
            chosen = component;
    }
    const component = chosen orelse return error.NoSinglePartComponent;
    const part = component.parts[0];
    const program = part.program;

    const eval_log = component.evaluation_log_size;
    const trace_log = component.trace_log_size;
    try std.testing.expectEqual(trace_log, program.header.domain_log_size);
    const row_count: u32 = @as(u32, 1) << @intCast(eval_log);

    const per_interaction = try columnCounts(allocator, program);
    defer allocator.free(per_interaction);
    const bases = try allocator.alloc(u32, per_interaction.len);
    defer allocator.free(bases);
    var total_columns: u32 = 0;
    for (per_interaction, bases) |count, *base| {
        base.* = total_columns;
        total_columns += count;
    }
    try std.testing.expect(total_columns > 0);

    const denominator_count: u32 = @as(u32, 1) << @intCast(eval_log - trace_log);

    // Arena layout. Column data first, contiguous and in global order, exactly
    // as `trace_arena` groups it; then the index arrays and scalars; then the
    // four coordinate outputs.
    var next: u32 = 0;
    const column_base = next;
    next += total_columns * row_count;
    const trace_offsets = next;
    next += total_columns;
    const interaction_offsets = next;
    next += @intCast(bases.len);
    const ext_params = next;
    next += @intCast(4 * program.header.n_ext_params);
    const random_coeffs = next;
    const coefficient_count: u32 = part.rc_base + program.header.n_constraints;
    next += 4 * coefficient_count;
    const denom_inv = next;
    next += denominator_count;
    var coordinates: [4]u32 = undefined;
    for (&coordinates) |*offset| {
        offset.* = next;
        next += row_count;
    }

    const arena_bytes = (@as(usize, next) + 1024) * @sizeOf(u32);
    var runtime = try metal.Runtime.initFull();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer(arena_bytes);
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    @memset(words[0..next], 0);

    fill(words[column_base .. column_base + total_columns * row_count], 0x5eed_1234);
    for (0..total_columns) |column|
        words[trace_offsets + column] = column_base + @as(u32, @intCast(column)) * row_count;
    for (bases, 0..) |base, index| words[interaction_offsets + index] = base;
    if (program.header.n_ext_params != 0)
        fill(words[ext_params .. ext_params + 4 * program.header.n_ext_params], 0xa11ce);
    fill(words[random_coeffs .. random_coeffs + 4 * coefficient_count], 0xb0b);
    fill(words[denom_inv .. denom_inv + denominator_count], 0xc0ffee);

    // Host reference, from the same arena words.
    const host_words: []const M31 = @as([*]const M31, @ptrCast(words))[0..next];
    var reader = HostReader{
        .words = host_words,
        .offsets = words[trace_offsets .. trace_offsets + total_columns],
        .bases = words[interaction_offsets .. interaction_offsets + bases.len],
    };
    const ext_values = try allocator.alloc(QM31, program.header.n_ext_params);
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
    const expected = try allocator.alloc(QM31, row_count);
    defer allocator.free(expected);
    @memset(expected, QM31.zero());
    try simd_evaluator.evaluatePart(allocator, program, .{
        .evaluation_log_size = eval_log,
        .trace_log_size = trace_log,
        .trace = .{ .context = @ptrCast(&reader), .resolve = HostReader.resolve },
        .extension_parameters = ext_values,
        .random_coefficients = coefficients,
        .constraint_base = part.rc_base,
        .denominator_inverses = words[denom_inv .. denom_inv + denominator_count],
    }, HostSink{ .values = expected });

    // Device side, from the digest-verified library under the gating policy.
    const admission = try composition_aot.authenticate(metallib_path, .approved_manifest);
    try std.testing.expect(admission.label != null);
    var library = try runtime.loadEvalLibrary(metallib_path);
    defer library.deinit();
    const name = try codegen.kernelName(allocator, part.semantic_hash);
    defer allocator.free(name);
    var plan = try runtime.prepareEvalFromLibrary(library, name, .{
        .trace_offsets = trace_offsets,
        .interaction_offsets = interaction_offsets,
        .base_params = 0,
        .ext_params = ext_params,
        .random_coeffs = random_coeffs,
        .denom_inv = denom_inv,
        .coordinates = coordinates,
        .row_count = row_count,
        .trace_log_size = trace_log,
        .domain_log_size = program.header.domain_log_size,
        .rc_base = part.rc_base,
    });
    defer plan.deinit();
    const gpu_ms = try runtime.evalPrepared(arena, plan);
    try std.testing.expect(gpu_ms >= 0);

    // Byte-exact, every row, every coordinate.
    for (0..row_count) |row| {
        const reference = expected[row].toM31Array();
        for (reference, coordinates) |coordinate, offset|
            try std.testing.expectEqual(coordinate.v, words[offset + row]);
    }
    std.debug.print(
        "COMPOSITION_BINDING component={s} eval_log={d} trace_log={d} columns={d} rows={d} gpu_ms={d:.4} label={s}\n",
        .{ component.label, eval_log, trace_log, total_columns, row_count, gpu_ms, admission.label.? },
    );
}
