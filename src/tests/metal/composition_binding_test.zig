//! Phase 1 unlock: the digest-verified composition metallib bound against a
//! live resident arena, byte-compared against the host evaluator.
//!
//! This is a *test*, not a product hook. What it demonstrates is exactly the
//! binding the Phase 1 increment could not measure: real Cairo component parts
//! from the authenticated composition bundle, their kernels resolved by name
//! out of `vectors/cairo/sn_pie_2_composition.metallib` under the gating
//! admission policy, dispatched with `evalPrepared` against a resident arena
//! whose trace columns are laid out the way `trace_arena` lays them out, and
//! their four QM31 coordinate outputs compared word-for-word with
//! `proving/air/simd_evaluator` running the same `eval_program` on the host.
//!
//! Contract being pinned, read out of `eval_codegen.zig:553-557`:
//!   `arena[interaction_offsets + interaction]` -> global column base
//!   `arena[trace_offsets + global]`             -> that column's word offset
//!   column data is indexed by the *evaluation*-domain row
//!   `arena[denom_inv + (row >> trace_log_size)]` -> denominator inverse
//!
//! ## The lifted-column convention, which is what increment 3.4 tripped over
//!
//! `simd_evaluator.ResolvedColumn.shift_amt` is NOT a "0 means natural order"
//! flag. The row loop reads
//!   `values[((position >> shift_amt) << 1) + (position & 1)]`
//! and the product's own producer sets `shift_amt = eval_log - column_log + 1`
//! (`proving/air/component.zig:355-359`). The `<< 1` and the `+ 1` are the
//! lifted-PCS pairing: the low bit of an evaluation-domain position selects
//! within a circle-domain conjugate pair and is preserved, while the rest of
//! the position is shifted down onto a column stored at its own smaller log
//! size. So the identity map — which is what the device kernel does, it reads
//! `column[row]` — is `shift_amt = 1`, and `shift_amt = 0` is the stride-2 walk
//! `values[2 * position + (position & 1)]`.
//!
//! Increment 3.4 handed evaluation-domain-length columns to the host reader
//! with `shift_amt = 0` and concluded the residual delta had to be semantic.
//! It was not: it was this convention. The first test below is the
//! discriminating experiment that names it observably rather than by argument.

const std = @import("std");
const core = @import("stwo_core");
const metal = @import("stwo_metal_backend").runtime;
const cairo = @import("stwo_cairo_frontend");
const integration = @import("stwo_cairo_metal_integration");

const composition = cairo.witness.composition_bundle;
const eval_program = cairo.witness.eval_program;
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

/// Reads one column out of the arena the way the *host* evaluator expects to be
/// handed it: a slice bounded to exactly that column's extent, plus the lifting
/// shift for its stored log size. Bounding the slice matters — an unbounded
/// `words[start..]` lets a wrong `shift_amt` read the neighbouring column's
/// data instead of tripping a bounds check, which is precisely how increment
/// 3.4's mismatch stayed silent.
const HostReader = struct {
    words: []const M31,
    offsets: []const u32,
    bases: []const u32,
    /// Every column in this arena is stored at evaluation-domain length.
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

// ---------------------------------------------------------------------------
// The discriminating experiment
// ---------------------------------------------------------------------------

// A one-column, one-constraint synthetic part whose output *is* the column
// value it read, so the coordinate written at row `r` names the index the
// evaluator read from. The column is filled with `index + 1`, so
// `coord_0[r] == map(r) + 1` reads the index map straight out of the buffer.
//
// This discriminates the two candidate conventions without any appeal to the
// real bundle: the device must show `map(r) = r`, the host under
// `shift_amt = 1` must show `map(r) = r`, and the host under `shift_amt = 0`
// must show `map(r) = 2r + (r & 1)`. Whichever way it comes out, the failure
// message is the convention rather than a pair of unattributable field
// elements.
test "metal: the eval ABI index map is the lifted-column identity at shift 1" {
    const allocator = std.testing.allocator;

    var base_insts = [_]eval_program.BaseInst{
        .{ .op = .trace_col, .interaction = 0, .dst = 0, .a = 0, .b = 0, .imm = 0 },
    };
    var ext_insts = [_]eval_program.ExtInst{
        .{ .op = .secure_col, .dst = 0, .a = 0, .b = 0, .c = 0, .d = 0 },
    };
    var roots = [_]u32{0};
    const program = eval_program.Program{
        .allocator = allocator,
        .header = .{
            .flags = eval_program.Flag.prefinalized_logup,
            .semantic_hash = 0x1de_2_1de_2,
            .capability_bits = eval_program.Capability.prefinalized_logup,
            .n_interactions = 1,
            .n_base_params = 0,
            .n_ext_params = 0,
            .n_constraints = 1,
            .max_base_regs = 1,
            .max_ext_regs = 1,
            .domain_log_size = 4,
        },
        .base_consts = &.{},
        .ext_consts = &.{},
        .base_insts = &base_insts,
        .ext_insts = &ext_insts,
        .constraint_roots = &roots,
    };

    const trace_log: u32 = program.header.domain_log_size;
    const eval_log: u32 = trace_log + 1;
    const row_count: u32 = @as(u32, 1) << @intCast(eval_log);
    const denominator_count: u32 = @as(u32, 1) << @intCast(eval_log - trace_log);

    var next: u32 = 1; // leave word 0 unused so a zero offset cannot pass by luck
    const column_base = next;
    // Twice the evaluation domain, because the `shift_amt = 0` candidate reaches
    // index `2 * row`. Filling that whole range is what makes the experiment
    // observe the index map rather than observe where the column ends.
    const column_words: u32 = 2 * row_count;
    next += column_words;
    const trace_offsets = next;
    next += 1;
    const interaction_offsets = next;
    next += 1;
    const random_coeffs = next;
    next += 4;
    const denom_inv = next;
    next += denominator_count;
    var coordinates: [4]u32 = undefined;
    for (&coordinates) |*offset| {
        offset.* = next;
        next += row_count;
    }

    var runtime = try metal.Runtime.initFull();
    defer runtime.deinit();
    var arena = try runtime.allocateResidentBuffer((@as(usize, next) + 64) * @sizeOf(u32));
    defer arena.deinit();
    const words: [*]u32 = @ptrCast(@alignCast(arena.contents));
    @memset(words[0..next], 0);

    // column[i] = i + 1, so the value read names the index read.
    for (0..column_words) |index| words[column_base + index] = @intCast(index + 1);
    words[trace_offsets] = column_base;
    words[interaction_offsets] = 0;
    // coefficient = 1, denominator inverse = 1: the fold is the identity.
    words[random_coeffs] = 1;
    for (0..denominator_count) |index| words[denom_inv + index] = 1;

    // Device: compile this exact program's kernel and dispatch it.
    const source = try codegen.generate(allocator, program);
    defer allocator.free(source);
    var library = try runtime.compileEvalLibrary(source);
    defer library.deinit();
    const name = try codegen.kernelName(allocator, program.header.semantic_hash);
    defer allocator.free(name);
    var plan = try runtime.prepareEvalFromLibrary(library, name, .{
        .trace_offsets = trace_offsets,
        .interaction_offsets = interaction_offsets,
        .base_params = 0,
        .ext_params = 0,
        .random_coeffs = random_coeffs,
        .denom_inv = denom_inv,
        .coordinates = coordinates,
        .row_count = row_count,
        .trace_log_size = trace_log,
        .domain_log_size = trace_log,
        .rc_base = 0,
    });
    defer plan.deinit();
    _ = try runtime.evalPrepared(arena, plan);

    // The device reads the evaluation-domain row directly.
    for (0..row_count) |row|
        try std.testing.expectEqual(@as(u32, @intCast(row + 1)), words[coordinates[0] + row]);

    // The host, given the same words, under each candidate shift.
    const coefficients = [_]QM31{QM31.fromU32Unchecked(1, 0, 0, 0)};
    const host_words: []const M31 = @as([*]const M31, @ptrCast(words))[0..next];
    for ([_]std.math.Log2Int(usize){ 0, 1 }) |shift| {
        var reader = HostReader{
            .words = host_words,
            .offsets = words[trace_offsets .. trace_offsets + 1],
            .bases = words[interaction_offsets .. interaction_offsets + 1],
            // Under shift 0 the read index reaches 2*row, so the column has to
            // be presented as twice as long for the experiment to observe the
            // map rather than trip a bounds check.
            .column_words = if (shift == 0) column_words else row_count,
            .shift_amt = shift,
        };
        const observed = try allocator.alloc(QM31, row_count);
        defer allocator.free(observed);
        @memset(observed, QM31.zero());
        try simd_evaluator.evaluatePart(allocator, program, .{
            .evaluation_log_size = eval_log,
            .trace_log_size = trace_log,
            .trace = .{ .context = @ptrCast(&reader), .resolve = HostReader.resolve },
            .extension_parameters = &.{},
            .random_coefficients = &coefficients,
            .constraint_base = 0,
            .denominator_inverses = words[denom_inv .. denom_inv + denominator_count],
        }, HostSink{ .values = observed });

        for (0..row_count) |row| {
            const mapped: u32 = if (shift == 0)
                @intCast(2 * row + (row & 1))
            else
                @intCast(row);
            try std.testing.expectEqual(mapped + 1, observed[row].toM31Array()[0].v);
        }
    }

    std.debug.print(
        "EVAL_INDEX_MAP device=row host_shift1=row host_shift0=2row+(row&1) rows={d}\n",
        .{row_count},
    );
}

// ---------------------------------------------------------------------------
// Real-bundle coverage
// ---------------------------------------------------------------------------

/// The part's own instruction stream is the authority on how many columns each
/// interaction has: a column the program never reads need not exist. Taken as
/// the union across every part of the component, because all parts of a
/// component share one arena layout.
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

const Outcome = struct {
    columns: u32,
    rows: u32,
    parts: usize,
    constraints: u64,
    gpu_ms: f64,
};

/// Binds every part of one real component against the arena and byte-compares
/// the accumulated four coordinate planes against the host evaluator.
///
/// Multi-part components are the stronger case and are covered on purpose: the
/// parts accumulate into the *same* four coordinate words in bundle order and
/// each addresses the shared random-coefficient block at its own `rc_base`, so
/// a wrong accumulator convention or a wrong `rc_base` offset shows up here and
/// cannot show up in a single-part comparison.
fn runComponent(
    allocator: std.mem.Allocator,
    runtime: *metal.Runtime,
    library: metal.EvalLibrary,
    component: composition.Component,
) !Outcome {
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
    var constraints: u64 = 0;
    for (component.parts) |part| {
        try std.testing.expectEqual(trace_log, part.program.header.domain_log_size);
        // The host evaluator refuses base params, and the layout has no place
        // to put them; a component using them is out of this test's contract.
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

    // Host reference, from the same arena words. Every column here is stored at
    // evaluation-domain length, so the lifting shift is the identity, 1.
    const host_words: []const M31 = @as([*]const M31, @ptrCast(words))[0..next];
    var reader = HostReader{
        .words = host_words,
        .offsets = words[trace_offsets .. trace_offsets + total_columns],
        .bases = words[interaction_offsets .. interaction_offsets + bases.len],
        .column_words = row_count,
        .shift_amt = 1,
    };
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
    const expected = try allocator.alloc(QM31, row_count);
    defer allocator.free(expected);
    @memset(expected, QM31.zero());

    var gpu_ms: f64 = 0;
    for (component.parts) |part| {
        try simd_evaluator.evaluatePart(allocator, part.program, .{
            .evaluation_log_size = eval_log,
            .trace_log_size = trace_log,
            .trace = .{ .context = @ptrCast(&reader), .resolve = HostReader.resolve },
            .extension_parameters = ext_values[0..part.program.header.n_ext_params],
            .random_coefficients = coefficients,
            .constraint_base = part.rc_base,
            .denominator_inverses = words[denom_inv .. denom_inv + denominator_count],
        }, HostSink{ .values = expected });

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
            .domain_log_size = part.program.header.domain_log_size,
            .rc_base = part.rc_base,
        });
        defer plan.deinit();
        gpu_ms += try runtime.evalPrepared(arena, plan);
    }

    // Byte-exact, every row, every coordinate.
    for (0..row_count) |row| {
        const reference = expected[row].toM31Array();
        for (reference, coordinates) |coordinate, offset|
            try std.testing.expectEqual(coordinate.v, words[offset + row]);
    }

    return .{
        .columns = total_columns,
        .rows = row_count,
        .parts = component.parts.len,
        .constraints = constraints,
        .gpu_ms = gpu_ms,
    };
}

/// True when this test's arena contract can express the component at all.
fn eligible(component: composition.Component) bool {
    if (component.parts.len == 0) return false;
    if (component.evaluation_log_size <= component.trace_log_size) return false;
    // The host row loop steps by `lane_count`; below that there is no row group.
    if (component.evaluation_log_size < 3) return false;
    for (component.parts) |part| {
        if (part.program.header.n_base_params != 0) return false;
        if (part.program.header.domain_log_size != component.trace_log_size) return false;
    }
    return true;
}

/// The components that constitute an arithmetic Cairo trace — the memory
/// argument and the arithmetic opcodes. Named rather than derived because the
/// SN2 bundle carries SN2's geometry, not arithmetic-2m's, so "arithmetic-2m's
/// dominant component" can only be identified here by which component it *is*,
/// not by how big it is in this bundle. Per note §6.2 the metallib kernel is
/// log-size-independent, so the SN2 instance of the component exercises exactly
/// the kernel arithmetic-2m would dispatch.
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

// Structural coverage: the smallest component in the bundle, the component
// carrying the most composition work (rows x constraints), the component with
// the most parts (the accumulator-order case), and the largest component of the
// arithmetic set above.
test "metal: the approved composition metallib matches the host evaluator on a live arena" {
    const allocator = std.testing.allocator;

    var bundle = try composition.Bundle.readFile(allocator, bundle_path);
    defer bundle.deinit();

    var smallest: ?composition.Component = null;
    var dominant: ?composition.Component = null;
    var widest: ?composition.Component = null;
    var arithmetic: ?composition.Component = null;
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
    }
    const small = smallest orelse return error.NoEligibleComponent;
    const big = dominant orelse return error.NoEligibleComponent;
    const multi = widest orelse return error.NoEligibleComponent;

    const admission = try composition_aot.authenticate(metallib_path, .approved_manifest);
    try std.testing.expect(admission.label != null);

    var runtime = try metal.Runtime.initFull();
    defer runtime.deinit();
    var library = try runtime.loadEvalLibrary(metallib_path);
    defer library.deinit();

    const cases = [_]struct { role: []const u8, component: composition.Component }{
        .{ .role = "small", .component = small },
        .{ .role = "dominant", .component = big },
        .{ .role = "multipart", .component = multi },
        .{
            .role = "arithmetic-dominant",
            .component = arithmetic orelse return error.NoArithmeticComponent,
        },
    };
    for (cases) |case| {
        const outcome = try runComponent(allocator, &runtime, library, case.component);
        std.debug.print(
            "COMPOSITION_BINDING role={s} component={s} eval_log={d} trace_log={d} " ++
                "columns={d} rows={d} parts={d} constraints={d} gpu_ms={d:.4} label={s}\n",
            .{
                case.role,                          case.component.label,
                case.component.evaluation_log_size, case.component.trace_log_size,
                outcome.columns,                    outcome.rows,
                outcome.parts,                      outcome.constraints,
                outcome.gpu_ms,                     admission.label.?,
            },
        );
    }
}
