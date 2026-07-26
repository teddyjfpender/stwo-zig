//! Functional boundary tests for Cairo AIR execution through the CPU prover.

const std = @import("std");
const stwo = @import("stwo");

const core = stwo.core;
const prover = stwo.prover;
const cairo = stwo.frontends.cairo;
const cairo_cpu = stwo.integrations.cairo_cpu;

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Poly = prover.air.component_prover.Poly;

test "Cairo proof-input construction compiles recursively" {
    std.testing.refAllDeclsRecursive(cairo.proving);
}

test "official Cairo all-opcodes commitment traces match Rust" {
    const allocator = std.testing.allocator;
    const input_path = "vectors/cairo/official/all_opcodes.prover_input.json";

    var input = try cairo.adapter.official_input.readFile(allocator, input_path);
    defer input.deinit(allocator);
    var programs = try cairo.witness.bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/official/witness_programs_v1.bin",
    );
    defer programs.deinit();
    var topology = try cairo.witness.feed_topology.readOfficial(
        allocator,
        "vectors/cairo/official/witness_feed_topology_v1.json",
    );
    defer topology.deinit();
    var fixed = try cairo.witness.fixed_table_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/cairo_fixed_tables.bin",
    );
    defer fixed.deinit();

    const encoded = try std.fs.cwd().readFileAlloc(allocator, input_path, 2 * 1024 * 1024);
    defer allocator.free(encoded);
    var input_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &input_digest, .{});
    var expected = try cairo.conformance.receipt.readFile(
        allocator,
        "vectors/cairo/official/all_opcodes.base_trace_checkpoint.json",
        .{
            .input_sha256 = input_digest,
            .authority = .{
                .stwo_cairo_revision = cairo.claim_registry.source_revision.stwo_cairo,
                .stwo_revision = cairo.claim_registry.source_revision.stwo,
            },
        },
    );
    defer expected.deinit();

    var trace = try cairo.proving.base_trace.build(
        allocator,
        &input,
        &programs,
        topology,
        &fixed,
        .canonical_small,
    );
    defer trace.deinit();

    try std.testing.expectEqual(@as(usize, 1464), trace.columns.len);
    var cells: usize = 0;
    for (trace.columns) |column| {
        cells = try std.math.add(usize, cells, column.values.len);
    }
    try std.testing.expectEqual(@as(usize, 28_690_992), cells);
    try std.testing.expectEqual(@as(usize, 24), trace.execution.producers.len);

    var relations = try cairo.witness.relation_bundle.Bundle.readFile(
        allocator,
        "vectors/cairo/cairo_relation_templates.bin",
    );
    defer relations.deinit();
    var interaction_expected = try cairo.conformance.interaction_receipt.readFile(
        allocator,
        "vectors/cairo/official/all_opcodes.interaction_trace_checkpoint.json",
        .{
            .input_sha256 = input_digest,
            .authority = cairo.conformance.interaction_receipt.official_authority,
            .challenge_derivation = cairo.conformance.interaction_receipt.official_challenge_derivation,
        },
    );
    defer interaction_expected.deinit();
    const z_limbs = interaction_expected.challenge.z_m31;
    const alpha_limbs = interaction_expected.challenge.alpha_m31;
    var interaction = try cairo.proving.interaction_trace.build(
        allocator,
        &input,
        topology,
        &fixed,
        &relations,
        &trace,
        expected.components,
        QM31.fromU32Unchecked(z_limbs[0], z_limbs[1], z_limbs[2], z_limbs[3]),
        QM31.fromU32Unchecked(
            alpha_limbs[0],
            alpha_limbs[1],
            alpha_limbs[2],
            alpha_limbs[3],
        ),
        null,
    );
    defer interaction.deinit();

    try std.testing.expectEqual(@as(usize, 1032), interaction.columns.len);
    try std.testing.expectEqual(
        interaction_expected.components.len,
        interaction.claimed_sums.len,
    );
    var max_rows: usize = 0;
    for (interaction.columns) |column| max_rows = @max(max_rows, column.values.len);
    const raw_values = try allocator.alloc(u32, max_rows);
    defer allocator.free(raw_values);
    var column_cursor: usize = 0;
    for (interaction_expected.components, 0..) |component, component_index| {
        const claimed_limbs = component.claimed_sum_m31;
        try std.testing.expect(interaction.claimed_sums[component_index].eql(
            QM31.fromU32Unchecked(
                claimed_limbs[0],
                claimed_limbs[1],
                claimed_limbs[2],
                claimed_limbs[3],
            ),
        ));
        for (component.columns) |expected_column| {
            const actual = interaction.columns[column_cursor];
            try std.testing.expectEqual(
                expected_column.row_count,
                actual.values.len,
            );
            for (actual.values, raw_values[0..actual.values.len]) |value, *raw|
                raw.* = value.v;
            const digest = try cairo.conformance.interaction_checkpoint.digestColumn(
                component.ordinal,
                component.label,
                expected_column.ordinal,
                raw_values[0..actual.values.len],
            );
            try std.testing.expectEqualSlices(u8, &expected_column.sha256, &digest);
            column_cursor += 1;
        }
    }
    try std.testing.expectEqual(interaction.columns.len, column_cursor);
    const public_sum = try cairo.statement.public_logup.sum(
        allocator,
        &input,
        QM31.fromU32Unchecked(z_limbs[0], z_limbs[1], z_limbs[2], z_limbs[3]),
        QM31.fromU32Unchecked(
            alpha_limbs[0],
            alpha_limbs[1],
            alpha_limbs[2],
            alpha_limbs[3],
        ),
    );
    try std.testing.expect(
        public_sum.add(interaction.component_sum).eql(QM31.zero()),
    );
}

test "Cairo CPU AIR evaluates coefficients and denominators on domain" {
    const allocator = std.testing.allocator;

    var base_consts: [0]u32 = .{};
    var extension_consts: [0][4]u32 = .{};
    var base_instructions = [_]cairo.witness.eval_program.BaseInst{.{
        .op = .trace_col,
        .interaction = 1,
        .dst = 0,
        .a = 0,
        .b = 0,
        .imm = 0,
    }};
    var extension_instructions = [_]cairo.witness.eval_program.ExtInst{
        .{ .op = .secure_col, .dst = 0, .a = 0, .b = 0, .c = 0, .d = 0 },
        .{ .op = .constant, .dst = 1, .a = 3, .b = 7, .c = 11, .d = 13 },
        .{ .op = .mul, .dst = 2, .a = 0, .b = 1, .c = 0, .d = 0 },
    };
    var constraint_roots = [_]u32{ 2, 1 };
    var program = cairo.witness.eval_program.Program{
        .allocator = allocator,
        .header = .{
            .flags = cairo.witness.eval_program.Flag.prefinalized_logup,
            .semantic_hash = 1,
            .capability_bits = cairo.witness.eval_program.Capability.prefinalized_logup |
                cairo.witness.eval_program.Capability.ext_mul,
            .n_interactions = 3,
            .n_base_params = 0,
            .n_ext_params = 0,
            .n_constraints = constraint_roots.len,
            .max_base_regs = 1,
            .max_ext_regs = 3,
            .domain_log_size = 2,
        },
        .base_consts = base_consts[0..],
        .ext_consts = extension_consts[0..],
        .base_insts = base_instructions[0..],
        .ext_insts = extension_instructions[0..],
        .constraint_roots = constraint_roots[0..],
    };
    try program.validate();

    var spans = [_]cairo.witness.composition_bundle.TraceSpan{
        .{ .tree = 1, .start = 0, .end = 1 },
        .{ .tree = 2, .start = 0, .end = 0 },
    };
    var preprocessed_indices: [0]u32 = .{};
    var denominator_inverses = [_]u32{ 1, 2 };
    var extension_sources: [0]cairo.witness.composition_bundle.ExtSource = .{};
    var label = "synthetic".*;
    var parts = [_]cairo.witness.composition_bundle.Part{.{
        .rc_base = 0,
        .semantic_hash = 1,
        .program = program,
    }};
    var captured = cairo.witness.composition_bundle.Component{
        .label = label[0..],
        .instance = 0,
        .trace_log_size = 2,
        .evaluation_log_size = 3,
        .n_constraints = constraint_roots.len,
        .random_coefficient_offset = 0,
        .trace_spans = spans[0..],
        .preprocessed_indices = preprocessed_indices[0..],
        .denominator_inverses = denominator_inverses[0..],
        .ext_sources = extension_sources[0..],
        .parts = parts[0..],
    };

    var trace_values: [8]M31 = undefined;
    for (&trace_values, 0..) |*value, index| {
        value.* = M31.fromCanonical(@intCast(index + 1));
    }
    var empty_polys: [0]Poly = .{};
    var base_polys = [_]Poly{.{
        .log_size = 3,
        .values = trace_values[0..],
    }};
    var trees = [_][]const Poly{
        empty_polys[0..],
        base_polys[0..],
        empty_polys[0..],
    };
    const trace = prover.air.component_prover.Trace{
        .polys = core.pcs.TreeVec([]const Poly).initOwned(trees[0..]),
    };

    const alpha = QM31.fromBase(M31.fromCanonical(5));
    var accumulator = try prover.air.accumulation.DomainEvaluationAccumulator.init(
        allocator,
        alpha,
        3,
        constraint_roots.len,
    );
    defer accumulator.deinit();

    const preprocessed_logs: [0]u32 = .{};
    const component = cairo_cpu.air.component.Component.init(
        allocator,
        &captured,
        &preprocessed_logs,
        4,
        QM31.one(),
        QM31.one(),
        QM31.zero(),
    );
    try component.evaluateConstraintQuotientsOnDomain(&trace, &accumulator);

    var evaluation = try accumulator.finalize();
    defer evaluation.deinit(allocator);
    const extension_constant = QM31.fromU32Unchecked(3, 7, 11, 13);
    for (trace_values, 0..) |trace_value, row| {
        const secure_value = QM31.fromM31(
            trace_value,
            trace_value,
            trace_value,
            trace_value,
        );
        const expected_unscaled = secure_value.mul(extension_constant).mul(alpha)
            .add(extension_constant);
        const denominator = M31.fromCanonical(if (row < 4) 1 else 2);
        try std.testing.expect(
            evaluation.at(row).eql(expected_unscaled.mulM31(denominator)),
        );
    }
}
