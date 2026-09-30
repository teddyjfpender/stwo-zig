//! Rung R6, leaf (design §8.2, milestone M6): the leaf verifier circuit of
//! the checked-in canonical_small leaf-prover registry, rebuilt in Zig, must
//! reproduce the registry's preprocessed root and circuit hash.
//!
//! As `circuit-params --registry` builds a leaf entry
//! (`crates/circuit_params/src/{lib,main}.rs`, https://github.com/starkware-libs/proving
//! at 5a7c5ede4299c91a61df19a07cba4f7502c14230): `leaf_verifier_config`
//! over the registry's `cairo_prover_params` at the entry's
//! `trace_log_size`, with the definition's program
//! (`crates/leaf_prover/tests/data/use_all_opcodes_and_builtins_compiled.json`)
//! and the Cairo preprocessed root committed at `trace_log_size +
//! log_blowup_factor`; `build_cairo_verifier_circuit` in topology mode;
//! `pad_to_targets` at the registry's shared target; preprocessing; then
//! `circuit_hash_and_preprocessed_root` at the circuit FRI blowup.
//!
//! The Cairo root is the committed oracle fixture
//! (`vectors/circuit/r6/topology.json`, `cairo_preprocessed_roots`); the
//! Cairo leaf lane recomputes the same roots in `test-cairo-leaf-proof`
//! (R10b). Labelled large: a 2^23-row circuit whose preprocessed trace is
//! committed at blowup 1.

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const cairo = @import("stwo_cairo_frontend");
const registry_codec = @import("stwo_circuit_recursion_wire").registry;
const testing = @import("circuit_testing");

const builder = circuit.builder;
const fixture = testing.fixture_json;
const finalize = circuit.common.finalize;
const preprocessed = circuit.common.preprocessed;
const circuit_hash = circuit.common.circuit_hash;
const circuit_statement = circuit.statements.circuit_statement;
const cairo_verifier = circuit.statements.cairo_verifier;
const cairo_leaf_config = circuit.statements.cairo_leaf_config;
const layout = core.cairo_air_layout;
const ComponentSizes = finalize.ComponentSizes;

const registry_path = "vectors/circuit/official/registries/leaf_prover_canonical_small.json";
const program_path = "vectors/circuit/official/programs/use_all_opcodes_and_builtins_compiled.json";
const topology_path = "vectors/circuit/r6/topology.json";
const projection_path = "vectors/circuit/official/compiled_air_constraints_v1.bin";

/// The committed Cairo preprocessed root of `variant` at `log_blowup_factor`
/// for a proof of `trace_log_size`.
fn committedCairoRoot(gpa: std.mem.Allocator, variant: layout.Variant, trace_log_size: u32, log_blowup_factor: u32) ![8]u32 {
    var document = try fixture.load(gpa, topology_path, 1 << 20);
    defer document.deinit();
    const body = try fixture.checkpointBody(document.root(), "r6", "topology");
    for (try fixture.array(try fixture.field(body, "cairo_preprocessed_roots"))) |entry| {
        if (!std.mem.eql(u8, try fixture.string(try fixture.field(entry, "preprocessed_trace")), @tagName(variant))) continue;
        if (try fixture.unsigned(u32, try fixture.field(entry, "log_blowup_factor")) != log_blowup_factor) continue;
        if (try fixture.unsigned(u32, try fixture.field(entry, "trace_log_size")) != trace_log_size) continue;
        try std.testing.expectEqual(trace_log_size + log_blowup_factor, try fixture.unsigned(u32, try fixture.field(entry, "lifting_log_size")));
        var words: [8]u32 = undefined;
        for (&words, try fixture.array(try fixture.field(entry, "preprocessed_root"))) |*word, value| word.* = try fixture.unsigned(u32, value);
        return words;
    }
    return error.MissingCairoRoot;
}

test "R6 leaf: the rebuilt canonical_small leaf verifier reproduces the registry's preprocessed root and circuit hash" {
    const gpa = std.testing.allocator;

    const registry_text = try std.fs.cwd().readFileAlloc(gpa, registry_path, 1 << 20);
    defer gpa.free(registry_text);
    var owned = try registry_codec.parseRegistry(gpa, registry_text);
    defer owned.deinit();
    const registry = owned.registry;
    const cairo_params = registry.cairo_prover_params;
    const variant = std.meta.stringToEnum(layout.Variant, @tagName(cairo_params.preprocessed_trace)) orelse return error.UnknownVariant;
    try std.testing.expectEqual(layout.Variant.canonical_small, variant);

    try std.testing.expectEqual(@as(usize, 1), registry.leaf_verifiers.len);
    const leaf = registry.leaf_verifiers[0];
    try std.testing.expectEqual(@as(u32, 20), leaf.trace_log_size);
    const circuit_config = try registry.config(leaf.config);
    const circuit_fri = circuit_config.fri_config;

    const cairo_root = try committedCairoRoot(gpa, variant, leaf.trace_log_size, cairo_params.fri_config.log_blowup_factor);

    const projection_bytes = try std.fs.cwd().readFileAlloc(gpa, projection_path, 8 << 20);
    defer gpa.free(projection_bytes);
    var projection = try circuit.air_eval.projection.parse(gpa, projection_bytes);
    defer projection.deinit();
    var table = try circuit.air_eval.cairo_components.build(gpa, &projection);
    defer table.deinit();

    const program_json = try std.fs.cwd().readFileAlloc(gpa, program_path, 8 << 20);
    defer gpa.free(program_json);
    const program = try cairo.statement.circuit_leaf.programFeltsFromCompiledJson(gpa, program_json);
    defer gpa.free(program);

    // `leaf_verifier_config`, completed with the program, root and blinding.
    var leaf_config = try cairo_leaf_config.leafVerifierConfig(gpa, &table, variant, cairo_params.fri_config, leaf.trace_log_size);
    defer leaf_config.deinit(gpa);
    try std.testing.expectEqual(@as(usize, 79), leaf_config.n_enabled_components);
    const zk_blinding_amount: ?usize = if (leaf.zk_blinding) @as(usize, circuit_fri.n_queries) + cairo_verifier.NON_QUERY_INFO_LEAK else null;
    const config = leaf_config.verifierConfig(program, cairo_root, zk_blinding_amount);

    const relation_ids = cairo.air.claims.relation_ids;
    const constants: circuit.statements.cairo_statement.Constants = .{
        .opcodes_relation_id = relation_ids.OPCODES.v,
        .memory_address_to_id_relation_id = relation_ids.MEMORY_ADDRESS_TO_ID.v,
        .memory_id_to_big_relation_id = relation_ids.MEMORY_ID_TO_BIG.v,
        .memory = table.constants,
    };

    // `padded_preprocessed_circuit` at the registry's shared target.
    const target = ComponentSizes.fromLogSizes(circuit_config.component_log_sizes);
    var pp = blk: {
        var ctx = try cairo_verifier.buildCairoVerifierTopology(gpa, &table, &config, constants, circuit.stark_verifier.verify.NoStages{});
        defer ctx.deinit();
        const unpadded = finalize.computePaddedSizes(&ctx.circuit);
        try std.testing.expectEqual(target, target.elementwiseMax(unpadded));
        try finalize.padToTargets(builder.NoValue, &ctx, target);
        break :blk try preprocessed.PreprocessedCircuit.fromBuilderCircuit(gpa, &ctx.circuit);
    };
    defer pp.deinit(gpa);

    // Every registry circuit shares the target's preprocessed layout.
    const pp_layout = pp.layout();
    const shared_layout = try preprocessed.ColumnLayout.fromComponentSizes(target);
    try std.testing.expect(pp_layout.eql(&shared_layout));

    const root = try pp.preprocessedRoot(gpa, circuit_fri.log_blowup_factor);
    const log_sizes = try circuit_statement.circuitComponentLogSizes(&pp_layout);
    const hash = try circuit_hash.hostCircuitHash(log_sizes, circuit_fri.log_blowup_factor, root);
    try std.testing.expectEqual(leaf.preprocessed_root.words, circuit_hash.leU32sFromBytes(8, &root));
    try std.testing.expectEqual(leaf.circuit_hash.words, circuit_hash.leU32sFromBytes(8, &hash));
}
