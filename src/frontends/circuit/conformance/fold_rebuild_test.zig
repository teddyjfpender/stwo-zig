//! Rung R6, fold (design §8.2): each checked-in registry's multiverifier,
//! rebuilt in Zig, against the registry and the oracle's `topology`
//! checkpoint (`vectors/circuit/r6/topology.json`).
//!
//! As `circuit_params::shared_target_fixpoint` and
//! `padded_preprocessed_circuit` do (https://github.com/starkware-libs/proving
//! at 5a7c5ede4299c91a61df19a07cba4f7502c14230): the verified proofs have
//! the layout of the registry's padding target, the multiverifier over two
//! of them is built in topology mode, must fit the target (a fixpoint),
//! is padded to it and preprocessed. Its 45-column layout, component log
//! sizes, preprocessed root (committed at blowup 1) and circuit hash must
//! equal the registry's and the oracle's.

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("circuit_frontend");
const testing = @import("circuit_testing");

const builder = circuit.builder;
const fixture = testing.fixture_json;
const fold_registry = testing.fold_registry;
const verifier_stages = testing.verifier_stages;
const finalize = circuit.common.finalize;
const preprocessed = circuit.common.preprocessed;
const circuit_hash = circuit.common.circuit_hash;
const component_list = circuit.common.component_list;
const multiverifier = circuit.statements.multiverifier;
const circuit_statement = circuit.statements.circuit_statement;
const ComponentSizes = finalize.ComponentSizes;
const Value = std.json.Value;

const topology_path = "vectors/circuit/r6/topology.json";

/// The checkpoint's upstream registry paths and their committed copies.
const registries = [_]struct { upstream: []const u8, local: []const u8 }{
    .{
        .upstream = "crates/stwo_run_and_prove_recursive_tree/test_data/circuit_registry.json",
        .local = "vectors/circuit/official/registries/recursive_tree_test.json",
    },
    .{
        .upstream = "crates/leaf_prover/tests/data/circuit_registry_canonical_small.json",
        .local = "vectors/circuit/official/registries/leaf_prover_canonical_small.json",
    },
};

test "R6 fold: rebuilt multiverifiers reproduce the registries' preprocessed roots and circuit hashes" {
    const gpa = std.testing.allocator;
    var document = try fixture.load(gpa, topology_path, 1 << 20);
    defer document.deinit();
    const body = try fixture.checkpointBody(document.root(), "r6", "topology");

    const privacy_layout = try preprocessed.ColumnLayout.fromComponentSizes(verifier_stages.privacy_target_sizes);
    try expectLayout(try fixture.field(body, "privacy_multiverifier_layout"), &privacy_layout);

    const projection_bytes = try std.fs.cwd().readFileAlloc(gpa, verifier_stages.projection_path, 8 << 20);
    defer gpa.free(projection_bytes);
    var projection = try circuit.air_eval.projection.parse(gpa, projection_bytes);
    defer projection.deinit();
    var table = try circuit.air_eval.circuit_components.build(gpa, &projection);
    defer table.deinit();

    const folds = try fixture.array(try fixture.field(body, "folds"));
    try std.testing.expectEqual(registries.len, folds.len);
    for (registries, folds) |registry, fold| {
        try std.testing.expectEqualStrings(registry.upstream, try fixture.string(try fixture.field(fold, "registry")));
        try checkFold(gpa, &table, registry.local, fold);
    }
}

fn checkFold(gpa: std.mem.Allocator, table: *const circuit.air_eval.component_table.Table, registry_path: []const u8, fold: Value) !void {
    const parsed = try fold_registry.load(gpa, registry_path);
    defer parsed.deinit();
    try std.testing.expectEqual(@as(usize, 1), parsed.value.multiverifiers.len);
    const entry = parsed.value.multiverifiers[0];
    const config = parsed.value.circuit_proof_configs.map.get(entry.config) orelse return error.MissingConfig;
    const fri = try config.fri_config.toFriConfig();
    try expectFields(try fixture.field(fold, "fri_config"), fri);
    try expectFields(try fixture.field(fold, "target_log_sizes"), config.component_log_sizes);

    // `shared_target_fixpoint` at the converged target.
    const target = ComponentSizes.fromLogSizes(config.component_log_sizes);
    var shared = try multiverifier.foldSharedConfig(gpa, target, fri);
    defer shared.deinit(gpa);
    try std.testing.expectEqual(try fixture.unsigned(u32, try fixture.field(fold, "trace_log_size")), shared.preprocessed_column_log_sizes.traceLogSize());
    try expectLayout(try fixture.field(fold, "layout"), &shared.preprocessed_column_log_sizes);

    var pp = try paddedPreprocessedCircuit(gpa, table, &shared, target, try fixture.field(fold, "unpadded_log_sizes"));
    defer pp.deinit(gpa);
    const layout = pp.layout();
    try std.testing.expect(layout.eql(&shared.preprocessed_column_log_sizes));

    const log_sizes = try circuit_statement.circuitComponentLogSizes(&layout);
    const expected_log_sizes = try fixture.array(try fixture.field(fold, "component_log_sizes"));
    try std.testing.expectEqual(component_list.N_COMPONENTS, expected_log_sizes.len);
    for (expected_log_sizes, component_list.COMPONENT_NAMES, log_sizes.toArray()) |pair, name, log_size| {
        const items = try fixture.array(pair);
        try std.testing.expectEqualStrings(name, try fixture.string(items[0]));
        try std.testing.expectEqual(try fixture.unsigned(u32, items[1]), log_size);
    }

    const root = try pp.preprocessedRoot(gpa, fri.log_blowup_factor);
    const hash = try circuit_hash.hostCircuitHash(log_sizes, fri.log_blowup_factor, root);
    try std.testing.expectEqualSlices(u8, &try fold_registry.parseDigest(entry.preprocessed_root), &root);
    try std.testing.expectEqualSlices(u8, &try fold_registry.parseDigest(entry.circuit_hash), &hash);
    try std.testing.expectEqual(try verifier_stages.words8(try fixture.field(fold, "preprocessed_root")), circuit_hash.leU32sFromBytes(8, &root));
    try std.testing.expectEqual(try verifier_stages.words8(try fixture.field(fold, "circuit_hash")), circuit_hash.leU32sFromBytes(8, &hash));
}

/// `padded_preprocessed_circuit`: the multiverifier topology, checked to
/// fit `target`, padded to it and preprocessed. The circuit is freed before
/// the caller commits the preprocessed trace.
fn paddedPreprocessedCircuit(
    gpa: std.mem.Allocator,
    table: *const circuit.air_eval.component_table.Table,
    shared: *const multiverifier.SharedConfig,
    target: ComponentSizes,
    expected_unpadded: Value,
) !preprocessed.PreprocessedCircuit {
    var ctx = try multiverifier.buildMultiverifierTopology(gpa, table, shared, circuit.stark_verifier.verify.NoStages{});
    defer ctx.deinit();
    const unpadded = finalize.computePaddedSizes(&ctx.circuit);
    try std.testing.expectEqual(target, target.elementwiseMax(unpadded));
    try expectFields(expected_unpadded, unpadded.map(log2));
    try finalize.padToTargets(builder.NoValue, &ctx, target);
    return preprocessed.PreprocessedCircuit.fromBuilderCircuit(gpa, &ctx.circuit);
}

fn log2(n: usize) usize {
    return std.math.log2_int(usize, n);
}

fn expectLayout(expected: Value, layout: *const preprocessed.ColumnLayout) !void {
    const entries = try fixture.array(expected);
    try std.testing.expectEqual(layout.entries.len, entries.len);
    for (entries, layout.entries) |want, got| {
        try std.testing.expectEqualStrings(try fixture.string(try fixture.field(want, "id")), got.id);
        try std.testing.expectEqual(try fixture.unsigned(u32, try fixture.field(want, "log_size")), got.log_size);
    }
}

/// Compares the fixture object's integer fields with `actual`'s fields of
/// the same names.
fn expectFields(expected: Value, actual: anytype) !void {
    inline for (std.meta.fields(@TypeOf(actual))) |field| {
        try std.testing.expectEqual(try fixture.unsigned(u64, try fixture.field(expected, field.name)), @as(u64, @field(actual, field.name)));
    }
}
