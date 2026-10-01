//! Registry generation (design §7.3): `circuit-params
//! --registry` of https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230, byte for byte.
//!
//! For both canonical_small test definitions, the Zig generator must write
//! the registry upstream commits beside them, including the trailing
//! newline. Those committed registries are the release `circuit-params`
//! binary's exact output for the same definitions (checked when the fixtures
//! were copied; upstream's own slow test compares them as JSON only).
//!
//! The definitions name their inputs by paths in the `proving` checkout;
//! each maps to its committed copy under `vectors/circuit/official`.
//! Labelled large: every definition builds a 2^23-row leaf verifier twice and
//! the multiverifier, and commits a canonical_small Cairo preprocessed trace.

const std = @import("std");
const cairo = @import("stwo_cairo_frontend");
const circuit = @import("stwo_circuit_frontend");
const circuit_cpu = @import("stwo_circuit_cpu_integration");
const wire = @import("stwo_circuit_recursion_wire");

const circuit_params = circuit_cpu.recursion.circuit_params;

const projection_path = "vectors/circuit/official/compiled_air_constraints_v1.bin";

/// A definition, its inputs' upstream paths and their committed copies.
const Case = struct {
    definition: []const u8,
    cairo_prover_params: [2][]const u8,
    circuit_fri_config: [2][]const u8,
    program: [2][]const u8,
    registry: []const u8,
};

const official = "vectors/circuit/official/";

const recursive_tree: Case = .{
    .definition = official ++ "registry_definitions/canonical_small/definition.json",
    .cairo_prover_params = .{ "crates/stwo_run_and_prove_recursive_tree/test_data/cairo_prover_params.json", official ++ "registry_definitions/canonical_small/cairo_prover_params.json" },
    .circuit_fri_config = .{ "crates/stwo_run_and_prove_recursive_tree/test_data/circuit_fri_config.json", official ++ "registry_definitions/canonical_small/circuit_fri_config.json" },
    .program = .{ "crates/stwo_run_and_prove_recursive_tree/test_data/leaf_simple_bootloader_compiled.json", official ++ "programs/leaf_simple_bootloader_compiled.json" },
    .registry = official ++ "registries/recursive_tree_test.json",
};

const leaf_prover: Case = .{
    .definition = official ++ "registry_definitions/leaf_prover_canonical_small/definition.json",
    .cairo_prover_params = .{ "crates/leaf_prover/tests/data/cairo_prover_params_canonical_small.json", official ++ "registry_definitions/leaf_prover_canonical_small/cairo_prover_params.json" },
    .circuit_fri_config = .{ "crates/leaf_prover/tests/data/circuit_fri_config_canonical_small.json", official ++ "registry_definitions/leaf_prover_canonical_small/circuit_fri_config.json" },
    .program = .{ "crates/leaf_prover/tests/data/use_all_opcodes_and_builtins_compiled.json", official ++ "programs/use_all_opcodes_and_builtins_compiled.json" },
    .registry = official ++ "registries/leaf_prover_canonical_small.json",
};

fn read(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.fs.cwd().readFileAlloc(allocator, path, 16 << 20);
}

/// The committed copy of the file the definition names.
fn copyOf(named: []const u8, pair: [2][]const u8) ![]const u8 {
    if (!std.mem.eql(u8, named, pair[0])) {
        std.debug.print("the definition names {s}, expected {s}\n", .{ named, pair[0] });
        return error.UnexpectedDefinitionPath;
    }
    return pair[1];
}

fn expectGenerated(case: Case) !void {
    const gpa = std.heap.smp_allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const a = arena_state.allocator();

    var definition = try wire.registry_definition.parseRegistryDefinition(gpa, try read(a, case.definition));
    defer definition.deinit();
    const d = definition.definition;
    const inputs: circuit_params.Inputs = .{
        .definition = d,
        .cairo_params = try wire.registry.parseProverParameters(a, try read(a, try copyOf(d.cairo_prover_params_json, case.cairo_prover_params))),
        .circuit_fri_config = try wire.registry.parseFriConfig(a, try read(a, try copyOf(d.circuit_fri_config_json, case.circuit_fri_config))),
        .program = try cairo.statement.circuit_leaf.programFeltsFromCompiledJson(a, try read(a, try copyOf(d.program, case.program))),
    };

    var projection = try circuit.air_eval.projection.parse(gpa, try read(a, projection_path));
    defer projection.deinit();
    var cairo_table = try circuit.air_eval.cairo_components.build(gpa, &projection);
    defer cairo_table.deinit();
    var circuit_table = try circuit.air_eval.circuit_components.build(gpa, &projection);
    defer circuit_table.deinit();

    var generated = try circuit_params.generate(gpa, .{ .cairo = &cairo_table, .circuit = &circuit_table }, inputs);
    defer generated.deinit();
    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try generated.write(&out.writer);

    const expected = try read(a, case.registry);
    if (!std.mem.eql(u8, expected, out.written())) {
        std.debug.print("generated registry differs from {s}:\n{s}\n", .{ case.registry, out.written() });
        return error.TestExpectedEqual;
    }
}

test "R11 registry: the recursive-tree canonical_small definition generates its registry byte for byte" {
    try expectGenerated(recursive_tree);
}

test "R11 registry: the leaf-prover canonical_small definition generates its registry byte for byte" {
    try expectGenerated(leaf_prover);
}
