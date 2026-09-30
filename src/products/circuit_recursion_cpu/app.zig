//! The circuit recursion CPU product: the recursive tree and registry
//! generation of https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230, byte for byte (design §7.4,
//! milestone M9).
//!
//! The circuit AIR's compiled-constraint projection and recorded evaluation
//! programs are embedded at build time and authenticated by SHA-256 before
//! use, so the binary needs no data files besides its inputs.

const std = @import("std");
const cairo = @import("stwo_cairo_frontend");
const circuit = @import("stwo_circuit_frontend");
const circuit_cpu = @import("stwo_circuit_cpu_integration");
const wire = @import("stwo_circuit_recursion_wire");
const cli = @import("cli.zig");

const recursion = circuit_cpu.recursion;

const projection_bytes = @embedFile("circuit_air_projection");
const air_programs_bytes = @embedFile("circuit_air_programs");
/// SHA-256 of `vectors/circuit/official/compiled_air_constraints_v1.bin`
/// (`vectors/circuit/provenance.json`).
const projection_sha256 = "ceea3c293a4fcd3ca8a20ba62f4845732f8725bdf610fe6367c83adcb8be7e09";

/// Largest JSON input read (a leaf file is about 0.7 MB, a compiled
/// program 1.6 MB).
const max_input_bytes = 64 << 20;

pub fn main() !void {
    const gpa = std.heap.smp_allocator;
    const argv = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, argv);
    var stderr_buffer: [4096]u8 = undefined;
    var stderr = std.fs.File.stderr().writer(&stderr_buffer);
    const parsed = cli.parse(argv[1..]) catch |err| {
        try stderr.interface.print("error: {s}\n{s}", .{ @errorName(err), cli.usage });
        try stderr.interface.flush();
        std.process.exit(2);
    };
    run(gpa, parsed) catch |err| {
        try stderr.interface.print("error: {s}\n", .{@errorName(err)});
        try stderr.interface.flush();
        std.process.exit(1);
    };
}

fn run(gpa: std.mem.Allocator, parsed: cli.Parsed) !void {
    switch (parsed) {
        .help => try std.fs.File.stdout().writeAll(cli.usage),
        .fold_tree => |command| try foldTree(gpa, command),
        .circuit_params => |command| try circuitParams(gpa, command),
    }
}

/// The circuit AIR's evaluator tables and recorded programs, authenticated.
const Air = struct {
    projection: circuit.air_eval.projection.Projection,
    circuit_table: circuit.air_eval.component_table.Table,

    /// Initializes in place: the tables borrow the projection.
    fn init(self: *Air, gpa: std.mem.Allocator) !void {
        try authenticate(projection_bytes, projection_sha256);
        self.projection = try circuit.air_eval.projection.parse(gpa, projection_bytes);
        errdefer self.projection.deinit();
        self.circuit_table = try circuit.air_eval.circuit_components.build(gpa, &self.projection);
    }

    fn deinit(self: *Air) void {
        self.circuit_table.deinit();
        self.projection.deinit();
    }
};

fn authenticate(bytes: []const u8, comptime expected: *const [64]u8) !void {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), expected)) return error.EmbeddedAssetDigestMismatch;
}

fn readFile(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.fs.cwd().readFileAlloc(allocator, path, max_input_bytes);
}

fn writeFile(path: []const u8, bytes: []const u8) !void {
    try std.fs.cwd().writeFile(.{ .sub_path = path, .data = bytes });
}

/// `stwo_run_and_prove_recursive_tree`: loads the leaves and the registry,
/// builds the canonical multiverifier (checked against the registry), folds
/// and writes the three root files.
fn foldTree(gpa: std.mem.Allocator, command: cli.FoldTree) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // `load_leaves`: the manifest, then every leaf file in order.
    const manifest = try wire.leaf_proof_json.parseLeavesManifest(arena, try readFile(arena, command.program_input));
    const leaves = try arena.alloc(wire.leaf_proof_json.LeafInput, manifest.value.len);
    for (leaves, manifest.value) |*leaf, path| {
        leaf.* = (try wire.leaf_proof_json.parseLeafInput(arena, try readFile(arena, path))).value;
    }
    const registry = try wire.registry.parseRegistry(arena, try readFile(arena, command.circuit_registry_json));
    if (leaves.len == 0) return error.EmptyLeaves;

    var air: Air = undefined;
    try air.init(gpa);
    defer air.deinit();
    try authenticate(air_programs_bytes, circuit_cpu.air.bundle_sha256);
    var bundle = try circuit_cpu.air.parse(gpa, air_programs_bytes);
    defer bundle.deinit();
    var canonical = try recursion.CanonicalCircuit.build(gpa, &air.circuit_table, registry.registry);
    defer canonical.deinit(gpa);

    const fold: recursion.Fold = .{
        .canonical = &canonical,
        .table = &air.circuit_table,
        .bundle = &bundle,
        .options = .{ .compact_polynomial_min_log = 18 },
        .packed_allocator = arena,
    };
    var folded = try recursion.tree.foldLeaves(gpa, &fold, leaves);
    defer folded.root.deinit();

    var proof: std.Io.Writer.Allocating = .init(gpa);
    defer proof.deinit();
    var outputs: std.Io.Writer.Allocating = .init(gpa);
    defer outputs.deinit();
    var packed_tree: std.Io.Writer.Allocating = .init(gpa);
    defer packed_tree.deinit();
    try recursion.tree.writeRootOutputs(&folded.root, &proof.writer, &outputs.writer, &packed_tree.writer);
    try writeFile(command.proof_path, proof.written());
    try writeFile(command.program_output, outputs.written());
    try writeFile(command.packed_output_path, packed_tree.written());
    std.log.info("recursive tree: {d} leaves, {d} layers, {d} reductions", .{
        folded.stats.n_leaves,
        folded.stats.n_layers,
        folded.stats.n_pair_reductions,
    });
}

/// `circuit-params --registry`: the definition's files are read relative to
/// the working directory, as upstream reads them.
fn circuitParams(gpa: std.mem.Allocator, command: cli.CircuitParams) !void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const definition = (try wire.registry_definition.parseRegistryDefinition(arena, try readFile(arena, command.definition))).definition;
    const inputs: recursion.circuit_params.Inputs = .{
        .definition = definition,
        .cairo_params = try wire.registry.parseProverParameters(arena, try readFile(arena, definition.cairo_prover_params_json)),
        .circuit_fri_config = try wire.registry.parseFriConfig(arena, try readFile(arena, definition.circuit_fri_config_json)),
        .program = try cairo.statement.circuit_leaf.programFeltsFromCompiledJson(arena, try readFile(arena, definition.program)),
    };

    var air: Air = undefined;
    try air.init(gpa);
    defer air.deinit();
    var cairo_table = try circuit.air_eval.cairo_components.build(gpa, &air.projection);
    defer cairo_table.deinit();
    var generated = try recursion.circuit_params.generate(gpa, .{ .cairo = &cairo_table, .circuit = &air.circuit_table }, inputs);
    defer generated.deinit();

    var out: std.Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    try generated.write(&out.writer);
    if (command.output_path) |path| {
        try writeFile(path, out.written());
    } else {
        try std.fs.File.stdout().writeAll(out.written());
    }
}

test "circuit recursion app: the embedded assets are the authenticated ones" {
    try authenticate(projection_bytes, projection_sha256);
    try authenticate(air_programs_bytes, circuit_cpu.air.bundle_sha256);
}

test {
    _ = cli;
}
