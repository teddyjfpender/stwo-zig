//! Rung R9 (design §8.2, milestone M9): the Zig recursive tree against
//! `stwo_run_and_prove_recursive_tree` of https://github.com/starkware-libs/proving
//! at 5a7c5ede4299c91a61df19a07cba4f7502c14230, as raw bytes.
//!
//! Every tree folds copies of the upstream golden leaf
//! (`test_data/goldens/four_leaves/leaf.json`, a canonical_small
//! `leaf_prover` output) under the recursive-tree test registry
//! (`test_data/circuit_registry.json`), as upstream's `dupe_and_fold` does:
//!
//! - four leaves: `root.proof`, `root_outputs.json` and `root_packed.json`
//!   must equal the committed upstream goldens byte for byte;
//! - one, two, three and five leaves (a self-fold, one pair, a carry, a
//!   carry over two layers): the same three files must equal the oracle's
//!   `fold-tree` checkpoint (`vectors/circuit/r9/fold_tree.json`), which ran
//!   upstream's tree function on the same leaves: `root_outputs.json` and
//!   `root_packed.json` verbatim, `root.proof` by length and SHA-256.
//!
//! Labelled large: every reduction proves a 2^23-row multiverifier (about
//! 20 s and several GB each); `-Dtest-filter` selects one tree.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const circuit_cpu = @import("stwo_circuit_cpu_integration");
const wire = @import("stwo_circuit_recursion_wire");
const testing = @import("circuit_testing");

const recursion = circuit_cpu.recursion;
const fixture = testing.fixture_json;

const registry_path = "vectors/circuit/official/registries/recursive_tree_test.json";
const leaf_path = "vectors/circuit/official/recursive_tree/four_leaves/leaf.json";
const goldens_dir = "vectors/circuit/official/recursive_tree/four_leaves";
const checkpoint_path = "vectors/circuit/r9/fold_tree.json";
const projection_path = "vectors/circuit/official/compiled_air_constraints_v1.bin";

/// The tree's shared inputs: registry, evaluators, AIR bundle, canonical
/// circuit and the golden leaf.
const Setup = struct {
    arena: std.heap.ArenaAllocator,
    registry: wire.registry.OwnedRegistry,
    projection: circuit.air_eval.projection.Projection,
    table: circuit.air_eval.component_table.Table,
    bundle: circuit_cpu.air.Bundle,
    canonical: recursion.CanonicalCircuit,
    leaf: wire.leaf_proof_json.Owned(wire.leaf_proof_json.LeafInput),

    fn init(self: *Setup, gpa: std.mem.Allocator) !void {
        self.arena = .init(gpa);
        errdefer self.arena.deinit();
        const a = self.arena.allocator();
        self.registry = try wire.registry.parseRegistry(gpa, try std.fs.cwd().readFileAlloc(a, registry_path, 1 << 20));
        errdefer self.registry.deinit();
        self.projection = try circuit.air_eval.projection.parse(gpa, try std.fs.cwd().readFileAlloc(a, projection_path, 8 << 20));
        errdefer self.projection.deinit();
        self.table = try circuit.air_eval.circuit_components.build(gpa, &self.projection);
        errdefer self.table.deinit();
        const bundle_bytes = try std.fs.cwd().readFileAlloc(a, circuit_cpu.air.bundle_path, 1 << 20);
        try std.testing.expectEqualStrings(circuit_cpu.air.bundle_sha256, &sha256Hex(bundle_bytes));
        self.bundle = try circuit_cpu.air.parse(gpa, bundle_bytes);
        errdefer self.bundle.deinit();
        self.canonical = try recursion.CanonicalCircuit.build(gpa, &self.table, self.registry.registry);
        errdefer self.canonical.deinit(gpa);
        self.leaf = try wire.leaf_proof_json.parseLeafInput(gpa, try std.fs.cwd().readFileAlloc(a, leaf_path, 8 << 20));
    }

    fn deinit(self: *Setup, gpa: std.mem.Allocator) void {
        self.leaf.deinit();
        self.canonical.deinit(gpa);
        self.bundle.deinit();
        self.table.deinit();
        self.projection.deinit();
        self.registry.deinit();
        self.arena.deinit();
    }
};

const Outputs = struct {
    proof: std.Io.Writer.Allocating,
    outputs: std.Io.Writer.Allocating,
    packed_tree: std.Io.Writer.Allocating,
    stats: recursion.Stats,

    fn deinit(self: *Outputs) void {
        self.proof.deinit();
        self.outputs.deinit();
        self.packed_tree.deinit();
    }
};

/// `dupe_and_fold`: folds `n` copies of the golden leaf, on a proof-scoped
/// worker pool (`STWO_ZIG_WORKERS` sizes it).
fn foldCopies(gpa: std.mem.Allocator, setup: *const Setup, n: usize) !Outputs {
    std.testing.log_level = .info;
    var pool: prover.work_pool.WorkPool = undefined;
    try pool.initInPlace();
    defer pool.deinit();
    var binding = try prover.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();

    var packed_arena = std.heap.ArenaAllocator.init(gpa);
    defer packed_arena.deinit();
    const fold: recursion.Fold = .{
        .canonical = &setup.canonical,
        .table = &setup.table,
        .bundle = &setup.bundle,
        .options = .{ .compact_polynomial_min_log = 18 },
        .packed_allocator = packed_arena.allocator(),
    };
    const leaves = try gpa.alloc(wire.leaf_proof_json.LeafInput, n);
    defer gpa.free(leaves);
    @memset(leaves, setup.leaf.value);
    var folded = try recursion.tree.foldLeaves(gpa, &fold, leaves);
    defer folded.root.deinit();

    var out: Outputs = .{ .proof = .init(gpa), .outputs = .init(gpa), .packed_tree = .init(gpa), .stats = folded.stats };
    errdefer out.deinit();
    try recursion.tree.writeRootOutputs(&folded.root, &out.proof.writer, &out.outputs.writer, &out.packed_tree.writer);
    return out;
}

fn sha256Hex(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn expectBytes(label: []const u8, expected: []const u8, actual: []const u8) !void {
    if (std.mem.indexOfDiff(u8, expected, actual)) |offset| {
        std.debug.print("{s}: {d} bytes, expected {d}; first difference at byte {d}\n", .{ label, actual.len, expected.len, offset });
        return error.TestExpectedEqual;
    }
}

/// Upstream's layer and reduction counts for `n` leaves.
fn expectStats(n: usize, stats: recursion.Stats) !void {
    try std.testing.expectEqual(n, stats.n_leaves);
    const layers: usize = if (n == 1) 1 else std.math.log2_int_ceil(usize, n);
    try std.testing.expectEqual(layers, stats.n_layers);
    try std.testing.expectEqual(if (n == 1) 1 else n - 1, stats.n_pair_reductions);
}

test "R9: four leaves reproduce the upstream goldens byte for byte" {
    const gpa = std.heap.smp_allocator;
    var setup: Setup = undefined;
    try setup.init(gpa);
    defer setup.deinit(gpa);

    var out = try foldCopies(gpa, &setup, 4);
    defer out.deinit();
    try expectStats(4, out.stats);
    inline for (.{ .{ "root.proof", "proof" }, .{ "root_outputs.json", "outputs" }, .{ "root_packed.json", "packed_tree" } }) |pair| {
        const expected = try std.fs.cwd().readFileAlloc(gpa, goldens_dir ++ "/" ++ pair[0], 8 << 20);
        defer gpa.free(expected);
        try expectBytes(pair[0], expected, @field(out, pair[1]).written());
    }
}

fn expectCheckpointTree(n: usize) !void {
    const gpa = std.heap.smp_allocator;
    var document = try fixture.load(gpa, checkpoint_path, 1 << 20);
    defer document.deinit();
    const body = try fixture.checkpointBody(document.root(), "r9", "fold-tree");
    const tree = for (try fixture.array(try fixture.field(body, "trees"))) |candidate| {
        if (try fixture.unsigned(usize, try fixture.field(candidate, "n_leaves")) == n) break candidate;
    } else return error.MissingTree;

    var setup: Setup = undefined;
    try setup.init(gpa);
    defer setup.deinit(gpa);
    var out = try foldCopies(gpa, &setup, n);
    defer out.deinit();

    try expectStats(n, out.stats);
    try std.testing.expectEqual(try fixture.unsigned(usize, try fixture.field(tree, "n_layers")), out.stats.n_layers);
    try std.testing.expectEqual(try fixture.unsigned(usize, try fixture.field(tree, "n_pair_reductions")), out.stats.n_pair_reductions);
    const proof_record = try fixture.field(tree, "root_proof");
    try std.testing.expectEqual(try fixture.unsigned(usize, try fixture.field(proof_record, "bytes")), out.proof.written().len);
    try std.testing.expectEqualStrings(try fixture.string(try fixture.field(proof_record, "sha256")), &sha256Hex(out.proof.written()));
    try expectBytes("root_outputs.json", try fixture.string(try fixture.field(tree, "root_outputs")), out.outputs.written());
    try expectBytes("root_packed.json", try fixture.string(try fixture.field(tree, "root_packed")), out.packed_tree.written());
}

test "R9: one leaf (root self-fold) matches upstream" {
    try expectCheckpointTree(1);
}

test "R9: two leaves match upstream" {
    try expectCheckpointTree(2);
}

test "R9: three leaves (carry) match upstream" {
    try expectCheckpointTree(3);
}

test "R9: five leaves (carry over two layers) match upstream" {
    try expectCheckpointTree(5);
}
