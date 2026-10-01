//! A root circuit proof in the Cairo circuit verifier's format.
//!
//! Ports `prepare_circuit_proof_for_cairo_verifier` and
//! `CairoStarkProof::from_stark_proof` (`crates/circuit_cairo_serialize/src/proof.rs`)
//! and `column_log_sizes_per_tree` (`crates/circuit_verifier/src/circuit_claim.rs`)
//! of https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230. The result is the wire
//! package's `CairoCircuitProof`, whose `writeJson` is the recursive tree's
//! `root.proof`. Only the proof goes on the wire: the verifier-config
//! constants (output addresses, preprocessed root, lifting heights) are baked
//! into the Cairo verifier binary.

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const wire = @import("stwo_circuit_recursion_wire");
const felt_stream = wire.circuit_felt_stream;

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Hash = wire.cairo_serialize.Blake2sHash;

const component_list = circuit.common.component_list;
const PerComponent = component_list.PerComponent;

pub const Error = error{
    /// The proof does not have the four circuit trees.
    InvalidCircuitProof,
} || wire.cairo_serialize.TransposeError;

/// A converted proof; its slices live in `arena`.
pub const CairoVerifierProof = struct {
    arena: std.heap.ArenaAllocator,
    proof: felt_stream.CairoCircuitProof,

    pub fn deinit(self: *CairoVerifierProof) void {
        self.arena.deinit();
        self.* = undefined;
    }

    /// `serde_json::to_vec_pretty` of the `0x`-hex felts: the root proof
    /// file, without a trailing newline.
    pub fn writeJson(self: *const CairoVerifierProof, out: *std.Io.Writer) !void {
        try felt_stream.writeJson(out, &self.proof);
    }
};

/// Per-column log sizes of the trace and interaction trees
/// (`column_log_sizes_per_tree`): each component's columns at its log size,
/// in `ComponentList` order.
pub fn columnLogSizesPerTree(
    allocator: std.mem.Allocator,
    log_sizes: PerComponent(u32),
) std.mem.Allocator.Error![2][]u32 {
    var trace: std.ArrayList(u32) = .empty;
    errdefer trace.deinit(allocator);
    var interaction: std.ArrayList(u32) = .empty;
    errdefer interaction.deinit(allocator);
    for (component_list.component_facts.toArray(), log_sizes.toArray()) |facts, log_size| {
        try trace.appendNTimes(allocator, log_size, facts.trace_columns);
        try interaction.appendNTimes(allocator, log_size, facts.interaction_columns);
    }
    const trace_slice = try trace.toOwnedSlice(allocator);
    errdefer allocator.free(trace_slice);
    return .{ trace_slice, try interaction.toOwnedSlice(allocator) };
}

/// `prepare_circuit_proof_for_cairo_verifier`: `proof` is a `CircuitProof`
/// of `prove.Prover(MC)` whose Merkle hasher is the plain Blake2s one (the
/// root profile). The result copies what it needs; `proof` is unchanged.
pub fn prepare(allocator: std.mem.Allocator, proof: anytype) Error!CairoVerifierProof {
    return fromVerifiedStark(allocator, &proof.stark_proof.proof, proof.component_log_sizes, proof.output_values, &proof.claimed_sums.toArray(), proof.interaction_pow_nonce, proof.channel_salt, proof.pcs_config.fri_config);
}

/// Build the Cairo root stream from an independently verified compressed
/// STARK. The CUDA resident prover has no CPU prover auxiliary tree, and this
/// wire format needs only the published proof and its public claims.
pub fn fromVerifiedStark(
    allocator: std.mem.Allocator,
    proof: anytype,
    log_sizes: PerComponent(u32),
    output_values: []const QM31,
    claimed_sums: []const QM31,
    interaction_pow_nonce: u64,
    channel_salt: u32,
    fri_config: core.pcs.config_v2.FriConfigV2,
) Error!CairoVerifierProof {
    const stark = &proof.commitment_scheme_proof;
    const n_trees = felt_stream.n_trees;
    if (stark.commitments.items.len != n_trees or stark.sampled_values.items.len != n_trees or
        stark.decommitments.items.len != n_trees or stark.queried_values.items.len != n_trees or
        claimed_sums.len != component_list.N_COMPONENTS)
        return error.InvalidCircuitProof;

    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();

    // `CairoStarkProof::from_stark_proof`: the trace and interaction trees
    // are stably sorted by column log size, then every tree is transposed.
    const tree_logs = try columnLogSizesPerTree(a, log_sizes);
    var tree_values: [n_trees][]const []const M31 = undefined;
    for (&tree_values, stark.queried_values.items) |*out, tree| out.* = tree;
    const sorted = try wire.cairo_serialize.sortAndTransposeQueriedValues(a, tree_values, tree_logs[0], tree_logs[1]);
    const queried_values = try a.dupe([]M31, &sorted);

    const decommitments = try a.alloc([]Hash, n_trees);
    for (decommitments, stark.decommitments.items) |*out, decommitment| out.* = try a.dupe(Hash, decommitment.hash_witness);
    const sampled_values = try a.alloc([][]QM31, n_trees);
    for (sampled_values, stark.sampled_values.items) |*tree_out, tree| {
        tree_out.* = try a.alloc([]QM31, tree.len);
        for (tree_out.*, tree) |*column_out, column| column_out.* = try a.dupe(QM31, column);
    }

    const fri = &stark.fri_proof;
    const inner_layers = try a.alloc(felt_stream.FriLayerProof, fri.inner_layers.len);
    for (inner_layers, fri.inner_layers) |*out, *layer| out.* = try friLayer(a, layer);

    return .{ .arena = arena, .proof = .{
        .output_values = try a.dupe(QM31, output_values),
        .interaction_pow = interaction_pow_nonce,
        .claimed_sums = claimed_sums[0..component_list.N_COMPONENTS].*,
        .stark_proof = .{
            .fri_config = fri_config,
            .commitments = try a.dupe(Hash, stark.commitments.items),
            .sampled_values = sampled_values,
            .decommitments = decommitments,
            .queried_values = queried_values,
            .proof_of_work = stark.proof_of_work,
            .fri_proof = .{
                .first_layer = try friLayer(a, &fri.first_layer),
                .inner_layers = inner_layers,
                .last_layer_poly = try a.dupe(QM31, fri.last_layer_poly.coeffs),
            },
        },
        .channel_salt = channel_salt,
    } };
}

fn friLayer(a: std.mem.Allocator, layer: anytype) std.mem.Allocator.Error!felt_stream.FriLayerProof {
    return .{
        .fri_witness = try a.dupe(QM31, layer.fri_witness),
        .decommitment = try a.dupe(Hash, layer.decommitment.hash_witness),
        .commitment = layer.commitment,
    };
}

test "cairo verifier proof: column log sizes repeat each component's size per column" {
    const allocator = std.testing.allocator;
    var log_sizes: PerComponent(u32) = undefined;
    inline for (std.meta.fields(PerComponent(u32)), 0..) |field, index| @field(log_sizes, field.name) = @intCast(10 + index);
    const trees = try columnLogSizesPerTree(allocator, log_sizes);
    defer for (trees) |tree| allocator.free(tree);
    var n_trace: usize = 0;
    var n_interaction: usize = 0;
    for (component_list.component_facts.toArray()) |facts| {
        n_trace += facts.trace_columns;
        n_interaction += facts.interaction_columns;
    }
    try std.testing.expectEqual(n_trace, trees[0].len);
    try std.testing.expectEqual(n_interaction, trees[1].len);
    // The first component's columns come first, at its log size.
    try std.testing.expectEqual(@as(u32, 10), trees[0][0]);
    try std.testing.expectEqual(@as(u32, 10 + component_list.N_COMPONENTS - 1), trees[0][trees[0].len - 1]);
}
