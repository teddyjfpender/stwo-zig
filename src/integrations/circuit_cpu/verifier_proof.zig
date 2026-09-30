//! A circuit proof in the in-circuit verifier's format.
//!
//! Ports `prepare_circuit_proof_for_circuit_verifier`
//! (`crates/circuit_prover/src/prover.rs`) and `proof_from_stark_proof`
//! (`crates/stark_verifier/src/proof_from_stark_proof.rs`) of
//! https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230 (design §4.5). The input is the
//! prover's own `ExtendedStarkProof` aux, as upstream: queried values are
//! re-expanded to `unsorted_query_locations` order (duplicates included),
//! trace auth paths are `all_node_values[j][pos ^ 1]`, FRI auth paths
//! `all_node_values[j - pack_shift][pos ^ 1]`, FRI witnesses the full fold
//! coset of `all_values[0]`, and the nonces and salt become
//! `QM31(lo, hi, 0, 0)`. The result is the CircuitSerialize `Proof` of the
//! circuit-recursion wire package; `serialize` writes its bytes, and
//! `circuitVerifierValues` gives the in-circuit verifier's proof values
//! (what a fold node guesses).

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const wire = @import("stwo_circuit_recursion_wire").circuit_serialize;

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const component_list = circuit.common.component_list;
const builder = circuit.builder;
const stark_proof = circuit.stark_verifier.proof;
const HashValue = builder.blake.HashValue;
const M31Wrapper = builder.wrappers.M31Wrapper;
const InteractionAtOods = circuit.stark_verifier.constraint_eval.InteractionAtOods;
const LOG_PACKED_LEAF_SIZE = core.fri.LOG_PACKED_LEAF_SIZE;

pub const Error = error{
    /// The proof's shape is not a circuit proof under its own config.
    InvalidCircuitProof,
    /// A decommitment lacks a node or value the conversion needs.
    MissingDecommitmentValue,
};

/// The circuit verifier's view of the circuit AIR's components
/// (`all_circuit_components`), in `ComponentList` order.
pub const component_shapes = circuit.statements.circuit_statement.circuit_component_shapes;

/// `ProofConfig::new(all_circuit_components, n_preprocessed, pcs_config,
/// INTERACTION_POW_BITS)` as the wire format reads it.
pub fn proofConfig(n_preprocessed_columns: usize, pcs_config: core.pcs.config_v2.PcsConfigV2) Error!wire.ProofConfig {
    if (pcs_config.trace_lifting_log_size != pcs_config.preprocessed_lifting_log_size or
        pcs_config.trace_lifting_log_size < pcs_config.fri_config.log_blowup_factor)
        return error.InvalidCircuitProof;
    return .{
        .n_preprocessed_columns = n_preprocessed_columns,
        .component_shapes = &component_shapes,
        .log_trace_size = pcs_config.trace_lifting_log_size - pcs_config.fri_config.log_blowup_factor,
        .fri = pcs_config.fri_config,
    };
}

/// A converted proof; its slices live in `arena`.
pub const VerifierProof = struct {
    arena: std.heap.ArenaAllocator,
    proof: wire.Proof,
    config: wire.ProofConfig,

    pub fn deinit(self: *VerifierProof) void {
        self.arena.deinit();
        self.* = undefined;
    }

    /// `CircuitSerialize::serialize`.
    pub fn serialize(self: *const VerifierProof, allocator: std.mem.Allocator) ![]u8 {
        return wire.serializeProofAlloc(allocator, &self.proof, self.config);
    }
};

/// `prepare_circuit_proof_for_circuit_verifier` minus the public data: the
/// verifier proof of `proof`, a `CircuitProof` of `prove.Prover(MC)` whose
/// Merkle hasher is the plain Blake2s one.
pub fn prepare(allocator: std.mem.Allocator, proof: anytype) !VerifierProof {
    const stark = &proof.stark_proof.proof.commitment_scheme_proof;
    if (stark.sampled_values.items.len != wire.n_traces) return error.InvalidCircuitProof;
    const config = try proofConfig(stark.sampled_values.items[0].len, proof.pcs_config);
    return fromStarkProof(
        allocator,
        &proof.stark_proof,
        config,
        &proof.claimed_sums.toArray(),
        proof.interaction_pow_nonce,
        proof.channel_salt,
    );
}

/// `proof_from_stark_proof`: the verifier proof of any `ExtendedStarkProof`
/// committed with the plain Blake2s Merkle hasher, under `config` (the
/// verified AIR's `ProofConfig`). `prepare` uses it for circuit proofs, the
/// leaf wrap for Cairo proofs (`prepare_cairo_proof_for_circuit_verifier`).
/// `config.component_shapes` is copied into the result.
pub fn fromStarkProof(
    allocator: std.mem.Allocator,
    extended_proof: anytype,
    proof_config: wire.ProofConfig,
    claimed_sums_in: []const QM31,
    interaction_pow_nonce: u64,
    channel_salt: u32,
) !VerifierProof {
    const stark = &extended_proof.proof.commitment_scheme_proof;
    const aux = &extended_proof.aux;
    if (stark.commitments.items.len != wire.n_traces or stark.sampled_values.items.len != wire.n_traces)
        return error.InvalidCircuitProof;
    proof_config.validate() catch return error.InvalidCircuitProof;
    if (claimed_sums_in.len != proof_config.nComponents()) return error.InvalidCircuitProof;

    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const a = arena.allocator();
    var config = proof_config;
    config.component_shapes = try a.dupe(wire.ComponentShape, proof_config.component_shapes);
    const n_queries = config.nQueries();
    const queries = aux.unsorted_query_locations;
    if (queries.len != n_queries) return error.InvalidCircuitProof;

    const claimed_sums = try a.dupe(QM31, claimed_sums_in);
    const interaction = stark.sampled_values.items[2];
    const interaction_at_oods = try a.alloc(wire.InteractionAtOods, interaction.len);
    for (interaction, interaction_at_oods) |samples, *out| out.* = switch (samples.len) {
        2 => .{ .at_oods = samples[1], .at_prev = samples[0] },
        1 => .{ .at_oods = samples[0], .at_prev = null },
        else => return error.InvalidCircuitProof,
    };
    const composition = try singleRow(a, stark.sampled_values.items[3]);
    if (composition.len != wire.n_composition_columns) return error.InvalidCircuitProof;

    var out = wire.Proof{
        .channel_salt = QM31.fromU32Unchecked(channel_salt % core.fields.m31.Modulus, 0, 0, 0),
        .trace_root = stark.commitments.items[1],
        .interaction_root = stark.commitments.items[2],
        .composition_polynomial_root = stark.commitments.items[3],
        .claimed_sums = claimed_sums,
        .preprocessed_columns_at_oods = try singleRow(a, stark.sampled_values.items[0]),
        .trace_at_oods = try singleRow(a, stark.sampled_values.items[1]),
        .interaction_at_oods = interaction_at_oods,
        .composition_eval_at_oods = composition[0..wire.n_composition_columns].*,
        .eval_domain_samples = undefined,
        .eval_domain_auth_paths = undefined,
        .pow_nonce = nonceQm31(stark.proof_of_work),
        .interaction_pow_nonce = nonceQm31(interaction_pow_nonce),
        .fri = undefined,
    };

    // Eval-domain samples: `queried_values` is per sorted unique position.
    const sorted = try a.dupe(usize, queries);
    std.mem.sort(usize, sorted, {}, std.sort.asc(usize));
    const unique = dedupSorted(sorted);
    const columns = config.nColumnsPerTrace();
    for (0..wire.n_traces) |tree| {
        const queried = stark.queried_values.items[tree];
        if (queried.len != columns[tree]) return error.InvalidCircuitProof;
        const samples = try a.alloc(M31, columns[tree] * n_queries);
        for (queried, 0..) |column, c| {
            if (column.len != unique.len) return error.InvalidCircuitProof;
            for (queries, 0..) |position, q| {
                const rank = std.sort.binarySearch(usize, unique, position, orderUsize) orelse
                    return error.MissingDecommitmentValue;
                samples[c * n_queries + q] = column[rank];
            }
        }
        out.eval_domain_samples[tree] = samples;
    }

    // Eval-domain auth paths.
    const depth = config.logEvaluationDomainSize();
    if (aux.trace_decommitment.items.len != wire.n_traces) return error.InvalidCircuitProof;
    for (aux.trace_decommitment.items, 0..) |decommitment, tree| {
        const paths = try a.alloc(wire.Hash, n_queries * depth);
        for (queries, 0..) |query, q| {
            var position = query;
            for (0..depth) |level| {
                paths[q * depth + level] = try nodeAt(decommitment.all_node_values, level, position ^ 1);
                position >>= 1;
            }
        }
        out.eval_domain_auth_paths[tree] = paths;
    }

    // FRI.
    var steps_buffer: [core.circuit_proof_shape.max_fri_layers]u32 = undefined;
    const steps = config.friFoldSteps(&steps_buffer);
    const n_layers = steps.len;
    if (stark.fri_proof.inner_layers.len + 1 != n_layers or
        aux.fri.inner_layers.len + 1 != n_layers)
        return error.InvalidCircuitProof;
    const commitments = try a.alloc(wire.Hash, n_layers);
    commitments[0] = stark.fri_proof.first_layer.commitment;
    for (stark.fri_proof.inner_layers, commitments[1..]) |layer, *commitment| commitment.* = layer.commitment;
    const auth_paths = try a.alloc([]wire.Hash, n_layers);
    const witness = try a.alloc([]QM31, n_layers);
    var log_layer_size = depth;
    var fold_sum: usize = 0;
    for (steps, 0..) |step_u32, layer| {
        const step: usize = step_u32;
        const layer_aux = if (layer == 0) &aux.fri.first_layer else &aux.fri.inner_layers[layer - 1];
        const pack_shift: usize = if (log_layer_size >= LOG_PACKED_LEAF_SIZE and step > 1) LOG_PACKED_LEAF_SIZE else 0;
        const path_len = log_layer_size - step;
        const paths = try a.alloc(wire.Hash, n_queries * path_len);
        const coset = try a.alloc(QM31, n_queries << @intCast(step));
        for (queries, 0..) |query, q| {
            var position = query >> @intCast(fold_sum + step);
            for (step..log_layer_size, 0..) |level, index| {
                paths[q * path_len + index] = try nodeAt(layer_aux.decommitment.all_node_values, level - pack_shift, position ^ 1);
                position >>= 1;
            }
            // `construct_fri_witness`: the fold coset of the query's position
            // in this layer.
            const layer_position = query >> @intCast(fold_sum);
            const start = (layer_position >> @intCast(step)) << @intCast(step);
            for (0..@as(usize, 1) << @intCast(step)) |i|
                coset[(q << @intCast(step)) + i] = try valueAt(layer_aux.all_values, start + i);
        }
        auth_paths[layer] = paths;
        witness[layer] = coset;
        log_layer_size -= step;
        fold_sum += step;
    }
    out.fri = .{
        .layer_commitments = commitments,
        .last_layer_coefs = try a.dupe(QM31, stark.fri_proof.last_layer_poly.coeffs),
        .auth_paths = auth_paths,
        .witness = witness,
    };
    out.validateShape(config) catch return error.InvalidCircuitProof;
    return .{ .arena = arena, .proof = out, .config = config };
}

fn singleRow(a: std.mem.Allocator, samples: []const []const QM31) ![]QM31 {
    const row = try a.alloc(QM31, samples.len);
    for (samples, row) |column, *value| {
        if (column.len != 1) return error.InvalidCircuitProof;
        value.* = column[0];
    }
    return row;
}

/// The in-circuit verifier's proof values (`Proof<QM31>` of
/// `crates/stark_verifier`) of a CircuitSerialize proof: the same fields in
/// the same flat layout, with every Merkle hash as eight packed `u32` words
/// and every sample as an M31. The values borrow nothing from `proof`; they
/// live in `allocator` (an arena).
pub fn circuitVerifierValues(
    allocator: std.mem.Allocator,
    proof: *const wire.Proof,
    config: wire.ProofConfig,
) (Error || std.mem.Allocator.Error)!stark_proof.Proof(QM31) {
    proof.validateShape(config) catch return error.InvalidCircuitProof;
    const interaction = try allocator.alloc(InteractionAtOods(QM31), proof.interaction_at_oods.len);
    for (interaction, proof.interaction_at_oods) |*out, column| out.* = .{ .at_oods = column.at_oods, .at_prev = column.at_prev };

    var samples: [wire.n_traces][]M31Wrapper(QM31) = undefined;
    const eval_trees = try allocator.alloc([]HashValue(QM31), wire.n_traces);
    for (&samples, eval_trees, proof.eval_domain_samples, proof.eval_domain_auth_paths) |*tree_samples, *tree_paths, values, nodes| {
        tree_samples.* = try allocator.alloc(M31Wrapper(QM31), values.len);
        for (tree_samples.*, values) |*out, value| out.* = builder.wrappers.m31Value(QM31, value);
        tree_paths.* = try hashValues(allocator, nodes);
    }
    const fri_trees = try allocator.alloc([]HashValue(QM31), proof.fri.auth_paths.len);
    for (fri_trees, proof.fri.auth_paths) |*out, nodes| out.* = try hashValues(allocator, nodes);
    const witness = try allocator.alloc([]QM31, proof.fri.witness.len);
    for (witness, proof.fri.witness) |*out, values| out.* = try allocator.dupe(QM31, values);

    return .{
        .channel_salt = proof.channel_salt,
        .trace_root = hashValue(proof.trace_root),
        .interaction_root = hashValue(proof.interaction_root),
        .composition_polynomial_root = hashValue(proof.composition_polynomial_root),
        .claimed_sums = try allocator.dupe(QM31, proof.claimed_sums),
        .preprocessed_columns_at_oods = try allocator.dupe(QM31, proof.preprocessed_columns_at_oods),
        .trace_at_oods = try allocator.dupe(QM31, proof.trace_at_oods),
        .interaction_at_oods = interaction,
        .composition_eval_at_oods = proof.composition_eval_at_oods,
        .eval_domain_samples = .{ .n_queries = config.nQueries(), .data = samples },
        .eval_domain_auth_paths = .{ .n_queries = config.nQueries(), .trees = eval_trees },
        .pow_nonce = proof.pow_nonce,
        .interaction_pow_nonce = proof.interaction_pow_nonce,
        .fri = .{
            .layer_commitments = try hashValues(allocator, proof.fri.layer_commitments),
            .last_layer_coefs = try allocator.dupe(QM31, proof.fri.last_layer_coefs),
            .auth_paths = .{ .n_queries = config.nQueries(), .trees = fri_trees },
            .witness = witness,
        },
    };
}

/// `HashValue::from(Blake2sHash)`.
fn hashValue(hash: wire.Hash) HashValue(QM31) {
    return builder.blake.hashValueFromDigest(QM31, hash);
}

fn hashValues(allocator: std.mem.Allocator, hashes: []const wire.Hash) std.mem.Allocator.Error![]HashValue(QM31) {
    const out = try allocator.alloc(HashValue(QM31), hashes.len);
    for (out, hashes) |*value, hash| value.* = hashValue(hash);
    return out;
}

fn nonceQm31(nonce: u64) QM31 {
    return QM31.fromM31(
        M31.fromU64(nonce & 0xffff_ffff),
        M31.fromU64(nonce >> 32),
        M31.zero(),
        M31.zero(),
    );
}

fn dedupSorted(values: []usize) []usize {
    if (values.len == 0) return values;
    var len: usize = 1;
    for (values[1..]) |value| {
        if (value != values[len - 1]) {
            values[len] = value;
            len += 1;
        }
    }
    return values[0..len];
}

fn orderUsize(key: usize, item: usize) std.math.Order {
    return std.math.order(key, item);
}

fn nodeAt(layers: anytype, level: usize, index: usize) Error!wire.Hash {
    if (level >= layers.len) return error.MissingDecommitmentValue;
    for (layers[level]) |node| if (node.index == index) return node.hash;
    return error.MissingDecommitmentValue;
}

fn valueAt(layers: anytype, index: usize) Error!QM31 {
    if (layers.len == 0) return error.MissingDecommitmentValue;
    for (layers[0]) |entry| if (entry.index == index) return entry.value;
    return error.MissingDecommitmentValue;
}
