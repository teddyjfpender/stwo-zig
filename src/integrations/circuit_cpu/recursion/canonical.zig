//! The one circuit shape that verifies every layer of a recursive tree.
//!
//! Ports `CanonicalCircuit::build` of
//! `crates/stwo_run_and_prove_recursive_tree/src/canonical.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230). The leaf and multiverifier
//! circuits of a registry are padded to its shared target, so they share one
//! preprocessed layout and one `trace_log_size`: a single multiverifier shape
//! verifies leaf proofs (layer 1) and multiverifier proofs (every layer
//! above), and an unpaired entry can be carried up unchanged.
//!
//! The shape depends only on the registry's target sizes and circuit FRI
//! config (design §3.5), so it is built once per process in topology mode
//! and its circuit hash is checked against the registry once, here, before
//! any proving (design §7.2).

const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const wire = @import("stwo_circuit_recursion_wire");
const verifier_proof = @import("../verifier_proof.zig");
const circuit_params = @import("circuit_params.zig");

const builder = circuit.builder;
const finalize = circuit.common.finalize;
const preprocessed = circuit.common.preprocessed;
const circuit_hash = circuit.common.circuit_hash;
const multiverifier = circuit.statements.multiverifier;
const component_table = circuit.air_eval.component_table;
const ComponentSizes = finalize.ComponentSizes;

pub const Hash = [32]u8;

pub const Error = error{
    /// `RecursiveTreeError::PaddingParity`: the multiverifier padded to the
    /// registry's target does not have the layout it was built to verify.
    PaddingParity,
    /// `RecursiveTreeError::MultiverifierCircuitHash`: the built multiverifier
    /// does not hash to the registry's entry.
    MultiverifierCircuitHash,
};

pub const CanonicalCircuit = struct {
    /// The configuration shared by every proof the multiverifier verifies.
    shared: multiverifier.SharedConfig,
    /// The registry's padding target.
    target_sizes: ComponentSizes,
    /// The padded multiverifier, preprocessed: the shape every fold proves.
    preprocessed: preprocessed.PreprocessedCircuit,
    /// Its preprocessed root at the circuit blowup and its circuit hash,
    /// equal to the registry's multiverifier entry.
    preprocessed_root: Hash,
    circuit_hash: Hash,

    /// `CanonicalCircuit::build`. `table` is the circuit AIR's in-circuit
    /// evaluator table (`air_eval.circuit_components.build`).
    pub fn build(
        gpa: std.mem.Allocator,
        table: *const component_table.Table,
        registry: wire.registry.CircuitRegistry,
    ) !CanonicalCircuit {
        const entry = try registry.multiverifier();
        const config = try registry.config(entry.config);
        const target = ComponentSizes.fromLogSizes(config.component_log_sizes);

        // 1. The shared config of a child proof, derived from the target.
        var shared = try multiverifier.foldSharedConfig(gpa, target, config.fri_config);
        errdefer shared.deinit(gpa);

        // 2. The multiverifier shape, padded to the target.
        var pp = blk: {
            var ctx = try multiverifier.buildMultiverifierTopology(gpa, table, &shared, circuit.stark_verifier.verify.NoStages{});
            break :blk try circuit_params.paddedPreprocessed(gpa, &ctx, target);
        };
        errdefer pp.deinit(gpa);

        // 3. Homogeneity: it has the layout it verifies.
        const layout = pp.layout();
        if (!layout.eql(&shared.preprocessed_column_log_sizes) or
            layout.traceLogSize() != shared.preprocessed_column_log_sizes.traceLogSize())
            return error.PaddingParity;

        // 4. The registry's trust anchor.
        const identity = try circuit_params.identity(gpa, &pp, shared.pcs_config.fri_config.log_blowup_factor);
        if (!std.mem.eql(u8, &identity.circuit_hash, &entry.circuit_hash.toBytes())) return error.MultiverifierCircuitHash;

        return .{
            .shared = shared,
            .target_sizes = target,
            .preprocessed = pp,
            .preprocessed_root = identity.preprocessed_root,
            .circuit_hash = identity.circuit_hash,
        };
    }

    pub fn deinit(self: *CanonicalCircuit, gpa: std.mem.Allocator) void {
        self.preprocessed.deinit(gpa);
        self.shared.deinit(gpa);
        self.* = undefined;
    }

    /// The `CircuitSerialize` layout of every proof in the tree
    /// (`shared_config.proof_config`).
    pub fn proofConfig(self: *const CanonicalCircuit) wire.circuit_serialize.ProofConfig {
        return self.shared.proof_config.shape();
    }
};
