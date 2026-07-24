//! Typed, allocation-free views over one prepared resident proof arena.

const quotient_abi = @import("../../../../backends/cuda/abi/stages/quotient.zig");
const column = @import("../../../../backends/cuda/runtime/column.zig");
const common = @import("../../../../backends/cuda/runtime/stages/common.zig");
const decommit_stage = @import("../../../../backends/cuda/runtime/stages/decommit.zig");
const oods_stage = @import("../../../../backends/cuda/runtime/stages/oods.zig");
const quotient_stage = @import("../../../../backends/cuda/runtime/stages/quotient.zig");
const request = @import("../request.zig");

pub const Trace = struct {
    twiddles_forward: common.Words,
    twiddles_inverse: common.Words,
    coefficient_slab: common.Words,
    main_coefficients: common.WordMatrix,
    composition_coefficients: common.WordMatrix,
    committed_evaluation_slab: common.Words,
    main_evaluations: common.WordMatrix,
    composition_evaluations: common.WordMatrix,
    all_evaluations: common.WordMatrix,
    coefficient_log_sizes: common.Words,
    main_commit_states: common.ProgressiveStates,
    composition_commit_states: common.ProgressiveStates,
    main_merkle_hashes: common.Hashes,
    composition_merkle_hashes: common.Hashes,
    main_merkle_layers: common.MerkleLayers,
    composition_merkle_layers: common.MerkleLayers,
};

pub const Transcript = struct {
    state: common.Words,
    input_snapshot: common.Words,
    output_snapshot: common.Words,
    boundary_snapshot: common.Words,
    static_inputs: common.Words,
};

pub const Constraint = struct {
    random_powers: common.SecureFields,
    denominator_inverses: common.Words,
    composition_coordinates: common.WordMatrix,
    composition_challenge: common.SecureFields,
};

pub const Oods = struct {
    parameter: common.SecureFields,
    offset_points: common.CirclePoints,
    fold_counts: common.Words,
    output_indices: common.Words,
    sample_points: common.SecureCirclePoints,
    evaluation_points: common.SecureCirclePoints,
    folding_factors: common.SecureFields,
    reduce_a: common.SecureFields,
    reduce_b: common.SecureFields,
    sampled_values: common.SecureFields,

    pub fn sampleMap(self: Oods) oods_stage.SampleMap {
        return .{
            .indices = .{
                .device = self.output_indices,
                .output_capacity = self.sampled_values.len,
            },
            .fold_counts = self.fold_counts,
        };
    }

    pub fn indexMap(self: Oods) oods_stage.IndexMap {
        return .{
            .device = self.output_indices,
            .output_capacity = self.sampled_values.len,
        };
    }
};

pub const Quotient = struct {
    challenge: common.SecureFields,
    prepared_terms: column.DeviceSlice(quotient_abi.PreparedTermDescriptor),
    group_offsets: common.Words,
    group_term_indices: common.Words,
    batch_terms: column.DeviceSlice(quotient_abi.BatchTermDescriptor),
    group_log_sizes: common.Words,
    partial_log_sizes: common.Words,
    term_points: common.SecureCirclePoints,
    line_coefficients: common.SecureFields,
    group_points: common.SecureCirclePoints,
    first_linear_terms: common.SecureFields,
    partial_coordinates: quotient_stage.CoordinateSlabs,
    result_coordinates: quotient_stage.CoordinateColumns,
    source_evaluations: common.WordMatrix,
    prepared_groups: quotient_stage.PreparedGroups,
    numerator_topology: quotient_stage.NumeratorTopology,
    combine_topology: quotient_stage.CombineTopology,
};

pub const FriLayer = struct {
    coordinates: common.WordMatrix,
    merkle_hashes: common.Hashes,
    merkle_layers: common.MerkleLayers,
};

pub const Fri = struct {
    alpha: common.SecureFields,
    layers: [request.max_log_n_rows]FriLayer,
    layer_count: usize,
    last_evaluation: common.SecureFields,
    last_coefficients: common.SecureFields,
    last_degree_error: common.Words,
    last_transcript: common.SecureFields,

    pub fn activeLayers(self: *const Fri) []const FriLayer {
        return self.layers[0..self.layer_count];
    }
};

pub const Pow = struct {
    prefix_digest: common.Words,
    best_nonce: common.Nonce,
    completed_blocks: common.Words,
    transcript_nonce: common.Words,
};

pub const Counts = struct {
    unique: common.Words,
    mapped_or_tree: common.Words,
    walk: common.Words,
    expanded: common.Words,
    leaf_or_sparse: common.Words,
};

pub const Decommit = struct {
    raw_queries: common.Words,
    unique_queries: common.Words,
    mapped_queries: common.Words,
    walk_queries: common.Words,
    walk_scratch: common.Words,
    leaf_indices: common.Words,
    expanded_positions: common.Words,
    sparse_indices: common.Words,
    sparse_hashes: common.Hashes,
    counts: Counts,
    sparse_level_offsets: common.Words,
    sparse_level_counts: common.Words,
    main_column_log_sizes: common.Words,
    composition_column_log_sizes: common.Words,

    pub fn traceQueries(self: Decommit) decommit_stage.TraceQueries {
        return .{
            .mapped = self.mapped_queries,
            .mapped_count = self.counts.mapped_or_tree,
            .walk = self.walk_queries,
            .walk_count = self.counts.walk,
            .leaf_indices = self.leaf_indices,
            .leaf_count = self.counts.leaf_or_sparse,
        };
    }

    pub fn friQueries(self: Decommit) decommit_stage.FriQueries {
        return .{
            .tree = self.mapped_queries,
            .tree_count = self.counts.mapped_or_tree,
            .expanded = self.expanded_positions,
            .expanded_count = self.counts.expanded,
            .walk = self.walk_queries,
            .walk_count = self.counts.walk,
        };
    }

    pub fn traceAssembly(
        self: Decommit,
        retained: decommit_stage.RetainedTree,
        assembly: common.Words,
    ) decommit_stage.TraceAssembly {
        return .{
            .mapped_count = self.counts.mapped_or_tree,
            .walk_queries = self.walk_queries,
            .walk_scratch = self.walk_scratch,
            .walk_count = self.counts.walk,
            .retained = retained,
            .sparse_indices = self.sparse_indices,
            .sparse_hashes = self.sparse_hashes,
            .sparse_level_offsets = self.sparse_level_offsets,
            .sparse_level_counts = self.sparse_level_counts,
            .assembly = assembly,
        };
    }

    pub fn friAssembly(
        self: Decommit,
        layer: FriLayer,
        assembly: common.Words,
    ) decommit_stage.FriAssembly {
        return .{
            .tree_queries = self.mapped_queries,
            .tree_query_count = self.counts.mapped_or_tree,
            .expanded_positions = self.expanded_positions,
            .expanded_count = self.counts.expanded,
            .coordinates = layer.coordinates,
            .walk_queries = self.walk_queries,
            .walk_scratch = self.walk_scratch,
            .walk_count = self.counts.walk,
            .retained = .{
                .hashes = layer.merkle_hashes,
                .layers = layer.merkle_layers,
            },
            .assembly = assembly,
        };
    }
};

pub const Proof = struct {
    // SWPC is word-packed: its header deliberately does not promise the
    // 32-byte alignment of standalone Blake2sHash slots.
    bundle: common.Words,
    degree_verdict: common.Words,
    trace_commitments: common.Words,
    sampled_values: common.Words,
    fri_commitments: common.Words,
    fri_last_layer: common.Words,
    pow_nonce: common.Words,
    decommitment: common.Words,
};

pub const Views = struct {
    trace: Trace,
    transcript: Transcript,
    constraint: Constraint,
    oods: Oods,
    quotient: Quotient,
    fri: Fri,
    pow: Pow,
    decommit: Decommit,
    proof: Proof,
};
