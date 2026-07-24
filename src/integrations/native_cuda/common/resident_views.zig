//! Typed, allocation-free views over one prepared resident proof arena.

const std = @import("std");
const quotient_abi = @import("../../../backends/cuda/abi/stages/quotient.zig");
const column = @import("../../../backends/cuda/runtime/column.zig");
const common = @import("../../../backends/cuda/runtime/stages/common.zig");
const decommit_stage = @import("../../../backends/cuda/runtime/stages/decommit.zig");
const oods_stage = @import("../../../backends/cuda/runtime/stages/oods.zig");
const quotient_stage = @import("../../../backends/cuda/runtime/stages/quotient.zig");
const trace_layout = @import("uniform_layout.zig");

pub const max_fri_layers: usize = 32;
pub const max_trace_trees: usize = 3;

pub const TraceTree = struct {
    role: trace_layout.TraceRole,
    coefficients: common.WordMatrix,
    evaluations: common.WordMatrix,
    column_log_sizes: common.Words,
    merkle_hashes: common.Hashes,
    merkle_layers: common.MerkleLayers,
};

pub const TraceTrees = struct {
    storage: [max_trace_trees]TraceTree,
    len: usize,

    pub fn init(trees: []const TraceTree) !TraceTrees {
        if (trees.len == 0 or trees.len > max_trace_trees)
            return error.InvalidKernelDescriptor;
        var result = TraceTrees{
            .storage = undefined,
            .len = trees.len,
        };
        for (trees, 0..) |tree, index| {
            try validateTraceTree(tree);
            for (trees[0..index]) |previous| {
                if (previous.role == tree.role)
                    return error.InvalidKernelDescriptor;
            }
            result.storage[index] = tree;
        }
        return result;
    }

    pub fn active(self: *const TraceTrees) []const TraceTree {
        return self.storage[0..self.len];
    }

    pub fn find(
        self: *const TraceTrees,
        role: trace_layout.TraceRole,
    ) ?TraceTree {
        for (self.active()) |tree| {
            if (tree.role == role) return tree;
        }
        return null;
    }

    pub fn require(
        self: *const TraceTrees,
        role: trace_layout.TraceRole,
    ) !TraceTree {
        return self.find(role) orelse error.InvalidKernelDescriptor;
    }
};

fn validateTraceTree(tree: TraceTree) !void {
    if (tree.coefficients.storage.len == 0 or
        tree.coefficients.column_stride_words == 0 or
        tree.coefficients.storage.len %
            tree.coefficients.column_stride_words != 0 or
        tree.coefficients.storage.len /
            tree.coefficients.column_stride_words !=
            tree.column_log_sizes.len or
        tree.evaluations.storage.len == 0 or
        tree.evaluations.column_stride_words == 0 or
        tree.evaluations.storage.len %
            tree.evaluations.column_stride_words != 0 or
        tree.evaluations.storage.len /
            tree.evaluations.column_stride_words !=
            tree.column_log_sizes.len or
        tree.merkle_hashes.len == 0 or
        tree.merkle_layers.len == 0)
    {
        return error.InvalidKernelDescriptor;
    }
}

pub const Trace = struct {
    trees: TraceTrees,
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
    layers: [max_fri_layers]FriLayer,
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

test "trace tree lookup is role-indexed and rejects duplicate roles" {
    const wordMatrix = struct {
        fn make(address: usize, columns: usize) common.WordMatrix {
            return .{
                .storage = .{
                    .address = address,
                    .len = columns * 8,
                    .owner = 1,
                    .generation = 2,
                },
                .column_stride_words = 8,
            };
        }
    }.make;
    const words = struct {
        fn make(address: usize, len: usize) common.Words {
            return .{
                .address = address,
                .len = len,
                .owner = 1,
                .generation = 2,
            };
        }
    }.make;
    const hashes = struct {
        fn make(address: usize) common.Hashes {
            return .{
                .address = address,
                .len = 15,
                .owner = 1,
                .generation = 2,
            };
        }
    }.make;
    const layers = struct {
        fn make(address: usize) common.MerkleLayers {
            return .{
                .address = address,
                .len = 4,
                .owner = 1,
                .generation = 2,
            };
        }
    }.make;
    const main = TraceTree{
        .role = .main,
        .coefficients = wordMatrix(0x1000, 1),
        .evaluations = wordMatrix(0x2000, 1),
        .column_log_sizes = words(0x3000, 1),
        .merkle_hashes = hashes(0x4000),
        .merkle_layers = layers(0x5000),
    };
    const composition = TraceTree{
        .role = .composition,
        .coefficients = wordMatrix(0x6000, 8),
        .evaluations = wordMatrix(0x7000, 8),
        .column_log_sizes = words(0x8000, 8),
        .merkle_hashes = hashes(0x9000),
        .merkle_layers = layers(0xa000),
    };
    const trees = try TraceTrees.init(&.{ main, composition });
    try std.testing.expectEqual(@as(usize, 2), trees.active().len);
    try std.testing.expect(
        (try trees.require(.composition)).role == .composition,
    );
    try std.testing.expect(trees.find(.preprocessed) == null);
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        TraceTrees.init(&.{ main, main }),
    );
}
