//! Exact Poseidon views over its three non-empty resident trace trees.

const field = @import("stwo_cuda_backend").abi.field;
const column = @import("stwo_cuda_backend").runtime.column;
const common = @import("stwo_cuda_backend").runtime.stages.common;
const poseidon_constraint = @import("stwo_cuda_backend").runtime.constraints.poseidon;
const relation_stage = @import("stwo_cuda_backend").runtime.stages.relation;
const relation_mod = @import("../relation.zig");
const shared = @import("../../common/resident_views.zig");

pub const max_fri_layers = shared.max_fri_layers;
pub const max_trace_trees = shared.max_trace_trees;
pub const TraceTree = shared.TraceTree;
pub const TraceTrees = shared.TraceTrees;
pub const Transcript = shared.Transcript;
pub const Oods = shared.Oods;
pub const Quotient = shared.Quotient;
pub const FriLayer = shared.FriLayer;
pub const Fri = shared.Fri;
pub const Pow = shared.Pow;
pub const Counts = shared.Counts;
pub const Decommit = shared.Decommit;
pub const Proof = shared.Proof;

const Words = column.DeviceSlice(u32);

pub const Trace = struct {
    trees: TraceTrees,
    twiddles_forward: common.Words,
    twiddles_inverse: common.Words,
    main_coefficients: common.WordMatrix,
    interaction_coefficients: common.WordMatrix,
    composition_coefficients: common.WordMatrix,
    committed_evaluation_slab: common.Words,
    main_evaluations: common.WordMatrix,
    interaction_evaluations: common.WordMatrix,
    composition_evaluations: common.WordMatrix,
    all_evaluations: common.WordMatrix,
    constraint_evaluations: common.WordMatrix,
    coefficient_log_sizes: common.Words,
    main_merkle_hashes: common.Hashes,
    interaction_merkle_hashes: common.Hashes,
    composition_merkle_hashes: common.Hashes,
    main_merkle_layers: common.MerkleLayers,
    interaction_merkle_layers: common.MerkleLayers,
    composition_merkle_layers: common.MerkleLayers,
};

pub const Relation = struct {
    buffers: relation_stage.DeviceBuffers,
    source_values: common.WordMatrix,
    source_columns: [relation_mod.source_pointer_count]Words,
    output_coordinates: [relation_mod.output_coordinate_count]Words,
    source_pointer_table: Words,
    descriptor_storage: Words,
    output_pointer_table: Words,
    denominator_slab: common.SecureFields,
    claimed_sum: common.SecureFields,

    pub fn instance(self: *const Relation) relation_stage.InstanceBinding {
        return .{
            .source_pointer_table = self.source_pointer_table,
            .source_columns = &self.source_columns,
            .descriptor_storage = self.descriptor_storage,
            .descriptors = &relation_mod.descriptors,
            .output_pointer_table = self.output_pointer_table,
            .output_coordinates = &self.output_coordinates,
            .denominator_slab = self.denominator_slab,
            .claimed_sum = self.claimed_sum,
        };
    }
};

pub const Constraint = struct {
    source_evaluations: common.WordMatrix,
    random_powers: common.SecureFields,
    denominator_inverses: common.Words,
    lookup_elements: common.SecureFields,
    claimed_sum: common.SecureFields,
    composition_coordinates: common.WordMatrix,
    composition_challenge: common.SecureFields,

    pub fn buffers(self: Constraint) poseidon_constraint.Buffers {
        return .{
            .source_evaluations = self.source_evaluations,
            .random_coefficient_powers = self.random_powers,
            .denominator_inverses = self.denominator_inverses,
            .lookup_elements = self.lookup_elements,
            .claimed_sum = self.claimed_sum,
            .composition_coordinates = self.composition_coordinates,
        };
    }
};

pub const Views = struct {
    trace: Trace,
    transcript: Transcript,
    relation: Relation,
    constraint: Constraint,
    oods: Oods,
    quotient: Quotient,
    fri: Fri,
    pow: Pow,
    decommit: Decommit,
    proof: Proof,
};

comptime {
    if (@sizeOf(field.SecureField) != 4 * @sizeOf(u32))
        @compileError("Poseidon relation binding assumes four-word QM31");
}
