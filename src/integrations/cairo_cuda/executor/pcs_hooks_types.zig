//! Typed Cairo views over the shared resident CUDA PCS buffers.

const proof_ir = @import("stwo_backend_contracts").proof_program;
const quotient_abi = @import("stwo_cuda_backend").abi.stages.quotient;
const column = @import("stwo_cuda_backend").runtime.column;
const common = @import("stwo_cuda_backend").runtime.stages.common;
const quotient_stage = @import("stwo_cuda_backend").runtime.stages.quotient;
const shared_views = @import(
    "../../native_cuda/common/resident_views.zig",
);

const Words = column.DeviceSlice(u32);

pub const production_ready = false;
pub const max_trace_trees: usize = 4;

pub const Stage = enum {
    composition_commit,
    oods,
    quotient,
    fri,
    pow,
    decommit,
    terminal_assembly,
};

pub const Readiness = enum {
    buffers_bound,
    executable,
};

pub const Gap = error{
    MissingCairoTranscriptSchedule,
    MissingCompositionCoordinateLayout,
    MissingMixedHeightOodsSchedule,
    MissingCompactQuotientSources,
    MissingCompactQuotientCombine,
    MissingQuotientFriAlias,
    MissingFriTerminalGeometry,
    MissingMixedHeightDecommitTopology,
    MissingTerminalCompaction,
};

pub const blockers = [_][]const u8{
    "authenticated Cairo transcript operations and snapshot sub-layout",
    "four-coordinate composition output layout before the split/commit hook",
    "mixed-height OODS cohorts and mask-point ordering",
    "compact quotient source descriptors for all sampled trace columns",
    "compact variable-height quotient combination into the common FRI domain",
    "resident quotient-result to FRI-layer-zero alias contract",
    "FRI terminal evaluation extent derived from the final fold",
    "mixed-height trace opening groups and proof-record offsets",
    "bounded compaction from the working decommit assembly into the terminal section",
};

pub fn readiness(_: Stage) Readiness {
    return .buffers_bound;
}

pub fn requireExecutable(stage: Stage) Gap!void {
    return switch (stage) {
        .composition_commit => Gap.MissingCompositionCoordinateLayout,
        .oods => Gap.MissingMixedHeightOodsSchedule,
        .quotient => Gap.MissingCompactQuotientSources,
        .fri => Gap.MissingFriTerminalGeometry,
        .pow => Gap.MissingCairoTranscriptSchedule,
        .decommit => Gap.MissingMixedHeightDecommitTopology,
        .terminal_assembly => Gap.MissingTerminalCompaction,
    };
}

pub const CompactTree = struct {
    ordinal: u32,
    role: proof_ir.CommitmentRole,
    first_column: u32,
    column_count: u32,
    evaluation_log_rows: u32,
    coefficients: Words,
    evaluations: Words,
    column_log_sizes: Words,
    column_offsets: Words,
    merkle_hashes: common.Hashes,
    merkle_layers: common.MerkleLayers,
    root: common.Hashes,
};

pub const TraceTrees = struct {
    storage: [max_trace_trees]CompactTree,
    len: usize,

    pub fn active(self: *const TraceTrees) []const CompactTree {
        return self.storage[0..self.len];
    }

    pub fn require(
        self: *const TraceTrees,
        role: proof_ir.CommitmentRole,
    ) !CompactTree {
        for (self.active()) |tree| {
            if (tree.role == role) return tree;
        }
        return error.InvalidKernelDescriptor;
    }
};

pub const Quotient = struct {
    challenge: common.SecureFields,
    prepared_terms: column.DeviceSlice(
        quotient_abi.PreparedTermDescriptor,
    ),
    group_offsets: Words,
    group_term_indices: Words,
    batch_terms: column.DeviceSlice(quotient_abi.BatchTermDescriptor),
    source_descriptors: column.DeviceSlice(
        quotient_abi.AddressedSourceDescriptor,
    ),
    group_log_sizes: Words,
    partial_log_sizes: Words,
    partial_offsets: column.DeviceSlice(u64),
    term_points: common.SecureCirclePoints,
    line_coefficients: common.SecureFields,
    group_points: common.SecureCirclePoints,
    first_linear_terms: common.SecureFields,
    partial_coordinates: [4]Words,
    result_coordinates: quotient_stage.CoordinateColumns,
};

pub const Composition = struct {
    tree: shared_views.TraceTree,
    interaction_claims: common.SecureFields,
    alpha: common.SecureFields,
    random_powers: common.SecureFields,
    denominator_inverses: Words,
};

pub const Bindings = struct {
    identity: proof_ir.Digest,
    trees: TraceTrees,
    composition: Composition,
    transcript_storage: Words,
    twiddles_forward: Words,
    twiddles_inverse: Words,
    oods: shared_views.Oods,
    quotient: Quotient,
    fri: shared_views.Fri,
    pow: shared_views.Pow,
    query_pow: shared_views.Pow,
    decommit: shared_views.Decommit,
    decommit_assembly: Words,
    proof: shared_views.Proof,
    fri_terminal_extent_matches: bool,
    quotient_result_aliases_fri_zero: bool,
    terminal_decommitment_fits: bool,

    pub fn requireFri(self: Bindings) Gap!void {
        if (!self.fri_terminal_extent_matches)
            return Gap.MissingFriTerminalGeometry;
        if (!self.quotient_result_aliases_fri_zero)
            return Gap.MissingQuotientFriAlias;
    }

    pub fn requireTerminalAssembly(self: Bindings) Gap!void {
        if (!self.terminal_decommitment_fits)
            return Gap.MissingTerminalCompaction;
        return Gap.MissingMixedHeightDecommitTopology;
    }
};
