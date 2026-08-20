//! Frozen verifier-owned geometry for one recursion V1 RISC-V segment proof.
//!
//! The native prover, fixed wire, scheduled transcript, and outer verifier all
//! consume these facts.  They are protocol parameters, not measurements
//! inferred from attacker-controlled proof vectors.  `validateStatement`
//! checks the statement-owned table roster before any expensive proof work.

const std = @import("std");
const stwo_core = @import("stwo_core");
const statement_mod = @import("../air/statement.zig");
const transcript_claims = @import("../air/transcript/claims.zig");
const fixed_profile = @import("fixed_profile.zig");
const fixed_wire = @import("fixed_wire.zig");
const protocol = @import("protocol.zig");
const transcript_shape = @import("transcript_shape.zig");
const circuit = @import("air/fri_verifier_circuit.zig");
const schedule = @import("air/verifier_schedule.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const COLUMN_LOG_DEGREE: u32 = 20;
pub const LIFTING_LOG_SIZE: u32 =
    COLUMN_LOG_DEGREE + protocol.FRI_LOG_BLOWUP_FACTOR;
pub const PREPROCESSED_COLUMN_COUNT: u32 = 38;
pub const MAIN_COLUMN_COUNT: u32 = 625;
pub const INTERACTION_COLUMN_COUNT: u32 = 200;
pub const COMPOSITION_COLUMN_COUNT: u32 = 8;
pub const TREE_COLUMN_COUNTS = [fixed_profile.TREE_COUNT]u32{
    PREPROCESSED_COLUMN_COUNT,
    MAIN_COLUMN_COUNT,
    INTERACTION_COLUMN_COUNT,
    COMPOSITION_COLUMN_COUNT,
};
pub const TREE_HEIGHTS = [_]u32{LIFTING_LOG_SIZE} ** fixed_profile.TREE_COUNT;
pub const TABLE_COUNT: u32 = blk: {
    var count: u32 = 0;
    for (TREE_COLUMN_COUNTS) |columns| count += columns;
    break :blk count;
};
/// Interaction columns are sampled at both the current and previous circle
/// point; the other trees are sampled once.
pub const SAMPLED_VALUE_COUNT: u32 = TABLE_COUNT + INTERACTION_COLUMN_COUNT;
pub const CLAIMED_SUM_COUNT: u32 = transcript_claims.COMPONENT_COUNT;
pub const FRI_LAYER_COUNT: usize = 5;
pub const MAXIMUM_FOLD_WIDTH: usize = 16;
pub const LAST_LAYER_COEFFICIENT_COUNT: usize = 1;
pub const MAXIMUM_MERKLE_DEPTH: usize = LIFTING_LOG_SIZE;
pub const FOLD_WIDTHS = [_]u32{MAXIMUM_FOLD_WIDTH} ** FRI_LAYER_COUNT;

pub const DIMENSIONS = fixed_wire.Dimensions{
    .commitment_count = fixed_profile.TREE_COUNT,
    .claimed_sum_count = CLAIMED_SUM_COUNT,
    .sampled_value_count = SAMPLED_VALUE_COUNT,
    .queried_value_count = TABLE_COUNT * protocol.FRI_QUERY_COUNT,
    .trace_path_count = fixed_profile.TREE_COUNT * protocol.FRI_QUERY_COUNT,
    .fri_layer_count = FRI_LAYER_COUNT,
    .query_count = protocol.FRI_QUERY_COUNT,
    .maximum_fold_width = MAXIMUM_FOLD_WIDTH,
    .last_layer_coefficient_count = LAST_LAYER_COEFFICIENT_COUNT,
    .maximum_merkle_depth = MAXIMUM_MERKLE_DEPTH,
};

pub const Error = transcript_shape.Error || schedule.Error || error{
    StatementGeometryMismatch,
};

pub fn circuitProfile() circuit.Profile {
    return .{
        .lifting_log_size = LIFTING_LOG_SIZE,
        .log_blowup_factor = protocol.FRI_LOG_BLOWUP_FACTOR,
        .log_last_layer_degree_bound = protocol.FRI_LOG_LAST_LAYER_DEGREE_BOUND,
        .fold_widths = &FOLD_WIDTHS,
        .query_count = protocol.FRI_QUERY_COUNT,
    };
}

pub fn transcriptShape() Error!schedule.ScheduleShape {
    return transcript_shape.derive(
        circuitProfile(),
        TREE_HEIGHTS,
        .{
            .sampled_value_count = SAMPLED_VALUE_COUNT,
            .queried_values_per_query = TABLE_COUNT,
            .claimed_sum_count = CLAIMED_SUM_COUNT,
            .interaction_pow_bits = protocol.INTERACTION_POW_BITS,
            .pcs_pow_bits = protocol.PCS_POW_BITS,
        },
    );
}

pub fn initPlans(
    allocator: std.mem.Allocator,
    max_input_words: u32,
    max_output_words: u32,
) Error!struct { vm: schedule.Plan, recursion: schedule.Plan } {
    const shape = try transcriptShape();
    var vm = try schedule.Plan.initShape(
        allocator,
        try schedule.vmProgramSpec(max_input_words, max_output_words),
        shape,
    );
    errdefer vm.deinit();
    const recursion = try schedule.Plan.initShape(
        allocator,
        schedule.RECURSION_PROGRAM_SPEC_V1,
        shape,
    );
    return .{ .vm = vm, .recursion = recursion };
}

/// Reject table-count or maximum-degree drift before the prover allocates its
/// largest traces.  Exact per-column log-size validation remains duplicated at
/// the post-verification fixed-wire boundary, where captured vectors exist.
pub fn validateStatement(statement: *const statement_mod.RiscVStatement) Error!void {
    if (statement.nPreprocessedColumns() != PREPROCESSED_COLUMN_COUNT or
        statement.nMainColumns() != MAIN_COLUMN_COUNT or
        statement.nInteractionColumns() != INTERACTION_COLUMN_COUNT)
    {
        return error.StatementGeometryMismatch;
    }
    var maximum_log: u32 = 0;
    for (statement.component_descs[0..statement.n_components]) |descriptor|
        maximum_log = @max(maximum_log, descriptor.log_size);
    for (statement.infra_descs[0..statement.n_infra]) |descriptor|
        maximum_log = @max(maximum_log, descriptor.log_size);
    if (maximum_log != COLUMN_LOG_DEGREE)
        return error.StatementGeometryMismatch;
}

test "recursion segment profile is one internally consistent frozen geometry" {
    DIMENSIONS.validate();
    const shape = try transcriptShape();
    try shape.validate();
    try std.testing.expectEqual(TABLE_COUNT, @as(u32, 871));
    try std.testing.expectEqual(SAMPLED_VALUE_COUNT, @as(u32, 1_071));
    try std.testing.expectEqual(CLAIMED_SUM_COUNT, @as(u32, 28));
    try std.testing.expectEqual(
        @as(usize, protocol.FRI_QUERY_COUNT * TABLE_COUNT),
        DIMENSIONS.queried_value_count,
    );
    try std.testing.expectEqual(FRI_LAYER_COUNT, shape.fri.count);
    for (shape.fri.active(), FOLD_WIDTHS) |round, width|
        try std.testing.expectEqual(width, round.fold_width);
    const composition_columns = stwo_core.verifier_types.compositionColumnCount(
        stwo_core.verifier_types.COMPOSITION_LOG_SPLIT,
        stwo_core.fields.qm31.SECURE_EXTENSION_DEGREE,
    ) orelse return error.StatementGeometryMismatch;
    try std.testing.expectEqual(COMPOSITION_COLUMN_COUNT, composition_columns);

    var plans = try initPlans(std.testing.allocator, 2, 3);
    defer plans.recursion.deinit();
    defer plans.vm.deinit();
    try std.testing.expectEqual(@as(u32, 75), plans.vm.spec.public_logup_term_count);
}
