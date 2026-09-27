//! Internal shard of binary_transcript_outer_source.zig; use the public facade.

const dependency_0 = @import("binary_transcript_outer_source_executors.zig");

const M31 = dependency_0.M31;
const manifest_mod = dependency_0.manifest_mod;
const roster = dependency_0.roster;
const control_air = dependency_0.control_air;
const transcript_air = dependency_0.transcript_air;
const transcript_binding_air = dependency_0.transcript_binding_air;
const transcript_state_air = dependency_0.transcript_state_air;
const transcript_word_air = dependency_0.transcript_word_air;
const transcript_payload_air = dependency_0.transcript_payload_air;
const pow_check_air = dependency_0.pow_check_air;
const pow_frame_air = dependency_0.pow_frame_air;
const relation_challenge_air = dependency_0.relation_challenge_air;
const verifier_randomness_air = dependency_0.verifier_randomness_air;
const FIRST_ROW = dependency_0.FIRST_ROW;
const ROW_COUNT = dependency_0.ROW_COUNT;
const LAST_ROW = dependency_0.LAST_ROW;
const ControlFramework = dependency_0.ControlFramework;
const TranscriptAirFramework = dependency_0.TranscriptAirFramework;
const TranscriptBindingFramework = dependency_0.TranscriptBindingFramework;
const TranscriptStateFramework = dependency_0.TranscriptStateFramework;
const TranscriptWordFramework = dependency_0.TranscriptWordFramework;
const TranscriptPayloadFramework = dependency_0.TranscriptPayloadFramework;
const PowCheckFramework = dependency_0.PowCheckFramework;
const PowFrameFramework = dependency_0.PowFrameFramework;
const RelationChallengeFramework = dependency_0.RelationChallengeFramework;
const VerifierRandomnessFramework = dependency_0.VerifierRandomnessFramework;
const ControlAdapter = dependency_0.ControlAdapter;
const TranscriptAirAdapter = dependency_0.TranscriptAirAdapter;
const TranscriptBindingAdapter = dependency_0.TranscriptBindingAdapter;
const TranscriptStateAdapter = dependency_0.TranscriptStateAdapter;
const TranscriptWordAdapter = dependency_0.TranscriptWordAdapter;
const TranscriptPayloadAdapter = dependency_0.TranscriptPayloadAdapter;
const PowCheckAdapter = dependency_0.PowCheckAdapter;
const PowFrameAdapter = dependency_0.PowFrameAdapter;
const RelationChallengeAdapter = dependency_0.RelationChallengeAdapter;
const VerifierRandomnessAdapter = dependency_0.VerifierRandomnessAdapter;

pub fn preflightDestination(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    destination: []const []M31,
) !void {
    const expected_columns = manifestTreeColumnCount(manifest, tree);
    if (destination.len != expected_columns)
        return error.DestinationColumnCountMismatch;
    inline for (0..ROW_COUNT) |index| {
        const row: roster.Component = @enumFromInt(FIRST_ROW + index);
        const placement = try manifest.placement(row);
        const offset = placementTreeOffset(placement, tree);
        const count = geometryColumnCount(placement.geometry, tree);
        const expected_rows = try traceSize(placement.geometry.log_size);
        if (offset > destination.len or count > destination.len - offset)
            return error.DestinationColumnCountMismatch;
        for (destination[offset..][0..count]) |column| {
            if (column.len != expected_rows)
                return error.DestinationLogSizeMismatch;
        }
    }
    // Reject two manifest columns backed by overlapping memory. Without this
    // check a malicious sink could make a later row overwrite an earlier one.
    inline for (0..ROW_COUNT) |left_index| {
        const left_row: roster.Component = @enumFromInt(FIRST_ROW + left_index);
        const left_placement = try manifest.placement(left_row);
        const left_offset = placementTreeOffset(left_placement, tree);
        const left_count = geometryColumnCount(left_placement.geometry, tree);
        for (destination[left_offset..][0..left_count], 0..) |left, column_index| {
            var right_row_index: usize = left_index;
            while (right_row_index < ROW_COUNT) : (right_row_index += 1) {
                const right_row: roster.Component = @enumFromInt(FIRST_ROW + right_row_index);
                const right_placement = try manifest.placement(right_row);
                const right_offset = placementTreeOffset(right_placement, tree);
                const right_count = geometryColumnCount(right_placement.geometry, tree);
                const start = if (right_row_index == left_index) column_index + 1 else 0;
                for (destination[right_offset + start ..][0 .. right_count - start]) |right| {
                    if (slicesOverlap(left, right)) return error.DestinationAlias;
                }
            }
        }
    }
}

pub fn slicesOverlap(left: []M31, right: []M31) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = left_start + left.len * @sizeOf(M31);
    const right_end = right_start + right.len * @sizeOf(M31);
    return left_start < right_end and right_start < left_end;
}

pub fn traceSize(log_size: u32) !usize {
    if (log_size >= @bitSizeOf(usize)) return error.ArithmeticOverflow;
    return @as(usize, 1) << @intCast(log_size);
}

pub fn manifestTreeColumnCount(manifest: *const manifest_mod.Manifest, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => manifest.total_main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
        else => unreachable,
    };
}

pub fn placementTreeOffset(placement: manifest_mod.Placement, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
        manifest_mod.MAIN_TREE_INDEX => placement.main_offset,
        manifest_mod.INTERACTION_TREE_INDEX => placement.interaction_offset,
        else => unreachable,
    };
}

pub fn geometryColumnCount(geometry: manifest_mod.Geometry, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => geometry.preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => geometry.main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => geometry.interaction_columns,
        else => unreachable,
    };
}

pub fn sourceColumnCount(index: usize, tree: usize) ?usize {
    const preprocessed = [ROW_COUNT]usize{
        control_air.PREPROCESSED_COLUMN_COUNT,
        transcript_air.PREPROCESSED_COLUMN_COUNT,
        transcript_binding_air.PREPROCESSED_COLUMN_COUNT,
        transcript_state_air.PREPROCESSED_COLUMN_COUNT,
        transcript_word_air.PREPROCESSED_COLUMN_COUNT,
        transcript_payload_air.PREPROCESSED_COLUMN_COUNT,
        pow_check_air.PREPROCESSED_COLUMN_COUNT,
        pow_frame_air.PREPROCESSED_COLUMN_COUNT,
        relation_challenge_air.PREPROCESSED_COLUMN_COUNT,
        verifier_randomness_air.PREPROCESSED_COLUMN_COUNT,
    };
    const main = [ROW_COUNT]usize{
        control_air.PHYSICAL_MAIN_COLUMN_COUNT,
        transcript_air.PHYSICAL_MAIN_COLUMN_COUNT,
        transcript_binding_air.PHYSICAL_MAIN_COLUMN_COUNT,
        transcript_state_air.PHYSICAL_MAIN_COLUMN_COUNT,
        transcript_word_air.PHYSICAL_MAIN_COLUMN_COUNT,
        transcript_payload_air.PHYSICAL_MAIN_COLUMN_COUNT,
        pow_check_air.PHYSICAL_MAIN_COLUMN_COUNT,
        pow_frame_air.PHYSICAL_MAIN_COLUMN_COUNT,
        relation_challenge_air.PHYSICAL_MAIN_COLUMN_COUNT,
        verifier_randomness_air.PHYSICAL_MAIN_COLUMN_COUNT,
    };
    const interaction = [ROW_COUNT]usize{
        ControlFramework.INTERACTION_COLUMN_COUNT,
        TranscriptAirFramework.INTERACTION_COLUMN_COUNT,
        TranscriptBindingFramework.INTERACTION_COLUMN_COUNT,
        TranscriptStateFramework.INTERACTION_COLUMN_COUNT,
        TranscriptWordFramework.INTERACTION_COLUMN_COUNT,
        TranscriptPayloadFramework.INTERACTION_COLUMN_COUNT,
        PowCheckFramework.INTERACTION_COLUMN_COUNT,
        PowFrameFramework.INTERACTION_COLUMN_COUNT,
        RelationChallengeFramework.INTERACTION_COLUMN_COUNT,
        VerifierRandomnessFramework.INTERACTION_COLUMN_COUNT,
    };
    if (index >= ROW_COUNT) return null;
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => preprocessed[index],
        manifest_mod.MAIN_TREE_INDEX => main[index],
        manifest_mod.INTERACTION_TREE_INDEX => interaction[index],
        else => null,
    };
}

comptime {
    if (FIRST_ROW != 0 or LAST_ROW != 9)
        @compileError("binary transcript outer source roster range drifted");
    if (ControlAdapter.PARAMETER_COLUMN_COUNT != 2 or
        TranscriptAirAdapter.PARAMETER_COLUMN_COUNT != 0 or
        TranscriptBindingAdapter.PARAMETER_COLUMN_COUNT != 2 or
        TranscriptStateAdapter.PARAMETER_COLUMN_COUNT != 2 or
        TranscriptWordAdapter.PARAMETER_COLUMN_COUNT != 2 or
        TranscriptPayloadAdapter.PARAMETER_COLUMN_COUNT != 2 or
        PowCheckAdapter.PARAMETER_COLUMN_COUNT != 0 or
        PowFrameAdapter.PARAMETER_COLUMN_COUNT != 0 or
        RelationChallengeAdapter.PARAMETER_COLUMN_COUNT != 4 or
        VerifierRandomnessAdapter.PARAMETER_COLUMN_COUNT != 2)
    {
        @compileError("binary transcript parameter geometry drifted");
    }
}
