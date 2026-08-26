//! Internal segment transcript outer components v2 authority shard; use segment_transcript_outer_components_v2.zig publicly.

const dependency_0 = @import("segment_transcript_outer_components_v2_contract.zig");
const dependency_1 = @import("segment_transcript_outer_components_v2_source.zig");
const dependency_2 = @import("segment_transcript_outer_components_v2_workspace.zig");

const Claims = dependency_0.Claims;
const ControlFramework = dependency_0.ControlFramework;
const FIRST_ROW = dependency_0.FIRST_ROW;
const M31 = dependency_0.M31;
const PowCheckFramework = dependency_0.PowCheckFramework;
const PowFrameFramework = dependency_0.PowFrameFramework;
const ROW_COUNT = dependency_0.ROW_COUNT;
const RelationChallengeFramework = dependency_0.RelationChallengeFramework;
const Source = dependency_1.Source;
const TranscriptAirFramework = dependency_0.TranscriptAirFramework;
const TranscriptBindingFramework = dependency_0.TranscriptBindingFramework;
const TranscriptPayloadFramework = dependency_0.TranscriptPayloadFramework;
const TranscriptStateFramework = dependency_0.TranscriptStateFramework;
const TranscriptWordFramework = dependency_0.TranscriptWordFramework;
const VerifierRandomnessFramework = dependency_0.VerifierRandomnessFramework;
const Workspace = dependency_2.Workspace;
const checkedAdd = dependency_1.checkedAdd;
const checkedMul = dependency_1.checkedMul;
const control_air = dependency_0.control_air;
const framework = dependency_0.framework;
const interactionColumnCount = dependency_1.interactionColumnCount;
const manifest_mod = dependency_0.manifest_mod;
const pow_check_air = dependency_0.pow_check_air;
const pow_frame_air = dependency_0.pow_frame_air;
const relation_challenge_air = dependency_0.relation_challenge_air;
const rowIndex = dependency_0.rowIndex;
const source_v2 = dependency_0.source_v2;
const std = dependency_0.std;
const traceSize = dependency_1.traceSize;
const transcript = dependency_0.transcript;
const transcript_air = dependency_0.transcript_air;
const transcript_binding_air = dependency_0.transcript_binding_air;
const transcript_payload_air = dependency_0.transcript_payload_air;
const transcript_state_air = dependency_0.transcript_state_air;
const transcript_word_air = dependency_0.transcript_word_air;
const universal = dependency_0.universal;
const verifier_randomness_air = dependency_0.verifier_randomness_air;

/// Writes Tree 0 for universal rows 0--9 from the sealed V2 cache. All shape,
/// authority, alias, and cache-integrity checks precede the first store.
pub fn fillPreprocessedInto(
    owner: *const Source,
    workspace: *const Workspace,
    prepared: *const source_v2.PreparedV2,
    manifest: *const manifest_mod.Manifest,
    destination: []const []M31,
) !void {
    try owner.validateAgainst(prepared, manifest);
    try workspace.validateAgainst(prepared);
    try preflightTree(
        workspace,
        prepared,
        manifest,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        destination,
    );
    writePhysical(
        control_air,
        workspace.control_rows,
        manifest.placements[manifest_mod.keyIndex(.control)].?,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        destination,
    );
    writePhysical(
        transcript_air,
        workspace.transcript_air_rows,
        manifest.placements[manifest_mod.keyIndex(.transcript_air)].?,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        destination,
    );
    writePhysical(
        transcript_binding_air,
        workspace.transcript_binding_rows,
        manifest.placements[manifest_mod.keyIndex(.transcript_binding)].?,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        destination,
    );
    writePhysical(
        transcript_state_air,
        workspace.transcript_state_rows,
        manifest.placements[manifest_mod.keyIndex(.transcript_state)].?,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        destination,
    );
    writePhysical(
        transcript_word_air,
        workspace.transcript_word_rows,
        manifest.placements[manifest_mod.keyIndex(.transcript_word)].?,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        destination,
    );
    writePhysical(
        transcript_payload_air,
        workspace.transcript_payload_rows,
        manifest.placements[manifest_mod.keyIndex(.transcript_payload)].?,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        destination,
    );
    writePhysical(
        pow_check_air,
        workspace.pow_check_rows,
        manifest.placements[manifest_mod.keyIndex(.pow_check)].?,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        destination,
    );
    writePhysical(
        pow_frame_air,
        workspace.pow_frame_rows,
        manifest.placements[manifest_mod.keyIndex(.pow_frame)].?,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        destination,
    );
    writePhysical(
        relation_challenge_air,
        workspace.relation_challenge_rows,
        manifest.placements[manifest_mod.keyIndex(.relation_challenge)].?,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        destination,
    );
    writePhysical(
        verifier_randomness_air,
        workspace.verifier_randomness_rows,
        manifest.placements[manifest_mod.keyIndex(.verifier_randomness)].?,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        destination,
    );
}

/// Writes Tree 1 for universal rows 0--9 from the same sealed logical rows.
pub fn fillMainInto(
    owner: *const Source,
    workspace: *const Workspace,
    prepared: *const source_v2.PreparedV2,
    manifest: *const manifest_mod.Manifest,
    destination: []const []M31,
) !void {
    try owner.validateAgainst(prepared, manifest);
    try workspace.validateAgainst(prepared);
    try preflightTree(
        workspace,
        prepared,
        manifest,
        manifest_mod.MAIN_TREE_INDEX,
        destination,
    );
    writePhysical(
        control_air,
        workspace.control_rows,
        manifest.placements[manifest_mod.keyIndex(.control)].?,
        manifest_mod.MAIN_TREE_INDEX,
        destination,
    );
    writePhysical(
        transcript_air,
        workspace.transcript_air_rows,
        manifest.placements[manifest_mod.keyIndex(.transcript_air)].?,
        manifest_mod.MAIN_TREE_INDEX,
        destination,
    );
    writePhysical(
        transcript_binding_air,
        workspace.transcript_binding_rows,
        manifest.placements[manifest_mod.keyIndex(.transcript_binding)].?,
        manifest_mod.MAIN_TREE_INDEX,
        destination,
    );
    writePhysical(
        transcript_state_air,
        workspace.transcript_state_rows,
        manifest.placements[manifest_mod.keyIndex(.transcript_state)].?,
        manifest_mod.MAIN_TREE_INDEX,
        destination,
    );
    writePhysical(
        transcript_word_air,
        workspace.transcript_word_rows,
        manifest.placements[manifest_mod.keyIndex(.transcript_word)].?,
        manifest_mod.MAIN_TREE_INDEX,
        destination,
    );
    writePhysical(
        transcript_payload_air,
        workspace.transcript_payload_rows,
        manifest.placements[manifest_mod.keyIndex(.transcript_payload)].?,
        manifest_mod.MAIN_TREE_INDEX,
        destination,
    );
    writePhysical(
        pow_check_air,
        workspace.pow_check_rows,
        manifest.placements[manifest_mod.keyIndex(.pow_check)].?,
        manifest_mod.MAIN_TREE_INDEX,
        destination,
    );
    writePhysical(
        pow_frame_air,
        workspace.pow_frame_rows,
        manifest.placements[manifest_mod.keyIndex(.pow_frame)].?,
        manifest_mod.MAIN_TREE_INDEX,
        destination,
    );
    writePhysical(
        relation_challenge_air,
        workspace.relation_challenge_rows,
        manifest.placements[manifest_mod.keyIndex(.relation_challenge)].?,
        manifest_mod.MAIN_TREE_INDEX,
        destination,
    );
    writePhysical(
        verifier_randomness_air,
        workspace.verifier_randomness_rows,
        manifest.placements[manifest_mod.keyIndex(.verifier_randomness)].?,
        manifest_mod.MAIN_TREE_INDEX,
        destination,
    );
}

/// Generates all ten framework LogUp traces into retained private staging,
/// then commits Tree 2 only after every denominator, claim, and prefix check
/// succeeds. A failing later row can never expose an earlier partial trace.
pub fn fillInteractionInto(
    owner: *const Source,
    workspace: *Workspace,
    prepared: *const source_v2.PreparedV2,
    manifest: *const manifest_mod.Manifest,
    relations: *const universal.UniversalRelations,
    destination: []const []M31,
) !Claims {
    try owner.validateAgainst(prepared, manifest);
    try workspace.validateAgainst(prepared);
    try relations.validate();
    try preflightTree(
        workspace,
        prepared,
        manifest,
        manifest_mod.INTERACTION_TREE_INDEX,
        destination,
    );
    try preflightExternalAlias(destination, manifest, relations);

    var control_columns = stagedColumns(
        ControlFramework,
        workspace,
        rowIndex(.control),
    );
    const control_claim = try ControlFramework.generatePreparedInto(
        &workspace.control_interaction,
        &owner.owners.control.relation,
        workspace.control_rows,
        workspace.log_sizes[rowIndex(.control)],
        relations,
        &control_columns,
    );
    var transcript_air_columns = stagedColumns(
        TranscriptAirFramework,
        workspace,
        rowIndex(.transcript_air),
    );
    const transcript_air_claim = try TranscriptAirFramework.generatePreparedInto(
        &workspace.transcript_air_interaction,
        &owner.owners.transcript_air.relation,
        workspace.transcript_air_rows,
        workspace.log_sizes[rowIndex(.transcript_air)],
        relations,
        &transcript_air_columns,
    );
    var transcript_binding_columns = stagedColumns(
        TranscriptBindingFramework,
        workspace,
        rowIndex(.transcript_binding),
    );
    const transcript_binding_claim =
        try TranscriptBindingFramework.generatePreparedInto(
            &workspace.transcript_binding_interaction,
            &owner.owners.transcript_binding.relation,
            workspace.transcript_binding_rows,
            workspace.log_sizes[rowIndex(.transcript_binding)],
            relations,
            &transcript_binding_columns,
        );
    var transcript_state_columns = stagedColumns(
        TranscriptStateFramework,
        workspace,
        rowIndex(.transcript_state),
    );
    const transcript_state_claim =
        try TranscriptStateFramework.generatePreparedInto(
            &workspace.transcript_state_interaction,
            &owner.owners.transcript_state.relation,
            workspace.transcript_state_rows,
            workspace.log_sizes[rowIndex(.transcript_state)],
            relations,
            &transcript_state_columns,
        );
    var transcript_word_columns = stagedColumns(
        TranscriptWordFramework,
        workspace,
        rowIndex(.transcript_word),
    );
    const transcript_word_claim = try TranscriptWordFramework.generatePreparedInto(
        &workspace.transcript_word_interaction,
        &owner.owners.transcript_word.relation,
        workspace.transcript_word_rows,
        workspace.log_sizes[rowIndex(.transcript_word)],
        relations,
        &transcript_word_columns,
    );
    var transcript_payload_columns = stagedColumns(
        TranscriptPayloadFramework,
        workspace,
        rowIndex(.transcript_payload),
    );
    const transcript_payload_claim =
        try TranscriptPayloadFramework.generatePreparedInto(
            &workspace.transcript_payload_interaction,
            &owner.owners.transcript_payload.relation,
            workspace.transcript_payload_rows,
            workspace.log_sizes[rowIndex(.transcript_payload)],
            relations,
            &transcript_payload_columns,
        );
    var pow_check_columns = stagedColumns(
        PowCheckFramework,
        workspace,
        rowIndex(.pow_check),
    );
    const pow_check_claim = try PowCheckFramework.generatePreparedInto(
        &workspace.pow_check_interaction,
        &owner.owners.pow_check.relation,
        workspace.pow_check_rows,
        workspace.log_sizes[rowIndex(.pow_check)],
        relations,
        &pow_check_columns,
    );
    var pow_frame_columns = stagedColumns(
        PowFrameFramework,
        workspace,
        rowIndex(.pow_frame),
    );
    const pow_frame_claim = try PowFrameFramework.generatePreparedInto(
        &workspace.pow_frame_interaction,
        &owner.owners.pow_frame.relation,
        workspace.pow_frame_rows,
        workspace.log_sizes[rowIndex(.pow_frame)],
        relations,
        &pow_frame_columns,
    );
    var relation_challenge_columns = stagedColumns(
        RelationChallengeFramework,
        workspace,
        rowIndex(.relation_challenge),
    );
    const relation_challenge_claim =
        try RelationChallengeFramework.generatePreparedInto(
            &workspace.relation_challenge_interaction,
            &owner.owners.relation_challenge.relation,
            workspace.relation_challenge_rows,
            workspace.log_sizes[rowIndex(.relation_challenge)],
            relations,
            &relation_challenge_columns,
        );
    var verifier_randomness_columns = stagedColumns(
        VerifierRandomnessFramework,
        workspace,
        rowIndex(.verifier_randomness),
    );
    const verifier_randomness_claim =
        try VerifierRandomnessFramework.generatePreparedInto(
            &workspace.verifier_randomness_interaction,
            &owner.owners.verifier_randomness.relation,
            workspace.verifier_randomness_rows,
            workspace.log_sizes[rowIndex(.verifier_randomness)],
            relations,
            &verifier_randomness_columns,
        );

    const claims = Claims{
        .control = control_claim,
        .transcript_air = transcript_air_claim,
        .transcript_binding = transcript_binding_claim,
        .transcript_state = transcript_state_claim,
        .transcript_word = transcript_word_claim,
        .transcript_payload = transcript_payload_claim,
        .pow_check = pow_check_claim,
        .pow_frame = pow_frame_claim,
        .relation_challenge = relation_challenge_claim,
        .verifier_randomness = verifier_randomness_claim,
    };

    inline for (0..ROW_COUNT) |index| {
        commitInteraction(
            workspace,
            index,
            manifest.placements[FIRST_ROW + index].?,
            destination,
        );
    }
    return claims;
}

/// Publishes only this transcript source's authenticated half-open interval in
/// the one caller-owned row-34 ProviderCall stream. No provider component or
/// second permutation trace is created here.
pub fn writeProviderCallsInto(
    workspace: *const Workspace,
    prepared: *const source_v2.PreparedV2,
    range: *const source_v2.PoseidonRequestRangeV2,
    shared_stream: []source_v2.ProviderCall,
) !void {
    try workspace.validateAgainst(prepared);
    range.validateAgainst(prepared) catch return error.InvalidProviderRange;
    const first: usize = range.first;
    const end: usize = range.end;
    if (first > end or end > shared_stream.len or
        end - first != workspace.provider_calls.len)
    {
        return error.InvalidProviderRange;
    }
    const target = shared_stream[first..end];
    if (try workspaceOverlaps(workspace, target) or
        try slicesOverlapAny(target, std.mem.asBytes(prepared)[0..]) or
        try slicesOverlapAny(target, std.mem.asBytes(range)[0..]))
    {
        return error.DestinationAlias;
    }
    @memcpy(target, workspace.provider_calls);
}

pub fn stagedColumns(
    comptime Framework: type,
    workspace: *Workspace,
    index: usize,
) [Framework.INTERACTION_COLUMN_COUNT][]M31 {
    const size = traceSize(workspace.log_sizes[index]) catch unreachable;
    const start = workspace.interaction_offsets[index];
    var result: [Framework.INTERACTION_COLUMN_COUNT][]M31 = undefined;
    for (&result, 0..) |*column, local_index| {
        column.* = workspace.interaction_stage[start + local_index * size ..][0..size];
    }
    return result;
}

pub fn commitInteraction(
    workspace: *const Workspace,
    index: usize,
    placement: manifest_mod.Placement,
    destination: []const []M31,
) void {
    const size = traceSize(workspace.log_sizes[index]) catch unreachable;
    const count = interactionColumnCount(index);
    const source_start = workspace.interaction_offsets[index];
    const destination_start: usize = placement.interaction_offset;
    for (0..count) |column| {
        @memcpy(
            destination[destination_start + column],
            workspace.interaction_stage[source_start + column * size ..][0..size],
        );
    }
}

pub fn preflightExternalAlias(
    destination: []const []M31,
    manifest: *const manifest_mod.Manifest,
    relations: *const universal.UniversalRelations,
) !void {
    inline for (0..ROW_COUNT) |index| {
        const placement = manifest.placements[FIRST_ROW + index].?;
        const start: usize = placement.interaction_offset;
        const count: usize = placement.geometry.interaction_columns;
        for (destination[start..][0..count]) |column| {
            if (try slicesOverlapAny(
                column,
                std.mem.asBytes(relations)[0..],
            )) return error.DestinationAlias;
        }
    }
}

pub fn writePhysical(
    comptime Air: type,
    rows: []const [Air.LOGICAL_INPUT_COUNT]M31,
    placement: manifest_mod.Placement,
    tree: usize,
    destination: []const []M31,
) void {
    const local_count = switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => Air.PREPROCESSED_COLUMN_COUNT,
        manifest_mod.MAIN_TREE_INDEX => Air.PHYSICAL_MAIN_COLUMN_COUNT,
        else => unreachable,
    };
    const input_start = if (tree == manifest_mod.PREPROCESSED_TREE_INDEX)
        Air.PHYSICAL_MAIN_COLUMN_COUNT
    else
        0;
    const output_start: usize = switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
        manifest_mod.MAIN_TREE_INDEX => placement.main_offset,
        else => unreachable,
    };
    for (destination[output_start..][0..local_count]) |column|
        @memset(column, M31.zero());
    for (rows, 0..) |row, logical_row| {
        const committed_row = framework.committedRow(
            logical_row,
            placement.geometry.log_size,
        );
        for (0..local_count) |column| {
            destination[output_start + column][committed_row] =
                row[input_start + column];
        }
    }
}

pub fn preflightTree(
    workspace: *const Workspace,
    prepared: *const source_v2.PreparedV2,
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    destination: []const []M31,
) !void {
    try manifest.validate();
    if (tree >= manifest_mod.TREE_COUNT) return error.InvalidTreeIndex;
    if (destination.len != manifestTreeColumnCount(manifest, tree))
        return error.DestinationColumnCountMismatch;

    inline for (0..ROW_COUNT) |index| {
        const placement = manifest.placements[FIRST_ROW + index] orelse
            return error.ManifestGeometryMismatch;
        const offset = placementTreeOffset(placement, tree);
        const count = geometryColumnCount(placement.geometry, tree);
        const size = try traceSize(placement.geometry.log_size);
        if (offset > destination.len or count > destination.len - offset)
            return error.DestinationColumnCountMismatch;
        for (destination[offset..][0..count], 0..) |column, local_index| {
            if (column.len != size) return error.DestinationLogSizeMismatch;
            if (try workspaceOverlaps(workspace, column) or
                try slicesOverlapAny(column, std.mem.asBytes(prepared)[0..]) or
                try slicesOverlapAny(column, std.mem.asBytes(manifest)[0..]))
            {
                return error.DestinationAlias;
            }
            const global_index = offset + local_index;
            for (destination, 0..) |other, other_index| {
                if (other_index != global_index and
                    try slicesOverlapAny(column, other))
                {
                    return error.DestinationAlias;
                }
            }
        }
    }
}

pub fn workspaceOverlaps(workspace: *const Workspace, target: anytype) !bool {
    if (try slicesOverlapAny(std.mem.asBytes(workspace)[0..], target) or
        try slicesOverlapAny(workspace.control_source, target) or
        try slicesOverlapAny(workspace.transcript_air_source, target) or
        try slicesOverlapAny(workspace.transcript_binding_source, target) or
        try slicesOverlapAny(workspace.transcript_state_source, target) or
        try slicesOverlapAny(workspace.transcript_word_source, target) or
        try slicesOverlapAny(workspace.transcript_payload_source, target) or
        try slicesOverlapAny(workspace.pow_check_source, target) or
        try slicesOverlapAny(workspace.pow_frame_source, target) or
        try slicesOverlapAny(workspace.relation_challenge_source, target) or
        try slicesOverlapAny(workspace.verifier_randomness_source, target) or
        try slicesOverlapAny(workspace.relation_events, target) or
        try slicesOverlapAny(workspace.provider_calls, target) or
        try slicesOverlapAny(workspace.control_rows, target) or
        try slicesOverlapAny(workspace.transcript_air_rows, target) or
        try slicesOverlapAny(workspace.transcript_binding_rows, target) or
        try slicesOverlapAny(workspace.transcript_state_rows, target) or
        try slicesOverlapAny(workspace.transcript_word_rows, target) or
        try slicesOverlapAny(workspace.transcript_payload_rows, target) or
        try slicesOverlapAny(workspace.pow_check_rows, target) or
        try slicesOverlapAny(workspace.pow_frame_rows, target) or
        try slicesOverlapAny(workspace.relation_challenge_rows, target) or
        try slicesOverlapAny(workspace.verifier_randomness_rows, target) or
        try slicesOverlapAny(workspace.control_interaction.scratch, target) or
        try slicesOverlapAny(workspace.transcript_air_interaction.scratch, target) or
        try slicesOverlapAny(workspace.transcript_binding_interaction.scratch, target) or
        try slicesOverlapAny(workspace.transcript_state_interaction.scratch, target) or
        try slicesOverlapAny(workspace.transcript_word_interaction.scratch, target) or
        try slicesOverlapAny(workspace.transcript_payload_interaction.scratch, target) or
        try slicesOverlapAny(workspace.pow_check_interaction.scratch, target) or
        try slicesOverlapAny(workspace.pow_frame_interaction.scratch, target) or
        try slicesOverlapAny(workspace.relation_challenge_interaction.scratch, target) or
        try slicesOverlapAny(workspace.verifier_randomness_interaction.scratch, target) or
        try slicesOverlapAny(workspace.interaction_stage, target))
    {
        return true;
    }
    return false;
}

pub const AddressRange = struct {
    start: usize,
    end: usize,

    fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

pub fn slicesOverlapAny(left: anytype, right: anytype) !bool {
    if (left.len == 0 or right.len == 0) return false;
    return (try sliceRangeAny(left)).overlaps(try sliceRangeAny(right));
}

pub fn sliceRangeAny(values: anytype) !AddressRange {
    const byte_len = try checkedMul(
        values.len,
        @sizeOf(std.meta.Elem(@TypeOf(values))),
    );
    const start = @intFromPtr(values.ptr);
    return .{
        .start = start,
        .end = try checkedAdd(start, byte_len),
    };
}

pub fn manifestTreeColumnCount(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => manifest.total_main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
        else => unreachable,
    };
}

pub fn placementTreeOffset(
    placement: manifest_mod.Placement,
    tree: usize,
) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
        manifest_mod.MAIN_TREE_INDEX => placement.main_offset,
        manifest_mod.INTERACTION_TREE_INDEX => placement.interaction_offset,
        else => unreachable,
    };
}

pub fn geometryColumnCount(
    geometry: manifest_mod.Geometry,
    tree: usize,
) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => geometry.preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => geometry.main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => geometry.interaction_columns,
        else => unreachable,
    };
}
