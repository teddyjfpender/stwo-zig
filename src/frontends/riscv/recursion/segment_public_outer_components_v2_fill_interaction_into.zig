//! Internal segment public outer components v2 authority shard; use segment_public_outer_components_v2.zig publicly.

const dependency_0 = @import("segment_public_outer_components_v2_contract.zig");
const dependency_1 = @import("segment_public_outer_components_v2_validate_events_for.zig");
const dependency_2 = @import("segment_public_outer_components_v2_workspace.zig");

const BoundaryAdapter = dependency_0.BoundaryAdapter;
const BoundaryRelation = dependency_0.BoundaryRelation;
const ChallengesAdapter = dependency_0.ChallengesAdapter;
const ChallengesRelation = dependency_0.ChallengesRelation;
const Claims = dependency_0.Claims;
const ControlAdapter = dependency_0.ControlAdapter;
const ControlFramework = dependency_0.ControlFramework;
const DomainAudits = dependency_0.DomainAudits;
const Error = dependency_0.Error;
const FIRST_ROW = dependency_0.FIRST_ROW;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const HOT_HEAP_ALLOCATIONS = dependency_0.HOT_HEAP_ALLOCATIONS;
const HeaderAdapter = dependency_0.HeaderAdapter;
const LAST_ROW = dependency_0.LAST_ROW;
const M31 = dependency_0.M31;
const QM31 = dependency_0.QM31;
const RELAY_COMPONENT_INDICES = dependency_0.RELAY_COMPONENT_INDICES;
const ROW_COUNT = dependency_0.ROW_COUNT;
const RelayFramework = dependency_0.RelayFramework;
const RelayRuntime = dependency_0.RelayRuntime;
const SealAdapter = dependency_0.SealAdapter;
const SealRelation = dependency_0.SealRelation;
const Source = dependency_0.Source;
const SumsAdapter = dependency_0.SumsAdapter;
const SumsFramework = dependency_0.SumsFramework;
const Workspace = dependency_2.Workspace;
const air_v2 = dependency_0.air_v2;
const checkedAdd = dependency_1.checkedAdd;
const checkedMul = dependency_2.checkedMul;
const framework = dependency_0.framework;
const manifest_mod = dependency_0.manifest_mod;
const relation = dependency_0.relation;
const relation_interaction = dependency_0.relation_interaction;
const source_v2 = dependency_0.source_v2;
const std = dependency_0.std;
const universal = dependency_0.universal;
const writePhysicalFor = dependency_2.writePhysicalFor;

/// Writes Tree 0 after complete source/cache/manifest/alias admission.
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
    for (RELAY_COMPONENT_INDICES) |index| writePhysicalFor(
        air_v2.PublicationHeader,
        workspace.logical_rows[index],
        manifest.placements[FIRST_ROW + index].?,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        destination,
    );
    writePhysicalFor(
        air_v2.NativePublicSums,
        workspace.claim_hash_logical_rows,
        manifest.placements[FIRST_ROW + 1].?,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        destination,
    );
    writePhysicalFor(
        air_v2.ControlRelay,
        workspace.controlActiveRows(),
        manifest.placements[LAST_ROW].?,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        destination,
    );
}

/// Writes Tree 1 from the same sealed logical rows.
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
    for (RELAY_COMPONENT_INDICES) |index| writePhysicalFor(
        air_v2.PublicationHeader,
        workspace.logical_rows[index],
        manifest.placements[FIRST_ROW + index].?,
        manifest_mod.MAIN_TREE_INDEX,
        destination,
    );
    writePhysicalFor(
        air_v2.NativePublicSums,
        workspace.claim_hash_logical_rows,
        manifest.placements[FIRST_ROW + 1].?,
        manifest_mod.MAIN_TREE_INDEX,
        destination,
    );
    writePhysicalFor(
        air_v2.ControlRelay,
        workspace.controlActiveRows(),
        manifest.placements[LAST_ROW].?,
        manifest_mod.MAIN_TREE_INDEX,
        destination,
    );
}

/// Generates every Tree-2 column into retained private staging. No committed
/// cell changes until all six framework generators return successfully.
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

    const plans = owner.owners.relayPlans();
    var claims: [ROW_COUNT]QM31 = undefined;
    for (plans, RELAY_COMPONENT_INDICES, 0..) |plan, index, local_index| {
        var columns = stagedRelayColumns(workspace, index);
        claims[index] = try RelayFramework.generatePreparedInto(
            &workspace.interactions[local_index],
            plan,
            workspace.logical_rows[index],
            workspace.log_sizes[index],
            relations,
            &columns,
        );
    }
    var claim_hash_columns = stagedClaimHashColumns(workspace);
    claims[1] = try SumsFramework.generatePreparedInto(
        &workspace.claim_hash_interaction,
        &owner.owners.native_public_sums.relation,
        workspace.claim_hash_logical_rows,
        workspace.log_sizes[1],
        relations,
        &claim_hash_columns,
    );
    var control_columns = stagedControlColumns(workspace);
    claims[ROW_COUNT - 1] = try ControlFramework.generatePreparedInto(
        &workspace.control_interaction,
        &owner.owners.control_relay.relation,
        workspace.controlActiveRows(),
        workspace.log_sizes[ROW_COUNT - 1],
        relations,
        &control_columns,
    );
    for (RELAY_COMPONENT_INDICES) |index| commitInteraction(
        workspace,
        index,
        manifest.placements[FIRST_ROW + index].?,
        RelayFramework.INTERACTION_COLUMN_COUNT,
        destination,
    );
    commitInteraction(
        workspace,
        1,
        manifest.placements[FIRST_ROW + 1].?,
        SumsFramework.INTERACTION_COLUMN_COUNT,
        destination,
    );
    commitInteraction(
        workspace,
        ROW_COUNT - 1,
        manifest.placements[LAST_ROW].?,
        ControlFramework.INTERACTION_COLUMN_COUNT,
        destination,
    );
    return claimsFromArray(claims);
}

/// Cold diagnostic decomposition of the exact rows used for Tree 2. Rows
/// 12--17 intentionally own no row-35 range contribution.
pub fn auditInteractionDomains(
    allocator: std.mem.Allocator,
    owner: *const Source,
    workspace: *const Workspace,
    prepared: *const source_v2.PreparedV2,
    relations: *const universal.UniversalRelations,
    claims: Claims,
    tuple_ledger: ?*relation_interaction.TupleLedger,
) !DomainAudits {
    try workspace.validateAgainst(prepared);
    try relations.validate();
    const plans = owner.owners.relayPlans();
    const claim_values = claims.asArray();
    var result: DomainAudits = undefined;
    for (plans, RELAY_COMPONENT_INDICES) |plan, index| {
        result[index] = try plan.auditPreparedDomainSums(
            allocator,
            workspace.logical_rows[index],
            relations,
            claim_values[index],
        );
        if (!result[index].values[
            @intFromEnum(relation.Domain.range_check_8_8)
        ].isZero()) return error.EventProjectionMismatch;
        if (tuple_ledger) |ledger| try plan.appendPreparedTupleContributions(
            ledger,
            @intCast(FIRST_ROW + index),
            workspace.logical_rows[index],
            relation_interaction.allDomainMask(),
        );
    }
    result[1] = try owner.owners.native_public_sums.relation
        .auditPreparedDomainSums(
        allocator,
        workspace.claim_hash_logical_rows,
        relations,
        claim_values[1],
    );
    if (!result[1].values[
        @intFromEnum(relation.Domain.range_check_8_8)
    ].isZero()) return error.EventProjectionMismatch;
    if (tuple_ledger) |ledger| try owner.owners.native_public_sums.relation
        .appendPreparedTupleContributions(
        ledger,
        FIRST_ROW + 1,
        workspace.claim_hash_logical_rows,
        relation_interaction.allDomainMask(),
    );
    result[ROW_COUNT - 1] = try owner.owners.control_relay.relation
        .auditPreparedDomainSums(
        allocator,
        workspace.controlActiveRows(),
        relations,
        claim_values[ROW_COUNT - 1],
    );
    if (tuple_ledger) |ledger| try owner.owners.control_relay.relation
        .appendPreparedTupleContributions(
        ledger,
        LAST_ROW,
        workspace.controlActiveRows(),
        relation_interaction.allDomainMask(),
    );
    return result;
}

pub fn claimsFromArray(values: [ROW_COUNT]QM31) Claims {
    return .{
        .publication_header = values[0],
        .native_public_sums = values[1],
        .publication_seal = values[2],
        .boundary_bridge = values[3],
        .native_challenges = values[4],
        .control_relay = values[5],
    };
}

pub fn stagedRelayColumns(
    workspace: *Workspace,
    index: usize,
) [RelayFramework.INTERACTION_COLUMN_COUNT][]M31 {
    const size = traceSize(workspace.log_sizes[index]) catch unreachable;
    const start = workspace.interaction_offsets[index];
    var result: [RelayFramework.INTERACTION_COLUMN_COUNT][]M31 = undefined;
    for (&result, 0..) |*column, local_index|
        column.* = workspace.interaction_stage[start + local_index * size ..][0..size];
    return result;
}

pub fn stagedControlColumns(
    workspace: *Workspace,
) [ControlFramework.INTERACTION_COLUMN_COUNT][]M31 {
    const index = ROW_COUNT - 1;
    const size = traceSize(workspace.log_sizes[index]) catch unreachable;
    const start = workspace.interaction_offsets[index];
    var result: [ControlFramework.INTERACTION_COLUMN_COUNT][]M31 = undefined;
    for (&result, 0..) |*column, local_index|
        column.* = workspace.interaction_stage[start + local_index * size ..][0..size];
    return result;
}

pub fn stagedClaimHashColumns(
    workspace: *Workspace,
) [SumsFramework.INTERACTION_COLUMN_COUNT][]M31 {
    const index: usize = 1;
    const size = traceSize(workspace.log_sizes[index]) catch unreachable;
    const start = workspace.interaction_offsets[index];
    var result: [SumsFramework.INTERACTION_COLUMN_COUNT][]M31 = undefined;
    for (&result, 0..) |*column, local_index|
        column.* = workspace.interaction_stage[start + local_index * size ..][0..size];
    return result;
}

pub fn commitInteraction(
    workspace: *const Workspace,
    index: usize,
    placement: manifest_mod.Placement,
    column_count: usize,
    destination: []const []M31,
) void {
    const size = traceSize(workspace.log_sizes[index]) catch unreachable;
    const source_start = workspace.interaction_offsets[index];
    const destination_start: usize = placement.interaction_offset;
    for (0..column_count) |column| @memcpy(
        destination[destination_start + column],
        workspace.interaction_stage[source_start + column * size ..][0..size],
    );
}

pub fn preflightExternalAlias(
    destination: []const []M31,
    manifest: *const manifest_mod.Manifest,
    relations: *const universal.UniversalRelations,
) !void {
    for (0..ROW_COUNT) |index| {
        const placement = manifest.placements[FIRST_ROW + index].?;
        const start: usize = placement.interaction_offset;
        const count: usize = placement.geometry.interaction_columns;
        for (destination[start..][0..count]) |column| if (try slicesOverlapAny(
            column,
            std.mem.asBytes(relations)[0..],
        )) return error.DestinationAlias;
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

    for (0..ROW_COUNT) |index| {
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
            for (destination, 0..) |other, other_index| if (other_index != global_index and
                try slicesOverlapAny(column, other)) return error.DestinationAlias;
        }
    }
}

pub fn workspaceOverlaps(workspace: *const Workspace, target: anytype) !bool {
    if (try slicesOverlapAny(std.mem.asBytes(workspace)[0..], target) or
        try slicesOverlapAny(workspace.relation_events, target) or
        try slicesOverlapAny(workspace.interaction_stage, target) or
        try slicesOverlapAny(workspace.arithmetic_use_count_scratch, target))
    {
        return true;
    }
    for (workspace.source_rows) |rows| if (try slicesOverlapAny(rows, target))
        return true;
    for (workspace.logical_rows) |rows| if (try slicesOverlapAny(rows, target))
        return true;
    if (try slicesOverlapAny(workspace.claim_hash_call_scratch, target) or
        try slicesOverlapAny(workspace.claim_hash_logical_rows, target) or
        try slicesOverlapAny(workspace.claim_hash_relation_events, target) or
        try slicesOverlapAny(workspace.claim_hash_interaction.scratch, target))
    {
        return true;
    }
    for (workspace.control_main) |column| if (try slicesOverlapAny(column, target))
        return true;
    for (workspace.control_preprocessed) |column| if (try slicesOverlapAny(
        column,
        target,
    )) return true;
    if (try slicesOverlapAny(workspace.control_physical_rows, target) or
        try slicesOverlapAny(workspace.control_relation_events, target) or
        try slicesOverlapAny(workspace.control_interaction.scratch, target))
    {
        return true;
    }
    for (&workspace.interactions) |*interaction| if (try slicesOverlapAny(
        interaction.scratch,
        target,
    )) return true;
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
        manifest_mod.PREPROCESSED_TREE_INDEX => @intCast(manifest.total_preprocessed_columns),
        manifest_mod.MAIN_TREE_INDEX => @intCast(manifest.total_main_columns),
        manifest_mod.INTERACTION_TREE_INDEX => @intCast(manifest.total_interaction_columns),
        else => unreachable,
    };
}

pub fn placementTreeOffset(
    placement: manifest_mod.Placement,
    tree: usize,
) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => @intCast(placement.preprocessed_offset),
        manifest_mod.MAIN_TREE_INDEX => @intCast(placement.main_offset),
        manifest_mod.INTERACTION_TREE_INDEX => @intCast(placement.interaction_offset),
        else => unreachable,
    };
}

pub fn geometryColumnCount(
    geometry: manifest_mod.Geometry,
    tree: usize,
) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => @intCast(geometry.preprocessed_columns),
        manifest_mod.MAIN_TREE_INDEX => @intCast(geometry.main_columns),
        manifest_mod.INTERACTION_TREE_INDEX => @intCast(geometry.interaction_columns),
        else => unreachable,
    };
}

pub fn traceSize(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return error.ArithmeticOverflow;
    return @as(usize, 1) << @intCast(log_size);
}

comptime {
    if (FORMAT_VERSION != 2 or FIRST_ROW != 12 or LAST_ROW != 17 or
        ROW_COUNT != 6 or HOT_HEAP_ALLOCATIONS != 0 or
        RelayFramework.INTERACTION_COLUMN_COUNT != 8 or
        HeaderAdapter.PARAMETER_COLUMN_COUNT != 1 or
        SumsAdapter.PARAMETER_COLUMN_COUNT != 1 or
        SealAdapter.PARAMETER_COLUMN_COUNT != 1 or
        BoundaryAdapter.PARAMETER_COLUMN_COUNT != 1 or
        ChallengesAdapter.PARAMETER_COLUMN_COUNT != 1 or
        ControlAdapter.PARAMETER_COLUMN_COUNT != 0 or
        SealRelation.Runtime != RelayRuntime or
        BoundaryRelation.Runtime != RelayRuntime or
        ChallengesRelation.Runtime != RelayRuntime or
        SumsFramework.INTERACTION_COLUMN_COUNT != 12 or
        ControlFramework.INTERACTION_COLUMN_COUNT != 4)
    {
        @compileError("V2 public component geometry drifted");
    }
}
