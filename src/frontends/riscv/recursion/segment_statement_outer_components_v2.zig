//! Concrete typed-component and commitment-tree bridge for SegmentV2 rows
//! 10 and 11.
//!
//! Row 10 remains an admitted, explicit typed component, but its physical
//! columns, verifier-owned parameters, relation weights, and claim are all
//! zero. Row 11 is populated exclusively from the authenticated statement
//! source. This module is deliberately equation-free: component geometry,
//! direct constraints, and relation plans come from the two typed AIRs.
//!
//! All three tree writers are allocation-free after `WorkspaceV2.init`.
//! Interaction columns are generated into private retained staging and are
//! copied to commitment storage only after both the inactive-row invariant
//! and the complete row-11 LogUp generation succeed.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

const row10_air = @import("air/statement_input.zig");
const relation_binding = @import("air/universal_relation_binding.zig");
const direct_program = @import("air/direct_constraint_program.zig");
const framework = @import("air/framework_interaction.zig");
const manifest_mod = @import("air/segment_outer_adapter_manifest_v2.zig");
const relation_interaction = @import("air/relation_interaction.zig");
const typed_component = @import("air/universal_typed_component.zig");
const universal = @import("air/universal_challenges.zig");
const statement = @import("segment_statement_outer_source_v2.zig");

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const FIRST_ROW: u8 = statement.FROZEN_ROW_10;
pub const LAST_ROW: u8 = statement.ROUTING_ROW_11;
pub const ROW_COUNT: usize = 2;
pub const ROW10_LOG_SIZE: u32 = 4;
pub const ROW10_TRACE_ROWS: usize = 1 << ROW10_LOG_SIZE;
pub const HOT_HEAP_ALLOCATIONS: usize = 0;
pub const TREE_WRITES_FAIL_BEFORE_FIRST_WRITE = true;
pub const ROW10_EXPLICITLY_INACTIVE = true;
pub const PRODUCTION_ACTIVATION = false;

const Row10Relation = relation_binding.Binding(row10_air);
const Row11Relation = relation_binding.Binding(statement.Air);
const Row10Framework = framework.Runtime(Row10Relation.Runtime);

pub const Row10AdapterV2 = typed_component.ComponentForManifest(
    row10_air,
    Row10Relation,
    manifest_mod,
);
pub const Row11AdapterV2 = typed_component.ComponentForManifest(
    statement.Air,
    Row11Relation,
    manifest_mod,
);

pub const Error = error{
    ArithmeticOverflow,
    DestinationAlias,
    DestinationColumnCountMismatch,
    DestinationLogSizeMismatch,
    InactiveRowInvariantMismatch,
    InvalidTreeIndex,
    ManifestGeometryMismatch,
    PreparedAuthorityMismatch,
    WorkspaceGeometryMismatch,
};

pub const ClaimsV2 = struct {
    row10_inactive: QM31 = QM31.zero(),
    row11_statement: QM31,

    pub fn validate(self: ClaimsV2) Error!void {
        if (!self.row10_inactive.isZero())
            return error.InactiveRowInvariantMismatch;
    }

    pub fn asArray(self: ClaimsV2) [ROW_COUNT]QM31 {
        return .{ self.row10_inactive, self.row11_statement };
    }

    pub fn bindInto(
        self: ClaimsV2,
        vector: *manifest_mod.ClaimVector,
    ) !void {
        try self.validate();
        try vector.bind(.statement_input, self.row10_inactive);
        try vector.bind(.statement_semantics_input, self.row11_statement);
    }
};

pub const ComponentsV2 = struct {
    row10_inactive: Row10AdapterV2,
    row11_statement: Row11AdapterV2,

    pub fn appendToGate(
        self: *const ComponentsV2,
        manifest: *const manifest_mod.Manifest,
        gate: *manifest_mod.ProofGate,
    ) !void {
        try gate.append(manifest, try self.row10_inactive.binding(manifest));
        try gate.append(manifest, try self.row11_statement.binding(manifest));
    }
};

/// Cold, owning authority for both typed programs. The row-11 member is also
/// the exact authority accepted by `segment_statement_outer_source_v2`, so a
/// caller never has to construct two independently authenticated copies.
pub const AuthorityV2 = struct {
    allocator: std.mem.Allocator,
    row10_definition: row10_air.Definition,
    row10_relation: Row10Relation.Plan,
    row10_direct: direct_program.Program,
    row11: statement.AuthorityV2,

    pub fn init(allocator: std.mem.Allocator) !AuthorityV2 {
        var row10_definition = try row10_air.build(allocator);
        errdefer row10_definition.deinit();
        const row10_relation = try Row10Relation.authenticate(
            &row10_definition,
        );
        const row10_direct = try direct_program.authenticate(
            &row10_definition.arena,
            row10_air.SEMANTIC_DIGEST,
            row10_air.LOGICAL_INPUT_COUNT,
        );
        var row11 = try statement.AuthorityV2.init(allocator);
        errdefer row11.deinit();
        var result = AuthorityV2{
            .allocator = allocator,
            .row10_definition = row10_definition,
            .row10_relation = row10_relation,
            .row10_direct = row10_direct,
            .row11 = row11,
        };
        try result.validate();
        return result;
    }

    pub fn deinit(self: *AuthorityV2) void {
        self.row11.deinit();
        self.row10_definition.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const AuthorityV2) !void {
        try self.row10_definition.validate();
        try self.row10_relation.validateAgainst(
            &self.row10_definition.arena,
            row10_air.SEMANTIC_DIGEST,
            Row10Relation.events(&self.row10_definition),
        );
        const expected_direct = try direct_program.authenticate(
            &self.row10_definition.arena,
            row10_air.SEMANTIC_DIGEST,
            row10_air.LOGICAL_INPUT_COUNT,
        );
        if (!std.meta.eql(expected_direct, self.row10_direct))
            return error.PreparedAuthorityMismatch;
        try self.row11.validate();
    }

    pub fn statementAuthority(
        self: *const AuthorityV2,
    ) *const statement.AuthorityV2 {
        return &self.row11;
    }

    pub fn validateAgainst(
        self: *const AuthorityV2,
        prepared: *const statement.PreparedV2,
        manifest: *const manifest_mod.Manifest,
    ) !void {
        try self.validate();
        try prepared.validate();
        try manifest.validate();
        if (!std.meta.eql(
            manifest.statement_manifest_id,
            prepared.manifest.identity,
        ) or prepared.row10_active or !prepared.row10_claim.isZero()) {
            return error.PreparedAuthorityMismatch;
        }
        const row10 = manifest.placements[FIRST_ROW] orelse
            return error.ManifestGeometryMismatch;
        const row11 = manifest.placements[LAST_ROW] orelse
            return error.ManifestGeometryMismatch;
        if (!std.meta.eql(
            row10.geometry,
            Row10AdapterV2.manifestGeometry(
                .statement_input,
                ROW10_LOG_SIZE,
            ),
        ) or !std.meta.eql(
            row11.geometry,
            Row11AdapterV2.manifestGeometry(
                .statement_semantics_input,
                prepared.manifest.trace_log_size,
            ),
        )) return error.ManifestGeometryMismatch;
    }

    pub fn initComponents(
        self: *const AuthorityV2,
        prepared: *const statement.PreparedV2,
        manifest: *const manifest_mod.Manifest,
        relations: *const universal.UniversalRelations,
        claims: ClaimsV2,
    ) !ComponentsV2 {
        try self.validateAgainst(prepared, manifest);
        try claims.validate();
        try relations.validate();
        return .{
            .row10_inactive = try Row10AdapterV2.init(
                &self.row10_definition,
                self.row10_relation,
                manifest,
                .statement_input,
                ROW10_LOG_SIZE,
                [_]M31{M31.zero()} ** Row10AdapterV2.PARAMETER_COLUMN_COUNT,
                relations,
                claims.row10_inactive,
            ),
            .row11_statement = try Row11AdapterV2.init(
                &self.row11.definition,
                self.row11.relation_plan,
                manifest,
                .statement_semantics_input,
                prepared.manifest.trace_log_size,
                [_]M31{M31.zero()} ** Row11AdapterV2.PARAMETER_COLUMN_COUNT,
                relations,
                claims.row11_statement,
            ),
        };
    }
};

/// Worker-retained row-11 inversion and interaction staging. Row 10 has an
/// audited zero-interaction fast path and therefore needs no inversion slab.
pub const WorkspaceV2 = struct {
    allocator: std.mem.Allocator,
    prepared_identity: statement.Digest,
    statement_manifest_id: statement.Digest,
    row11_log_size: u32,
    row11_interaction: statement.Framework.Workspace,
    interaction_stage: []M31,

    pub fn init(
        allocator: std.mem.Allocator,
        prepared: *const statement.PreparedV2,
    ) !WorkspaceV2 {
        try prepared.validate();
        var row11_interaction = try statement.Framework.Workspace.init(
            allocator,
            prepared.manifest.trace_log_size,
        );
        errdefer row11_interaction.deinit();
        const stage_len = try checkedMul(
            statement.Air.INTERACTION_COLUMN_COUNT,
            try traceSize(prepared.manifest.trace_log_size),
        );
        const interaction_stage = try allocator.alloc(M31, stage_len);
        return .{
            .allocator = allocator,
            .prepared_identity = prepared.identity,
            .statement_manifest_id = prepared.manifest.identity,
            .row11_log_size = prepared.manifest.trace_log_size,
            .row11_interaction = row11_interaction,
            .interaction_stage = interaction_stage,
        };
    }

    pub fn deinit(self: *WorkspaceV2) void {
        self.allocator.free(self.interaction_stage);
        self.row11_interaction.deinit();
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const WorkspaceV2,
        prepared: *const statement.PreparedV2,
    ) !void {
        try prepared.validate();
        const expected_len = try checkedMul(
            statement.Air.INTERACTION_COLUMN_COUNT,
            try traceSize(prepared.manifest.trace_log_size),
        );
        if (!std.meta.eql(self.prepared_identity, prepared.identity) or
            !std.meta.eql(
                self.statement_manifest_id,
                prepared.manifest.identity,
            ) or self.row11_log_size != prepared.manifest.trace_log_size or
            self.interaction_stage.len != expected_len or
            self.row11_interaction.capacity_log_size != self.row11_log_size)
        {
            return error.WorkspaceGeometryMismatch;
        }
    }

    fn stagedColumns(
        self: *WorkspaceV2,
    ) [statement.Air.INTERACTION_COLUMN_COUNT][]M31 {
        const size = traceSize(self.row11_log_size) catch unreachable;
        var result: [statement.Air.INTERACTION_COLUMN_COUNT][]M31 = undefined;
        for (&result, 0..) |*column, index|
            column.* = self.interaction_stage[index * size ..][0..size];
        return result;
    }
};

pub const DomainAuditsV2 = struct {
    row10_inactive: relation_interaction.DomainAudit,
    row11_statement: relation_interaction.DomainAudit,
};

/// Writes the exact row-10/11 Tree-0 slices in circle-domain commitment
/// order. The complete destination geometry and alias contract is admitted
/// before either row is changed.
pub fn fillPreprocessedInto(
    authority: *const AuthorityV2,
    prepared: *const statement.PreparedV2,
    logical_rows: []const statement.Air.Row,
    manifest: *const manifest_mod.Manifest,
    destination: []const []M31,
) !void {
    try validateInputs(authority, prepared, logical_rows, manifest);
    try preflightTree(
        authority,
        prepared,
        logical_rows,
        manifest,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        destination,
        null,
        null,
    );
    zeroComponent(
        manifest.placements[FIRST_ROW].?,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        destination,
    );
    writeRow11Physical(
        logical_rows,
        manifest.placements[LAST_ROW].?,
        manifest_mod.PREPROCESSED_TREE_INDEX,
        destination,
    );
}

/// Writes the exact row-10/11 Tree-1 slices. Row 10 remains physically
/// present and all-zero; it is never represented by an omitted component.
pub fn fillMainInto(
    authority: *const AuthorityV2,
    prepared: *const statement.PreparedV2,
    logical_rows: []const statement.Air.Row,
    manifest: *const manifest_mod.Manifest,
    destination: []const []M31,
) !void {
    try validateInputs(authority, prepared, logical_rows, manifest);
    try preflightTree(
        authority,
        prepared,
        logical_rows,
        manifest,
        manifest_mod.MAIN_TREE_INDEX,
        destination,
        null,
        null,
    );
    zeroComponent(
        manifest.placements[FIRST_ROW].?,
        manifest_mod.MAIN_TREE_INDEX,
        destination,
    );
    writeRow11Physical(
        logical_rows,
        manifest.placements[LAST_ROW].?,
        manifest_mod.MAIN_TREE_INDEX,
        destination,
    );
}

/// Generates Tree 2 transactionally. The explicit row-10 fast path checks
/// the authenticated direct program and every compiled relation numerator on
/// the zero row before committing its zero columns.
pub fn fillInteractionInto(
    authority: *const AuthorityV2,
    workspace: *WorkspaceV2,
    prepared: *const statement.PreparedV2,
    logical_rows: []const statement.Air.Row,
    manifest: *const manifest_mod.Manifest,
    relations: *const universal.UniversalRelations,
    destination: []const []M31,
) !ClaimsV2 {
    try validateInputs(authority, prepared, logical_rows, manifest);
    try workspace.validateAgainst(prepared);
    try relations.validate();
    try preflightTree(
        authority,
        prepared,
        logical_rows,
        manifest,
        manifest_mod.INTERACTION_TREE_INDEX,
        destination,
        std.mem.asBytes(workspace),
        std.mem.asBytes(relations),
    );
    for (destination) |column| if (try slicesOverlapAny(
        column,
        workspace.interaction_stage,
    )) return error.DestinationAlias;
    for (destination) |column| if (try slicesOverlapAny(
        column,
        workspace.row11_interaction.scratch,
    )) return error.DestinationAlias;

    try validateInactiveRow10(authority, relations);
    var staged = workspace.stagedColumns();
    const row11_claim = try statement.generateInteractionInto(
        &workspace.row11_interaction,
        &authority.row11,
        prepared,
        logical_rows,
        relations,
        &staged,
    );

    zeroComponent(
        manifest.placements[FIRST_ROW].?,
        manifest_mod.INTERACTION_TREE_INDEX,
        destination,
    );
    const row11 = manifest.placements[LAST_ROW].?;
    const offset: usize = row11.interaction_offset;
    for (staged, destination[offset..][0..staged.len]) |source, target|
        @memcpy(target, source);
    return .{ .row11_statement = row11_claim };
}

/// Cold exact-domain evidence for both claims. Optional tuple-ledger output
/// uses the same authenticated plans and rows as Tree 2.
pub fn auditInteractionDomains(
    allocator: std.mem.Allocator,
    authority: *const AuthorityV2,
    prepared: *const statement.PreparedV2,
    logical_rows: []const statement.Air.Row,
    manifest: *const manifest_mod.Manifest,
    relations: *const universal.UniversalRelations,
    claims: ClaimsV2,
    tuple_ledger: ?*relation_interaction.TupleLedger,
) !DomainAuditsV2 {
    try validateInputs(authority, prepared, logical_rows, manifest);
    try relations.validate();
    try claims.validate();
    const inactive_rows = inactiveRow10Rows();
    const row10_audit = try authority.row10_relation.auditPreparedDomainSums(
        allocator,
        &inactive_rows,
        relations,
        claims.row10_inactive,
    );
    const row11_audit = try authority.row11.relation_plan
        .auditPreparedDomainSums(
        allocator,
        logical_rows,
        relations,
        claims.row11_statement,
    );
    if (tuple_ledger) |ledger| {
        try authority.row10_relation.appendPreparedTupleContributions(
            ledger,
            FIRST_ROW,
            &inactive_rows,
            relation_interaction.allDomainMask(),
        );
        try authority.row11.relation_plan.appendPreparedTupleContributions(
            ledger,
            LAST_ROW,
            logical_rows,
            relation_interaction.allDomainMask(),
        );
    }
    return .{
        .row10_inactive = row10_audit,
        .row11_statement = row11_audit,
    };
}

/// Challenge-independent, cold tuple projection for the exact rows used by
/// Tree 2. Keeping the canonical inactive row 10 in this API makes full-cohort
/// diagnostics robust to later event-program changes without granting the
/// diagnostic any claim or boundary authority.
pub fn appendTupleContributions(
    authority: *const AuthorityV2,
    prepared: *const statement.PreparedV2,
    logical_rows: []const statement.Air.Row,
    manifest: *const manifest_mod.Manifest,
    ledger: *relation_interaction.TupleLedger,
    domain_mask: u64,
) !void {
    try validateInputs(authority, prepared, logical_rows, manifest);
    const inactive_rows = inactiveRow10Rows();
    try authority.row10_relation.appendPreparedTupleContributions(
        ledger,
        FIRST_ROW,
        &inactive_rows,
        domain_mask,
    );
    try authority.row11.relation_plan.appendPreparedTupleContributions(
        ledger,
        LAST_ROW,
        logical_rows,
        domain_mask,
    );
}

fn validateInputs(
    authority: *const AuthorityV2,
    prepared: *const statement.PreparedV2,
    logical_rows: []const statement.Air.Row,
    manifest: *const manifest_mod.Manifest,
) !void {
    try authority.validateAgainst(prepared, manifest);
    try statement.validateLogicalRows(prepared, logical_rows);
}

fn validateInactiveRow10(
    authority: *const AuthorityV2,
    relations: *const universal.UniversalRelations,
) !void {
    const row = inactiveRow10();
    var scratch: [direct_program.MAX_NODES]M31 = undefined;
    var roots: [row10_air.DIRECT_CONSTRAINT_COUNT]M31 = undefined;
    try authority.row10_direct.evaluateBaseInto(&row, &scratch, &roots);
    for (roots) |root| if (!root.isZero())
        return error.InactiveRowInvariantMismatch;
    const pairs = try authority.row10_relation.preparedRowPairs(row, relations);
    for (pairs) |pair| if (!pair.n1.isZero() or !pair.n2.isZero())
        return error.InactiveRowInvariantMismatch;
}

fn inactiveRow10() Row10Relation.Row {
    return [_]M31{M31.zero()} ** row10_air.LOGICAL_INPUT_COUNT;
}

fn inactiveRow10Rows() [ROW10_TRACE_ROWS]Row10Relation.Row {
    return [_]Row10Relation.Row{inactiveRow10()} ** ROW10_TRACE_ROWS;
}

fn writeRow11Physical(
    rows: []const statement.Air.Row,
    placement: manifest_mod.Placement,
    tree: usize,
    destination: []const []M31,
) void {
    const column_count: usize = switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => statement.Air.PREPROCESSED_COLUMN_COUNT,
        manifest_mod.MAIN_TREE_INDEX => statement.Air.PHYSICAL_MAIN_COLUMN_COUNT,
        else => unreachable,
    };
    const input_offset: usize = if (tree == manifest_mod.PREPROCESSED_TREE_INDEX)
        statement.Air.PHYSICAL_MAIN_COLUMN_COUNT
    else
        0;
    const output_offset: usize = placementTreeOffset(placement, tree);
    for (destination[output_offset..][0..column_count]) |column|
        @memset(column, M31.zero());
    for (rows, 0..) |row, logical_row| {
        const committed = framework.committedRow(
            logical_row,
            placement.geometry.log_size,
        );
        for (0..column_count) |column|
            destination[output_offset + column][committed] =
                row[input_offset + column];
    }
}

fn zeroComponent(
    placement: manifest_mod.Placement,
    tree: usize,
    destination: []const []M31,
) void {
    const offset = placementTreeOffset(placement, tree);
    const count = geometryColumnCount(placement.geometry, tree);
    for (destination[offset..][0..count]) |column|
        @memset(column, M31.zero());
}

fn preflightTree(
    authority: *const AuthorityV2,
    prepared: *const statement.PreparedV2,
    logical_rows: []const statement.Air.Row,
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    destination: []const []M31,
    workspace_header: ?[]const u8,
    relations_header: ?[]const u8,
) !void {
    if (tree >= manifest_mod.TREE_COUNT) return error.InvalidTreeIndex;
    if (destination.len != manifestTreeColumnCount(manifest, tree))
        return error.DestinationColumnCountMismatch;
    inline for (.{ FIRST_ROW, LAST_ROW }) |row_index| {
        const placement = manifest.placements[row_index] orelse
            return error.ManifestGeometryMismatch;
        const offset = placementTreeOffset(placement, tree);
        const count = geometryColumnCount(placement.geometry, tree);
        const size = try traceSize(placement.geometry.log_size);
        if (offset > destination.len or count > destination.len - offset)
            return error.DestinationColumnCountMismatch;
        for (destination[offset..][0..count], 0..) |column, local_index| {
            if (column.len != size)
                return error.DestinationLogSizeMismatch;
            if (try slicesOverlapAny(column, std.mem.asBytes(authority)) or
                try slicesOverlapAny(column, std.mem.asBytes(prepared)) or
                try slicesOverlapAny(column, std.mem.asBytes(manifest)) or
                try slicesOverlapAny(column, logical_rows) or
                if (workspace_header) |bytes|
                    try slicesOverlapAny(column, bytes)
                else
                    false or
                        if (relations_header) |bytes|
                            try slicesOverlapAny(column, bytes)
                        else
                            false)
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

fn manifestTreeColumnCount(
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

fn placementTreeOffset(
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

fn geometryColumnCount(
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

const AddressRange = struct {
    start: usize,
    end: usize,

    fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

fn slicesOverlapAny(left: anytype, right: anytype) !bool {
    if (left.len == 0 or right.len == 0) return false;
    return (try sliceRangeAny(left)).overlaps(try sliceRangeAny(right));
}

fn sliceRangeAny(values: anytype) !AddressRange {
    const byte_len = try checkedMul(
        values.len,
        @sizeOf(std.meta.Elem(@TypeOf(values))),
    );
    const start = @intFromPtr(values.ptr);
    return .{ .start = start, .end = try checkedAdd(start, byte_len) };
}

fn traceSize(log_size: u32) !usize {
    if (log_size >= @bitSizeOf(usize) or log_size >= 31)
        return error.ArithmeticOverflow;
    return @as(usize, 1) << @intCast(log_size);
}

fn checkedAdd(left: usize, right: usize) !usize {
    return std.math.add(usize, left, right) catch error.ArithmeticOverflow;
}

fn checkedMul(left: usize, right: usize) !usize {
    return std.math.mul(usize, left, right) catch error.ArithmeticOverflow;
}

comptime {
    if (FORMAT_VERSION != 1 or FIRST_ROW != 10 or LAST_ROW != 11 or
        ROW_COUNT != 2 or ROW10_LOG_SIZE != 4 or
        ROW10_TRACE_ROWS != 16 or !ROW10_EXPLICITLY_INACTIVE or
        HOT_HEAP_ALLOCATIONS != 0 or
        Row10AdapterV2.PARAMETER_COLUMN_COUNT != row10_air.PARAMETER_COUNT or
        Row11AdapterV2.PARAMETER_COLUMN_COUNT != statement.Air.PARAMETER_COUNT or
        Row10Framework.INTERACTION_COLUMN_COUNT !=
            row10_air.INTERACTION_COLUMN_COUNT)
    {
        @compileError("SegmentV2 statement component geometry drifted");
    }
}
