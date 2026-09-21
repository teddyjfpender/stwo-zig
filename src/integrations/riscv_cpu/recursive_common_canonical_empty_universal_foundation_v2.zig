//! Universal-36 witness/cohort foundation for the canonical-empty wrapper.
//!
//! This module extracts the exact inactive roster which already passes the
//! native universal-recursion proof gate: 34 compiler-owned logical AIRs plus
//! the Poseidon2 and range-check providers.  It deliberately contains no
//! NodePublic encoding or SHA computation.  The eventual field-native
//! RecursiveNodePublicV2 owner must replace the inactive public-output lane
//! before this foundation can mint a common-wrapper proof.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const recursion_air = frontend.recursion.air;
const adapter = recursion_air.universal_typed_component;
const binding = recursion_air.universal_relation_binding;
const catalog = recursion_air.universal_catalog;
const manifest_mod = recursion_air.universal_adapter_manifest;
const provider = recursion_air.universal_shared_provider;
const range_bridge = recursion_air.range_check_8_8_bridge;
const roster = recursion_air.universal_roster;
const universal = recursion_air.universal_challenges;
const universal_manifest = recursion_air.universal_manifest;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 2;
pub const COMPONENT_COUNT: usize = roster.COMPONENT_COUNT;
pub const LOGICAL_COMPONENT_COUNT: usize = catalog.LOGICAL_COUNT;
pub const LOGICAL_LOG_SIZE: u32 = 4;
pub const POSEIDON_LOG_SIZE: u32 = 4;
pub const RANGE_LOG_SIZE: u32 = range_bridge.LOG_SIZE;
pub const PREPROCESSED_COLUMN_COUNT: u32 = 570;
pub const MAIN_COLUMN_COUNT: u32 = 1044;
pub const INTERACTION_COLUMN_COUNT: u32 = 560;
pub const CONSTRAINT_COUNT: u32 = 1312;

pub const PRODUCTION_ACTIVATION = false;
pub const PUBLIC_OUTPUT_LANE_AVAILABLE = false;
pub const COLD_FIXED_PROOF_SHAPE_AVAILABLE = false;
pub const REGISTRY_GEOMETRY_AVAILABLE = false;
pub const SHA_IN_RECURSIVE_AIR = false;

pub const Error = error{
    ArithmeticOverflow,
    CanonicalInactiveWitnessMismatch,
    CanonicalUniversalCohortMismatch,
    CanonicalUniversalManifestMismatch,
    ColdFixedProofShapeUnavailable,
    FieldNativePublicOutputUnavailable,
    InvalidTreeIndex,
};

pub const MissingAuthorityV2 = enum(u8) {
    recursive_node_public_v2_air_owner = 1,
    poseidon_statement_digest_witness = 2,
    ordered_subtree_digest_witness = 3,
    poseidon_output_digest_witness = 4,
    cold_fixed_proof_shape_v3 = 5,
    cold_authenticated_registry_geometry = 6,
};

/// Exact native geometry already exercised by the universal proof fixture.
/// This is a circuit/witness authority, not an authenticated cold-proof shape.
pub const ManifestAuthorityV2 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    component_log_sizes: universal_manifest.LogSizes,
    manifest: manifest_mod.Manifest,

    pub fn build() !ManifestAuthorityV2 {
        const log_sizes = exactLogSizes();
        const manifest = try universal_manifest.build(log_sizes);
        const result = ManifestAuthorityV2{
            .component_log_sizes = log_sizes,
            .manifest = manifest,
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: *const ManifestAuthorityV2) !void {
        try self.manifest.validate();
        const expected_logs = exactLogSizes();
        const expected = try universal_manifest.build(expected_logs);
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.meta.eql(self.component_log_sizes, expected_logs) or
            !std.meta.eql(self.manifest, expected) or
            self.manifest.roster_count != COMPONENT_COUNT or
            self.manifest.total_preprocessed_columns !=
                PREPROCESSED_COLUMN_COUNT or
            self.manifest.total_main_columns != MAIN_COLUMN_COUNT or
            self.manifest.total_interaction_columns !=
                INTERACTION_COLUMN_COUNT or
            self.manifest.total_constraints != CONSTRAINT_COUNT)
        {
            return error.CanonicalUniversalManifestMismatch;
        }
    }
};

pub const TreeKindV2 = enum(u8) {
    preprocessed = manifest_mod.PREPROCESSED_TREE_INDEX,
    main = manifest_mod.MAIN_TREE_INDEX,
    interaction = manifest_mod.INTERACTION_TREE_INDEX,
};

const ColumnV2 = struct {
    log_size: u32,
    cell_offset: usize,
    cell_count: usize,
};

/// Owned, contiguous native trace-tree witness.  It retains exact per-column
/// log sizes and can later be adapted to PCS ColumnEvaluation without changing
/// witness values or allocating one buffer per column.
pub const OwnedTreeWitnessV2 = struct {
    allocator: std.mem.Allocator,
    tree: TreeKindV2,
    columns: []ColumnV2,
    cells: []M31,

    pub fn init(
        allocator: std.mem.Allocator,
        authority: *const ManifestAuthorityV2,
        tree: TreeKindV2,
    ) !OwnedTreeWitnessV2 {
        try authority.validate();
        const column_count = treeColumnCount(&authority.manifest, tree);
        const columns = try allocator.alloc(ColumnV2, column_count);
        errdefer allocator.free(columns);
        var cursor: usize = 0;
        for (authority.manifest.roster_rows[0..authority.manifest.roster_count]) |row| {
            const placement = authority.manifest.placements[row] orelse
                return error.CanonicalUniversalManifestMismatch;
            const offset = treeOffset(placement, tree);
            const count = treeGeometryColumns(placement.geometry, tree);
            if (offset > columns.len or count > columns.len - offset)
                return error.CanonicalUniversalManifestMismatch;
            for (columns[offset..][0..count]) |*metadata| {
                const cell_count = @as(usize, 1) <<
                    @intCast(placement.geometry.log_size);
                metadata.* = .{
                    .log_size = placement.geometry.log_size,
                    .cell_offset = cursor,
                    .cell_count = cell_count,
                };
                cursor = std.math.add(usize, cursor, cell_count) catch
                    return error.ArithmeticOverflow;
            }
        }
        const cells = try allocator.alloc(M31, cursor);
        @memset(cells, M31.zero());
        return .{
            .allocator = allocator,
            .tree = tree,
            .columns = columns,
            .cells = cells,
        };
    }

    pub fn deinit(self: *OwnedTreeWitnessV2) void {
        self.allocator.free(self.cells);
        self.allocator.free(self.columns);
        self.* = undefined;
    }

    pub fn column(self: *OwnedTreeWitnessV2, index: usize) ![]M31 {
        if (index >= self.columns.len)
            return error.CanonicalInactiveWitnessMismatch;
        const metadata = self.columns[index];
        return self.cells[metadata.cell_offset..][0..metadata.cell_count];
    }

    pub fn columnConst(self: *const OwnedTreeWitnessV2, index: usize) ![]const M31 {
        if (index >= self.columns.len)
            return error.CanonicalInactiveWitnessMismatch;
        const metadata = self.columns[index];
        return self.cells[metadata.cell_offset..][0..metadata.cell_count];
    }

    pub fn validateShape(
        self: *const OwnedTreeWitnessV2,
        authority: *const ManifestAuthorityV2,
    ) !void {
        try authority.validate();
        if (self.columns.len != treeColumnCount(&authority.manifest, self.tree))
            return error.CanonicalInactiveWitnessMismatch;
        var cursor: usize = 0;
        for (authority.manifest.roster_rows[0..authority.manifest.roster_count]) |row| {
            const placement = authority.manifest.placements[row].?;
            const offset = treeOffset(placement, self.tree);
            const count = treeGeometryColumns(placement.geometry, self.tree);
            for (self.columns[offset..][0..count]) |metadata| {
                const expected_cells = @as(usize, 1) <<
                    @intCast(placement.geometry.log_size);
                if (metadata.log_size != placement.geometry.log_size or
                    metadata.cell_offset != cursor or
                    metadata.cell_count != expected_cells)
                {
                    return error.CanonicalInactiveWitnessMismatch;
                }
                cursor = std.math.add(usize, cursor, expected_cells) catch
                    return error.ArithmeticOverflow;
            }
        }
        if (cursor != self.cells.len)
            return error.CanonicalInactiveWitnessMismatch;
    }
};

/// Exact canonical inactive trace.  Main and interaction trees are all zero;
/// preprocessing contains only the native Poseidon first-row selector and the
/// complete (8,8) range table.  This is genuine witness data for the inactive
/// universal shell, but not a canonical-empty wrapper output proof.
pub const OwnedInactiveWitnessV2 = struct {
    authority: ManifestAuthorityV2,
    preprocessed: OwnedTreeWitnessV2,
    main: OwnedTreeWitnessV2,
    interaction: OwnedTreeWitnessV2,

    pub fn create(allocator: std.mem.Allocator) !OwnedInactiveWitnessV2 {
        const authority = try ManifestAuthorityV2.build();
        var preprocessed = try OwnedTreeWitnessV2.init(
            allocator,
            &authority,
            .preprocessed,
        );
        errdefer preprocessed.deinit();
        var main = try OwnedTreeWitnessV2.init(allocator, &authority, .main);
        errdefer main.deinit();
        var interaction = try OwnedTreeWitnessV2.init(
            allocator,
            &authority,
            .interaction,
        );
        errdefer interaction.deinit();
        try fillCanonicalProviderPreprocessing(&authority.manifest, &preprocessed);
        var result = OwnedInactiveWitnessV2{
            .authority = authority,
            .preprocessed = preprocessed,
            .main = main,
            .interaction = interaction,
        };
        try result.validate();
        return result;
    }

    pub fn deinit(self: *OwnedInactiveWitnessV2) void {
        self.interaction.deinit();
        self.main.deinit();
        self.preprocessed.deinit();
        self.* = undefined;
    }

    pub fn validate(self: *const OwnedInactiveWitnessV2) !void {
        try self.authority.validate();
        try self.preprocessed.validateShape(&self.authority);
        try self.main.validateShape(&self.authority);
        try self.interaction.validateShape(&self.authority);
        try validateAllZero(&self.main);
        try validateAllZero(&self.interaction);
        try validateCanonicalProviderPreprocessing(
            &self.authority.manifest,
            &self.preprocessed,
        );
    }
};

fn LogicalOwner(comptime entry: catalog.Entry) type {
    const Air = entry.Air;
    const Relation = binding.Binding(Air);
    const TypedAdapter = adapter.Component(Air, Relation);
    return struct {
        definition: Air.Definition,
        component: TypedAdapter,

        fn init(
            allocator: std.mem.Allocator,
            manifest: *const manifest_mod.Manifest,
            relations: *const universal.UniversalRelations,
        ) !@This() {
            var definition = if (entry.requires_location)
                try Air.build(allocator, .generated)
            else
                try Air.build(allocator);
            errdefer definition.deinit();
            const relation_plan = try Relation.authenticate(&definition);
            const parameters = [_]M31{M31.zero()} **
                TypedAdapter.PARAMETER_COLUMN_COUNT;
            return .{
                .definition = definition,
                .component = try TypedAdapter.init(
                    &definition,
                    relation_plan,
                    manifest,
                    entry.row,
                    LOGICAL_LOG_SIZE,
                    parameters,
                    relations,
                    QM31.zero(),
                ),
            };
        }

        fn deinit(self: *@This()) void {
            self.definition.deinit();
            self.* = undefined;
        }
    };
}

fn LogicalOwnersType() type {
    var types: [catalog.LOGICAL_COUNT]type = undefined;
    inline for (catalog.LOGICAL_ROWS, 0..) |entry, index|
        types[index] = LogicalOwner(entry);
    return std.meta.Tuple(&types);
}

const LogicalOwners = LogicalOwnersType();

/// Stable-address component owner for the exact inactive all-36 gate.  The
/// zero parameters intentionally select no public-output semantics; the V2
/// output owner must replace that lane rather than mutating this cohort.
pub const InactiveCohortV2 = struct {
    allocator: std.mem.Allocator,
    authority: ManifestAuthorityV2,
    relations: universal.UniversalRelations,
    provider_relations: provider.SharedProviderRelations,
    range_definition: range_bridge.Definition,
    range_executor: range_bridge.Executor,
    owners: LogicalOwners,
    initialized_owners: usize,
    poseidon: provider.Poseidon2Adapter,
    range: provider.RangeCheck8x8Adapter,

    pub fn create(
        allocator: std.mem.Allocator,
        relations: *const universal.UniversalRelations,
    ) !*InactiveCohortV2 {
        try relations.validate();
        const self = try allocator.create(InactiveCohortV2);
        errdefer allocator.destroy(self);
        self.* = undefined;
        self.allocator = allocator;
        self.authority = try ManifestAuthorityV2.build();
        self.relations = relations.*;
        self.initialized_owners = 0;
        self.provider_relations = try provider.SharedProviderRelations.init(
            &self.relations,
        );
        self.range_definition = try range_bridge.build(allocator);
        errdefer self.range_definition.deinit();
        const range_binding = try range_bridge.Binding.canonical(
            &self.range_definition,
        );
        self.range_executor = try range_bridge.Executor.init(
            &self.range_definition,
            &range_binding,
        );
        errdefer deinitOwners(&self.owners, self.initialized_owners);
        inline for (catalog.LOGICAL_ROWS, 0..) |entry, index| {
            self.owners[index] = try LogicalOwner(entry).init(
                allocator,
                &self.authority.manifest,
                &self.relations,
            );
            self.initialized_owners += 1;
        }
        self.poseidon = try provider.Poseidon2Adapter.init(
            &self.authority.manifest,
            POSEIDON_LOG_SIZE,
            0,
            &self.provider_relations,
            &self.relations,
            .{QM31.zero()} ** provider.POSEIDON_INTERACTION_BATCH_COUNT,
        );
        self.range = try provider.RangeCheck8x8Adapter.init(
            &self.range_definition,
            &self.range_executor,
            &self.authority.manifest,
            &self.provider_relations,
            &self.relations,
            QM31.zero(),
        );
        try self.validate();
        return self;
    }

    pub fn deinit(self: *InactiveCohortV2) void {
        deinitOwners(&self.owners, self.initialized_owners);
        self.range_definition.deinit();
        const allocator = self.allocator;
        self.* = undefined;
        allocator.destroy(self);
    }

    pub fn validate(self: *const InactiveCohortV2) !void {
        try self.authority.validate();
        try self.relations.validate();
        try self.provider_relations.validateAgainst(&self.relations);
        if (self.initialized_owners != LOGICAL_COMPONENT_COUNT)
            return error.CanonicalUniversalCohortMismatch;
        inline for (catalog.LOGICAL_ROWS, 0..) |entry, index| {
            _ = entry;
            for (self.owners[index].component.parameters) |parameter|
                if (!parameter.eql(M31.zero()))
                    return error.CanonicalUniversalCohortMismatch;
            _ = try self.owners[index].component.binding(
                &self.authority.manifest,
            );
        }
        _ = try self.poseidon.binding(&self.authority.manifest);
        _ = try self.range.binding(&self.authority.manifest);
    }

    pub fn appendAndSealGate(
        self: *const InactiveCohortV2,
        gate: *manifest_mod.ProofGate,
    ) !void {
        try self.validate();
        if (gate.count != 0 or gate.sealed)
            return error.CanonicalUniversalCohortMismatch;
        inline for (catalog.LOGICAL_ROWS, 0..) |entry, index| {
            _ = entry;
            try gate.append(
                &self.authority.manifest,
                try self.owners[index].component.binding(
                    &self.authority.manifest,
                ),
            );
        }
        try gate.append(
            &self.authority.manifest,
            try self.poseidon.binding(&self.authority.manifest),
        );
        try gate.append(
            &self.authority.manifest,
            try self.range.binding(&self.authority.manifest),
        );
        try gate.sealGate(&self.authority.manifest);
        try gate.validate(&self.authority.manifest);
    }
};

pub fn firstMissingAuthority() MissingAuthorityV2 {
    return .recursive_node_public_v2_air_owner;
}

pub fn requirePublicOutputLane() Error!void {
    return error.FieldNativePublicOutputUnavailable;
}

pub fn requireColdFixedProofShape() Error!void {
    return error.ColdFixedProofShapeUnavailable;
}

pub fn exactLogSizes() universal_manifest.LogSizes {
    var result = [_]u32{LOGICAL_LOG_SIZE} ** COMPONENT_COUNT;
    result[@intFromEnum(roster.Component.poseidon2)] = POSEIDON_LOG_SIZE;
    result[@intFromEnum(roster.Component.range_check_8_8)] = RANGE_LOG_SIZE;
    return result;
}

fn deinitOwners(owners: *LogicalOwners, initialized: usize) void {
    inline for (catalog.LOGICAL_ROWS, 0..) |entry, index| {
        _ = entry;
        if (index < initialized) owners[index].deinit();
    }
}

fn fillCanonicalProviderPreprocessing(
    manifest: *const manifest_mod.Manifest,
    tree: *OwnedTreeWitnessV2,
) !void {
    if (tree.tree != .preprocessed)
        return error.CanonicalInactiveWitnessMismatch;
    const poseidon = try manifest.placement(.poseidon2);
    const poseidon_selector = try tree.column(poseidon.preprocessed_offset);
    poseidon_selector[committedRow(0, poseidon.geometry.log_size)] = M31.one();

    const range = try manifest.placement(.range_check_8_8);
    const range_selector = try tree.column(range.preprocessed_offset);
    range_selector[range_bridge.committedRow(0)] = M31.one();
    const low = try tree.column(range.preprocessed_offset + 1);
    const high = try tree.column(range.preprocessed_offset + 2);
    for (0..range_bridge.TABLE_SIZE) |logical_row| {
        const destination = range_bridge.committedRow(logical_row);
        low[destination] = M31.fromCanonical(@intCast(logical_row & 0xff));
        high[destination] = M31.fromCanonical(@intCast(logical_row >> 8));
    }
}

fn validateCanonicalProviderPreprocessing(
    manifest: *const manifest_mod.Manifest,
    tree: *const OwnedTreeWitnessV2,
) !void {
    if (tree.tree != .preprocessed)
        return error.CanonicalInactiveWitnessMismatch;
    const poseidon = try manifest.placement(.poseidon2);
    const range = try manifest.placement(.range_check_8_8);
    for (tree.columns, 0..) |_, column_index| {
        const values = try tree.columnConst(column_index);
        if (column_index == poseidon.preprocessed_offset) {
            try validateSelector(values, committedRow(0, poseidon.geometry.log_size));
        } else if (column_index == range.preprocessed_offset) {
            try validateSelector(values, range_bridge.committedRow(0));
        } else if (column_index == range.preprocessed_offset + 1 or
            column_index == range.preprocessed_offset + 2)
        {
            for (0..range_bridge.TABLE_SIZE) |logical_row| {
                const destination = range_bridge.committedRow(logical_row);
                const raw = if (column_index == range.preprocessed_offset + 1)
                    logical_row & 0xff
                else
                    logical_row >> 8;
                if (!values[destination].eql(M31.fromCanonical(@intCast(raw))))
                    return error.CanonicalInactiveWitnessMismatch;
            }
        } else {
            for (values) |value| if (!value.eql(M31.zero()))
                return error.CanonicalInactiveWitnessMismatch;
        }
    }
}

fn validateSelector(values: []const M31, selected: usize) !void {
    if (selected >= values.len)
        return error.CanonicalInactiveWitnessMismatch;
    for (values, 0..) |value, row| {
        const expected = if (row == selected) M31.one() else M31.zero();
        if (!value.eql(expected))
            return error.CanonicalInactiveWitnessMismatch;
    }
}

fn validateAllZero(tree: *const OwnedTreeWitnessV2) !void {
    for (tree.cells) |value| if (!value.eql(M31.zero()))
        return error.CanonicalInactiveWitnessMismatch;
}

fn treeColumnCount(
    manifest: *const manifest_mod.Manifest,
    tree: TreeKindV2,
) usize {
    return switch (tree) {
        .preprocessed => manifest.total_preprocessed_columns,
        .main => manifest.total_main_columns,
        .interaction => manifest.total_interaction_columns,
    };
}

fn treeOffset(
    placement: manifest_mod.Placement,
    tree: TreeKindV2,
) usize {
    return switch (tree) {
        .preprocessed => placement.preprocessed_offset,
        .main => placement.main_offset,
        .interaction => placement.interaction_offset,
    };
}

fn treeGeometryColumns(
    geometry: manifest_mod.Geometry,
    tree: TreeKindV2,
) usize {
    return switch (tree) {
        .preprocessed => geometry.preprocessed_columns,
        .main => geometry.main_columns,
        .interaction => geometry.interaction_columns,
    };
}

fn committedRow(logical_row: usize, log_size: u32) usize {
    return stwo_core.utils.bitReverseIndex(
        stwo_core.utils.cosetIndexToCircleDomainIndex(logical_row, log_size),
        log_size,
    );
}

comptime {
    if (COMPONENT_COUNT != 36 or LOGICAL_COMPONENT_COUNT != 34 or
        PREPROCESSED_COLUMN_COUNT != 570 or MAIN_COLUMN_COUNT != 1044 or
        INTERACTION_COLUMN_COUNT != 560 or CONSTRAINT_COUNT != 1312 or
        PRODUCTION_ACTIVATION or PUBLIC_OUTPUT_LANE_AVAILABLE or
        COLD_FIXED_PROOF_SHAPE_AVAILABLE or REGISTRY_GEOMETRY_AVAILABLE or
        SHA_IN_RECURSIVE_AIR)
    {
        @compileError("canonical-empty universal foundation contract drifted");
    }
}
