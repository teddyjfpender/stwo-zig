//! One frontend-owned assembly boundary for segment-leaf outer rows.
//!
//! The bundle does not re-author a constraint, relation, witness, or shared
//! provider.  It borrows the authenticated production sources for rows 0--9,
//! 10--11/35, and 12--17 and gives the all-36 driver one ordered interface for
//! manifest installation, committed-tree population, claims, components, and
//! relation-domain provenance.
//!
//! Row 35 is deliberately split from the contiguous prefix.  The caller must
//! append rows 18--34 before calling `Components.appendSharedProviderToGate`;
//! this makes it impossible for the bundle to disguise a non-roster proof
//! order.  Hot fills require fresh-zero owned destinations.  That precondition
//! permits allocation-free rollback across source boundaries and preserves the
//! exact allocation profile documented below.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

const public_data_mod = @import("../air/public_data.zig");
const fixed_wire = @import("fixed_wire.zig");
const leaf_authority = @import("segment_leaf_authority.zig");
const transcript_witness = @import("segment_transcript_witness.zig");
const transcript_source_mod = @import("segment_transcript_outer_source.zig");
const statement_source = @import("segment_statement_outer_source.zig");
const public_source = @import("segment_public_outer_source.zig");

const air = @import("air/mod.zig");
const manifest_mod = air.universal_adapter_manifest;
const relation_interaction = air.relation_interaction;
const roster = air.universal_roster;
const schedule = air.verifier_schedule;
const shared_provider = air.universal_shared_provider;
const universal = air.universal_challenges;
const universal_manifest = air.universal_manifest;
const lowering = air.verifier_arithmetic_lowering;

pub const FORMAT_VERSION: u16 = 1;
pub const FIRST_PREFIX_ROW: usize = @intFromEnum(roster.Component.control);
pub const PREFIX_ROW_COUNT: usize = 18;
pub const LAST_PREFIX_ROW: usize = @intFromEnum(
    roster.Component.vm_public_logup_control,
);
pub const SHARED_PROVIDER_ROW: usize = @intFromEnum(
    roster.Component.range_check_8_8,
);
pub const OWNED_ROW_COUNT: usize = PREFIX_ROW_COUNT + 1;

/// Exact allocations performed by the three existing sources for a
/// fresh-zero, non-aliasing full-manifest destination.  Rows 0--9 write Tree 0
/// and Tree 1 directly. Tree 2 retains one logical-row conversion plus two
/// framework allocations per transcript row.
/// Rows 10/11/35 retain all scratch in their workspace.  Rows 12--17 retain
/// one transactional stage per tree plus two framework allocations per
/// interaction row.
pub const HOT_TREE_HEAP_ALLOCATIONS = [manifest_mod.TREE_COUNT]usize{
    1,
    1,
    43,
};
pub const HOT_ALL_TREES_HEAP_ALLOCATIONS: usize = 45;

/// Authentication is cold authority construction/admission.  No pair node is
/// authenticated while any of the three committed trees is populated.
pub const HOT_TREE_PAIR_AUTHENTICATIONS =
    [_]usize{0} ** manifest_mod.TREE_COUNT;
pub const HOT_ALL_TREES_PAIR_AUTHENTICATIONS: usize = 0;

pub const Error = error{
    ArithmeticOverflow,
    DestinationAlias,
    DestinationNotZero,
    InvalidTreeIndex,
    InvalidTraceShape,
};

pub const Claims = struct {
    transcript: transcript_source_mod.Claims,
    statement: statement_source.Claims,
    public: public_source.Claims,

    /// Exact proof-visible values for the contiguous rows 0--17.
    pub fn prefixValues(self: Claims) [PREFIX_ROW_COUNT]QM31 {
        var result: [PREFIX_ROW_COUNT]QM31 = undefined;
        const transcript_values = self.transcript.asArray();
        const statement_values = self.statement.rosterValues();
        const public_values = self.public.asArray();
        @memcpy(result[0..10], &transcript_values);
        result[10] = statement_values[0];
        result[11] = statement_values[1];
        @memcpy(result[12..18], &public_values);
        return result;
    }

    pub fn sharedProviderValue(self: Claims) QM31 {
        return self.statement.range_check;
    }

    /// Binds only the contiguous prefix, leaving rows 18--35 available to the
    /// all-36 driver.  The shared provider has a separate ordered operation.
    pub fn bindPrefixInto(
        self: Claims,
        vector: *manifest_mod.ClaimVector,
    ) !void {
        for (self.transcript.asArray(), 0..) |value, index|
            try vector.bind(@enumFromInt(FIRST_PREFIX_ROW + index), value);
        try vector.bind(.statement_input, self.statement.statement_input);
        try vector.bind(
            .statement_semantics_input,
            self.statement.statement_semantics,
        );
        for (self.public.asArray(), 0..) |value, index|
            try vector.bind(@enumFromInt(public_source.FIRST_ROW + index), value);
    }

    pub fn bindSharedProviderInto(
        self: Claims,
        vector: *manifest_mod.ClaimVector,
    ) !void {
        try vector.bind(.range_check_8_8, self.statement.range_check);
    }

    pub fn bindInto(
        self: Claims,
        vector: *manifest_mod.ClaimVector,
    ) !void {
        try self.bindPrefixInto(vector);
        try self.bindSharedProviderInto(vector);
    }
};

pub const DomainAudits = struct {
    transcript: transcript_source_mod.DomainAudits,
    statement: statement_source.DomainAudits,
    public: public_source.DomainAudits,

    /// Exact signed contribution of these nineteen rows to every universal
    /// relation.  It is intentionally not asserted zero: rows 18--34 close
    /// several of the prefix's domains.
    pub fn closureContribution(self: *const DomainAudits) ClosureContribution {
        var result = ClosureContribution{};
        for (self.transcript) |audit| result.addAudit(audit);
        result.addAudit(self.statement.statement_input);
        result.addAudit(self.statement.statement_semantics);
        result.addAudit(self.statement.range_check);
        for (self.public) |audit| result.addAudit(audit);
        return result;
    }
};

pub const ClosureContribution = struct {
    values: [universal.RELATION_COUNT]QM31 =
        [_]QM31{QM31.zero()} ** universal.RELATION_COUNT,

    fn addAudit(self: *ClosureContribution, audit: relation_interaction.DomainAudit) void {
        for (&self.values, audit.values) |*destination, value|
            destination.* = destination.add(value);
    }

    pub fn addInto(
        self: ClosureContribution,
        destination: *[universal.RELATION_COUNT]QM31,
    ) void {
        for (destination, self.values) |*value, contribution|
            value.* = value.add(contribution);
    }

    pub fn total(self: ClosureContribution) QM31 {
        var result = QM31.zero();
        for (self.values) |value| result = result.add(value);
        return result;
    }
};

pub const Components = struct {
    transcript: transcript_source_mod.Components,
    statement: statement_source.Components,
    public: public_source.Components,

    /// Appends exactly rows 0--17.  `ProofGate.append` checks every roster
    /// transition, so an incorrectly positioned bundle fails closed.
    pub fn appendPrefixToGate(
        self: *const Components,
        manifest: *const manifest_mod.Manifest,
        gate: *manifest_mod.ProofGate,
    ) !void {
        try self.transcript.appendToGate(manifest, gate);
        try gate.append(
            manifest,
            try self.statement.statement_input.binding(manifest),
        );
        try gate.append(
            manifest,
            try self.statement.statement_semantics.binding(manifest),
        );
        try self.public.appendToGate(manifest, gate);
    }

    /// Appends only row 35.  The all-36 driver calls this after rows 18--34.
    pub fn appendSharedProviderToGate(
        self: *const Components,
        manifest: *const manifest_mod.Manifest,
        gate: *manifest_mod.ProofGate,
    ) !void {
        try gate.append(
            manifest,
            try self.statement.range_check.binding(manifest),
        );
    }
};

/// A move-safe set of borrowed, already-authenticated authorities and proof
/// snapshots.  One mutable statement workspace is intentionally explicit;
/// callers provide one bundle/workspace per concurrent proof worker.
pub fn Bundle(comptime dimensions: fixed_wire.Dimensions) type {
    dimensions.validate();
    const TranscriptSource = transcript_source_mod.Source(dimensions);
    const TranscriptPrepared = transcript_witness.Prepared(dimensions);

    return struct {
        const Self = @This();

        pub const Inputs = struct {
            vm_plan: *const schedule.Plan,
            recursion_plan: *const schedule.Plan,
            transcript_preprocessing: *const transcript_witness.Preprocessing,
            transcript_prepared: *const TranscriptPrepared,
            transcript_source: *const TranscriptSource,
            leaf_preprocessing: *const leaf_authority.Preprocessing,
            leaf: *const leaf_authority.Prepared,
            public_data: *const public_data_mod.PublicData,
            statement_authority: *const statement_source.Authority,
            statement_workspace: *statement_source.Workspace,
            statement_prepared: *const statement_source.Prepared,
            public_source: *const public_source.Source,
            public_prepared: *const public_source.Prepared,
        };

        inputs: Inputs,

        pub fn init(inputs: Inputs) !Self {
            const result = Self{ .inputs = inputs };
            try result.validate();
            return result;
        }

        /// Allocation-free chain-of-custody admission across all three source
        /// families.  No copied digest is accepted as a substitute for the
        /// source-specific validation routines.
        pub fn validate(self: *const Self) !void {
            const input = self.inputs;
            try input.transcript_source.validateAgainst(
                input.vm_plan,
                input.recursion_plan,
                input.transcript_preprocessing,
                input.transcript_prepared,
            );
            try input.statement_prepared.validateAgainst(
                input.statement_authority,
                input.statement_workspace,
                input.leaf_preprocessing,
                input.public_data,
                input.leaf,
            );
            try input.public_source.validateAgainst(
                input.vm_plan,
                input.recursion_plan,
                input.leaf_preprocessing,
            );
            try input.public_prepared.validateAgainst(
                input.public_source,
                input.leaf_preprocessing,
                input.leaf,
                input.public_data,
            );
        }

        /// Installs exactly rows 0--17 and 35, leaving the remaining seventeen
        /// log sizes untouched for the recursive source.
        pub fn installLogSizes(
            self: *const Self,
            destination: *universal_manifest.LogSizes,
        ) void {
            self.inputs.transcript_source.installLogSizes(destination);
            self.inputs.statement_authority.installLogSizes(destination);
            self.inputs.public_source.installLogSizes(destination);
        }

        /// Exact shared arithmetic lanes consumed by universal rows 30--32,
        /// in source-roster order: statement semantics, public claim, public
        /// LogUp.
        pub fn loweringLanes(self: *const Self) [3]lowering.Lane {
            const public_lanes = self.inputs.public_source.loweringLanes();
            return .{
                self.inputs.statement_authority.loweringLane(),
                public_lanes[0],
                public_lanes[1],
            };
        }

        pub fn fillPreprocessedInto(
            self: *const Self,
            manifest: *const manifest_mod.Manifest,
            destination: [][]M31,
        ) !void {
            try preflightFreshOwnedTree(
                manifest,
                manifest_mod.PREPROCESSED_TREE_INDEX,
                destination,
            );
            errdefer clearOwnedTree(
                manifest,
                manifest_mod.PREPROCESSED_TREE_INDEX,
                destination,
            );

            const input = self.inputs;
            try input.transcript_source.fillPreprocessedInto(
                input.vm_plan,
                input.recursion_plan,
                input.transcript_preprocessing,
                input.transcript_prepared,
                manifest,
                destination,
            );
            var statement_columns = try statement_source.bindPreprocessedCommitted(
                input.statement_authority,
                manifest,
                destination,
            );
            try statement_source.fillPreprocessedCommitted(
                input.statement_authority,
                input.statement_workspace,
                &statement_columns,
            );
            try input.public_source.fillPreprocessedInto(
                input.vm_plan,
                input.recursion_plan,
                input.leaf_preprocessing,
                manifest,
                destination,
            );
        }

        pub fn fillMainInto(
            self: *const Self,
            manifest: *const manifest_mod.Manifest,
            destination: [][]M31,
        ) !void {
            try preflightFreshOwnedTree(
                manifest,
                manifest_mod.MAIN_TREE_INDEX,
                destination,
            );
            errdefer clearOwnedTree(
                manifest,
                manifest_mod.MAIN_TREE_INDEX,
                destination,
            );

            const input = self.inputs;
            try input.transcript_source.fillMainInto(
                input.vm_plan,
                input.recursion_plan,
                input.transcript_preprocessing,
                input.transcript_prepared,
                manifest,
                destination,
            );
            var statement_columns = try statement_source.bindMainCommitted(
                input.statement_authority,
                manifest,
                destination,
            );
            try statement_source.fillMainCommitted(
                input.statement_authority,
                input.statement_workspace,
                input.statement_prepared,
                input.leaf_preprocessing,
                input.public_data,
                input.leaf,
                &statement_columns,
            );
            try input.public_source.fillMainInto(
                input.vm_plan,
                input.recursion_plan,
                input.leaf_preprocessing,
                input.leaf,
                input.public_prepared,
                input.public_data,
                manifest,
                destination,
            );
        }

        pub fn fillInteractionInto(
            self: *const Self,
            manifest: *const manifest_mod.Manifest,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
            destination: [][]M31,
        ) !Claims {
            try preflightFreshOwnedTree(
                manifest,
                manifest_mod.INTERACTION_TREE_INDEX,
                destination,
            );
            errdefer clearOwnedTree(
                manifest,
                manifest_mod.INTERACTION_TREE_INDEX,
                destination,
            );

            const input = self.inputs;
            const transcript_claims = try input.transcript_source.fillInteractionInto(
                input.vm_plan,
                input.recursion_plan,
                input.transcript_preprocessing,
                input.transcript_prepared,
                manifest,
                relations,
                destination,
            );
            var statement_columns = try statement_source.bindInteractionsCommitted(
                input.statement_authority,
                manifest,
                destination,
            );
            const statement_claims = try statement_source.fillInteractionsCommitted(
                input.statement_authority,
                input.statement_workspace,
                input.statement_prepared,
                input.leaf_preprocessing,
                input.public_data,
                input.leaf,
                relations,
                provider_relations,
                &statement_columns,
            );
            const public_claims = try input.public_source.fillInteractionInto(
                input.vm_plan,
                input.recursion_plan,
                input.leaf_preprocessing,
                input.leaf,
                input.public_prepared,
                input.public_data,
                manifest,
                relations,
                destination,
            );
            return .{
                .transcript = transcript_claims,
                .statement = statement_claims,
                .public = public_claims,
            };
        }

        pub fn auditInteractionDomains(
            self: *const Self,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
            claims: Claims,
            tuple_ledger: ?*relation_interaction.TupleLedger,
        ) !DomainAudits {
            const input = self.inputs;
            return .{
                .transcript = try input.transcript_source.auditInteractionDomains(
                    input.vm_plan,
                    input.recursion_plan,
                    input.transcript_preprocessing,
                    input.transcript_prepared,
                    relations,
                    claims.transcript,
                    tuple_ledger,
                ),
                .statement = try statement_source.auditInteractionDomains(
                    input.statement_authority,
                    input.statement_workspace,
                    input.statement_prepared,
                    input.leaf_preprocessing,
                    input.public_data,
                    input.leaf,
                    relations,
                    provider_relations,
                    claims.statement,
                    tuple_ledger,
                ),
                .public = try input.public_source.auditInteractionDomains(
                    input.vm_plan,
                    input.recursion_plan,
                    input.leaf_preprocessing,
                    input.leaf,
                    input.public_prepared,
                    input.public_data,
                    relations,
                    claims.public,
                    tuple_ledger,
                ),
            };
        }

        pub fn initComponents(
            self: *const Self,
            manifest: *const manifest_mod.Manifest,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
            claims: Claims,
        ) !Components {
            return .{
                .transcript = try self.inputs.transcript_source.initComponents(
                    manifest,
                    relations,
                    claims.transcript,
                ),
                .statement = try self.inputs.statement_authority.components(
                    manifest,
                    relations,
                    provider_relations,
                    claims.statement.rosterClaims(),
                ),
                .public = try self.inputs.public_source.initComponents(
                    manifest,
                    relations,
                    claims.public,
                ),
            };
        }
    };
}

fn preflightFreshOwnedTree(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    destination: []const []M31,
) !void {
    // `Manifest.placement` deliberately revalidates and rehashes the complete
    // manifest.  This boundary validates exactly once, then uses the sealed
    // placement table for the remainder of the transactional preflight.  In
    // particular, never put `placement` in the column-alias loops below: the
    // main tree has hundreds of columns and doing so turns this guard into
    // millions of redundant SHA-256 manifest rebuilds.
    try manifest.validate();
    if (destination.len != try totalColumns(manifest, tree))
        return error.InvalidTraceShape;

    const owned = try ownedTreeRanges(manifest, tree);

    // Validate owned geometry and the fresh-zero rollback precondition.
    inline for (0..PREFIX_ROW_COUNT) |row|
        try preflightOwnedRow(manifest, tree, @enumFromInt(row), destination);
    try preflightOwnedRow(manifest, tree, .range_check_8_8, destination);

    // Reject aliases between an owned output and every other global output.
    // This prevents a legal write to rows 0--17/35 from silently changing a
    // recursive row that another source owns.
    for (destination, 0..) |owned_column, owned_index| {
        if (!owned.contains(owned_index)) continue;
        for (destination, 0..) |other, other_index| {
            if (owned_index == other_index) continue;
            if (owned.contains(other_index) and
                other_index < owned_index)
            {
                continue;
            }
            if (try slicesOverlap(owned_column, other))
                return error.DestinationAlias;
        }
    }
}

fn preflightOwnedRow(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    row: roster.Component,
    destination: []const []M31,
) !void {
    const placement = try placementAfterValidation(manifest, row);
    const offset = try treeOffset(placement, tree);
    const column_count = try treeColumnCount(placement, tree);
    const end = std.math.add(usize, offset, column_count) catch
        return error.ArithmeticOverflow;
    if (end > destination.len) return error.InvalidTraceShape;
    const row_count = @as(usize, 1) << @intCast(placement.geometry.log_size);
    for (destination[offset..end]) |column| {
        if (column.len != row_count) return error.InvalidTraceShape;
        for (column) |value|
            if (!value.eql(M31.zero())) return error.DestinationNotZero;
    }
}

fn clearOwnedTree(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    destination: []const []M31,
) void {
    inline for (0..PREFIX_ROW_COUNT) |row|
        clearOwnedRow(manifest, tree, @enumFromInt(row), destination);
    clearOwnedRow(manifest, tree, .range_check_8_8, destination);
}

fn clearOwnedRow(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    row: roster.Component,
    destination: []const []M31,
) void {
    const placement = placementAfterValidation(manifest, row) catch unreachable;
    const offset = treeOffset(placement, tree) catch unreachable;
    const column_count = treeColumnCount(placement, tree) catch unreachable;
    for (destination[offset .. offset + column_count]) |column|
        @memset(column, M31.zero());
}

const ColumnRange = struct {
    start: usize,
    end: usize,

    fn contains(self: ColumnRange, column: usize) bool {
        return column >= self.start and column < self.end;
    }
};

const OwnedTreeRanges = struct {
    prefix: ColumnRange,
    shared_provider: ColumnRange,

    fn contains(self: OwnedTreeRanges, column: usize) bool {
        return self.prefix.contains(column) or
            self.shared_provider.contains(column);
    }
};

/// The manifest is roster-ordered, so rows 0--17 occupy one contiguous range
/// in every committed tree and row 35 occupies one final range.  Preparing
/// these two intervals once makes ownership tests constant-time.
fn ownedTreeRanges(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
) !OwnedTreeRanges {
    const first = try placementAfterValidation(manifest, .control);
    const last = try placementAfterValidation(
        manifest,
        .vm_public_logup_control,
    );
    const provider = try placementAfterValidation(manifest, .range_check_8_8);

    const prefix_start = try treeOffset(first, tree);
    const prefix_end = std.math.add(
        usize,
        try treeOffset(last, tree),
        try treeColumnCount(last, tree),
    ) catch return error.ArithmeticOverflow;
    const provider_start = try treeOffset(provider, tree);
    const provider_end = std.math.add(
        usize,
        provider_start,
        try treeColumnCount(provider, tree),
    ) catch return error.ArithmeticOverflow;
    return .{
        .prefix = .{ .start = prefix_start, .end = prefix_end },
        .shared_provider = .{
            .start = provider_start,
            .end = provider_end,
        },
    };
}

/// Reads a placement only after the caller has authenticated the complete
/// manifest.  Keeping this helper private makes the trust boundary explicit.
fn placementAfterValidation(
    manifest: *const manifest_mod.Manifest,
    row: roster.Component,
) !manifest_mod.Placement {
    return manifest.placements[@intFromEnum(row)] orelse
        error.ComponentNotAdmitted;
}

fn totalColumns(manifest: *const manifest_mod.Manifest, tree: usize) !usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => manifest.total_main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
        else => error.InvalidTreeIndex,
    };
}

fn treeOffset(placement: manifest_mod.Placement, tree: usize) !usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
        manifest_mod.MAIN_TREE_INDEX => placement.main_offset,
        manifest_mod.INTERACTION_TREE_INDEX => placement.interaction_offset,
        else => error.InvalidTreeIndex,
    };
}

fn treeColumnCount(placement: manifest_mod.Placement, tree: usize) !usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => placement.geometry.preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => placement.geometry.main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => placement.geometry.interaction_columns,
        else => error.InvalidTreeIndex,
    };
}

fn slicesOverlap(lhs: []const M31, rhs: []const M31) !bool {
    if (lhs.len == 0 or rhs.len == 0) return false;
    const lhs_start = @intFromPtr(lhs.ptr);
    const rhs_start = @intFromPtr(rhs.ptr);
    const lhs_bytes = std.math.mul(usize, lhs.len, @sizeOf(M31)) catch
        return error.ArithmeticOverflow;
    const rhs_bytes = std.math.mul(usize, rhs.len, @sizeOf(M31)) catch
        return error.ArithmeticOverflow;
    const lhs_end = std.math.add(usize, lhs_start, lhs_bytes) catch
        return error.ArithmeticOverflow;
    const rhs_end = std.math.add(usize, rhs_start, rhs_bytes) catch
        return error.ArithmeticOverflow;
    return lhs_start < rhs_end and rhs_start < lhs_end;
}

comptime {
    if (FIRST_PREFIX_ROW != 0 or PREFIX_ROW_COUNT != 18 or
        LAST_PREFIX_ROW + 1 != PREFIX_ROW_COUNT or SHARED_PROVIDER_ROW != 35 or
        OWNED_ROW_COUNT != 19)
    {
        @compileError("segment-leaf bundle roster ownership drifted");
    }
    if (transcript_source_mod.FIRST_ROW != 0 or
        transcript_source_mod.ROW_COUNT != 10 or
        public_source.FIRST_ROW != 12 or public_source.ROW_COUNT != 6)
    {
        @compileError("segment-leaf source cohort drifted");
    }
    if (HOT_ALL_TREES_HEAP_ALLOCATIONS !=
        HOT_TREE_HEAP_ALLOCATIONS[0] + HOT_TREE_HEAP_ALLOCATIONS[1] +
            HOT_TREE_HEAP_ALLOCATIONS[2] or
        HOT_ALL_TREES_PAIR_AUTHENTICATIONS != 0)
    {
        @compileError("segment-leaf hot-path accounting drifted");
    }
}
