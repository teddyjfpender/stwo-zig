//! Cold-to-hot runtime bridge from two successful SegmentV2 outer-verifier
//! artifacts to the exact temporal-parent Tree0/Tree1/Tree2 prefix columns.
//!
//! The cold constructor re-admits the shared manifest, both dynamic verifier
//! captures, fixed recursive witnesses, pointer-free publications, prepared
//! native leaf sources, and authenticated temporal pair. It then owns every
//! rows-0--17 authority and allocation needed by the temporal V3 writer.
//! Tree publication is allocation-free: Tree0 and Tree1 are filled in one
//! transaction, while Tree2 remains challenge ordered and is filled only
//! after the parent transcript draws its universal relations.
//!
//! This module is intentionally only the prefix-runtime owner. Rows 18--35,
//! the complete parent manifest/gate, PCS commitment, independent verification,
//! and verifier-minted publication are owned by the append-only temporal V3
//! cohort and native engine; none is claimed as a capability of this partial
//! module.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const binary_outer = @import("recursive_binary_outer.zig");
const leaf_outer = @import("recursive_segment_v2_leaf_outer.zig");
const pair_authority = @import("recursive_temporal_pair_authority_v2.zig");
const segment_artifact =
    @import("recursive_segment_v2_verified_artifact.zig");
const temporal_nonfri = @import("recursive_temporal_nonfri_source_v2.zig");
const support = @import("recursive_temporal_parent_prefix_support.zig");
const contract = @import("recursive_temporal_parent_prefix_contract.zig");

const M31 = stwo_core.fields.m31.M31;
const recursion = frontend.recursion;
const binary_fri_source = recursion.binary_fri_outer_source;
const binary_inactive = recursion.binary_inactive_outer_source;
const leaf_authority = recursion.segment_leaf_authority;
const segment_public = recursion.segment_public_outer_source;
const statement_air = recursion.outer_parent_statement_air_source;
const statement_source = recursion.segment_statement_outer_source;
const range_authority = recursion.outer_parent_range_authority;
const range_bridge = recursion.air.range_check_8_8_bridge;
const schedule = recursion.air.verifier_schedule;
const universal = recursion.air.universal_challenges;
const vm_claim = recursion.vm_public_claim;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-parent-prefix-runtime/v1\x00";
pub const CHILD_COUNT: usize = 2;
pub const HOT_TREE_HEAP_ALLOCATIONS: usize = 0;
pub const HOT_BASE_LOGICAL_PREPARATIONS: usize = 1;
pub const RETAINED_CHILD_CAPTURE_POINTERS: usize = 0;
pub const COMPLETE_PARENT_MANIFEST_AVAILABLE = false;
pub const COMPLETE_PARENT_GATE_AVAILABLE = false;
pub const VERIFIED_PARENT_PROOF_AVAILABLE = false;
pub const VERIFIED_PARENT_PUBLICATION_AVAILABLE = false;
pub const PRODUCTION_CAPABILITY = false;

pub const ROW35_AUTHORITY_FORMAT_VERSION: u16 = 1;
pub const ROW35_AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-parent-row35-authority/v1\x00";

pub const Error = error{
    ArithmeticOverflow,
    ChildPreparedLeafMismatch,
    CompleteParentUnavailable,
    DuplicatePreparedLeaf,
    InvalidPrefixRuntime,
    InvalidPrefixRuntimePhase,
    InvalidTreeStorage,
    RuntimeProfileMismatch,
};

pub const RuntimeInputsV1 = contract.RuntimeInputsV1;
pub const PhaseV1 = contract.PhaseV1;
pub const BaseTreeReceiptsV1 = contract.BaseTreeReceiptsV1;

/// Read-only capability for the exact binary-statement range ledger reused at
/// universal roster row 35.  Every pointer is rebound to its owning prefix
/// runtime by `validateAgainst`; copying this value cannot detach or replace a
/// provider snapshot, witness executor, or typed AIR definition.
pub const Row35AuthorityV1 = struct {
    format_version: u16 = ROW35_AUTHORITY_FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    padding: [4]u8 = .{ 0, 0, 0, 0 },
    definition: *const range_bridge.Definition,
    executor: *const range_bridge.Executor,
    prepared: *const range_authority.Prepared,
    provider: *const range_bridge.PreparedBatch,
    prefix_authority_sha_id: [32]u8,
    statement_source_id: temporal_nonfri.Digest,
    source_authority_sha_id: [32]u8,
    provider_snapshot_sha_id: [32]u8,
    identity: [32]u8,

    pub fn validateAgainst(
        self: *const Row35AuthorityV1,
        owner: *OwnerV1,
    ) !void {
        try owner.validateCold();
        try owner.statement_rows.validateHot(
            &owner.statement_authority,
            &owner.statement_workspace,
        );
        try owner.statement_rows.range.validateAgainst(
            &owner.statement_workspace.range,
            .{
                .preprocessing = &owner.statement_authority
                    .statement_semantics_preprocessing,
                .values = owner.statement_rows.statement_values,
                .left = &owner.statement_rows.left_words,
                .right = &owner.statement_rows.right_words,
                .parent = &owner.statement_rows.parent_words,
            },
        );
        try owner.statement_authority.range_definition.validate();
        try owner.statement_authority.range_executor.validate();
        try owner.statement_rows.range.provider().validate();

        if (self.format_version != ROW35_AUTHORITY_FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.mem.allEqual(u8, &self.padding, 0) or
            self.definition != &owner.statement_authority.range_definition or
            self.executor != &owner.statement_authority.range_executor or
            self.prepared != &owner.statement_rows.range or
            self.provider != owner.statement_rows.range.provider() or
            !std.mem.eql(
                u8,
                &self.prefix_authority_sha_id,
                &owner.authority_sha_id,
            ) or !std.meta.eql(
            self.statement_source_id,
            owner.statement_rows.source_id,
        ) or !std.mem.eql(
            u8,
            &self.source_authority_sha_id,
            &owner.statement_rows.range.source_authority_digest,
        ) or !std.mem.eql(
            u8,
            &self.provider_snapshot_sha_id,
            &owner.statement_rows.range.provider().authority_digest,
        ) or !std.mem.eql(
            u8,
            &self.identity,
            &support.row35Identity(ROW35_AUTHORITY_DOMAIN, self),
        )) {
            return error.InvalidPrefixRuntime;
        }
    }
};

const OwnedTreeV3 = struct {
    allocator: std.mem.Allocator,
    tree_index: u8,
    padding: [7]u8 = .{ 0, 0, 0, 0, 0, 0, 0 },
    layout_sha_id: [32]u8,
    columns: [][]M31,
    cells: []M31,

    fn init(
        allocator: std.mem.Allocator,
        layout: *const temporal_nonfri.TemporalPrefixCommitmentLayoutV3,
        tree: usize,
    ) !OwnedTreeV3 {
        try layout.validate();
        if (tree >= temporal_nonfri.PREFIX_TREE_COUNT)
            return error.InvalidTreeStorage;
        const column_count = support.treeColumnCount(layout, tree);
        const cell_count = try support.treeCellCount(layout, tree);
        const columns = try allocator.alloc([]M31, column_count);
        errdefer allocator.free(columns);
        const cells = try allocator.alloc(M31, cell_count);
        errdefer allocator.free(cells);
        @memset(cells, M31.zero());
        var column_cursor: usize = 0;
        var cell_cursor: usize = 0;
        for (layout.placements) |placement| {
            const offset = support.treeOffset(placement, tree);
            const count = support.treeGeometryColumns(placement, tree);
            const trace_size = @as(usize, 1) <<
                @intCast(placement.geometry.log_size);
            if (offset != column_cursor) return error.InvalidTreeStorage;
            for (columns[offset .. offset + count]) |*column| {
                const next = std.math.add(usize, cell_cursor, trace_size) catch
                    return error.ArithmeticOverflow;
                if (next > cells.len) return error.InvalidTreeStorage;
                column.* = cells[cell_cursor..next];
                cell_cursor = next;
            }
            column_cursor += count;
        }
        if (column_cursor != columns.len or cell_cursor != cells.len)
            return error.InvalidTreeStorage;
        var result = OwnedTreeV3{
            .allocator = allocator,
            .tree_index = @intCast(tree),
            .layout_sha_id = layout.layout_sha_id,
            .columns = columns,
            .cells = cells,
        };
        try result.validate(layout);
        return result;
    }

    fn deinit(self: *OwnedTreeV3) void {
        self.allocator.free(self.cells);
        self.allocator.free(self.columns);
        self.* = undefined;
    }

    fn validate(
        self: *const OwnedTreeV3,
        layout: *const temporal_nonfri.TemporalPrefixCommitmentLayoutV3,
    ) !void {
        try layout.validate();
        const tree: usize = self.tree_index;
        if (tree >= temporal_nonfri.PREFIX_TREE_COUNT or
            !std.mem.allEqual(u8, &self.padding, 0) or
            !std.mem.eql(u8, &self.layout_sha_id, &layout.layout_sha_id) or
            self.columns.len != support.treeColumnCount(layout, tree) or
            self.cells.len != try support.treeCellCount(layout, tree))
        {
            return error.InvalidTreeStorage;
        }
        var column_cursor: usize = 0;
        var cell_cursor: usize = 0;
        for (layout.placements) |placement| {
            const offset = support.treeOffset(placement, tree);
            const count = support.treeGeometryColumns(placement, tree);
            const trace_size = @as(usize, 1) <<
                @intCast(placement.geometry.log_size);
            if (offset != column_cursor) return error.InvalidTreeStorage;
            for (self.columns[offset .. offset + count]) |column| {
                const next = std.math.add(usize, cell_cursor, trace_size) catch
                    return error.ArithmeticOverflow;
                if (next > self.cells.len or column.len != trace_size or
                    @intFromPtr(column.ptr) !=
                        @intFromPtr(self.cells[cell_cursor..].ptr))
                {
                    return error.InvalidTreeStorage;
                }
                cell_cursor = next;
            }
            column_cursor += count;
        }
        if (column_cursor != self.columns.len or cell_cursor != self.cells.len)
            return error.InvalidTreeStorage;
    }

    fn clear(self: *OwnedTreeV3) void {
        @memset(self.cells, M31.zero());
    }

    fn isZero(self: *const OwnedTreeV3) bool {
        for (self.cells) |value| if (!value.isZero()) return false;
        return true;
    }
};

const OwnedPrefixTreesV3 = struct {
    tree0: OwnedTreeV3,
    tree1: OwnedTreeV3,
    tree2: OwnedTreeV3,

    fn init(
        allocator: std.mem.Allocator,
        layout: *const temporal_nonfri.TemporalPrefixCommitmentLayoutV3,
    ) !OwnedPrefixTreesV3 {
        var tree0 = try OwnedTreeV3.init(
            allocator,
            layout,
            temporal_nonfri.PREFIX_TREE0_INDEX,
        );
        errdefer tree0.deinit();
        var tree1 = try OwnedTreeV3.init(
            allocator,
            layout,
            temporal_nonfri.PREFIX_TREE1_INDEX,
        );
        errdefer tree1.deinit();
        var tree2 = try OwnedTreeV3.init(
            allocator,
            layout,
            temporal_nonfri.PREFIX_TREE2_INDEX,
        );
        errdefer tree2.deinit();
        return .{ .tree0 = tree0, .tree1 = tree1, .tree2 = tree2 };
    }

    fn deinit(self: *OwnedPrefixTreesV3) void {
        self.tree2.deinit();
        self.tree1.deinit();
        self.tree0.deinit();
        self.* = undefined;
    }

    fn validate(
        self: *const OwnedPrefixTreesV3,
        layout: *const temporal_nonfri.TemporalPrefixCommitmentLayoutV3,
    ) !void {
        try self.tree0.validate(layout);
        try self.tree1.validate(layout);
        try self.tree2.validate(layout);
        if (support.slicesOverlap(self.tree0.cells, self.tree1.cells) or
            support.slicesOverlap(self.tree0.cells, self.tree2.cells) or
            support.slicesOverlap(self.tree1.cells, self.tree2.cells))
        {
            return error.InvalidTreeStorage;
        }
    }

    fn clear(self: *OwnedPrefixTreesV3) void {
        self.tree2.clear();
        self.tree1.clear();
        self.tree0.clear();
    }
};

/// Self-contained owner for the temporal non-FRI prefix. Child captures are
/// consumed only during cold construction; this value retains no capture or
/// prepared-leaf pointer and can be moved safely between proof stages.
pub const OwnerV1 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    phase: PhaseV1 = .cold,
    padding: [3]u8 = .{ 0, 0, 0 },
    child_prepared_leaf_sha_ids: [CHILD_COUNT][32]u8,
    child_publication_ids: [CHILD_COUNT]temporal_nonfri.Digest,
    segment_manifest_sha_ids: [CHILD_COUNT][32]u8,
    shape: vm_claim.Shape,

    vm_plan: schedule.Plan,
    recursion_plan: schedule.Plan,
    leaf_preprocessing: leaf_authority.Preprocessing,
    statement_authority: statement_source.Authority,
    statement_workspace: statement_air.Workspace,
    statement_rows: temporal_nonfri.PreparedRows10Through11V2,
    public_source: segment_public.Source,
    inactive_source: binary_inactive.Source,
    inactive_prepared: binary_inactive.Prepared,
    transcript_rows: temporal_nonfri.PreparedTranscriptRowsV2,
    rows_10_through_17: temporal_nonfri.Rows10Through17AuthorityV2,
    custody: temporal_nonfri.TemporalRows0Through17CustodyV3,
    writer: temporal_nonfri.TemporalPrefixTreeWriterV3,
    trees: OwnedPrefixTreesV3,
    base_receipts: ?BaseTreeReceiptsV1 = null,
    interactions: ?temporal_nonfri.TemporalPrefixInteractionsV3 = null,
    authority_sha_id: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        inputs: RuntimeInputsV1,
    ) !OwnerV1 {
        const shape = try inputs.validate();
        const left_prepared = inputs.prepared_leaves[0];
        const artifacts = support.temporalArtifacts(inputs.artifacts);
        const outer_schedule_shape = try temporal_nonfri.outerScheduleShape(
            artifacts[0].capture,
        );
        const right_schedule_shape = try temporal_nonfri.outerScheduleShape(
            artifacts[1].capture,
        );
        if (!std.meta.eql(outer_schedule_shape, right_schedule_shape))
            return error.RuntimeProfileMismatch;

        var vm_plan = try schedule.Plan.initShape(
            allocator,
            left_prepared.vm_plan.spec,
            outer_schedule_shape,
        );
        errdefer vm_plan.deinit();
        var recursion_plan = try schedule.Plan.initShape(
            allocator,
            left_prepared.recursion_plan.spec,
            outer_schedule_shape,
        );
        errdefer recursion_plan.deinit();
        var leaf_preprocessing = try leaf_authority.Preprocessing.init(
            allocator,
            shape,
        );
        errdefer leaf_preprocessing.deinit();
        var statement_authority = try statement_source.Authority.init(
            allocator,
            &leaf_preprocessing,
        );
        errdefer statement_authority.deinit();
        var statement_workspace = try statement_air.Workspace.init(allocator);
        errdefer statement_workspace.deinit();
        var statement_rows = try temporal_nonfri.PreparedRows10Through11V2.init(
            allocator,
            &statement_authority,
            &statement_workspace,
            inputs.artifacts.pair,
        );
        errdefer statement_rows.deinit();
        var public_source = try segment_public.Source.init(
            allocator,
            &vm_plan,
            &recursion_plan,
            &leaf_preprocessing,
            segment_artifact.CLAIM_COUNT,
        );
        errdefer public_source.deinit();
        var inactive_source = try binary_inactive.Source.init(
            allocator,
            &public_source,
            &vm_plan,
            &recursion_plan,
            &leaf_preprocessing,
        );
        errdefer inactive_source.deinit();
        var inactive_prepared = try binary_inactive.Prepared.init(
            allocator,
            &inactive_source,
            &public_source,
            &vm_plan,
            &recursion_plan,
            &leaf_preprocessing,
        );
        errdefer inactive_prepared.deinit();
        var transcript_rows = try temporal_nonfri.PreparedTranscriptRowsV2.init(
            allocator,
            inputs.artifacts.pair,
            artifacts[0],
            artifacts[1],
        );
        errdefer transcript_rows.deinit();
        const rows_10_through_17 =
            try temporal_nonfri.Rows10Through17AuthorityV2.init(
                &statement_rows,
                &statement_authority,
                &statement_workspace,
                inputs.artifacts.pair,
                &inactive_source,
                &inactive_prepared,
                &public_source,
                &vm_plan,
                &recursion_plan,
                &leaf_preprocessing,
            );
        var custody: temporal_nonfri.TemporalRows0Through17CustodyV3 =
            undefined;
        try temporal_nonfri.initTemporalRows0Through17CustodyInto(
            &custody,
            inputs.artifacts.pair,
            &transcript_rows,
            &statement_rows,
            &statement_authority,
            &statement_workspace,
            &rows_10_through_17,
            &inactive_source,
            &vm_plan,
            &recursion_plan,
            artifacts[0],
            artifacts[1],
        );

        const sources = temporal_nonfri.TemporalPrefixTreeSourcesV3{
            .custody = &custody,
            .transcript = &transcript_rows,
            .statement = &statement_rows,
            .statement_authority = &statement_authority,
            .statement_workspace = &statement_workspace,
            .inactive_source = &inactive_source,
            .inactive_prepared = &inactive_prepared,
            .typed_public = &public_source,
            .vm_plan = &vm_plan,
            .recursion_plan = &recursion_plan,
            .preprocessing = &leaf_preprocessing,
        };
        var writer = try temporal_nonfri.TemporalPrefixTreeWriterV3.init(
            allocator,
            sources,
        );
        errdefer writer.deinit();
        var trees = try OwnedPrefixTreesV3.init(
            allocator,
            &custody.commitment_layout,
        );
        errdefer trees.deinit();

        var result = OwnerV1{
            .allocator = allocator,
            .child_prepared_leaf_sha_ids = .{
                inputs.prepared_leaves[0].identity,
                inputs.prepared_leaves[1].identity,
            },
            .child_publication_ids = .{
                inputs.artifacts.children[0].publication.publication_id,
                inputs.artifacts.children[1].publication.publication_id,
            },
            .segment_manifest_sha_ids = .{
                inputs.artifacts.segment_manifests[0].seal,
                inputs.artifacts.segment_manifests[1].seal,
            },
            .shape = shape,
            .vm_plan = vm_plan,
            .recursion_plan = recursion_plan,
            .leaf_preprocessing = leaf_preprocessing,
            .statement_authority = statement_authority,
            .statement_workspace = statement_workspace,
            .statement_rows = statement_rows,
            .public_source = public_source,
            .inactive_source = inactive_source,
            .inactive_prepared = inactive_prepared,
            .transcript_rows = transcript_rows,
            .rows_10_through_17 = rows_10_through_17,
            .custody = custody,
            .writer = writer,
            .trees = trees,
            .authority_sha_id = undefined,
        };
        result.authority_sha_id = support.ownerIdentity(AUTHORITY_DOMAIN, &result);
        try result.validateCold();
        return result;
    }

    pub fn deinit(self: *OwnerV1) void {
        self.trees.deinit();
        self.writer.deinit();
        self.transcript_rows.deinit();
        self.inactive_prepared.deinit();
        self.inactive_source.deinit();
        self.public_source.deinit();
        self.statement_rows.deinit();
        self.statement_workspace.deinit();
        self.statement_authority.deinit();
        self.leaf_preprocessing.deinit();
        self.recursion_plan.deinit();
        self.vm_plan.deinit();
        self.* = undefined;
    }

    /// Exhaustive owner audit. It is allocation-free because complete plan
    /// hashing occurred at `RuntimeInputsV1.validate` before ownership moved.
    pub fn validateCold(self: *OwnerV1) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.mem.allEqual(u8, &self.padding, 0))
        {
            return error.InvalidPrefixRuntime;
        }
        try self.leaf_preprocessing.validate();
        const source_view = self.sourceView();
        try self.writer.validateAgainst(source_view);
        try self.trees.validate(&self.custody.commitment_layout);
        if (!std.mem.eql(
            u8,
            &self.authority_sha_id,
            &support.ownerIdentity(AUTHORITY_DOMAIN, self),
        ))
            return error.InvalidPrefixRuntime;
        try self.validatePhase();
    }

    /// Fills Tree0 and Tree1 as one failure-atomic transaction. All source
    /// checks and all 18 logical-row preparations occur once.
    pub fn fillBaseTrees(self: *OwnerV1) !BaseTreeReceiptsV1 {
        try self.validateCold();
        if (self.phase != .cold) return error.InvalidPrefixRuntimePhase;
        errdefer {
            self.trees.tree1.clear();
            self.trees.tree0.clear();
        }
        const receipts = try self.writer.fillBaseTreesInto(
            self.sourceView(),
            self.trees.tree0.columns,
            self.trees.tree1.columns,
        );
        const base = try BaseTreeReceiptsV1.init(&self.custody, receipts);
        try base.trees[0].validateStorage(
            &self.custody,
            self.trees.tree0.columns,
        );
        try base.trees[1].validateStorage(
            &self.custody,
            self.trees.tree1.columns,
        );
        self.base_receipts = base;
        self.phase = .base_trees_filled;
        return base;
    }

    /// Challenge-ordered Tree2 fill. The universal relations must be those
    /// drawn after the caller commits both base-tree receipts.
    pub fn fillInteractionTree(
        self: *OwnerV1,
        relations: *const universal.UniversalRelations,
    ) !temporal_nonfri.TemporalPrefixInteractionsV3 {
        try self.validateCold();
        if (self.phase != .base_trees_filled)
            return error.InvalidPrefixRuntimePhase;
        const generated = try self.writer.fillTree2Into(
            self.sourceView(),
            relations,
            self.trees.tree2.columns,
        );
        try generated.tree.validateStorage(
            &self.custody,
            self.trees.tree2.columns,
        );
        self.interactions = generated;
        self.phase = .prefix_trees_filled;
        return generated;
    }

    /// Revalidates and lends one exact committed-column view to the PCS
    /// adapter. The returned slices remain owned by this runtime.
    pub fn treeColumns(
        self: *OwnerV1,
        tree: usize,
    ) ![]const []M31 {
        try self.validateCold();
        switch (tree) {
            temporal_nonfri.PREFIX_TREE0_INDEX,
            temporal_nonfri.PREFIX_TREE1_INDEX,
            => if (self.phase == .cold)
                return error.InvalidPrefixRuntimePhase,
            temporal_nonfri.PREFIX_TREE2_INDEX => if (self.phase != .prefix_trees_filled)
                return error.InvalidPrefixRuntimePhase,
            else => return error.InvalidTreeStorage,
        }
        return switch (tree) {
            temporal_nonfri.PREFIX_TREE0_INDEX => self.trees.tree0.columns,
            temporal_nonfri.PREFIX_TREE1_INDEX => self.trees.tree1.columns,
            temporal_nonfri.PREFIX_TREE2_INDEX => self.trees.tree2.columns,
            else => error.InvalidTreeStorage,
        };
    }

    /// Revalidated, pointer-stable custody for manifest rows 0--17.  The
    /// caller never reconstructs prefix geometry from column lengths.
    pub fn commitmentLayout(
        self: *OwnerV1,
    ) !*const temporal_nonfri.TemporalPrefixCommitmentLayoutV3 {
        try self.validateCold();
        return &self.custody.commitment_layout;
    }

    /// Lends the exact transcript authority consumed by rows 0--9.  The
    /// temporal suffix uses this same immutable replay to derive query words
    /// and the row-34 transcript requester range; no detached transcript or
    /// caller-authored query schedule is accepted at the join.
    pub fn transcriptRows(
        self: *OwnerV1,
    ) !*const temporal_nonfri.PreparedTranscriptRowsV2 {
        try self.validateCold();
        try self.transcript_rows.validate();
        return &self.transcript_rows;
    }

    /// Publishes row 11's authenticated statement circuit as the additional
    /// arithmetic lane shared by rows 30--32.  This is the only non-FRI lane
    /// in the temporal suffix lowering plan, and both graph and evaluation
    /// continue to borrow storage owned by this prefix runtime.
    pub fn sharedArithmeticInput(
        self: *OwnerV1,
    ) !binary_fri_source.SharedArithmeticInput {
        try self.validateCold();
        try self.statement_rows.validateHot(
            &self.statement_authority,
            &self.statement_workspace,
        );
        return binary_fri_source.SharedArithmeticInput.seal(
            statement_air.loweringLane(&self.statement_authority),
            .{
                .circuit_identity = self.statement_rows.circuit_evaluation
                    .circuit_identity,
                .values = self.statement_rows.circuit_evaluation.values(),
            },
        );
    }

    /// Mints the sole row-35 range-table capability from the same statement
    /// snapshot which produced rows 10 and 11.  This is intentionally a
    /// borrowed view: all four pointers must continue to target this owner.
    pub fn row35Authority(self: *OwnerV1) !Row35AuthorityV1 {
        try self.validateCold();
        var result = Row35AuthorityV1{
            .definition = &self.statement_authority.range_definition,
            .executor = &self.statement_authority.range_executor,
            .prepared = &self.statement_rows.range,
            .provider = self.statement_rows.range.provider(),
            .prefix_authority_sha_id = self.authority_sha_id,
            .statement_source_id = self.statement_rows.source_id,
            .source_authority_sha_id = self.statement_rows.range.source_authority_digest,
            .provider_snapshot_sha_id = self.statement_rows.range.provider().authority_digest,
            .identity = undefined,
        };
        result.identity = support.row35Identity(ROW35_AUTHORITY_DOMAIN, &result);
        try result.validateAgainst(self);
        return result;
    }

    /// Reuses the prefix writer's stable component owners and exact committed
    /// interaction claims.  A complete parent cohort appends rows 18--35 to
    /// this returned prefix before sealing its proof gate.
    pub fn initComponentsForManifest(
        self: *OwnerV1,
        comptime manifest_contract: type,
        manifest: *const manifest_contract.Manifest,
        relations: *const universal.UniversalRelations,
    ) !temporal_nonfri.TemporalPrefixComponentsForManifest(manifest_contract) {
        try self.validateCold();
        if (self.phase != .prefix_trees_filled)
            return error.InvalidPrefixRuntimePhase;
        const interactions = &self.interactions.?;
        return self.writer.initComponentsForManifest(
            self.sourceView(),
            manifest_contract,
            manifest,
            relations,
            interactions,
        );
    }

    /// Cold verifier/provenance pass for global relation closure.  The
    /// returned value owns no pointers and is bound to the exact Tree-2
    /// receipt retained by this runtime.
    pub fn auditInteractionDomains(
        self: *OwnerV1,
        relations: *const universal.UniversalRelations,
        tuple_ledger: ?*recursion.air.relation_interaction.TupleLedger,
    ) !temporal_nonfri.TemporalPrefixDomainAuditsV3 {
        try self.validateCold();
        if (self.phase != .prefix_trees_filled)
            return error.InvalidPrefixRuntimePhase;
        return self.writer.auditInteractionDomains(
            self.sourceView(),
            relations,
            &self.interactions.?,
            tuple_ledger,
        );
    }

    pub fn requireCompleteParent(_: *const OwnerV1) !void {
        return error.CompleteParentUnavailable;
    }

    fn sourceView(self: *OwnerV1) temporal_nonfri.TemporalPrefixTreeSourcesV3 {
        return .{
            .custody = &self.custody,
            .transcript = &self.transcript_rows,
            .statement = &self.statement_rows,
            .statement_authority = &self.statement_authority,
            .statement_workspace = &self.statement_workspace,
            .inactive_source = &self.inactive_source,
            .inactive_prepared = &self.inactive_prepared,
            .typed_public = &self.public_source,
            .vm_plan = &self.vm_plan,
            .recursion_plan = &self.recursion_plan,
            .preprocessing = &self.leaf_preprocessing,
        };
    }

    fn validatePhase(self: *OwnerV1) !void {
        switch (self.phase) {
            .cold => {
                if (self.base_receipts != null or self.interactions != null or
                    !self.trees.tree0.isZero() or
                    !self.trees.tree1.isZero() or
                    !self.trees.tree2.isZero())
                {
                    return error.InvalidPrefixRuntimePhase;
                }
            },
            .base_trees_filled => {
                const base = self.base_receipts orelse
                    return error.InvalidPrefixRuntimePhase;
                if (self.interactions != null or !self.trees.tree2.isZero())
                    return error.InvalidPrefixRuntimePhase;
                try base.validate(&self.custody);
                try base.trees[0].validateStorage(
                    &self.custody,
                    self.trees.tree0.columns,
                );
                try base.trees[1].validateStorage(
                    &self.custody,
                    self.trees.tree1.columns,
                );
            },
            .prefix_trees_filled => {
                const base = self.base_receipts orelse
                    return error.InvalidPrefixRuntimePhase;
                const generated = self.interactions orelse
                    return error.InvalidPrefixRuntimePhase;
                try base.validate(&self.custody);
                try generated.validate(&self.custody);
                try base.trees[0].validateStorage(
                    &self.custody,
                    self.trees.tree0.columns,
                );
                try base.trees[1].validateStorage(
                    &self.custody,
                    self.trees.tree1.columns,
                );
                try generated.tree.validateStorage(
                    &self.custody,
                    self.trees.tree2.columns,
                );
            },
        }
    }
};

comptime {
    if (CHILD_COUNT != pair_authority.CHILD_COUNT or
        HOT_TREE_HEAP_ALLOCATIONS != 0 or
        HOT_BASE_LOGICAL_PREPARATIONS != 1 or
        RETAINED_CHILD_CAPTURE_POINTERS != 0 or
        COMPLETE_PARENT_MANIFEST_AVAILABLE or COMPLETE_PARENT_GATE_AVAILABLE or
        VERIFIED_PARENT_PROOF_AVAILABLE or VERIFIED_PARENT_PUBLICATION_AVAILABLE or
        PRODUCTION_CAPABILITY or temporal_nonfri.ROWS_0_THROUGH_17_TREE_WRITER_AVAILABLE)
    {
        @compileError("temporal parent prefix runtime capability drifted");
    }
}

test "temporal parent prefix runtime remains fail closed at the full parent" {
    std.testing.refAllDeclsRecursive(RuntimeInputsV1);
    std.testing.refAllDeclsRecursive(OwnerV1);
    try std.testing.expectEqual(@as(usize, 0), HOT_TREE_HEAP_ALLOCATIONS);
    try std.testing.expectEqual(@as(usize, 1), HOT_BASE_LOGICAL_PREPARATIONS);
    try std.testing.expect(!COMPLETE_PARENT_MANIFEST_AVAILABLE);
    try std.testing.expect(!COMPLETE_PARENT_GATE_AVAILABLE);
    try std.testing.expect(!VERIFIED_PARENT_PROOF_AVAILABLE);
    try std.testing.expect(!VERIFIED_PARENT_PUBLICATION_AVAILABLE);
    try std.testing.expect(!PRODUCTION_CAPABILITY);
}
