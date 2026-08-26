//! End-to-end custody, composition, mutation, and performance gates for the
//! binary non-FRI rows 0--17/35 bundle.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

const bundle_mod = @import("binary_pair_nonfri_outer_bundle.zig");
const pair_authority = @import("binary_pair_authority.zig");
const pair_fixture_mod = @import("binary_pair_test_fixture.zig");
const transcript_source_mod = @import("binary_transcript_outer_source.zig");
const statement_source = @import("outer_parent_statement_air_source.zig");
const statement_parent_source = @import("outer_parent_statement_source.zig");
const outer_transcript_source = @import("outer_parent_transcript_source.zig");
const statement_authority_mod = @import("segment_statement_outer_source.zig");
const admission = @import("outer_parent_child_admission.zig");
const outer_support = @import("outer_parent_transcript_source_test.zig");
const inactive_source_mod = @import("binary_inactive_outer_source.zig");
const public_authority_mod = @import("segment_public_outer_source.zig");
const leaf_authority = @import("segment_leaf_authority.zig");
const pair_node = @import("pair_node.zig");
const vm_claim = @import("vm_public_claim.zig");
const global_closure = @import("binary_global_closure_outer_source.zig");
const relation = @import("../air/lang/relation.zig");

const air = @import("air/mod.zig");
const manifest_mod = air.universal_adapter_manifest;
const roster = air.universal_roster;
const shared_provider = air.universal_shared_provider;
const universal = air.universal_challenges;
const universal_manifest = air.universal_manifest;

pub const TRANSCRIPT_DIMENSIONS = pair_fixture_mod.DIMENSIONS;
pub const STATEMENT_DIMENSIONS = outer_support.TEST_DIMENSIONS;
const PairPrepared = pair_authority.Prepared(TRANSCRIPT_DIMENSIONS);
const TranscriptSource = transcript_source_mod.Source(TRANSCRIPT_DIMENSIONS);
const StatementParent = statement_parent_source.Prepared(STATEMENT_DIMENSIONS);
const StatementPrepared = statement_source.Prepared(STATEMENT_DIMENSIONS);
const Bundle = bundle_mod.Bundle(TRANSCRIPT_DIMENSIONS, STATEMENT_DIMENSIONS);

// Shared fixtures and mutation helpers for this conformance suite.

pub const Fixture = struct {
    allocator: std.mem.Allocator,
    pair: pair_fixture_mod.HonestFixture,
    pair_prepared: PairPrepared,
    transcript_source: TranscriptSource,
    transcript_workspace: TranscriptSource.InteractionWorkspace,

    left: outer_support.AdmittedChild,
    right: outer_support.AdmittedChild,
    left_binding: admission.PairChildInputsV1,
    right_binding: admission.PairChildInputsV1,
    statement_suite: pair_node.PreparedProtocolSuiteV1,
    statement_scratch: []u8,
    statement_parent: StatementParent,
    publications: [statement_source.CHILD_COUNT]statement_source.VerifiedStatementPublicationV1,
    leaf_preprocessing: leaf_authority.Preprocessing,
    statement_authority: statement_authority_mod.Authority,
    statement_workspace: statement_source.Workspace,
    statement_prepared: StatementPrepared,

    public_authority: public_authority_mod.Source,
    inactive_source: inactive_source_mod.Source,
    inactive_prepared: inactive_source_mod.Prepared,

    pub fn init(allocator: std.mem.Allocator) !Fixture {
        var pair = try pair_fixture_mod.HonestFixture.init(allocator);
        errdefer pair.deinit();
        try pair_fixture_mod.installAuthenticatedMerkleWires(&pair);
        try alignPairVerificationKey(&pair, outer_support.digest(71));
        const recursion_plans = [2]*const air.verifier_schedule.Plan{
            &pair.recursion_plans[0],
            &pair.recursion_plans[1],
        };
        var pair_prepared = try PairPrepared.init(
            allocator,
            .sealed_candidate,
            &pair.vm_plan,
            recursion_plans,
            &pair.transcript_preprocessing,
            &pair.statement_preprocessing,
            &pair.semantics,
            &pair.validation_workspace,
            pair.pair_inputs,
            pair.children(),
        );
        errdefer pair_prepared.deinit();
        const minimum_logs = try pair_prepared.minimumLogSizes(
            &pair.vm_plan,
            &pair.recursion_plans[0],
            &pair.transcript_preprocessing,
            &pair.statement_preprocessing,
        );
        var transcript_source = try TranscriptSource.init(
            allocator,
            &pair.vm_plan,
            recursion_plans,
            &pair.transcript_preprocessing,
            &pair_prepared,
            try transcript_source_mod.PowLogSizes.init(
                @max(transcript_source_mod.MIN_LOG_SIZE, minimum_logs[6]),
                @max(transcript_source_mod.MIN_LOG_SIZE, minimum_logs[7]),
            ),
        );
        errdefer transcript_source.deinit();
        var transcript_workspace = try TranscriptSource.InteractionWorkspace.init(
            allocator,
            &transcript_source,
            &pair.transcript_preprocessing,
            &pair_prepared,
        );
        errdefer transcript_workspace.deinit();

        var left = try outer_support.AdmittedChild.initWithStatement(
            allocator,
            0,
            outer_support.digest(11),
            pair_prepared.left_statement,
        );
        errdefer left.deinit();
        var right = try outer_support.AdmittedChild.initWithStatement(
            allocator,
            1,
            outer_support.digest(11),
            pair_prepared.right_statement,
        );
        errdefer right.deinit();
        const outer_pair = outer_transcript_source.PairInputsV1{
            .context = pair.pair_inputs.context,
            .root_pin = pair.pair_inputs.root_pin,
        };
        const left_binding = try bindingFor(
            &left,
            outer_pair,
            pair_prepared.authority.children[0],
        );
        const right_binding = try bindingFor(
            &right,
            outer_pair,
            pair_prepared.authority.children[1],
        );
        const verifier_authority = authorityFromBindings(
            outer_pair.context,
            .{ left_binding, right_binding },
            .{ left.candidate, right.candidate },
        );
        const statement_suite = try pair_node.prepareProtocolSuite();
        const statement_scratch = try allocator.alloc(
            u8,
            admission.serializedByteCount(STATEMENT_DIMENSIONS),
        );
        errdefer allocator.free(statement_scratch);
        const outer_pair_inputs = statement_parent_source.AuthorityInputsV1{
            .pair = outer_pair,
            .verified = &verifier_authority,
            .suite = &statement_suite,
        };
        var statement_parent: StatementParent = undefined;
        try StatementParent.prepareInto(
            &statement_parent,
            statement_scratch,
            outer_pair_inputs,
            .{
                left.bundle(left_binding),
                right.bundle(right_binding),
            },
        );
        var publications: [statement_source.CHILD_COUNT]statement_source.VerifiedStatementPublicationV1 = undefined;
        try statement_source.publishVerifierStatementsInto(
            STATEMENT_DIMENSIONS,
            &publications,
            &statement_parent,
            &statement_suite,
        );

        var leaf_preprocessing = try leaf_authority.Preprocessing.init(
            allocator,
            // The binary fixture intentionally exercises the frozen V1 VM
            // schedule, whose public-LogUp cardinality is the 70 fixed terms
            // with no public-I/O capacity extension.
            try vm_claim.Shape.init(0, 0),
        );
        errdefer leaf_preprocessing.deinit();
        var statement_authority = try statement_authority_mod.Authority.init(
            allocator,
            &leaf_preprocessing,
        );
        errdefer statement_authority.deinit();
        var statement_workspace = try statement_source.Workspace.init(allocator);
        errdefer statement_workspace.deinit();
        var statement_prepared = try StatementPrepared.init(
            allocator,
            &statement_authority,
            &statement_workspace,
            &statement_parent,
            &statement_suite,
            &publications,
        );
        errdefer statement_prepared.deinit();

        var public_authority = try public_authority_mod.Source.init(
            allocator,
            &pair.vm_plan,
            &pair.recursion_plans[0],
            &leaf_preprocessing,
            pair.shape.claimed_sum_count,
        );
        errdefer public_authority.deinit();
        var inactive_source = try inactive_source_mod.Source.init(
            allocator,
            &public_authority,
            &pair.vm_plan,
            &pair.recursion_plans[0],
            &leaf_preprocessing,
        );
        errdefer inactive_source.deinit();
        var inactive_prepared = try inactive_source_mod.Prepared.init(
            allocator,
            &inactive_source,
            &public_authority,
            &pair.vm_plan,
            &pair.recursion_plans[0],
            &leaf_preprocessing,
        );
        errdefer inactive_prepared.deinit();

        return .{
            .allocator = allocator,
            .pair = pair,
            .pair_prepared = pair_prepared,
            .transcript_source = transcript_source,
            .transcript_workspace = transcript_workspace,
            .left = left,
            .right = right,
            .left_binding = left_binding,
            .right_binding = right_binding,
            .statement_suite = statement_suite,
            .statement_scratch = statement_scratch,
            .statement_parent = statement_parent,
            .publications = publications,
            .leaf_preprocessing = leaf_preprocessing,
            .statement_authority = statement_authority,
            .statement_workspace = statement_workspace,
            .statement_prepared = statement_prepared,
            .public_authority = public_authority,
            .inactive_source = inactive_source,
            .inactive_prepared = inactive_prepared,
        };
    }

    pub fn deinit(self: *Fixture) void {
        self.inactive_prepared.deinit();
        self.inactive_source.deinit();
        self.public_authority.deinit();
        self.statement_prepared.deinit();
        self.statement_workspace.deinit();
        self.statement_authority.deinit();
        self.leaf_preprocessing.deinit();
        self.allocator.free(self.statement_scratch);
        self.right.deinit();
        self.left.deinit();
        self.transcript_workspace.deinit();
        self.transcript_source.deinit();
        self.pair_prepared.deinit();
        self.pair.deinit();
        self.* = undefined;
    }

    pub fn inputs(self: *Fixture) Bundle.Inputs {
        return .{
            .vm_plan = &self.pair.vm_plan,
            .recursion_plans = .{
                &self.pair.recursion_plans[0],
                &self.pair.recursion_plans[1],
            },
            .transcript_preprocessing = &self.pair.transcript_preprocessing,
            .transcript_prepared = &self.pair_prepared,
            .transcript_source = &self.transcript_source,
            .transcript_workspace = &self.transcript_workspace,
            .pair_validation_workspace = &self.pair.validation_workspace,
            .root_pin = self.pair.pair_inputs.root_pin,
            .statement_authority = &self.statement_authority,
            .statement_workspace = &self.statement_workspace,
            .statement_parent = &self.statement_parent,
            .statement_suite = &self.statement_suite,
            .statement_publications = &self.publications,
            .statement_prepared = &self.statement_prepared,
            .leaf_preprocessing = &self.leaf_preprocessing,
            .public_authority = &self.public_authority,
            .inactive_source = &self.inactive_source,
            .inactive_prepared = &self.inactive_prepared,
        };
    }

    pub fn bundle(self: *Fixture) !Bundle {
        return Bundle.init(self.inputs());
    }

    pub fn manifest(self: *Fixture, outer: *const Bundle) !manifest_mod.Manifest {
        _ = self;
        var logs = [_]u32{4} ** roster.COMPONENT_COUNT;
        outer.installLogSizes(&logs);
        return universal_manifest.build(logs);
    }
};

pub fn alignPairVerificationKey(
    pair: *pair_fixture_mod.HonestFixture,
    verification_key: [8]u32,
) !void {
    pair.pair_inputs.context.aggregator_vk_id = verification_key;
    pair.pair_inputs.root_pin.expected_aggregator_vk_id = verification_key;
    const challenge = try pair.pair_inputs.context.challengeContextId();
    const authority_context = try pair.pair_inputs.context.contextId();
    for (&pair.captures) |*capture| {
        capture.verified.parent_vk_id = verification_key;
        capture.verified.challenge_context_id = challenge;
        capture.verified.authority_context_id = authority_context;
    }
}

pub fn bindingFor(
    child: *const outer_support.AdmittedChild,
    pair: outer_transcript_source.PairInputsV1,
    expected: pair_node.VerifiedChildV1,
) !admission.PairChildInputsV1 {
    var result = try outer_support.childBinding(
        child,
        pair,
        @intFromEnum(expected.position),
        expected.signed_relation_total,
    );
    result.position = expected.position;
    result.role = expected.role;
    result.leaf_index = expected.leaf_index;
    result.pair_index = expected.pair_index;
    result.leaf_count = expected.leaf_count;
    result.session_id = expected.session_id;
    result.challenge_context_id = expected.challenge_context_id;
    result.authority_context_id = expected.authority_context_id;
    result.parent_vk_id = expected.parent_vk_id;
    result.statement_id = expected.statement_id;
    result.summary_id = expected.summary_id;
    result.event_count = expected.event_count;
    return result;
}

pub fn authorityFromBindings(
    context: pair_node.VerifierContextV1,
    bindings: [2]admission.PairChildInputsV1,
    candidates: [2]admission.BinaryPairCandidateV1,
) pair_node.VerifierAuthorityV1 {
    var children: [2]pair_node.VerifiedChildV1 = undefined;
    for (&children, bindings, candidates) |*target, binding, candidate| {
        target.* = .{
            .position = binding.position,
            .role = binding.role,
            .leaf_index = binding.leaf_index,
            .pair_index = binding.pair_index,
            .leaf_count = binding.leaf_count,
            .protocol_id = @import("protocol.zig").PROTOCOL_ID_WORDS,
            .session_id = binding.session_id,
            .challenge_context_id = binding.challenge_context_id,
            .authority_context_id = binding.authority_context_id,
            .parent_vk_id = binding.parent_vk_id,
            .statement_id = binding.statement_id,
            .proof_id = candidate.proof_id,
            .transcript_id = candidate.transcript_id,
            .summary_id = binding.summary_id,
            .event_count = binding.event_count,
            .signed_relation_total = binding.signed_relation_total,
        };
    }
    return .{ .context = context, .children = children };
}

pub const Tree = struct {
    allocator: std.mem.Allocator,
    columns: [][]M31,
    storage: []M31,

    pub fn init(
        allocator: std.mem.Allocator,
        manifest: *const manifest_mod.Manifest,
        tree: usize,
    ) !Tree {
        const columns = try allocator.alloc([]M31, treeColumnCount(manifest, tree));
        errdefer allocator.free(columns);
        var total: usize = 0;
        for (manifest.roster_rows[0..manifest.roster_count]) |row| {
            const placement = manifest.placements[row].?;
            total = try std.math.add(
                usize,
                total,
                try std.math.mul(
                    usize,
                    geometryColumnCount(placement.geometry, tree),
                    @as(usize, 1) << @intCast(placement.geometry.log_size),
                ),
            );
        }
        const storage = try allocator.alloc(M31, total);
        errdefer allocator.free(storage);
        @memset(storage, M31.zero());
        var storage_cursor: usize = 0;
        for (manifest.roster_rows[0..manifest.roster_count]) |row| {
            const placement = manifest.placements[row].?;
            const offset = treeOffset(placement, tree);
            const column_count = geometryColumnCount(placement.geometry, tree);
            const row_count = @as(usize, 1) << @intCast(placement.geometry.log_size);
            for (columns[offset..][0..column_count]) |*column| {
                column.* = storage[storage_cursor..][0..row_count];
                storage_cursor += row_count;
            }
        }
        std.debug.assert(storage_cursor == storage.len);
        return .{
            .allocator = allocator,
            .columns = columns,
            .storage = storage,
        };
    }

    pub fn deinit(self: *Tree) void {
        self.allocator.free(self.storage);
        self.allocator.free(self.columns);
        self.* = undefined;
    }
};

pub fn treeColumnCount(manifest: *const manifest_mod.Manifest, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => manifest.total_main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
        else => unreachable,
    };
}

pub fn treeOffset(placement: manifest_mod.Placement, tree: usize) usize {
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

pub fn ownedRow(row: u8) bool {
    return row < bundle_mod.PREFIX_ROW_COUNT or row == bundle_mod.SHARED_PROVIDER_ROW;
}

pub fn expectOwnedTreeZero(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    columns: []const []M31,
) !void {
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        if (!ownedRow(row)) continue;
        const placement = manifest.placements[row].?;
        const offset = treeOffset(placement, tree);
        const count = geometryColumnCount(placement.geometry, tree);
        for (columns[offset..][0..count]) |column|
            for (column) |value| try std.testing.expect(value.isZero());
    }
}

pub fn expectOwnedTreeHasData(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    columns: []const []M31,
) !void {
    var nonzero = false;
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        if (!ownedRow(row)) continue;
        const placement = manifest.placements[row].?;
        const offset = treeOffset(placement, tree);
        const count = geometryColumnCount(placement.geometry, tree);
        for (columns[offset..][0..count]) |column| {
            for (column) |value| nonzero = nonzero or !value.isZero();
        }
    }
    try std.testing.expect(nonzero);
}

pub fn expectUnownedTreeZero(
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    columns: []const []M31,
) !void {
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        if (ownedRow(row)) continue;
        const placement = manifest.placements[row].?;
        const offset = treeOffset(placement, tree);
        const count = geometryColumnCount(placement.geometry, tree);
        for (columns[offset..][0..count]) |column|
            for (column) |value| try std.testing.expect(value.isZero());
    }
}
