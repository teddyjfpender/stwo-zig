//! End-to-end authority, transactionality, and allocation gates for V2 rows 0--9.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const PcsConfig = stwo_core.pcs.PcsConfig;

const public_data_v2 = @import("../air/public_data_v2.zig");
const support = @import("../air/public_data_v2_test_support.zig");
const relation_challenges = @import("../air/relation_challenges.zig");
const statement_v1 = @import("../air/statement.zig");
const boundary_air = @import("segment_leaf_outer_air_v2.zig");
const boundary_manifest = @import("segment_leaf_outer_authority_v2.zig");
const fixed_profile = @import("fixed_profile.zig");
const channel = @import("poseidon2_channel.zig");
const manifest_mod = @import("air/segment_outer_adapter_manifest_v2.zig");
const range_bridge = @import("air/range_check_8_8_bridge.zig");
const schedule = @import("air/verifier_schedule.zig");
const row17_witness_v2 =
    @import("air/vm_public_logup_control_witness_v2.zig");
const universal = @import("air/universal_challenges.zig");
const universal_manifest = @import("air/universal_manifest.zig");
const universal_roster = @import("air/universal_roster.zig");
const source_v2 = @import("segment_transcript_outer_source_v2.zig");
const subject = @import("segment_transcript_outer_components_v2.zig");
const transcript = @import("transcript_program_v2.zig");
const provider_authority =
    @import("segment_publication_input_provider_authority_v2.zig");

const config = PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
        .fold_step = 1,
    },
};

const component_descs = [_]statement_v1.FamilyComponentDesc{.{
    .family = .base_alu_imm,
    .log_size = 4,
    .n_rows = 2,
    .n_columns = 10,
}};

const infra_descs = [_]statement_v1.InfraComponentDesc{.{
    .kind = .program,
    .log_size = 4,
    .n_rows = 2,
    .n_columns = 2,
}};

test "V2 rows 0--9 publish all trees, ten claims, and one provider range" {
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    const allocator = measured.allocator();
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    const evidence = try fixture.execution.evidence(&fixture.program);
    const prepared = try source_v2.preflight(
        &fixture.program,
        &fixture.execution,
        &evidence,
        &fixture.plan,
        config,
        &fixture.data,
        &component_descs,
        &infra_descs,
    );
    const manifest = try buildManifest(&prepared);
    var owner = try subject.Source.init(allocator, &prepared, &manifest);
    defer owner.deinit();
    var workspace = try subject.Workspace.init(allocator, &prepared);
    defer workspace.deinit();
    try workspace.prepare(&owner, &prepared, &manifest, nativeInputs(
        &fixture,
        &evidence,
    ));

    var tree0 = try OwnedTree.init(
        allocator,
        &manifest,
        manifest_mod.PREPROCESSED_TREE_INDEX,
    );
    defer tree0.deinit();
    var tree1 = try OwnedTree.init(
        allocator,
        &manifest,
        manifest_mod.MAIN_TREE_INDEX,
    );
    defer tree1.deinit();
    var tree2 = try OwnedTree.init(
        allocator,
        &manifest,
        manifest_mod.INTERACTION_TREE_INDEX,
    );
    defer tree2.deinit();
    tree0.fillSentinel();
    tree1.fillSentinel();
    tree2.fillSentinel();

    var relations = universal.UniversalRelations.dummy();
    const allocations_before = measured.alloc_index;
    try subject.fillPreprocessedInto(
        &owner,
        &workspace,
        &prepared,
        &manifest,
        tree0.columns,
    );
    try subject.fillMainInto(
        &owner,
        &workspace,
        &prepared,
        &manifest,
        tree1.columns,
    );
    const claims = try subject.fillInteractionInto(
        &owner,
        &workspace,
        &prepared,
        &manifest,
        &relations,
        tree2.columns,
    );
    try std.testing.expectEqual(allocations_before, measured.alloc_index);

    var components = try owner.initComponents(
        &prepared,
        &manifest,
        &relations,
        claims,
    );
    var gate = try manifest_mod.ProofGate.init(&manifest);
    try components.appendToGate(&manifest, &gate);
    try std.testing.expectEqual(@as(u8, subject.ROW_COUNT), gate.count);
    try std.testing.expect(!gate.sealed);
    var claim_vector = try manifest_mod.ClaimVector.init(&manifest);
    try claims.bindInto(&claim_vector);
    try std.testing.expectEqual(
        (@as(u64, 1) << subject.ROW_COUNT) - 1,
        claim_vector.bound_mask,
    );

    var saw_dynamic_geometry = false;
    for (
        workspace.transcript_payload_source,
        workspace.transcript_payload_rows,
    ) |source, logical| {
        if (source.source_kind == .public_geometry) {
            saw_dynamic_geometry = true;
            try std.testing.expectEqual(@as(u32, 13), logical[13].toU32());
        }
    }
    try std.testing.expect(saw_dynamic_geometry);

    const first: usize = 3;
    const range = try source_v2.PoseidonRequestRangeV2.init(&prepared, first);
    const stream = try allocator.alloc(
        source_v2.ProviderCall,
        first + workspace.provider_calls.len + 2,
    );
    defer allocator.free(stream);
    @memset(stream, sentinelCall());
    const provider_allocations_before = measured.alloc_index;
    try subject.writeProviderCallsInto(&workspace, &prepared, &range, stream);
    try std.testing.expectEqual(
        provider_allocations_before,
        measured.alloc_index,
    );
    for (stream[0..first]) |call|
        try std.testing.expectEqualDeep(sentinelCall(), call);
    for (
        stream[first..range.end],
        fixture.execution.poseidon_calls,
    ) |actual, expected| {
        try std.testing.expect(actual.io);
        try std.testing.expect(!actual.wide);
        try std.testing.expect(actual.narrow_output == null);
        for (actual.input, expected.input) |raw, word|
            try std.testing.expectEqual(word.toU32(), raw);
    }
    for (stream[range.end..]) |call|
        try std.testing.expectEqualDeep(sentinelCall(), call);
    try std.testing.expect(!owner.productionReady());
    try std.testing.expectEqual(@as(usize, 0), subject.HOT_HEAP_ALLOCATIONS);
    try std.testing.expectEqual(@as(usize, 1), subject.SHARED_PROVIDER_COMPONENT_COUNT);
}

test "V2 rows 0--9 reject cache, challenge, manifest, and alias mutations atomically" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const evidence = try fixture.execution.evidence(&fixture.program);
    const prepared = try source_v2.preflight(
        &fixture.program,
        &fixture.execution,
        &evidence,
        &fixture.plan,
        config,
        &fixture.data,
        &component_descs,
        &infra_descs,
    );
    const manifest = try buildManifest(&prepared);
    var owner = try subject.Source.init(std.testing.allocator, &prepared, &manifest);
    defer owner.deinit();
    var workspace = try subject.Workspace.init(std.testing.allocator, &prepared);
    defer workspace.deinit();
    try workspace.prepare(&owner, &prepared, &manifest, nativeInputs(
        &fixture,
        &evidence,
    ));
    var tree = try OwnedTree.init(
        std.testing.allocator,
        &manifest,
        manifest_mod.INTERACTION_TREE_INDEX,
    );
    defer tree.deinit();
    tree.fillSentinel();
    const initial = tree.digest();

    var relations = universal.UniversalRelations.dummy();
    const saved_logical = workspace.transcript_payload_rows[0][1];
    workspace.transcript_payload_rows[0][1] = saved_logical.add(M31.one());
    try std.testing.expectError(
        error.WorkspaceSealMismatch,
        subject.fillInteractionInto(
            &owner,
            &workspace,
            &prepared,
            &manifest,
            &relations,
            tree.columns,
        ),
    );
    try std.testing.expectEqual(initial, tree.digest());
    workspace.transcript_payload_rows[0][1] = saved_logical;

    const first_event = workspace.relation_events[0];
    const element = &relations.elements[@intFromEnum(first_event.domain)];
    element.z = element.z.add(try element.combineBase(
        first_event.tuple[0..first_event.arity],
    ));
    try std.testing.expectError(
        error.ZeroDenominator,
        subject.fillInteractionInto(
            &owner,
            &workspace,
            &prepared,
            &manifest,
            &relations,
            tree.columns,
        ),
    );
    try std.testing.expectEqual(initial, tree.digest());

    relations = universal.UniversalRelations.dummy();
    const saved_column = tree.columns[1];
    tree.columns[1] = tree.columns[0];
    try std.testing.expectError(
        error.DestinationAlias,
        subject.fillInteractionInto(
            &owner,
            &workspace,
            &prepared,
            &manifest,
            &relations,
            tree.columns,
        ),
    );
    tree.columns[1] = saved_column;
    try std.testing.expectEqual(initial, tree.digest());

    var bad_manifest = manifest;
    bad_manifest.seal[0] ^= 1;
    try std.testing.expectError(
        error.ManifestSealMismatch,
        subject.fillInteractionInto(
            &owner,
            &workspace,
            &prepared,
            &bad_manifest,
            &relations,
            tree.columns,
        ),
    );
    try std.testing.expectEqual(initial, tree.digest());
}

test "V2 workspace allocation geometry is failure-clean" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const evidence = try fixture.execution.evidence(&fixture.program);
    const prepared = try source_v2.preflight(
        &fixture.program,
        &fixture.execution,
        &evidence,
        &fixture.plan,
        config,
        &fixture.data,
        &component_descs,
        &infra_descs,
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        workspaceFailureCase,
        .{&prepared},
    );
}

fn workspaceFailureCase(
    allocator: std.mem.Allocator,
    prepared: *const source_v2.PreparedV2,
) !void {
    var workspace = try subject.Workspace.init(allocator, prepared);
    defer workspace.deinit();
}

fn nativeInputs(
    fixture: *const Fixture,
    evidence: *const transcript.Evidence,
) subject.NativeInputs {
    return .{
        .program = &fixture.program,
        .execution = &fixture.execution,
        .evidence = evidence,
        .plan = &fixture.plan,
        .pcs_config = config,
        .data = &fixture.data,
        .component_descs = &component_descs,
        .infra_descs = &infra_descs,
    };
}

fn buildManifest(prepared: *const source_v2.PreparedV2) !manifest_mod.Manifest {
    const catalog_mod = @import("air/segment_outer_typed_catalog_v2.zig");
    var log_sizes = [_]u32{4} ** universal_roster.COMPONENT_COUNT;
    for (prepared.manifest.log_sizes, 0..) |log_size, row|
        log_sizes[row] = log_size;
    log_sizes[17] = row17_witness_v2.TRACE_LOG_SIZE;
    log_sizes[@intFromEnum(universal_roster.Component.range_check_8_8)] =
        range_bridge.LOG_SIZE;
    const boundary_components = [boundary_manifest.COMPONENT_COUNT]boundary_manifest.ComponentGeometryV2{
        .{
            .kind = .statement_source,
            .component_tag = boundary_manifest.STATEMENT_COMPONENT_TAG,
            .logical_rows = 129,
            .trace_log_size = 8,
            .trace_rows = 256,
            .preprocessed_columns = boundary_air.Statement.PREPROCESSED_COLUMN_COUNT,
            .main_columns = boundary_air.Statement.PHYSICAL_MAIN_COLUMN_COUNT,
            .interaction_columns = boundary_air.Statement.INTERACTION_COLUMN_COUNT,
            .direct_constraints = boundary_air.Statement.DIRECT_CONSTRAINT_COUNT,
            .interaction_batches = boundary_air.Statement.INTERACTION_BATCH_COUNT,
            .protocol_constraint_degree = boundary_air.Statement.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = boundary_air.Statement.SEMANTIC_DIGEST,
        },
        .{
            .kind = .public_logup_source,
            .component_tag = boundary_manifest.PUBLIC_LOGUP_COMPONENT_TAG,
            .logical_rows = boundary_manifest.PUBLIC_LOGUP_LOGICAL_ROWS,
            .trace_log_size = boundary_manifest.PUBLIC_LOGUP_TRACE_LOG_SIZE,
            .trace_rows = boundary_manifest.PUBLIC_LOGUP_TRACE_ROWS,
            .preprocessed_columns = boundary_air.PublicLogUp.PREPROCESSED_COLUMN_COUNT,
            .main_columns = boundary_air.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT,
            .interaction_columns = boundary_air.PublicLogUp.INTERACTION_COLUMN_COUNT,
            .direct_constraints = boundary_air.PublicLogUp.DIRECT_CONSTRAINT_COUNT,
            .interaction_batches = boundary_air.PublicLogUp.INTERACTION_BATCH_COUNT,
            .protocol_constraint_degree = boundary_air.PublicLogUp.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE,
            .semantic_digest = boundary_air.PublicLogUp.SEMANTIC_DIGEST,
        },
    };
    const catalog = try catalog_mod.build(log_sizes, boundary_components);
    return manifest_mod.assemble(&catalog, .{
        .transcript_manifest_id = prepared.manifest.identity,
        .statement_manifest_id = nativeDigest(53),
        .public_manifest_id = nativeDigest(75),
        .boundary_manifest_id = nativeDigest(97),
        .boundary_authority_sha_id = shaDigest(131),
        .provider_authority_sha_id = provider_authority.sourceAuthorityShaId(),
    });
}

fn statementSourceGeometry(log_size: u32) manifest_mod.Geometry {
    return .{
        .roster_row = manifest_mod.STATEMENT_SOURCE_INDEX,
        .log_size = log_size,
        .preprocessed_columns = boundary_air.Statement.PREPROCESSED_COLUMN_COUNT,
        .main_columns = boundary_air.Statement.PHYSICAL_MAIN_COLUMN_COUNT,
        .interaction_columns = boundary_air.Statement.INTERACTION_COLUMN_COUNT,
        .direct_constraints = boundary_air.Statement.DIRECT_CONSTRAINT_COUNT,
        .interaction_batches = boundary_air.Statement.INTERACTION_BATCH_COUNT,
        .protocol_constraint_degree = boundary_air.Statement.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE,
        .profiled_constraint_degree = boundary_air.Statement.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = boundary_air.Statement.SEMANTIC_DIGEST,
    };
}

fn publicLogUpSourceGeometry() manifest_mod.Geometry {
    return .{
        .roster_row = manifest_mod.PUBLIC_LOGUP_SOURCE_INDEX,
        .log_size = boundary_manifest.PUBLIC_LOGUP_TRACE_LOG_SIZE,
        .preprocessed_columns = boundary_air.PublicLogUp.PREPROCESSED_COLUMN_COUNT,
        .main_columns = boundary_air.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT,
        .interaction_columns = boundary_air.PublicLogUp.INTERACTION_COLUMN_COUNT,
        .direct_constraints = boundary_air.PublicLogUp.DIRECT_CONSTRAINT_COUNT,
        .interaction_batches = boundary_air.PublicLogUp.INTERACTION_BATCH_COUNT,
        .protocol_constraint_degree = boundary_air.PublicLogUp.REFERENCE_MAXIMUM_CONSTRAINT_DEGREE,
        .profiled_constraint_degree = boundary_air.PublicLogUp.MAXIMUM_CONSTRAINT_DEGREE,
        .semantic_digest = boundary_air.PublicLogUp.SEMANTIC_DIGEST,
    };
}

const OwnedTree = struct {
    allocator: std.mem.Allocator,
    columns: [][]M31,

    fn init(
        allocator: std.mem.Allocator,
        manifest: *const manifest_mod.Manifest,
        tree: usize,
    ) !OwnedTree {
        const count: usize = switch (tree) {
            manifest_mod.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
            manifest_mod.MAIN_TREE_INDEX => manifest.total_main_columns,
            manifest_mod.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
            else => return error.InvalidTree,
        };
        const columns = try allocator.alloc([]M31, count);
        errdefer allocator.free(columns);
        var allocated: usize = 0;
        errdefer for (columns[0..allocated]) |column| allocator.free(column);
        for (manifest.roster_rows[0..manifest.roster_count]) |row| {
            const placement = manifest.placements[row].?;
            const offset: usize = switch (tree) {
                manifest_mod.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
                manifest_mod.MAIN_TREE_INDEX => placement.main_offset,
                manifest_mod.INTERACTION_TREE_INDEX => placement.interaction_offset,
                else => unreachable,
            };
            const local_count: usize = switch (tree) {
                manifest_mod.PREPROCESSED_TREE_INDEX => placement.geometry.preprocessed_columns,
                manifest_mod.MAIN_TREE_INDEX => placement.geometry.main_columns,
                manifest_mod.INTERACTION_TREE_INDEX => placement.geometry.interaction_columns,
                else => unreachable,
            };
            const size = @as(usize, 1) << @intCast(placement.geometry.log_size);
            for (columns[offset..][0..local_count]) |*column| {
                column.* = try allocator.alloc(M31, size);
                allocated += 1;
            }
        }
        if (allocated != count) return error.InvalidTree;
        return .{ .allocator = allocator, .columns = columns };
    }

    fn deinit(self: *OwnedTree) void {
        for (self.columns) |column| self.allocator.free(column);
        self.allocator.free(self.columns);
        self.* = undefined;
    }

    fn fillSentinel(self: *OwnedTree) void {
        for (self.columns) |column|
            @memset(column, M31.fromCanonical(0x5a5a));
    }

    fn digest(self: *const OwnedTree) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        for (self.columns) |column| for (column) |value| {
            var encoded: [4]u8 = undefined;
            std.mem.writeInt(u32, &encoded, value.toU32(), .little);
            hash.update(&encoded);
        };
        return hash.finalResult();
    }
};

const Fixture = struct {
    allocator: std.mem.Allocator,
    words: []M31,
    data: public_data_v2.PublicDataV2,
    plan: schedule.Plan,
    program: transcript.Program,
    trace_commitments: [4]channel.Digest,
    claimed_sums: [transcript.COMPONENT_CLAIM_COUNT]QM31,
    sampled_values: [3]QM31,
    fri_commitments: [4]channel.Digest,
    last_layer_coefficients: [1]QM31,
    execution: transcript.Execution,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const source_fixture = try support.Fixture.init();
        const source = source_fixture.leftSource();
        const words = try support.encode(allocator, &source);
        errdefer allocator.free(words);
        const data = try public_data_v2.PublicDataV2.authenticate(words);
        var plan = try testPlan(allocator);
        errdefer plan.deinit();
        var program = try transcript.Program.init(
            allocator,
            &plan,
            config,
            &data,
            &component_descs,
            &infra_descs,
        );
        errdefer program.deinit();
        const trace_commitments = [_]channel.Digest{
            support.id("v2-components-tree-0"),
            support.id("v2-components-tree-1"),
            support.id("v2-components-tree-2"),
            support.id("v2-components-tree-3"),
        };
        var claimed_sums: [transcript.COMPONENT_CLAIM_COUNT]QM31 = undefined;
        for (&claimed_sums, 0..) |*value, index| value.* = qm31(index + 10);
        var sampled_values: [3]QM31 = undefined;
        for (&sampled_values, 0..) |*value, index| value.* = qm31(index + 100);
        const fri_commitments = [_]channel.Digest{
            support.id("v2-components-fri-0"),
            support.id("v2-components-fri-1"),
            support.id("v2-components-fri-2"),
            support.id("v2-components-fri-3"),
        };
        const last_layer_coefficients = [_]QM31{qm31(200)};
        const execution = try transcript.execute(allocator, &program, &data, .{
            .trace_commitments = &trace_commitments,
            .interaction_pow = 0,
            .claimed_sums = &claimed_sums,
            .sampled_values = &sampled_values,
            .fri_commitments = &fri_commitments,
            .last_layer_coefficients = &last_layer_coefficients,
            .pcs_pow = 0,
        });
        return .{
            .allocator = allocator,
            .words = words,
            .data = data,
            .plan = plan,
            .program = program,
            .trace_commitments = trace_commitments,
            .claimed_sums = claimed_sums,
            .sampled_values = sampled_values,
            .fri_commitments = fri_commitments,
            .last_layer_coefficients = last_layer_coefficients,
            .execution = execution,
        };
    }

    fn deinit(self: *Fixture) void {
        self.execution.deinit();
        self.program.deinit();
        self.plan.deinit();
        self.allocator.free(self.words);
        self.* = undefined;
    }
};

fn testPlan(allocator: std.mem.Allocator) !schedule.Plan {
    return schedule.Plan.initShape(
        allocator,
        try schedule.ProgramSpec.init(
            .vm,
            relation_challenges.RELATION_COUNT,
            1,
            2,
            relation_challenges.RELATION_COUNT,
        ),
        .{
            .protocol_id = support.id("v2-components-protocol"),
            .shape_id = support.id("v2-components-shape"),
            .interaction_pow_bits = 0,
            .pcs_pow_bits = config.pow_bits,
            .query_count = @intCast(config.fri_config.n_queries),
            .table_count = 4,
            .claimed_sum_count = transcript.COMPONENT_CLAIM_COUNT,
            .sampled_value_count = 3,
            .tree_heights = .{ 5, 5, 5, 5 },
            .fri = try fixed_profile.FriSchedule.init(4, config.fri_config),
        },
    );
}

fn sentinelCall() source_v2.ProviderCall {
    return .{
        .input = [_]u32{0x5a5a_5a5a} ** 16,
        .wide = true,
        .io = false,
        .narrow_output = 0x5a5a_5a5a,
    };
}

fn nativeDigest(seed: u32) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index));
    return result;
}

fn shaDigest(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index|
        byte.* = seed +% @as(u8, @intCast(index));
    return result;
}

fn qm31(seed: usize) QM31 {
    return QM31.fromU32Unchecked(
        @intCast(seed),
        @intCast(seed + 1),
        @intCast(seed + 2),
        @intCast(seed + 3),
    );
}
