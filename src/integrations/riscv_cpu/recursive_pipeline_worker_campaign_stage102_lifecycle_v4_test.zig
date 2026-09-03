const std = @import("std");
const artifact_store = @import("stwo_artifact_store");
const frontend = @import("stwo_riscv_frontend");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const support = @import("recursive_pipeline_worker_support_v1.zig");
const storage = @import("recursive_pipeline_worker_storage_v1.zig");
const worker_mod = @import("recursive_pipeline_worker_v1.zig");
const real_worker = @import("recursive_pipeline_worker_campaign_real_leaf_v4.zig");
const campaign_artifact = @import("recursive_campaign_node_artifact_v2.zig");
const campaign_public = @import("recursive_campaign_node_public_v2.zig");
const campaign_store = @import("recursive_campaign_node_artifact_store_v2.zig");
const node_store = @import("recursive_node_artifact_store_v2.zig");
const shape_mod = @import("recursive_pipeline_campaign_shape_v2.zig");
const target_mod = @import("recursive_pipeline_campaign_padding_target_v2.zig");
const remint_mod = @import("recursive_common_wrapper_padding_remint_v2.zig");
const final_mod = @import("recursive_pipeline_campaign_final_remint_v2.zig");
const policy_mod = @import("recursive_pipeline_worker_execution_policy_v2.zig");
const inventory = @import("recursive_pipeline_worker_campaign_stage102_inventory_v4.zig");
const builder_mod = @import("recursive_pipeline_worker_campaign_stage102_inventory_builder_v4.zig");
const provider_mod = @import("recursive_pipeline_worker_campaign_session_provider_v4.zig");
const lifecycle_support = @import(
    "recursive_pipeline_worker_campaign_stage102_lifecycle_test_support_v4.zig",
);
const padding_fixture = @import("recursive_common_wrapper_padding_remint_v2_test.zig");

const recursion = frontend.recursion;
const Authority = FixtureAuthorityV4;
const Builder = builder_mod.BuilderFor(Authority);
const ImmutableSession = inventory.SessionFor(Authority);
const BuildProvider = provider_mod.ProviderFor(Builder);
const ReplayProvider = provider_mod.ProviderFor(ImmutableSession);
const BuildAdapter = lifecycle_support.AdapterV4(BuildProvider);
const ReplayAdapter = lifecycle_support.AdapterV4(ReplayProvider);
const BuildWorker = worker_mod.Worker(BuildAdapter);
const ReplayWorker = worker_mod.Worker(ReplayAdapter);

test "Stage102 typed semantic options preserve generic key and campaign projection domains" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    var store = try artifact_store.Store.openOrCreate(
        std.testing.allocator,
        root,
        false,
    );
    defer store.deinit();
    const fixture = try FixtureV4.init(std.testing.allocator, &store, 2);
    defer fixture.deinit();
    const row = &fixture.rows[0];
    const projected = try campaign_artifact.semanticInputsForStore(
        &fixture.shape,
        &row.artifact,
    );

    try real_worker.validateSemanticProjectionV4(
        std.testing.allocator,
        &fixture.shape,
        row.node,
        &row.semantic,
        &row.ordered_inputs,
        &projected,
    );
    const options_identity = try protocol.canonicalDigest(
        std.testing.allocator,
        row.node.semantic_options,
    );
    const regenerated = try real_worker.semanticOptionsValueV4(
        fixture.arena.allocator(),
        &projected,
    );
    const canonical = try protocol.canonicalAlloc(
        fixture.arena.allocator(),
        row.node.semantic_options,
        false,
    );
    const canonical_regenerated = try protocol.canonicalAlloc(
        fixture.arena.allocator(),
        regenerated,
        false,
    );
    try std.testing.expectEqualStrings(canonical, canonical_regenerated);
    try std.testing.expectEqualDeep(
        options_identity,
        row.semantic.fields.semantic_options_identity,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &options_identity,
        &projected.identity_sha256,
    ));

    var missing_node = row.node;
    missing_node.semantic_options = protocol.jsonObject(fixture.arena.allocator());
    try protocol.put(
        &missing_node.semantic_options,
        "schema",
        protocol.string(real_worker.semantic_options_schema),
    );
    try expectRejected(real_worker.validateSemanticProjectionV4(
        std.testing.allocator,
        &fixture.shape,
        missing_node,
        &row.semantic,
        &row.ordered_inputs,
        &projected,
    ));

    var wrong_type_node = row.node;
    wrong_type_node.semantic_options = protocol.jsonObject(
        fixture.arena.allocator(),
    );
    try protocol.put(
        &wrong_type_node.semantic_options,
        "schema",
        protocol.string(real_worker.semantic_options_schema),
    );
    try protocol.put(
        &wrong_type_node.semantic_options,
        "campaign_semantic_inputs_identity_sha256",
        protocol.integer(1),
    );
    try expectRejected(real_worker.validateSemanticProjectionV4(
        std.testing.allocator,
        &fixture.shape,
        wrong_type_node,
        &row.semantic,
        &row.ordered_inputs,
        &projected,
    ));

    var wrong_identity_node = row.node;
    wrong_identity_node.semantic_options = protocol.jsonObject(
        fixture.arena.allocator(),
    );
    try protocol.put(
        &wrong_identity_node.semantic_options,
        "schema",
        protocol.string(real_worker.semantic_options_schema),
    );
    try protocol.putDigest(
        fixture.arena.allocator(),
        &wrong_identity_node.semantic_options,
        "campaign_semantic_inputs_identity_sha256",
        digest(0xee),
    );
    try expectRejected(real_worker.validateSemanticProjectionV4(
        std.testing.allocator,
        &fixture.shape,
        wrong_identity_node,
        &row.semantic,
        &row.ordered_inputs,
        &projected,
    ));

    var mutated_artifact = row.artifact;
    mutated_artifact.profile_identity_sha256[0] ^= 1;
    mutated_artifact.semantic_inputs_identity_sha256 = undefined;
    mutated_artifact.field_public_transport_sha256 = undefined;
    mutated_artifact.content_identity_sha256 = undefined;
    mutated_artifact = try campaign_artifact.seal(
        &fixture.shape,
        mutated_artifact,
    );
    const mutated_projection = try campaign_artifact.semanticInputsForStore(
        &fixture.shape,
        &mutated_artifact,
    );
    try expectRejected(real_worker.validateSemanticProjectionV4(
        std.testing.allocator,
        &fixture.shape,
        row.node,
        &row.semantic,
        &row.ordered_inputs,
        &mutated_projection,
    ));
}

test "Stage102 worker builder seals a two-leaf CAS inventory then replays it" {
    try exerciseLifecycleV4(2);
}

test "Stage102 worker builder canonicalizes an out-of-order three-leaf inventory" {
    try exerciseLifecycleV4(3);
}

fn exerciseLifecycleV4(count: usize) !void {
    const allocator = std.testing.allocator;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(allocator, ".");
    defer allocator.free(root);
    var store = try artifact_store.Store.openOrCreate(allocator, root, false);
    defer store.deinit();
    const fixture = try FixtureV4.init(allocator, &store, count);
    defer fixture.deinit();

    var builder = try Builder.init(
        allocator,
        allocator,
        &store,
        &fixture.authority,
        &fixture.policy,
    );
    var builder_live = true;
    defer if (builder_live) builder.deinit();

    var installed = try BuildProvider.install(allocator, &builder);
    var installed_live = true;
    defer if (installed_live) installed.deinit();
    var worker = try BuildWorker.init(allocator, root);
    var worker_live = true;
    defer if (worker_live) worker.deinit();
    const first_index = count - 1;
    fixture.rows[first_index].stage_manifest_ref = try lifecycle_support.coldOpenAndClose(
        BuildWorker,
        &worker,
        allocator,
        &fixture.rows[first_index],
        null,
    );
    try std.testing.expectEqual(@as(usize, 1), try builder.adoptedCount());
    const duplicate_manifest = try lifecycle_support.coldOpenAndClose(
        BuildWorker,
        &worker,
        allocator,
        &fixture.rows[first_index],
        fixture.rows[first_index].stage_manifest_ref,
    );
    try std.testing.expectEqualDeep(
        fixture.rows[first_index].stage_manifest_ref.?,
        duplicate_manifest,
    );
    try std.testing.expectEqual(@as(usize, 1), try builder.adoptedCount());

    try exerciseDriftRejections(
        &builder,
        allocator,
        fixture,
        first_index,
    );
    worker.deinit();
    worker_live = false;
    installed.deinit();
    installed_live = false;
    try std.testing.expect(!BuildProvider.isInstalled());
    try std.testing.expectError(
        error.CampaignStage102BuilderIncompleteV4,
        builder.sealComplete(allocator),
    );
    try builder.validate(allocator);
    try std.testing.expectEqual(@as(usize, 1), try builder.adoptedCount());

    installed = try BuildProvider.install(allocator, &builder);
    installed_live = true;
    worker = try BuildWorker.init(allocator, root);
    worker_live = true;
    var index: usize = 0;
    while (index + 1 < count) : (index += 1) {
        fixture.rows[index].stage_manifest_ref = try lifecycle_support.coldOpenAndClose(
            BuildWorker,
            &worker,
            allocator,
            &fixture.rows[index],
            null,
        );
    }
    try std.testing.expectEqual(count, try builder.adoptedCount());
    worker.deinit();
    worker_live = false;
    installed.deinit();
    installed_live = false;

    var sealed = try builder.sealComplete(allocator);
    builder_live = false;
    defer sealed.deinit();
    try sealed.validate(allocator);
    const session = try sealed.sessionView();
    var replay_install = try ReplayProvider.install(allocator, session);
    defer replay_install.deinit();
    var replay = try ReplayWorker.init(allocator, root);
    defer replay.deinit();
    for (fixture.rows, 0..) |*row, ordinal| {
        const admission = try ReplayProvider.stage102AdmissionForOutput(
            fixture.shape.campaign_namespace_sha256,
            row.output_ref,
        );
        try std.testing.expectEqualStrings(
            row.node.node_id,
            admission.node.node_id,
        );
        try std.testing.expectEqual(
            @as(u32, @intCast(ordinal)),
            row.artifact.coordinate.index,
        );
        const replayed_manifest = try lifecycle_support.coldOpenAndClose(
            ReplayWorker,
            &replay,
            allocator,
            row,
            row.stage_manifest_ref,
        );
        try std.testing.expectEqualDeep(row.stage_manifest_ref.?, replayed_manifest);
    }
}

fn exerciseDriftRejections(
    builder: *const Builder,
    allocator: std.mem.Allocator,
    fixture: *FixtureV4,
    index: usize,
) !void {
    const row = &fixture.rows[index];
    const dependency_refs = [_]artifact_store.BlobRefV1{
        row.dependency_manifest_ref,
    };
    const wrong_index: usize = if (index == 0) 1 else 0;
    try expectRejected(builder.adoptStage102ColdPublication(
        allocator,
        row.node,
        row.semantic,
        row.execution,
        &row.ordered_inputs,
        fixture.rows[wrong_index].output_ref,
        row.stage_manifest_ref.?,
        &dependency_refs,
    ));

    var changed_fields = row.semantic.fields;
    changed_fields.profile_identity = digest(0xf1);
    const changed_semantic = try artifact_store.SemanticKeyV1.create(
        allocator,
        changed_fields,
    );
    try expectRejected(builder.adoptStage102ColdPublication(
        allocator,
        row.node,
        changed_semantic,
        row.execution,
        &row.ordered_inputs,
        row.output_ref,
        row.stage_manifest_ref.?,
        &dependency_refs,
    ));

    try expectRejected(builder.adoptStage102ColdPublication(
        allocator,
        row.node,
        row.semantic,
        row.execution,
        &row.ordered_inputs,
        row.output_ref,
        row.dependency_manifest_ref,
        &dependency_refs,
    ));
}

pub const FixtureV4 = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    padding: padding_fixture.Fixture,
    shape: shape_mod.CampaignShapeAuthorityV2,
    target: target_mod.CampaignPaddingTargetV2,
    remint: remint_mod.FinalRemintAuthorityV2,
    final_remint: final_mod.CampaignFinalRemintAuthorityV2,
    policy: policy_mod.PolicyV2,
    authority: Authority,
    selector_rows: []FixtureSelectorRowV4,
    stage101_admissions: []FixtureStage101AdmissionV4,
    rows: []FixtureRowV4,

    pub fn init(
        allocator: std.mem.Allocator,
        store: *artifact_store.Store,
        count: usize,
    ) !*FixtureV4 {
        if (count < 2) return error.InvalidFixtureCampaignCountV4;
        const self = try allocator.create(FixtureV4);
        errdefer allocator.destroy(self);
        self.allocator = allocator;
        self.arena = std.heap.ArenaAllocator.init(allocator);
        errdefer self.arena.deinit();
        const arena = self.arena.allocator();
        self.padding = try padding_fixture.Fixture.init();
        self.shape = try shape_mod.CampaignShapeAuthorityV2.init(
            digest(0x11),
            digest(0x12),
            @intCast(count),
        );
        self.target = try target_mod.CampaignPaddingTargetV2.derive(
            &self.shape,
            self.padding.activeSources(),
        );
        self.padding.remintForTarget(&self.target.target);
        self.remint = try remint_mod.FinalRemintAuthorityV2.mint(
            &self.target.target,
            self.padding.activeSources(),
            self.padding.finalSources(),
        );
        self.final_remint = try final_mod.CampaignFinalRemintAuthorityV2.init(
            &self.shape,
            &self.remint,
        );
        const host = try policy_mod.HostExecutionAuthorityV2.init(4, 1 << 30);
        self.policy = try policy_mod.PolicyV2.init(host, .{
            .total_cpu_tokens = 4,
            .cpu_tokens_per_node = 2,
            .proof_worker_count = 2,
            .maximum_parallel_nodes = 2,
            .total_rss_bytes = 1 << 30,
            .rss_bytes_per_node = 1 << 28,
        });
        self.selector_rows = try arena.alloc(FixtureSelectorRowV4, count);
        self.stage101_admissions = try arena.alloc(
            FixtureStage101AdmissionV4,
            count,
        );
        self.rows = try arena.alloc(FixtureRowV4, count);
        self.authority = .{
            .final_remint = &self.final_remint,
            .padding_target = &self.target,
            .stage101_admissions = self.stage101_admissions,
            .rows = self.selector_rows,
        };
        for (self.rows, 0..) |*row, index| {
            row.* = try initRow(self, store, arena, index);
            row.node.dependencies = &row.dependency;
            row.semantic.fields.ordered_inputs = &row.ordered_inputs;
            self.selector_rows[index] = .{ .segment_index = @intCast(index) };
            self.stage101_admissions[index] = .{
                .wrapper_local_task_identity_sha256 = row.node.local_task_identity_sha256,
            };
        }
        try self.authority.validate(
            allocator,
            self.shape.campaign_namespace_sha256,
        );
        return self;
    }

    pub fn deinit(self: *FixtureV4) void {
        self.arena.deinit();
        const allocator = self.allocator;
        self.* = undefined;
        allocator.destroy(self);
    }
};

const FixtureSelectorRowV4 = struct { segment_index: u32 };
const FixtureStage101AdmissionV4 = struct {
    wrapper_local_task_identity_sha256: artifact_store.Digest,
};

pub const FixtureAuthorityV4 = struct {
    final_remint: *const final_mod.CampaignFinalRemintAuthorityV2,
    padding_target: *const target_mod.CampaignPaddingTargetV2,
    stage101_admissions: []const FixtureStage101AdmissionV4,
    rows: []const FixtureSelectorRowV4,

    const SelectionV4 = struct {
        index: usize,
        row: *const FixtureSelectorRowV4,
        admission: *const FixtureStage101AdmissionV4,
    };

    pub fn validate(
        self: *const FixtureAuthorityV4,
        _: std.mem.Allocator,
        namespace: artifact_store.Digest,
    ) !void {
        try self.final_remint.validateAgainstCampaign(namespace);
        try self.padding_target.validateAgainstFinal(self.final_remint);
        const count: usize = @intCast(self.final_remint.shape.real_leaf_count);
        if (self.rows.len != count or self.stage101_admissions.len != count)
            return error.InvalidFixtureCampaignAuthorityV4;
        for (self.rows, self.stage101_admissions, 0..) |row, admission, index| {
            if (row.segment_index != @as(u32, @intCast(index)) or
                artifact_store.encoding.isZeroDigest(
                    admission.wrapper_local_task_identity_sha256,
                )) return error.InvalidFixtureCampaignAuthorityV4;
        }
    }

    pub fn admissionForWrapperTask(
        self: *const FixtureAuthorityV4,
        allocator: std.mem.Allocator,
        namespace: artifact_store.Digest,
        identity: artifact_store.Digest,
    ) !SelectionV4 {
        try self.validate(allocator, namespace);
        for (self.stage101_admissions, 0..) |*admission, index| {
            if (std.mem.eql(
                u8,
                &admission.wrapper_local_task_identity_sha256,
                &identity,
            )) return .{
                .index = index,
                .row = &self.rows[index],
                .admission = admission,
            };
        }
        return error.InvalidFixtureCampaignAuthorityV4;
    }
};

pub const FixtureRowV4 = struct {
    artifact: campaign_artifact.Artifact,
    node: protocol.Node,
    dependency: [1]protocol.Dependency,
    ordered_inputs: [1]artifact_store.InputRefV1,
    semantic: artifact_store.SemanticKeyV1,
    execution: artifact_store.ExecutionKeyV1,
    output_ref: artifact_store.BlobRefV1,
    output_path: []const u8,
    dependency_manifest_ref: artifact_store.BlobRefV1,
    stage_manifest_ref: ?artifact_store.BlobRefV1 = null,
};

fn initRow(
    fixture: *FixtureV4,
    store: *artifact_store.Store,
    allocator: std.mem.Allocator,
    index: usize,
) !FixtureRowV4 {
    const child_bytes = try std.fmt.allocPrint(
        allocator,
        "stage101-proof-{d}",
        .{index},
    );
    const child_ref = try store.putBytes(.proof_artifact, 1, child_bytes);
    const nested_bytes = try std.fmt.allocPrint(
        allocator,
        "stage102-nested-proof-{d}",
        .{index},
    );
    const nested_ref = try store.putBytes(.proof_artifact, 1, nested_bytes);
    const geometry = try fixture.final_remint.geometryForRole(
        .ethereum_incremental_leaf_wrapper_v4,
    );
    const coordinate = try campaign_public.coordinate(
        &fixture.shape,
        0,
        @intCast(index),
    );
    const statement = try campaignLeafStatement(
        @intCast(fixture.rows.len),
        @intCast(index),
    );
    const canonical = try statement.canonicalWords();
    var statement_words: [
        @import("recursive_field_node_public_v2.zig")
            .STATEMENT_WORD_COUNT
    ]u32 = undefined;
    for (&statement_words, canonical) |*destination, word|
        destination.* = word.toU32();
    const node_public = try campaign_public.initLeaf(
        &fixture.shape,
        coordinate,
        statement_words,
        poseidonDigest(@intCast(0x100 + index * 16)),
    );
    const artifact = try campaign_artifact.seal(&fixture.shape, .{
        .stage_kind = .leaf_wrapper,
        .node_kind = .real,
        .child_count = 1,
        .coordinate = coordinate,
        .node_public = node_public,
        .campaign_namespace_sha256 = fixture.shape.campaign_namespace_sha256,
        .circuit_identity_sha256 = geometry.circuit_identity_sha256,
        .program_identity_sha256 = geometry.program_identity_sha256,
        .profile_identity_sha256 = geometry.profile_identity_sha256,
        .pcs_identity_sha256 = geometry.pcs.identity_sha256,
        .padding_layout_identity_sha256 = geometry.padding_layout_identity_sha256,
        .registry_identity_sha256 = fixture.remint.registry.identity_sha256,
        .node_public_abi_sha256 = @import("recursive_field_node_public_v2.zig").abiIdentitySha256(),
        .proof_shape_identity_sha256 = geometry.proof_shape.identity_sha256,
        .ordered_children = .{
            try node_store.fromSharedRef(child_ref),
            campaign_artifact.ArtifactRef.zero(),
        },
        .proof_ref = try node_store.fromSharedRef(nested_ref),
        .preprocessed_root = geometry.preprocessed_root,
        .semantic_inputs_identity_sha256 = undefined,
        .field_public_transport_sha256 = undefined,
        .content_identity_sha256 = undefined,
    });
    const projected = try campaign_artifact.semanticInputsForStore(
        &fixture.shape,
        &artifact,
    );
    var dependency = [_]protocol.Dependency{.{
        .node_id = try std.fmt.allocPrint(
            allocator,
            "stage101/{d}",
            .{index},
        ),
        .role = @intFromEnum(artifact_store.InputRoleV1.proof),
        .ordinal = 0,
    }};
    const ordered_inputs = [_]artifact_store.InputRefV1{.{
        .role = .proof,
        .ordinal = 0,
        .blob = child_ref,
    }};
    const local_task = try campaign_store.localTaskIdentity(
        &fixture.shape,
        &projected,
    );
    const security = node_store.security.ProofSecurityV1.recursiveParentSecure();
    const semantic_options = try real_worker.semanticOptionsValueV4(
        allocator,
        &projected,
    );
    const node = protocol.Node{
        .node_id = try std.fmt.allocPrint(allocator, "stage102/{d}", .{index}),
        .stage_kind = .prove,
        .stage_schema_version = real_worker.STAGE_SCHEMA_VERSION,
        .adapter = real_worker.adapter_name,
        .dependencies = &dependency,
        .external_inputs = &.{},
        .local_task_identity_sha256 = local_task,
        .semantic_authorities = .{
            .protocol_identity_sha256 = projected.circuit_identity_sha256,
            .program_identity_sha256 = projected.program_identity_sha256,
            .profile_identity_sha256 = projected.profile_identity_sha256,
            .pcs_identity_sha256 = projected.pcs_identity_sha256,
            .security_identity_sha256 = security.identity,
            .statement_identity_sha256 = try campaign_store.statementCacheIdentity(
                &fixture.shape,
                &projected,
            ),
            .provider_identity_sha256 = [_]u8{0} ** 32,
            .layout_identity_sha256 = projected.padding_layout_identity_sha256,
            .registry_identity_sha256 = projected.registry_identity_sha256,
        },
        .semantic_options = semantic_options,
        .cpu_tokens = fixture.policy.cpu_tokens_per_node,
        .rss_tokens = fixture.policy.rss_bytes_per_node,
        .output_kind = .recursion_node,
        .output_schema_version = campaign_artifact.SCHEMA_VERSION,
    };
    const semantic = try support.createSemanticKey(
        allocator,
        node,
        &ordered_inputs,
        fixture.shape.campaign_namespace_sha256,
    );
    const execution = try artifact_store.ExecutionKeyV1.create(.{
        .semantic_key_identity = semantic.identity,
        .producer_identity = digest(0x51),
        .verifier_identity = digest(0x52),
        .source_identity = digest(0x53),
        .build_identity = digest(0x54),
        .executable_identity = digest(0x55),
        .toolchain_identity = digest(0x56),
        .backend_identity = digest(0x57),
        .optimization_identity = digest(0x58),
        .worker_policy_identity = fixture.policy.worker_policy_identity,
        .memory_policy_identity = fixture.policy.memory_policy_identity,
        .retention_policy_identity = digest(0x5b),
        .timeout_policy_identity = digest(0x5c),
    });
    try publishKeys(store, allocator, semantic, execution);
    const dependency_manifest_ref = try publishDependencyManifest(
        store,
        allocator,
        child_ref,
        index,
    );
    const output_ref = try campaign_store.publishRecursiveNode(
        store,
        &fixture.shape,
        &artifact,
    );
    return .{
        .artifact = artifact,
        .node = node,
        .dependency = dependency,
        .ordered_inputs = ordered_inputs,
        .semantic = semantic,
        .execution = execution,
        .output_ref = output_ref,
        .output_path = try storage.objectPathAlloc(allocator, store, output_ref),
        .dependency_manifest_ref = dependency_manifest_ref,
    };
}

fn publishKeys(
    store: *artifact_store.Store,
    allocator: std.mem.Allocator,
    semantic: artifact_store.SemanticKeyV1,
    execution: artifact_store.ExecutionKeyV1,
) !void {
    const semantic_bytes = try semantic.canonicalBytesAlloc(allocator);
    const semantic_ref = try store.putBytes(.semantic_key, 1, semantic_bytes);
    if (!std.mem.eql(u8, &semantic_ref.sha256, &semantic.identity))
        return error.InvalidFixtureStageV4;
    const execution_bytes = try execution.canonicalBytes();
    const execution_ref = try store.putBytes(.execution_key, 1, &execution_bytes);
    if (!std.mem.eql(u8, &execution_ref.sha256, &execution.identity))
        return error.InvalidFixtureStageV4;
}

fn publishDependencyManifest(
    store: *artifact_store.Store,
    allocator: std.mem.Allocator,
    output_ref: artifact_store.BlobRefV1,
    index: usize,
) !artifact_store.BlobRefV1 {
    const outputs = [_]artifact_store.BlobRefV1{output_ref};
    const manifest = try artifact_store.StageManifestV1.create(allocator, .{
        .stage_kind = .prove,
        .stage_schema_version = 101,
        .node_identity = digest(@intCast(0x70 + index)),
        .semantic_key_identity = digest(@intCast(0x80 + index)),
        .execution_key_identity = digest(@intCast(0x90 + index)),
        .phase = .published,
        .status = .complete,
        .ordered_dependency_manifest_ids = &.{},
        .ordered_inputs = &.{},
        .ordered_outputs = &outputs,
    });
    const bytes = try manifest.canonicalBytesAlloc(allocator);
    return store.putBytes(.stage_manifest, 1, bytes);
}

fn campaignJob(segment_count: u32) !recursion.span_statement.JobContext {
    return recursion.span_statement.JobContext.init(
        try recursion.span_statement.CompleteExecution.init(
            recursion.protocol.PROTOCOL_ID_WORDS,
            poseidonDigest(0x41),
            try recursion.span_statement.MachineState.init(
                0x1000,
                [_]u32{0} ** 32,
                poseidonDigest(0x11),
                poseidonDigest(0x21),
            ),
            try recursion.span_statement.MachineState.init(
                0x2000,
                [_]u32{0} ** 32,
                poseidonDigest(0x31),
                poseidonDigest(0x41),
            ),
            poseidonDigest(0x51),
            poseidonDigest(0x61),
            88_000,
        ),
        segment_count,
    );
}

fn campaignLeafStatement(
    segment_count: u32,
    index: u32,
) !recursion.span_statement.SpanStatement {
    if (index >= segment_count) return error.InvalidFixtureCampaignCoordinateV4;
    const job = try campaignJob(segment_count);
    const next_index = try std.math.add(u32, index, 1);
    const total_cycles = job.complete.total_cycles;
    const count_u64: u64 = segment_count;
    const first_cycle = total_cycles * @as(u64, index) / count_u64;
    const final_cycle = total_cycles * @as(u64, next_index) / count_u64;
    const input = if (index == 0)
        try recursion.span_statement.EdgeClaim.present(job.complete.public_input)
    else
        recursion.span_statement.EdgeClaim.absent();
    const output = if (next_index == segment_count)
        try recursion.span_statement.EdgeClaim.present(job.complete.public_output)
    else
        recursion.span_statement.EdgeClaim.absent();
    const executed = try recursion.span_statement.ExecutedSpan.init(
        index,
        1,
        first_cycle,
        final_cycle - first_cycle,
        try campaignBoundaryState(job, index),
        try campaignBoundaryState(job, next_index),
        input,
        output,
    );
    return recursion.span_statement.SpanStatement.segmentLeaf(job, index, executed);
}

fn campaignBoundaryState(
    job: recursion.span_statement.JobContext,
    boundary: u32,
) !recursion.span_statement.MachineState {
    if (boundary == 0) return job.complete.initial_state;
    if (boundary == job.segment_count) return job.complete.final_state;
    if (boundary > job.segment_count)
        return error.InvalidFixtureCampaignCoordinateV4;
    var registers = [_]u32{0} ** 32;
    registers[1] = boundary;
    return recursion.span_statement.MachineState.init(
        0x1000 + boundary * 4,
        registers,
        poseidonDigest(0x100 + boundary * 16),
        poseidonDigest(0x180 + boundary * 16),
    );
}

fn poseidonDigest(seed: u32) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index));
    return result;
}

fn digest(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index|
        byte.* = seed +% @as(u8, @intCast(index));
    return result;
}

fn expectRejected(result: anytype) !void {
    _ = result catch return;
    return error.ExpectedFixtureRejectionV4;
}
