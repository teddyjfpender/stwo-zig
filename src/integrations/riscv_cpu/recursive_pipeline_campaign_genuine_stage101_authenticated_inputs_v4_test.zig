const std = @import("std");
const artifact_store = @import("stwo_artifact_store");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");

const subject =
    @import("recursive_pipeline_campaign_genuine_stage101_authenticated_inputs_v4.zig");
const namespace_mod =
    @import("recursive_pipeline_campaign_namespace_v1.zig");
const native_worker = @import("recursive_pipeline_worker_native_leaf_v4.zig");
const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const recipe_mod =
    @import("recursive_pipeline_incremental_leaf_recipe_v4.zig");
const support = @import("recursive_pipeline_worker_support_v1.zig");
const table_mod =
    @import("recursive_pipeline_incremental_campaign_table_v4.zig");
const wire_publication =
    @import("ethereum_incremental_public_wire_publication_v4.zig");

const Engine = frontend.recursion.engine.ProverEngineForBackend(CpuBackend);
const Family = blk: {
    @setEvalBranchQuota(500_000);
    break :blk subject.Types(Engine);
};

test "authenticated Stage101 owner is runtime-count cold custody, never a codec" {
    @setEvalBranchQuota(500_000);
    std.testing.refAllDecls(Family.OwnedCampaignV4);
    try std.testing.expect(subject.RUNTIME_CAMPAIGN_COUNT);
    try std.testing.expect(subject.EVERY_LEAF_INDEPENDENTLY_COLD_OPENED);
    try std.testing.expect(!subject.TABLE_REF_ALONE_IS_ADMISSION);
    try std.testing.expect(!subject.PROOF_REF_ALONE_IS_ADMISSION);
    try std.testing.expect(!subject.PRODUCTION_ACTIVATION);
    try std.testing.expect(!subject.ROUTER_ACTIVATION);
    try std.testing.expect(!subject.SERIALIZABLE_FRESH_CAPABILITY);
    try std.testing.expect(Family.NativeLeaseV4 ==
        native_worker.AdapterForEngine(Engine).LeasePayload);
    inline for (.{ "encode", "decode", "serialize", "deserialize" }) |name| {
        try std.testing.expect(!@hasDecl(Family.OwnedCampaignV4, name));
    }
    inline for (.{
        "open",
        "openThreeLeafFixture",
        "retainedLeaseAt",
        "retainedFreshInputAt",
        "coldOpenLeaseAt",
        "openFreshInput",
        "fillStage101Admissions",
    }) |name| try std.testing.expect(@hasDecl(Family.OwnedCampaignV4, name));

    const wrong_kind = ref(
        .raw,
        table_mod.CAS_SCHEMA_VERSION,
        try table_mod.encodedByteCount(3),
        1,
    );
    try std.testing.expectError(
        error.AuthenticatedStage101TableReferenceMismatchV4,
        Family.OwnedCampaignV4.openThreeLeafFixture(
            std.testing.allocator,
            undefined,
            wrong_kind,
            &.{},
        ),
    );
}

test "authenticated Stage101 publication binds ordered table row and exact keys" {
    const allocator = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var records: [3]table_mod.LeafRecordV4 = undefined;
    const table = try fixtureTable(&records);
    const namespace = try namespace_mod.fromValidatedTable(&table);
    const row_index: usize = 1;
    const row = table.records[row_index];
    const projected = try native_worker.semanticProjection(
        row.segment_index,
        table.segment_count,
        &row.stage_inputs,
        namespace,
    );
    const dependencies = try arena.alloc(protocol.Dependency, 0);
    const external_inputs = try arena.dupe(
        artifact_store.InputRefV1,
        &row.stage_inputs,
    );
    const options = protocol.jsonObject(arena);
    const node = protocol.Node{
        .node_id = "native/1",
        .stage_kind = .prove,
        .stage_schema_version = native_worker.STAGE_SCHEMA_VERSION,
        .adapter = native_worker.adapter_name,
        .dependencies = dependencies,
        .external_inputs = external_inputs,
        .local_task_identity_sha256 = projected.local_task_identity_sha256,
        .semantic_authorities = projected.authorities,
        .semantic_options = options,
        .cpu_tokens = 3,
        .rss_tokens = 4096,
        .output_kind = .proof_artifact,
        .output_schema_version = native_worker.OUTPUT_SCHEMA_VERSION,
    };
    const semantic = try support.createSemanticKey(
        arena,
        node,
        &row.stage_inputs,
        namespace,
    );
    const execution = try executionFor(semantic.identity);
    const publication = subject.PublishedStage101V4{
        .node = node,
        .semantic = semantic,
        .execution = execution,
        .output_ref = ref(
            .proof_artifact,
            native_worker.OUTPUT_SCHEMA_VERSION,
            101,
            2,
        ),
        .stage_manifest_ref = ref(
            .stage_manifest,
            support.stage_manifest_schema_version,
            103,
            3,
        ),
    };
    try subject.testing.validatePublicationEnvelopeV4(
        allocator,
        &table,
        namespace,
        row_index,
        publication,
    );

    var mutation = publication;
    mutation.output_ref.schema_version +%= 1;
    try expectPublicationRejected(
        allocator,
        &table,
        namespace,
        row_index,
        mutation,
    );

    mutation = publication;
    var wrong_inputs = row.stage_inputs;
    wrong_inputs[4].blob.sha256[0] ^= 1;
    mutation.node.external_inputs = &wrong_inputs;
    try expectPublicationRejected(
        allocator,
        &table,
        namespace,
        row_index,
        mutation,
    );

    mutation = publication;
    mutation.execution.fields.semantic_key_identity[0] ^= 1;
    mutation.execution = try artifact_store.ExecutionKeyV1.create(
        mutation.execution.fields,
    );
    try expectPublicationRejected(
        allocator,
        &table,
        namespace,
        row_index,
        mutation,
    );

    try expectPublicationRejected(
        allocator,
        &table,
        namespace,
        0,
        publication,
    );
}

test "authenticated Stage101 table ref pins runtime cardinality before Store access" {
    const byte_count = try table_mod.encodedByteCount(3);
    const table_ref = ref(
        table_mod.ARTIFACT_KIND,
        table_mod.CAS_SCHEMA_VERSION,
        byte_count,
        4,
    );
    try subject.testing.validateTableRefV4(table_ref, 3);
    try std.testing.expectError(
        error.AuthenticatedStage101TableReferenceMismatchV4,
        subject.testing.validateTableRefV4(table_ref, 2),
    );
}

fn expectPublicationRejected(
    allocator: std.mem.Allocator,
    table: *const table_mod.CampaignTableV4,
    namespace: artifact_store.Digest,
    index: usize,
    publication: subject.PublishedStage101V4,
) !void {
    try std.testing.expectError(
        error.AuthenticatedStage101PublicationMismatchV4,
        subject.testing.validatePublicationEnvelopeV4(
            allocator,
            table,
            namespace,
            index,
            publication,
        ),
    );
}

fn fixtureTable(
    records: *[3]table_mod.LeafRecordV4,
) !table_mod.CampaignTableV4 {
    const globals = fixtureGlobals();
    for (records, 0..) |*record, index|
        record.* = fixtureRecord(globals, @intCast(index));
    return table_mod.CampaignTableV4.seal(.{
        .segment_count = 3,
        .globals = globals,
        .records = records,
        .content_sha256 = undefined,
    });
}

fn fixtureGlobals() table_mod.GlobalRefsV4 {
    return .{
        .capture_manifest = ref(.capture_transport, 4, 13, 11),
        .public_wire_manifest = ref(
            .capture_transport,
            wire_publication.CAS_MANIFEST_SCHEMA_VERSION,
            17,
            12,
        ),
        .compact_manifest = ref(
            .capture_transport,
            table_mod.COMPACT_MANIFEST_CAS_SCHEMA_VERSION,
            19,
            13,
        ),
        .execution_profile_receipt = ref(.profile_receipt, 1, 23, 14),
        .materialization_result = ref(
            .source,
            table_mod.MATERIALIZATION_CAS_SCHEMA_VERSION,
            29,
            15,
        ),
        .source_request = ref(.source, 1, 31, 16),
        .execution_journal = ref(
            .journal,
            table_mod.FULL_JOURNAL_CAS_SCHEMA_VERSION,
            37,
            17,
        ),
        .program = ref(.program, 1, 41, 18),
        .raw_input = ref(.raw, 1, 43, 19),
        .expected_output = ref(.raw, 1, 47, 20),
    };
}

fn fixtureRecord(
    globals: table_mod.GlobalRefsV4,
    index: u32,
) table_mod.LeafRecordV4 {
    const statement = ref(
        .statement,
        1,
        @import("ethereum_block_leaf_support.zig").source_wire.encoded_size,
        @intCast(30 + index),
    );
    const recipe = ref(
        .capture_transport,
        recipe_mod.SCHEMA_VERSION,
        recipe_mod.ENCODED_BYTE_COUNT,
        @intCast(40 + index),
    );
    const compact = ref(
        .capture_transport,
        1,
        53 + index,
        @intCast(50 + index),
    );
    const boundary = ref(
        .capture_transport,
        4,
        59 + index,
        @intCast(60 + index),
    );
    const public_reference = ref(
        .capture_transport,
        wire_publication.CAS_REFERENCE_SCHEMA_VERSION,
        wire_publication.reference_byte_count,
        @intCast(70 + index),
    );
    const journal = ref(
        .journal,
        1,
        61 + index,
        @intCast(80 + index),
    );
    return .{
        .segment_index = index,
        .recipe = recipe,
        .stage_inputs = .{
            input(.statement, 0, statement),
            input(.program, 0, globals.program),
            input(.profile, 0, recipe),
            input(.witness, 0, compact),
            input(.capture, 0, boundary),
            input(.capture, 1, public_reference),
            input(.journal, 0, journal),
        },
    };
}

fn executionFor(
    semantic_identity: artifact_store.Digest,
) !artifact_store.ExecutionKeyV1 {
    return artifact_store.ExecutionKeyV1.create(.{
        .semantic_key_identity = semantic_identity,
        .producer_identity = digest(91),
        .verifier_identity = digest(92),
        .source_identity = digest(93),
        .build_identity = digest(94),
        .executable_identity = digest(95),
        .toolchain_identity = digest(96),
        .backend_identity = digest(97),
        .optimization_identity = digest(98),
        .worker_policy_identity = digest(99),
        .memory_policy_identity = digest(100),
        .retention_policy_identity = digest(101),
        .timeout_policy_identity = digest(102),
    });
}

fn input(
    role: artifact_store.InputRoleV1,
    ordinal: u32,
    blob: artifact_store.BlobRefV1,
) artifact_store.InputRefV1 {
    return .{ .role = role, .ordinal = ordinal, .blob = blob };
}

fn ref(
    kind: artifact_store.ArtifactKindV1,
    schema_version: u16,
    byte_count: anytype,
    seed: u8,
) artifact_store.BlobRefV1 {
    return artifact_store.BlobRefV1.create(
        kind,
        schema_version,
        @as(u64, @intCast(byte_count)),
        digest(seed),
    ) catch unreachable;
}

fn digest(seed: u8) artifact_store.Digest {
    var result = [_]u8{seed} ** 32;
    result[31] +%= 1;
    return result;
}

comptime {
    if (subject.PRODUCTION_ACTIVATION or subject.ROUTER_ACTIVATION or
        subject.SERIALIZABLE_FRESH_CAPABILITY)
    {
        @compileError("authenticated Stage101 test fixture activated routing");
    }
}
