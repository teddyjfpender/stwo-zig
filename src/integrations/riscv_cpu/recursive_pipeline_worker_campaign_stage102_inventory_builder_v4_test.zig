const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");
const immutable =
    @import("recursive_pipeline_worker_campaign_stage102_inventory_v4.zig");
const builder =
    @import("recursive_pipeline_worker_campaign_stage102_inventory_builder_v4.zig");

test "Stage102 builder deep-owns every transient admission projection" {
    const allocator = std.testing.allocator;
    var request_arena = std.heap.ArenaAllocator.init(allocator);
    var request_arena_live = true;
    defer if (request_arena_live) request_arena.deinit();
    const request_allocator = request_arena.allocator();

    var option_text = [_]u8{ 'f', 'r', 'e', 's', 'h' };
    const option_copy = try request_allocator.dupe(u8, &option_text);
    var options = protocol.jsonObject(request_allocator);
    try protocol.put(&options, "mode", protocol.string(option_copy));

    var node_id = [_]u8{ 'r', 'o', 'w', '-', '0' };
    var adapter = [_]u8{ 's', 't', 'a', 'g', 'e', '1', '0', '2' };
    var dependency_name = [_]u8{ 's', 't', 'a', 'g', 'e', '1', '0', '1' };
    var dependencies = [_]protocol.Dependency{.{
        .node_id = &dependency_name,
        .role = @intFromEnum(artifact_store.InputRoleV1.proof),
        .ordinal = 0,
    }};
    var external_inputs: [0]artifact_store.InputRefV1 = .{};
    var ordered_inputs = [_]artifact_store.InputRefV1{.{
        .role = .proof,
        .ordinal = 0,
        .blob = blob(.proof_artifact, 1, 991, 30),
    }};
    const semantic = try artifact_store.SemanticKeyV1.create(allocator, .{
        .stage_kind = .prove,
        .stage_schema_version = 102,
        .campaign_namespace = digest(1),
        .local_task_identity = digest(2),
        .protocol_identity = digest(3),
        .program_identity = digest(4),
        .profile_identity = digest(5),
        .pcs_identity = digest(6),
        .security_identity = digest(7),
        .statement_identity = digest(8),
        .provider_identity = digest(9),
        .layout_identity = digest(10),
        .registry_identity = digest(11),
        .semantic_options_identity = try protocol.canonicalDigest(
            allocator,
            options,
        ),
        .ordered_inputs = &ordered_inputs,
    });
    const execution = try artifact_store.ExecutionKeyV1.create(.{
        .semantic_key_identity = semantic.identity,
        .producer_identity = digest(20),
        .verifier_identity = digest(21),
        .source_identity = digest(22),
        .build_identity = digest(23),
        .executable_identity = digest(24),
        .toolchain_identity = digest(25),
        .backend_identity = digest(26),
        .optimization_identity = digest(27),
        .worker_policy_identity = digest(28),
        .memory_policy_identity = digest(29),
        .retention_policy_identity = digest(30),
        .timeout_policy_identity = digest(31),
    });
    const node = protocol.Node{
        .node_id = &node_id,
        .stage_kind = .prove,
        .stage_schema_version = 102,
        .adapter = &adapter,
        .dependencies = &dependencies,
        .external_inputs = &external_inputs,
        .local_task_identity_sha256 = digest(2),
        .semantic_authorities = .{
            .protocol_identity_sha256 = digest(3),
            .program_identity_sha256 = digest(4),
            .profile_identity_sha256 = digest(5),
            .pcs_identity_sha256 = digest(6),
            .security_identity_sha256 = digest(7),
            .statement_identity_sha256 = digest(8),
            .provider_identity_sha256 = digest(9),
            .layout_identity_sha256 = digest(10),
            .registry_identity_sha256 = digest(11),
        },
        .semantic_options = options,
        .cpu_tokens = 4,
        .rss_tokens = 4096,
        .output_kind = .recursion_node,
        .output_schema_version = 2,
    };
    const output_ref = blob(.recursion_node, 2, 2380, 40);
    const admission = immutable.Admission{
        .node = &node,
        .semantic = &semantic,
        .execution = &execution,
        .ordered_inputs = &ordered_inputs,
        .stage_manifest_ref = blob(.stage_manifest, 1, 800, 41),
        .dependency_stage_manifest_ref = blob(.stage_manifest, 1, 700, 42),
    };
    const owned = try builder.testing.deepOwnEntry(
        allocator,
        allocator,
        output_ref,
        admission,
    );
    defer builder.testing.deinitEntry(owned, allocator);
    const owned_view = builder.testing.entry(owned);
    try std.testing.expect(try immutable.exactEntryMatchV4(
        allocator,
        &owned_view,
        output_ref,
        admission,
    ));

    var drift_node = node;
    drift_node.node_id = "row-drift";
    var drift = admission;
    drift.node = &drift_node;
    try std.testing.expect(!try immutable.exactEntryMatchV4(
        allocator,
        &owned_view,
        output_ref,
        drift,
    ));

    node_id[0] = 'X';
    adapter[0] = 'X';
    dependency_name[0] = 'X';
    option_text[0] = 'X';
    option_copy[0] = 'X';
    ordered_inputs[0].blob.sha256[0] +%= 1;
    request_arena.deinit();
    request_arena_live = false;

    try std.testing.expectEqualStrings("row-0", owned_view.admission.node.node_id);
    try std.testing.expectEqualStrings(
        "stage102",
        owned_view.admission.node.adapter,
    );
    try std.testing.expectEqualStrings(
        "stage101",
        owned_view.admission.node.dependencies[0].node_id,
    );
    const owned_options = try protocol.objectValue(
        owned_view.admission.node.semantic_options,
    );
    try std.testing.expectEqualStrings(
        "fresh",
        try protocol.stringField(owned_options, "mode"),
    );
    try std.testing.expectEqual(
        @as(u8, 30),
        owned_view.admission.ordered_inputs[0].blob.sha256[0],
    );
    try owned_view.admission.semantic.validate(allocator);
    try owned_view.admission.execution.validate();
}

test "Stage102 builder authority remains unrouteable and nonserializable" {
    try std.testing.expect(!builder.PRODUCTION_ACTIVATION);
    try std.testing.expect(!builder.ROUTER_ACTIVATION);
    try std.testing.expect(!builder.SERIALIZABLE_FRESH_CAPABILITY);
    try std.testing.expect(builder.REQUEST_PROJECTIONS_DEEP_OWNED);
    try std.testing.expect(builder.POINTER_STABLE_COORDINATE_SLOTS);
    try std.testing.expect(builder.OUT_OF_ORDER_ARRIVAL_CANONICALIZED);
    try std.testing.expect(builder.SEAL_COMPLETE_IS_ATOMIC);
}

fn blob(
    kind: artifact_store.ArtifactKindV1,
    schema: u16,
    byte_count: u64,
    seed: u8,
) artifact_store.BlobRefV1 {
    return .{
        .kind = kind,
        .schema_version = schema,
        .byte_count = byte_count,
        .sha256 = digest(seed),
    };
}

fn digest(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index|
        byte.* = seed +% @as(u8, @intCast(index));
    return result;
}
