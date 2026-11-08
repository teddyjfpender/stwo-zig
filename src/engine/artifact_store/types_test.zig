const std = @import("std");
const encoding = @import("encoding.zig");
const types = @import("types.zig");
const manifest = @import("manifest.zig");
const wire = @import("wire.zig");

fn digest(byte: u8) encoding.Digest {
    return [_]u8{byte} ** 32;
}

fn proofBlob(byte: u8) types.BlobRefV1 {
    return types.BlobRefV1.create(.proof_artifact, 3, 5, digest(byte)) catch unreachable;
}

fn semanticFields(inputs: []const types.InputRefV1) types.SemanticKeyFieldsV1 {
    return .{
        .stage_kind = .prove,
        .stage_schema_version = 7,
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
        .semantic_options_identity = digest(12),
        .ordered_inputs = inputs,
    };
}

fn goldenInputs() [2]types.InputRefV1 {
    return .{
        .{
            .role = .statement,
            .ordinal = 0,
            .blob = types.BlobRefV1.create(.statement, 3, 5, digest(0x11)) catch unreachable,
        },
        .{
            .role = .child_left,
            .ordinal = 0,
            .blob = types.BlobRefV1.create(.recursion_node, 2, 9, digest(0x22)) catch unreachable,
        },
    };
}

fn executionFields(semantic_identity: encoding.Digest) types.ExecutionKeyFieldsV1 {
    return .{
        .semantic_key_identity = semantic_identity,
        .producer_identity = digest(21),
        .verifier_identity = digest(22),
        .source_identity = digest(23),
        .build_identity = digest(24),
        .executable_identity = digest(25),
        .toolchain_identity = digest(26),
        .backend_identity = digest(27),
        .optimization_identity = digest(28),
        .worker_policy_identity = digest(29),
        .memory_policy_identity = digest(30),
        .retention_policy_identity = digest(31),
        .timeout_policy_identity = digest(32),
    };
}

test "artifact keys: BlobRef preserves zero-byte native kind and schema" {
    const empty = try types.BlobRefV1.create(
        .raw,
        9,
        0,
        encoding.digestBytes(""),
    );
    const bytes = try empty.canonicalBytes();
    const reopened = try types.BlobRefV1.decodeCanonical(&bytes);
    try std.testing.expect(types.BlobRefV1.eql(empty, reopened));
    try std.testing.expectEqual(@as(u16, 9), reopened.schema_version);
}

test "artifact keys: canonical Zig semantic and execution golden vectors" {
    const inputs = goldenInputs();
    const semantic = try types.SemanticKeyV1.create(
        std.testing.allocator,
        semanticFields(&inputs),
    );
    const semantic_bytes = try semantic.canonicalBytesAlloc(std.testing.allocator);
    defer std.testing.allocator.free(semantic_bytes);
    try std.testing.expectEqual(@as(usize, 548), semantic_bytes.len);
    var expected_semantic: encoding.Digest = undefined;
    _ = try std.fmt.hexToBytes(
        &expected_semantic,
        "abe55472520e39062de460217ce896bb63c2b690ec7478368d09b89a2ae8a1c4",
    );
    try std.testing.expectEqual(expected_semantic, semantic.identity);

    const execution = try types.ExecutionKeyV1.create(executionFields(semantic.identity));
    const execution_bytes = try execution.canonicalBytes();
    try std.testing.expectEqual(@as(usize, 459), execution_bytes.len);
    var expected_execution: encoding.Digest = undefined;
    _ = try std.fmt.hexToBytes(
        &expected_execution,
        "17b1e66e314d5cfe7356d78e8861c6d1019f6123640fa4d1190a033508bf5731",
    );
    try std.testing.expectEqual(expected_execution, execution.identity);

    var reopened_semantic = try wire.decodeSemanticKeyAlloc(
        std.testing.allocator,
        semantic_bytes,
    );
    defer reopened_semantic.deinit(std.testing.allocator);
    try std.testing.expectEqual(semantic.identity, reopened_semantic.value.identity);
    const reopened_execution = try wire.decodeExecutionKey(&execution_bytes);
    try std.testing.expectEqual(execution.identity, reopened_execution.identity);
}

test "artifact keys: direct input order and semantic options are semantic" {
    const inputs = goldenInputs();
    const first = try types.SemanticKeyV1.create(
        std.testing.allocator,
        semanticFields(&inputs),
    );
    const reversed = [_]types.InputRefV1{ inputs[1], inputs[0] };
    const reordered = try types.SemanticKeyV1.create(
        std.testing.allocator,
        semanticFields(&reversed),
    );
    try std.testing.expect(!std.mem.eql(u8, &first.identity, &reordered.identity));
    var changed_fields = semanticFields(&inputs);
    changed_fields.semantic_options_identity = digest(44);
    const changed = try types.SemanticKeyV1.create(std.testing.allocator, changed_fields);
    try std.testing.expect(!std.mem.eql(u8, &first.identity, &changed.identity));
}

test "artifact keys: execution policy changes do not alter semantic key" {
    comptime {
        if (@hasField(types.SemanticKeyFieldsV1, "path") or
            @hasField(types.SemanticKeyFieldsV1, "timestamp") or
            @hasField(types.SemanticKeyFieldsV1, "power_source") or
            @hasField(types.SemanticKeyFieldsV1, "worker_policy_identity"))
        {
            @compileError("environment or execution policy entered SemanticKeyV1");
        }
        if (@hasField(types.SemanticKeyFieldsV1, "validator_identity"))
            @compileError("validator identity must remain outside SemanticKeyV1");
    }
    const inputs = goldenInputs();
    const semantic = try types.SemanticKeyV1.create(
        std.testing.allocator,
        semanticFields(&inputs),
    );
    const first = try types.ExecutionKeyV1.create(executionFields(semantic.identity));
    var changed_fields = executionFields(semantic.identity);
    changed_fields.worker_policy_identity = digest(88);
    const changed = try types.ExecutionKeyV1.create(changed_fields);
    try std.testing.expect(!std.mem.eql(u8, &first.identity, &changed.identity));
    try std.testing.expectEqual(semantic.identity, first.fields.semantic_key_identity);
    try std.testing.expectEqual(semantic.identity, changed.fields.semantic_key_identity);

    var build_fields = executionFields(semantic.identity);
    build_fields.build_identity = digest(89);
    const changed_build = try types.ExecutionKeyV1.create(build_fields);
    try std.testing.expect(!std.mem.eql(u8, &first.identity, &changed_build.identity));
    try std.testing.expectEqual(semantic.identity, changed_build.fields.semantic_key_identity);

    var retention_fields = executionFields(semantic.identity);
    retention_fields.retention_policy_identity = digest(90);
    const changed_retention = try types.ExecutionKeyV1.create(retention_fields);
    try std.testing.expect(!std.mem.eql(u8, &first.identity, &changed_retention.identity));
    try std.testing.expectEqual(semantic.identity, changed_retention.fields.semantic_key_identity);

    var timeout_fields = executionFields(semantic.identity);
    timeout_fields.timeout_policy_identity = digest(91);
    const changed_timeout = try types.ExecutionKeyV1.create(timeout_fields);
    try std.testing.expect(!std.mem.eql(u8, &first.identity, &changed_timeout.identity));
    try std.testing.expectEqual(semantic.identity, changed_timeout.fields.semantic_key_identity);
}

test "artifact manifest: validator version revalidates without changing proof key" {
    const inputs = goldenInputs();
    const semantic = try types.SemanticKeyV1.create(
        std.testing.allocator,
        semanticFields(&inputs),
    );
    const execution = try types.ExecutionKeyV1.create(executionFields(semantic.identity));
    const outputs = [_]types.BlobRefV1{proofBlob(40)};
    const receipt_blob = try types.BlobRefV1.create(
        .validation_receipt,
        1,
        17,
        digest(41),
    );
    const receipts_v1 = [_]manifest.ValidationReceiptRefV1{.{
        .validator_kind = 3,
        .validator_schema_version = 1,
        .authority_identity = digest(42),
        .validator_identity = digest(43),
        .blob = receipt_blob,
    }};
    const fields = manifest.StageManifestFieldsV1{
        .stage_kind = .prove,
        .stage_schema_version = 7,
        .node_identity = digest(2),
        .semantic_key_identity = semantic.identity,
        .execution_key_identity = execution.identity,
        .phase = .validated,
        .status = .complete,
        .ordered_dependency_manifest_ids = &.{},
        .ordered_inputs = &inputs,
        .ordered_outputs = &outputs,
        .validation_receipts = &receipts_v1,
    };
    const first = try manifest.StageManifestV1.create(std.testing.allocator, fields);
    try first.validateAgainstKeys(std.testing.allocator, semantic, execution);
    var changed_receipts = receipts_v1;
    changed_receipts[0].validator_schema_version = 2;
    changed_receipts[0].validator_identity = digest(44);
    var changed_fields = fields;
    changed_fields.validation_receipts = &changed_receipts;
    const changed = try manifest.StageManifestV1.create(
        std.testing.allocator,
        changed_fields,
    );
    try std.testing.expect(!std.mem.eql(u8, &first.identity, &changed.identity));
    try std.testing.expectEqual(semantic.identity, changed.fields.semantic_key_identity);
}

test "artifact wire: manifest cold roundtrip and truncation fail closed" {
    const inputs = goldenInputs();
    const semantic = try types.SemanticKeyV1.create(
        std.testing.allocator,
        semanticFields(&inputs),
    );
    const execution = try types.ExecutionKeyV1.create(executionFields(semantic.identity));
    const outputs = [_]types.BlobRefV1{proofBlob(50)};
    const value = try manifest.StageManifestV1.create(std.testing.allocator, .{
        .stage_kind = .prove,
        .stage_schema_version = 7,
        .node_identity = digest(2),
        .semantic_key_identity = semantic.identity,
        .execution_key_identity = execution.identity,
        .phase = .published,
        .status = .complete,
        .ordered_dependency_manifest_ids = &.{digest(60)},
        .ordered_inputs = &inputs,
        .ordered_outputs = &outputs,
    });
    const bytes = try value.canonicalBytesAlloc(std.testing.allocator);
    defer std.testing.allocator.free(bytes);
    var reopened = try wire.decodeStageManifestAlloc(std.testing.allocator, bytes);
    defer reopened.deinit(std.testing.allocator);
    try std.testing.expectEqual(value.identity, reopened.value.identity);
    try reopened.value.validateAgainstKeys(std.testing.allocator, semantic, execution);
    try std.testing.expectError(
        error.TruncatedArtifactEncoding,
        wire.decodeStageManifestAlloc(std.testing.allocator, bytes[0 .. bytes.len - 1]),
    );
    var extended = try std.testing.allocator.alloc(u8, bytes.len + 1);
    defer std.testing.allocator.free(extended);
    @memcpy(extended[0..bytes.len], bytes);
    extended[bytes.len] = 0;
    try std.testing.expectError(
        error.NonCanonicalArtifactEncoding,
        wire.decodeStageManifestAlloc(std.testing.allocator, extended),
    );
}

fn allocationFailureRoundtrip(allocator: std.mem.Allocator) !void {
    const inputs = goldenInputs();
    const semantic = try types.SemanticKeyV1.create(allocator, semanticFields(&inputs));
    const bytes = try semantic.canonicalBytesAlloc(allocator);
    defer allocator.free(bytes);
    var reopened = try wire.decodeSemanticKeyAlloc(allocator, bytes);
    defer reopened.deinit(allocator);
    try reopened.value.validate(allocator);
}

test "artifact wire: semantic key roundtrip releases every failed allocation" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureRoundtrip,
        .{},
    );
}
