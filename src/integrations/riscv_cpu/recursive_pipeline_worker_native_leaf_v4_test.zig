const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const subject = @import("recursive_pipeline_worker_native_leaf_v4.zig");
const recipe = @import("recursive_pipeline_incremental_leaf_recipe_v4.zig");
const wire = @import("ethereum_incremental_public_wire_publication_v4.zig");

test "stage101 exposes the exact seven-input proof contract" {
    const description = try subject.Adapter.describe(.prove, 101);
    try std.testing.expectEqual(
        artifact_store.StageKindV1.prove,
        description.stage_kind,
    );
    try std.testing.expectEqual(@as(u16, 101), description.stage_schema_version);
    try std.testing.expectEqual(
        artifact_store.ArtifactKindV1.proof_artifact,
        description.output_kind,
    );
    try std.testing.expectEqual(@as(u16, 1), description.output_schema_version);
    try std.testing.expect(description.root_cold_open_transitive);
    try std.testing.expect(subject.Adapter.available);
    try std.testing.expect(!subject.Adapter.production);
    try std.testing.expect(!subject.PRODUCTION_ACTIVATION);
    try std.testing.expect(!subject.SERIALIZABLE_FRESH_CAPABILITY);
    try std.testing.expectEqual(@as(usize, 7), subject.EXTERNAL_INPUT_COUNT);

    const inputs = try validInputs();
    try subject.validateExternalInputs(&inputs);
    inline for (subject.external_input_coordinates, 0..) |expected, ordinal| {
        try std.testing.expectEqual(expected.role, inputs[ordinal].role);
        try std.testing.expectEqual(expected.ordinal, inputs[ordinal].ordinal);
        try std.testing.expectEqual(expected.kind, inputs[ordinal].blob.kind);
        try std.testing.expectEqual(
            expected.schema_version,
            inputs[ordinal].blob.schema_version,
        );
    }
    try std.testing.expectError(
        error.UnsupportedRecursivePipelineStage,
        subject.Adapter.describe(.fold, 101),
    );
    try std.testing.expectError(
        error.UnsupportedRecursivePipelineStage,
        subject.Adapter.describe(.prove, 102),
    );
}

test "stage101 rejects role ordinal codec and order mutations" {
    const inputs = try validInputs();

    var mutation = inputs;
    mutation[0].role = .program;
    try expectInputMismatch(&mutation);

    mutation = inputs;
    mutation[5].ordinal = 0;
    try expectInputMismatch(&mutation);

    mutation = inputs;
    mutation[4].blob.schema_version = 3;
    try expectInputMismatch(&mutation);

    mutation = inputs;
    mutation[2].blob.byte_count += 1;
    try expectInputMismatch(&mutation);

    mutation = inputs;
    std.mem.swap(artifact_store.InputRefV1, &mutation[4], &mutation[5]);
    try expectInputMismatch(&mutation);

    try std.testing.expectError(
        error.NativeLeafStage101InputMismatch,
        subject.validateExternalInputs(inputs[0..6]),
    );
}

test "stage101 Zig semantic projection binds coordinate and ordered refs" {
    const inputs = try validInputs();
    const namespace = [_]u8{0x42} ** 32;
    const projection = try subject.semanticProjection(4, 5, &inputs, namespace);
    try std.testing.expectEqualDeep(
        namespace,
        projection.campaign_namespace_sha256,
    );
    try std.testing.expect(!std.mem.allEqual(
        u8,
        &projection.local_task_identity_sha256,
        0,
    ));
    try std.testing.expectEqualDeep(
        inputs[0].blob.sha256,
        projection.authorities.statement_identity_sha256,
    );
    try std.testing.expectEqualDeep(
        inputs[1].blob.sha256,
        projection.authorities.program_identity_sha256,
    );
    try std.testing.expectEqualDeep(
        inputs[2].blob.sha256,
        projection.authorities.profile_identity_sha256,
    );
    try std.testing.expect(std.mem.allEqual(
        u8,
        &projection.authorities.provider_identity_sha256,
        0,
    ));
    try std.testing.expect(std.mem.allEqual(
        u8,
        &projection.authorities.registry_identity_sha256,
        0,
    ));

    const next = try subject.semanticProjection(3, 5, &inputs, namespace);
    try std.testing.expect(!std.mem.eql(
        u8,
        &projection.local_task_identity_sha256,
        &next.local_task_identity_sha256,
    ));
    var mutated = inputs;
    mutated[3].blob.sha256[0] ^= 1;
    const changed = try subject.semanticProjection(4, 5, &mutated, namespace);
    try std.testing.expect(!std.mem.eql(
        u8,
        &projection.local_task_identity_sha256,
        &changed.local_task_identity_sha256,
    ));
    try std.testing.expect(!std.mem.eql(
        u8,
        &projection.authorities.layout_identity_sha256,
        &changed.authorities.layout_identity_sha256,
    ));
    inline for ([_]u32{ 2, 3, 5 }) |segment_count| {
        const first = try subject.semanticProjection(
            0,
            segment_count,
            &inputs,
            namespace,
        );
        const last = try subject.semanticProjection(
            segment_count - 1,
            segment_count,
            &inputs,
            namespace,
        );
        try std.testing.expect(!std.mem.eql(
            u8,
            &first.local_task_identity_sha256,
            &last.local_task_identity_sha256,
        ));
        try std.testing.expectError(
            error.NativeLeafStage101InputMismatch,
            subject.semanticProjection(
                segment_count,
                segment_count,
                &inputs,
                namespace,
            ),
        );
    }
    const count_two = try subject.semanticProjection(0, 2, &inputs, namespace);
    const count_three = try subject.semanticProjection(0, 3, &inputs, namespace);
    try std.testing.expect(!std.mem.eql(
        u8,
        &count_two.local_task_identity_sha256,
        &count_three.local_task_identity_sha256,
    ));
    try std.testing.expectError(
        error.NativeLeafStage101InputMismatch,
        subject.semanticProjection(0, 1, &inputs, namespace),
    );
    try std.testing.expectError(
        error.NativeLeafStage101InputMismatch,
        subject.semanticProjection(
            0,
            recipe.MAX_SEGMENT_COUNT + 1,
            &inputs,
            namespace,
        ),
    );
    try std.testing.expectError(
        error.NativeLeafStage101InputMismatch,
        subject.semanticProjection(0, 2, &inputs, [_]u8{0} ** 32),
    );
}

test "stage101 store-less hooks cannot mint admission" {
    try std.testing.expectError(
        error.NativeLeafStage101RequiresArtifactStore,
        subject.Adapter.buildOutput(
            std.testing.allocator,
            undefined,
            undefined,
            &.{},
            0,
        ),
    );
    try std.testing.expectError(
        error.NativeLeafStage101RequiresArtifactStore,
        subject.Adapter.validateOutput(
            std.testing.allocator,
            &.{},
            undefined,
            undefined,
            &.{},
        ),
    );
    comptime {
        for (.{
            "LeasePayload",
            "buildOutputWithLeases",
            "coldOpenLease",
            "deinitLeasePayload",
        }) |name| if (!@hasDecl(subject.Adapter, name))
            @compileError("stage101 worker lease surface drifted: " ++ name);
        if (@hasDecl(subject.Adapter.LeasePayload, "encode") or
            @hasDecl(subject.Adapter.LeasePayload, "decode"))
        {
            @compileError("stage101 fresh lease acquired a durable codec");
        }
        _ = typecheckLease;
    }
}

fn typecheckLease(payload: *const subject.Adapter.LeasePayload) !void {
    try payload.validate();
    _ = payload.freshView();
}

fn expectInputMismatch(inputs: []const artifact_store.InputRefV1) !void {
    try std.testing.expectError(
        error.NativeLeafStage101InputMismatch,
        subject.validateExternalInputs(inputs),
    );
}

fn validInputs() ![subject.EXTERNAL_INPUT_COUNT]artifact_store.InputRefV1 {
    return .{
        input(.statement, 0, try ref(.statement, 1, 2159, 1)),
        input(.program, 0, try ref(.program, 1, 4096, 2)),
        input(
            .profile,
            0,
            try ref(
                .capture_transport,
                recipe.SCHEMA_VERSION,
                recipe.ENCODED_BYTE_COUNT,
                3,
            ),
        ),
        input(.witness, 0, try ref(.capture_transport, 1, 8192, 4)),
        input(.capture, 0, try ref(.capture_transport, 4, 16384, 5)),
        input(
            .capture,
            1,
            try ref(
                .capture_transport,
                wire.CAS_REFERENCE_SCHEMA_VERSION,
                wire.reference_byte_count,
                6,
            ),
        ),
        input(.journal, 0, try ref(.journal, 1, 128, 7)),
    };
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
    byte_count: u64,
    seed: u8,
) !artifact_store.BlobRefV1 {
    var digest = [_]u8{seed} ** 32;
    digest[31] +%= 1;
    return artifact_store.BlobRefV1.create(
        kind,
        schema_version,
        byte_count,
        digest,
    );
}
