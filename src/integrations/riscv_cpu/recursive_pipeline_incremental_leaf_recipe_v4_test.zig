const std = @import("std");
const artifact_store = @import("stwo_artifact_store");

const subject = @import("recursive_pipeline_incremental_leaf_recipe_v4.zig");

test "stage101 recipe is canonical and binds every leaf-local input" {
    const value = try fixture(4, 5);
    const encoded = try subject.encode(&value);
    try std.testing.expectEqual(
        @as(usize, subject.ENCODED_BYTE_COUNT),
        encoded.len,
    );
    const decoded = try subject.decode(&encoded);
    try std.testing.expectEqualDeep(value, decoded);

    const recipe_ref = try ref(.capture_transport, subject.SCHEMA_VERSION, 90);
    const inputs = [_]artifact_store.InputRefV1{
        input(.statement, 0, value.statement),
        input(.program, 0, value.program),
        input(.profile, 0, recipe_ref),
        input(.witness, 0, value.compact_witness),
        input(.capture, 0, value.boundary_v4),
        input(.capture, 1, value.public_wire_reference_v4),
        input(.journal, 0, value.journal_record),
    };
    try value.validateStageInputs(&inputs, recipe_ref);
    inline for ([_]u32{ 2, 3, 5 }) |segment_count| {
        const bounded = try fixture(segment_count - 1, segment_count);
        try bounded.validateAgainstCampaignCount(segment_count);
        const bounded_bytes = try subject.encode(&bounded);
        try std.testing.expectEqualDeep(
            bounded,
            try subject.decode(&bounded_bytes),
        );
    }

    var reversed = inputs;
    std.mem.swap(
        artifact_store.InputRefV1,
        &reversed[4],
        &reversed[5],
    );
    try std.testing.expectError(
        error.IncrementalLeafRecipeInputMismatchV4,
        value.validateStageInputs(&reversed, recipe_ref),
    );
}

test "stage101 recipe rejects coordinate codec and reseal mutations" {
    const value = try fixture(4, 5);

    var mutation = value;
    mutation.segment_index =
        subject.CURRENT_ETHEREUM_CONFORMANCE_SEGMENT_COUNT;
    try std.testing.expectError(
        error.InvalidIncrementalLeafRecipeV4,
        mutation.validate(),
    );

    mutation = value;
    mutation.public_wire_reference_v4.schema_version = 4;
    try std.testing.expectError(
        error.InvalidIncrementalLeafRecipeV4,
        mutation.validate(),
    );

    var encoded = try subject.encode(&value);
    encoded[encoded.len - 1] ^= 1;
    try std.testing.expectError(
        error.InvalidIncrementalLeafRecipeV4,
        subject.decode(&encoded),
    );
}

fn fixture(segment_index: u32, segment_count: u32) !subject.RecipeV4 {
    return subject.RecipeV4.seal(.{
        .segment_index = segment_index,
        .segment_count = segment_count,
        .statement = try ref(.statement, 1, 1),
        .program = try ref(.program, 1, 2),
        .compact_witness = try ref(.capture_transport, 1, 3),
        .boundary_v4 = try ref(.capture_transport, 4, 4),
        .public_wire_reference_v4 = try ref(
            .capture_transport,
            0x0402,
            5,
        ),
        .journal_record = try ref(.journal, 1, 6),
        .raw_input = try ref(.raw, 1, 7),
        .expected_output = try ref(.raw, 1, 8),
        .boundary_manifest_v4 = try ref(.capture_transport, 4, 9),
        .public_wire_manifest_v4 = try ref(
            .capture_transport,
            0x0403,
            10,
        ),
        .content_sha256 = undefined,
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
    seed: u8,
) !artifact_store.BlobRefV1 {
    var digest = [_]u8{seed} ** 32;
    digest[31] +%= 1;
    return artifact_store.BlobRefV1.create(
        kind,
        schema_version,
        @as(u64, seed) + 1,
        digest,
    );
}
