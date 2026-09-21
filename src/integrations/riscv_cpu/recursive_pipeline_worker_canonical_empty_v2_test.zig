const std = @import("std");
const artifact_store = @import("stwo_artifact_store");
const M31 = @import("stwo_core").fields.m31.M31;

const subject = @import("recursive_pipeline_worker_canonical_empty_v2.zig");
const protocol = @import("recursive_pipeline_worker_protocol_v1.zig");

test "stage103 describes only the field canonical-empty wrapper" {
    const description = try subject.Adapter.describe(.prove, 103);
    try std.testing.expectEqual(
        artifact_store.StageKindV1.prove,
        description.stage_kind,
    );
    try std.testing.expectEqual(@as(u16, 103), description.stage_schema_version);
    try std.testing.expectEqual(
        artifact_store.ArtifactKindV1.recursion_node,
        description.output_kind,
    );
    try std.testing.expectEqual(@as(u16, 2), description.output_schema_version);
    try std.testing.expect(description.root_cold_open_transitive);
    try std.testing.expect(!subject.Adapter.production);
    try std.testing.expect(!subject.Adapter.available);
    try std.testing.expectError(
        error.UnsupportedRecursivePipelineStage,
        subject.Adapter.describe(.fold, 103),
    );
    try std.testing.expectError(
        error.UnsupportedRecursivePipelineStage,
        subject.Adapter.describe(.prove, 102),
    );
}

test "stage103 requires a replayed three-role parity authority" {
    var invalid = std.mem.zeroes(subject.RegistryParityAuthorityV2);
    try std.testing.expectError(
        error.InvalidCircuitRegistry,
        invalid.validate(),
    );
    invalid.registry.production_activation = true;
    try std.testing.expectError(
        error.InvalidCircuitRegistry,
        subject.RegistryParityAuthorityV2.init(
            invalid.registry,
            invalid.geometries,
            invalid.parity,
        ),
    );
    try std.testing.expectError(
        error.CommonWrapperRegistryParityUnavailable,
        unavailableAdapter(),
    );
}

fn unavailableAdapter() !void {
    return subject.Adapter.unavailable();
}

test "stage103 fold child requires verifier-rerecorded live graph" {
    try std.testing.expectEqual(
        subject.FoldChildReadinessV2.verifier_rerecorded_composition_graph,
        subject.currentFoldChildReadiness(),
    );
    try std.testing.expect(subject.AUTHENTICATED_COMPOSITION_GRAPH_AVAILABLE);
    try std.testing.expect(!subject.SERIALIZABLE_FRESH_CAPABILITY);
    comptime {
        if (!@hasDecl(subject.LeasePayloadV2, "requireFoldChild") or
            !@hasDecl(subject.FreshFoldChildV2, "validateBorrowed") or
            !@hasField(subject.FreshFoldChildV2, "query_words") or
            @FieldType(subject.FreshFoldChildV2, "query_words") !=
                *const [193]M31)
        {
            @compileError("stage103 fold-child query replay surface drifted");
        }
        _ = typecheckFoldChild;
    }
}

fn typecheckFoldChild(payload: *const subject.LeasePayloadV2) !void {
    const child = try payload.requireFoldChild();
    try child.validateBorrowed();
}

test "stage103 worker surface typechecks behind the unavailable authority" {
    const TypecheckingAuthority = struct {
        pub const available = true;

        pub fn current() !subject.RegistryParityAuthorityV2 {
            return error.CommonWrapperRegistryParityUnavailable;
        }
    };
    const Adapter = subject.AdapterForRegistryAuthority(TypecheckingAuthority);
    try std.testing.expect(Adapter.available);
    try std.testing.expectError(
        error.CommonWrapperRegistryParityUnavailable,
        Adapter.buildOutputWithLeases(
            std.testing.allocator,
            undefined,
            undefined,
            undefined,
            &.{},
            0,
            &.{},
        ),
    );
    try std.testing.expectError(
        error.CommonWrapperRegistryParityUnavailable,
        Adapter.validateOutput(
            std.testing.allocator,
            &.{},
            undefined,
            undefined,
            &.{},
        ),
    );
    try std.testing.expectError(
        error.CommonWrapperRegistryParityUnavailable,
        Adapter.coldOpenLease(
            std.testing.allocator,
            undefined,
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
        }) |name| if (!@hasDecl(Adapter, name))
            @compileError("stage103 worker lease surface drifted: " ++ name);
    }
    _ = protocol.StageDescription;
}
