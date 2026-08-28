//! Real four-leaf temporal aggregation custody gate.
//!
//! Four distinct adjacent SegmentV2 leaves are independently proved and
//! verified.  Two independent temporal-parent STARKs are then proved and
//! verified, each minting the append-only binary-child sidecar.  Finally the
//! canonical height-2 cohort proves and independently verifies their root.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const integration = @import("stwo_riscv_cpu_integration");

const quad_fixture = @import("recursive_segment_v2_temporal_quad_fixture.zig");
const parent_gate = @import("recursive_temporal_parent_real_proof_test.zig");

const leaf_outer = integration.recursive_segment_v2_leaf_outer;
const parent_publication =
    integration.recursive_temporal_parent_cohort_v3.Cohort.VerifiedPublicationV1;
const parent_artifact = integration.recursive_temporal_parent_verified_artifact_v1;
const level2 = integration.recursive_temporal_parent_pair_authority_v1;
const level2_composition = integration.recursive_temporal_level2_composition_v1;
const level2_suffix = integration.recursive_temporal_level2_suffix_v1;
const level2_cohort = integration.recursive_temporal_level2_cohort_v1;
const binary_driver = integration.recursive_binary_outer;
const recursion = frontend.recursion;

pub fn runGate(allocator: std.mem.Allocator) !void {
    return quad_fixture.runTemporalQuadGateWithHook(allocator, QuadHook);
}

const CapturedParent = struct {
    allocator: std.mem.Allocator,
    publication: ?parent_publication = null,
    artifact: ?parent_artifact.VerifiedTemporalParentArtifactV1 = null,
    capture: ?binary_driver.OuterProofCapture = null,
    composition: ?level2_composition.CaptureV1 = null,
    receipt: ?binary_driver.Receipt = null,

    fn init(allocator: std.mem.Allocator) CapturedParent {
        return .{ .allocator = allocator };
    }

    fn deinit(self: *CapturedParent) void {
        if (self.composition) |*capture| capture.deinit();
        if (self.capture) |*capture| capture.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn consume(
        self: *CapturedParent,
        publication: *const parent_publication,
        artifact: *const parent_artifact.VerifiedTemporalParentArtifactV1,
        capture: *binary_driver.OuterProofCapture,
        composition: *level2_composition.CaptureV1,
        receipt: binary_driver.Receipt,
    ) !bool {
        if (self.publication != null or self.artifact != null or
            self.capture != null or self.composition != null or
            self.receipt != null)
        {
            return error.DuplicateParentPublication;
        }
        try publication.validate();
        try artifact.validateAgainst(publication);
        try artifact.recursive_admission.validateAgainst(capture);
        try composition.validateRetained();
        self.publication = publication.*;
        self.artifact = artifact.*;
        self.capture = capture.*;
        self.composition = composition.*;
        self.receipt = receipt;
        return true;
    }
};

const QuadHook = struct {
    pub fn run(
        allocator: std.mem.Allocator,
        leaves: *const [4]leaf_outer.PreparedNativeV2LeafOuter,
    ) !void {
        var left_parent = CapturedParent.init(allocator);
        defer left_parent.deinit();
        try parent_gate.proveTemporalParentWithConsumer(
            allocator,
            &leaves[0],
            &leaves[1],
            &left_parent,
        );
        var right_parent = CapturedParent.init(allocator);
        defer right_parent.deinit();
        try parent_gate.proveTemporalParentWithConsumer(
            allocator,
            &leaves[2],
            &leaves[3],
            &right_parent,
        );

        const left_publication = &left_parent.publication.?;
        const left_artifact = &left_parent.artifact.?;
        const right_publication = &right_parent.publication.?;
        const right_artifact = &right_parent.artifact.?;
        var left_child: level2.PreparedParentChildV1 = undefined;
        level2.admitInto(
            &left_child,
            left_publication,
            left_artifact,
        ) catch |err| return stageFailure("left_parent_admission", err);
        var right_child: level2.PreparedParentChildV1 = undefined;
        level2.admitInto(
            &right_child,
            right_publication,
            right_artifact,
        ) catch |err| return stageFailure("right_parent_admission", err);
        const root_pin = recursion.temporal_pair_node.RootVkPinV2{
            .expected_aggregator_vk_id = left_artifact.child.recursive_parent_vk_id,
        };
        var root: level2.PreparedLevel2PairV1 = undefined;
        level2.prepareInto(
            &root,
            &left_child,
            &right_child,
            &root_pin,
        ) catch |err| return stageFailure("root_pair_prepare", err);
        const authenticated = try root.authenticatePrepared();
        try std.testing.expectEqual(
            level2.FIRST_MULTI_LEVEL_HEIGHT,
            authenticated.pair.parent_height,
        );
        try std.testing.expectEqual(
            @as(u64, 4),
            authenticated.pair.parent_statement.slots.capacity(),
        );
        const child_inputs = [2]level2_suffix.ChildInputV1{
            .{
                .publication = left_publication,
                .artifact = left_artifact,
                .capture = &left_parent.capture.?,
                .composition = &left_parent.composition.?,
            },
            .{
                .publication = right_publication,
                .artifact = right_artifact,
                .capture = &right_parent.capture.?,
                .composition = &right_parent.composition.?,
            },
        };
        const RootKernel = binary_driver.NativeCoreEngineKernelForManifest(
            level2_cohort.Cohort,
            integration.recursive_temporal_parent_manifest_v3,
        );
        const root_receipt = RootKernel.proveAndVerify(
            allocator,
            .{
                .pair = &root,
                .children = child_inputs,
            },
        ) catch |err| return stageFailure("root_prove_verify", err);
        try std.testing.expect(root_receipt.canonical_proof_bytes > 0);
        try std.testing.expect(root_receipt.prove_ns > 0);
        try std.testing.expect(root_receipt.verify_ns > 0);
        try std.testing.expect(!std.mem.allEqual(
            u8,
            &root_receipt.canonical_proof_sha256,
            0,
        ));

        // Sibling order and parent-publication custody are protocol-visible.
        var untouched = root;
        try std.testing.expectError(
            error.ChildOrderMismatch,
            level2.prepareInto(
                &untouched,
                &right_child,
                &left_child,
                &root_pin,
            ),
        );
        var forged_artifact = left_artifact.*;
        forged_artifact.child.proof_id[0] +%= 1;
        try std.testing.expectError(
            error.ArtifactIdentityMismatch,
            level2.admitInto(
                &left_child,
                left_publication,
                &forged_artifact,
            ),
        );

        const total_parent_bytes = try std.math.add(
            usize,
            left_parent.receipt.?.canonical_proof_bytes,
            right_parent.receipt.?.canonical_proof_bytes,
        );
        const root_sha256_hex = std.fmt.bytesToHex(
            root_receipt.canonical_proof_sha256,
            .lower,
        );
        std.debug.print(
            "\nTEMPORAL_MULTILEVEL_REAL leaves=4 verified_parents=2 " ++
                "root_height={d} parent_bytes={d} root_bytes={d} " ++
                "root_prove_ms={d:.3} root_verify_ms={d:.3} " ++
                "root_sha256={s} root_proof={}\n",
            .{
                authenticated.pair.parent_height,
                total_parent_bytes,
                root_receipt.canonical_proof_bytes,
                milliseconds(root_receipt.prove_ns),
                milliseconds(root_receipt.verify_ns),
                &root_sha256_hex,
                true,
            },
        );
    }
};

fn milliseconds(nanoseconds: u64) f64 {
    return @as(f64, @floatFromInt(nanoseconds)) / std.time.ns_per_ms;
}

fn stageFailure(stage: []const u8, err: anyerror) anyerror {
    std.debug.print(
        "\nTEMPORAL_MULTILEVEL_STAGE_FAIL stage={s} error={s}\n",
        .{ stage, @errorName(err) },
    );
    if (@errorReturnTrace()) |trace| std.debug.dumpStackTrace(trace.*);
    return err;
}

test "real four-leaf temporal tree authenticates two verified parents" {
    try runGate(std.testing.allocator);
}
