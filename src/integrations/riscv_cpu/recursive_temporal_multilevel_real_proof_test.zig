//! Real four-leaf temporal aggregation custody gate.
//!
//! Four distinct adjacent SegmentV2 leaves are independently proved and
//! verified.  Two independent temporal-parent STARKs are then proved and
//! verified, each minting the append-only binary-child sidecar.  Finally the
//! canonical temporal authority authenticates those two verified parents as
//! one height-2 span.  The final value is intentionally an aggregation
//! receipt; `ROOT_PROOF_AVAILABLE` remains false until the binary-parent
//! transcript source itself accepts binary children.

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
const binary_driver = integration.recursive_binary_outer;
const recursion = frontend.recursion;

pub fn runGate(allocator: std.mem.Allocator) !void {
    return quad_fixture.runTemporalQuadGateWithHook(allocator, QuadHook);
}

const CapturedParent = struct {
    publication: ?parent_publication = null,
    artifact: ?parent_artifact.VerifiedTemporalParentArtifactV1 = null,
    receipt: ?binary_driver.Receipt = null,

    pub fn consume(
        self: *CapturedParent,
        publication: *const parent_publication,
        artifact: *const parent_artifact.VerifiedTemporalParentArtifactV1,
        receipt: binary_driver.Receipt,
    ) !void {
        if (self.publication != null or self.artifact != null or
            self.receipt != null)
        {
            return error.DuplicateParentPublication;
        }
        try publication.validate();
        try artifact.validateAgainst(publication);
        self.publication = publication.*;
        self.artifact = artifact.*;
        self.receipt = receipt;
    }
};

const QuadHook = struct {
    pub fn run(
        allocator: std.mem.Allocator,
        leaves: *const [4]leaf_outer.PreparedNativeV2LeafOuter,
    ) !void {
        var left_parent: CapturedParent = .{};
        try parent_gate.proveTemporalParentWithConsumer(
            allocator,
            &leaves[0],
            &leaves[1],
            &left_parent,
        );
        var right_parent: CapturedParent = .{};
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
        try level2.admitInto(
            &left_child,
            left_publication,
            left_artifact,
        );
        var right_child: level2.PreparedParentChildV1 = undefined;
        try level2.admitInto(
            &right_child,
            right_publication,
            right_artifact,
        );
        const root_pin = recursion.temporal_pair_node.RootVkPinV2{
            .expected_aggregator_vk_id = left_artifact.child.recursive_parent_vk_id,
        };
        var root: level2.PreparedLevel2PairV1 = undefined;
        try level2.prepareInto(
            &root,
            &left_child,
            &right_child,
            &root_pin,
        );
        const authenticated = try root.authenticatePrepared();
        try std.testing.expectEqual(
            level2.FIRST_MULTI_LEVEL_HEIGHT,
            authenticated.pair.parent_height,
        );
        try std.testing.expectEqual(
            @as(u64, 4),
            authenticated.pair.parent_statement.slots.capacity(),
        );
        try std.testing.expect(!root.root_proof_available);
        try std.testing.expect(!root.production_activation);

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
        std.debug.print(
            "\nTEMPORAL_MULTILEVEL_REAL leaves=4 verified_parents=2 " ++
                "root_height={d} parent_bytes={d} root_proof={}\n",
            .{
                authenticated.pair.parent_height,
                total_parent_bytes,
                root.root_proof_available,
            },
        );
    }
};

test "real four-leaf temporal tree authenticates two verified parents" {
    try runGate(std.testing.allocator);
}
