//! Genuine eight-leaf height-3 temporal recursion closure.
//!
//! The proof topology is breadth-wise: four first-parent proofs, two reusable
//! height-2 node proofs, then one height-3 root proof. Every intermediate node
//! is independently verified and re-admitted only through its verifier-minted
//! publication, artifact, proof capture, and retained composition graph.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const integration = @import("stwo_riscv_cpu_integration");

const octet_fixture = @import("recursive_segment_v2_temporal_octet_fixture.zig");
const parent_gate = @import("recursive_temporal_parent_real_proof_test.zig");
const parent_capture = integration.recursive_temporal_verified_parent_capture_v1;

const leaf_outer = integration.recursive_segment_v2_leaf_outer;
const pair_mod = integration.recursive_temporal_parent_pair_authority_v1;
const node_mod = integration.recursive_temporal_verified_node_v1;
const recursion = frontend.recursion;

const FIRST_PARENT_COUNT: usize = octet_fixture.LEAF_COUNT / 2;
const HEIGHT2_NODE_COUNT: usize = FIRST_PARENT_COUNT / 2;

pub fn runGate(allocator: std.mem.Allocator) !void {
    return octet_fixture.runTemporalOctetGateWithHook(allocator, OctetHook);
}

const OctetHook = struct {
    pub fn run(
        allocator: std.mem.Allocator,
        leaves: *const [octet_fixture.LEAF_COUNT]leaf_outer.PreparedNativeV2LeafOuter,
    ) !void {
        var first_parents: [FIRST_PARENT_COUNT]parent_capture.VerifiedParentCaptureV1 =
            undefined;
        for (&first_parents) |*parent|
            parent.* = parent_capture.VerifiedParentCaptureV1.init(allocator);
        defer for (&first_parents) |*parent| parent.deinit();

        for (&first_parents, 0..) |*parent, index| {
            parent_gate.proveTemporalParentWithConsumer(
                allocator,
                &leaves[index * 2],
                &leaves[index * 2 + 1],
                parent,
            ) catch |err| return stageFailure("height1_parent", err);
            try parent.validate();
        }

        var height2_nodes: [HEIGHT2_NODE_COUNT]node_mod.VerifiedTemporalNodeV1 =
            undefined;
        var height2_count: usize = 0;
        defer for (height2_nodes[0..height2_count]) |*node| node.deinit();
        for (0..HEIGHT2_NODE_COUNT) |index| {
            const left = &first_parents[index * 2];
            const right = &first_parents[index * 2 + 1];
            var pair = try preparePair(
                &left.publication.?,
                &left.artifact.?,
                &right.publication.?,
                &right.artifact.?,
            );
            try std.testing.expectEqual(pair_mod.SCHEMA_VERSION, pair.schema_version);
            height2_nodes[index] = node_mod.proveAndVerify(
                allocator,
                &pair,
                .{ try left.childInput(), try right.childInput() },
                .{},
            ) catch |err| return stageFailure("height2_node", err);
            height2_count += 1;
            try height2_nodes[index].validate();
            const statement = try height2_nodes[index].artifact.child.statement();
            try std.testing.expectEqual(@as(u8, 2), statement.slots.height);
        }

        var root_pair = try preparePair(
            &height2_nodes[0].publication,
            &height2_nodes[0].artifact,
            &height2_nodes[1].publication,
            &height2_nodes[1].artifact,
        );
        try std.testing.expectEqual(
            pair_mod.GENERIC_SCHEMA_VERSION,
            root_pair.schema_version,
        );
        var root = node_mod.proveAndVerify(
            allocator,
            &root_pair,
            .{
                height2_nodes[0].childInput(),
                height2_nodes[1].childInput(),
            },
            .{},
        ) catch |err| return stageFailure("height3_root", err);
        defer root.deinit();
        try root.validate();
        const root_statement = try root.artifact.child.statement();
        try std.testing.expectEqual(@as(u8, 3), root_statement.slots.height);
        try std.testing.expectEqual(@as(u64, 8), root_statement.slots.capacity());
        try std.testing.expectEqual(@as(u64, 0), root_statement.slots.first);

        const totals = try proofTotals(&first_parents, &height2_nodes, &root);
        const root_sha256 = std.fmt.bytesToHex(
            root.receipt.canonical_proof_sha256,
            .lower,
        );
        std.debug.print(
            "\nTEMPORAL_HEIGHT3_REAL leaves=8 h1=4 h2=2 h3=1 " ++
                "proof_bytes={d} prove_ms={d:.3} verify_ms={d:.3} " ++
                "root_bytes={d} root_sha256={s} fresh_verify={}\n",
            .{
                totals.bytes,
                milliseconds(totals.prove_ns),
                milliseconds(totals.verify_ns),
                root.receipt.canonical_proof_bytes,
                &root_sha256,
                true,
            },
        );
    }
};

fn preparePair(
    left_publication: anytype,
    left_artifact: anytype,
    right_publication: anytype,
    right_artifact: anytype,
) !pair_mod.PreparedTemporalNodePairV1 {
    var left: pair_mod.PreparedParentChildV1 = undefined;
    try pair_mod.admitInto(&left, left_publication, left_artifact);
    var right: pair_mod.PreparedParentChildV1 = undefined;
    try pair_mod.admitInto(&right, right_publication, right_artifact);
    const root_pin = recursion.temporal_pair_node.RootVkPinV2{
        .expected_aggregator_vk_id = left_artifact.child.recursive_parent_vk_id,
    };
    var result: pair_mod.PreparedTemporalNodePairV1 = undefined;
    try pair_mod.prepareInto(&result, &left, &right, &root_pin);
    return result;
}

const Totals = struct {
    bytes: usize = 0,
    prove_ns: u64 = 0,
    verify_ns: u64 = 0,

    fn add(self: *Totals, receipt: anytype) !void {
        self.bytes = try std.math.add(
            usize,
            self.bytes,
            receipt.canonical_proof_bytes,
        );
        self.prove_ns = try std.math.add(u64, self.prove_ns, receipt.prove_ns);
        self.verify_ns = try std.math.add(u64, self.verify_ns, receipt.verify_ns);
    }
};

fn proofTotals(
    parents: *[FIRST_PARENT_COUNT]parent_capture.VerifiedParentCaptureV1,
    nodes: *[HEIGHT2_NODE_COUNT]node_mod.VerifiedTemporalNodeV1,
    root: *node_mod.VerifiedTemporalNodeV1,
) !Totals {
    var result = Totals{};
    for (parents) |*parent| try result.add(parent.receipt.?);
    for (nodes) |*node| try result.add(node.receipt);
    try result.add(root.receipt);
    return result;
}

fn milliseconds(nanoseconds: u64) f64 {
    return @as(f64, @floatFromInt(nanoseconds)) / std.time.ns_per_ms;
}

fn stageFailure(stage: []const u8, err: anyerror) anyerror {
    std.debug.print(
        "\nTEMPORAL_HEIGHT3_STAGE_FAIL stage={s} error={s}\n",
        .{ stage, @errorName(err) },
    );
    if (@errorReturnTrace()) |trace| std.debug.dumpStackTrace(trace.*);
    return err;
}

test "real eight-leaf temporal tree proves and freshly verifies height three" {
    try runGate(std.testing.allocator);
}
