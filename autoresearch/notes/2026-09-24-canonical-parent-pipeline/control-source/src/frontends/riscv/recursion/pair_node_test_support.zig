const std = @import("std");
const stwo_core = @import("stwo_core");
const pair_node = @import("pair_node.zig");
const protocol = @import("protocol.zig");
const channel = @import("poseidon2_channel.zig");

const m31 = stwo_core.fields.m31;
const Digest = pair_node.Digest;

const GOLDEN_WIRE_SHA256 = hexDigest(
    "548dfc7e9d531f424c2ee2c22f7c50ef9c0c2192b33b8a1c9c60d92f7910916c",
);
const GOLDEN_RECORD_ID = Digest{
    2_039_660_602, 115_237_135,   1_331_741_423, 1_294_625_639,
    1_449_265_885, 1_690_024_629, 188_314_213,   1_988_757_495,
};
const GOLDEN_STATEMENT_ID = Digest{
    1_668_581_139, 1_656_416_802, 50_065_182,  2_125_230_098,
    410_337_995,   170_031_781,   255_905_502, 1_004_825_127,
};
const GOLDEN_PROOF_ID = Digest{
    2_090_435_214, 1_960_971_288, 245_807_019, 1_845_949_681,
    885_842_594,   425_023_899,   425_575_428, 2_080_706_910,
};
const GOLDEN_TRANSCRIPT_ID = Digest{
    2_060_483_450, 924_184_605,   949_267_678, 1_412_135_031,
    323_620_981,   1_611_917_707, 215_859_777, 1_824_587_802,
};
const GOLDEN_SUMMARY_ID = Digest{
    992_521_607,   547_623_542, 743_238_183,   1_184_546_926,
    1_925_167_659, 358_932_843, 1_946_952_417, 716_933_793,
};
const GOLDEN_NODE_ID = Digest{
    1_121_897_635, 1_933_104_947, 1_194_423_304, 1_229_304_646,
    314_473_721,   245_804_358,   601_591_189,   264_131_684,
};

// Shared fixtures and mutation helpers for this conformance suite.

pub const Fixture = struct {
    authority: pair_node.VerifierAuthorityV1,
    record: pair_node.PairNodeRecordV1,
    root_pin: pair_node.RootVkPinV1,

    pub fn init() !Fixture {
        const context = pair_node.VerifierContextV1{
            .session_id = id("session"),
            .job_id = id("job"),
            .execution_statement_id = id("execution-statement"),
            .public_call_commitment = id("ordered-public-calls"),
            .event_count = 2,
            .session_leaf_count = 8,
            .pair_index = 3,
            .aggregator_vk_id = try pair_node.verificationKeyId(
                "canonical-aggregator-vk-wire-v1",
            ),
        };
        const challenge = try context.challengeContextId();
        const context_id = try context.contextId();
        const request = pair_node.SecureFelt{ .limbs = .{ 5, 7, 11, 13 } };
        const supply = request.neg();
        const left = makeChild(
            context,
            challenge,
            context_id,
            .left,
            .core_request,
            "left",
            request,
        );
        const right = makeChild(
            context,
            challenge,
            context_id,
            .right,
            .poseidon2_provider,
            "right",
            supply,
        );
        const authority = pair_node.VerifierAuthorityV1{
            .context = context,
            .children = .{
                verifiedChild(left),
                verifiedChild(right),
            },
        };
        return .{
            .authority = authority,
            .root_pin = .{
                .expected_aggregator_vk_id = context.aggregator_vk_id,
            },
            .record = .{
                .pair_index = context.pair_index,
                .first_leaf_index = context.pair_index * pair_node.CHILD_COUNT,
                .aggregator_vk_id = context.aggregator_vk_id,
                .authority_context_id = context_id,
                .children = .{ left, right },
            },
        };
    }
};

pub fn makeChild(
    context_authority: pair_node.VerifierContextV1,
    challenge: Digest,
    context_id: Digest,
    position: pair_node.ChildPosition,
    role: pair_node.ChildRole,
    label: []const u8,
    total: pair_node.SecureFelt,
) pair_node.ChildEvidenceV1 {
    const position_value: u32 = @intFromEnum(position);
    var statement_label: [32]u8 = .{0} ** 32;
    var proof_label: [32]u8 = .{0} ** 32;
    var transcript_label: [32]u8 = .{0} ** 32;
    var summary_label: [32]u8 = .{0} ** 32;
    @memcpy(statement_label[0..label.len], label);
    @memcpy(statement_label[label.len..][0..10], "-statement");
    @memcpy(proof_label[0..label.len], label);
    @memcpy(proof_label[label.len..][0..6], "-proof");
    @memcpy(transcript_label[0..label.len], label);
    @memcpy(transcript_label[label.len..][0..11], "-transcript");
    @memcpy(summary_label[0..label.len], label);
    @memcpy(summary_label[label.len..][0..8], "-summary");
    return .{
        .position = position,
        .role = role,
        .leaf_index = context_authority.pair_index * pair_node.CHILD_COUNT + position_value,
        .pair_index = context_authority.pair_index,
        .protocol_id = protocol.PROTOCOL_ID_WORDS,
        .session_id = context_authority.session_id,
        .challenge_context_id = challenge,
        .authority_context_id = context_id,
        .parent_vk_id = context_authority.aggregator_vk_id,
        .statement_id = protocol.statementId(&id(std.mem.sliceTo(&statement_label, 0))),
        .proof_id = protocol.proofId(std.mem.sliceTo(&proof_label, 0)),
        .transcript_id = protocol.transcriptId(
            id(std.mem.sliceTo(&transcript_label, 0)),
            position_value + 1,
        ),
        .summary_id = protocol.summaryId(std.mem.sliceTo(&summary_label, 0)),
        .event_count = context_authority.event_count,
        .signed_relation_total = total,
    };
}

pub fn verifiedChild(child: pair_node.ChildEvidenceV1) pair_node.VerifiedChildV1 {
    return .{
        .position = child.position,
        .role = child.role,
        .leaf_index = child.leaf_index,
        .pair_index = child.pair_index,
        .leaf_count = child.leaf_count,
        .protocol_id = child.protocol_id,
        .session_id = child.session_id,
        .challenge_context_id = child.challenge_context_id,
        .authority_context_id = child.authority_context_id,
        .parent_vk_id = child.parent_vk_id,
        .statement_id = child.statement_id,
        .proof_id = child.proof_id,
        .transcript_id = child.transcript_id,
        .summary_id = child.summary_id,
        .event_count = child.event_count,
        .signed_relation_total = child.signed_relation_total,
    };
}

pub fn id(label: []const u8) Digest {
    return channel.hashBytes(label, 0x504e_5445); // "PNTE"
}

pub fn hexDigest(comptime value: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch
        @compileError("invalid pair-node golden SHA-256");
    return result;
}
