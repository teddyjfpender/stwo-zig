//! Exact typed transcript replay for two verified temporal-parent children.
//!
//! A height-2 root cannot begin from the retained pre-core checkpoint.  It
//! replays each parent from the zero Poseidon state, including the manifest,
//! cohort authority, 94 relation challenges, 36 claims, public wire boundary,
//! and the complete PCS/FRI continuation.  The resulting rows reuse the same
//! typed rows-0--9 authority as the first temporal parent.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const driver = @import("recursive_binary_outer.zig");
const artifact_mod = @import("recursive_temporal_parent_verified_artifact_v1.zig");
const publication_mod = @import("recursive_temporal_parent_publication_v3.zig");
const manifest_mod = @import("recursive_temporal_parent_manifest_v3.zig");
const cohort_mod = @import("recursive_temporal_parent_cohort_v3.zig");
const nonfri = @import("recursive_temporal_nonfri_source_v2.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const admission = recursion.outer_parent_child_admission;
const transcript_air = recursion.air.transcript_air_witness;
const channel = recursion.poseidon2_channel;

pub const TRANSCRIPT_PREFIX_ID_DOMAIN: u32 = 0x4c32_5431; // "L2T1"

pub const ChildV1 = struct {
    publication: *const publication_mod.VerifiedPublicationV1,
    artifact: *const artifact_mod.VerifiedTemporalParentArtifactV1,
    capture: *const driver.OuterProofCapture,

    pub fn validate(self: ChildV1) !void {
        try self.artifact.validateAgainst(self.publication);
        try self.artifact.recursive_admission.validateAgainst(self.capture);
        try self.artifact.transcript_prefix.validate();
        if (!std.meta.eql(
            self.publication.capture_id,
            self.artifact.recursive_admission.seal.capture_id,
        )) return error.ChildTranscriptMismatch;
    }
};

pub fn prepare(
    allocator: std.mem.Allocator,
    pair_authority_id: nonfri.Digest,
    children: [2]ChildV1,
) !nonfri.PreparedTranscriptRowsV2 {
    try children[0].validate();
    try children[1].validate();
    var recorder = nonfri.TranscriptRowRecorderV2.init(
        allocator,
        transcript_air.LEFT_RECURSION_VERIFIER_ID,
    );
    defer recorder.deinit();

    var lane_row_counts: [2]usize = undefined;
    var lane_operation_counts: [2]usize = undefined;
    var lane_frame_counts: [2]usize = undefined;
    var lane_word_counts: [2]usize = undefined;
    var lane_payload_counts: [2]usize = undefined;
    var replays: [2]nonfri.TemporalChildTranscriptReplayV2 = undefined;
    inline for (0..2) |lane| {
        if (lane != 0) try recorder.beginLane(
            transcript_air.RIGHT_RECURSION_VERIFIER_ID,
        );
        const first_row = recorder.rows.items.len;
        const first_frame = recorder.frames.items.len;
        replays[lane] = try replayParent(&recorder, children[lane]);
        try recorder.checkHealthy();
        lane_row_counts[lane] = recorder.rows.items.len - first_row;
        lane_operation_counts[lane] = recorder.operation_id;
        lane_frame_counts[lane] = recorder.hash_id;
        lane_word_counts[lane] = try nonfri.transcriptWordCount(
            recorder.frames.items[first_frame..],
        );
        lane_payload_counts[lane] = try nonfri.transcriptPayloadCount(
            recorder.frames.items[first_frame..],
        );
        if (lane_row_counts[lane] == 0 or lane_operation_counts[lane] == 0 or
            lane_frame_counts[lane] == 0 or lane_word_counts[lane] == 0 or
            lane_payload_counts[lane] == 0)
        {
            return error.InvalidTranscriptRecorder;
        }
    }

    const rows = try recorder.takeRows();
    errdefer allocator.free(rows);
    const operations = try recorder.takeOperations();
    errdefer allocator.free(operations);
    const frames = try recorder.takeFrames();
    errdefer allocator.free(frames);
    var result = nonfri.PreparedTranscriptRowsV2{
        .allocator = allocator,
        .log_size = try nonfri.transcriptTraceLogSize(rows.len),
        .pair_authority_id = pair_authority_id,
        .lane_row_counts = lane_row_counts,
        .lane_operation_counts = lane_operation_counts,
        .lane_frame_counts = lane_frame_counts,
        .lane_word_counts = lane_word_counts,
        .lane_payload_counts = lane_payload_counts,
        .lane_claim_counts = [_]u32{
            @intCast(manifest_mod.COMPONENT_COUNT),
        } ** 2,
        .child_replays = replays,
        .rows = rows,
        .operations = operations,
        .frames = frames,
        .authority_sha_id = undefined,
    };
    try nonfri.validateTranscriptRowsV2(&result);
    result.authority_sha_id = nonfri.transcriptRowsAuthoritySha(&result);
    try result.validate();
    return result;
}

fn replayParent(
    transcript: anytype,
    child: ChildV1,
) !nonfri.TemporalChildTranscriptReplayV2 {
    try child.validate();
    const publication = child.publication;
    const artifact = child.artifact;
    const capture = child.capture;
    const prefix = &artifact.transcript_prefix;
    const receipt = &artifact.recursive_admission.receipt;
    try validateCapture(capture);

    nonfri.mixMerkleRoot(
        transcript,
        capture.commitments[manifest_mod.PREPROCESSED_TREE_INDEX],
    );
    nonfri.mixMerkleRoot(
        transcript,
        capture.commitments[manifest_mod.MAIN_TREE_INDEX],
    );
    try prefix.mixManifestPrefix(transcript);
    transcript.mixU32s(&.{
        cohort_mod.AUTHORITY_TRANSCRIPT_DOMAIN,
        cohort_mod.FORMAT_VERSION,
        cohort_mod.SCHEMA_VERSION,
        manifest_mod.COMPONENT_COUNT,
    });
    transcript.mixU32s(&nonfri.shaWords(publication.cohort_authority_sha_id));
    transcript.mixU32s(&publication.pair_authority_id);
    transcript.mixU32s(&nonfri.shaWords(publication.context.identity));
    try nonfri.replayRelationDraws(transcript, &prefix.relation_draws);

    transcript.mixU32s(&.{manifest_mod.COMPONENT_COUNT});
    for (
        receipt.claimed_sums,
        receipt.component_log_sizes,
        prefix.interaction_columns,
        0..,
    ) |claim, log_size, interaction_columns, row| {
        transcript.mixU32s(&.{
            @intCast(row),
            log_size,
            interaction_columns,
        });
        transcript.mixFelts(&.{qm31FromWire(claim)});
    }
    transcript.mixU32s(&nonfri.shaWords(publication.claims_sha_id));
    try prefix.mixWireBoundary(transcript);
    nonfri.mixMerkleRoot(
        transcript,
        capture.commitments[manifest_mod.INTERACTION_TREE_INDEX],
    );

    const pre_core_digest = transcript.digestWords();
    const pre_core_draw_count = transcript.n_draws;
    if (!std.meta.eql(pre_core_digest, receipt.pre_core_channel.digest) or
        pre_core_draw_count != receipt.pre_core_channel.draw_count)
    {
        return error.ChildTranscriptMismatch;
    }
    nonfri.annotateNextDraw(transcript, .composition_draw, .{ 0, 0, 0, 0 });
    const composition_randomness = transcript.drawSecureFelt();
    if (!composition_randomness.eql(capture.composition_randomness))
        return error.ChildTranscriptMismatch;
    nonfri.mixMerkleRoot(transcript, capture.commitments[3]);
    nonfri.annotateNextDraw(transcript, .oods_draw, .{ 0, 0, 0, 0 });
    const oods_seed = transcript.drawSecureFelt();
    if (!oods_seed.eql(capture.oods_seed)) return error.ChildTranscriptMismatch;
    transcript.mixFelts(capture.sampled_values);
    nonfri.annotateNextDraw(transcript, .deep_draw, .{ 0, 0, 0, 0 });
    const deep_randomness = transcript.drawSecureFelt();
    if (!deep_randomness.eql(capture.deep_randomness))
        return error.ChildTranscriptMismatch;

    var fri_alphas = [_]QM31{QM31.zero()} ** nonfri.MAX_CHILD_FRI_ROUNDS;
    for (capture.fri.layers, 0..) |layer, index| {
        nonfri.mixMerkleRoot(transcript, layer.commitment);
        nonfri.annotateNextDraw(
            transcript,
            .fri_alpha_draw,
            .{ @intCast(index), 0, 0, 0 },
        );
        fri_alphas[index] = transcript.drawSecureFelt();
        if (!fri_alphas[index].eql(layer.folding_alpha))
            return error.ChildTranscriptMismatch;
    }
    transcript.mixFelts(capture.last_layer_coefficients);
    if (!transcript.verifyPowNonce(admission.PCS_POW_BITS, capture.proof_of_work))
        return error.ChildTranscriptMismatch;
    transcript.mixU64(capture.proof_of_work);

    const query_log = try nonfri.queryLogFromCapture(capture);
    nonfri.annotateNextDraw(transcript, .query_draw, .{
        0, nonfri.CHILD_QUERY_COUNT, query_log, 0,
    });
    const query_words = transcript.drawU32s();
    const query_mask = (@as(u32, 1) << @intCast(query_log)) - 1;
    var raw_queries: [nonfri.CHILD_QUERY_COUNT]u32 = undefined;
    for (&raw_queries, capture.queries.raw, query_words[0..nonfri.CHILD_QUERY_COUNT]) |
        *destination,
        captured,
        word,
    | {
        destination.* = word & query_mask;
        if (captured != destination.*) return error.ChildTranscriptMismatch;
    }
    const final_digest = transcript.digestWords();
    const final_draw_count = transcript.n_draws;
    if (!std.meta.eql(
        publication.transcript_id,
        recursion.protocol.transcriptId(final_digest, final_draw_count),
    )) return error.ChildTranscriptMismatch;

    var result = nonfri.TemporalChildTranscriptReplayV2{
        .fri_round_count = @intCast(capture.fri.layers.len),
        .publication_id = artifact.publication_id,
        .witness_id = artifact.artifact_id,
        .capture_id = publication.capture_id,
        .transcript_prefix_id = channel.hashBytes(
            &prefix.identity,
            TRANSCRIPT_PREFIX_ID_DOMAIN,
        ),
        .manifest_sha_id = publication.manifest_sha_id,
        .pre_core_digest = pre_core_digest,
        .pre_core_draw_count = pre_core_draw_count,
        .composition_randomness = composition_randomness,
        .oods_seed = oods_seed,
        .deep_randomness = deep_randomness,
        .fri_alphas = fri_alphas,
        .raw_queries = raw_queries,
        .final_digest = final_digest,
        .final_draw_count = final_draw_count,
        .replay_id = undefined,
    };
    result.replay_id = nonfri.transcriptReplayIdentity(&result);
    try result.validate();
    return result;
}

fn validateCapture(capture: *const driver.OuterProofCapture) !void {
    if (capture.commitments.len != 4 or
        capture.column_log_sizes.len != 4 or
        capture.sampled_points.len != 4 or
        capture.trace_paths.len != 4 or
        capture.queries.raw.len != nonfri.CHILD_QUERY_COUNT or
        capture.deep_answers.len != nonfri.CHILD_QUERY_COUNT or
        capture.fri.layers.len == 0 or
        capture.fri.layers.len > nonfri.MAX_CHILD_FRI_ROUNDS or
        capture.sampled_values.len == 0 or
        capture.last_layer_coefficients.len == 0)
    {
        std.debug.print(
            "\nTEMPORAL_LEVEL2_CAPTURE_SHAPE commitments={d} logs={d} " ++
                "points={d} paths={d} queries={d} answers={d} fri={d} " ++
                "samples={d} coefficients={d}\n",
            .{
                capture.commitments.len,
                capture.column_log_sizes.len,
                capture.sampled_points.len,
                capture.trace_paths.len,
                capture.queries.raw.len,
                capture.deep_answers.len,
                capture.fri.layers.len,
                capture.sampled_values.len,
                capture.last_layer_coefficients.len,
            },
        );
        return error.CaptureShapeMismatch;
    }
    _ = try nonfri.queryLogFromCapture(capture);
}

fn qm31FromWire(value: recursion.fixed_wire.Qm31Wire) QM31 {
    return QM31.fromU32Unchecked(value[0], value[1], value[2], value[3]);
}
