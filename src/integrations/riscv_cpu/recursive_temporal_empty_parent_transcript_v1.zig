//! Authenticated transcript source for an empty/empty height-one parent.
//!
//! A proofless height-zero empty owns no child STARK transcript.  The parent
//! nevertheless needs verifier-owned challenges for the statement-specific
//! canonical-empty composition program.  This module defines that append-only
//! transcript: each lane starts from zero, absorbs the exact pair, leaf,
//! program, layout, registry and statement authorities, then draws the 47
//! relation pairs, composition randomness and OODS seed.  No FRI/deep/query
//! draw exists, and no proof bytes or Merkle paths are fabricated.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const leaf_mod = @import("recursive_temporal_leaf_or_empty_v1.zig");
const nonfri = @import("recursive_temporal_nonfri_source_v2.zig");
const temporal_manifest = @import("recursive_temporal_parent_manifest_v3.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const channel = recursion.poseidon2_channel;
const composition_v3 = recursion.recursion_air_composition_circuit_v3;
const packed_challenge = recursion.air.temporal_packed_relation_challenge_v2;
const universal = recursion.air.universal_challenges;
const rows_source = recursion.binary_fri_outer_source;
const span = recursion.span_statement;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 2;
pub const CHILD_COUNT: usize = 2;
pub const RELATION_DRAW_COUNT: usize = universal.DRAW_COUNT;
pub const PACKED_RELATION_DRAW_COUNT: usize =
    RELATION_DRAW_COUNT / packed_challenge.CHALLENGES_PER_DRAW;
pub const TRANSCRIPT_DOMAIN: u32 = 0x4550_5431; // "EPT1"
pub const TRANSCRIPT_HEADER_WORDS: u32 = 5;
pub const PAIR_AUTHORITY_ID_DOMAIN: u32 = 0x4550_5031; // "EPP1"
pub const LEAF_WITNESS_ID_DOMAIN: u32 = 0x4550_5731; // "EPW1"
pub const LANE_PREFIX_ID_DOMAIN: u32 = 0x4550_4c31; // "EPL1"
pub const PROOF_BYTES_ACCEPTED = false;
pub const FRI_DRAWS_EMITTED = false;
pub const QUERY_DRAWS_EMITTED = false;

const AUTHORITY_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-empty-parent-transcript/v1\x00";
const RECORDING_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-empty-parent-rows/v1\x00";

pub const ProgramBindingV1 = struct {
    program_identity: [32]u8,
    air_program_id: channel.Digest,
    manifest_sha_id: [32]u8,
    binary_layout_sha_id: [32]u8,
    empty_layout_sha_id: [32]u8,
    parameter_authority_sha_id: [32]u8,
    statement_id: channel.Digest,
    publication_id: channel.Digest,

    pub fn fromValidatedProgram(
        program: composition_v3.CanonicalEmptyProgramV3,
    ) !ProgramBindingV1 {
        const result = ProgramBindingV1{
            .program_identity = program.identity,
            .air_program_id = program.air_program_id,
            .manifest_sha_id = program.manifest_seal,
            .binary_layout_sha_id = program.binary_layout_identity,
            .empty_layout_sha_id = program.empty_layout_identity,
            .parameter_authority_sha_id = program.parameter_authority_identity,
            .statement_id = program.statement_id,
            .publication_id = program.publication_id,
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: ProgramBindingV1) !void {
        inline for (.{
            self.program_identity,
            self.manifest_sha_id,
            self.binary_layout_sha_id,
            self.empty_layout_sha_id,
            self.parameter_authority_sha_id,
        }) |value| if (std.mem.allEqual(u8, &value, 0))
            return error.InvalidEmptyTranscriptAuthority;
        try requireDigest(self.air_program_id);
        try requireDigest(self.statement_id);
        try requireDigest(self.publication_id);
    }
};

pub const LaneAuthorityV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    verifier_id: u32,
    pair_authority_sha_id: [32]u8,
    leaf_authority_sha_id: [32]u8,
    child_id: channel.Digest,
    program: ProgramBindingV1,
    registry_order_sha_id: [32]u8,
    relation_draws: [RELATION_DRAW_COUNT]QM31,
    pre_core_digest: channel.Digest,
    pre_core_draw_count: u32,
    composition_randomness: QM31,
    oods_seed: QM31,
    final_digest: channel.Digest,
    final_draw_count: u32,
    identity: [32]u8,

    pub fn validateAgainst(
        self: *const LaneAuthorityV1,
        pair: *const leaf_mod.PreparedLeafPairV1,
        leaf: *const leaf_mod.LeafOrEmptyV1,
        program: ProgramBindingV1,
        verifier_id: u32,
    ) !void {
        try pair.validate();
        try leaf.validate();
        try program.validate();
        if (leaf.kind() != .empty or
            self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.verifier_id != verifier_id or
            !std.mem.eql(
                u8,
                &self.pair_authority_sha_id,
                &pair.authority_sha_id,
            ) or !std.mem.eql(
            u8,
            &self.leaf_authority_sha_id,
            &leaf.authority_sha_id,
        ) or !std.meta.eql(self.child_id, try leaf.child().id()) or
            !std.meta.eql(self.program, program) or
            !std.mem.eql(
                u8,
                &self.registry_order_sha_id,
                &universal.registryOrderDigest(),
            ))
        {
            return error.InvalidEmptyTranscriptAuthority;
        }
        var native = channel.Channel{};
        const expected = try deriveLane(
            &native,
            pair,
            leaf,
            program,
            verifier_id,
        );
        if (!laneEqual(self, &expected) or
            !std.mem.eql(u8, &self.identity, &laneIdentity(self)))
        {
            return error.InvalidEmptyTranscriptAuthority;
        }
    }

    pub fn relations(self: *const LaneAuthorityV1) universal.UniversalRelations {
        return universal.UniversalRelations.fromDraws(&self.relation_draws);
    }
};

/// Retained row-1/row-34 source.  The recorder rows are generated by the same
/// generic protocol routine used for the native replay above; callers cannot
/// supply detached challenges, provider calls, or final channel state.
pub const PreparedTranscriptV1 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    padding: [4]u8 = .{ 0, 0, 0, 0 },
    pair_authority_sha_id: [32]u8,
    child_authority_sha_ids: [CHILD_COUNT][32]u8,
    lanes: [CHILD_COUNT]LaneAuthorityV1,
    transcript_rows: nonfri.PreparedTranscriptRowsV2,
    authority_sha_id: [32]u8,

    pub fn init(
        allocator: std.mem.Allocator,
        pair: *const leaf_mod.PreparedLeafPairV1,
        children: [CHILD_COUNT]*const leaf_mod.LeafOrEmptyV1,
        programs: [CHILD_COUNT]ProgramBindingV1,
    ) !PreparedTranscriptV1 {
        try validateInputs(pair, children, programs);
        var recorder = nonfri.TranscriptRowRecorderV2.init(
            allocator,
            rows_source.LEFT_RECURSION_VERIFIER_ID,
        );
        defer recorder.deinit();

        var lanes: [CHILD_COUNT]LaneAuthorityV1 = undefined;
        var lane_row_counts: [CHILD_COUNT]usize = undefined;
        var lane_operation_counts: [CHILD_COUNT]usize = undefined;
        var lane_frame_counts: [CHILD_COUNT]usize = undefined;
        var lane_word_counts: [CHILD_COUNT]usize = undefined;
        var lane_payload_counts: [CHILD_COUNT]usize = undefined;
        inline for (0..CHILD_COUNT) |lane| {
            const verifier_id = verifierId(lane);
            if (lane != 0) try recorder.beginLane(verifier_id);
            const first_row = recorder.rows.items.len;
            const first_frame = recorder.frames.items.len;
            lanes[lane] = try deriveLane(
                &recorder,
                pair,
                children[lane],
                programs[lane],
                verifier_id,
            );
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
                return error.InvalidEmptyTranscriptAuthority;
            }
        }
        const rows = try recorder.takeRows();
        errdefer allocator.free(rows);
        const operations = try recorder.takeOperations();
        errdefer allocator.free(operations);
        const frames = try recorder.takeFrames();
        errdefer allocator.free(frames);
        var child_replays: [CHILD_COUNT]nonfri.TemporalChildTranscriptReplayV2 =
            undefined;
        inline for (0..CHILD_COUNT) |lane| child_replays[lane] =
            try prooflessReplay(&lanes[lane], children[lane], programs[lane]);
        var transcript_rows = nonfri.PreparedTranscriptRowsV2{
            .allocator = allocator,
            .schema_version = nonfri.PROOFLESS_EMPTY_TRANSCRIPT_ROWS_SCHEMA_VERSION,
            .log_size = try nonfri.transcriptTraceLogSize(rows.len),
            .pair_authority_id = pairAuthorityId(pair),
            .lane_row_counts = lane_row_counts,
            .lane_operation_counts = lane_operation_counts,
            .lane_frame_counts = lane_frame_counts,
            .lane_word_counts = lane_word_counts,
            .lane_payload_counts = lane_payload_counts,
            .lane_claim_counts = [_]u32{
                @intCast(temporal_manifest.COMPONENT_COUNT),
            } ** CHILD_COUNT,
            .child_replays = child_replays,
            .rows = rows,
            .operations = operations,
            .frames = frames,
            .authority_sha_id = undefined,
        };
        try nonfri.validateTranscriptRowsV2(&transcript_rows);
        transcript_rows.authority_sha_id =
            nonfri.transcriptRowsAuthoritySha(&transcript_rows);
        try transcript_rows.validate();
        var result = PreparedTranscriptV1{
            .allocator = allocator,
            .pair_authority_sha_id = pair.authority_sha_id,
            .child_authority_sha_ids = .{
                children[0].authority_sha_id,
                children[1].authority_sha_id,
            },
            .lanes = lanes,
            .transcript_rows = transcript_rows,
            .authority_sha_id = undefined,
        };
        result.authority_sha_id = recordingIdentity(&result);
        try result.validateAgainst(pair, children, programs);
        return result;
    }

    pub fn deinit(self: *PreparedTranscriptV1) void {
        self.transcript_rows.deinit();
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const PreparedTranscriptV1,
        pair: *const leaf_mod.PreparedLeafPairV1,
        children: [CHILD_COUNT]*const leaf_mod.LeafOrEmptyV1,
        programs: [CHILD_COUNT]ProgramBindingV1,
    ) !void {
        try validateInputs(pair, children, programs);
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.mem.allEqual(u8, &self.padding, 0) or
            !std.mem.eql(
                u8,
                &self.pair_authority_sha_id,
                &pair.authority_sha_id,
            ) or !std.meta.eql(
            self.transcript_rows.pair_authority_id,
            pairAuthorityId(pair),
        ) or self.transcript_rows.schema_version !=
            nonfri.PROOFLESS_EMPTY_TRANSCRIPT_ROWS_SCHEMA_VERSION)
        {
            return error.InvalidEmptyTranscriptAuthority;
        }
        try self.transcript_rows.validate();
        inline for (0..CHILD_COUNT) |lane| {
            if (!std.mem.eql(
                u8,
                &self.child_authority_sha_ids[lane],
                &children[lane].authority_sha_id,
            )) return error.InvalidEmptyTranscriptAuthority;
            try self.lanes[lane].validateAgainst(
                pair,
                children[lane],
                programs[lane],
                verifierId(lane),
            );
            const expected_replay = try prooflessReplay(
                &self.lanes[lane],
                children[lane],
                programs[lane],
            );
            if (!std.meta.eql(
                self.transcript_rows.child_replays[lane],
                expected_replay,
            )) {
                return error.InvalidEmptyTranscriptAuthority;
            }
        }
        if (!std.mem.eql(
            u8,
            &self.authority_sha_id,
            &recordingIdentity(self),
        )) return error.InvalidEmptyTranscriptAuthority;
    }

    pub fn transcriptRows(
        self: *const PreparedTranscriptV1,
    ) *const nonfri.PreparedTranscriptRowsV2 {
        return &self.transcript_rows;
    }
};

fn validateInputs(
    pair: *const leaf_mod.PreparedLeafPairV1,
    children: [CHILD_COUNT]*const leaf_mod.LeafOrEmptyV1,
    programs: [CHILD_COUNT]ProgramBindingV1,
) !void {
    try pair.validateAgainst(children[0], children[1]);
    inline for (0..CHILD_COUNT) |lane| {
        try programs[lane].validate();
        const child = children[lane];
        if (child.kind() != .empty or
            !std.meta.eql(programs[lane].statement_id, try child.child().statementId()) or
            !std.meta.eql(programs[lane].publication_id, try child.child().id()))
        {
            return error.InvalidEmptyTranscriptAuthority;
        }
        const words = try child.statement();
        const canonical = try words.canonicalWords();
        _ = canonical;
    }
}

fn deriveLane(
    transcript: anytype,
    pair: *const leaf_mod.PreparedLeafPairV1,
    leaf: *const leaf_mod.LeafOrEmptyV1,
    program: ProgramBindingV1,
    verifier_id: u32,
) !LaneAuthorityV1 {
    try leaf.validate();
    try program.validate();
    const child = leaf.child();
    transcript.mixU32s(&.{
        TRANSCRIPT_DOMAIN,
        FORMAT_VERSION,
        SCHEMA_VERSION,
        verifier_id,
        TRANSCRIPT_HEADER_WORDS,
    });
    transcript.mixU32s(&shaWords(pair.authority_sha_id));
    transcript.mixU32s(&shaWords(leaf.authority_sha_id));
    const child_id = child.id() catch
        return error.InvalidEmptyTranscriptAuthority;
    transcript.mixU32s(&child_id);
    transcript.mixU32s(&shaWords(program.program_identity));
    transcript.mixU32s(&program.air_program_id);
    transcript.mixU32s(&shaWords(program.manifest_sha_id));
    transcript.mixU32s(&shaWords(program.binary_layout_sha_id));
    transcript.mixU32s(&shaWords(program.empty_layout_sha_id));
    transcript.mixU32s(&shaWords(program.parameter_authority_sha_id));
    transcript.mixU32s(&program.statement_id);
    transcript.mixU32s(&program.publication_id);
    transcript.mixU32s(&shaWords(universal.registryOrderDigest()));
    var statement_words: [span.SPAN_STATEMENT_CANONICAL_WORDS]u32 = undefined;
    for (&statement_words, child.statement_words) |*destination, word|
        destination.* = word.toU32();
    transcript.mixU32s(&statement_words);

    var relation_draws: [RELATION_DRAW_COUNT]QM31 = undefined;
    for (0..PACKED_RELATION_DRAW_COUNT) |packed_index| {
        nonfri.annotateNextDraw(transcript, .relation_draw, .{
            @intCast(2 * packed_index),
            packed_challenge.CHALLENGES_PER_DRAW,
            packed_challenge.PACKING_FORMAT_VERSION,
            0,
        });
        const words = transcript.drawU32s();
        relation_draws[2 * packed_index] = QM31.fromU32Unchecked(
            words[0],
            words[1],
            words[2],
            words[3],
        );
        relation_draws[2 * packed_index + 1] = QM31.fromU32Unchecked(
            words[4],
            words[5],
            words[6],
            words[7],
        );
    }
    const pre_core_digest = transcript.digestWords();
    const pre_core_draw_count = transcript.n_draws;
    nonfri.annotateNextDraw(transcript, .composition_draw, .{ 0, 0, 0, 0 });
    const composition_randomness = transcript.drawSecureFelt();
    nonfri.annotateNextDraw(transcript, .oods_draw, .{ 0, 0, 0, 0 });
    const oods_seed = transcript.drawSecureFelt();
    var result = LaneAuthorityV1{
        .verifier_id = verifier_id,
        .pair_authority_sha_id = pair.authority_sha_id,
        .leaf_authority_sha_id = leaf.authority_sha_id,
        .child_id = try child.id(),
        .program = program,
        .registry_order_sha_id = universal.registryOrderDigest(),
        .relation_draws = relation_draws,
        .pre_core_digest = pre_core_digest,
        .pre_core_draw_count = pre_core_draw_count,
        .composition_randomness = composition_randomness,
        .oods_seed = oods_seed,
        .final_digest = transcript.digestWords(),
        .final_draw_count = transcript.n_draws,
        .identity = undefined,
    };
    result.identity = laneIdentity(&result);
    return result;
}

fn prooflessReplay(
    lane: *const LaneAuthorityV1,
    leaf: *const leaf_mod.LeafOrEmptyV1,
    program: ProgramBindingV1,
) !nonfri.TemporalChildTranscriptReplayV2 {
    try leaf.validate();
    try program.validate();
    if (leaf.kind() != .empty or
        !std.meta.eql(lane.child_id, try leaf.child().id()) or
        !std.meta.eql(lane.program, program))
    {
        return error.InvalidEmptyTranscriptAuthority;
    }
    var result = nonfri.TemporalChildTranscriptReplayV2{
        .schema_version = nonfri.PROOFLESS_EMPTY_CHILD_REPLAY_SCHEMA_VERSION,
        .fri_round_count = 0,
        .query_count = 0,
        .publication_id = lane.child_id,
        // Schema 2 assigns the legacy witness/capture slots to the admitted
        // proofless-leaf authority and its typed AIR program respectively.
        // No proof capture or proof bytes are synthesized.
        .witness_id = channel.hashBytes(
            &leaf.authority_sha_id,
            LEAF_WITNESS_ID_DOMAIN,
        ),
        .capture_id = program.air_program_id,
        .transcript_prefix_id = channel.hashBytes(
            &lane.identity,
            LANE_PREFIX_ID_DOMAIN,
        ),
        .manifest_sha_id = program.manifest_sha_id,
        .pre_core_digest = lane.pre_core_digest,
        .pre_core_draw_count = lane.pre_core_draw_count,
        .composition_randomness = lane.composition_randomness,
        .oods_seed = lane.oods_seed,
        .deep_randomness = QM31.zero(),
        .fri_alphas = [_]QM31{QM31.zero()} ** nonfri.MAX_CHILD_FRI_ROUNDS,
        .raw_queries = [_]u32{0} ** nonfri.CHILD_QUERY_COUNT,
        .final_digest = lane.final_digest,
        .final_draw_count = lane.final_draw_count,
        .replay_id = undefined,
    };
    result.replay_id = nonfri.transcriptReplayIdentity(&result);
    try result.validate();
    return result;
}

pub fn pairAuthorityId(pair: *const leaf_mod.PreparedLeafPairV1) channel.Digest {
    return channel.hashBytes(&pair.authority_sha_id, PAIR_AUTHORITY_ID_DOMAIN);
}

fn verifierId(lane: usize) u32 {
    return if (lane == 0)
        rows_source.LEFT_RECURSION_VERIFIER_ID
    else
        rows_source.RIGHT_RECURSION_VERIFIER_ID;
}

fn laneEqual(left: *const LaneAuthorityV1, right: *const LaneAuthorityV1) bool {
    return std.meta.eql(left.*, right.*);
}

fn laneIdentity(value: *const LaneAuthorityV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(AUTHORITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u32, value.verifier_id);
    hash.update(&value.pair_authority_sha_id);
    hash.update(&value.leaf_authority_sha_id);
    hashDigest(&hash, value.child_id);
    hashProgram(&hash, value.program);
    hash.update(&value.registry_order_sha_id);
    for (value.relation_draws) |draw| hashQm31(&hash, draw);
    hashDigest(&hash, value.pre_core_digest);
    hashInt(&hash, u32, value.pre_core_draw_count);
    hashQm31(&hash, value.composition_randomness);
    hashQm31(&hash, value.oods_seed);
    hashDigest(&hash, value.final_digest);
    hashInt(&hash, u32, value.final_draw_count);
    return hash.finalResult();
}

fn recordingIdentity(value: *const PreparedTranscriptV1) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(RECORDING_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.pair_authority_sha_id);
    for (value.child_authority_sha_ids) |identity| hash.update(&identity);
    for (value.lanes) |lane| hash.update(&lane.identity);
    hash.update(&value.transcript_rows.authority_sha_id);
    return hash.finalResult();
}

fn hashProgram(hash: *Sha256, value: ProgramBindingV1) void {
    hash.update(&value.program_identity);
    hashDigest(hash, value.air_program_id);
    hash.update(&value.manifest_sha_id);
    hash.update(&value.binary_layout_sha_id);
    hash.update(&value.empty_layout_sha_id);
    hash.update(&value.parameter_authority_sha_id);
    hashDigest(hash, value.statement_id);
    hashDigest(hash, value.publication_id);
}

fn shaWords(value: [32]u8) channel.Digest {
    var result: channel.Digest = undefined;
    for (&result, 0..) |*word, index| word.* = std.mem.readInt(
        u32,
        value[index * 4 ..][0..4],
        .little,
    );
    return result;
}

fn requireDigest(value: channel.Digest) !void {
    var aggregate: u32 = 0;
    for (value) |word| {
        if (word >= stwo_core.fields.m31.Modulus)
            return error.InvalidEmptyTranscriptAuthority;
        aggregate |= word;
    }
    if (aggregate == 0) return error.InvalidEmptyTranscriptAuthority;
}

fn hashDigest(hash: *Sha256, value: channel.Digest) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashQm31(hash: *Sha256, value: QM31) void {
    for (value.toM31Array()) |word| hashInt(hash, u32, word.toU32());
}

fn hashInt(hash: *Sha256, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (CHILD_COUNT != 2 or RELATION_DRAW_COUNT != 94 or
        PACKED_RELATION_DRAW_COUNT != 47 or PROOF_BYTES_ACCEPTED or
        FRI_DRAWS_EMITTED or QUERY_DRAWS_EMITTED)
    {
        @compileError("empty-parent transcript contract drifted");
    }
}
