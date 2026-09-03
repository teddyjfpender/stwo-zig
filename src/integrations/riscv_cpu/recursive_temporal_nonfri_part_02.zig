//! Cohesive internal authority extracted from recursive_temporal_nonfri_source_v2.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const M31 = context.d_M31;
        const QM31 = context.d_QM31;
        const recursion = context.d_recursion;
        const channel = context.d_channel;
        const manifest_mod = context.d_manifest_mod;
        const outer_admission = context.d_outer_admission;
        const transcript_air = context.d_transcript_air;
        const segment_artifact = context.d_segment_artifact;
        const Digest = context.d_Digest;
        const FORMAT_VERSION = context.d_FORMAT_VERSION;
        const SCHEMA_VERSION = context.d_SCHEMA_VERSION;
        const PROOFLESS_EMPTY_CHILD_REPLAY_SCHEMA_VERSION =
            context.d_PROOFLESS_EMPTY_CHILD_REPLAY_SCHEMA_VERSION;
        const CHILD_QUERY_COUNT = context.d_CHILD_QUERY_COUNT;
        const MAX_CHILD_FRI_ROUNDS = context.d_MAX_CHILD_FRI_ROUNDS;
        const CHILD_COMMITMENT_COUNT = context.d_CHILD_COMMITMENT_COUNT;
        const CHILD_RELATION_DRAW_COUNT = context.d_CHILD_RELATION_DRAW_COUNT;
        const Error = context.d_Error;
        const SegmentPublication = context.d_SegmentPublication;
        const SegmentRecursiveWitness = context.d_SegmentRecursiveWitness;
        const OuterProofCapture = context.d_OuterProofCapture;
        const mixChildAuthorityPrefix = context.d_mixChildAuthorityPrefix;
        const replayRelationDraws = context.d_replayRelationDraws;
        const mixPublicWireBoundary = context.d_mixPublicWireBoundary;
        const validateCaptureTranscriptShape = context.d_validateCaptureTranscriptShape;
        const queryLogFromCapture = context.d_queryLogFromCapture;
        const transcriptReplayIdentity = context.d_transcriptReplayIdentity;
        const requireDigest = context.d_requireDigest;
        const requireSha = context.d_requireSha;
        const requireCanonical = context.d_requireCanonical;
        const allZero = context.d_allZero;

        pub const TemporalChildTranscriptReplayV2 = struct {
            format_version: u16 = FORMAT_VERSION,
            schema_version: u16 = SCHEMA_VERSION,
            fri_round_count: u8,
            query_count: u8 = CHILD_QUERY_COUNT,
            relation_draw_count: u8 = CHILD_RELATION_DRAW_COUNT,
            padding: [1]u8 = .{0},

            publication_id: Digest,
            witness_id: Digest,
            capture_id: Digest,
            transcript_prefix_id: Digest,
            manifest_sha_id: [32]u8,
            pre_core_digest: Digest,
            pre_core_draw_count: u32,
            composition_randomness: QM31,
            oods_seed: QM31,
            deep_randomness: QM31,
            fri_alphas: [MAX_CHILD_FRI_ROUNDS]QM31,
            raw_queries: [CHILD_QUERY_COUNT]u32,
            final_digest: Digest,
            final_draw_count: u32,
            replay_id: Digest,

            pub fn deriveFromArtifact(
                manifest: *const manifest_mod.Manifest,
                publication: *const SegmentPublication,
                witness: *const SegmentRecursiveWitness,
                capture: *const OuterProofCapture,
            ) Error!TemporalChildTranscriptReplayV2 {
                try segment_artifact.preflight(
                    capture,
                    publication,
                    witness,
                    manifest,
                );
                try validateCaptureTranscriptShape(capture);

                var transcript = channel.Channel{};
                return deriveReplayAfterPreflight(
                    &transcript,
                    manifest,
                    publication,
                    witness,
                    capture,
                );
            }

            pub fn validateAgainstArtifact(
                self: *const TemporalChildTranscriptReplayV2,
                manifest: *const manifest_mod.Manifest,
                publication: *const SegmentPublication,
                witness: *const SegmentRecursiveWitness,
                capture: *const OuterProofCapture,
            ) Error!void {
                const expected = try deriveFromArtifact(
                    manifest,
                    publication,
                    witness,
                    capture,
                );
                if (!std.meta.eql(self.*, expected))
                    return error.ChildTranscriptMismatch;
            }

            pub fn validate(self: *const TemporalChildTranscriptReplayV2) Error!void {
                const legacy = self.schema_version == SCHEMA_VERSION;
                const proofless_empty = self.schema_version ==
                    PROOFLESS_EMPTY_CHILD_REPLAY_SCHEMA_VERSION;
                if (self.format_version != FORMAT_VERSION or
                    (!legacy and !proofless_empty) or
                    self.relation_draw_count != CHILD_RELATION_DRAW_COUNT or
                    !allZero(&self.padding))
                {
                    return error.UnsupportedFormat;
                }
                if (legacy) {
                    if (self.fri_round_count == 0 or
                        self.fri_round_count > MAX_CHILD_FRI_ROUNDS or
                        self.query_count != CHILD_QUERY_COUNT)
                    {
                        return error.UnsupportedFormat;
                    }
                } else if (self.fri_round_count != 0 or self.query_count != 0) {
                    return error.UnsupportedFormat;
                }
                inline for (.{
                    self.publication_id,
                    self.witness_id,
                    self.capture_id,
                    self.transcript_prefix_id,
                    self.pre_core_digest,
                    self.final_digest,
                    self.replay_id,
                }) |value| try requireDigest(value);
                try requireSha(self.manifest_sha_id);
                try requireCanonical(self.composition_randomness);
                try requireCanonical(self.oods_seed);
                if (proofless_empty and !self.deep_randomness.isZero())
                    return error.ChildTranscriptMismatch;
                try requireCanonical(self.deep_randomness);
                for (self.fri_alphas[0..self.fri_round_count]) |value|
                    try requireCanonical(value);
                for (self.fri_alphas[self.fri_round_count..]) |value|
                    if (!value.isZero()) return error.ChildTranscriptMismatch;
                if (proofless_empty)
                    for (self.raw_queries) |query|
                        if (query != 0) return error.ChildTranscriptMismatch;
                if (!std.meta.eql(
                    self.replay_id,
                    transcriptReplayIdentity(self),
                )) return error.ChildTranscriptMismatch;
            }
        };

        /// One protocol implementation serves both native replay and typed-row
        /// recording.  The generic seam is intentionally below preflight: no channel
        /// implementation ever sees an unvalidated artifact shape.
        pub fn deriveReplayAfterPreflight(
            transcript: anytype,
            manifest: *const manifest_mod.Manifest,
            publication: *const SegmentPublication,
            witness: *const SegmentRecursiveWitness,
            capture: *const OuterProofCapture,
        ) Error!TemporalChildTranscriptReplayV2 {
            mixMerkleRoot(
                transcript,
                capture.commitments[manifest_mod.PREPROCESSED_TREE_INDEX],
            );
            mixMerkleRoot(
                transcript,
                capture.commitments[manifest_mod.MAIN_TREE_INDEX],
            );
            try manifest.mixStatementPrefix(transcript);
            try mixChildAuthorityPrefix(
                transcript,
                publication,
                &witness.transcript_prefix,
            );
            try replayRelationDraws(transcript, &witness.relation_draws);

            var claims = try manifest_mod.ClaimVector.init(manifest);
            for (witness.claimed_sums, 0..) |claim, row|
                try claims.bind(@enumFromInt(row), claim);
            try claims.sealClaims(manifest);
            if (!std.mem.eql(
                u8,
                &claims.seal,
                &publication.closure.claim_seal_sha_id,
            )) return error.ChildTranscriptMismatch;
            try claims.mixInteractionClaims(manifest, transcript);
            try mixPublicWireBoundary(transcript, &witness.transcript_prefix);
            mixMerkleRoot(
                transcript,
                capture.commitments[manifest_mod.INTERACTION_TREE_INDEX],
            );

            const pre_core_digest = transcript.digestWords();
            const pre_core_draw_count = transcript.n_draws;
            annotateNextDraw(transcript, .composition_draw, .{ 0, 0, 0, 0 });
            const composition_randomness = transcript.drawSecureFelt();
            if (!composition_randomness.eql(capture.composition_randomness))
                return error.ChildTranscriptMismatch;

            mixMerkleRoot(
                transcript,
                capture.commitments[CHILD_COMMITMENT_COUNT - 1],
            );
            annotateNextDraw(transcript, .oods_draw, .{ 0, 0, 0, 0 });
            const oods_seed = transcript.drawSecureFelt();
            if (!oods_seed.eql(capture.oods_seed))
                return error.ChildTranscriptMismatch;
            transcript.mixFelts(capture.sampled_values);
            annotateNextDraw(transcript, .deep_draw, .{ 0, 0, 0, 0 });
            const deep_randomness = transcript.drawSecureFelt();
            if (!deep_randomness.eql(capture.deep_randomness))
                return error.ChildTranscriptMismatch;

            var fri_alphas = [_]QM31{QM31.zero()} ** MAX_CHILD_FRI_ROUNDS;
            for (capture.fri.layers, 0..) |layer, index| {
                mixMerkleRoot(transcript, layer.commitment);
                annotateNextDraw(
                    transcript,
                    .fri_alpha_draw,
                    .{ @intCast(index), 0, 0, 0 },
                );
                fri_alphas[index] = transcript.drawSecureFelt();
                if (!fri_alphas[index].eql(layer.folding_alpha))
                    return error.ChildTranscriptMismatch;
            }
            transcript.mixFelts(capture.last_layer_coefficients);
            if (!transcript.verifyPowNonce(
                outer_admission.PCS_POW_BITS,
                capture.proof_of_work,
            )) return error.ChildTranscriptMismatch;
            transcript.mixU64(capture.proof_of_work);

            const query_log = try queryLogFromCapture(capture);
            annotateNextDraw(transcript, .query_draw, .{
                0, CHILD_QUERY_COUNT, query_log, 0,
            });
            const query_words = transcript.drawU32s();
            const query_mask = (@as(u32, 1) << @intCast(query_log)) - 1;
            var raw_queries: [CHILD_QUERY_COUNT]u32 = undefined;
            for (&raw_queries, capture.queries.raw, query_words[0..CHILD_QUERY_COUNT]) |
                *destination,
                captured,
                word,
            | {
                destination.* = word & query_mask;
                if (captured != destination.*)
                    return error.ChildTranscriptMismatch;
            }

            const final_digest = transcript.digestWords();
            const final_draw_count = transcript.n_draws;
            if (!std.meta.eql(
                publication.transcript_id,
                recursion.protocol.transcriptId(final_digest, final_draw_count),
            )) return error.ChildTranscriptMismatch;

            var result = TemporalChildTranscriptReplayV2{
                .fri_round_count = @intCast(capture.fri.layers.len),
                .publication_id = publication.publication_id,
                .witness_id = witness.witness_id,
                .capture_id = witness.capture_id,
                .transcript_prefix_id = witness.transcript_prefix.transcript_prefix_id,
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
            result.replay_id = transcriptReplayIdentity(&result);
            try result.validate();
            return result;
        }

        pub fn mixMerkleRoot(transcript: anytype, root: Digest) void {
            var words: [channel.RATE]M31 = undefined;
            for (&words, root) |*destination, word|
                destination.* = M31.fromCanonical(word);
            transcript.mixCanonicalM31Words(&words);
        }

        pub fn annotateNextDraw(
            transcript: anytype,
            tag: TemporalTranscriptOperationTag,
            args: [4]u32,
        ) void {
            const Child = @typeInfo(@TypeOf(transcript)).pointer.child;
            if (comptime @hasDecl(Child, "annotateNextDraw"))
                transcript.annotateNextDraw(tag, args);
        }

        pub const TemporalTranscriptOperationTag = enum(u32) {
            mix_canonical_words = 1,
            mix_u32s = 2,
            mix_felts = 3,
            mix_u64 = 4,
            draw = 5,
            verify_pow = 6,
            relation_draw = 7,
            composition_draw = 8,
            oods_draw = 9,
            deep_draw = 10,
            fri_alpha_draw = 11,
            query_draw = 12,
        };

        pub const RecordedFrameV2 = struct {
            verifier_id: u32,
            sequence: u32,
            tag: u32,
            args: [4]u32,
            hash_id: u32,
            first_call_id: u32,
            call_count: u32,
            payload_word_count: u32,
            purpose: transcript_air.HashPurpose,
            pow_draw: bool,
            input_digest: [channel.RATE]M31,
            output_digest: [channel.RATE]M31,
            input_state_key: u32 = 0,
            output_state_key: u32 = 0,
            initial_mask: u32 = 0,
            state_consume_mask: u32 = 0,
            state_produce_multiplicity: u32 = 0,
            draw_output_mask: u32 = 0,
        };

        pub const RecorderPayload = union(enum) {
            canonical: []const M31,
            u32s: []const u32,
            felts: []const QM31,
            u64_value: u64,
            draw_count: u32,

            pub fn wordCount(self: RecorderPayload) usize {
                return switch (self) {
                    .canonical => |words| words.len,
                    .u32s => |words| words.len * 2,
                    .felts => |felts| felts.len * 4,
                    .u64_value => 4,
                    .draw_count => 2,
                };
            }

            pub fn word(self: RecorderPayload, index: usize) M31 {
                return switch (self) {
                    .canonical => |words| words[index],
                    .u32s => |words| blk: {
                        const value = words[index / 2];
                        const limb = if (index % 2 == 0)
                            value & 0xffff
                        else
                            value >> 16;
                        break :blk M31.fromCanonical(limb);
                    },
                    .felts => |felts| felts[index / 4].toM31Array()[index % 4],
                    .u64_value => |value| M31.fromCanonical(@intCast(
                        (value >> @intCast(16 * index)) & 0xffff,
                    )),
                    .draw_count => |draw_count| M31.fromCanonical(if (index == 0)
                        draw_count
                    else
                        channel.DRAW_TAG),
                };
            }
        };

        pub const PendingPow = struct {
            nonce: u64,
            absorbed_digest: Digest,
        };

        pub const OperationContextV2 = struct {
            sequence: u32,
            tag: u32,
            args: [4]u32,
        };

        pub const NextDrawOperationV2 = struct {
            tag: TemporalTranscriptOperationTag,
            args: [4]u32,
        };

        // Cold exact-channel recorder for transcript row 1.  It computes each
        // permutation once, retaining only the row ABI consumed by the existing AIR.
        // No frame-word allocation or second replay is performed.
    };
}
