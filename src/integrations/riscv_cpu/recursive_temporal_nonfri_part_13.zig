//! Cohesive internal authority extracted from recursive_temporal_nonfri_source_v2.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const recursion = context.d_recursion;
        const channel = context.d_channel;
        const inactive = context.d_inactive;
        const statement_air = context.d_statement_air;
        const statement_source = context.d_statement_source;
        const temporal = context.d_temporal;
        const transcript_air = context.d_transcript_air;
        const relation_challenge = context.d_relation_challenge;
        const universal_catalog = context.d_universal_catalog;
        const universal_manifest = context.d_universal_manifest;
        const universal_typed_component = context.d_universal_typed_component;
        const packed_relation_challenge_v2 = context.d_packed_relation_challenge_v2;
        const Digest = context.d_Digest;
        const PairAuthority = context.d_PairAuthority;
        const PREFIX_CUSTODY_FORMAT_VERSION = context.d_PREFIX_CUSTODY_FORMAT_VERSION;
        const PREFIX_ROW_COUNT = context.d_PREFIX_ROW_COUNT;
        const PREFIX_CUSTODY_ID_DOMAIN = context.d_PREFIX_CUSTODY_ID_DOMAIN;
        const PREFIX_LAYOUT_AUTHORITY_DOMAIN = context.d_PREFIX_LAYOUT_AUTHORITY_DOMAIN;
        const RELATION_DOMAIN_CUSTODY_DOMAIN = context.d_RELATION_DOMAIN_CUSTODY_DOMAIN;
        const RELATION_DOMAIN_COUNT = context.d_RELATION_DOMAIN_COUNT;
        const TEMPORAL_PAYLOAD_AUTHORITY_DOMAIN = context.d_TEMPORAL_PAYLOAD_AUTHORITY_DOMAIN;
        const TemporalTranscriptManifestV2 = context.d_TemporalTranscriptManifestV2;
        const TemporalPayloadAuthorityV2 = context.d_TemporalPayloadAuthorityV2;
        const TemporalPrefixCommitmentLayoutV3 = context.d_TemporalPrefixCommitmentLayoutV3;
        const Error = context.d_Error;
        const TemporalChildTranscriptReplayV2 = context.d_TemporalChildTranscriptReplayV2;
        const TemporalTranscriptOperationTag = context.d_TemporalTranscriptOperationTag;
        const RecordedFrameV2 = context.d_RecordedFrameV2;
        const TemporalChildArtifactV2 = context.d_TemporalChildArtifactV2;
        const PreparedTranscriptRowsV2 = context.d_PreparedTranscriptRowsV2;
        const PreparedRows10Through11V2 = context.d_PreparedRows10Through11V2;
        const Rows10Through17AuthorityV2 = context.d_Rows10Through17AuthorityV2;
        const TemporalRows0Through17CustodyV3 = context.d_TemporalRows0Through17CustodyV3;
        const relationRowForFrame = context.d_relationRowForFrame;
        const shaInt = context.d_shaInt;
        const IdentityHasher = context.d_IdentityHasher;
        const byteRange = context.d_byteRange;

        pub const TemporalPrefixManifestContract = struct {
            pub const ComponentKey = universal_manifest.ComponentKey;
            pub const Geometry = universal_manifest.Geometry;

            pub fn keyIndex(key: ComponentKey) u8 {
                return universal_manifest.keyIndex(key);
            }
        };

        pub fn temporalPrefixGeometry(
            row: u8,
            log_size: u32,
        ) Error!universal_manifest.Geometry {
            if (row >= PREFIX_ROW_COUNT) return error.InvalidPrefixCommitmentLayout;
            if (row == @intFromEnum(universal_manifest.ComponentKey.relation_challenge)) {
                return universal_typed_component.manifestGeometryForAir(
                    packed_relation_challenge_v2,
                    TemporalPrefixManifestContract,
                    .relation_challenge,
                    log_size,
                );
            }
            inline for (universal_catalog.LOGICAL_ROWS) |entry| {
                if (entry.row == .relation_challenge) continue;
                if (row == @intFromEnum(entry.row)) {
                    return universal_typed_component.manifestGeometryForAir(
                        entry.Air,
                        TemporalPrefixManifestContract,
                        entry.row,
                        log_size,
                    );
                }
            }
            return error.InvalidPrefixCommitmentLayout;
        }

        pub fn temporalPrefixLogSizes(
            transcript_manifest: *const TemporalTranscriptManifestV2,
            inactive_source: *const inactive.Source,
        ) Error![PREFIX_ROW_COUNT]u32 {
            try transcript_manifest.validate();
            var result: [PREFIX_ROW_COUNT]u32 = undefined;
            for (transcript_manifest.log_sizes, 0..) |log_size, row|
                result[row] = log_size;
            result[10] = statement_air.STATEMENT_INPUT_LOG_SIZE;
            result[11] = statement_air.STATEMENT_SEMANTICS_LOG_SIZE;
            for (inactive_source.log_sizes, 0..) |log_size, index|
                result[12 + index] = log_size;
            for (result) |log_size| if (log_size == 0 or log_size >= 31)
                return error.InvalidPrefixCommitmentLayout;
            return result;
        }

        pub fn buildTemporalPrefixCommitmentLayout(
            log_sizes: [PREFIX_ROW_COUNT]u32,
            pair_authority_id: Digest,
            parent_public_id: Digest,
            transcript_manifest_sha_id: [32]u8,
            rows_10_through_17_authority_id: Digest,
            child_replays: [temporal.CHILD_COUNT]TemporalChildTranscriptReplayV2,
            child_relation_domain_sha_ids: [temporal.CHILD_COUNT][32]u8,
        ) Error!TemporalPrefixCommitmentLayoutV3 {
            var placements: [PREFIX_ROW_COUNT]universal_manifest.Placement = undefined;
            var preprocessed: u32 = 0;
            var main: u32 = 0;
            var interaction: u32 = 0;
            var constraints: u32 = 0;
            for (&placements, log_sizes, 0..) |*placement, log_size, row| {
                const geometry = try temporalPrefixGeometry(@intCast(row), log_size);
                placement.* = .{
                    .geometry = geometry,
                    .preprocessed_offset = preprocessed,
                    .main_offset = main,
                    .interaction_offset = interaction,
                    .constraint_offset = constraints,
                    .claimed_sum_index = @intCast(row),
                };
                preprocessed = std.math.add(
                    u32,
                    preprocessed,
                    geometry.preprocessed_columns,
                ) catch return error.ArithmeticOverflow;
                main = std.math.add(
                    u32,
                    main,
                    geometry.main_columns,
                ) catch return error.ArithmeticOverflow;
                interaction = std.math.add(
                    u32,
                    interaction,
                    geometry.interaction_columns,
                ) catch return error.ArithmeticOverflow;
                constraints = std.math.add(
                    u32,
                    constraints,
                    @as(u32, geometry.direct_constraints) +
                        geometry.interaction_batches,
                ) catch return error.ArithmeticOverflow;
            }
            var result = TemporalPrefixCommitmentLayoutV3{
                .relation_registry_sha_id = relationRegistryShaId(),
                .temporal_payload_authority_sha_id = TemporalPayloadAuthorityV2.pinned().identity,
                .pair_authority_id = pair_authority_id,
                .parent_public_id = parent_public_id,
                .transcript_manifest_sha_id = transcript_manifest_sha_id,
                .rows_10_through_17_authority_id = rows_10_through_17_authority_id,
                .child_publication_ids = .{
                    child_replays[0].publication_id,
                    child_replays[1].publication_id,
                },
                .child_replay_ids = .{
                    child_replays[0].replay_id,
                    child_replays[1].replay_id,
                },
                .child_relation_domain_sha_ids = child_relation_domain_sha_ids,
                .placements = placements,
                .total_preprocessed_columns = preprocessed,
                .total_main_columns = main,
                .total_interaction_columns = interaction,
                .total_constraints = constraints,
                .layout_sha_id = undefined,
            };
            result.layout_sha_id = prefixLayoutSha(&result);
            try result.validate();
            return result;
        }

        pub fn relationDomainShaForLane(
            frames: []const RecordedFrameV2,
            lane: usize,
        ) Error![32]u8 {
            if (lane >= temporal.CHILD_COUNT)
                return error.InvalidRelationDomainCustody;
            const expected_verifier = if (lane == 0)
                transcript_air.LEFT_RECURSION_VERIFIER_ID
            else
                transcript_air.RIGHT_RECURSION_VERIFIER_ID;
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(RELATION_DOMAIN_CUSTODY_DOMAIN);
            const registry_sha_id = relationRegistryShaId();
            hash.update(&registry_sha_id);
            shaInt(&hash, u16, PREFIX_CUSTODY_FORMAT_VERSION);
            shaInt(&hash, u8, @as(u8, @intCast(lane)));
            shaInt(&hash, u8, RELATION_DOMAIN_COUNT);
            var domain: usize = 0;
            for (frames) |frame| {
                if (frame.tag != @intFromEnum(
                    TemporalTranscriptOperationTag.relation_draw,
                )) continue;
                if (domain >= RELATION_DOMAIN_COUNT or
                    frame.verifier_id != expected_verifier or
                    frame.args[0] != 2 * @as(u32, @intCast(domain)) or
                    frame.args[1] != packed_relation_challenge_v2.CHALLENGES_PER_DRAW or
                    frame.args[2] != packed_relation_challenge_v2.PACKING_FORMAT_VERSION or
                    frame.args[3] != 0)
                {
                    return error.InvalidRelationDomainCustody;
                }
                try packed_relation_challenge_v2.validateRow(
                    relationRowForFrame(frame),
                );
                shaInt(&hash, u8, @as(u8, @intCast(domain)));
                shaInt(&hash, u32, frame.sequence);
                shaInt(&hash, u32, frame.hash_id);
                for (frame.output_digest) |word|
                    shaInt(&hash, u32, word.toU32());
                domain += 1;
            }
            if (domain != RELATION_DOMAIN_COUNT)
                return error.InvalidRelationDomainCustody;
            return hash.finalResult();
        }

        pub fn relationRegistryShaId() [32]u8 {
            const relations =
                recursion.air.universal_challenges.UniversalRelations.dummy();
            return relations.registry_order_digest;
        }

        pub fn temporalPayloadAuthoritySha(
            value: *const TemporalPayloadAuthorityV2,
        ) [32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(TEMPORAL_PAYLOAD_AUTHORITY_DOMAIN);
            shaInt(&hash, u16, value.format_version);
            shaInt(&hash, u16, value.schema_version);
            shaInt(&hash, u8, @intFromBool(value.frozen_witness_compatible));
            shaInt(&hash, u8, value.source_kind_count);
            shaInt(&hash, u8, value.public_geometry_source_kind);
            shaInt(&hash, u8, value.relation_event_count);
            hash.update(&value.padding);
            shaInt(&hash, u64, value.relation_domain_mask);
            hash.update(&value.typed_air_semantic_digest);
            hash.update(&value.relation_registry_sha_id);
            return hash.finalResult();
        }

        pub fn prefixLayoutSha(
            value: *const TemporalPrefixCommitmentLayoutV3,
        ) [32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(PREFIX_LAYOUT_AUTHORITY_DOMAIN);
            shaInt(&hash, u16, value.format_version);
            shaInt(&hash, u16, value.schema_version);
            shaInt(&hash, u8, value.row_count);
            shaInt(&hash, u8, value.relation_domain_count);
            shaInt(&hash, u64, value.row_mask);
            shaInt(&hash, u64, value.typed_row_mask);
            shaInt(&hash, u64, value.relation_domain_mask);
            hash.update(&value.relation_registry_sha_id);
            hash.update(&value.temporal_payload_authority_sha_id);
            for (value.pair_authority_id) |word| shaInt(&hash, u32, word);
            for (value.parent_public_id) |word| shaInt(&hash, u32, word);
            hash.update(&value.transcript_manifest_sha_id);
            for (value.rows_10_through_17_authority_id) |word|
                shaInt(&hash, u32, word);
            for (value.child_publication_ids) |digest_value|
                for (digest_value) |word| shaInt(&hash, u32, word);
            for (value.child_replay_ids) |digest_value|
                for (digest_value) |word| shaInt(&hash, u32, word);
            for (value.child_relation_domain_sha_ids) |sha_value|
                hash.update(&sha_value);
            for (value.placements) |placement| {
                const geometry = placement.geometry;
                shaInt(&hash, u8, geometry.roster_row);
                shaInt(&hash, u32, geometry.log_size);
                shaInt(&hash, u16, geometry.preprocessed_columns);
                shaInt(&hash, u16, geometry.main_columns);
                shaInt(&hash, u16, geometry.interaction_columns);
                shaInt(&hash, u16, geometry.direct_constraints);
                shaInt(&hash, u16, geometry.interaction_batches);
                shaInt(&hash, u8, geometry.protocol_constraint_degree);
                shaInt(&hash, u8, geometry.profiled_constraint_degree);
                hash.update(&geometry.semantic_digest);
                shaInt(&hash, u32, placement.preprocessed_offset);
                shaInt(&hash, u32, placement.main_offset);
                shaInt(&hash, u32, placement.interaction_offset);
                shaInt(&hash, u32, placement.constraint_offset);
                shaInt(&hash, u8, placement.claimed_sum_index);
            }
            shaInt(&hash, u32, value.total_preprocessed_columns);
            shaInt(&hash, u32, value.total_main_columns);
            shaInt(&hash, u32, value.total_interaction_columns);
            shaInt(&hash, u32, value.total_constraints);
            return hash.finalResult();
        }

        pub fn prefixCustodyIdentity(
            value: *const TemporalRows0Through17CustodyV3,
        ) Digest {
            var hash = IdentityHasher.init(PREFIX_CUSTODY_ID_DOMAIN);
            hash.addU32(value.format_version);
            hash.addU32(value.schema_version);
            hash.addU32(value.row_count);
            hash.digest(value.parent_public.identity);
            hash.sha(value.transcript_manifest.identity);
            hash.digest(value.rows_10_through_17.authority_id);
            for (value.child_replays) |replay| hash.digest(replay.replay_id);
            for (value.child_relation_domain_sha_ids) |domain_sha|
                hash.sha(domain_sha);
            hash.sha(value.commitment_layout.layout_sha_id);
            return hash.finalize();
        }

        pub fn rejectPrefixCustodyAliases(
            destination: *TemporalRows0Through17CustodyV3,
            pair: *const PairAuthority,
            transcript_rows: *const PreparedTranscriptRowsV2,
            statement_rows: *const PreparedRows10Through11V2,
            statement_authority: *const statement_source.Authority,
            statement_workspace: *const statement_air.Workspace,
            rows_10_through_17: *const Rows10Through17AuthorityV2,
            inactive_source: *const inactive.Source,
            left: TemporalChildArtifactV2,
            right: TemporalChildArtifactV2,
        ) Error!void {
            if (left.publication == right.publication or left.witness == right.witness or
                left.capture == right.capture)
            {
                return error.DuplicateChild;
            }
            const target = std.mem.asBytes(destination);
            inline for (.{
                std.mem.asBytes(pair),
                std.mem.asBytes(transcript_rows),
                std.mem.asBytes(statement_rows),
                std.mem.asBytes(statement_authority),
                std.mem.asBytes(statement_workspace),
                std.mem.asBytes(rows_10_through_17),
                std.mem.asBytes(inactive_source),
                std.mem.asBytes(left.manifest),
                std.mem.asBytes(left.publication),
                std.mem.asBytes(left.witness),
                std.mem.asBytes(left.capture),
                std.mem.asBytes(right.manifest),
                std.mem.asBytes(right.publication),
                std.mem.asBytes(right.witness),
                std.mem.asBytes(right.capture),
            }) |source| if ((try byteRange(target)).overlaps(try byteRange(source)))
                return error.AliasedDestination;
            inline for (.{
                std.mem.sliceAsBytes(transcript_rows.rows),
                std.mem.sliceAsBytes(transcript_rows.operations),
                std.mem.sliceAsBytes(transcript_rows.frames),
                std.mem.sliceAsBytes(statement_workspace.logical_storage),
                std.mem.sliceAsBytes(statement_workspace.secure_storage),
            }) |source| if ((try byteRange(target)).overlaps(try byteRange(source)))
                return error.AliasedDestination;
        }

        pub fn transcriptTraceLogSize(row_count: usize) Error!u32 {
            const padded = std.math.ceilPowerOfTwo(
                usize,
                @max(row_count, 1),
            ) catch return error.ArithmeticOverflow;
            const log_size: u32 = @max(
                transcript_air.MIN_LOG_SIZE,
                std.math.log2_int(usize, padded),
            );
            if (log_size > transcript_air.MAX_LOG_SIZE)
                return error.RowCountOutOfRange;
            return log_size;
        }

        pub fn transcriptWordCount(frames: []const RecordedFrameV2) Error!usize {
            var result: usize = 0;
            for (frames) |frame| {
                const padded = std.math.mul(
                    usize,
                    frame.call_count,
                    channel.RATE,
                ) catch return error.ArithmeticOverflow;
                if (padded < channel.RATE) return error.InvalidTranscriptRecorder;
                result = std.math.add(
                    usize,
                    result,
                    padded - channel.RATE,
                ) catch return error.ArithmeticOverflow;
            }
            return result;
        }

        pub fn transcriptPayloadCount(frames: []const RecordedFrameV2) Error!usize {
            var result: usize = 0;
            for (frames) |frame| {
                if (frame.purpose != .mix) continue;
                result = std.math.add(
                    usize,
                    result,
                    frame.payload_word_count,
                ) catch return error.ArithmeticOverflow;
            }
            return result;
        }
    };
}
