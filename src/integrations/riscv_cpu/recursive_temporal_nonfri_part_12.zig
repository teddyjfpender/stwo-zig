//! Cohesive internal authority extracted from recursive_temporal_nonfri_source_v2.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const QM31 = context.d_QM31;
        const recursion = context.d_recursion;
        const channel = context.d_channel;
        const cohort_protocol = context.d_cohort_protocol;
        const inactive = context.d_inactive;
        const manifest_mod = context.d_manifest_mod;
        const outer_admission = context.d_outer_admission;
        const schedule = context.d_schedule;
        const statement_air = context.d_statement_air;
        const statement_source = context.d_statement_source;
        const temporal = context.d_temporal;
        const relation_interaction = context.d_relation_interaction;
        const segment_artifact = context.d_segment_artifact;
        const packed_relation_challenge_v2 = context.d_packed_relation_challenge_v2;
        const Digest = context.d_Digest;
        const PairAuthority = context.d_PairAuthority;
        const authenticatePreparedPairForSource = context.d_authenticatePreparedPairForSource;
        const PUBLIC_ID_DOMAIN = context.d_PUBLIC_ID_DOMAIN;
        const STATEMENT_SOURCE_ID_DOMAIN = context.d_STATEMENT_SOURCE_ID_DOMAIN;
        const ROW_AUTHORITY_ID_DOMAIN = context.d_ROW_AUTHORITY_ID_DOMAIN;
        const CHILD_QUERY_COUNT = context.d_CHILD_QUERY_COUNT;
        const MAX_CHILD_FRI_ROUNDS = context.d_MAX_CHILD_FRI_ROUNDS;
        const CHILD_COMMITMENT_COUNT = context.d_CHILD_COMMITMENT_COUNT;
        const CHILD_RELATION_DRAW_COUNT = context.d_CHILD_RELATION_DRAW_COUNT;
        const COHORT_AUTHORITY_TRANSCRIPT_DOMAIN = context.d_COHORT_AUTHORITY_TRANSCRIPT_DOMAIN;
        const COHORT_FORMAT_VERSION = context.d_COHORT_FORMAT_VERSION;
        const CORE_FIRST_ROW = context.d_CORE_FIRST_ROW;
        const CORE_LAST_ROW = context.d_CORE_LAST_ROW;
        const NONCORE_AUTHORITY_TRANSCRIPT_DOMAIN = context.d_NONCORE_AUTHORITY_TRANSCRIPT_DOMAIN;
        const NONCORE_FORMAT_VERSION = context.d_NONCORE_FORMAT_VERSION;
        const NONCORE_ROW_COUNT = context.d_NONCORE_ROW_COUNT;
        const CORE_AUTHORITY_TRANSCRIPT_DOMAIN = context.d_CORE_AUTHORITY_TRANSCRIPT_DOMAIN;
        const CORE_FORMAT_VERSION = context.d_CORE_FORMAT_VERSION;
        const CORE_PROVIDER_INSTANCE_COUNT = context.d_CORE_PROVIDER_INSTANCE_COUNT;
        const PUBLIC_WIRE_BOUNDARY_TRANSCRIPT_DOMAIN = context.d_PUBLIC_WIRE_BOUNDARY_TRANSCRIPT_DOMAIN;
        const TRANSCRIPT_REPLAY_ID_DOMAIN = context.d_TRANSCRIPT_REPLAY_ID_DOMAIN;
        const Error = context.d_Error;
        const SegmentPublication = context.d_SegmentPublication;
        const OuterProofCapture = context.d_OuterProofCapture;
        const TemporalChildTranscriptReplayV2 = context.d_TemporalChildTranscriptReplayV2;
        const annotateNextDraw = context.d_annotateNextDraw;
        const TemporalChildArtifactV2 = context.d_TemporalChildArtifactV2;
        const PreparedTranscriptRowsV2 = context.d_PreparedTranscriptRowsV2;
        const TemporalParentPublicV2 = context.d_TemporalParentPublicV2;
        const PreparedRows10Through11V2 = context.d_PreparedRows10Through11V2;
        const Rows10Through17AuthorityV2 = context.d_Rows10Through17AuthorityV2;
        const TemporalRows0Through17CustodyV3 = context.d_TemporalRows0Through17CustodyV3;
        const temporalPrefixLogSizes = context.d_temporalPrefixLogSizes;
        const buildTemporalPrefixCommitmentLayout = context.d_buildTemporalPrefixCommitmentLayout;
        const prefixCustodyIdentity = context.d_prefixCustodyIdentity;
        const rejectPrefixCustodyAliases = context.d_rejectPrefixCustodyAliases;
        const IdentityHasher = context.d_IdentityHasher;
        const statementId = context.d_statementId;

        pub fn initTemporalRows0Through17CustodyInto(
            destination: *TemporalRows0Through17CustodyV3,
            pair: *const PairAuthority,
            transcript_rows: *const PreparedTranscriptRowsV2,
            statement_rows: *const PreparedRows10Through11V2,
            statement_authority: *const statement_source.Authority,
            statement_workspace: *statement_air.Workspace,
            rows_10_through_17: *const Rows10Through17AuthorityV2,
            inactive_source: *const inactive.Source,
            vm_plan: *const schedule.Plan,
            recursion_plan: *const schedule.Plan,
            left: TemporalChildArtifactV2,
            right: TemporalChildArtifactV2,
        ) Error!void {
            try rejectPrefixCustodyAliases(
                destination,
                pair,
                transcript_rows,
                statement_rows,
                statement_authority,
                statement_workspace,
                rows_10_through_17,
                inactive_source,
                left,
                right,
            );
            try pair.validate();
            try transcript_rows.validateAgainstArtifacts(pair, left, right);
            try statement_rows.validateAgainstPair(
                statement_authority,
                statement_workspace,
                pair,
            );
            try rows_10_through_17.validate();
            if (!std.meta.eql(
                rows_10_through_17.statement_source_id,
                statement_rows.source_id,
            ) or !std.meta.eql(
                rows_10_through_17.pair_authority_id,
                pair.authority_id,
            ) or !std.mem.eql(
                u8,
                &rows_10_through_17.inactive_source_sha_id,
                &inactive_source.authority_seal,
            )) return error.SourceIdentityMismatch;

            const authenticated = try authenticatePreparedPairForSource(pair);
            const parent_public = try publicFromPair(pair, authenticated);
            if (!std.meta.eql(parent_public, statement_rows.public))
                return error.PairSnapshotMismatch;
            const transcript_manifest = try transcript_rows.manifestForPlans(
                vm_plan,
                recursion_plan,
            );
            const relation_domain_sha_ids =
                try transcript_rows.relationDomainShaIds();
            const log_sizes = try temporalPrefixLogSizes(
                &transcript_manifest,
                inactive_source,
            );
            const layout = try buildTemporalPrefixCommitmentLayout(
                log_sizes,
                pair.authority_id,
                parent_public.identity,
                transcript_manifest.identity,
                rows_10_through_17.authority_id,
                transcript_rows.child_replays,
                relation_domain_sha_ids,
            );
            var staged = TemporalRows0Through17CustodyV3{
                .parent_public = parent_public,
                .transcript_manifest = transcript_manifest,
                .rows_10_through_17 = rows_10_through_17.*,
                .child_replays = transcript_rows.child_replays,
                .child_relation_domain_sha_ids = relation_domain_sha_ids,
                .commitment_layout = layout,
                .custody_id = undefined,
            };
            staged.custody_id = prefixCustodyIdentity(&staged);
            try staged.validate();
            destination.* = staged;
        }

        /// Compile-time compatibility gate for the existing zero-allocation Tree 1
        /// writer.  Keeping this concrete instantiation beside the temporal prepared
        /// type prevents the `anytype` seam from becoming an untested structural
        /// promise.
        pub fn typecheckTemporalStatementMainWriter(
            authority: *const statement_source.Authority,
            workspace: *statement_air.Workspace,
            prepared: *const PreparedRows10Through11V2,
            columns: *statement_air.MainColumns,
        ) !void {
            try statement_air.fillMainCommitted(
                recursion.segment_profile.DIMENSIONS,
                authority,
                workspace,
                prepared,
                columns,
            );
        }

        pub fn typecheckTemporalStatementInteractionWriter(
            authority: *const statement_source.Authority,
            workspace: *statement_air.Workspace,
            prepared: *const PreparedRows10Through11V2,
            relations: *const recursion.air.universal_challenges.UniversalRelations,
            provider_relations: *const recursion.air.universal_shared_provider.SharedProviderRelations,
            columns: *statement_air.InteractionColumns,
        ) !statement_air.Claims {
            return statement_air.fillInteractionsCommitted(
                recursion.segment_profile.DIMENSIONS,
                authority,
                workspace,
                prepared,
                relations,
                provider_relations,
                columns,
            );
        }

        pub fn typecheckTemporalStatementDomainAudit(
            authority: *const statement_source.Authority,
            workspace: *statement_air.Workspace,
            prepared: *const PreparedRows10Through11V2,
            relations: *const recursion.air.universal_challenges.UniversalRelations,
            provider_relations: *const recursion.air.universal_shared_provider.SharedProviderRelations,
            claims: statement_air.Claims,
            tuple_ledger: ?*recursion.air.relation_interaction.TupleLedger,
        ) !statement_air.DomainAudits {
            return statement_air.auditInteractionDomains(
                recursion.segment_profile.DIMENSIONS,
                authority,
                workspace,
                prepared,
                relations,
                provider_relations,
                claims,
                tuple_ledger,
            );
        }

        pub fn mixChildAuthorityPrefix(
            transcript: anytype,
            publication: *const SegmentPublication,
            prefix: *const segment_artifact.TranscriptPrefixV1,
        ) Error!void {
            try prefix.validate();
            transcript.mixU32s(&.{
                COHORT_AUTHORITY_TRANSCRIPT_DOMAIN,
                COHORT_FORMAT_VERSION,
                manifest_mod.COMPONENT_COUNT,
                CORE_FIRST_ROW,
                CORE_LAST_ROW,
                cohort_protocol.MEASURED_TOTAL_POSEIDON_CALLS,
            });
            transcript.mixU32s(&shaWords(publication.manifest_sha_id));
            transcript.mixU32s(&shaWords(publication.plan_sha_id));
            transcript.mixU32s(&shaWords(publication.cohort_authority_sha_id));

            transcript.mixU32s(&.{
                NONCORE_AUTHORITY_TRANSCRIPT_DOMAIN,
                NONCORE_FORMAT_VERSION,
                NONCORE_ROW_COUNT,
            });
            transcript.mixU32s(&shaWords(prefix.noncore_authority_sha_id));

            transcript.mixU32s(&.{
                CORE_AUTHORITY_TRANSCRIPT_DOMAIN,
                CORE_FORMAT_VERSION,
                CORE_FIRST_ROW,
                CORE_LAST_ROW,
                CORE_PROVIDER_INSTANCE_COUNT,
                prefix.core_total_call_count,
            });
            transcript.mixU32s(&shaWords(prefix.core_authority_sha_id));
            transcript.mixU32s(&shaWords(prefix.core_layout_sha_id));
            transcript.mixU32s(&shaWords(prefix.core_call_buffer_sha_id));
        }

        pub fn replayRelationDraws(
            transcript: anytype,
            expected: *const [CHILD_RELATION_DRAW_COUNT]QM31,
        ) Error!void {
            comptime {
                if (channel.RATE != 8 or CHILD_RELATION_DRAW_COUNT % 2 != 0)
                    @compileError("temporal relation-draw packing drifted");
            }
            var at: usize = 0;
            while (at < expected.len) : (at += 2) {
                annotateNextDraw(transcript, .relation_draw, .{
                    @intCast(at),
                    packed_relation_challenge_v2.CHALLENGES_PER_DRAW,
                    packed_relation_challenge_v2.PACKING_FORMAT_VERSION,
                    0,
                });
                const words = transcript.drawU32s();
                const first = QM31.fromU32Unchecked(
                    words[0],
                    words[1],
                    words[2],
                    words[3],
                );
                const second = QM31.fromU32Unchecked(
                    words[4],
                    words[5],
                    words[6],
                    words[7],
                );
                if (!first.eql(expected[at]) or !second.eql(expected[at + 1]))
                    return error.ChildTranscriptMismatch;
            }
        }

        pub fn mixPublicWireBoundary(
            transcript: anytype,
            prefix: *const segment_artifact.TranscriptPrefixV1,
        ) Error!void {
            const boundary = try cohort_protocol.PublicWireBoundaryV2.init(
                prefix.core_authority_sha_id,
                prefix.public_wire_boundary_term_count,
                prefix.public_wire_boundary_claimed_sum,
            );
            if (!std.mem.eql(
                u8,
                &boundary.identity,
                &prefix.public_wire_boundary_sha_id,
            )) return error.ChildTranscriptMismatch;
            transcript.mixU32s(&.{
                PUBLIC_WIRE_BOUNDARY_TRANSCRIPT_DOMAIN,
                boundary.format_version,
                @intFromEnum(boundary.domain),
                boundary.term_count,
            });
            transcript.mixU32s(&shaWords(boundary.source_authority_id));
            transcript.mixFelts(&.{boundary.claimed_sum});
            transcript.mixU32s(&shaWords(boundary.identity));
        }

        pub fn validateCaptureTranscriptShape(
            capture: *const OuterProofCapture,
        ) Error!void {
            if (capture.commitments.len != CHILD_COMMITMENT_COUNT or
                capture.column_log_sizes.len != CHILD_COMMITMENT_COUNT or
                capture.sampled_points.len != CHILD_COMMITMENT_COUNT or
                capture.trace_paths.len != CHILD_COMMITMENT_COUNT or
                capture.queries.raw.len != CHILD_QUERY_COUNT or
                capture.deep_answers.len != CHILD_QUERY_COUNT or
                capture.fri.layers.len == 0 or
                capture.fri.layers.len > MAX_CHILD_FRI_ROUNDS or
                capture.sampled_values.len == 0 or
                capture.last_layer_coefficients.len == 0)
            {
                return error.CaptureShapeMismatch;
            }
            _ = try queryLogFromCapture(capture);
        }

        pub fn queryLogFromCapture(capture: *const OuterProofCapture) Error!u32 {
            const logs = capture.column_log_sizes[CHILD_COMMITMENT_COUNT - 1];
            if (logs.len == 0) return error.CaptureShapeMismatch;
            var query_log: u32 = 0;
            for (logs) |log_size| {
                if (log_size <= outer_admission.LOG_BLOWUP_FACTOR or
                    log_size > outer_admission.MAX_DOMAIN_LOG)
                {
                    return error.CaptureShapeMismatch;
                }
                query_log = @max(query_log, log_size);
            }
            if (query_log >= 32 or
                capture.trace_paths[CHILD_COMMITMENT_COUNT - 1].path_depth != query_log)
            {
                return error.CaptureShapeMismatch;
            }
            // A recursive parent commits components with distinct native log
            // sizes into the composition tree. Query indices are sampled over
            // the authenticated maximum tree depth; shorter columns retain
            // their own log sizes and are opened through the same tree. Requiring
            // every column to equal the maximum was a leaf-only assumption.
            return query_log;
        }

        pub fn transcriptReplayIdentity(
            value: *const TemporalChildTranscriptReplayV2,
        ) Digest {
            var hash = IdentityHasher.init(TRANSCRIPT_REPLAY_ID_DOMAIN);
            hash.addU32(value.format_version);
            hash.addU32(value.schema_version);
            hash.addU32(value.fri_round_count);
            hash.addU32(value.query_count);
            hash.addU32(value.relation_draw_count);
            hash.digest(value.publication_id);
            hash.digest(value.witness_id);
            hash.digest(value.capture_id);
            hash.digest(value.transcript_prefix_id);
            hash.sha(value.manifest_sha_id);
            hash.digest(value.pre_core_digest);
            hash.addU32(value.pre_core_draw_count);
            hash.qm31(value.composition_randomness);
            hash.qm31(value.oods_seed);
            hash.qm31(value.deep_randomness);
            for (value.fri_alphas[0..value.fri_round_count]) |alpha|
                hash.qm31(alpha);
            for (value.raw_queries) |query| hash.addU32(query);
            hash.digest(value.final_digest);
            hash.addU32(value.final_draw_count);
            return hash.finalize();
        }

        pub fn shaWords(value: [32]u8) [8]u32 {
            var result: [8]u32 = undefined;
            for (&result, 0..) |*word, index|
                word.* = std.mem.readInt(u32, value[index * 4 ..][0..4], .little);
            return result;
        }

        pub fn publicFromPair(
            pair: *const PairAuthority,
            authenticated: temporal.RootAuthenticatedTemporalPairV2,
        ) Error!TemporalParentPublicV2 {
            const authority = &pair.prepared_root.authority_snapshot;
            const root = authenticated.pair;
            var child_kinds: [temporal.CHILD_COUNT]temporal.ProofKind = undefined;
            var child_statement_ids: [temporal.CHILD_COUNT]Digest = undefined;
            for (
                &child_kinds,
                &child_statement_ids,
                &authority.children,
            ) |*kind, *statement_id, *child| {
                kind.* = child.kind;
                statement_id.* = try child.statementId();
            }
            var result = TemporalParentPublicV2{
                .parent_height = root.parent_height,
                .parent_node_index = root.parent_node_index,
                .pair_authority_id = pair.authority_id,
                .adjacency_id = pair.adjacency_id,
                .context_id = root.context_id,
                .node_id = root.node_id,
                .record_id = root.record_id,
                .session_id = root.session_id,
                .job_id = root.job_id,
                .aggregator_vk_id = root.aggregator_vk_id,
                .child_kinds = child_kinds,
                .child_ids = root.child_ids,
                .child_publication_ids = .{
                    pair.source_bindings[0].source_publication_id,
                    pair.source_bindings[1].source_publication_id,
                },
                .child_statement_ids = child_statement_ids,
                .parent_statement_id = root.parent_statement_id,
                .identity = undefined,
            };
            result.identity = publicIdentity(&result);
            try result.validate();
            return result;
        }

        pub fn publicIdentity(value: *const TemporalParentPublicV2) Digest {
            var hash = IdentityHasher.init(PUBLIC_ID_DOMAIN);
            hash.addU32(value.format_version);
            hash.addU32(value.schema_version);
            hash.addU32(@intFromEnum(value.status));
            hash.addU32(value.parent_height);
            hash.addU64(value.parent_node_index);
            hash.digest(value.pair_authority_id);
            hash.digest(value.adjacency_id);
            hash.digest(value.context_id);
            hash.digest(value.node_id);
            hash.digest(value.record_id);
            hash.digest(value.session_id);
            hash.digest(value.job_id);
            hash.digest(value.aggregator_vk_id);
            for (value.child_kinds) |kind| hash.addU32(@intFromEnum(kind));
            for (value.child_ids) |id| hash.digest(id);
            for (value.child_publication_ids) |id| hash.digest(id);
            for (value.child_statement_ids) |id| hash.digest(id);
            hash.digest(value.parent_statement_id);
            return hash.finalize();
        }

        pub fn statementSourceIdentity(value: *const PreparedRows10Through11V2) Digest {
            var hash = IdentityHasher.init(STATEMENT_SOURCE_ID_DOMAIN);
            hash.addU32(value.format_version);
            hash.addU32(value.schema_version);
            hash.addU32(@intFromEnum(value.status));
            hash.digest(value.public.identity);
            hash.words(&value.left_words);
            hash.words(&value.right_words);
            hash.words(&value.parent_words);
            hash.sha(value.range.source_authority_digest);
            hash.addU64(value.range.request_count);
            hash.sha(value.circuit_evaluation.circuit_identity);
            return hash.finalize();
        }

        pub fn rowAuthorityIdentity(value: *const Rows10Through17AuthorityV2) Digest {
            var hash = IdentityHasher.init(ROW_AUTHORITY_ID_DOMAIN);
            hash.addU32(value.format_version);
            hash.addU32(value.schema_version);
            hash.addU32(value.row_count);
            hash.addU64(value.row_mask);
            for (value.active_domain_masks) |mask| hash.addU64(mask);
            for (value.owners) |owner| hash.addU32(@intFromEnum(owner));
            hash.digest(value.statement_source_id);
            hash.digest(value.pair_authority_id);
            hash.sha(value.inactive_source_sha_id);
            hash.sha(value.inactive_prepared_sha_id);
            return hash.finalize();
        }
    };
}
