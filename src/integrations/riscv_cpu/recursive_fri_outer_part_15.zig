//! Cohesive internal authority extracted from recursive_fri_outer.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const stwo_core = context.d_stwo_core;
        const QM31 = context.d_QM31;
        const recursion = context.d_recursion;
        const outer_admission = context.d_outer_admission;
        const global_closure = context.d_global_closure;
        const segment_range_authority = context.d_segment_range_authority;
        const circuit_mod = context.d_circuit_mod;
        const pcs_circuit_mod = context.d_pcs_circuit_mod;
        const manifest_mod = context.d_manifest_mod;
        const shared_provider = context.d_shared_provider;
        const universal = context.d_universal;
        const Engine = context.d_Engine;
        const OuterProofCapture = context.d_OuterProofCapture;
        const RelationReplayReceiptV1 = context.d_RelationReplayReceiptV1;
        const Poseidon2AuxiliaryClaimSealV1 = context.d_Poseidon2AuxiliaryClaimSealV1;
        const VerifiedOuterProofV1 = context.d_VerifiedOuterProofV1;
        const SegmentProviderClaimV2 = context.d_SegmentProviderClaimV2;
        const SegmentGlobalClosureReceiptV2 = context.d_SegmentGlobalClosureReceiptV2;
        const VerifiedOuterProofV2 = context.d_VerifiedOuterProofV2;
        const CapturePublication = context.d_CapturePublication;
        const VerifierScheme = context.d_VerifierScheme;
        const OUTER_CONFIG = context.d_OUTER_CONFIG;
        const VerifierPlans = context.d_VerifierPlans;
        const SegmentTranscriptInputs = context.d_SegmentTranscriptInputs;
        const PublicBoundaryClaims = context.d_PublicBoundaryClaims;
        const Claims = context.d_Claims;
        const RelationDomain = context.d_RelationDomain;
        const relationDomainBit = context.d_relationDomainBit;
        const ExactClosurePreflightV2 = context.d_ExactClosurePreflightV2;
        const ScheduleFacts = context.d_ScheduleFacts;
        const Authority = context.d_Authority;
        const VerificationMetrics = context.d_VerificationMetrics;
        const verifierReceipt = context.d_verifierReceipt;
        const verifiedStatementId = context.d_verifiedStatementId;
        const vmInputClaim = context.d_vmInputClaim;
        const compositionControlClaim = context.d_compositionControlClaim;
        const Components = context.d_Components;
        const verifierInputBoundaryClaim = context.d_verifierInputBoundaryClaim;
        const claimVector = context.d_claimVector;
        const mixAuthority = context.d_mixAuthority;
        const mixPublicBoundaries = context.d_mixPublicBoundaries;
        const rebuildExactSegmentClosureV2 = context.d_rebuildExactSegmentClosureV2;
        const segmentClosureReceiptIdentity = context.d_segmentClosureReceiptIdentity;
        const requireZeroDomainClosure = context.d_requireZeroDomainClosure;
        const verifyGlobalClosure = context.d_verifyGlobalClosure;
        const digestWords = context.d_digestWords;
        const stageTelemetryBegin = context.d_stageTelemetryBegin;
        const stageTelemetryEnd = context.d_stageTelemetryEnd;
        const assertPreprocessedRoot = context.d_assertPreprocessedRoot;
        const commitVerifierTree = context.d_commitVerifierTree;

        pub fn verifyCaptured(
            allocator: std.mem.Allocator,
            captured: *const recursion.captured_fri.Owned,
            profile: circuit_mod.Profile,
            pcs_profile: pcs_circuit_mod.Profile,
            trace_tree_heights: []const u32,
            column_log_sizes: []const []const u32,
            schedule_facts: ScheduleFacts,
            vm_air: ?*const recursion.vm_air_composition_circuit.Prepared,
            verifier_plans: ?VerifierPlans,
            segment_transcript: ?SegmentTranscriptInputs,
            proof_in: *recursion.engine.Proof,
            proof_owned: *bool,
            claims: Claims,
            publication: ?CapturePublication,
        ) !VerificationMetrics {
            if (!proof_owned.*) return error.ProofAlreadyConsumed;
            const commitments = proof_in.commitment_scheme_proof.commitments.items;
            if (commitments.len != manifest_mod.TREE_COUNT + 1)
                return error.InvalidProofShape;

            var circuit = try circuit_mod.build(allocator, profile);
            defer circuit.deinit();
            var pcs_circuit = try pcs_circuit_mod.build(allocator, pcs_profile);
            defer pcs_circuit.deinit();
            stageTelemetryBegin("verifier.authority-init");
            var authority_timer = try std.time.Timer.start();
            var authority = try Authority.init(
                allocator,
                &circuit,
                &pcs_circuit,
                trace_tree_heights,
                column_log_sizes,
                schedule_facts,
                vm_air,
                verifier_plans,
                segment_transcript,
                null,
                0,
            );
            stageTelemetryEnd("verifier.authority-init", authority_timer.read());
            defer authority.deinit();
            try assertPreprocessedRoot(
                allocator,
                &authority,
                commitments[manifest_mod.PREPROCESSED_TREE_INDEX],
            );

            var scheme = try VerifierScheme.init(allocator, OUTER_CONFIG);
            defer scheme.deinit(allocator);
            var channel = Engine.Channel{};
            try commitVerifierTree(
                allocator,
                &scheme,
                &authority.manifest,
                manifest_mod.PREPROCESSED_TREE_INDEX,
                commitments[manifest_mod.PREPROCESSED_TREE_INDEX],
                &channel,
            );
            try commitVerifierTree(
                allocator,
                &scheme,
                &authority.manifest,
                manifest_mod.MAIN_TREE_INDEX,
                commitments[manifest_mod.MAIN_TREE_INDEX],
                &channel,
            );
            try authority.manifest.mixStatementPrefix(&channel);
            mixAuthority(&channel, &authority);
            const pre_relation_channel = outer_admission.ChannelCheckpointV1{
                .digest = channel.digestWords(),
                .draw_count = channel.n_draws,
            };
            const relations = try universal.UniversalRelations.draw(allocator, &channel);
            const provider_relations = try shared_provider.SharedProviderRelations.init(
                &relations,
            );
            const expected_vm_input = try vmInputClaim(&authority, &relations);
            if (!expected_vm_input.eql(claims.vm_input))
                return error.AuthorityMismatch;
            const expected_composition_control = try compositionControlClaim(
                &authority,
                &relations,
            );
            if (!expected_composition_control.eql(claims.composition_control))
                return error.AuthorityMismatch;
            const expected_boundaries = PublicBoundaryClaims{
                .wire = try authority.lowering_plan.publicBoundaryClaim(
                    .segment_leaf,
                    &relations,
                ),
                .verifier_input = try verifierInputBoundaryClaim(
                    &authority,
                    &relations,
                ),
            };
            if (!expected_boundaries.eql(claims.public_boundaries))
                return error.AuthorityMismatch;
            var claim_vector = try claimVector(&authority.manifest, claims);
            stageTelemetryBegin("verifier.global-closure");
            var closure_timer = try std.time.Timer.start();
            try claims.verifyWireClosure();
            try verifyGlobalClosure(&claim_vector, claims.public_boundaries);
            stageTelemetryEnd("verifier.global-closure", closure_timer.read());
            var verification_metrics = VerificationMetrics{};
            var exact_closure_preflight: ?ExactClosurePreflightV2 = null;
            if (authority.vm_air != null and
                authority.segment_transcript_inputs != null)
            {
                stageTelemetryBegin("verifier.exact-domain-closure");
                var exact_closure_timer = try std.time.Timer.start();
                exact_closure_preflight = try rebuildExactSegmentClosureV2(
                    allocator,
                    captured,
                    &authority,
                    &relations,
                    &provider_relations,
                    claims,
                    &claim_vector,
                );
                verification_metrics.exact_domain_closure_checked = true;
                verification_metrics.exact_domain_closure_ns =
                    exact_closure_timer.read();
                stageTelemetryEnd(
                    "verifier.exact-domain-closure",
                    verification_metrics.exact_domain_closure_ns,
                );
            }
            try claim_vector.mixInteractionClaims(&authority.manifest, &channel);
            mixPublicBoundaries(&channel, claims);
            try commitVerifierTree(
                allocator,
                &scheme,
                &authority.manifest,
                manifest_mod.INTERACTION_TREE_INDEX,
                commitments[manifest_mod.INTERACTION_TREE_INDEX],
                &channel,
            );
            const pre_core_channel = outer_admission.ChannelCheckpointV1{
                .digest = channel.digestWords(),
                .draw_count = channel.n_draws,
            };

            var components = try Components.init(
                &authority,
                &relations,
                &provider_relations,
                claims,
            );
            defer components.deinit();
            var gate = try manifest_mod.ProofGate.init(&authority.manifest);
            try components.append(&gate, &authority.manifest);
            try gate.sealGate(&authority.manifest);
            const proof = moveOwnedForVerifier(
                recursion.engine.Proof,
                proof_in,
                proof_owned,
            );
            stageTelemetryBegin("verifier.stark-verify");
            var stark_verify_timer = try std.time.Timer.start();
            if (publication) |destination| {
                var capture: OuterProofCapture = undefined;
                try stwo_core.verifier.verifyWithProofCapture(
                    recursion.engine.Hasher,
                    recursion.engine.MerkleChannel,
                    allocator,
                    try gate.verifierSlice(),
                    &channel,
                    &scheme,
                    proof,
                    &capture,
                );
                stageTelemetryEnd("verifier.stark-verify", stark_verify_timer.read());
                var capture_owned = true;
                errdefer if (capture_owned) capture.deinit(allocator);
                stageTelemetryBegin("verifier.capture-admission");
                var capture_admission_timer = try std.time.Timer.start();
                if (capture.commitments.len <= manifest_mod.PREPROCESSED_TREE_INDEX)
                    return error.InvalidProofShape;
                switch (destination) {
                    .capture => |capture_out| capture_out.* = capture,
                    else => {
                        const statement_inputs = authority.segment_transcript_inputs orelse
                            return error.AuthorityMismatch;
                        const statement_words =
                            statement_inputs.statement.prepared.statement_words;
                        const statement_id = try verifiedStatementId(&statement_words);
                        const receipt = try verifierReceipt(
                            &authority,
                            &claim_vector,
                            claims,
                            pre_core_channel,
                            capture.commitments[manifest_mod.PREPROCESSED_TREE_INDEX],
                            statement_id,
                        );
                        const seal = try outer_admission.deriveVerifierSeal(
                            &receipt,
                            &capture,
                        );
                        const relation_replay =
                            try RelationReplayReceiptV1.initVerified(
                                pre_relation_channel,
                                &receipt,
                                seal,
                                capture.commitments[
                                    manifest_mod.INTERACTION_TREE_INDEX
                                ],
                            );
                        // Core verification has succeeded. Only now may the native
                        // verifier publish the two row-34 provider coordinates that
                        // its reconstructed Claims value authenticated. They remain
                        // auxiliary to transcript/claim-vector V1.
                        const poseidon2_partials = claims.poseidon2;
                        const auxiliary_claim_seal =
                            try Poseidon2AuxiliaryClaimSealV1.initVerified(
                                &receipt,
                                seal,
                                relation_replay.identity,
                                poseidon2_partials,
                            );
                        // `deriveVerifierSeal` immediately above already performed
                        // the full capture-shape validation and transcript replay.
                        // Repeating `staged.validate()` here would rehash every query,
                        // path, and FRI value. Validate only the new custody record
                        // before the single publication assignment.
                        const staged = VerifiedOuterProofV1{
                            .capture = capture,
                            .receipt = receipt,
                            .seal = seal,
                            .statement_words = statement_words,
                            .relation_replay = relation_replay,
                            .poseidon2_partials = poseidon2_partials,
                            .auxiliary_claim_seal = auxiliary_claim_seal,
                        };
                        switch (destination) {
                            .verified => |verified_out| verified_out.* = staged,
                            .verified_v2 => |verified_out| {
                                const preflight = exact_closure_preflight orelse
                                    return error.SegmentClosurePublicationUnavailable;
                                var closure: SegmentGlobalClosureReceiptV2 = undefined;
                                try preflight.finalizeInto(
                                    receipt.manifest_id,
                                    seal.receipt_id,
                                    relation_replay.identity,
                                    &closure,
                                );
                                const staged_v2 = VerifiedOuterProofV2{
                                    .verified_v1 = staged,
                                    .global_closure = closure,
                                };
                                verified_out.* = staged_v2;
                            },
                            .capture => unreachable,
                        }
                    },
                }
                capture_owned = false;
                stageTelemetryEnd(
                    "verifier.capture-admission",
                    capture_admission_timer.read(),
                );
            } else {
                try stwo_core.verifier.verify(
                    recursion.engine.Hasher,
                    recursion.engine.MerkleChannel,
                    allocator,
                    try gate.verifierSlice(),
                    &channel,
                    &scheme,
                    proof,
                );
                stageTelemetryEnd("verifier.stark-verify", stark_verify_timer.read());
            }
            return verification_metrics;
        }

        /// Transfers one allocator-owning value into a fallible verifier before the
        /// verifier is called. The caller's owner bit changes in the same non-failing
        /// operation as the move, so an error returned after handoff cannot trigger a
        /// second deinitialization through the caller's cleanup path.
        pub fn moveOwnedForVerifier(
            comptime T: type,
            value: *T,
            owned: *bool,
        ) T {
            std.debug.assert(owned.*);
            const moved = value.*;
            value.* = undefined;
            owned.* = false;
            return moved;
        }

        test "fallible verifier handoff clears caller ownership atomically" {
            var value: u64 = 0x1234_5678_9abc_def0;
            var owned = true;
            const moved = moveOwnedForVerifier(u64, &value, &owned);
            try std.testing.expectEqual(@as(u64, 0x1234_5678_9abc_def0), moved);
            try std.testing.expect(!owned);
        }

        test "recursion Poseidon2 native leaf segment closure rejects cross-domain cancellation" {
            const delta = QM31.fromU32Unchecked(3, 5, 7, 11);
            var totals = [_]QM31{QM31.zero()} ** global_closure.DOMAIN_COUNT;
            totals[@intFromEnum(RelationDomain.recursion_wire)] = delta;
            totals[@intFromEnum(RelationDomain.recursion_verifier_input_word)] =
                delta.neg();
            var aggregate = QM31.zero();
            for (totals) |value| aggregate = aggregate.add(value);
            try std.testing.expect(aggregate.isZero());
            try std.testing.expectError(
                error.RelationDomainClosureMismatch,
                requireZeroDomainClosure(&totals),
            );
        }

        test "recursion Poseidon2 native leaf segment closure receipt mutations and atomicity" {
            const fixture = try segmentClosureReceiptFixture();
            try fixture.receipt.validate();

            const delta = QM31.fromU32Unchecked(13, 17, 19, 23);
            var cross_domain = fixture.receipt;
            const wire_index = @intFromEnum(RelationDomain.recursion_wire);
            const input_index = @intFromEnum(
                RelationDomain.recursion_verifier_input_word,
            );
            cross_domain.prefix_totals[wire_index] =
                cross_domain.prefix_totals[wire_index].add(delta);
            cross_domain.prefix_totals[input_index] =
                cross_domain.prefix_totals[input_index].sub(delta);
            cross_domain.closed_totals[wire_index] = delta;
            cross_domain.closed_totals[input_index] = delta.neg();
            cross_domain.closure_id = segmentClosureReceiptIdentity(&cross_domain);
            try std.testing.expectError(
                error.RelationDomainClosureMismatch,
                cross_domain.validate(),
            );

            var provider_snapshot = fixture.receipt;
            provider_snapshot.provider_claim.snapshot_id[0] ^= 1;
            try std.testing.expectError(
                error.SegmentClosureProviderMismatch,
                provider_snapshot.validate(),
            );

            var swapped_boundaries = fixture.receipt;
            std.mem.swap(
                global_closure.PublicBoundaryClaimV2,
                &swapped_boundaries.public_boundaries.wire,
                &swapped_boundaries.public_boundaries.verifier_input,
            );
            try std.testing.expectError(
                error.BoundaryKindMismatch,
                swapped_boundaries.validate(),
            );

            var stale_identity = fixture.receipt;
            stale_identity.closure_id[0] ^= 1;
            try std.testing.expectError(
                error.SegmentClosureIdentityMismatch,
                stale_identity.validate(),
            );

            var destination: SegmentGlobalClosureReceiptV2 = undefined;
            @memset(std.mem.asBytes(&destination), 0xa5);
            const before = std.mem.asBytes(&destination)[0..@sizeOf(
                SegmentGlobalClosureReceiptV2,
            )].*;
            try std.testing.expectError(
                error.AuxiliaryClaimSealMismatch,
                fixture.preflight.finalizeInto(
                    [_]u32{0} ** recursion.poseidon2_channel.RATE,
                    segmentClosureNativeDigest(71),
                    segmentClosureNativeDigest(91),
                    &destination,
                ),
            );
            try std.testing.expectEqualSlices(
                u8,
                &before,
                std.mem.asBytes(&destination),
            );
        }

        pub const SegmentClosureReceiptFixture = struct {
            preflight: ExactClosurePreflightV2,
            receipt: SegmentGlobalClosureReceiptV2,
        };

        pub fn segmentClosureReceiptFixture() !SegmentClosureReceiptFixture {
            const provider_value = QM31.fromU32Unchecked(29, 31, 37, 41);
            const wire_value = QM31.fromU32Unchecked(43, 47, 53, 59);
            const input_value = QM31.fromU32Unchecked(61, 67, 71, 73);
            const provider = try SegmentProviderClaimV2.init(
                segment_range_authority.SourceAuthority.pinned().identityDigest(),
                segmentClosureSha256("segment-provider-snapshot"),
                provider_value,
            );
            const wire_evidence = global_closure.BoundaryEvidenceV2{
                .source_authority_id = segmentClosureSha256("wire-source"),
                .snapshot_id = segmentClosureSha256("wire-snapshot"),
                .tuple_provenance_id = segmentClosureSha256("wire-tuples"),
                .tuple_count = 3,
                .claimed_sum = wire_value,
            };
            const input_evidence = global_closure.BoundaryEvidenceV2{
                .source_authority_id = segmentClosureSha256("input-source"),
                .snapshot_id = segmentClosureSha256("input-snapshot"),
                .tuple_provenance_id = segmentClosureSha256("input-tuples"),
                .tuple_count = 4,
                .claimed_sum = input_value,
            };
            const authorities = try global_closure.BoundaryAuthoritiesV2.init(
                try global_closure.BoundarySourceV2.init(.wire, wire_evidence),
                try global_closure.BoundarySourceV2.init(
                    .verifier_input,
                    input_evidence,
                ),
            );
            const prepared = try global_closure.prepareAuthorityV2(authorities);
            const public_boundaries = try global_closure.PublicBoundariesV2.init(
                &prepared,
                wire_evidence,
                input_evidence,
            );
            var prefix_totals = [_]QM31{QM31.zero()} ** global_closure.DOMAIN_COUNT;
            prefix_totals[@intFromEnum(RelationDomain.range_check_8_8)] =
                provider_value.neg();
            prefix_totals[@intFromEnum(RelationDomain.recursion_wire)] =
                wire_value.neg();
            prefix_totals[
                @intFromEnum(RelationDomain.recursion_verifier_input_word)
            ] = input_value.neg();
            const preflight = ExactClosurePreflightV2{
                .row_claims_id = segmentClosureSha256("row-claims"),
                .active_domain_mask = relationDomainBit(.range_check_8_8) |
                    relationDomainBit(.recursion_wire) |
                    relationDomainBit(.recursion_verifier_input_word),
                .prefix_totals = prefix_totals,
                .provider_claim = provider,
                .public_boundaries = public_boundaries,
                .closed_totals = [_]QM31{QM31.zero()} ** global_closure.DOMAIN_COUNT,
                .framework_total = QM31.zero(),
            };
            return .{
                .preflight = preflight,
                .receipt = try preflight.finalize(
                    segmentClosureNativeDigest(11),
                    segmentClosureNativeDigest(31),
                    segmentClosureNativeDigest(51),
                ),
            };
        }

        pub fn segmentClosureSha256(label: []const u8) [32]u8 {
            var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(label, &digest, .{});
            return digest;
        }

        pub fn segmentClosureNativeDigest(
            seed: u32,
        ) recursion.poseidon2_channel.Digest {
            var result: recursion.poseidon2_channel.Digest = undefined;
            for (&result, 0..) |*word, index|
                word.* = seed + @as(u32, @intCast(index));
            return result;
        }
    };
}
