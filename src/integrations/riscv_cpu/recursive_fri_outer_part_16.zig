//! Cohesive internal authority extracted from recursive_fri_outer.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const stwo_core = context.d_stwo_core;
        const M31 = context.d_M31;
        const QM31 = context.d_QM31;
        const recursion = context.d_recursion;
        const outer_admission = context.d_outer_admission;
        const air = context.d_air;
        const manifest_mod = context.d_manifest_mod;
        const universal_manifest = context.d_universal_manifest;
        const range_bridge = context.d_range_bridge;
        const universal = context.d_universal;
        const Engine = context.d_Engine;
        const POSEIDON2_ROSTER_ROW = context.d_POSEIDON2_ROSTER_ROW;
        const POSEIDON2_PARTIAL_COUNT = context.d_POSEIDON2_PARTIAL_COUNT;
        const RELATION_REPLAY_FORMAT_VERSION = context.d_RELATION_REPLAY_FORMAT_VERSION;
        const RELATION_REPLAY_DOMAIN = context.d_RELATION_REPLAY_DOMAIN;
        const RelationReplayReceiptV1 = context.d_RelationReplayReceiptV1;
        const Poseidon2AuxiliaryClaimSealV1 = context.d_Poseidon2AuxiliaryClaimSealV1;
        const VerifiedOuterProofV1 = context.d_VerifiedOuterProofV1;
        const FORMAT_VERSION = context.d_FORMAT_VERSION;
        const TRANSCRIPT_DOMAIN = context.d_TRANSCRIPT_DOMAIN;
        const OUTER_CONFIG = context.d_OUTER_CONFIG;
        const AIR_PROGRAM_ID_DOMAIN = context.d_AIR_PROGRAM_ID_DOMAIN;
        const MANIFEST_ID_DOMAIN = context.d_MANIFEST_ID_DOMAIN;
        const VERIFICATION_KEY_ID_DOMAIN = context.d_VERIFICATION_KEY_ID_DOMAIN;
        const Receipt = context.d_Receipt;
        const Claims = context.d_Claims;
        const Authority = context.d_Authority;
        const validatePoseidon2AuxiliaryClaimCustody = context.d_validatePoseidon2AuxiliaryClaimCustody;
        const digestWords = context.d_digestWords;

        test "outer verifier Poseidon2 auxiliary custody rejects every partial alias" {
            const fixture = try auxiliaryClaimPublicationFixture();
            const original = fixture.publication;
            try validateAuxiliaryFixture(&original);
            try std.testing.expectEqual(
                original.receipt.claimed_sums[POSEIDON2_ROSTER_ROW],
                qm31Wire(original.poseidon2_partials[0].add(
                    original.poseidon2_partials[1],
                )),
            );

            inline for (0..POSEIDON2_PARTIAL_COUNT) |partial_index| {
                var mutated = original;
                mutated.poseidon2_partials[partial_index] =
                    mutated.poseidon2_partials[partial_index].add(QM31.one());
                try std.testing.expectError(
                    error.AuxiliaryClaimTotalMismatch,
                    validateAuxiliaryFixture(&mutated),
                );
            }

            var swapped = original;
            std.mem.swap(
                QM31,
                &swapped.poseidon2_partials[0],
                &swapped.poseidon2_partials[1],
            );
            try std.testing.expect(
                swapped.poseidon2_partials[0].add(swapped.poseidon2_partials[1]).eql(
                    original.poseidon2_partials[0].add(original.poseidon2_partials[1]),
                ),
            );
            try std.testing.expectError(
                error.AuxiliaryClaimSealMismatch,
                validateAuxiliaryFixture(&swapped),
            );
            const swapped_seal = try Poseidon2AuxiliaryClaimSealV1.initVerified(
                &swapped.receipt,
                swapped.seal,
                swapped.relation_replay.identity,
                swapped.poseidon2_partials,
            );
            try std.testing.expect(!std.meta.eql(
                swapped_seal,
                original.auxiliary_claim_seal,
            ));

            var stale_seal = original;
            stale_seal.auxiliary_claim_seal.digest[0] ^= 1;
            try std.testing.expectError(
                error.AuxiliaryClaimSealMismatch,
                validateAuxiliaryFixture(&stale_seal),
            );

            const delta = QM31.fromU32Unchecked(1, 2, 3, 4);
            var corrective = original;
            corrective.poseidon2_partials[0] =
                corrective.poseidon2_partials[0].add(delta);
            corrective.poseidon2_partials[1] =
                corrective.poseidon2_partials[1].sub(delta);
            try std.testing.expect(
                corrective.poseidon2_partials[0].add(
                    corrective.poseidon2_partials[1],
                ).eql(original.poseidon2_partials[0].add(
                    original.poseidon2_partials[1],
                )),
            );
            try std.testing.expectError(
                error.AuxiliaryClaimSealMismatch,
                validateAuxiliaryFixture(&corrective),
            );
            const corrective_seal = try Poseidon2AuxiliaryClaimSealV1.initVerified(
                &corrective.receipt,
                corrective.seal,
                corrective.relation_replay.identity,
                corrective.poseidon2_partials,
            );
            try std.testing.expect(!std.meta.eql(
                corrective_seal,
                original.auxiliary_claim_seal,
            ));

            var noncanonical = original;
            noncanonical.poseidon2_partials[0].c0.a = M31.fromU32Unchecked(
                stwo_core.fields.m31.Modulus,
            );
            try std.testing.expectError(
                error.AuxiliaryClaimNonCanonical,
                validateAuxiliaryFixture(&noncanonical),
            );
        }

        test "outer verifier relation replay rejects checkpoint and identity mutation" {
            const fixture = try auxiliaryClaimPublicationFixture();
            const original = fixture.publication;
            const relations = try original.relation_replay.validateAndReplay(
                &original.receipt,
                original.seal,
                fixture.interaction_root,
            );
            try relations.validate();

            var checkpoint_digest = original;
            checkpoint_digest.relation_replay.pre_relation_channel.digest[0] ^= 1;
            try std.testing.expectError(
                error.RelationReplayCheckpointMismatch,
                checkpoint_digest.relation_replay.validateAndReplay(
                    &checkpoint_digest.receipt,
                    checkpoint_digest.seal,
                    fixture.interaction_root,
                ),
            );

            var checkpoint_draw = original;
            checkpoint_draw.relation_replay.pre_relation_channel.draw_count = 1;
            try std.testing.expectError(
                error.RelationReplayCheckpointMismatch,
                checkpoint_draw.relation_replay.validateAndReplay(
                    &checkpoint_draw.receipt,
                    checkpoint_draw.seal,
                    fixture.interaction_root,
                ),
            );

            var stale_identity = original;
            stale_identity.relation_replay.identity[0] ^= 1;
            try std.testing.expectError(
                error.RelationReplayIdentityMismatch,
                stale_identity.relation_replay.validateAndReplay(
                    &stale_identity.receipt,
                    stale_identity.seal,
                    fixture.interaction_root,
                ),
            );
            try std.testing.expectError(
                error.AuxiliaryClaimSealMismatch,
                validateAuxiliaryFixture(&stale_identity),
            );

            var manifest_alias = original;
            manifest_alias.receipt.manifest_id[0] ^= 1;
            try std.testing.expectError(
                error.RelationReplayManifestMismatch,
                manifest_alias.relation_replay.validateAndReplay(
                    &manifest_alias.receipt,
                    manifest_alias.seal,
                    fixture.interaction_root,
                ),
            );
        }

        pub fn validateAuxiliaryFixture(value: *const VerifiedOuterProofV1) !void {
            try validatePoseidon2AuxiliaryClaimCustody(
                &value.receipt,
                value.seal,
                value.relation_replay.identity,
                value.poseidon2_partials,
                value.auxiliary_claim_seal,
            );
        }

        pub const AuxiliaryClaimPublicationFixture = struct {
            publication: VerifiedOuterProofV1,
            interaction_root: recursion.poseidon2_channel.Digest,
        };

        pub fn auxiliaryClaimPublicationFixture() !AuxiliaryClaimPublicationFixture {
            const partials = [POSEIDON2_PARTIAL_COUNT]QM31{
                QM31.fromU32Unchecked(11, 13, 17, 19),
                QM31.fromU32Unchecked(23, 29, 31, 37),
            };
            const zero_wire = recursion.fixed_wire.Qm31Wire{ 0, 0, 0, 0 };
            var claimed_sums = [_]recursion.fixed_wire.Qm31Wire{zero_wire} **
                outer_admission.CLAIMED_SUM_COUNT;
            claimed_sums[POSEIDON2_ROSTER_ROW] = qm31Wire(
                partials[0].add(partials[1]),
            );
            var component_log_sizes = [_]u32{4} **
                outer_admission.CLAIMED_SUM_COUNT;
            component_log_sizes[
                @intFromEnum(
                    air.universal_roster.Component.range_check_8_8,
                )
            ] = range_bridge.LOG_SIZE;
            const manifest = try universal_manifest.build(component_log_sizes);
            var receipt = outer_admission.VerifierReceiptV1{
                .air_program_id = auxiliaryTestDigest(11),
                .manifest_id = outerManifestId(&manifest),
                .statement_id = auxiliaryTestDigest(51),
                .verification_key_id = auxiliaryTestDigest(71),
                .component_log_sizes = component_log_sizes,
                .pre_core_channel = .{ .digest = auxiliaryTestDigest(91) },
                .claimed_sums = claimed_sums,
                .verifier_input_boundary = zero_wire,
                .wire_closure = .{ zero_wire, zero_wire },
            };
            try receipt.validate();
            const seal = outer_admission.VerifierSealV1{
                .profile_id = auxiliaryTestDigest(111),
                .capture_id = auxiliaryTestDigest(131),
                .receipt_id = auxiliaryTestDigest(151),
                .transcript_id = auxiliaryTestDigest(171),
                .claimed_sums_id = auxiliaryTestDigest(191),
                .verifier_input_boundary = zero_wire,
            };
            try seal.validate();
            const pre_relation_channel = outer_admission.ChannelCheckpointV1{
                .digest = auxiliaryTestDigest(211),
            };
            const interaction_root = auxiliaryTestDigest(231);
            receipt.pre_core_channel = try RelationReplayReceiptV1.expectedPreCoreChannel(
                pre_relation_channel,
                &receipt,
                interaction_root,
            );
            try receipt.validate();
            const relation_replay = try RelationReplayReceiptV1.initVerified(
                pre_relation_channel,
                &receipt,
                seal,
                interaction_root,
            );
            var result: VerifiedOuterProofV1 = undefined;
            @memset(std.mem.asBytes(&result), 0);
            result.receipt = receipt;
            result.seal = seal;
            result.relation_replay = relation_replay;
            result.poseidon2_partials = partials;
            result.auxiliary_claim_seal = try Poseidon2AuxiliaryClaimSealV1.initVerified(
                &receipt,
                seal,
                relation_replay.identity,
                partials,
            );
            return .{
                .publication = result,
                .interaction_root = interaction_root,
            };
        }

        pub fn auxiliaryTestDigest(seed: u32) recursion.poseidon2_channel.Digest {
            var result: recursion.poseidon2_channel.Digest = undefined;
            for (&result, 0..) |*word, index|
                word.* = seed + @as(u32, @intCast(index));
            return result;
        }

        pub fn verifierReceipt(
            authority: *const Authority,
            claim_vector: *const manifest_mod.ClaimVector,
            claims: Claims,
            pre_core_channel: outer_admission.ChannelCheckpointV1,
            preprocessed_root: recursion.poseidon2_channel.Digest,
            statement_id: recursion.poseidon2_channel.Digest,
        ) !outer_admission.VerifierReceiptV1 {
            try authority.manifest.validate();
            try claim_vector.validate(&authority.manifest);
            if (authority.manifest.roster_count != outer_admission.CLAIMED_SUM_COUNT or
                authority.vm_air == null or
                authority.segment_transcript_inputs == null)
            {
                return error.AuthorityMismatch;
            }

            var component_log_sizes: [outer_admission.CLAIMED_SUM_COUNT]u32 = undefined;
            var claimed_sums: [outer_admission.CLAIMED_SUM_COUNT]recursion.fixed_wire.Qm31Wire = undefined;
            for (0..outer_admission.CLAIMED_SUM_COUNT) |row| {
                const placement = authority.manifest.placements[row] orelse
                    return error.AuthorityMismatch;
                if (placement.claimed_sum_index != row)
                    return error.AuthorityMismatch;
                component_log_sizes[row] = placement.geometry.log_size;
                claimed_sums[row] = qm31Wire(claim_vector.values[row]);
            }

            const air_program_id = try outerAirProgramId(authority);
            const manifest_id = outerManifestId(&authority.manifest);
            const receipt = outer_admission.VerifierReceiptV1{
                .scope = .verifier_subsystem,
                .air_program_id = air_program_id,
                .manifest_id = manifest_id,
                .statement_id = statement_id,
                .verification_key_id = outerVerificationKeyId(
                    air_program_id,
                    manifest_id,
                    preprocessed_root,
                ),
                .component_log_sizes = component_log_sizes,
                .pre_core_channel = pre_core_channel,
                .claimed_sums = claimed_sums,
                .wire_closure = .{
                    qm31Wire(claims.input_wire),
                    qm31Wire(claims.public_boundaries.wire),
                },
                .verifier_input_boundary = qm31Wire(claims.public_boundaries.verifier_input),
                .interaction_pow_nonce = 0,
            };
            try receipt.validate();
            return receipt;
        }

        /// Stable identity of the complete verifier-owned AIR authority, distinct
        /// from proof-dependent roots and statement words.  Every absorbed value is
        /// already validated by `Authority.init`; unrestricted SHA words cross the
        /// channel's injective u32 encoding rather than being reduced into M31.
        pub fn outerAirProgramId(
            authority: *const Authority,
        ) !recursion.poseidon2_channel.Digest {
            const vm_air = authority.vm_air orelse return error.AuthorityMismatch;
            const inputs = authority.segment_transcript_inputs orelse
                return error.AuthorityMismatch;
            var channel = recursion.poseidon2_channel.Channel{};
            channel.mixU32s(&.{
                AIR_PROGRAM_ID_DOMAIN,
                FORMAT_VERSION,
                outer_admission.FORMAT_VERSION,
            });
            channel.mixU32s(&digestWords(authority.manifest.seal));
            channel.mixU32s(&digestWords(authority.circuit.identity_digest));
            channel.mixU32s(&digestWords(authority.pcs_circuit.identity_digest));
            channel.mixU32s(&authority.vm_schedule.authority_digest);
            channel.mixU32s(&authority.recursion_schedule.authority_digest);
            channel.mixU32s(&digestWords(authority.lowering_plan.authority_digest));
            channel.mixU32s(&digestWords(vm_air.prepared.circuit.identity_digest));
            channel.mixU32s(&digestWords(
                vm_air.prepared.preprocessing.authority_digest,
            ));
            channel.mixU32s(&digestWords(
                inputs.statement.authority.circuit.identity_digest,
            ));
            channel.mixU32s(&digestWords(
                inputs.statement.authority.lowering_graph.identity_digest,
            ));
            channel.mixU32s(&digestWords(inputs.public.source.authority_seal));
            return channel.digestWords();
        }

        pub fn outerManifestId(
            manifest: *const manifest_mod.Manifest,
        ) recursion.poseidon2_channel.Digest {
            return manifestIdForSeal(manifest.seal);
        }

        /// Single authority for the role-neutral outer-manifest identity consumed by
        /// relation replay and downstream binary composition.
        pub fn manifestIdForSeal(
            manifest_seal: [32]u8,
        ) recursion.poseidon2_channel.Digest {
            return recursion.poseidon2_channel.hashBytes(
                &manifest_seal,
                MANIFEST_ID_DOMAIN,
            );
        }

        pub fn verifiedStatementId(
            words: *const recursion.span_statement.StatementWords,
        ) !recursion.poseidon2_channel.Digest {
            _ = try recursion.span_statement.SpanStatement.fromCanonicalWords(words);
            var canonical: [recursion.span_statement.SPAN_STATEMENT_CANONICAL_WORDS]u32 =
                undefined;
            for (words, &canonical) |word, *target| {
                const value = word.toU32();
                if (value >= stwo_core.fields.m31.Modulus)
                    return error.CanonicalWordNonCanonical;
                target.* = value;
            }
            return recursion.protocol.statementId(&canonical);
        }

        pub fn outerVerificationKeyId(
            air_program_id: recursion.poseidon2_channel.Digest,
            manifest_id: recursion.poseidon2_channel.Digest,
            preprocessed_root: recursion.poseidon2_channel.Digest,
        ) recursion.poseidon2_channel.Digest {
            var channel = recursion.poseidon2_channel.Channel{};
            channel.mixU32s(&.{
                VERIFICATION_KEY_ID_DOMAIN,
                FORMAT_VERSION,
                outer_admission.FORMAT_VERSION,
                OUTER_CONFIG.pow_bits,
                OUTER_CONFIG.fri_config.log_blowup_factor,
                OUTER_CONFIG.fri_config.log_last_layer_degree_bound,
                OUTER_CONFIG.fri_config.n_queries,
                OUTER_CONFIG.fri_config.fold_step,
            });
            channel.mixU32s(&air_program_id);
            channel.mixU32s(&manifest_id);
            channel.mixU32s(&preprocessed_root);
            return channel.digestWords();
        }

        pub fn qm31Wire(value: QM31) recursion.fixed_wire.Qm31Wire {
            var result: recursion.fixed_wire.Qm31Wire = undefined;
            for (value.toM31Array(), &result) |coordinate, *word|
                word.* = coordinate.toU32();
            return result;
        }

        pub fn qm31FromWire(value: recursion.fixed_wire.Qm31Wire) QM31 {
            return QM31.fromU32Unchecked(value[0], value[1], value[2], value[3]);
        }

        pub const RelationReplayResult = struct {
            relations: universal.UniversalRelations,
            final_channel: outer_admission.ChannelCheckpointV1,
        };

        /// Allocation-free replay of the exact transcript interval owned by the
        /// relation receipt. Receipt validation establishes canonical fixed-wire
        /// limbs before they are promoted back into QM31 values.
        pub fn replayRelationTranscript(
            pre_relation_channel: outer_admission.ChannelCheckpointV1,
            receipt: *const outer_admission.VerifierReceiptV1,
            interaction_root: recursion.poseidon2_channel.Digest,
        ) !RelationReplayResult {
            try receipt.validate();
            try validateAuxiliaryDigest(interaction_root);
            const manifest = try universal_manifest.build(receipt.component_log_sizes);
            if (!std.meta.eql(outerManifestId(&manifest), receipt.manifest_id))
                return error.RelationReplayManifestMismatch;

            var channel = Engine.Channel{
                .digest = pre_relation_channel.digest,
                .n_draws = pre_relation_channel.draw_count,
            };
            var draws: [universal.DRAW_COUNT]QM31 = undefined;
            for (0..universal.RELATION_COUNT) |relation_index| {
                const words = channel.drawU32s();
                draws[2 * relation_index] = QM31.fromU32Unchecked(
                    words[0],
                    words[1],
                    words[2],
                    words[3],
                );
                draws[2 * relation_index + 1] = QM31.fromU32Unchecked(
                    words[4],
                    words[5],
                    words[6],
                    words[7],
                );
            }
            const relations = universal.UniversalRelations.fromDraws(&draws);
            try relations.validate();

            var claims = try manifest_mod.ClaimVector.init(&manifest);
            for (0..outer_admission.CLAIMED_SUM_COUNT) |row| {
                try claims.bind(
                    @enumFromInt(row),
                    qm31FromWire(receipt.claimed_sums[row]),
                );
            }
            try claims.sealClaims(&manifest);
            try claims.mixInteractionClaims(&manifest, &channel);
            channel.mixU32s(&.{ TRANSCRIPT_DOMAIN, FORMAT_VERSION, 2 });
            channel.mixFelts(&.{
                qm31FromWire(receipt.wire_closure[0]),
                qm31FromWire(receipt.wire_closure[1]),
                qm31FromWire(receipt.verifier_input_boundary),
            });
            recursion.engine.MerkleChannel.mixRoot(&channel, interaction_root);
            return .{
                .relations = relations,
                .final_channel = .{
                    .digest = channel.digestWords(),
                    .draw_count = channel.n_draws,
                },
            };
        }

        pub fn deriveRelationReplayIdentity(
            pre_relation_channel: outer_admission.ChannelCheckpointV1,
            receipt: *const outer_admission.VerifierReceiptV1,
            verifier_seal: outer_admission.VerifierSealV1,
            interaction_root: recursion.poseidon2_channel.Digest,
        ) recursion.poseidon2_channel.Digest {
            var channel = recursion.poseidon2_channel.Channel{};
            channel.mixU32s(&.{
                RELATION_REPLAY_DOMAIN,
                RELATION_REPLAY_FORMAT_VERSION,
                FORMAT_VERSION,
                universal.FORMAT_VERSION,
                universal.RELATION_COUNT,
                universal.DRAW_COUNT,
                outer_admission.CLAIMED_SUM_COUNT,
            });
            channel.mixU32s(&recursion.poseidon2_channel.parameterId());
            channel.mixU32s(&pre_relation_channel.digest);
            channel.mixU32s(&.{pre_relation_channel.draw_count});
            channel.mixU32s(&receipt.pre_core_channel.digest);
            channel.mixU32s(&.{receipt.pre_core_channel.draw_count});
            channel.mixU32s(&receipt.manifest_id);
            channel.mixU32s(&verifier_seal.capture_id);
            channel.mixU32s(&verifier_seal.receipt_id);
            channel.mixU32s(&verifier_seal.claimed_sums_id);
            channel.mixU32s(&interaction_root);
            return channel.digestWords();
        }

        pub fn validateAuxiliaryQm31(value: QM31) !void {
            for (value.toM31Array()) |coordinate| {
                if (coordinate.toU32() >= stwo_core.fields.m31.Modulus)
                    return error.AuxiliaryClaimNonCanonical;
            }
        }

        pub fn validateAuxiliaryDigest(
            digest: recursion.poseidon2_channel.Digest,
        ) !void {
            var aggregate: u32 = 0;
            for (digest) |word| {
                if (word >= stwo_core.fields.m31.Modulus)
                    return error.AuxiliaryClaimNonCanonical;
                aggregate |= word;
            }
            if (aggregate == 0) return error.AuxiliaryClaimSealMismatch;
        }
    };
}
