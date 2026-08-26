//! Cohesive internal authority extracted from recursive_fri_outer.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const M31 = context.d_M31;
        const QM31 = context.d_QM31;
        const recursion = context.d_recursion;
        const global_closure = context.d_global_closure;
        const air = context.d_air;
        const vm_input_witness = context.d_vm_input_witness;
        const lowering = context.d_lowering;
        const manifest_v2 = context.d_manifest_v2;
        const universal = context.d_universal;
        const SEGMENT_GLOBAL_CLOSURE_FORMAT_VERSION = context.d_SEGMENT_GLOBAL_CLOSURE_FORMAT_VERSION;
        const V2_CORE_ROWS_18_34_PREFLIGHT_ID_DOMAIN = context.d_V2_CORE_ROWS_18_34_PREFLIGHT_ID_DOMAIN;
        const SEGMENT_PROVIDER_CLAIM_ID_DOMAIN = context.d_SEGMENT_PROVIDER_CLAIM_ID_DOMAIN;
        const SEGMENT_CLOSURE_INPUT_ID_DOMAIN = context.d_SEGMENT_CLOSURE_INPUT_ID_DOMAIN;
        const SEGMENT_CLOSURE_RECEIPT_ID_DOMAIN = context.d_SEGMENT_CLOSURE_RECEIPT_ID_DOMAIN;
        const SEGMENT_WIRE_BOUNDARY_SNAPSHOT_DOMAIN = context.d_SEGMENT_WIRE_BOUNDARY_SNAPSHOT_DOMAIN;
        const SEGMENT_WIRE_BOUNDARY_TUPLES_DOMAIN = context.d_SEGMENT_WIRE_BOUNDARY_TUPLES_DOMAIN;
        const SEGMENT_VERIFIER_INPUT_SNAPSHOT_DOMAIN = context.d_SEGMENT_VERIFIER_INPUT_SNAPSHOT_DOMAIN;
        const SEGMENT_VERIFIER_INPUT_TUPLES_DOMAIN = context.d_SEGMENT_VERIFIER_INPUT_TUPLES_DOMAIN;
        const SegmentProviderClaimV2 = context.d_SegmentProviderClaimV2;
        const SegmentGlobalClosureReceiptV2 = context.d_SegmentGlobalClosureReceiptV2;
        const V2CoreRows18Through34PreflightReceipt = context.d_V2CoreRows18Through34PreflightReceipt;
        const NATIVE_V2_CORE_FORMAT_VERSION = context.d_NATIVE_V2_CORE_FORMAT_VERSION;
        const NATIVE_V2_CORE_FIRST_ROW = context.d_NATIVE_V2_CORE_FIRST_ROW;
        const NATIVE_V2_CORE_LAST_ROW = context.d_NATIVE_V2_CORE_LAST_ROW;
        const NATIVE_V2_CORE_ROW_COUNT = context.d_NATIVE_V2_CORE_ROW_COUNT;
        const NATIVE_V2_CORE_AUTHORITY_ID_DOMAIN = context.d_NATIVE_V2_CORE_AUTHORITY_ID_DOMAIN;
        const NATIVE_V2_CORE_GENERATED_ID_DOMAIN = context.d_NATIVE_V2_CORE_GENERATED_ID_DOMAIN;
        const NativeSegmentCoreGeneratedV2 = context.d_NativeSegmentCoreGeneratedV2;
        const NativeSegmentCoreV2 = context.d_NativeSegmentCoreV2;
        const Claims = context.d_Claims;
        const RelationDomain = context.d_RelationDomain;
        const DomainAudit = context.d_DomainAudit;
        const relationDomainBit = context.d_relationDomainBit;
        const ClosureAudit = context.d_ClosureAudit;
        const ExactClosurePreflightV2 = context.d_ExactClosurePreflightV2;
        const Authority = context.d_Authority;
        const validateAuxiliaryQm31 = context.d_validateAuxiliaryQm31;
        const verifierInputBoundaryClaim = context.d_verifierInputBoundaryClaim;
        const detailedClaimCoordinate = context.d_detailedClaimCoordinate;
        const validateDetailedClaimBoundaryCount = context.d_validateDetailedClaimBoundaryCount;
        const requireSha256Id = context.d_requireSha256Id;
        const requireZeroDomainClosure = context.d_requireZeroDomainClosure;
        const hashSegmentPoseidonDigest = context.d_hashSegmentPoseidonDigest;
        const hashSegmentQm31 = context.d_hashSegmentQm31;
        const hashSegmentInt = context.d_hashSegmentInt;
        const TreeStorage = context.d_TreeStorage;

        pub fn preflightExactSegmentClosureV2(
            authority: *const Authority,
            relations: *const universal.UniversalRelations,
            claims: Claims,
            audit: *const ClosureAudit,
        ) !ExactClosurePreflightV2 {
            if (audit.collect_tuples) return error.AuthorityMismatch;
            const inputs = authority.segment_transcript_inputs orelse
                return error.SegmentClosurePublicationUnavailable;
            try authority.manifest.validate();
            try relations.validate();

            var prefix_totals = [_]QM31{QM31.zero()} ** global_closure.DOMAIN_COUNT;
            var active_domain_mask: u64 = 0;
            var input_hash = std.crypto.hash.sha2.Sha256.init(.{});
            input_hash.update(SEGMENT_CLOSURE_INPUT_ID_DOMAIN);
            hashSegmentInt(
                &input_hash,
                u16,
                SEGMENT_GLOBAL_CLOSURE_FORMAT_VERSION,
            );
            input_hash.update(&authority.manifest.seal);
            hashSegmentInt(
                &input_hash,
                u8,
                air.universal_roster.COMPONENT_COUNT,
            );
            hashSegmentInt(&input_hash, u8, global_closure.DOMAIN_COUNT);
            for (audit.rows, 0..) |row, row_index| {
                try validateAuxiliaryQm31(row.total);
                hashSegmentInt(&input_hash, u8, row_index);
                hashSegmentInt(&input_hash, u64, row.logical_rows);
                hashSegmentInt(&input_hash, u64, row.event_terms);
                for (row.values, 0..) |value, domain_index| {
                    try validateAuxiliaryQm31(value);
                    hashSegmentInt(&input_hash, u8, domain_index);
                    hashSegmentQm31(&input_hash, value);
                    if (!value.isZero())
                        active_domain_mask |= @as(u64, 1) << @intCast(domain_index);
                    if (row_index < global_closure.PREFIX_ROW_COUNT) {
                        prefix_totals[domain_index] =
                            prefix_totals[domain_index].add(value);
                    }
                }
                hashSegmentQm31(&input_hash, row.total);
            }

            const provider_audit = audit.rows[
                @intFromEnum(air.universal_roster.Component.range_check_8_8)
            ];
            for (provider_audit.values, 0..) |value, domain_index| {
                if (domain_index == @intFromEnum(RelationDomain.range_check_8_8))
                    continue;
                if (!value.isZero()) return error.SegmentClosureProviderMismatch;
            }
            const range_snapshot = &inputs.statement.prepared.range;
            const provider_claim = try SegmentProviderClaimV2.init(
                range_snapshot.source_authority_digest,
                range_snapshot.range_check.authority_digest,
                provider_audit.total,
            );
            if (!provider_claim.claimed_sum.eql(claims.segment_leaf.?.sharedProviderValue()))
                return error.SegmentClosureProviderMismatch;

            const wire_evidence = try segmentWireBoundaryEvidence(authority, relations);
            const verifier_input_evidence = try segmentVerifierInputBoundaryEvidence(
                authority,
                relations,
            );
            if (!wire_evidence.claimed_sum.eql(claims.public_boundaries.wire) or
                !verifier_input_evidence.claimed_sum.eql(
                    claims.public_boundaries.verifier_input,
                ))
            {
                return error.AuthorityMismatch;
            }
            const boundary_authorities = try global_closure.BoundaryAuthoritiesV2.init(
                try global_closure.BoundarySourceV2.init(.wire, wire_evidence),
                try global_closure.BoundarySourceV2.init(
                    .verifier_input,
                    verifier_input_evidence,
                ),
            );
            const prepared_boundaries = try global_closure.prepareAuthorityV2(
                boundary_authorities,
            );
            const public_boundaries = try global_closure.PublicBoundariesV2.init(
                &prepared_boundaries,
                wire_evidence,
                verifier_input_evidence,
            );
            active_domain_mask |= relationDomainBit(.range_check_8_8) |
                relationDomainBit(.recursion_wire) |
                relationDomainBit(.recursion_verifier_input_word);

            var closed_totals = prefix_totals;
            closed_totals[@intFromEnum(RelationDomain.range_check_8_8)] =
                closed_totals[@intFromEnum(RelationDomain.range_check_8_8)].add(
                    provider_claim.claimed_sum,
                );
            closed_totals[@intFromEnum(RelationDomain.recursion_wire)] =
                closed_totals[@intFromEnum(RelationDomain.recursion_wire)].add(
                    public_boundaries.wire.claimed_sum,
                );
            closed_totals[
                @intFromEnum(RelationDomain.recursion_verifier_input_word)
            ] = closed_totals[
                @intFromEnum(RelationDomain.recursion_verifier_input_word)
            ].add(public_boundaries.verifier_input.claimed_sum);
            try requireZeroDomainClosure(&closed_totals);

            var framework_total = QM31.zero();
            for (audit.rows) |row| framework_total = framework_total.add(row.total);
            framework_total = framework_total.add(public_boundaries.claimedSum());
            if (!framework_total.isZero())
                return error.RelationDomainClosureMismatch;

            const row_claims_id = input_hash.finalResult();
            try requireSha256Id(row_claims_id);
            return .{
                .row_claims_id = row_claims_id,
                .active_domain_mask = active_domain_mask,
                .prefix_totals = prefix_totals,
                .provider_claim = provider_claim,
                .public_boundaries = public_boundaries,
                .closed_totals = closed_totals,
                .framework_total = framework_total,
            };
        }

        pub fn segmentWireBoundaryEvidence(
            authority: *const Authority,
            relations: *const universal.UniversalRelations,
        ) !global_closure.BoundaryEvidenceV2 {
            try authority.lowering_plan.validateAgainst(authority.arithmetic_reference);
            var snapshot = std.crypto.hash.sha2.Sha256.init(.{});
            snapshot.update(SEGMENT_WIRE_BOUNDARY_SNAPSHOT_DOMAIN);
            snapshot.update(&authority.arithmetic_reference.authority_digest);
            snapshot.update(&authority.lowering_plan.authority_digest);
            hashSegmentInt(&snapshot, u8, @intFromEnum(lowering.Mode.segment));

            var provenance = std.crypto.hash.sha2.Sha256.init(.{});
            provenance.update(SEGMENT_WIRE_BOUNDARY_TUPLES_DOMAIN);
            provenance.update(&authority.arithmetic_reference.authority_digest);
            provenance.update(&authority.lowering_plan.authority_digest);
            hashSegmentInt(&provenance, u8, @intFromEnum(lowering.Mode.segment));
            var tuple_count: u32 = 0;
            for (authority.lowering_plan.public_terms) |term| {
                if (term.active_in != .segment) continue;
                tuple_count = std.math.add(u32, tuple_count, 1) catch
                    return error.ArithmeticOverflow;
                hashSegmentInt(&provenance, u32, term.lane);
                hashSegmentInt(&provenance, u8, @intFromEnum(term.active_in));
                hashSegmentInt(&provenance, u8, @intFromEnum(term.role));
                hashSegmentInt(&provenance, u32, term.circuit_id);
                hashSegmentInt(&provenance, u32, term.node_id);
                hashSegmentQm31(&provenance, term.value);
                hashSegmentInt(&provenance, u32, term.multiplicity);
            }
            if (tuple_count == 0) return error.AuthorityMismatch;
            hashSegmentInt(&snapshot, u32, tuple_count);
            hashSegmentInt(&provenance, u32, tuple_count);
            return .{
                .source_authority_id = authority.lowering_plan.authority_digest,
                .snapshot_id = snapshot.finalResult(),
                .tuple_provenance_id = provenance.finalResult(),
                .tuple_count = tuple_count,
                .claimed_sum = try authority.lowering_plan.publicBoundaryClaim(
                    .segment_leaf,
                    relations,
                ),
            };
        }

        pub fn segmentVerifierInputBoundaryEvidence(
            authority: *const Authority,
            relations: *const universal.UniversalRelations,
        ) !global_closure.BoundaryEvidenceV2 {
            const vm_air = authority.vm_air orelse
                return error.SegmentClosurePublicationUnavailable;
            try vm_air.prepared.validate();
            var snapshot = std.crypto.hash.sha2.Sha256.init(.{});
            snapshot.update(SEGMENT_VERIFIER_INPUT_SNAPSHOT_DOMAIN);
            snapshot.update(&vm_air.prepared.preprocessing.authority_digest);
            snapshot.update(&vm_air.prepared.circuit.identity_digest);
            var provenance = std.crypto.hash.sha2.Sha256.init(.{});
            provenance.update(SEGMENT_VERIFIER_INPUT_TUPLES_DOMAIN);
            provenance.update(&vm_air.prepared.preprocessing.authority_digest);
            provenance.update(&vm_air.prepared.circuit.identity_digest);

            var tuple_count: u32 = 0;
            for (
                vm_air.prepared.preprocessing.rows,
                vm_air.prepared.schedule_values,
            ) |row, value| {
                const coordinate = detailedClaimCoordinate(row) orelse continue;
                tuple_count = std.math.add(u32, tuple_count, 1) catch
                    return error.ArithmeticOverflow;
                inline for (.{ &snapshot, &provenance }) |hash| {
                    hashSegmentInt(hash, u32, vm_input_witness.SEGMENT_VERIFIER_ID);
                    hashSegmentInt(hash, u32, vm_input_witness.VM_CLAIMED_SUM_KIND);
                    hashSegmentInt(hash, u32, coordinate.item_index);
                    hashSegmentInt(hash, u32, coordinate.word_index);
                    hashSegmentInt(hash, u32, value.toU32());
                }
            }
            try validateDetailedClaimBoundaryCount(vm_air.prepared, tuple_count);
            hashSegmentInt(&snapshot, u32, tuple_count);
            hashSegmentInt(&provenance, u32, tuple_count);
            return .{
                .source_authority_id = vm_air.prepared.preprocessing.authority_digest,
                .snapshot_id = snapshot.finalResult(),
                .tuple_provenance_id = provenance.finalResult(),
                .tuple_count = tuple_count,
                .claimed_sum = try verifierInputBoundaryClaim(authority, relations),
            };
        }

        pub fn segmentProviderClaimIdentity(
            claim: *const SegmentProviderClaimV2,
        ) [32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(SEGMENT_PROVIDER_CLAIM_ID_DOMAIN);
            hashSegmentInt(&hash, u16, claim.format_version);
            hashSegmentInt(&hash, u8, claim.present);
            hash.update(&claim.source_authority_id);
            hash.update(&claim.snapshot_id);
            hashSegmentQm31(&hash, claim.claimed_sum);
            return hash.finalResult();
        }

        pub fn segmentClosureReceiptIdentity(
            receipt: *const SegmentGlobalClosureReceiptV2,
        ) [32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(SEGMENT_CLOSURE_RECEIPT_ID_DOMAIN);
            hashSegmentInt(&hash, u16, receipt.format_version);
            hashSegmentInt(&hash, u8, receipt.roster_count);
            hashSegmentInt(&hash, u8, receipt.domain_count);
            hashSegmentInt(&hash, u64, receipt.checked_domain_mask);
            hashSegmentInt(&hash, u64, receipt.active_domain_mask);
            hashSegmentPoseidonDigest(&hash, receipt.native_manifest_id);
            hashSegmentPoseidonDigest(&hash, receipt.native_verifier_receipt_id);
            hashSegmentPoseidonDigest(&hash, receipt.native_relation_replay_id);
            hash.update(&receipt.row_claims_id);
            for (receipt.prefix_totals) |value| hashSegmentQm31(&hash, value);
            hash.update(&receipt.provider_claim.identity);
            hash.update(&receipt.public_boundaries.identity);
            for (receipt.closed_totals) |value| hashSegmentQm31(&hash, value);
            hashSegmentQm31(&hash, receipt.framework_total);
            return hash.finalResult();
        }

        pub fn v2CoreRows18Through34PreflightIdentity(
            receipt: *const V2CoreRows18Through34PreflightReceipt,
        ) [32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(V2_CORE_ROWS_18_34_PREFLIGHT_ID_DOMAIN);
            hashSegmentInt(&hash, u16, receipt.format_version);
            hashSegmentInt(&hash, u8, receipt.first_row);
            hashSegmentInt(&hash, u8, receipt.last_row);
            hashSegmentInt(&hash, u8, receipt.row_count);
            hashSegmentInt(&hash, u32, receipt.preprocessed_columns);
            hashSegmentInt(&hash, u32, receipt.main_columns);
            hashSegmentInt(&hash, u32, receipt.interaction_columns);
            hashSegmentInt(&hash, u32, receipt.constraint_count);
            for (receipt.log_sizes) |log_size|
                hashSegmentInt(&hash, u32, log_size);
            hashSegmentInt(&hash, u32, receipt.core_poseidon_call_count);
            hash.update(&receipt.manifest_seal);
            hash.update(&receipt.lowering_authority_id);
            return hash.finalResult();
        }

        pub fn nativeCoreClaims(claims: Claims) [NATIVE_V2_CORE_ROW_COUNT]QM31 {
            return .{
                claims.vm_input,
                claims.composition_control,
                claims.query_bits,
                claims.query_mapping,
                claims.merkle_root,
                claims.trace_merkle,
                claims.pcs_deep,
                claims.fri_leaf,
                claims.fri_node,
                claims.fri_anchor,
                claims.control,
                claims.input,
                claims.multiply,
                claims.inverse,
                claims.linear,
                claims.merkle_path,
                claims.poseidon2[0].add(claims.poseidon2[1]),
            };
        }

        pub fn validateCoreDomainAudit(audit: DomainAudit, claim: QM31) !void {
            var total = QM31.zero();
            for (audit.values) |value| {
                try validateAuxiliaryQm31(value);
                total = total.add(value);
            }
            try validateAuxiliaryQm31(audit.total);
            // Some authenticated profiles have a structurally present but logically
            // inactive row (for example FRI node rows when fold-step packing consumes
            // every sibling at the leaf). Admit only the unique canonical empty audit;
            // this is not a synthesized closure and cannot hide a non-zero claim.
            if (audit.logical_rows == 0) {
                if (audit.event_terms != 0 or !claim.isZero() or
                    !audit.total.isZero() or !total.isZero())
                {
                    return error.V2CoreCohortMismatch;
                }
                return;
            }
            if (audit.event_terms == 0) return error.V2CoreCohortMismatch;
            if (!total.eql(audit.total) or !audit.total.eql(claim))
                return error.V2CoreCohortMismatch;
        }

        pub fn nativeCoreAuthorityIdentity(owner: *const NativeSegmentCoreV2) [32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(NATIVE_V2_CORE_AUTHORITY_ID_DOMAIN);
            hashSegmentInt(&hash, u16, NATIVE_V2_CORE_FORMAT_VERSION);
            hash.update(&owner.captured.circuit.identity_digest);
            hash.update(&owner.captured.pcs_circuit.identity_digest);
            hash.update(&owner.vm_air_prepared.circuit.identity_digest);
            hash.update(&owner.public_native_sum_authority_id);
            hash.update(&owner.public_native_sum_evaluation_id);
            for (owner.verifier_plans.vm.authority_digest) |word|
                hashSegmentInt(&hash, u32, word);
            for (owner.verifier_plans.recursion.authority_digest) |word|
                hashSegmentInt(&hash, u32, word);
            hash.update(&owner.authority.manifest.seal);
            hash.update(&owner.authority.lowering_plan.authority_digest);
            hash.update(&owner.complete_layout.identity);
            hash.update(&owner.complete_layout.call_buffer_id);
            hashSegmentInt(&hash, u64, owner.boundary_prefix_count);
            hashSegmentInt(&hash, u64, owner.core_poseidon_call_count);
            for (owner.authority.log_sizes) |log_size|
                hashSegmentInt(&hash, u32, log_size);
            return hash.finalResult();
        }

        pub fn loweringLaneEql(left: lowering.Lane, right: lowering.Lane) bool {
            return left.circuit_id == right.circuit_id and
                left.active_in == right.active_in and
                std.mem.eql(u8, &left.circuit_identity, &right.circuit_identity) and
                std.mem.eql(
                    u8,
                    &left.graph.identity_digest,
                    &right.graph.identity_digest,
                ) and left.graph.nodes.ptr == right.graph.nodes.ptr and
                left.graph.nodes.len == right.graph.nodes.len and
                left.graph.outputs.ptr == right.graph.outputs.ptr and
                left.graph.outputs.len == right.graph.outputs.len;
        }

        pub fn nativeCoreGeneratedIdentity(
            generated: *const NativeSegmentCoreGeneratedV2,
        ) [32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(NATIVE_V2_CORE_GENERATED_ID_DOMAIN);
            hashSegmentInt(&hash, u16, generated.format_version);
            hash.update(&generated.padding);
            hash.update(&generated.authority_id);
            hash.update(&generated.schedule_id);
            hash.update(&generated.relation_registry_id);
            hash.update(&generated.provider_relation_id);
            for (generated.claims) |claim| hashSegmentQm31(&hash, claim);
            for (generated.poseidon2_partials) |claim| hashSegmentQm31(&hash, claim);
            for (generated.audits) |audit| {
                for (audit.values) |value| hashSegmentQm31(&hash, value);
                hashSegmentQm31(&hash, audit.total);
                hashSegmentInt(&hash, u64, audit.logical_rows);
                hashSegmentInt(&hash, u64, audit.event_terms);
            }
            return hash.finalResult();
        }

        pub fn publishNativeCoreTree(
            authority: *const Authority,
            source: *const TreeStorage,
            manifest: *const manifest_v2.Manifest,
            tree: usize,
            destination: [][]M31,
        ) !void {
            const expected_columns: usize = switch (tree) {
                manifest_v2.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
                manifest_v2.MAIN_TREE_INDEX => manifest.total_main_columns,
                manifest_v2.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
                else => return error.V2CoreCohortMismatch,
            };
            if (destination.len != expected_columns)
                return error.V2CoreCohortMismatch;

            // Complete preflight before the first external write. This checks only the
            // owned rows so independently assembled prefix/suffix cohorts may already
            // occupy their disjoint manifest columns.
            for (NATIVE_V2_CORE_FIRST_ROW..NATIVE_V2_CORE_LAST_ROW + 1) |row| {
                const source_placement = authority.manifest.placements[row] orelse
                    return error.V2CoreCohortMismatch;
                const target_placement = manifest.placements[row] orelse
                    return error.V2CoreCohortMismatch;
                const count: usize = switch (tree) {
                    manifest_v2.PREPROCESSED_TREE_INDEX => target_placement.geometry.preprocessed_columns,
                    manifest_v2.MAIN_TREE_INDEX => target_placement.geometry.main_columns,
                    manifest_v2.INTERACTION_TREE_INDEX => target_placement.geometry.interaction_columns,
                    else => unreachable,
                };
                const source_count: usize = switch (tree) {
                    manifest_v2.PREPROCESSED_TREE_INDEX => source_placement.geometry.preprocessed_columns,
                    manifest_v2.MAIN_TREE_INDEX => source_placement.geometry.main_columns,
                    manifest_v2.INTERACTION_TREE_INDEX => source_placement.geometry.interaction_columns,
                    else => unreachable,
                };
                const source_offset: usize = switch (tree) {
                    manifest_v2.PREPROCESSED_TREE_INDEX => source_placement.preprocessed_offset,
                    manifest_v2.MAIN_TREE_INDEX => source_placement.main_offset,
                    manifest_v2.INTERACTION_TREE_INDEX => source_placement.interaction_offset,
                    else => unreachable,
                };
                const target_offset: usize = switch (tree) {
                    manifest_v2.PREPROCESSED_TREE_INDEX => target_placement.preprocessed_offset,
                    manifest_v2.MAIN_TREE_INDEX => target_placement.main_offset,
                    manifest_v2.INTERACTION_TREE_INDEX => target_placement.interaction_offset,
                    else => unreachable,
                };
                if (count != source_count or source_offset + count > source.columns.len or
                    target_offset + count > destination.len)
                {
                    return error.V2CoreCohortMismatch;
                }
                for (0..count) |local| {
                    const source_column = source.columns[source_offset + local];
                    const target_column = destination[target_offset + local];
                    if (target_column.len != source_column.len)
                        return error.V2CoreCohortMismatch;
                    for (target_column) |value| if (!value.isZero())
                        return error.DestinationNotZero;
                    const target_start = @intFromPtr(target_column.ptr);
                    const target_bytes = std.math.mul(
                        usize,
                        target_column.len,
                        @sizeOf(M31),
                    ) catch return error.ArithmeticOverflow;
                    const target_end = std.math.add(usize, target_start, target_bytes) catch
                        return error.ArithmeticOverflow;
                    for (NATIVE_V2_CORE_FIRST_ROW..row + 1) |prior_row| {
                        const prior_placement = manifest.placements[prior_row].?;
                        const prior_count: usize = switch (tree) {
                            manifest_v2.PREPROCESSED_TREE_INDEX => prior_placement.geometry.preprocessed_columns,
                            manifest_v2.MAIN_TREE_INDEX => prior_placement.geometry.main_columns,
                            manifest_v2.INTERACTION_TREE_INDEX => prior_placement.geometry.interaction_columns,
                            else => unreachable,
                        };
                        const prior_offset: usize = switch (tree) {
                            manifest_v2.PREPROCESSED_TREE_INDEX => prior_placement.preprocessed_offset,
                            manifest_v2.MAIN_TREE_INDEX => prior_placement.main_offset,
                            manifest_v2.INTERACTION_TREE_INDEX => prior_placement.interaction_offset,
                            else => unreachable,
                        };
                        const end_local = if (prior_row == row) local else prior_count;
                        for (0..end_local) |prior_local| {
                            const prior = destination[prior_offset + prior_local];
                            const prior_start = @intFromPtr(prior.ptr);
                            const prior_bytes = std.math.mul(
                                usize,
                                prior.len,
                                @sizeOf(M31),
                            ) catch return error.ArithmeticOverflow;
                            const prior_end = std.math.add(
                                usize,
                                prior_start,
                                prior_bytes,
                            ) catch return error.ArithmeticOverflow;
                            if (target_start < prior_end and prior_start < target_end)
                                return error.DestinationAlias;
                        }
                    }
                }
            }
            for (NATIVE_V2_CORE_FIRST_ROW..NATIVE_V2_CORE_LAST_ROW + 1) |row| {
                const source_placement = authority.manifest.placements[row].?;
                const target_placement = manifest.placements[row].?;
                const count: usize = switch (tree) {
                    manifest_v2.PREPROCESSED_TREE_INDEX => target_placement.geometry.preprocessed_columns,
                    manifest_v2.MAIN_TREE_INDEX => target_placement.geometry.main_columns,
                    manifest_v2.INTERACTION_TREE_INDEX => target_placement.geometry.interaction_columns,
                    else => unreachable,
                };
                const source_offset: usize = switch (tree) {
                    manifest_v2.PREPROCESSED_TREE_INDEX => source_placement.preprocessed_offset,
                    manifest_v2.MAIN_TREE_INDEX => source_placement.main_offset,
                    manifest_v2.INTERACTION_TREE_INDEX => source_placement.interaction_offset,
                    else => unreachable,
                };
                const target_offset: usize = switch (tree) {
                    manifest_v2.PREPROCESSED_TREE_INDEX => target_placement.preprocessed_offset,
                    manifest_v2.MAIN_TREE_INDEX => target_placement.main_offset,
                    manifest_v2.INTERACTION_TREE_INDEX => target_placement.interaction_offset,
                    else => unreachable,
                };
                for (0..count) |local|
                    @memcpy(
                        destination[target_offset + local],
                        source.columns[source_offset + local],
                    );
            }
        }
    };
}
