//! Cohesive internal authority extracted from recursive_temporal_nonfri_source_v2.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const M31 = context.d_M31;
        const QM31 = context.d_QM31;
        const recursion = context.d_recursion;
        const transcript_air = context.d_transcript_air;
        const transcript_component = context.d_transcript_component;
        const transcript_binding = context.d_transcript_binding;
        const transcript_state = context.d_transcript_state;
        const transcript_word = context.d_transcript_word;
        const transcript_payload = context.d_transcript_payload;
        const pow_check_air = context.d_pow_check_air;
        const relation_challenge = context.d_relation_challenge;
        const verifier_randomness = context.d_verifier_randomness;
        const relation_interaction = context.d_relation_interaction;
        const universal_binding = context.d_universal_binding;
        const universal_manifest = context.d_universal_manifest;
        const universal_roster = context.d_universal_roster;
        const global_closure = context.d_global_closure;
        const packed_relation_challenge_v2 = context.d_packed_relation_challenge_v2;
        const control_air = context.d_control_air;
        const transcript_binding_air = context.d_transcript_binding_air;
        const transcript_state_air = context.d_transcript_state_air;
        const transcript_word_air = context.d_transcript_word_air;
        const pow_frame_air = context.d_pow_frame_air;
        const verifier_randomness_air = context.d_verifier_randomness_air;
        const statement_input_air = context.d_statement_input_air;
        const statement_semantics_air = context.d_statement_semantics_air;
        const vm_claim_input_air = context.d_vm_claim_input_air;
        const vm_claim_hash_air = context.d_vm_claim_hash_air;
        const vm_io_hash_air = context.d_vm_io_hash_air;
        const vm_claim_semantics_air = context.d_vm_claim_semantics_air;
        const vm_public_logup_air = context.d_vm_public_logup_air;
        const vm_public_logup_control_air = context.d_vm_public_logup_control_air;
        const PREFIX_ROW_COUNT = context.d_PREFIX_ROW_COUNT;
        const PREFIX_TREE_WRITER_FORMAT_VERSION = context.d_PREFIX_TREE_WRITER_FORMAT_VERSION;
        const PREFIX_INTERACTIONS_SCHEMA_VERSION = context.d_PREFIX_INTERACTIONS_SCHEMA_VERSION;
        const PREFIX_TREE_WRITER_AUTHORITY_DOMAIN = context.d_PREFIX_TREE_WRITER_AUTHORITY_DOMAIN;
        const PREFIX_DOMAIN_AUDITS_AUTHORITY_DOMAIN = context.d_PREFIX_DOMAIN_AUDITS_AUTHORITY_DOMAIN;
        const InteractionFramework = context.d_InteractionFramework;
        const Error = context.d_Error;
        const TemporalRows0Through17CustodyV3 = context.d_TemporalRows0Through17CustodyV3;
        const TemporalPrefixTreeSourcesV3 = context.d_TemporalPrefixTreeSourcesV3;
        const TemporalPrefixTreeReceiptV3 = context.d_TemporalPrefixTreeReceiptV3;
        const TemporalPrefixInteractionsV3 = context.d_TemporalPrefixInteractionsV3;
        const TemporalPrefixDomainAuditsV3 = context.d_TemporalPrefixDomainAuditsV3;
        const TemporalPrefixTreeWriterV3 = context.d_TemporalPrefixTreeWriterV3;
        const prefixTreeColumnCount = context.d_prefixTreeColumnCount;
        const prefixTreeCellCount = context.d_prefixTreeCellCount;
        const shaInt = context.d_shaInt;

        pub fn generatePrefixInteractions(
            writer: *TemporalPrefixTreeWriterV3,
            sources: TemporalPrefixTreeSourcesV3,
            relations: *const recursion.air.universal_challenges.UniversalRelations,
            destination: []const []M31,
        ) Error![PREFIX_ROW_COUNT]QM31 {
            const layout = &sources.custody.commitment_layout;
            return .{
                try generatePrefixInteractionRow(
                    control_air,
                    writer,
                    &writer.owners.control.relation,
                    writer.buffers.control,
                    layout.placements[0],
                    relations,
                    destination,
                ),
                try generatePrefixInteractionRow(
                    transcript_component,
                    writer,
                    &writer.owners.transcript_air.relation,
                    writer.buffers.transcript_air,
                    layout.placements[1],
                    relations,
                    destination,
                ),
                try generatePrefixInteractionRow(
                    transcript_binding_air,
                    writer,
                    &writer.owners.transcript_binding.relation,
                    writer.buffers.transcript_binding,
                    layout.placements[2],
                    relations,
                    destination,
                ),
                try generatePrefixInteractionRow(
                    transcript_state_air,
                    writer,
                    &writer.owners.transcript_state.relation,
                    writer.buffers.transcript_state,
                    layout.placements[3],
                    relations,
                    destination,
                ),
                try generatePrefixInteractionRow(
                    transcript_word_air,
                    writer,
                    &writer.owners.transcript_word.relation,
                    writer.buffers.transcript_word,
                    layout.placements[4],
                    relations,
                    destination,
                ),
                try generatePrefixInteractionRow(
                    transcript_payload,
                    writer,
                    &writer.owners.transcript_payload.relation,
                    writer.buffers.transcript_payload,
                    layout.placements[5],
                    relations,
                    destination,
                ),
                try generatePrefixInteractionRow(
                    pow_check_air,
                    writer,
                    &writer.owners.pow_check.relation,
                    writer.buffers.pow_check,
                    layout.placements[6],
                    relations,
                    destination,
                ),
                try generatePrefixInteractionRow(
                    pow_frame_air,
                    writer,
                    &writer.owners.pow_frame.relation,
                    writer.buffers.pow_frame,
                    layout.placements[7],
                    relations,
                    destination,
                ),
                try generatePrefixInteractionRow(
                    packed_relation_challenge_v2,
                    writer,
                    &writer.owners.packed_relation_challenge.relation,
                    writer.buffers.packed_relation_challenge,
                    layout.placements[8],
                    relations,
                    destination,
                ),
                try generatePrefixInteractionRow(
                    verifier_randomness_air,
                    writer,
                    &writer.owners.verifier_randomness.relation,
                    writer.buffers.verifier_randomness,
                    layout.placements[9],
                    relations,
                    destination,
                ),
                try generatePrefixInteractionRow(
                    statement_input_air,
                    writer,
                    &sources.statement_authority.statement_input_relation,
                    writer.buffers.statement_input,
                    layout.placements[10],
                    relations,
                    destination,
                ),
                try generatePrefixInteractionRow(
                    statement_semantics_air,
                    writer,
                    &sources.statement_authority.statement_semantics_relation,
                    writer.buffers.statement_semantics,
                    layout.placements[11],
                    relations,
                    destination,
                ),
                try generatePrefixInteractionRow(
                    vm_claim_input_air,
                    writer,
                    &sources.typed_public.owners.claim_input.relation,
                    sources.inactive_prepared.claim_input_rows,
                    layout.placements[12],
                    relations,
                    destination,
                ),
                try generatePrefixInteractionRow(
                    vm_claim_hash_air,
                    writer,
                    &sources.typed_public.owners.claim_hash.relation,
                    sources.inactive_prepared.claim_hash_rows,
                    layout.placements[13],
                    relations,
                    destination,
                ),
                try generatePrefixInteractionRow(
                    vm_io_hash_air,
                    writer,
                    &sources.typed_public.owners.io_hash.relation,
                    sources.inactive_prepared.io_hash_rows,
                    layout.placements[14],
                    relations,
                    destination,
                ),
                try generatePrefixInteractionRow(
                    vm_claim_semantics_air,
                    writer,
                    &sources.typed_public.owners.claim_semantics.relation,
                    sources.inactive_prepared.claim_semantics_rows,
                    layout.placements[15],
                    relations,
                    destination,
                ),
                try generatePrefixInteractionRow(
                    vm_public_logup_air,
                    writer,
                    &sources.typed_public.owners.public_logup.relation,
                    sources.inactive_prepared.public_logup_rows,
                    layout.placements[16],
                    relations,
                    destination,
                ),
                try generatePrefixInteractionRow(
                    vm_public_logup_control_air,
                    writer,
                    &sources.typed_public.owners.public_logup_control.relation,
                    sources.inactive_source.public_logup_control_rows,
                    layout.placements[17],
                    relations,
                    destination,
                ),
            };
        }

        pub fn auditPrefixInteractionRows(
            writer: *TemporalPrefixTreeWriterV3,
            sources: TemporalPrefixTreeSourcesV3,
            relations: *const recursion.air.universal_challenges.UniversalRelations,
            claims: [PREFIX_ROW_COUNT]QM31,
            tuple_ledger: ?*relation_interaction.TupleLedger,
        ) ![PREFIX_ROW_COUNT]relation_interaction.DomainAudit {
            return .{
                try auditPrefixInteractionRow(
                    control_air,
                    writer,
                    &writer.owners.control.relation,
                    writer.buffers.control,
                    relations,
                    claims[0],
                    .control,
                    tuple_ledger,
                ),
                try auditPrefixInteractionRow(
                    transcript_component,
                    writer,
                    &writer.owners.transcript_air.relation,
                    writer.buffers.transcript_air,
                    relations,
                    claims[1],
                    .transcript_air,
                    tuple_ledger,
                ),
                try auditPrefixInteractionRow(
                    transcript_binding_air,
                    writer,
                    &writer.owners.transcript_binding.relation,
                    writer.buffers.transcript_binding,
                    relations,
                    claims[2],
                    .transcript_binding,
                    tuple_ledger,
                ),
                try auditPrefixInteractionRow(
                    transcript_state_air,
                    writer,
                    &writer.owners.transcript_state.relation,
                    writer.buffers.transcript_state,
                    relations,
                    claims[3],
                    .transcript_state,
                    tuple_ledger,
                ),
                try auditPrefixInteractionRow(
                    transcript_word_air,
                    writer,
                    &writer.owners.transcript_word.relation,
                    writer.buffers.transcript_word,
                    relations,
                    claims[4],
                    .transcript_word,
                    tuple_ledger,
                ),
                try auditPrefixInteractionRow(
                    transcript_payload,
                    writer,
                    &writer.owners.transcript_payload.relation,
                    writer.buffers.transcript_payload,
                    relations,
                    claims[5],
                    .transcript_payload,
                    tuple_ledger,
                ),
                try auditPrefixInteractionRow(
                    pow_check_air,
                    writer,
                    &writer.owners.pow_check.relation,
                    writer.buffers.pow_check,
                    relations,
                    claims[6],
                    .pow_check,
                    tuple_ledger,
                ),
                try auditPrefixInteractionRow(
                    pow_frame_air,
                    writer,
                    &writer.owners.pow_frame.relation,
                    writer.buffers.pow_frame,
                    relations,
                    claims[7],
                    .pow_frame,
                    tuple_ledger,
                ),
                try auditPrefixInteractionRow(
                    packed_relation_challenge_v2,
                    writer,
                    &writer.owners.packed_relation_challenge.relation,
                    writer.buffers.packed_relation_challenge,
                    relations,
                    claims[8],
                    .relation_challenge,
                    tuple_ledger,
                ),
                try auditPrefixInteractionRow(
                    verifier_randomness_air,
                    writer,
                    &writer.owners.verifier_randomness.relation,
                    writer.buffers.verifier_randomness,
                    relations,
                    claims[9],
                    .verifier_randomness,
                    tuple_ledger,
                ),
                try auditPrefixInteractionRow(
                    statement_input_air,
                    writer,
                    &sources.statement_authority.statement_input_relation,
                    writer.buffers.statement_input,
                    relations,
                    claims[10],
                    .statement_input,
                    tuple_ledger,
                ),
                try auditPrefixInteractionRow(
                    statement_semantics_air,
                    writer,
                    &sources.statement_authority.statement_semantics_relation,
                    writer.buffers.statement_semantics,
                    relations,
                    claims[11],
                    .statement_semantics_input,
                    tuple_ledger,
                ),
                try auditPrefixInteractionRow(
                    vm_claim_input_air,
                    writer,
                    &sources.typed_public.owners.claim_input.relation,
                    sources.inactive_prepared.claim_input_rows,
                    relations,
                    claims[12],
                    .vm_public_claim_input,
                    tuple_ledger,
                ),
                try auditPrefixInteractionRow(
                    vm_claim_hash_air,
                    writer,
                    &sources.typed_public.owners.claim_hash.relation,
                    sources.inactive_prepared.claim_hash_rows,
                    relations,
                    claims[13],
                    .vm_public_claim_hash,
                    tuple_ledger,
                ),
                try auditPrefixInteractionRow(
                    vm_io_hash_air,
                    writer,
                    &sources.typed_public.owners.io_hash.relation,
                    sources.inactive_prepared.io_hash_rows,
                    relations,
                    claims[14],
                    .vm_public_io_hash,
                    tuple_ledger,
                ),
                try auditPrefixInteractionRow(
                    vm_claim_semantics_air,
                    writer,
                    &sources.typed_public.owners.claim_semantics.relation,
                    sources.inactive_prepared.claim_semantics_rows,
                    relations,
                    claims[15],
                    .vm_public_claim_semantics_input,
                    tuple_ledger,
                ),
                try auditPrefixInteractionRow(
                    vm_public_logup_air,
                    writer,
                    &sources.typed_public.owners.public_logup.relation,
                    sources.inactive_prepared.public_logup_rows,
                    relations,
                    claims[16],
                    .vm_public_logup_input,
                    tuple_ledger,
                ),
                try auditPrefixInteractionRow(
                    vm_public_logup_control_air,
                    writer,
                    &sources.typed_public.owners.public_logup_control.relation,
                    sources.inactive_source.public_logup_control_rows,
                    relations,
                    claims[17],
                    .vm_public_logup_control,
                    tuple_ledger,
                ),
            };
        }

        pub fn auditPrefixInteractionRow(
            comptime Air: type,
            writer: *TemporalPrefixTreeWriterV3,
            plan: *const universal_binding.Binding(Air).Plan,
            rows: []const universal_binding.Binding(Air).Row,
            relations: *const recursion.air.universal_challenges.UniversalRelations,
            expected_claim: QM31,
            component: universal_roster.Component,
            tuple_ledger: ?*relation_interaction.TupleLedger,
        ) !relation_interaction.DomainAudit {
            const audit = try plan.auditPreparedDomainSums(
                writer.allocator,
                rows,
                relations,
                expected_claim,
            );
            if (tuple_ledger) |ledger| try plan.appendPreparedTupleContributions(
                ledger,
                @intCast(@intFromEnum(component)),
                rows,
                relation_interaction.allDomainMask(),
            );
            return audit;
        }

        pub fn generatePrefixInteractionRow(
            comptime Air: type,
            writer: *TemporalPrefixTreeWriterV3,
            plan: *const universal_binding.Binding(Air).Plan,
            rows: []const universal_binding.Binding(Air).Row,
            placement: universal_manifest.Placement,
            relations: *const recursion.air.universal_challenges.UniversalRelations,
            destination: []const []M31,
        ) Error!QM31 {
            const Framework = InteractionFramework(Air);
            const scratch_count = try Framework.requiredScratchElementCount(
                placement.geometry.log_size,
            );
            var workspace = Framework.Workspace{
                .allocator = writer.allocator,
                .capacity_log_size = placement.geometry.log_size,
                .scratch = writer.interaction_scratch[0..scratch_count],
            };
            var columns: [Air.INTERACTION_COLUMN_COUNT][]M31 = undefined;
            const offset: usize = @intCast(placement.interaction_offset);
            for (&columns, destination[offset .. offset + columns.len]) |
                *target,
                source,
            | target.* = source;
            return Framework.generatePreparedInto(
                &workspace,
                plan,
                rows,
                placement.geometry.log_size,
                relations,
                &columns,
            );
        }

        pub fn prefixTreeReceipt(
            custody: *const TemporalRows0Through17CustodyV3,
            tree: usize,
            columns: []const []M31,
        ) Error!TemporalPrefixTreeReceiptV3 {
            const layout = &custody.commitment_layout;
            var result = TemporalPrefixTreeReceiptV3{
                .tree_index = @intCast(tree),
                .column_count = prefixTreeColumnCount(layout, tree),
                .cell_count = try prefixTreeCellCount(layout, tree),
                .custody_id = custody.custody_id,
                .layout_sha_id = layout.layout_sha_id,
                .tree_sha_id = prefixTreeSha(custody, tree, columns),
                .identity = undefined,
            };
            result.identity = prefixTreeReceiptSha(&result);
            try result.validate(custody);
            return result;
        }

        pub fn prefixTreeSha(
            custody: *const TemporalRows0Through17CustodyV3,
            tree: usize,
            columns: []const []M31,
        ) [32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(PREFIX_TREE_WRITER_AUTHORITY_DOMAIN);
            shaInt(&hash, u16, PREFIX_TREE_WRITER_FORMAT_VERSION);
            shaInt(&hash, u8, tree);
            for (custody.custody_id) |word| shaInt(&hash, u32, word);
            hash.update(&custody.commitment_layout.layout_sha_id);
            shaInt(&hash, u32, columns.len);
            for (columns, 0..) |column, index| {
                shaInt(&hash, u32, index);
                shaInt(&hash, u64, column.len);
                for (column) |value| shaInt(&hash, u32, value.toU32());
            }
            return hash.finalResult();
        }

        pub fn prefixTreeReceiptSha(value: *const TemporalPrefixTreeReceiptV3) [32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(PREFIX_TREE_WRITER_AUTHORITY_DOMAIN);
            shaInt(&hash, u16, value.format_version);
            shaInt(&hash, u16, value.schema_version);
            shaInt(&hash, u8, value.tree_index);
            hash.update(&value.padding);
            shaInt(&hash, u32, value.column_count);
            shaInt(&hash, u64, value.cell_count);
            for (value.custody_id) |word| shaInt(&hash, u32, word);
            hash.update(&value.layout_sha_id);
            hash.update(&value.tree_sha_id);
            return hash.finalResult();
        }

        pub fn prefixInteractionsSha(value: *const TemporalPrefixInteractionsV3) [32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(PREFIX_TREE_WRITER_AUTHORITY_DOMAIN);
            shaInt(&hash, u16, value.format_version);
            shaInt(&hash, u16, value.schema_version);
            hash.update(&value.padding);
            hash.update(&value.tree.identity);
            hash.update(&value.relation_registry_sha_id);
            hash.update(&value.relation_challenges_sha_id);
            for (value.claims) |claim| for (claim.toM31Array()) |coordinate|
                shaInt(&hash, u32, coordinate.toU32());
            return hash.finalResult();
        }

        pub fn prefixDomainAuditsSha(
            value: *const TemporalPrefixDomainAuditsV3,
        ) [32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(PREFIX_DOMAIN_AUDITS_AUTHORITY_DOMAIN);
            shaInt(&hash, u16, value.format_version);
            shaInt(&hash, u16, value.schema_version);
            hash.update(&value.padding);
            for (value.custody_id) |word| shaInt(&hash, u32, word);
            hash.update(&value.interactions_identity);
            for (value.rows, 0..) |audit, row| {
                shaInt(&hash, u8, row);
                shaInt(&hash, u64, audit.logical_rows);
                shaInt(&hash, u64, audit.event_terms);
                for (audit.values) |domain_value| for (domain_value.toM31Array()) |
                    coordinate,
                | shaInt(&hash, u32, coordinate.toU32());
                for (audit.total.toM31Array()) |coordinate|
                    shaInt(&hash, u32, coordinate.toU32());
            }
            return hash.finalResult();
        }

        pub fn prefixGlobalRowClaim(
            row: universal_roster.Component,
            audit: relation_interaction.DomainAudit,
        ) global_closure.RowClaimsV1 {
            var domains: [global_closure.DOMAIN_COUNT]global_closure.DomainClaimV1 =
                undefined;
            for (&domains, audit.values, 0..) |*destination, value, index| {
                destination.* = .{
                    .active = @intFromBool(!value.isZero()),
                    .domain = @enumFromInt(index),
                    .value = value,
                };
            }
            return .{
                .row = row,
                .domains = domains,
                .claimed_sum = audit.total,
            };
        }

        pub fn universalRelationsSha(
            relations: *const recursion.air.universal_challenges.UniversalRelations,
        ) [32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(PREFIX_TREE_WRITER_AUTHORITY_DOMAIN);
            shaInt(&hash, u16, PREFIX_INTERACTIONS_SCHEMA_VERSION);
            shaInt(&hash, u16, relations.format_version);
            hash.update(&relations.registry_order_digest);
            for (relations.elements) |element| {
                shaInt(&hash, u8, element.arity);
                for (element.z.toM31Array()) |coordinate|
                    shaInt(&hash, u32, coordinate.toU32());
                for (element.alpha.toM31Array()) |coordinate|
                    shaInt(&hash, u32, coordinate.toU32());
            }
            return hash.finalResult();
        }

        pub fn prefixTreeWriterSha(value: *const TemporalPrefixTreeWriterV3) [32]u8 {
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(PREFIX_TREE_WRITER_AUTHORITY_DOMAIN);
            shaInt(&hash, u16, value.format_version);
            shaInt(&hash, u16, value.schema_version);
            hash.update(&value.padding);
            for (value.custody_id) |word| shaInt(&hash, u32, word);
            hash.update(&value.layout_sha_id);
            hash.update(&value.transcript_rows_authority_sha_id);
            for (value.statement_source_id) |word| shaInt(&hash, u32, word);
            hash.update(&value.inactive_source_sha_id);
            hash.update(&value.inactive_prepared_sha_id);
            shaInt(&hash, u64, value.interaction_scratch.len);
            inline for (.{
                control_air.SEMANTIC_DIGEST,
                transcript_component.SEMANTIC_DIGEST,
                transcript_binding_air.SEMANTIC_DIGEST,
                transcript_state_air.SEMANTIC_DIGEST,
                transcript_word_air.SEMANTIC_DIGEST,
                transcript_payload.SEMANTIC_DIGEST,
                pow_check_air.SEMANTIC_DIGEST,
                pow_frame_air.SEMANTIC_DIGEST,
                packed_relation_challenge_v2.SEMANTIC_DIGEST,
                verifier_randomness_air.SEMANTIC_DIGEST,
            }) |semantic_digest| hash.update(&semantic_digest);
            return hash.finalResult();
        }

        // Fail-atomic cold constructor. Every pair, publication, witness, capture,
        // statement and row-authority check completes before the single destination
        // assignment. No caller-authored claim, relation challenge, row geometry or
        // placement is accepted.
    };
}
