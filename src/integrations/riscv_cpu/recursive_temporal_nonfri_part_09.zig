//! Cohesive internal authority extracted from recursive_temporal_nonfri_source_v2.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const M31 = context.d_M31;
        const QM31 = context.d_QM31;
        const recursion = context.d_recursion;
        const binary_transcript_source = context.d_binary_transcript_source;
        const statement_air = context.d_statement_air;
        const transcript_air = context.d_transcript_air;
        const transcript_binding = context.d_transcript_binding;
        const transcript_state = context.d_transcript_state;
        const transcript_word = context.d_transcript_word;
        const transcript_payload = context.d_transcript_payload;
        const relation_challenge = context.d_relation_challenge;
        const verifier_randomness = context.d_verifier_randomness;
        const relation_interaction = context.d_relation_interaction;
        const TemporalPrefixAdaptersForManifest = context.d_TemporalPrefixAdaptersForManifest;
        const TemporalPrefixComponentsForManifest = context.d_TemporalPrefixComponentsForManifest;
        const Digest = context.d_Digest;
        const PREFIX_TREE_WRITER_FORMAT_VERSION = context.d_PREFIX_TREE_WRITER_FORMAT_VERSION;
        const PREFIX_TREE_WRITER_SCHEMA_VERSION = context.d_PREFIX_TREE_WRITER_SCHEMA_VERSION;
        const PREFIX_TREE0_INDEX = context.d_PREFIX_TREE0_INDEX;
        const PREFIX_TREE1_INDEX = context.d_PREFIX_TREE1_INDEX;
        const PREFIX_TREE2_INDEX = context.d_PREFIX_TREE2_INDEX;
        const Error = context.d_Error;
        const TemporalTranscriptOwnersV3 = context.d_TemporalTranscriptOwnersV3;
        const TemporalPrefixLogicalBuffersV3 = context.d_TemporalPrefixLogicalBuffersV3;
        const TemporalPrefixTreeSourcesV3 = context.d_TemporalPrefixTreeSourcesV3;
        const TemporalPrefixTreeReceiptV3 = context.d_TemporalPrefixTreeReceiptV3;
        const TemporalPrefixInteractionsV3 = context.d_TemporalPrefixInteractionsV3;
        const TemporalPrefixDomainAuditsV3 = context.d_TemporalPrefixDomainAuditsV3;
        const validatePrefixBufferGeometry = context.d_validatePrefixBufferGeometry;
        const fillPrefixLogicalRows = context.d_fillPrefixLogicalRows;
        const scatterPrefixTree = context.d_scatterPrefixTree;
        const preflightPrefixTree = context.d_preflightPrefixTree;
        const rejectPrefixTreeCrossAlias = context.d_rejectPrefixTreeCrossAlias;
        const clearPrefixTree = context.d_clearPrefixTree;
        const prefixInteractionScratchCount = context.d_prefixInteractionScratchCount;
        const generatePrefixInteractions = context.d_generatePrefixInteractions;
        const auditPrefixInteractionRows = context.d_auditPrefixInteractionRows;
        const prefixTreeReceipt = context.d_prefixTreeReceipt;
        const prefixInteractionsSha = context.d_prefixInteractionsSha;
        const prefixDomainAuditsSha = context.d_prefixDomainAuditsSha;
        const universalRelationsSha = context.d_universalRelationsSha;
        const prefixTreeWriterSha = context.d_prefixTreeWriterSha;
        const allZero = context.d_allZero;

        pub const TemporalPrefixTreeWriterV3 = struct {
            allocator: std.mem.Allocator,
            format_version: u16 = PREFIX_TREE_WRITER_FORMAT_VERSION,
            schema_version: u16 = PREFIX_TREE_WRITER_SCHEMA_VERSION,
            padding: [4]u8 = .{ 0, 0, 0, 0 },
            custody_id: Digest,
            layout_sha_id: [32]u8,
            transcript_rows_authority_sha_id: [32]u8,
            statement_source_id: Digest,
            inactive_source_sha_id: [32]u8,
            inactive_prepared_sha_id: [32]u8,
            owners: TemporalTranscriptOwnersV3,
            buffers: TemporalPrefixLogicalBuffersV3,
            interaction_scratch: []QM31,
            authority_sha_id: [32]u8,

            pub fn init(
                allocator: std.mem.Allocator,
                sources: TemporalPrefixTreeSourcesV3,
            ) Error!TemporalPrefixTreeWriterV3 {
                try sources.validate();
                var owners = TemporalTranscriptOwnersV3.init(allocator) catch |err|
                    switch (err) {
                        error.OutOfMemory => return error.OutOfMemory,
                        else => return error.InvalidPrefixTreeWriter,
                    };
                errdefer owners.deinit();
                const statement_input_count =
                    sources.statement_authority.statement_input_preprocessing.rows.len;
                const statement_semantics_count =
                    sources.statement_authority.statement_semantics_preprocessing.rows.len;
                var buffers = try TemporalPrefixLogicalBuffersV3.init(
                    allocator,
                    sources.custody.transcript_manifest.logical_rows,
                    statement_input_count,
                    statement_semantics_count,
                );
                errdefer buffers.deinit();
                const scratch_count = try prefixInteractionScratchCount(
                    &sources.custody.commitment_layout,
                );
                const interaction_scratch = try allocator.alloc(QM31, scratch_count);
                errdefer allocator.free(interaction_scratch);
                var result = TemporalPrefixTreeWriterV3{
                    .allocator = allocator,
                    .custody_id = sources.custody.custody_id,
                    .layout_sha_id = sources.custody.commitment_layout.layout_sha_id,
                    .transcript_rows_authority_sha_id = sources.transcript.authority_sha_id,
                    .statement_source_id = sources.statement.source_id,
                    .inactive_source_sha_id = sources.inactive_source.authority_seal,
                    .inactive_prepared_sha_id = sources.inactive_prepared.authority_seal,
                    .owners = owners,
                    .buffers = buffers,
                    .interaction_scratch = interaction_scratch,
                    .authority_sha_id = undefined,
                };
                result.authority_sha_id = prefixTreeWriterSha(&result);
                try result.validateAgainst(sources);
                return result;
            }

            pub fn deinit(self: *TemporalPrefixTreeWriterV3) void {
                self.allocator.free(self.interaction_scratch);
                self.buffers.deinit();
                self.owners.deinit();
                self.* = undefined;
            }

            pub fn validateAgainst(
                self: *const TemporalPrefixTreeWriterV3,
                sources: TemporalPrefixTreeSourcesV3,
            ) Error!void {
                try sources.validateHot();
                self.owners.validate() catch return error.InvalidPrefixTreeWriter;
                if (self.format_version != PREFIX_TREE_WRITER_FORMAT_VERSION or
                    self.schema_version != PREFIX_TREE_WRITER_SCHEMA_VERSION or
                    !allZero(&self.padding) or
                    !std.meta.eql(self.custody_id, sources.custody.custody_id) or
                    !std.mem.eql(
                        u8,
                        &self.layout_sha_id,
                        &sources.custody.commitment_layout.layout_sha_id,
                    ) or !std.mem.eql(
                    u8,
                    &self.transcript_rows_authority_sha_id,
                    &sources.transcript.authority_sha_id,
                ) or !std.meta.eql(
                    self.statement_source_id,
                    sources.statement.source_id,
                ) or !std.mem.eql(
                    u8,
                    &self.inactive_source_sha_id,
                    &sources.inactive_source.authority_seal,
                ) or !std.mem.eql(
                    u8,
                    &self.inactive_prepared_sha_id,
                    &sources.inactive_prepared.authority_seal,
                ) or self.interaction_scratch.len !=
                    try prefixInteractionScratchCount(
                        &sources.custody.commitment_layout,
                    ) or !std.mem.eql(
                    u8,
                    &self.authority_sha_id,
                    &prefixTreeWriterSha(self),
                )) {
                    return error.InvalidPrefixTreeWriter;
                }
                try validatePrefixBufferGeometry(&self.buffers, sources);
            }

            /// Transactional Tree0+Tree1 publication. Both destinations are fully
            /// preflighted before the first cell write, and the 18 logical row sets
            /// are prepared only once. This is the normal parent-runtime entry point;
            /// the single-tree methods remain useful to independent verifier stages.
            pub fn fillBaseTreesInto(
                self: *TemporalPrefixTreeWriterV3,
                sources: TemporalPrefixTreeSourcesV3,
                tree0: []const []M31,
                tree1: []const []M31,
            ) Error![2]TemporalPrefixTreeReceiptV3 {
                try self.prepareLogicalRows(sources);
                const layout = &sources.custody.commitment_layout;
                try preflightPrefixTree(
                    self,
                    sources,
                    layout,
                    PREFIX_TREE0_INDEX,
                    tree0,
                );
                try preflightPrefixTree(
                    self,
                    sources,
                    layout,
                    PREFIX_TREE1_INDEX,
                    tree1,
                );
                try rejectPrefixTreeCrossAlias(tree0, tree1);
                errdefer {
                    clearPrefixTree(tree1);
                    clearPrefixTree(tree0);
                }
                scatterPrefixTree(
                    self,
                    sources,
                    layout,
                    PREFIX_TREE0_INDEX,
                    tree0,
                );
                scatterPrefixTree(
                    self,
                    sources,
                    layout,
                    PREFIX_TREE1_INDEX,
                    tree1,
                );
                return .{
                    try prefixTreeReceipt(
                        sources.custody,
                        PREFIX_TREE0_INDEX,
                        tree0,
                    ),
                    try prefixTreeReceipt(
                        sources.custody,
                        PREFIX_TREE1_INDEX,
                        tree1,
                    ),
                };
            }

            pub fn fillTree0Into(
                self: *TemporalPrefixTreeWriterV3,
                sources: TemporalPrefixTreeSourcesV3,
                destination: []const []M31,
            ) Error!TemporalPrefixTreeReceiptV3 {
                try self.prepareLogicalRows(sources);
                const layout = &sources.custody.commitment_layout;
                try preflightPrefixTree(
                    self,
                    sources,
                    layout,
                    PREFIX_TREE0_INDEX,
                    destination,
                );
                errdefer clearPrefixTree(destination);
                scatterPrefixTree(
                    self,
                    sources,
                    layout,
                    PREFIX_TREE0_INDEX,
                    destination,
                );
                return prefixTreeReceipt(
                    sources.custody,
                    PREFIX_TREE0_INDEX,
                    destination,
                );
            }

            pub fn fillTree1Into(
                self: *TemporalPrefixTreeWriterV3,
                sources: TemporalPrefixTreeSourcesV3,
                destination: []const []M31,
            ) Error!TemporalPrefixTreeReceiptV3 {
                try self.prepareLogicalRows(sources);
                const layout = &sources.custody.commitment_layout;
                try preflightPrefixTree(
                    self,
                    sources,
                    layout,
                    PREFIX_TREE1_INDEX,
                    destination,
                );
                errdefer clearPrefixTree(destination);
                scatterPrefixTree(
                    self,
                    sources,
                    layout,
                    PREFIX_TREE1_INDEX,
                    destination,
                );
                return prefixTreeReceipt(
                    sources.custody,
                    PREFIX_TREE1_INDEX,
                    destination,
                );
            }

            pub fn fillTree2Into(
                self: *TemporalPrefixTreeWriterV3,
                sources: TemporalPrefixTreeSourcesV3,
                relations: *const recursion.air.universal_challenges.UniversalRelations,
                destination: []const []M31,
            ) Error!TemporalPrefixInteractionsV3 {
                try self.prepareLogicalRows(sources);
                try relations.validate();
                const layout = &sources.custody.commitment_layout;
                if (!std.mem.eql(
                    u8,
                    &relations.registry_order_digest,
                    &layout.relation_registry_sha_id,
                )) return error.InvalidRelationDomainCustody;
                try preflightPrefixTree(
                    self,
                    sources,
                    layout,
                    PREFIX_TREE2_INDEX,
                    destination,
                );
                errdefer clearPrefixTree(destination);
                const claims = try generatePrefixInteractions(
                    self,
                    sources,
                    relations,
                    destination,
                );
                const tree = try prefixTreeReceipt(
                    sources.custody,
                    PREFIX_TREE2_INDEX,
                    destination,
                );
                var result = TemporalPrefixInteractionsV3{
                    .tree = tree,
                    .relation_registry_sha_id = relations.registry_order_digest,
                    .relation_challenges_sha_id = universalRelationsSha(relations),
                    .claims = claims,
                    .identity = undefined,
                };
                result.identity = prefixInteractionsSha(&result);
                try result.validateAgainstRelations(sources.custody, relations);
                return result;
            }

            /// Cold provenance pass over the exact rows retained for Tree 2.  It does
            /// not run in the proving hot path: diagnostics pay the bounded audit
            /// allocations, while normal interaction generation remains allocation
            /// free after writer construction.
            pub fn auditInteractionDomains(
                self: *TemporalPrefixTreeWriterV3,
                sources: TemporalPrefixTreeSourcesV3,
                relations: *const recursion.air.universal_challenges.UniversalRelations,
                interactions: *const TemporalPrefixInteractionsV3,
                tuple_ledger: ?*relation_interaction.TupleLedger,
            ) !TemporalPrefixDomainAuditsV3 {
                try self.prepareLogicalRows(sources);
                try interactions.validateAgainstRelations(sources.custody, relations);
                const rows = try auditPrefixInteractionRows(
                    self,
                    sources,
                    relations,
                    interactions.claims,
                    tuple_ledger,
                );
                var result = TemporalPrefixDomainAuditsV3{
                    .custody_id = sources.custody.custody_id,
                    .interactions_identity = interactions.identity,
                    .rows = rows,
                    .identity = undefined,
                };
                result.identity = prefixDomainAuditsSha(&result);
                try result.validateAgainst(sources.custody, interactions);
                return result;
            }

            /// Constructs the exact rows-0--17 native component cohort only after the
            /// committed interaction receipt is rebound to the same challenge values.
            /// The returned components borrow stable definitions/plans owned by this
            /// writer and `sources`; callers must retain both through prove/verify.
            pub fn initComponentsForManifest(
                self: *TemporalPrefixTreeWriterV3,
                sources: TemporalPrefixTreeSourcesV3,
                comptime manifest_contract: type,
                manifest: *const manifest_contract.Manifest,
                relations: *const recursion.air.universal_challenges.UniversalRelations,
                interactions: *const TemporalPrefixInteractionsV3,
            ) !TemporalPrefixComponentsForManifest(manifest_contract) {
                try self.validateAgainst(sources);
                try interactions.validateAgainstRelations(sources.custody, relations);
                try manifest.validateAgainstPrefix(
                    &sources.custody.commitment_layout,
                );

                const layout = &sources.custody.commitment_layout;
                const transcript_parameters =
                    binary_transcript_source.Parameters.binaryNode();
                const inactive_parameters = sources.inactive_source.parameters;
                const claims = interactions.claims;
                const Adapters = TemporalPrefixAdaptersForManifest(manifest_contract);
                return .{
                    .control = try Adapters.Control.init(
                        &self.owners.control.definition,
                        self.owners.control.relation,
                        manifest,
                        .control,
                        layout.placements[0].geometry.log_size,
                        transcript_parameters.control,
                        relations,
                        claims[0],
                    ),
                    .transcript_air = try Adapters.TranscriptAir.init(
                        &self.owners.transcript_air.definition,
                        self.owners.transcript_air.relation,
                        manifest,
                        .transcript_air,
                        layout.placements[1].geometry.log_size,
                        transcript_parameters.transcript_air,
                        relations,
                        claims[1],
                    ),
                    .transcript_binding = try Adapters.TranscriptBinding.init(
                        &self.owners.transcript_binding.definition,
                        self.owners.transcript_binding.relation,
                        manifest,
                        .transcript_binding,
                        layout.placements[2].geometry.log_size,
                        transcript_parameters.transcript_binding,
                        relations,
                        claims[2],
                    ),
                    .transcript_state = try Adapters.TranscriptState.init(
                        &self.owners.transcript_state.definition,
                        self.owners.transcript_state.relation,
                        manifest,
                        .transcript_state,
                        layout.placements[3].geometry.log_size,
                        transcript_parameters.transcript_state,
                        relations,
                        claims[3],
                    ),
                    .transcript_word = try Adapters.TranscriptWord.init(
                        &self.owners.transcript_word.definition,
                        self.owners.transcript_word.relation,
                        manifest,
                        .transcript_word,
                        layout.placements[4].geometry.log_size,
                        transcript_parameters.transcript_word,
                        relations,
                        claims[4],
                    ),
                    .transcript_payload = try Adapters.TranscriptPayload.init(
                        &self.owners.transcript_payload.definition,
                        self.owners.transcript_payload.relation,
                        manifest,
                        .transcript_payload,
                        layout.placements[5].geometry.log_size,
                        transcript_parameters.transcript_payload,
                        relations,
                        claims[5],
                    ),
                    .pow_check = try Adapters.PowCheck.init(
                        &self.owners.pow_check.definition,
                        self.owners.pow_check.relation,
                        manifest,
                        .pow_check,
                        layout.placements[6].geometry.log_size,
                        transcript_parameters.pow_check,
                        relations,
                        claims[6],
                    ),
                    .pow_frame = try Adapters.PowFrame.init(
                        &self.owners.pow_frame.definition,
                        self.owners.pow_frame.relation,
                        manifest,
                        .pow_frame,
                        layout.placements[7].geometry.log_size,
                        transcript_parameters.pow_frame,
                        relations,
                        claims[7],
                    ),
                    .packed_relation_challenge = try Adapters.PackedRelationChallenge.init(
                        &self.owners.packed_relation_challenge.definition,
                        self.owners.packed_relation_challenge.relation,
                        manifest,
                        .relation_challenge,
                        layout.placements[8].geometry.log_size,
                        transcript_parameters.relation_challenge,
                        relations,
                        claims[8],
                    ),
                    .verifier_randomness = try Adapters.VerifierRandomness.init(
                        &self.owners.verifier_randomness.definition,
                        self.owners.verifier_randomness.relation,
                        manifest,
                        .verifier_randomness,
                        layout.placements[9].geometry.log_size,
                        transcript_parameters.verifier_randomness,
                        relations,
                        claims[9],
                    ),
                    .statement_input = try Adapters.StatementInput.init(
                        &sources.statement_authority.statement_input_definition,
                        sources.statement_authority.statement_input_relation,
                        manifest,
                        .statement_input,
                        layout.placements[10].geometry.log_size,
                        statement_air.STATEMENT_INPUT_PARAMETERS,
                        relations,
                        claims[10],
                    ),
                    .statement_semantics = try Adapters.StatementSemantics.init(
                        &sources.statement_authority.statement_semantics_definition,
                        sources.statement_authority.statement_semantics_relation,
                        manifest,
                        .statement_semantics_input,
                        layout.placements[11].geometry.log_size,
                        statement_air.STATEMENT_SEMANTICS_PARAMETERS,
                        relations,
                        claims[11],
                    ),
                    .vm_claim_input = try Adapters.VmClaimInput.init(
                        &sources.typed_public.owners.claim_input.definition,
                        sources.typed_public.owners.claim_input.relation,
                        manifest,
                        .vm_public_claim_input,
                        layout.placements[12].geometry.log_size,
                        inactive_parameters.claim_input,
                        relations,
                        claims[12],
                    ),
                    .vm_claim_hash = try Adapters.VmClaimHash.init(
                        &sources.typed_public.owners.claim_hash.definition,
                        sources.typed_public.owners.claim_hash.relation,
                        manifest,
                        .vm_public_claim_hash,
                        layout.placements[13].geometry.log_size,
                        inactive_parameters.claim_hash,
                        relations,
                        claims[13],
                    ),
                    .vm_io_hash = try Adapters.VmIoHash.init(
                        &sources.typed_public.owners.io_hash.definition,
                        sources.typed_public.owners.io_hash.relation,
                        manifest,
                        .vm_public_io_hash,
                        layout.placements[14].geometry.log_size,
                        inactive_parameters.io_hash,
                        relations,
                        claims[14],
                    ),
                    .vm_claim_semantics = try Adapters.VmClaimSemantics.init(
                        &sources.typed_public.owners.claim_semantics.definition,
                        sources.typed_public.owners.claim_semantics.relation,
                        manifest,
                        .vm_public_claim_semantics_input,
                        layout.placements[15].geometry.log_size,
                        inactive_parameters.claim_semantics,
                        relations,
                        claims[15],
                    ),
                    .vm_public_logup = try Adapters.VmPublicLogup.init(
                        &sources.typed_public.owners.public_logup.definition,
                        sources.typed_public.owners.public_logup.relation,
                        manifest,
                        .vm_public_logup_input,
                        layout.placements[16].geometry.log_size,
                        inactive_parameters.public_logup,
                        relations,
                        claims[16],
                    ),
                    .vm_public_logup_control = try Adapters.VmPublicLogupControl.init(
                        &sources.typed_public.owners.public_logup_control.definition,
                        sources.typed_public.owners.public_logup_control.relation,
                        manifest,
                        .vm_public_logup_control,
                        layout.placements[17].geometry.log_size,
                        inactive_parameters.public_logup_control,
                        relations,
                        claims[17],
                    ),
                };
            }

            fn prepareLogicalRows(
                self: *TemporalPrefixTreeWriterV3,
                sources: TemporalPrefixTreeSourcesV3,
            ) Error!void {
                try self.validateAgainst(sources);
                const prepared = sources.transcript;
                try prepared.fillControlRowsForPlansInto(
                    self.buffers.control_typed,
                    sources.vm_plan,
                    sources.recursion_plan,
                );
                try prepared.fillBindingRowsInto(self.buffers.binding_typed);
                try prepared.fillStateRowsInto(self.buffers.state_typed);
                try prepared.fillWordRowsInto(self.buffers.word_typed);
                try prepared.fillPayloadRowsInto(self.buffers.payload_typed);
                try prepared.fillPowRowsInto(
                    self.buffers.pow_check_typed,
                    self.buffers.pow_frame_typed,
                );
                try prepared.fillRelationChallengeRowsInto(self.buffers.packed_typed);
                try prepared.validateRelationChallengeRows(self.buffers.packed_typed);
                try prepared.fillRandomnessRowsInto(self.buffers.randomness_typed);
                try fillPrefixLogicalRows(self, sources);
            }
        };
    };
}
