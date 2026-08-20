//! Cohesive internal authority extracted from recursive_temporal_nonfri_source_v2.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const M31 = context.d_M31;
        const QM31 = context.d_QM31;
        const m31 = context.d_m31;
        const recursion = context.d_recursion;
        const inactive = context.d_inactive;
        const leaf_authority = context.d_leaf_authority;
        const schedule = context.d_schedule;
        const segment_public = context.d_segment_public;
        const statement_air = context.d_statement_air;
        const statement_source = context.d_statement_source;
        const temporal = context.d_temporal;
        const relation_interaction = context.d_relation_interaction;
        const global_closure = context.d_global_closure;
        const Digest = context.d_Digest;
        const PREFIX_ROW_COUNT = context.d_PREFIX_ROW_COUNT;
        const PREFIX_TREE_WRITER_FORMAT_VERSION = context.d_PREFIX_TREE_WRITER_FORMAT_VERSION;
        const PREFIX_TREE_WRITER_SCHEMA_VERSION = context.d_PREFIX_TREE_WRITER_SCHEMA_VERSION;
        const PREFIX_INTERACTIONS_SCHEMA_VERSION = context.d_PREFIX_INTERACTIONS_SCHEMA_VERSION;
        const PREFIX_DOMAIN_AUDITS_SCHEMA_VERSION = context.d_PREFIX_DOMAIN_AUDITS_SCHEMA_VERSION;
        const PREFIX_TREE_COUNT = context.d_PREFIX_TREE_COUNT;
        const PREFIX_TREE2_INDEX = context.d_PREFIX_TREE2_INDEX;
        const Error = context.d_Error;
        const PreparedTranscriptRowsV2 = context.d_PreparedTranscriptRowsV2;
        const PreparedRows10Through11V2 = context.d_PreparedRows10Through11V2;
        const TemporalRows0Through17CustodyV3 = context.d_TemporalRows0Through17CustodyV3;
        const TemporalPrefixTreeWriterV3 = context.d_TemporalPrefixTreeWriterV3;
        const prefixTreeColumnCount = context.d_prefixTreeColumnCount;
        const prefixTreeOffset = context.d_prefixTreeOffset;
        const prefixTreeColumns = context.d_prefixTreeColumns;
        const prefixTreeCellCount = context.d_prefixTreeCellCount;
        const prefixTreeSha = context.d_prefixTreeSha;
        const prefixTreeReceiptSha = context.d_prefixTreeReceiptSha;
        const prefixInteractionsSha = context.d_prefixInteractionsSha;
        const prefixDomainAuditsSha = context.d_prefixDomainAuditsSha;
        const prefixGlobalRowClaim = context.d_prefixGlobalRowClaim;
        const universalRelationsSha = context.d_universalRelationsSha;
        const byteRange = context.d_byteRange;
        const allZero = context.d_allZero;

        pub const TemporalPrefixTreeSourcesV3 = struct {
            custody: *const TemporalRows0Through17CustodyV3,
            transcript: *const PreparedTranscriptRowsV2,
            statement: *const PreparedRows10Through11V2,
            statement_authority: *const statement_source.Authority,
            statement_workspace: *statement_air.Workspace,
            inactive_source: *const inactive.Source,
            inactive_prepared: *const inactive.Prepared,
            typed_public: *const segment_public.Source,
            vm_plan: *const schedule.Plan,
            recursion_plan: *const schedule.Plan,
            preprocessing: *const leaf_authority.Preprocessing,

            pub fn validate(self: TemporalPrefixTreeSourcesV3) Error!void {
                try self.custody.validate();
                try self.transcript.validate();
                try self.statement.validateHot(
                    self.statement_authority,
                    self.statement_workspace,
                );
                // `Prepared.validateAgainst` transitively authenticates the inactive
                // source and typed public source. Calling the source first would repeat
                // both complete schedule audits and their temporary digest allocation.
                self.inactive_prepared.validateAgainst(
                    self.inactive_source,
                    self.typed_public,
                    self.vm_plan,
                    self.recursion_plan,
                    self.preprocessing,
                ) catch |err| switch (err) {
                    error.OutOfMemory => return error.OutOfMemory,
                    else => return error.SourceIdentityMismatch,
                };

                try self.validateIdentityLinks();
            }

            /// Allocation-free tree-path admission. `TemporalPrefixTreeWriterV3.init`
            /// first calls the exhaustive `validate`, including both complete plan
            /// digests. Subsequent fills consume only sealed cached rows, so rehashing
            /// the full verifier schedules would add heap traffic without authenticating
            /// any additional value used by the writer.
            pub fn validateHot(self: TemporalPrefixTreeSourcesV3) Error!void {
                try self.custody.validate();
                try self.transcript.validate();
                try self.statement.validateHot(
                    self.statement_authority,
                    self.statement_workspace,
                );
                // Prepared -> inactive source -> typed public source is the complete
                // sealed chain. Keep exactly one walk on every hot tree admission.
                self.inactive_prepared.validateHotAgainstSealedPlans(
                    self.inactive_source,
                    self.typed_public,
                    self.vm_plan,
                    self.recursion_plan,
                    self.preprocessing,
                ) catch return error.SourceIdentityMismatch;

                try self.validateIdentityLinks();
            }

            fn validateIdentityLinks(self: TemporalPrefixTreeSourcesV3) Error!void {
                const manifest = try self.transcript.manifestForPlans(
                    self.vm_plan,
                    self.recursion_plan,
                );
                const domains = try self.transcript.relationDomainShaIds();
                if (!std.meta.eql(manifest, self.custody.transcript_manifest) or
                    !std.meta.eql(
                        self.transcript.child_replays,
                        self.custody.child_replays,
                    ) or !std.meta.eql(
                    domains,
                    self.custody.child_relation_domain_sha_ids,
                ) or !std.meta.eql(
                    self.statement.public,
                    self.custody.parent_public,
                ) or !std.meta.eql(
                    self.statement.source_id,
                    self.custody.rows_10_through_17.statement_source_id,
                ) or !std.mem.eql(
                    u8,
                    &self.inactive_source.authority_seal,
                    &self.custody.rows_10_through_17.inactive_source_sha_id,
                ) or !std.mem.eql(
                    u8,
                    &self.inactive_prepared.authority_seal,
                    &self.custody.rows_10_through_17.inactive_prepared_sha_id,
                )) {
                    return error.SourceIdentityMismatch;
                }
            }
        };

        /// Pointer-free commitment receipt for one exact V3 prefix tree.
        pub const TemporalPrefixTreeReceiptV3 = struct {
            format_version: u16 = PREFIX_TREE_WRITER_FORMAT_VERSION,
            schema_version: u16 = PREFIX_TREE_WRITER_SCHEMA_VERSION,
            tree_index: u8,
            padding: [3]u8 = .{ 0, 0, 0 },
            column_count: u32,
            cell_count: u64,
            custody_id: Digest,
            layout_sha_id: [32]u8,
            tree_sha_id: [32]u8,
            identity: [32]u8,

            pub fn validate(
                self: *const TemporalPrefixTreeReceiptV3,
                custody: *const TemporalRows0Through17CustodyV3,
            ) Error!void {
                try custody.validate();
                const layout = &custody.commitment_layout;
                if (self.format_version != PREFIX_TREE_WRITER_FORMAT_VERSION or
                    self.schema_version != PREFIX_TREE_WRITER_SCHEMA_VERSION or
                    self.tree_index >= PREFIX_TREE_COUNT or !allZero(&self.padding) or
                    self.column_count != prefixTreeColumnCount(layout, self.tree_index) or
                    self.cell_count != try prefixTreeCellCount(layout, self.tree_index) or
                    !std.meta.eql(self.custody_id, custody.custody_id) or
                    !std.mem.eql(u8, &self.layout_sha_id, &layout.layout_sha_id) or
                    allZero(&self.tree_sha_id) or
                    !std.mem.eql(u8, &self.identity, &prefixTreeReceiptSha(self)))
                {
                    return error.InvalidPrefixTreeReceipt;
                }
            }

            /// Re-admits the exact committed column view immediately before a PCS
            /// consumer borrows it. This catches slice-table, shape, alias, field, or
            /// cell mutation after the writer minted the pointer-free receipt.
            pub fn validateStorage(
                self: *const TemporalPrefixTreeReceiptV3,
                custody: *const TemporalRows0Through17CustodyV3,
                columns: []const []M31,
            ) Error!void {
                try self.validate(custody);
                const tree: usize = self.tree_index;
                const layout = &custody.commitment_layout;
                if (columns.len != @as(
                    usize,
                    @intCast(prefixTreeColumnCount(layout, tree)),
                )) return error.InvalidTraceShape;
                for (layout.placements) |placement| {
                    const offset: usize = @intCast(prefixTreeOffset(placement, tree));
                    const count: usize = @intCast(prefixTreeColumns(placement, tree));
                    const trace_size = @as(usize, 1) <<
                        @intCast(placement.geometry.log_size);
                    if (offset + count > columns.len) return error.InvalidTraceShape;
                    for (columns[offset .. offset + count]) |column| {
                        if (column.len != trace_size) return error.InvalidTraceShape;
                        for (column) |value| if (value.toU32() >= m31.Modulus)
                            return error.NonBaseCircuitInput;
                    }
                }
                for (columns, 0..) |column, index| {
                    const range = try byteRange(column);
                    for (columns[0..index]) |prior|
                        if (range.overlaps(try byteRange(prior)))
                            return error.DestinationAlias;
                }
                if (!std.mem.eql(
                    u8,
                    &self.tree_sha_id,
                    &prefixTreeSha(custody, tree, columns),
                )) return error.InvalidPrefixTreeReceipt;
            }
        };

        /// Tree-2 receipt. Claims are emitted only by the authenticated relation
        /// plans over the exact logical rows retained by the writer.
        pub const TemporalPrefixInteractionsV3 = struct {
            format_version: u16 = PREFIX_TREE_WRITER_FORMAT_VERSION,
            schema_version: u16 = PREFIX_INTERACTIONS_SCHEMA_VERSION,
            padding: [4]u8 = .{ 0, 0, 0, 0 },
            tree: TemporalPrefixTreeReceiptV3,
            relation_registry_sha_id: [32]u8,
            relation_challenges_sha_id: [32]u8,
            claims: [PREFIX_ROW_COUNT]QM31,
            identity: [32]u8,

            pub fn validate(
                self: *const TemporalPrefixInteractionsV3,
                custody: *const TemporalRows0Through17CustodyV3,
            ) Error!void {
                if (self.format_version != PREFIX_TREE_WRITER_FORMAT_VERSION or
                    self.schema_version != PREFIX_INTERACTIONS_SCHEMA_VERSION or
                    !allZero(&self.padding) or self.tree.tree_index != PREFIX_TREE2_INDEX or
                    allZero(&self.relation_challenges_sha_id) or
                    !std.mem.eql(
                        u8,
                        &self.relation_registry_sha_id,
                        &custody.commitment_layout.relation_registry_sha_id,
                    ))
                {
                    return error.InvalidPrefixTreeReceipt;
                }
                try self.tree.validate(custody);
                for (self.claims) |claim| for (claim.toM31Array()) |coordinate|
                    if (coordinate.toU32() >= m31.Modulus)
                        return error.NonBaseCircuitInput;
                if (!std.mem.eql(u8, &self.identity, &prefixInteractionsSha(self)))
                    return error.InvalidPrefixTreeReceipt;
            }

            /// Rebinds the receipt to the exact challenge values used by component
            /// evaluators. Registry identity alone detects domain-order drift, but not
            /// a same-registry challenge substitution after Tree2 generation.
            pub fn validateAgainstRelations(
                self: *const TemporalPrefixInteractionsV3,
                custody: *const TemporalRows0Through17CustodyV3,
                relations: *const recursion.air.universal_challenges.UniversalRelations,
            ) Error!void {
                try self.validate(custody);
                relations.validate() catch return error.InvalidRelationDomainCustody;
                if (!std.mem.eql(
                    u8,
                    &self.relation_registry_sha_id,
                    &relations.registry_order_digest,
                ) or !std.mem.eql(
                    u8,
                    &self.relation_challenges_sha_id,
                    &universalRelationsSha(relations),
                )) return error.InvalidRelationDomainCustody;
            }
        };

        /// Cold, pointer-free decomposition of the exact committed row-0--17 claims
        /// by universal relation domain.  This receipt is minted only by replaying the
        /// authenticated plans over the writer's retained logical rows and is bound to
        /// the Tree-2 interaction receipt (including its exact challenge identity).
        pub const TemporalPrefixDomainAuditsV3 = struct {
            format_version: u16 = PREFIX_TREE_WRITER_FORMAT_VERSION,
            schema_version: u16 = PREFIX_DOMAIN_AUDITS_SCHEMA_VERSION,
            padding: [4]u8 = .{ 0, 0, 0, 0 },
            custody_id: Digest,
            interactions_identity: [32]u8,
            rows: [PREFIX_ROW_COUNT]relation_interaction.DomainAudit,
            identity: [32]u8,

            pub fn validateAgainst(
                self: *const TemporalPrefixDomainAuditsV3,
                custody: *const TemporalRows0Through17CustodyV3,
                interactions: *const TemporalPrefixInteractionsV3,
            ) Error!void {
                try interactions.validate(custody);
                if (self.format_version != PREFIX_TREE_WRITER_FORMAT_VERSION or
                    self.schema_version != PREFIX_DOMAIN_AUDITS_SCHEMA_VERSION or
                    !allZero(&self.padding) or
                    !std.meta.eql(self.custody_id, custody.custody_id) or
                    !std.mem.eql(
                        u8,
                        &self.interactions_identity,
                        &interactions.identity,
                    )) return error.InvalidRelationDomainCustody;

                for (self.rows, interactions.claims) |audit, claim| {
                    var total = QM31.zero();
                    for (audit.values) |value| {
                        for (value.toM31Array()) |coordinate|
                            if (coordinate.toU32() >= m31.Modulus)
                                return error.NonBaseCircuitInput;
                        total = total.add(value);
                    }
                    for (audit.total.toM31Array()) |coordinate|
                        if (coordinate.toU32() >= m31.Modulus)
                            return error.NonBaseCircuitInput;
                    if (!total.eql(audit.total) or !audit.total.eql(claim))
                        return error.InvalidRelationDomainCustody;
                }
                if (!std.mem.eql(u8, &self.identity, &prefixDomainAuditsSha(self)))
                    return error.InvalidRelationDomainCustody;
            }

            pub fn rowClaims(
                self: *const TemporalPrefixDomainAuditsV3,
            ) [PREFIX_ROW_COUNT]global_closure.RowClaimsV1 {
                var result: [PREFIX_ROW_COUNT]global_closure.RowClaimsV1 = undefined;
                for (&result, self.rows, 0..) |*destination, audit, row|
                    destination.* = prefixGlobalRowClaim(@enumFromInt(row), audit);
                return result;
            }
        };

        // Retained, allocation-free hot writer for exact temporal rows 0--17.
        // Construction authenticates every transcript relation plan and allocates a
        // single max-sized inversion slab reused sequentially by all 18 components.
    };
}
