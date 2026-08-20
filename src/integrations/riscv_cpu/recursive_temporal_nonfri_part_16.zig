//! Cohesive internal authority extracted from recursive_temporal_nonfri_source_v2.zig.

pub fn Namespace(comptime context: type) type {
    return struct {
        const std = context.d_std;
        const M31 = context.d_M31;
        const QM31 = context.d_QM31;
        const m31 = context.d_m31;
        const channel = context.d_channel;
        const statement_air = context.d_statement_air;
        const statement_source = context.d_statement_source;
        const temporal = context.d_temporal;
        const transcript_payload = context.d_transcript_payload;
        const segment_artifact = context.d_segment_artifact;
        const packed_relation_challenge_v2 = context.d_packed_relation_challenge_v2;
        const IMPLEMENTED_ROW_MASK = context.d_IMPLEMENTED_ROW_MASK;
        const TRANSCRIPT_ROW_MASK = context.d_TRANSCRIPT_ROW_MASK;
        const ROWS_0_THROUGH_9_AVAILABLE = context.d_ROWS_0_THROUGH_9_AVAILABLE;
        const ROWS_0_THROUGH_9_EXACT_REPLAY_AVAILABLE = context.d_ROWS_0_THROUGH_9_EXACT_REPLAY_AVAILABLE;
        const ROWS_0_THROUGH_9_TYPED_AIR_AVAILABLE = context.d_ROWS_0_THROUGH_9_TYPED_AIR_AVAILABLE;
        const ROWS_0_THROUGH_9_EXTENDED_MANIFEST_AVAILABLE = context.d_ROWS_0_THROUGH_9_EXTENDED_MANIFEST_AVAILABLE;
        const ROWS_0_THROUGH_17_COMMITMENT_LAYOUT_AVAILABLE = context.d_ROWS_0_THROUGH_17_COMMITMENT_LAYOUT_AVAILABLE;
        const ROWS_0_THROUGH_17_RELATION_DOMAIN_CUSTODY_AVAILABLE = context.d_ROWS_0_THROUGH_17_RELATION_DOMAIN_CUSTODY_AVAILABLE;
        const ROWS_0_THROUGH_17_TREE_WRITER_AVAILABLE = context.d_ROWS_0_THROUGH_17_TREE_WRITER_AVAILABLE;
        const TRANSCRIPT_ROW_1_TYPED_AIR_AVAILABLE = context.d_TRANSCRIPT_ROW_1_TYPED_AIR_AVAILABLE;
        const TRANSCRIPT_POSEIDON_PROVIDER_AVAILABLE = context.d_TRANSCRIPT_POSEIDON_PROVIDER_AVAILABLE;
        const TRANSCRIPT_ROWS_0_THROUGH_3_TYPED_AIR_AVAILABLE = context.d_TRANSCRIPT_ROWS_0_THROUGH_3_TYPED_AIR_AVAILABLE;
        const TRANSCRIPT_ROWS_0_THROUGH_4_TYPED_AIR_AVAILABLE = context.d_TRANSCRIPT_ROWS_0_THROUGH_4_TYPED_AIR_AVAILABLE;
        const TRANSCRIPT_ROWS_0_THROUGH_7_TYPED_AIR_AVAILABLE = context.d_TRANSCRIPT_ROWS_0_THROUGH_7_TYPED_AIR_AVAILABLE;
        const TRANSCRIPT_ROWS_6_7_9_TYPED_AIR_AVAILABLE = context.d_TRANSCRIPT_ROWS_6_7_9_TYPED_AIR_AVAILABLE;
        const TRANSCRIPT_ROW_8_PACKED_V2_TYPED_AIR_AVAILABLE = context.d_TRANSCRIPT_ROW_8_PACKED_V2_TYPED_AIR_AVAILABLE;
        const TYPED_TRANSCRIPT_ROW_MASK = context.d_TYPED_TRANSCRIPT_ROW_MASK;
        const CHILD_QUERY_COUNT = context.d_CHILD_QUERY_COUNT;
        const MAX_CHILD_FRI_ROUNDS = context.d_MAX_CHILD_FRI_ROUNDS;
        const PREFIX_TREE_COUNT = context.d_PREFIX_TREE_COUNT;
        const TemporalPayloadAuthorityV2 = context.d_TemporalPayloadAuthorityV2;
        const TemporalPrefixCommitmentLayoutV3 = context.d_TemporalPrefixCommitmentLayoutV3;
        const Error = context.d_Error;
        const TranscriptPrefixRequirementsV1 = context.d_TranscriptPrefixRequirementsV1;
        const CURRENT_CAPABILITIES = context.d_CURRENT_CAPABILITIES;
        const TemporalChildTranscriptReplayV2 = context.d_TemporalChildTranscriptReplayV2;
        const PreparedTranscriptRowsV2 = context.d_PreparedTranscriptRowsV2;
        const typecheckTemporalTranscriptPreparation = context.d_typecheckTemporalTranscriptPreparation;
        const typecheckTemporalTranscriptWriters = context.d_typecheckTemporalTranscriptWriters;
        const PreparedRows10Through11V2 = context.d_PreparedRows10Through11V2;
        const Rows10Through17AuthorityV2 = context.d_Rows10Through17AuthorityV2;
        const TemporalPrefixTreeWriterV3 = context.d_TemporalPrefixTreeWriterV3;
        const prefixTreeColumnCount = context.d_prefixTreeColumnCount;
        const prefixTreeOffset = context.d_prefixTreeOffset;
        const prefixTreeColumns = context.d_prefixTreeColumns;
        const prefixTreeCellCount = context.d_prefixTreeCellCount;
        const initTemporalRows0Through17CustodyInto = context.d_initTemporalRows0Through17CustodyInto;
        const typecheckTemporalStatementMainWriter = context.d_typecheckTemporalStatementMainWriter;
        const typecheckTemporalStatementInteractionWriter = context.d_typecheckTemporalStatementInteractionWriter;
        const typecheckTemporalStatementDomainAudit = context.d_typecheckTemporalStatementDomainAudit;
        const transcriptReplayIdentity = context.d_transcriptReplayIdentity;
        const temporalPayloadAuthoritySha = context.d_temporalPayloadAuthoritySha;

        test "temporal statement adapters select the binary proof-kind parameters" {
            try std.testing.expect(statement_air.STATEMENT_INPUT_PARAMETERS[0].isZero());
            try std.testing.expect(statement_air.STATEMENT_INPUT_PARAMETERS[1].eql(M31.one()));
            try std.testing.expect(statement_air.STATEMENT_SEMANTICS_PARAMETERS[0].isZero());
            try std.testing.expect(statement_air.STATEMENT_SEMANTICS_PARAMETERS[1].eql(M31.one()));
            try std.testing.expect(!std.meta.eql(
                statement_air.STATEMENT_INPUT_PARAMETERS,
                statement_source.STATEMENT_INPUT_PARAMETERS,
            ));
            try std.testing.expect(!std.meta.eql(
                statement_air.STATEMENT_SEMANTICS_PARAMETERS,
                statement_source.STATEMENT_SEMANTICS_PARAMETERS,
            ));
        }

        test "temporal non-FRI authority exposes exact honest frontier" {
            const payload_authority = TemporalPayloadAuthorityV2.pinned();
            try payload_authority.validate();
            var frozen_payload = payload_authority;
            frozen_payload.frozen_witness_compatible = true;
            frozen_payload.identity = temporalPayloadAuthoritySha(&frozen_payload);
            try std.testing.expectError(
                error.InvalidTemporalPayloadAuthority,
                frozen_payload.validate(),
            );
            var truncated_payload = payload_authority;
            truncated_payload.source_kind_count = transcript_payload.INPUT_KIND_COUNT;
            truncated_payload.identity = temporalPayloadAuthoritySha(&truncated_payload);
            try std.testing.expectError(
                error.InvalidTemporalPayloadAuthority,
                truncated_payload.validate(),
            );
            var packed_definition = try packed_relation_challenge_v2.build(
                std.testing.allocator,
            );
            defer packed_definition.deinit();
            try packed_definition.validate();
            _ = TemporalChildTranscriptReplayV2.deriveFromArtifact;
            _ = PreparedTranscriptRowsV2.init;
            _ = typecheckTemporalTranscriptPreparation;
            _ = typecheckTemporalTranscriptWriters;
            _ = PreparedRows10Through11V2.init;
            _ = Rows10Through17AuthorityV2.init;
            _ = initTemporalRows0Through17CustodyInto;
            _ = TemporalPrefixTreeWriterV3.init;
            _ = TemporalPrefixTreeWriterV3.auditInteractionDomains;
            _ = typecheckTemporalStatementMainWriter;
            _ = typecheckTemporalStatementInteractionWriter;
            _ = typecheckTemporalStatementDomainAudit;
            try std.testing.expect(!CURRENT_CAPABILITIES.ready());
            try std.testing.expectError(
                error.ProductionCapabilityUnavailable,
                CURRENT_CAPABILITIES.requireProduction(),
            );
            try std.testing.expectEqual(@as(u64, 0x0003_fc00), IMPLEMENTED_ROW_MASK);
            try std.testing.expectEqual(@as(u64, 0x0000_03ff), TRANSCRIPT_ROW_MASK);
            try std.testing.expect(ROWS_0_THROUGH_9_EXACT_REPLAY_AVAILABLE);
            try std.testing.expect(ROWS_0_THROUGH_9_TYPED_AIR_AVAILABLE);
            try std.testing.expect(ROWS_0_THROUGH_9_EXTENDED_MANIFEST_AVAILABLE);
            try std.testing.expect(TRANSCRIPT_ROW_1_TYPED_AIR_AVAILABLE);
            try std.testing.expect(TRANSCRIPT_POSEIDON_PROVIDER_AVAILABLE);
            try std.testing.expect(TRANSCRIPT_ROWS_0_THROUGH_3_TYPED_AIR_AVAILABLE);
            try std.testing.expect(TRANSCRIPT_ROWS_0_THROUGH_4_TYPED_AIR_AVAILABLE);
            try std.testing.expect(TRANSCRIPT_ROWS_0_THROUGH_7_TYPED_AIR_AVAILABLE);
            try std.testing.expect(TRANSCRIPT_ROWS_6_7_9_TYPED_AIR_AVAILABLE);
            try std.testing.expect(TRANSCRIPT_ROW_8_PACKED_V2_TYPED_AIR_AVAILABLE);
            try std.testing.expectEqual(@as(u64, 0x3ff), TYPED_TRANSCRIPT_ROW_MASK);
            try std.testing.expect(ROWS_0_THROUGH_9_AVAILABLE);
            try std.testing.expect(ROWS_0_THROUGH_17_COMMITMENT_LAYOUT_AVAILABLE);
            try std.testing.expect(
                ROWS_0_THROUGH_17_RELATION_DOMAIN_CUSTODY_AVAILABLE,
            );
            try std.testing.expect(!ROWS_0_THROUGH_17_TREE_WRITER_AVAILABLE);
            comptime if (TranscriptPrefixRequirementsV1 !=
                segment_artifact.TranscriptPrefixV1)
                @compileError("temporal replay detached from verifier prefix ABI");
            try std.testing.expect(!@hasDecl(
                PreparedRows10Through11V2,
                "initFromClaims",
            ));
            try std.testing.expect(!@hasDecl(
                Rows10Through17AuthorityV2,
                "setClaims",
            ));
        }

        pub fn syntheticReplayForTest(seed: u32) Error!TemporalChildTranscriptReplayV2 {
            std.debug.assert(seed > 0 and seed + 7 < m31.Modulus);
            var result = TemporalChildTranscriptReplayV2{
                .fri_round_count = 1,
                .publication_id = .{seed} ** channel.RATE,
                .witness_id = .{seed + 1} ** channel.RATE,
                .capture_id = .{seed + 2} ** channel.RATE,
                .transcript_prefix_id = .{seed + 3} ** channel.RATE,
                .manifest_sha_id = .{@as(u8, @intCast(seed))} ** 32,
                .pre_core_digest = .{seed + 4} ** channel.RATE,
                .pre_core_draw_count = 0,
                .composition_randomness = QM31.fromU32Unchecked(seed, 0, 0, 0),
                .oods_seed = QM31.fromU32Unchecked(seed + 1, 0, 0, 0),
                .deep_randomness = QM31.fromU32Unchecked(seed + 2, 0, 0, 0),
                .fri_alphas = .{QM31.zero()} ** MAX_CHILD_FRI_ROUNDS,
                .raw_queries = .{0} ** CHILD_QUERY_COUNT,
                .final_digest = .{seed + 5} ** channel.RATE,
                .final_draw_count = 1,
                .replay_id = undefined,
            };
            result.fri_alphas[0] = QM31.fromU32Unchecked(seed + 3, 0, 0, 0);
            result.replay_id = transcriptReplayIdentity(&result);
            try result.validate();
            return result;
        }

        /// Test-only owner for the protocol's ragged commitment-column layout.  One
        /// backing allocation makes ownership explicit while the column table retains
        /// the exact per-component trace lengths pinned by the V3 placements.
        pub const TestPrefixTreeStorage = struct {
            allocator: std.mem.Allocator,
            columns: [][]M31,
            cells: []M31,

            fn init(
                allocator: std.mem.Allocator,
                layout: *const TemporalPrefixCommitmentLayoutV3,
                tree: usize,
            ) Error!TestPrefixTreeStorage {
                try layout.validate();
                if (tree >= PREFIX_TREE_COUNT) return error.InvalidTraceShape;
                const column_count: usize = @intCast(prefixTreeColumnCount(
                    layout,
                    tree,
                ));
                const cell_count = std.math.cast(
                    usize,
                    try prefixTreeCellCount(layout, tree),
                ) orelse return error.ArithmeticOverflow;
                const columns = try allocator.alloc([]M31, column_count);
                errdefer allocator.free(columns);
                const cells = try allocator.alloc(M31, cell_count);
                errdefer allocator.free(cells);
                @memset(cells, M31.zero());

                var assigned_columns: usize = 0;
                var assigned_cells: usize = 0;
                for (layout.placements) |placement| {
                    const offset: usize = @intCast(prefixTreeOffset(placement, tree));
                    const count: usize = @intCast(prefixTreeColumns(placement, tree));
                    const trace_size = @as(usize, 1) <<
                        @intCast(placement.geometry.log_size);
                    if (offset != assigned_columns or
                        assigned_cells + count * trace_size > cells.len)
                    {
                        return error.InvalidTraceShape;
                    }
                    for (columns[offset .. offset + count]) |*column| {
                        column.* = cells[assigned_cells .. assigned_cells + trace_size];
                        assigned_cells += trace_size;
                    }
                    assigned_columns += count;
                }
                if (assigned_columns != columns.len or assigned_cells != cells.len)
                    return error.InvalidTraceShape;
                return .{
                    .allocator = allocator,
                    .columns = columns,
                    .cells = cells,
                };
            }

            fn deinit(self: *TestPrefixTreeStorage) void {
                self.allocator.free(self.cells);
                self.allocator.free(self.columns);
                self.* = undefined;
            }

            fn fillDeterministic(self: *TestPrefixTreeStorage, seed: u32) void {
                const modulus_minus_one: u64 = m31.Modulus - 1;
                for (self.columns, 0..) |column, column_index| {
                    for (column, 0..) |*cell, row| {
                        const value = (@as(u64, seed) +
                            131 * @as(u64, @intCast(column_index)) +
                            17 * @as(u64, @intCast(row))) % modulus_minus_one + 1;
                        cell.* = M31.fromCanonical(@intCast(value));
                    }
                }
            }
        };
    };
}
