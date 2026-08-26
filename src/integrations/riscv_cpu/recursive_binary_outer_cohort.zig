//! Concrete all-36-row cohort for the binary outer-proof engine.
//!
//! This is an assembly boundary, not a new source of AIR equations. Rows
//! 0--17 and row 35 remain owned by `binary_pair_nonfri_outer_bundle`; rows
//! 18--34 remain owned by `binary_fri_outer_bundle`. The cohort binds both
//! bundles to one admitted pair, builds the canonical universal manifest,
//! regenerates verifier claims from authority, and admits a proof only after
//! the exact 47-domain global relation audit closes.
//!
//! The complete native STWO proof transaction is deliberately still marked
//! protocol substrate: the rows-0--17 V1 parent model retains split child-role
//! semantics and is not yet an authenticated temporal V2 recursive protocol.

const std = @import("std");
const builtin = @import("builtin");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const cohort_support = @import("recursive_binary_outer_cohort_support.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

const recursion = frontend.recursion;
const air = recursion.air;
const fixed_wire = recursion.fixed_wire;
const manifest_mod = air.universal_adapter_manifest;
const universal_manifest = air.universal_manifest;
const roster = air.universal_roster;
const universal = air.universal_challenges;
const relation_interaction = air.relation_interaction;
const shared_provider = air.universal_shared_provider;
const non_fri_mod = recursion.binary_pair_nonfri_outer_bundle;
const fri_mod = recursion.binary_fri_outer_bundle;
const fri_source_mod = recursion.binary_fri_outer_source;
const global_closure = recursion.binary_global_closure_outer_source;
const pair_node = recursion.pair_node;
const statement_source = recursion.outer_parent_statement_air_source;
const TreeScratch = cohort_support.TreeScratch;
const validateCrossCustodyEnvelope = cohort_support.validateCrossCustodyEnvelope;
const validateCrossCustodyCold = cohort_support.validateCrossCustodyCold;
const globalBoundaryEvidence = cohort_support.globalBoundaryEvidence;
const validateManifestComposition = cohort_support.validateManifestComposition;
const rowClaim = cohort_support.rowClaim;
const poseidonRowClaim = cohort_support.poseidonRowClaim;
const appendFriTupleContributions = cohort_support.appendFriTupleContributions;
const printUnmatchedTupleGroups = cohort_support.printUnmatchedTupleGroups;
const generatedIdentity = cohort_support.generatedIdentity;
const preflightTree = cohort_support.preflightTree;
const clearTree = cohort_support.clearTree;
const digestWords = cohort_support.digestWords;
const allZero = cohort_support.allZero;

pub const FORMAT_VERSION: u16 = 1;
pub const GENERATED_FORMAT_VERSION: u16 = 1;
pub const AUTHORITY_TRANSCRIPT_DOMAIN: u32 = 0x4342_4f31; // "CBO1"
pub const COLD_MANIFEST_COMPOSITION_VALIDATION_PASSES_PER_INIT: usize = 1;
pub const COMPLETE_ROW_COUNT: usize = roster.COMPONENT_COUNT;
pub const FRI_FIRST_ROW: usize = fri_source_mod.FIRST_ROW;
pub const FRI_ROW_COUNT: usize = fri_source_mod.ROW_COUNT;
pub const FRI_TYPED_ROW_COUNT: usize = fri_source_mod.TYPED_RELATION_ROW_COUNT;
pub const PROVIDER_ROW: usize = @intFromEnum(global_closure.PROVIDER_ROW);

pub const PROTOCOL_SUBSTRATE_ONLY = true;
pub const WHOLE_FRONTEND_VERIFIED = false;
pub const AUTHENTICATED_TEMPORAL_V2 = false;
pub const PRODUCTION_ACTIVATION = false;

/// Cohort-layer costs are exact. Source-owned costs are preserved rather than
/// hidden by the composition boundary.
pub const HOT_ENVELOPE_HEAP_ALLOCATIONS: usize = 0;
pub const HOT_COHORT_TREE_OVERHEAD_HEAP_ALLOCATIONS =
    [_]usize{0} ** manifest_mod.TREE_COUNT;
pub const HOT_TREE_HEAP_ALLOCATIONS = [manifest_mod.TREE_COUNT]usize{
    non_fri_mod.HOT_TREE_HEAP_ALLOCATIONS[0] +
        fri_mod.HOT_TREE_HEAP_ALLOCATIONS[0],
    non_fri_mod.HOT_TREE_HEAP_ALLOCATIONS[1] +
        fri_mod.HOT_TREE_HEAP_ALLOCATIONS[1],
    non_fri_mod.HOT_TREE_HEAP_ALLOCATIONS[2] +
        fri_mod.HOT_TREE_HEAP_ALLOCATIONS[2],
};
pub const HOT_ALL_TREES_HEAP_ALLOCATIONS: usize =
    HOT_TREE_HEAP_ALLOCATIONS[0] + HOT_TREE_HEAP_ALLOCATIONS[1] +
    HOT_TREE_HEAP_ALLOCATIONS[2];
pub const VERIFIER_REBUILD_COHORT_OVERHEAD_HEAP_ALLOCATIONS: usize = 4;
pub const VERIFIER_REBUILD_TOTAL_HEAP_ALLOCATIONS: usize =
    VERIFIER_REBUILD_COHORT_OVERHEAD_HEAP_ALLOCATIONS +
    HOT_TREE_HEAP_ALLOCATIONS[manifest_mod.MAIN_TREE_INDEX] +
    HOT_TREE_HEAP_ALLOCATIONS[manifest_mod.INTERACTION_TREE_INDEX];
pub const VERIFIER_REBUILD_PEAK_LIVE_TREE_COUNT: usize = 1;
pub const ROW34_REPLAYED_SCALAR_PERMUTATIONS: usize =
    fri_mod.ROW34_REPLAYED_SCALAR_PERMUTATIONS;

pub const Error = error{
    ArithmeticOverflow,
    AuthorityIdentityMismatch,
    ClaimAuditMismatch,
    CrossCustodyMismatch,
    DestinationAlias,
    DestinationNotFresh,
    DestinationShapeMismatch,
    GeneratedIdentityMismatch,
    ManifestGeometryMismatch,
    RosterOrderMismatch,
};

/// Concrete composition of the two frozen source-owned bundles. One child
/// dimension is intentional: both halves must consume the same fixed child
/// proof geometry and the same authenticated `binary_pair_authority.Prepared`.
pub fn Cohort(
    comptime child_dimensions: fixed_wire.Dimensions,
    comptime statement_dimensions: fixed_wire.Dimensions,
) type {
    child_dimensions.validate();
    statement_dimensions.validate();

    const NonFri = non_fri_mod.Bundle(child_dimensions, statement_dimensions);
    const FriSource = fri_source_mod.Source(child_dimensions);
    const Fri = fri_mod.Bundle(child_dimensions);

    return struct {
        const Self = @This();

        pub const AuthorityInputs = struct {
            non_fri: NonFri.Inputs,
            fri_source: *const FriSource,
        };

        /// Exact verifier-owned authority tuple consumed by the successful
        /// publication boundary. All pointers refer to the cohort's already
        /// cross-validated authority graph; the SHA identity is copied by
        /// value so no prover-side generated receipt can supply it.
        pub const PublicationAuthorityV1 = struct {
            authority: *const pair_node.VerifierAuthorityV1,
            record: *const pair_node.PairNodeRecordV1,
            root_pin: *const pair_node.RootVkPinV1,
            cohort_authority_sha_id: [32]u8,
        };

        /// Pointer-free interaction publication. The sub-receipts retain their
        /// native row-34 partials and authenticated row-35 provider identity.
        pub const GeneratedInteractionsV1 = struct {
            format_version: u16 = GENERATED_FORMAT_VERSION,
            padding: [6]u8 = [_]u8{0} ** 6,
            cohort_id: [32]u8,
            manifest_seal: [32]u8,
            non_fri: non_fri_mod.GeneratedInteractionsV1,
            fri: fri_mod.GeneratedInteractionsV1,
            identity: [32]u8,
        };

        /// Cold, independently reconstructed closure evidence. This object is
        /// diagnostic/custody substrate; the proof engine consumes only after
        /// all included receipts and the final zero-closure are validated.
        pub const AuditedInteractionsV2 = struct {
            non_fri: non_fri_mod.AuditedInteractionsV1,
            fri: fri_mod.AuditedInteractionsV1,
            prefix_rows: [global_closure.PREFIX_ROW_COUNT]global_closure.RowClaimsV1,
            wire_boundary: global_closure.BoundaryEvidenceV2,
            verifier_input_boundary: global_closure.BoundaryEvidenceV2,
            closure: global_closure.ClosureReceiptV2,
        };

        /// Compatibility name consumed by the generic binary outer engine;
        /// its payload is strictly the source-authenticated V2 closure ABI.
        pub const AuditedInteractionsV1 = AuditedInteractionsV2;

        pub const Components = struct {
            non_fri: non_fri_mod.Components,
            fri: fri_mod.Components,

            pub fn deinit(self: *Components) void {
                // Component adapters borrow cohort-owned definitions and own
                // no heap storage. Keep the Engine contract explicit.
                self.* = undefined;
            }

            pub fn appendRows0Through33ToGate(
                self: *const Components,
                manifest_value: *const manifest_mod.Manifest,
                gate: *manifest_mod.ProofGate,
            ) !void {
                if (gate.count != 0) return error.RosterOrderMismatch;
                try self.non_fri.appendPrefixToGate(manifest_value, gate);
                if (gate.count != FRI_FIRST_ROW)
                    return error.RosterOrderMismatch;
                try gate.append(
                    manifest_value,
                    try self.fri.composition_input.binding(manifest_value),
                );
                try gate.append(
                    manifest_value,
                    try self.fri.composition_control.binding(manifest_value),
                );
                try gate.append(manifest_value, try self.fri.query_bits.binding(manifest_value));
                try gate.append(manifest_value, try self.fri.query_mapping.binding(manifest_value));
                try gate.append(manifest_value, try self.fri.merkle_root.binding(manifest_value));
                try gate.append(manifest_value, try self.fri.trace_merkle.binding(manifest_value));
                try gate.append(manifest_value, try self.fri.pcs_deep.binding(manifest_value));
                try gate.append(manifest_value, try self.fri.fri_leaf.binding(manifest_value));
                try gate.append(manifest_value, try self.fri.fri_node.binding(manifest_value));
                try gate.append(manifest_value, try self.fri.fri_anchor.binding(manifest_value));
                try gate.append(manifest_value, try self.fri.fri_control.binding(manifest_value));
                try gate.append(manifest_value, try self.fri.fri_input.binding(manifest_value));
                try gate.append(manifest_value, try self.fri.multiply.binding(manifest_value));
                try gate.append(manifest_value, try self.fri.inverse.binding(manifest_value));
                try gate.append(manifest_value, try self.fri.linear.binding(manifest_value));
                try gate.append(manifest_value, try self.fri.merkle_path.binding(manifest_value));
                if (gate.count != PROVIDER_ROW - 1)
                    return error.RosterOrderMismatch;
            }

            pub fn appendRow34ProviderToGate(
                self: *const Components,
                manifest_value: *const manifest_mod.Manifest,
                gate: *manifest_mod.ProofGate,
            ) !void {
                if (gate.count != PROVIDER_ROW - 1)
                    return error.RosterOrderMismatch;
                try gate.append(
                    manifest_value,
                    try self.fri.poseidon2.binding(manifest_value),
                );
                if (gate.count != PROVIDER_ROW)
                    return error.RosterOrderMismatch;
            }

            pub fn appendRow35ProviderToGate(
                self: *const Components,
                manifest_value: *const manifest_mod.Manifest,
                gate: *manifest_mod.ProofGate,
            ) !void {
                if (gate.count != PROVIDER_ROW)
                    return error.RosterOrderMismatch;
                try self.non_fri.appendSharedProviderToGate(manifest_value, gate);
                if (gate.count != COMPLETE_ROW_COUNT)
                    return error.RosterOrderMismatch;
            }

            /// Exact universal order: prefix 0--17, FRI 18--34 (including
            /// row-34 Poseidon), and only then row-35 range provider.
            pub fn appendToGate(
                self: *const Components,
                manifest_value: *const manifest_mod.Manifest,
                gate: *manifest_mod.ProofGate,
            ) !void {
                try self.appendRows0Through33ToGate(manifest_value, gate);
                try self.appendRow34ProviderToGate(manifest_value, gate);
                try self.appendRow35ProviderToGate(manifest_value, gate);
            }
        };

        allocator: std.mem.Allocator,
        inputs: AuthorityInputs,
        non_fri: NonFri,
        fri: Fri,
        complete_manifest: manifest_mod.Manifest,
        closure_authority: global_closure.PreparedAuthorityV1,
        closure_workspace: global_closure.Workspace,
        authority_seal: [32]u8,

        pub fn init(
            allocator: std.mem.Allocator,
            inputs: AuthorityInputs,
        ) !Self {
            try validateCrossCustodyEnvelope(inputs);
            const non_fri = try NonFri.init(inputs.non_fri);
            var fri = try Fri.init(allocator, inputs.fri_source);
            errdefer fri.deinit();

            var logs = [_]u32{0} ** roster.COMPONENT_COUNT;
            non_fri.installLogSizes(&logs);
            try inputs.fri_source.installLogSizes(&logs);
            const complete_manifest = try universal_manifest.build(logs);
            try validateManifestComposition(
                &non_fri,
                &fri,
                &complete_manifest,
            );

            var result = Self{
                .allocator = allocator,
                .inputs = inputs,
                .non_fri = non_fri,
                .fri = fri,
                .complete_manifest = complete_manifest,
                .closure_authority = try global_closure.prepareAuthority(),
                .closure_workspace = global_closure.Workspace.init(),
                .authority_seal = undefined,
            };
            result.authority_seal = cohort_support.cohortIdentity(
                &result,
                FORMAT_VERSION,
                PROTOCOL_SUBSTRATE_ONLY,
                AUTHENTICATED_TEMPORAL_V2,
            );
            try result.validateEnvelope();
            return result;
        }

        pub fn deinit(self: *Self) void {
            self.fri.deinit();
            self.* = undefined;
        }

        /// Constant-storage envelope check used by the Engine between stages.
        /// Source operations perform their own mutation-sensitive validation;
        /// this method intentionally does not repeat cold pair authentication
        /// or reconstruct the manifest geometries.
        pub fn validate(self: *const Self) !void {
            try self.validateEnvelope();
        }

        /// Explicit hostile-input/cold audit for diagnostics and mutation
        /// suites. Construction already performs the corresponding admission
        /// once inside each source-owned bundle and does not replay it here.
        pub fn validateColdAuthority(self: *const Self) !void {
            try validateCrossCustodyCold(self.inputs);
            try self.non_fri.validate();
            try self.fri.validate();
            try self.complete_manifest.validate();
            try self.closure_workspace.validate();
            try validateManifestComposition(
                &self.non_fri,
                &self.fri,
                &self.complete_manifest,
            );
            if (!std.mem.eql(
                u8,
                &self.authority_seal,
                &cohort_support.cohortIdentity(
                    self,
                    FORMAT_VERSION,
                    PROTOCOL_SUBSTRATE_ONLY,
                    AUTHENTICATED_TEMPORAL_V2,
                ),
            )) return error.AuthorityIdentityMismatch;
        }

        fn validateEnvelope(self: *const Self) !void {
            try validateCrossCustodyEnvelope(self.inputs);
            try self.complete_manifest.validate();
            if (self.complete_manifest.roster_count != COMPLETE_ROW_COUNT or
                !std.mem.eql(
                    u8,
                    &self.authority_seal,
                    &cohort_support.cohortIdentity(
                        self,
                        FORMAT_VERSION,
                        PROTOCOL_SUBSTRATE_ONLY,
                        AUTHENTICATED_TEMPORAL_V2,
                    ),
                )) return error.AuthorityIdentityMismatch;
        }

        pub fn manifest(self: *const Self) *const manifest_mod.Manifest {
            return &self.complete_manifest;
        }

        /// Returns the same pair authority, record, root pin, and cohort SHA
        /// that were admitted at construction. The independent verifier calls
        /// this on its own cohort; no prover cohort object crosses the seam.
        pub fn publicationAuthority(
            self: *const Self,
        ) !PublicationAuthorityV1 {
            try self.validateEnvelope();
            return .{
                .authority = &self.inputs.non_fri.transcript_prepared.authority,
                .record = &self.inputs.non_fri.transcript_prepared.record,
                .root_pin = &self.inputs.non_fri.root_pin,
                .cohort_authority_sha_id = self.authority_seal,
            };
        }

        /// Exact recursive statement admitted by this initialized cohort.
        /// The binary V3 verifier sidecar copies these words only after the
        /// native proof succeeds; callers never provide a detached statement.
        pub fn recursiveStatementWords(
            self: *const Self,
        ) !*const recursion.span_statement.StatementWords {
            try self.validateEnvelope();
            return &self.inputs.non_fri.statement_prepared.parent_words;
        }

        /// Capability-compatible log installation. The output is overwritten
        /// only at the two bundles' disjoint, fixed roster ranges.
        pub fn installLogSizes(
            self: *const Self,
            destination: *universal_manifest.LogSizes,
        ) !void {
            try self.validate();
            self.non_fri.installLogSizes(destination);
            try self.inputs.fri_source.installLogSizes(destination);
        }

        /// Binds both source seals and the authenticated pair-node ID before
        /// relation challenges are drawn. Binding the node ID explicitly keeps
        /// the seam ready for temporal V2 without claiming that V2 exists.
        pub fn mixAuthority(self: *const Self, channel: anytype) !void {
            try self.validateEnvelope();
            channel.mixU32s(&.{
                AUTHORITY_TRANSCRIPT_DOMAIN,
                FORMAT_VERSION,
                @intFromBool(PROTOCOL_SUBSTRATE_ONLY),
                COMPLETE_ROW_COUNT,
            });
            channel.mixU32s(&digestWords(self.authority_seal));
            channel.mixU32s(
                &self.inputs.non_fri.transcript_prepared.authenticated_root.pair.node_id,
            );
        }

        pub fn fillPreprocessedInto(
            self: *Self,
            manifest_value: *const manifest_mod.Manifest,
            destination: [][]M31,
        ) !void {
            try self.requireManifest(manifest_value);
            try preflightTree(manifest_value, manifest_mod.PREPROCESSED_TREE_INDEX, destination);
            errdefer clearTree(destination);
            try self.non_fri.fillPreprocessedInto(manifest_value, destination);
            try self.fri.fillPreprocessedInto(manifest_value, destination);
        }

        pub fn fillMainInto(
            self: *Self,
            manifest_value: *const manifest_mod.Manifest,
            destination: [][]M31,
        ) !void {
            try self.requireManifest(manifest_value);
            try preflightTree(manifest_value, manifest_mod.MAIN_TREE_INDEX, destination);
            errdefer clearTree(destination);
            try self.non_fri.fillMainInto(manifest_value, destination);
            try self.fri.fillMainInto(manifest_value, destination);
        }

        pub fn fillInteractionInto(
            self: *Self,
            manifest_value: *const manifest_mod.Manifest,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
            destination: [][]M31,
        ) !GeneratedInteractionsV1 {
            try self.requireManifest(manifest_value);
            try preflightTree(manifest_value, manifest_mod.INTERACTION_TREE_INDEX, destination);
            errdefer clearTree(destination);
            const non_fri = try self.non_fri.fillInteractionInto(
                manifest_value,
                relations,
                provider_relations,
                destination,
            );
            const fri = try self.fri.fillInteractionInto(
                manifest_value,
                relations,
                provider_relations,
                destination,
            );
            var result = GeneratedInteractionsV1{
                .cohort_id = self.authority_seal,
                .manifest_seal = manifest_value.seal,
                .non_fri = non_fri,
                .fri = fri,
                .identity = undefined,
            };
            result.identity = generatedIdentity(&result);
            try self.validateGenerated(&result, relations, provider_relations);
            return result;
        }

        pub fn validateGenerated(
            self: *const Self,
            generated: *const GeneratedInteractionsV1,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
        ) !void {
            try self.validateEnvelope();
            if (generated.format_version != GENERATED_FORMAT_VERSION or
                !allZero(&generated.padding) or
                !std.mem.eql(u8, &generated.cohort_id, &self.authority_seal) or
                !std.mem.eql(
                    u8,
                    &generated.manifest_seal,
                    &self.complete_manifest.seal,
                ) or !std.mem.eql(
                u8,
                &generated.identity,
                &generatedIdentity(generated),
            )) return error.GeneratedIdentityMismatch;
            try generated.non_fri.validateAgainst(&self.non_fri);
            try self.fri.validateGeneratedInteractions(
                &generated.fri,
                relations,
                provider_relations,
            );
        }

        pub fn bindClaimsInto(
            self: *const Self,
            generated: *const GeneratedInteractionsV1,
            destination: *manifest_mod.ClaimVector,
        ) !void {
            _ = self;
            try generated.non_fri.claims.bindPrefixInto(destination);
            for (generated.fri.claims.asRows18Through34(), FRI_FIRST_ROW..) |
                value,
                row,
            | try destination.bind(@enumFromInt(row), value);
            try generated.non_fri.claims.bindSharedProviderInto(destination);
        }

        pub fn claimVector(
            self: *const Self,
            generated: *const GeneratedInteractionsV1,
        ) !manifest_mod.ClaimVector {
            var result = try manifest_mod.ClaimVector.init(&self.complete_manifest);
            try self.bindClaimsInto(generated, &result);
            try result.sealClaims(&self.complete_manifest);
            return result;
        }

        pub fn auditGeneratedInteractions(
            self: *Self,
            generated: *const GeneratedInteractionsV1,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
        ) !AuditedInteractionsV1 {
            try self.validateGenerated(generated, relations, provider_relations);
            var tuple_ledger = relation_interaction.TupleLedger.init(self.allocator);
            defer tuple_ledger.deinit();
            const diagnostic_ledger: ?*relation_interaction.TupleLedger =
                if (builtin.is_test) &tuple_ledger else null;
            const non_fri = try self.non_fri.auditGeneratedInteractions(
                relations,
                provider_relations,
                &generated.non_fri,
                diagnostic_ledger,
            );
            const fri = try self.fri.auditGeneratedInteractions(
                self.allocator,
                relations,
                provider_relations,
                &generated.fri,
            );
            if (diagnostic_ledger) |ledger|
                try appendFriTupleContributions(self, ledger);

            var rows: [global_closure.PREFIX_ROW_COUNT]global_closure.RowClaimsV1 =
                undefined;
            @memcpy(
                rows[0..non_fri_mod.PREFIX_ROW_COUNT],
                non_fri.prefix_rows[0..],
            );
            for (fri.audits.typed_rows, 0..) |audit, index| {
                rows[FRI_FIRST_ROW + index] = rowClaim(
                    @enumFromInt(FRI_FIRST_ROW + index),
                    audit.values,
                    audit.total,
                );
            }
            rows[FRI_FIRST_ROW + FRI_TYPED_ROW_COUNT] = poseidonRowClaim(
                fri.audits.poseidon2,
            );

            const wire_boundary = globalBoundaryEvidence(
                try self.inputs.fri_source.wireBoundaryEvidence(relations),
            );
            const verifier_input_boundary = globalBoundaryEvidence(
                try self.inputs.fri_source.verifierInputBoundaryEvidence(
                    relations,
                ),
            );
            const boundary_authorities = try global_closure.BoundaryAuthoritiesV2.init(
                try global_closure.BoundarySourceV2.init(
                    .wire,
                    wire_boundary,
                ),
                try global_closure.BoundarySourceV2.init(
                    .verifier_input,
                    verifier_input_boundary,
                ),
            );
            const closure_authority = try global_closure.prepareAuthorityV2(
                boundary_authorities,
            );
            const public_boundaries = try global_closure.PublicBoundariesV2.init(
                &closure_authority,
                wire_boundary,
                verifier_input_boundary,
            );
            const closure_input = try global_closure.ClosureInputV2.init(
                &closure_authority,
                &rows,
                &non_fri.provider_claim,
                public_boundaries,
            );
            var closure = global_closure.ClosureReceiptV2.fresh();
            global_closure.fillIntoV2(
                &self.closure_workspace,
                &closure_authority,
                &closure_input,
                &closure,
            ) catch |err| {
                if (builtin.is_test and err == error.RelationNotClosed) {
                    for (self.closure_workspace.closed_totals, 0..) |value, domain| {
                        if (!value.isZero()) {
                            std.debug.print(
                                "binary cohort unclosed domain {d}: {any}\n",
                                .{ domain, value.toM31Array() },
                            );
                            for (rows, 0..) |row, row_index| {
                                const contribution = row.domains[domain].value;
                                if (!contribution.isZero()) std.debug.print(
                                    "  row {d}: {any}\n",
                                    .{ row_index, contribution.toM31Array() },
                                );
                            }
                            if (domain == @intFromEnum(global_closure.PROVIDER_DOMAIN) and
                                !non_fri.provider_claim.claimed_sum.isZero())
                            {
                                std.debug.print(
                                    "  row {d}: {any}\n",
                                    .{
                                        PROVIDER_ROW,
                                        non_fri.provider_claim.claimed_sum.toM31Array(),
                                    },
                                );
                            }
                        }
                    }
                    if (!self.closure_workspace.framework_total.isZero())
                        std.debug.print(
                            "binary cohort unclosed framework total: {any}\n",
                            .{self.closure_workspace.framework_total.toM31Array()},
                        );
                    printUnmatchedTupleGroups(&tuple_ledger);
                }
                return err;
            };
            try closure.validate();
            return .{
                .non_fri = non_fri,
                .fri = fri,
                .prefix_rows = rows,
                .wire_boundary = wire_boundary,
                .verifier_input_boundary = verifier_input_boundary,
                .closure = closure,
            };
        }

        pub fn auditGlobalClosureV2(
            self: *Self,
            generated: *const GeneratedInteractionsV1,
            claims: *const manifest_mod.ClaimVector,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
        ) !AuditedInteractionsV2 {
            try claims.validate(&self.complete_manifest);
            const audited = try self.auditGeneratedInteractions(
                generated,
                relations,
                provider_relations,
            );
            for (audited.prefix_rows, 0..) |row, index|
                if (!row.claimed_sum.eql(claims.values[index]))
                    return error.ClaimAuditMismatch;
            if (!audited.non_fri.provider_claim.claimed_sum.eql(
                claims.values[PROVIDER_ROW],
            )) return error.ClaimAuditMismatch;
            return audited;
        }

        /// Compatibility wrapper for proof engines that need only admission.
        pub fn auditGlobalClosure(
            self: *Self,
            generated: *const GeneratedInteractionsV1,
            claims: *const manifest_mod.ClaimVector,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
        ) !void {
            _ = try self.auditGlobalClosureV2(
                generated,
                claims,
                relations,
                provider_relations,
            );
        }

        /// Independent verifier-side regeneration. No generated receipt,
        /// claim scalar, or interaction column crosses from the prover cohort.
        pub fn rebuildGeneratedInteractions(
            self: *Self,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
        ) !GeneratedInteractionsV1 {
            {
                var main = try TreeScratch.init(
                    self.allocator,
                    &self.complete_manifest,
                    manifest_mod.MAIN_TREE_INDEX,
                );
                defer main.deinit();
                try self.fillMainInto(&self.complete_manifest, main.columns);
            }

            var interaction = try TreeScratch.init(
                self.allocator,
                &self.complete_manifest,
                manifest_mod.INTERACTION_TREE_INDEX,
            );
            defer interaction.deinit();
            return self.fillInteractionInto(
                &self.complete_manifest,
                relations,
                provider_relations,
                interaction.columns,
            );
        }

        pub fn initComponents(
            self: *const Self,
            generated: *const GeneratedInteractionsV1,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
        ) !Components {
            try self.validateGenerated(generated, relations, provider_relations);
            return .{
                .non_fri = try self.non_fri.initComponents(
                    &self.complete_manifest,
                    relations,
                    provider_relations,
                    &generated.non_fri,
                ),
                .fri = try self.fri.initComponents(
                    &self.complete_manifest,
                    relations,
                    provider_relations,
                    &generated.fri,
                ),
            };
        }

        fn requireManifest(
            self: *const Self,
            manifest_value: *const manifest_mod.Manifest,
        ) !void {
            try self.validateEnvelope();
            if (manifest_value != &self.complete_manifest) {
                try manifest_value.validate();
                if (!std.meta.eql(manifest_value.*, self.complete_manifest))
                    return error.ManifestGeometryMismatch;
            }
            if (!std.mem.eql(
                u8,
                &manifest_value.seal,
                &self.complete_manifest.seal,
            ))
                return error.ManifestGeometryMismatch;
        }

        // Expose the capability-inspection names without introducing a second
        // implementation or allowing provider rows to be appended detached.
        pub const appendRows0Through33ToGate = Components.appendRows0Through33ToGate;
        pub const appendRow34ProviderToGate = Components.appendRow34ProviderToGate;
        pub const appendRow35ProviderToGate = Components.appendRow35ProviderToGate;
    };
}

comptime {
    if (COMPLETE_ROW_COUNT != 36 or FRI_FIRST_ROW != 18 or
        FRI_ROW_COUNT != 17 or FRI_TYPED_ROW_COUNT != 16 or PROVIDER_ROW != 35)
    {
        @compileError("binary outer cohort roster ownership drifted");
    }
    if (!PROTOCOL_SUBSTRATE_ONLY or WHOLE_FRONTEND_VERIFIED or
        AUTHENTICATED_TEMPORAL_V2 or PRODUCTION_ACTIVATION)
    {
        @compileError("binary outer cohort production boundary changed");
    }
}
