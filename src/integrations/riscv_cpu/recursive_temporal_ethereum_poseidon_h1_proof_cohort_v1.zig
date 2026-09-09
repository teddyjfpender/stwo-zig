//! Secure-engine cohort adapter for the authenticated Ethereum h1 wrapper.
//!
//! The factory is generic over a concrete verifier-minted capture capability.
//! `DefaultPoseidonV4AdapterV1` is only one adapter; a projected candidate may
//! instantiate the same cohort after its own cold verifier exposes the exact
//! capture-view surface. Digest-only captures cannot satisfy this contract.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const ingress_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_ingress_v1.zig");
const manifest_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_manifest_v1.zig");
const materializer_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_materializer_v1.zig");
const cohort_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_cohort_v1.zig");
const components_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_components_v1.zig");
const trace_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_trace_v1.zig");
const interactions_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_interactions_v1.zig");
const boundary_mod =
    @import("recursive_temporal_ethereum_poseidon_h1_boundary_v1.zig");

const recursion = frontend.recursion;
const universal = recursion.air.universal_challenges;
const shared_provider = recursion.air.universal_shared_provider;
const QM31 = stwo_core.fields.qm31.QM31;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const AUTHORITY_TRANSCRIPT_DOMAIN: u32 = 0x4843_3131; // "HC11"

pub const AuditBoundaryV1 = struct {
    domain: @TypeOf(boundary_mod.STATEMENT_DOMAIN),
    tuple_count: u32,
    claimed_sum: QM31,
    tuple_provenance_sha256: [32]u8,

    fn fromResidual(value: boundary_mod.BoundaryResidualV1) AuditBoundaryV1 {
        return .{
            .domain = value.domain,
            .tuple_count = value.tuple_count,
            .claimed_sum = value.claimed_sum,
            .tuple_provenance_sha256 = value.tuple_provenance_sha256,
        };
    }
};

pub const ClosureIdentityV1 = struct {
    closure_id: [32]u8,
};

pub const H1AuditedInteractionsV2 = struct {
    /// Compatibility field name consumed by the generic artifact identity.
    /// Its explicit domain remains `recursion_statement_word`, never wire.
    wire_boundary: AuditBoundaryV1,
    verifier_input_boundary: AuditBoundaryV1,
    closure: ClosureIdentityV1,
    h1_boundary: boundary_mod.ClosureReceiptV1,

    pub fn validate(self: *const H1AuditedInteractionsV2) !void {
        try self.h1_boundary.validate();
        if (self.wire_boundary.domain != boundary_mod.STATEMENT_DOMAIN or
            self.verifier_input_boundary.domain !=
                boundary_mod.VERIFIER_INPUT_DOMAIN or
            !boundaryEqual(
                self.wire_boundary,
                AuditBoundaryV1.fromResidual(self.h1_boundary.statement),
            ) or !boundaryEqual(
            self.verifier_input_boundary,
            AuditBoundaryV1.fromResidual(self.h1_boundary.verifier_input),
        ) or !std.mem.eql(
            u8,
            &self.closure.closure_id,
            &self.h1_boundary.identity_sha256,
        )) return error.InvalidEthereumPoseidonH1Audit;
    }
};

pub fn CohortForVerifierMinted(comptime VerifierMinted: type) type {
    return struct {
        const Self = @This();

        pub const AuthorityInputs = struct {
            verifier_minted: VerifierMinted,
        };
        pub const GeneratedInteractionsV1 =
            interactions_mod.GeneratedInteractionsV1;
        pub const AuditedInteractionsV2 = H1AuditedInteractionsV2;

        allocator: std.mem.Allocator,
        verifier_minted: VerifierMinted,
        materialized: materializer_mod.MaterializedV1,
        structural_cohort: cohort_mod.CohortV1,
        owners: components_mod.OwnersV1,

        pub fn init(
            allocator: std.mem.Allocator,
            inputs: AuthorityInputs,
        ) !Self {
            try validateVerifierMintedSurface(VerifierMinted);
            var materialized = try materializer_mod.MaterializedV1
                .initFromVerifierMinted(allocator, inputs.verifier_minted);
            errdefer materialized.deinit();
            const structural_cohort = try cohort_mod.CohortV1.init(
                &materialized.plan,
                inputs.verifier_minted.custody(),
            );
            var owners = try components_mod.OwnersV1.init(allocator);
            errdefer owners.deinit();
            var result = Self{
                .allocator = allocator,
                .verifier_minted = inputs.verifier_minted,
                .materialized = materialized,
                .structural_cohort = structural_cohort,
                .owners = owners,
            };
            try result.validate();
            return result;
        }

        pub fn deinit(self: *Self) void {
            self.owners.deinit();
            self.materialized.deinit();
            self.* = undefined;
        }

        pub fn validate(self: *Self) !void {
            try self.materialized.validateAgainstVerifierMinted(
                self.verifier_minted,
            );
            try self.structural_cohort.validateMaterialized(
                &self.materialized,
                self.verifier_minted.custody(),
            );
            try self.owners.validate();
        }

        pub fn manifest(self: *const Self) *const manifest_mod.Manifest {
            return &self.materialized.plan.manifest;
        }

        pub fn recursiveStatementWords(
            self: *const Self,
        ) !*const recursion.span_statement.StatementWords {
            try self.verifier_minted.custody().validate();
            return &self.verifier_minted.custody().parent_statement_words;
        }

        pub fn publicationAuthority(
            self: *const Self,
        ) *const ingress_mod.CustodyV1 {
            return self.verifier_minted.custody();
        }

        pub fn mixAuthority(self: *Self, transcript: anytype) !void {
            try self.validate();
            transcript.mixU32s(&.{
                AUTHORITY_TRANSCRIPT_DOMAIN,
                FORMAT_VERSION,
                SCHEMA_VERSION,
                manifest_mod.COMPONENT_COUNT,
                @intFromEnum(self.materialized.plan.freshness_kind),
            });
            transcript.mixU32s(&digestWords(
                self.verifier_minted.custody().identity_sha256,
            ));
            transcript.mixU32s(&digestWords(
                self.materialized.identity_sha256,
            ));
            transcript.mixU32s(&digestWords(
                self.structural_cohort.identity_sha256,
            ));
            transcript.mixU32s(&digestWords(
                self.verifier_minted.custody().air_contract.identity_sha256,
            ));
            transcript.mixU32s(&digestWords(
                self.verifier_minted.custody().h1_profile.identity_sha256,
            ));
        }

        pub fn fillPreprocessedInto(
            self: *Self,
            active_manifest: *const manifest_mod.Manifest,
            destination: [][]stwo_core.fields.m31.M31,
        ) !void {
            try self.validate();
            try trace_mod.fillPreprocessedInto(
                &self.materialized,
                &self.structural_cohort,
                self.verifier_minted.custody(),
                active_manifest,
                destination,
            );
        }

        pub fn fillMainInto(
            self: *Self,
            active_manifest: *const manifest_mod.Manifest,
            destination: [][]stwo_core.fields.m31.M31,
        ) !void {
            try self.validate();
            try trace_mod.fillMainInto(
                self.allocator,
                &self.materialized,
                &self.structural_cohort,
                self.verifier_minted.custody(),
                active_manifest,
                destination,
            );
        }

        pub fn fillInteractionInto(
            self: *Self,
            active_manifest: *const manifest_mod.Manifest,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
            destination: [][]stwo_core.fields.m31.M31,
        ) !GeneratedInteractionsV1 {
            try self.validate();
            return interactions_mod.fillInteractionInto(
                self.allocator,
                &self.owners,
                &self.materialized,
                &self.structural_cohort,
                self.verifier_minted.custody(),
                active_manifest,
                relations,
                provider_relations,
                destination,
            );
        }

        pub fn rebuildGeneratedInteractions(
            self: *Self,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
        ) !GeneratedInteractionsV1 {
            var tree = try trace_mod.TreeV1.init(
                self.allocator,
                self.manifest(),
                manifest_mod.INTERACTION_TREE_INDEX,
            );
            defer tree.deinit();
            return self.fillInteractionInto(
                self.manifest(),
                relations,
                provider_relations,
                tree.columns,
            );
        }

        pub fn validateGenerated(
            self: *Self,
            generated: *const GeneratedInteractionsV1,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
        ) !void {
            try self.validate();
            try generated.validate(
                &self.materialized,
                &self.structural_cohort,
                self.manifest(),
                relations,
                provider_relations,
            );
        }

        pub fn claimVector(
            self: *Self,
            generated: *const GeneratedInteractionsV1,
        ) !manifest_mod.ClaimVector {
            return generated.claims.bindInto(self.manifest());
        }

        pub fn auditGlobalClosureV2(
            self: *Self,
            generated: *const GeneratedInteractionsV1,
            claims: *const manifest_mod.ClaimVector,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
        ) !AuditedInteractionsV2 {
            try self.validateGenerated(
                generated,
                relations,
                provider_relations,
            );
            const expected_claims = try self.claimVector(generated);
            if (!std.meta.eql(claims.*, expected_claims))
                return error.EthereumPoseidonH1ClaimMismatch;
            const boundary = try boundary_mod.audit(
                self.allocator,
                &self.owners,
                &self.materialized,
                &self.structural_cohort,
                self.verifier_minted.custody(),
                self.manifest(),
                relations,
                provider_relations,
                generated,
            );
            var result = AuditedInteractionsV2{
                .wire_boundary = AuditBoundaryV1.fromResidual(
                    boundary.statement,
                ),
                .verifier_input_boundary = AuditBoundaryV1.fromResidual(
                    boundary.verifier_input,
                ),
                .closure = .{ .closure_id = boundary.identity_sha256 },
                .h1_boundary = boundary,
            };
            try result.validate();
            return result;
        }

        pub fn auditGlobalClosure(
            self: *Self,
            generated: *const GeneratedInteractionsV1,
            claims: *const manifest_mod.ClaimVector,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
        ) !AuditedInteractionsV2 {
            return self.auditGlobalClosureV2(
                generated,
                claims,
                relations,
                provider_relations,
            );
        }

        pub fn validateAuditedInteractions(
            self: *Self,
            audited: *const AuditedInteractionsV2,
            claims: *const manifest_mod.ClaimVector,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
        ) !void {
            try audited.validate();
            const generated = try self.rebuildGeneratedInteractions(
                relations,
                provider_relations,
            );
            const expected = try self.auditGlobalClosureV2(
                &generated,
                claims,
                relations,
                provider_relations,
            );
            if (!std.meta.eql(audited.*, expected))
                return error.InvalidEthereumPoseidonH1Audit;
        }

        pub const ComponentSetV1 = struct {
            inner: components_mod.ComponentsV1,

            pub fn appendToGate(
                self: *const ComponentSetV1,
                active_manifest: *const manifest_mod.Manifest,
                gate: *manifest_mod.ProofGate,
            ) !void {
                try self.inner.appendToGate(active_manifest, gate);
            }

            pub fn deinit(self: *ComponentSetV1) void {
                self.* = undefined;
            }
        };

        pub fn initComponents(
            self: *Self,
            generated: *const GeneratedInteractionsV1,
            relations: *const universal.UniversalRelations,
            provider_relations: *const shared_provider.SharedProviderRelations,
        ) !ComponentSetV1 {
            try self.validateGenerated(
                generated,
                relations,
                provider_relations,
            );
            return .{ .inner = try components_mod.initComponents(
                &self.owners,
                &self.structural_cohort,
                self.manifest(),
                relations,
                provider_relations,
                generated.claims,
            ) };
        }
    };
}

pub const DefaultCohortV1 = CohortForVerifierMinted(
    materializer_mod.DefaultPoseidonV4AdapterV1,
);

fn validateVerifierMintedSurface(comptime T: type) !void {
    inline for (.{
        "validateForH1",
        "custody",
        "freshnessKind",
        "captureViews",
    }) |name| if (!@hasDecl(T, name))
        @compileError("H1 verifier-minted capture surface missing " ++ name);
}

fn boundaryEqual(left: AuditBoundaryV1, right: AuditBoundaryV1) bool {
    return left.domain == right.domain and
        left.tuple_count == right.tuple_count and
        left.claimed_sum.eql(right.claimed_sum) and
        std.mem.eql(
            u8,
            &left.tuple_provenance_sha256,
            &right.tuple_provenance_sha256,
        );
}

fn digestWords(value: [32]u8) [8]u32 {
    var result: [8]u32 = undefined;
    for (&result, 0..) |*word, index| {
        const start = index * @sizeOf(u32);
        word.* = std.mem.readInt(
            u32,
            value[start..][0..@sizeOf(u32)],
            .little,
        );
    }
    return result;
}

comptime {
    if (manifest_mod.COMPONENT_COUNT != 12 or PRODUCTION_ACTIVATION)
        @compileError("Ethereum Poseidon h1 proof cohort contract drifted");
}
