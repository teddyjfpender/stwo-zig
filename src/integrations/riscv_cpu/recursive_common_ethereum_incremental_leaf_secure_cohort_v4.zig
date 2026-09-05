//! Secure-engine adapter for the complete schema-3 role-0 universal cohort.
//!
//! Every engine transaction reconstructs fresh geometry and all 36 physical
//! row owners from one live campaign-bound stage-102 materialization. The
//! adapter retains no serialized freshness bit and never substitutes the
//! canonical-empty or common-fold cohort for the role-0 program.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const campaign_materializer =
    @import("recursive_common_ethereum_incremental_leaf_campaign_materializer_v4.zig");
const complete_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_cohort_v4_complete.zig");
const geometry_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_geometry_authority_v4.zig");
const manifest_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const preprocessed_authority =
    @import("recursive_process_local_preprocessed_authority_v1.zig");
const padding_target_mod =
    @import("recursive_pipeline_campaign_padding_target_v2.zig");
const campaign_public = @import("recursive_campaign_node_public_v2.zig");
const secure_artifact =
    @import("recursive_temporal_secure_parent_artifact_v1.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const universal = recursion.air.universal_challenges;
const provider = recursion.air.universal_shared_provider;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const COMPONENT_COUNT: usize = manifest_mod.COMPONENT_COUNT;
pub const ROLE = manifest_mod.ROLE;
pub const PRODUCTION_ACTIVATION = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;

const AUTHORITY_TRANSCRIPT_DOMAIN: u32 = 0x4549_4134; // "EIA4"
const BOUNDARY_TRANSCRIPT_DOMAIN: u32 = 0x4549_4234; // "EIB4"
const COHORT_IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-secure-cohort/v4-schema3\x00";
const AUDIT_IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-secure-audit/v4-schema3\x00";

pub const Error = error{
    EthereumIncrementalSecureAuditMismatchV4,
    EthereumIncrementalSecureCohortMismatchV4,
};

const ClosureReceiptV4 = @FieldType(complete_mod.GeneratedV4, "closure");
const PublicWireBoundaryV4 = @FieldType(ClosureReceiptV4, "public_wire");

pub const BoundaryEvidenceV4 = struct {
    domain: @FieldType(PublicWireBoundaryV4, "domain"),
    tuple_count: u64,
    claimed_sum: QM31,

    pub fn validate(self: BoundaryEvidenceV4, allow_empty: bool) !void {
        if ((!allow_empty and self.tuple_count == 0) or
            (allow_empty and self.tuple_count != 0) or
            !secureCanonical(self.claimed_sum) or
            (allow_empty and !self.claimed_sum.isZero()))
        {
            return error.EthereumIncrementalSecureAuditMismatchV4;
        }
    }
};

pub const ClosureEvidenceV4 = struct {
    closure_id: [32]u8,

    pub fn validate(self: ClosureEvidenceV4) !void {
        if (std.mem.allEqual(u8, &self.closure_id, 0))
            return error.EthereumIncrementalSecureAuditMismatchV4;
    }
};

pub const SecureAuditedInteractionsV4 = struct {
    receipt: @FieldType(complete_mod.GeneratedV4, "closure"),
    wire_boundary: BoundaryEvidenceV4,
    verifier_input_boundary: BoundaryEvidenceV4,
    closure: ClosureEvidenceV4,
    identity_sha256: [32]u8,

    pub fn init(
        generated: *const complete_mod.GeneratedV4,
    ) !SecureAuditedInteractionsV4 {
        try generated.validateStructure();
        var result = SecureAuditedInteractionsV4{
            .receipt = generated.closure,
            .wire_boundary = .{
                .domain = generated.closure.public_wire.domain,
                .tuple_count = generated.closure.public_wire.term_count,
                .claimed_sum = generated.closure.public_wire.claimed_sum,
            },
            .verifier_input_boundary = .{
                .domain = generated.closure.public_wire.domain,
                .tuple_count = 0,
                .claimed_sum = QM31.zero(),
            },
            .closure = .{
                .closure_id = generated.closure.identity_sha256,
            },
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = auditedIdentity(&result);
        try result.validate();
        return result;
    }

    pub fn validate(self: *const SecureAuditedInteractionsV4) !void {
        try self.receipt.validate();
        try self.wire_boundary.validate(false);
        try self.verifier_input_boundary.validate(true);
        try self.closure.validate();
        if (self.wire_boundary.domain != self.receipt.public_wire.domain or
            self.wire_boundary.tuple_count !=
                self.receipt.public_wire.term_count or
            !self.wire_boundary.claimed_sum.eql(
                self.receipt.public_wire.claimed_sum,
            ) or !std.mem.eql(
            u8,
            &self.closure.closure_id,
            &self.receipt.identity_sha256,
        ) or !std.mem.eql(
            u8,
            &self.identity_sha256,
            &auditedIdentity(self),
        )) return error.EthereumIncrementalSecureAuditMismatchV4;
    }
};

pub fn CohortV4(comptime Engine: type) type {
    const Materialized =
        campaign_materializer.PreparedOwnedCampaignCaptureV4(Engine);
    const Geometry = geometry_mod.OwnerV4(Engine);
    const Complete = complete_mod.CohortV4(Engine);
    const Schedule = @FieldType(Materialized, "schedule");
    const CohortAuditedInteractionsV2 = SecureAuditedInteractionsV4;

    return struct {
        const Self = @This();

        pub const AuthorityInputs = struct {
            materialized: *const Materialized,
        };
        pub const GeneratedInteractionsV1 = complete_mod.GeneratedV4;
        pub const AuditedInteractionsV2 = CohortAuditedInteractionsV2;
        pub const Components = complete_mod.ComponentSetV4;

        allocator: std.mem.Allocator,
        inputs: AuthorityInputs,
        geometry: *Geometry,
        complete: *Complete,
        manifest_value: *const manifest_mod.Manifest,
        log_sizes: manifest_mod.LogSizesV4,
        complete_provider: geometry_mod.CompleteProviderGeometryV4,
        padding_target: ?*const padding_target_mod.CampaignPaddingTargetV2,
        statement_words: recursion.span_statement.StatementWords,
        identity_sha256: [32]u8,

        pub fn init(
            allocator: std.mem.Allocator,
            inputs: AuthorityInputs,
        ) !Self {
            return initWithPaddingTarget(allocator, inputs, null);
        }

        /// Target-native role-0 transaction. The complete 36-row cohort is
        /// regenerated at the role-independent campaign padding vector and
        /// every session identity is bound to that same target below.
        pub fn initForPaddingTarget(
            allocator: std.mem.Allocator,
            inputs: AuthorityInputs,
            padding_target: *const padding_target_mod.CampaignPaddingTargetV2,
        ) !Self {
            return initWithPaddingTarget(
                allocator,
                inputs,
                padding_target,
            );
        }

        fn initWithPaddingTarget(
            allocator: std.mem.Allocator,
            inputs: AuthorityInputs,
            padding_target: ?*const padding_target_mod.CampaignPaddingTargetV2,
        ) !Self {
            try inputs.materialized.validate();
            if (padding_target) |target|
                try validateTargetCustody(target, inputs.materialized);
            const geometry = if (padding_target) |target|
                try Geometry.initForLogSizes(
                    allocator,
                    inputs.materialized,
                    try targetLogSizes(target),
                )
            else
                try Geometry.init(allocator, inputs.materialized);
            errdefer geometry.deinit();
            const complete = try Complete.init(allocator, geometry);
            errdefer complete.deinit();
            const manifest_value = try geometry.manifest();
            var statement_words: recursion.span_statement.StatementWords =
                undefined;
            for (
                &statement_words,
                inputs.materialized.base.input.statement_words,
            ) |*destination, word| destination.* = M31.fromCanonical(word);
            var result = Self{
                .allocator = allocator,
                .inputs = inputs,
                .geometry = geometry,
                .complete = complete,
                .manifest_value = manifest_value,
                .log_sizes = try geometry.logSizes(),
                .complete_provider = try geometry.completeProviderGeometry(),
                .padding_target = padding_target,
                .statement_words = statement_words,
                .identity_sha256 = undefined,
            };
            result.identity_sha256 = try cohortIdentity(&result);
            try result.validate();
            return result;
        }

        pub fn deinit(self: *Self) void {
            self.complete.deinit();
            self.geometry.deinit();
            self.* = undefined;
        }

        pub fn validate(self: *Self) !void {
            try self.inputs.materialized.validate();
            try self.geometry.validate();
            try self.complete.validate();
            const expected_manifest = try self.geometry.manifest();
            if (self.manifest_value != expected_manifest or
                !std.meta.eql(self.log_sizes, try self.geometry.logSizes()) or
                !std.meta.eql(
                    self.complete_provider,
                    try self.geometry.completeProviderGeometry(),
                ) or !std.mem.eql(
                u8,
                &self.identity_sha256,
                &(try cohortIdentity(self)),
            )) return error.EthereumIncrementalSecureCohortMismatchV4;
            if (self.padding_target) |target| {
                try validateTargetCustody(target, self.inputs.materialized);
                if (!std.meta.eql(self.log_sizes, try targetLogSizes(target)))
                    return error.EthereumIncrementalSecureCohortMismatchV4;
            }
            for (
                self.statement_words,
                self.inputs.materialized.base.input.statement_words,
            ) |felt, word| if (felt.toU32() != word)
                return error.EthereumIncrementalSecureCohortMismatchV4;
        }

        pub fn manifest(self: *const Self) *const manifest_mod.Manifest {
            return self.manifest_value;
        }

        pub fn publicationAuthority(
            self: *Self,
        ) !*const Schedule {
            try self.validate();
            return &self.inputs.materialized.schedule;
        }

        pub fn recursiveStatementWords(
            self: *Self,
        ) !*const recursion.span_statement.StatementWords {
            try self.validate();
            return &self.statement_words;
        }

        pub fn parentManifestIdentity(self: *Self) ![32]u8 {
            try self.validate();
            const base = try manifest_mod.contractIdentity(
                self.log_sizes,
                self.inputs.materialized.campaign_authority,
                self.complete_provider,
            );
            return self.bindPaddingTarget(
                "stwo-zig/role0-padded-contract/v4\x00",
                base,
            );
        }

        pub fn programIdentity(self: *Self) ![32]u8 {
            try self.validate();
            const base = try manifest_mod.programIdentity(
                self.log_sizes,
                self.inputs.materialized.campaign_authority,
                self.complete_provider,
            );
            return self.bindPaddingTarget(
                "stwo-zig/role0-padded-program/v4\x00",
                base,
            );
        }

        pub fn profileIdentity(self: *Self) ![32]u8 {
            try self.validate();
            const base = try manifest_mod.profileIdentity(
                self.log_sizes,
                self.inputs.materialized.campaign_authority,
                self.complete_provider,
            );
            return self.bindPaddingTarget(
                "stwo-zig/role0-padded-profile/v4\x00",
                base,
            );
        }

        pub fn paddingLayoutIdentity(self: *Self) ![32]u8 {
            try self.validate();
            if (self.padding_target) |target|
                return target.target.padding_table_layout_identity_sha256;
            return manifest_mod.paddingLayoutIdentity(
                self.log_sizes,
                self.inputs.materialized.campaign_authority,
                self.complete_provider,
            );
        }

        pub fn tableLayoutIdentity(self: *Self) ![32]u8 {
            try self.validate();
            if (self.padding_target) |target|
                return target.target.padding_table_layout_identity_sha256;
            return manifest_mod.tableLayoutIdentity(
                self.log_sizes,
                self.inputs.materialized.campaign_authority,
                self.complete_provider,
            );
        }

        pub fn verificationKeyId(
            self: *Self,
        ) !recursion.poseidon2_channel.Digest {
            try self.validate();
            const base = try manifest_mod.verificationKeyId(
                self.log_sizes,
                self.inputs.materialized.campaign_authority,
                self.complete_provider,
            );
            return self.bindPaddingTargetDigest(
                0x4550_564b, // "EPVK"
                base,
            );
        }

        pub fn nextParentVkId(
            self: *Self,
        ) !recursion.poseidon2_channel.Digest {
            try self.validate();
            const base = try manifest_mod.nextParentVkId(
                self.log_sizes,
                self.inputs.materialized.campaign_authority,
                self.complete_provider,
            );
            return self.bindPaddingTargetDigest(
                0x4550_4e4b, // "EPNK"
                base,
            );
        }

        pub fn airProgramId(
            self: *Self,
        ) !recursion.poseidon2_channel.Digest {
            try self.validate();
            const base = try manifest_mod.airProgramId(
                self.log_sizes,
                self.inputs.materialized.campaign_authority,
                self.complete_provider,
            );
            return self.bindPaddingTargetDigest(
                0x4550_4150, // "EPAP"
                base,
            );
        }

        pub fn processLocalPreprocessedCacheKey(
            self: *Self,
            pcs_identity_sha256: [32]u8,
            root: recursion.engine.Hasher.Hash,
        ) !preprocessed_authority.KeyV1 {
            try self.validate();
            return preprocessed_authority.KeyV1.init(.{
                .circuit_identity_sha256 = try self.parentManifestIdentity(),
                .program_identity_sha256 = try self.programIdentity(),
                .profile_identity_sha256 = try self.profileIdentity(),
                .pcs_identity_sha256 = pcs_identity_sha256,
                .padding_identity_sha256 = try self.paddingLayoutIdentity(),
                .preprocessed_identity_sha256 = try preprocessed_authority
                    .preprocessedIdentity(
                    recursion.engine.Hasher.Hash,
                    try self.tableLayoutIdentity(),
                    self.manifest_value.seal,
                    root,
                ),
                .identity_sha256 = undefined,
            });
        }

        pub fn sessionAuthority(
            self: *Self,
        ) !secure_artifact.EthereumIncrementalLeafWrapperSessionAuthorityV4 {
            try self.validate();
            return .{
                .ingress_identity_sha256 = self.inputs.materialized
                    .identity_sha256,
                .parent_statement_words = self.statement_words,
                .profile_identity_sha256 = try self.profileIdentity(),
                .child_composition_manifest_sha256 = self.inputs.materialized
                    .base.composition_program.graph_sha256,
                .parent_outer_manifest_sha256 = try self
                    .parentManifestIdentity(),
                .verification_key_id = try self.verificationKeyId(),
                .next_parent_vk_id = try self.nextParentVkId(),
                .air_program_id = try self.airProgramId(),
            };
        }

        fn bindPaddingTarget(
            self: *Self,
            comptime domain: []const u8,
            base: [32]u8,
        ) [32]u8 {
            const target = self.padding_target orelse return base;
            var hash = std.crypto.hash.sha2.Sha256.init(.{});
            hash.update(domain);
            hash.update(&base);
            hash.update(&target.identity_sha256);
            hash.update(&target.shape.identity_sha256);
            return hash.finalResult();
        }

        /// Field-native IDs remain field-native. The target binding is an
        /// explicit canonical little-endian word transport into the pinned
        /// Poseidon2 byte hash, never a bitcast between Digest and SHA types.
        fn bindPaddingTargetDigest(
            self: *Self,
            capacity_tag: u32,
            base: recursion.poseidon2_channel.Digest,
        ) recursion.poseidon2_channel.Digest {
            const target = self.padding_target orelse return base;
            var bytes: [@sizeOf(recursion.poseidon2_channel.Digest) + 64]u8 =
                undefined;
            var cursor: usize = 0;
            for (base) |word| {
                std.mem.writeInt(
                    u32,
                    bytes[cursor..][0..@sizeOf(u32)],
                    word,
                    .little,
                );
                cursor += @sizeOf(u32);
            }
            @memcpy(bytes[cursor..][0..32], &target.identity_sha256);
            cursor += 32;
            @memcpy(bytes[cursor..][0..32], &target.shape.identity_sha256);
            cursor += 32;
            std.debug.assert(cursor == bytes.len);
            return recursion.poseidon2_channel.hashBytes(
                &bytes,
                capacity_tag,
            );
        }

        pub fn session(self: *Self) !secure_artifact.SessionV1 {
            return secure_artifact.SessionV1
                .initEthereumIncrementalLeafWrapperV4(
                try self.sessionAuthority(),
            );
        }

        pub fn validateSession(
            self: *Self,
            candidate: *const secure_artifact.SessionV1,
        ) !void {
            if (!std.meta.eql(candidate.*, try self.session()))
                return error.EthereumIncrementalSecureCohortMismatchV4;
        }

        /// Field-native NodePublicV2 is the recursive public statement. SHA
        /// identities remain session/custody metadata and are not mixed here.
        pub fn mixAuthority(self: *Self, transcript: anytype) !void {
            const publication = try self.publicationAuthority();
            const words = try publication.node_public.canonicalAirWords();
            transcript.mixU32s(&.{
                AUTHORITY_TRANSCRIPT_DOMAIN,
                FORMAT_VERSION,
                SCHEMA_VERSION,
                @as(u32, @intCast(words.len)),
            });
            transcript.mixU32s(&words);
        }

        pub fn mixBoundaryReceipt(
            transcript: anytype,
            audited: *const AuditedInteractionsV2,
        ) !void {
            try audited.validate();
            transcript.mixU32s(&.{
                BOUNDARY_TRANSCRIPT_DOMAIN,
                FORMAT_VERSION,
                SCHEMA_VERSION,
                @as(u32, @intCast(audited.wire_boundary.tuple_count)),
                0,
                @intFromEnum(audited.wire_boundary.domain),
            });
            transcript.mixFelts(&.{
                audited.wire_boundary.claimed_sum,
                audited.verifier_input_boundary.claimed_sum,
            });
        }

        pub fn fillPreprocessedInto(
            self: *Self,
            manifest_value: *const manifest_mod.Manifest,
            destination: [][]M31,
        ) !void {
            try self.requireManifest(manifest_value);
            return self.complete.fillPreprocessedInto(destination);
        }

        pub fn fillMainInto(
            self: *Self,
            manifest_value: *const manifest_mod.Manifest,
            destination: [][]M31,
        ) !void {
            try self.requireManifest(manifest_value);
            return self.complete.fillMainInto(destination);
        }

        pub fn fillInteractionInto(
            self: *Self,
            manifest_value: *const manifest_mod.Manifest,
            relations: *const universal.UniversalRelations,
            provider_relations: *const provider.SharedProviderRelations,
            destination: [][]M31,
        ) !GeneratedInteractionsV1 {
            try self.requireManifest(manifest_value);
            return self.complete.fillInteractionInto(
                relations,
                provider_relations,
                destination,
            );
        }

        pub fn rebuildGeneratedInteractions(
            self: *Self,
            relations: *const universal.UniversalRelations,
            provider_relations: *const provider.SharedProviderRelations,
        ) !GeneratedInteractionsV1 {
            try self.validate();
            return self.complete.rebuildGeneratedInteractions(
                relations,
                provider_relations,
            );
        }

        pub fn validateGenerated(
            self: *Self,
            generated: *const GeneratedInteractionsV1,
            relations: *const universal.UniversalRelations,
            provider_relations: *const provider.SharedProviderRelations,
        ) !void {
            try self.validate();
            return self.complete.validateGenerated(
                generated,
                relations,
                provider_relations,
            );
        }

        pub fn claimVector(
            self: *Self,
            generated: *const GeneratedInteractionsV1,
        ) !manifest_mod.ClaimVector {
            try self.validate();
            try generated.validateStructure();
            if (!std.mem.eql(
                u8,
                &generated.cohort_identity_sha256,
                &(try self.complete.identity()),
            ) or !std.mem.eql(
                u8,
                &generated.manifest_seal,
                &self.manifest_value.seal,
            )) return error.EthereumIncrementalSecureCohortMismatchV4;
            try generated.claims.validate(self.manifest_value);
            return generated.claims;
        }

        pub fn auditGlobalClosureV2(
            self: *Self,
            generated: *const GeneratedInteractionsV1,
            claims: *const manifest_mod.ClaimVector,
            relations: *const universal.UniversalRelations,
            provider_relations: *const provider.SharedProviderRelations,
        ) !AuditedInteractionsV2 {
            try self.validateGenerated(
                generated,
                relations,
                provider_relations,
            );
            if (!std.meta.eql(claims.*, try self.claimVector(generated)))
                return error.EthereumIncrementalSecureAuditMismatchV4;
            return AuditedInteractionsV2.init(generated);
        }

        pub fn auditGlobalClosure(
            self: *Self,
            generated: *const GeneratedInteractionsV1,
            claims: *const manifest_mod.ClaimVector,
            relations: *const universal.UniversalRelations,
            provider_relations: *const provider.SharedProviderRelations,
        ) !void {
            _ = try self.auditGlobalClosureV2(
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
            provider_relations: *const provider.SharedProviderRelations,
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
                return error.EthereumIncrementalSecureAuditMismatchV4;
        }

        pub fn initComponents(
            self: *Self,
            generated: *const GeneratedInteractionsV1,
            relations: *const universal.UniversalRelations,
            provider_relations: *const provider.SharedProviderRelations,
        ) !Components {
            try self.validate();
            return self.complete.initComponents(
                generated,
                relations,
                provider_relations,
            );
        }

        fn requireManifest(
            self: *Self,
            candidate: *const manifest_mod.Manifest,
        ) !void {
            try self.validate();
            if (!std.meta.eql(candidate.*, self.manifest_value.*))
                return error.EthereumIncrementalSecureCohortMismatchV4;
        }
    };
}

fn cohortIdentity(value: anytype) ![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(COHORT_IDENTITY_DOMAIN);
    hashInt(&hash, u16, FORMAT_VERSION);
    hashInt(&hash, u16, SCHEMA_VERSION);
    hash.update(&value.inputs.materialized.identity_sha256);
    hash.update(&value.inputs.materialized.campaign_authority
        .authority_identity_sha256);
    hash.update(&(try value.geometry.identity()));
    hash.update(&(try value.complete.identity()));
    hash.update(&value.manifest_value.seal);
    if (value.padding_target) |target| {
        hash.update(&target.identity_sha256);
        hash.update(&target.shape.identity_sha256);
    }
    for (value.statement_words) |word|
        hashInt(&hash, u32, word.toU32());
    return hash.finalResult();
}

fn targetLogSizes(
    target: *const padding_target_mod.CampaignPaddingTargetV2,
) !manifest_mod.LogSizesV4 {
    try target.validateSelf();
    const padded = try target.paddedLogs();
    var result: manifest_mod.LogSizesV4 = undefined;
    for (&result, padded[0..manifest_mod.COMPONENT_COUNT]) |
        *destination,
        source,
    | destination.* = source;
    return result;
}

fn validateTargetCustody(
    target: *const padding_target_mod.CampaignPaddingTargetV2,
    materialized: anytype,
) !void {
    try target.validateSelf();
    try materialized.validate();
    try campaign_public.validate(
        &target.shape,
        &materialized.schedule.node_public,
    );
    if (materialized.campaign_authority.leaf_count !=
        target.shape.real_leaf_count or
        !std.mem.eql(
            u8,
            &materialized.campaign_authority.campaign_inventory
                .table_identity_sha256,
            &target.shape.inventory_identity_sha256,
        )) return error.EthereumIncrementalSecureCohortMismatchV4;
}

fn auditedIdentity(value: *const SecureAuditedInteractionsV4) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(AUDIT_IDENTITY_DOMAIN);
    hash.update(&value.receipt.identity_sha256);
    hashInt(&hash, u64, value.wire_boundary.tuple_count);
    hashQm31(&hash, value.wire_boundary.claimed_sum);
    hashInt(&hash, u64, value.verifier_input_boundary.tuple_count);
    hashQm31(&hash, value.verifier_input_boundary.claimed_sum);
    hash.update(&value.closure.closure_id);
    return hash.finalResult();
}

fn secureCanonical(value: QM31) bool {
    for (value.toM31Array()) |word| if (word.toU32() >=
        stwo_core.fields.m31.Modulus)
    {
        return false;
    };
    return true;
}

fn hashQm31(hash: anytype, value: QM31) void {
    for (value.toM31Array()) |word|
        hashInt(hash, u32, word.toU32());
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or
        COMPONENT_COUNT != 36 or @intFromEnum(ROLE) != 0 or
        PRODUCTION_ACTIVATION or SERIALIZABLE_FRESH_CAPABILITY)
    {
        @compileError("Ethereum incremental secure cohort V4 drifted");
    }
}
