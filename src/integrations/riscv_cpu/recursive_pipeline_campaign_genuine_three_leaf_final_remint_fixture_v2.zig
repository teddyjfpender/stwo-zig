//! Genuine 3 -> 4 campaign fixture owner for the final padding transaction.
//!
//! The owner runs the repository's tiny Ethereum recovery+Keccak program as
//! three independently proved and cold-opened Stage-101 leaves.  Leaf two is
//! materialized and proved once at its active role-0 geometry.  A canonical
//! trailing empty source is derived from that verifier-owned statement and
//! session authority.  Callers then supply independently cold-owned active
//! role-1 and role-2 geometries; the existing genuine transaction remints all
//! three roles at one target and alone creates FinalRemint.
//!
//! The authenticated STWCIT04 table is caller-owned.  This module neither
//! invents its seven-ref rows nor treats the direct Stage-101 proof bytes as a
//! transitive replay recipe.  That separation is what lets the same final
//! owner later build the exact production role-0 replay authority.

const std = @import("std");
const artifact_store = @import("stwo_artifact_store");
const frontend = @import("stwo_riscv_frontend");

const genuine_stage101 =
    @import("recursive_common_ethereum_incremental_leaf_universal_proof_v4_genuine_fixture.zig");
const fresh_input_mod =
    @import("recursive_common_ethereum_incremental_leaf_input_v4.zig");
const proof_artifact =
    @import("ethereum_incremental_full_leaf_proof_artifact_v4.zig");
const campaign_geometry_mod =
    @import("recursive_common_ethereum_incremental_leaf_campaign_provider_geometry_v4.zig");
const campaign_materializer_mod =
    @import("recursive_common_ethereum_incremental_leaf_campaign_materializer_v4.zig");
const role0_proof_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_proof_v4.zig");
const empty_source_mod =
    @import("recursive_common_canonical_empty_campaign_source_v2.zig");
const leaf_mod = @import("recursive_temporal_leaf_or_empty_v1.zig");
const campaign_table_mod =
    @import("recursive_pipeline_incremental_campaign_table_v4.zig");
const campaign_namespace_mod =
    @import("recursive_pipeline_campaign_namespace_v1.zig");
const campaign_shape_mod =
    @import("recursive_pipeline_campaign_shape_v2.zig");
const campaign_public = @import("recursive_campaign_node_public_v2.zig");
const genuine_final_mod =
    @import("recursive_pipeline_campaign_genuine_final_remint_v2.zig");
const role0_authority_mod =
    @import("recursive_pipeline_worker_campaign_real_leaf_authority_v4.zig");
const policy_mod =
    @import("recursive_pipeline_worker_execution_policy_v2.zig");
const secure_engine =
    @import("recursive_temporal_secure_parent_native_engine_v1.zig");

const span = frontend.recursion.span_statement;
const channel = frontend.recursion.poseidon2_channel;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const REAL_LEAF_COUNT: u32 = 3;
pub const PADDED_LEAF_COUNT: u32 = 4;
pub const EMPTY_LEAF_INDEX: u32 = 3;
pub const ACTIVE_ROLE0_LEAF_INDEX: u32 = 2;
pub const FIRST_FOLD_HEIGHT: u8 = 1;
pub const FIRST_FOLD_INDEX: u32 = 1;
pub const PRODUCTION_ACTIVATION = false;
pub const ROUTER_ACTIVATION = false;
pub const GENUINE_Q193_GATE_GREEN = false;
pub const SERIALIZABLE_FRESH_CAPABILITY = false;
pub const CALLER_AUTHORED_STAGE101_REFS_ADMITTED = false;
pub const EXACT_STWCIT04_REQUIRED = true;

const EMPTY_SESSION_DOMAIN: u32 = 0x3345_4d50; // "3EMP"

pub const Error = error{
    GenuineThreeLeafCampaignFixtureMismatchV2,
};

pub fn Types(
    comptime Engine: type,
    comptime dimensions: frontend.recursion.fixed_wire.Dimensions,
    comptime ActiveEmpty: type,
    comptime ActiveCommon: type,
) type {
    dimensions.validate();
    assertActiveSource(ActiveEmpty, .canonical_empty_field_v2);
    assertActiveSource(ActiveCommon, .common_fold_field_v2);

    const FreshInput = fresh_input_mod.FreshInputV4(Engine);
    const Stage101Artifacts = genuine_stage101.OwnedThreeArtifactsV4(Engine);
    const CampaignGeometry = campaign_geometry_mod
        .OwnedCampaignProviderGeometryV4;
    const Materialized = campaign_materializer_mod
        .PreparedOwnedCampaignCaptureV4(Engine);
    const Role0Proof = role0_proof_mod.Types(Engine);
    const Role0Cold = Role0Proof.OwnedColdProofV4;
    const GenuineFinal = genuine_final_mod.Types(Engine, dimensions);
    const ActiveSources = struct {
        *const Role0Cold,
        *const ActiveEmpty,
        *const ActiveCommon,
    };
    const Role0Authority = role0_authority_mod.CampaignAuthorityV4(
        ActiveSources,
    );

    return struct {
        pub const EngineV4 = Engine;
        pub const FreshInputV4 = FreshInput;
        pub const Stage101ArtifactsV4 = Stage101Artifacts;
        pub const CampaignGeometryV4 = CampaignGeometry;
        pub const MaterializedV4 = Materialized;
        pub const Role0ProofV4 = Role0Proof;
        pub const Role0ColdV4 = Role0Cold;
        pub const ActiveSourcesV2 = ActiveSources;
        pub const GenuineFinalV2 = GenuineFinal;
        pub const Role0AuthorityV4 = Role0Authority;

        const FixtureTypes = @This();

        /// Heap-stable Stage-101/campaign owner. `table` is borrowed and must
        /// outlive this value. `campaign` is heap-stable because the role-0
        /// materializer retains its exact address.
        pub const OwnedCampaignV2 = struct {
            allocator: std.mem.Allocator,
            table: *const campaign_table_mod.CampaignTableV4,
            artifacts: Stage101Artifacts,
            campaign: *CampaignGeometry,
            shape: campaign_shape_mod.CampaignShapeAuthorityV2,
            materialized: *Materialized,
            active_role0: *Role0Cold,
            active_role0_receipt: secure_engine.ReceiptV1,
            empty_source: empty_source_mod.ColdInputV2,

            pub fn buildWithExecution(
                allocator: std.mem.Allocator,
                table: *const campaign_table_mod.CampaignTableV4,
                stage101_execution: genuine_stage101.Stage101ExecutionOptions,
                role0_execution: secure_engine.ExecutionOptions,
            ) !*OwnedCampaignV2 {
                try requireThreeLeafTable(table);

                var artifacts = try genuine_stage101
                    .buildThreeArtifactsWithExecution(
                    Engine,
                    allocator,
                    stage101_execution,
                );
                var artifacts_owned = true;
                defer if (artifacts_owned) artifacts.deinit();

                var fresh: [REAL_LEAF_COUNT]FreshInput = undefined;
                var fresh_count: usize = 0;
                defer {
                    var index = fresh_count;
                    while (index != 0) {
                        index -= 1;
                        fresh[index].deinit();
                    }
                }
                for (0..REAL_LEAF_COUNT) |index| {
                    fresh[index] = try FreshInput.coldOpen(
                        allocator,
                        artifacts.bytes[index],
                        try @import("recursive_node_artifact_v1.zig")
                            .TaskCoordinateV1.init(0, @intCast(index)),
                        proof_artifact.Limits{},
                    );
                    fresh_count += 1;
                }

                const campaign = try allocator.create(CampaignGeometry);
                var campaign_initialized = false;
                errdefer {
                    if (campaign_initialized) campaign.deinit();
                    allocator.destroy(campaign);
                }
                const fresh_pointers = [REAL_LEAF_COUNT]*const FreshInput{
                    &fresh[0],
                    &fresh[1],
                    &fresh[2],
                };
                campaign.* = try CampaignGeometry.mintFromBorrowedFreshInputs(
                    Engine,
                    allocator,
                    try campaign_geometry_mod.CampaignInventoryAuthorityV4
                        .fromTable(table),
                    &fresh_pointers,
                );
                campaign_initialized = true;

                const namespace = try campaign_namespace_mod
                    .fromValidatedTable(table);
                const shape = try campaign_shape_mod.CampaignShapeAuthorityV2
                    .init(namespace, table.content_sha256, REAL_LEAF_COUNT);
                try requireThreeToFourShape(&shape);

                const materialized = try allocator.create(Materialized);
                var materialized_initialized = false;
                errdefer {
                    if (materialized_initialized) materialized.deinit();
                    allocator.destroy(materialized);
                }
                materialized.* = try Materialized.initOwned(
                    allocator,
                    &fresh[ACTIVE_ROLE0_LEAF_INDEX],
                    campaign,
                    ACTIVE_ROLE0_LEAF_INDEX,
                );
                // The materializer moved the only allocation-owning field.
                fresh_count -= 1;
                materialized_initialized = true;

                var proved = try Role0Proof.proveAndColdVerify(
                    allocator,
                    materialized,
                    role0_execution,
                );
                var proved_owned = true;
                defer if (proved_owned) proved.deinit();
                const active_role0 = try allocator.create(Role0Cold);
                var active_role0_initialized = false;
                errdefer {
                    if (active_role0_initialized) active_role0.deinit();
                    allocator.destroy(active_role0);
                }
                active_role0.* = proved.proof;
                active_role0_initialized = true;
                proved.proof = undefined;
                const active_role0_receipt = proved.receipt;
                proved_owned = false;

                const empty_source = try buildEmptySource(
                    &shape,
                    active_role0,
                );
                const self = try allocator.create(OwnedCampaignV2);
                self.* = .{
                    .allocator = allocator,
                    .table = table,
                    .artifacts = artifacts,
                    .campaign = campaign,
                    .shape = shape,
                    .materialized = materialized,
                    .active_role0 = active_role0,
                    .active_role0_receipt = active_role0_receipt,
                    .empty_source = empty_source,
                };
                artifacts_owned = false;
                campaign_initialized = false;
                materialized_initialized = false;
                active_role0_initialized = false;
                errdefer self.deinit();
                try self.validate();
                return self;
            }

            pub fn deinit(self: *OwnedCampaignV2) void {
                const allocator = self.allocator;
                self.active_role0.deinit();
                allocator.destroy(self.active_role0);
                self.materialized.deinit();
                allocator.destroy(self.materialized);
                self.campaign.deinit();
                allocator.destroy(self.campaign);
                self.artifacts.deinit();
                self.* = undefined;
                allocator.destroy(self);
            }

            pub fn validate(self: *const OwnedCampaignV2) !void {
                try requireThreeLeafTable(self.table);
                try requireThreeToFourShape(&self.shape);
                try self.campaign.validateStructure();
                try self.materialized.validate();
                try self.active_role0.validateBorrowed();
                try self.active_role0_receipt.validate();
                const empty_bytes = try self.empty_source.source
                    .encodeCanonical(&self.empty_source.shape);
                try self.empty_source.validate(&empty_bytes);
                const empty_coordinate = try self.empty_source.coordinate();
                const role0_statement = try span.SpanStatement
                    .fromCanonicalWords(
                    &self.active_role0.session.parent_statement_words,
                );
                const empty_statement = try self.empty_source.leaf.statement();
                const expected_empty_session = channel.hashBytes(
                    &self.shape.identity_sha256,
                    EMPTY_SESSION_DOMAIN,
                );
                if (self.materialized.campaign_authority != self.campaign or
                    self.materialized.campaign_leaf_index !=
                        ACTIVE_ROLE0_LEAF_INDEX or
                    self.active_role0.materialized != self.materialized or
                    self.campaign.leaf_count != REAL_LEAF_COUNT or
                    !std.mem.eql(
                        u8,
                        &self.campaign.campaign_inventory
                            .table_identity_sha256,
                        &self.table.content_sha256,
                    ) or !std.meta.eql(self.empty_source.shape, self.shape) or
                    empty_coordinate.height != 0 or
                    empty_coordinate.index != EMPTY_LEAF_INDEX or
                    empty_coordinate.global_ordinal != EMPTY_LEAF_INDEX or
                    !std.meta.eql(empty_statement.job, role0_statement.job) or
                    !std.meta.eql(
                        self.empty_source.source.session_id,
                        expected_empty_session,
                    ) or !std.meta.eql(
                    self.empty_source.source.segment_leaf_vk_id,
                    self.active_role0.session.verification_key_id,
                ) or !std.meta.eql(
                    self.empty_source.source.recursive_parent_vk_id,
                    self.active_role0.session.next_parent_vk_id,
                )) {
                    return error.GenuineThreeLeafCampaignFixtureMismatchV2;
                }
            }

            comptime {
                rejectCodec(OwnedCampaignV2);
            }
        };

        /// Heap-stable final transaction plus the exact active-source tuple
        /// needed by the Stage-102 replay authority. It borrows `campaign`,
        /// `active_empty`, and `active_common`, which must outlive it.
        pub const OwnedFinalV2 = struct {
            allocator: std.mem.Allocator,
            campaign: *const OwnedCampaignV2,
            active_sources: ActiveSources,
            genuine: *GenuineFinal.OwnedV2,

            pub fn proveAndFinalize(
                allocator: std.mem.Allocator,
                campaign: *const OwnedCampaignV2,
                active_empty: *const ActiveEmpty,
                active_common: *const ActiveCommon,
                execution: artifact_store.ExecutionKeyV1,
                policy: *const policy_mod.PolicyV2,
            ) !*OwnedFinalV2 {
                // Deliberately first: compile-only gates can exercise the
                // entire exact body without dereferencing fake proof owners.
                try policy.validateAgainstExecution(execution);
                try campaign.validate();
                try active_empty.validateColdGeometry();
                try active_common.validateColdGeometry();
                const self = try allocator.create(OwnedFinalV2);
                errdefer allocator.destroy(self);
                self.allocator = allocator;
                self.campaign = campaign;
                self.active_sources = .{
                    campaign.active_role0,
                    active_empty,
                    active_common,
                };
                self.genuine = try GenuineFinal.proveAndFinalize(
                    allocator,
                    self.active_sources,
                    &campaign.shape,
                    campaign.materialized,
                    &campaign.empty_source,
                    try campaign_public.coordinate(
                        &campaign.shape,
                        FIRST_FOLD_HEIGHT,
                        FIRST_FOLD_INDEX,
                    ),
                    execution,
                    policy,
                );
                errdefer self.genuine.deinit();
                try self.validate();
                return self;
            }

            pub fn deinit(self: *OwnedFinalV2) void {
                const allocator = self.allocator;
                self.genuine.deinit();
                self.* = undefined;
                allocator.destroy(self);
            }

            pub fn validate(self: *const OwnedFinalV2) !void {
                try self.campaign.validate();
                try self.genuine.validate(self.active_sources);
                if (self.active_sources[0] != self.campaign.active_role0 or
                    self.genuine.authority().shape != &self.genuine.target.shape or
                    !std.meta.eql(
                        self.genuine.target.shape,
                        self.campaign.shape,
                    ))
                {
                    return error.GenuineThreeLeafCampaignFixtureMismatchV2;
                }
            }

            /// Builds the exact production role-0 authority over caller-owned
            /// Zig Stage-101 key admissions. The returned value and admission
            /// slice must be kept stable through every Stage-102 cold lease.
            pub fn role0Authority(
                self: *const OwnedFinalV2,
                admissions: []const role0_authority_mod.Stage101AdmissionV4,
            ) !Role0Authority {
                try self.validate();
                const result = Role0Authority{
                    .table = self.campaign.table,
                    .campaign_geometry = self.campaign.campaign,
                    .padding_target = &self.genuine.target,
                    .final_remint = self.genuine.authority(),
                    .active_sources = &self.active_sources,
                    .stage101_admissions = admissions,
                };
                try result.validate(
                    self.allocator,
                    self.genuine.authority().shape
                        .campaign_namespace_sha256,
                );
                return result;
            }

            comptime {
                rejectCodec(OwnedFinalV2);
            }
        };

        comptime {
            if (FixtureTypes.Role0AuthorityV4 != Role0Authority or
                FixtureTypes.ActiveSourcesV2 != ActiveSources)
            {
                @compileError("three-leaf campaign fixture type closure drifted");
            }
        }
    };
}

fn requireThreeLeafTable(
    table: *const campaign_table_mod.CampaignTableV4,
) !void {
    try table.validate();
    const topology = try table.topology();
    if (table.segment_count != REAL_LEAF_COUNT or
        topology.leaf_count != REAL_LEAF_COUNT or
        topology.padded_leaf_count != PADDED_LEAF_COUNT or
        topology.empty_leaf_count != 1 or topology.fold_count != 3)
    {
        return error.GenuineThreeLeafCampaignFixtureMismatchV2;
    }
}

fn requireThreeToFourShape(
    shape: *const campaign_shape_mod.CampaignShapeAuthorityV2,
) !void {
    try shape.validate();
    if (shape.real_leaf_count != REAL_LEAF_COUNT or
        shape.padded_leaf_count != PADDED_LEAF_COUNT or
        shape.empty_leaf_count != 1 or shape.fold_count != 3 or
        shape.root_height != 2)
    {
        return error.GenuineThreeLeafCampaignFixtureMismatchV2;
    }
}

fn buildEmptySource(
    shape: *const campaign_shape_mod.CampaignShapeAuthorityV2,
    active_role0: anytype,
) !empty_source_mod.ColdInputV2 {
    try active_role0.validateBorrowed();
    const statement = try span.SpanStatement.fromCanonicalWords(
        &active_role0.session.parent_statement_words,
    );
    if (statement.job.segment_count != REAL_LEAF_COUNT or
        statement.slots.height != 0 or
        statement.slots.first != ACTIVE_ROLE0_LEAF_INDEX)
    {
        return error.GenuineThreeLeafCampaignFixtureMismatchV2;
    }
    var leaf: leaf_mod.LeafOrEmptyV1 = undefined;
    try leaf_mod.admitEmptyInto(
        &leaf,
        statement.job,
        EMPTY_LEAF_INDEX,
        channel.hashBytes(&shape.identity_sha256, EMPTY_SESSION_DOMAIN),
        active_role0.session.verification_key_id,
        active_role0.session.next_parent_vk_id,
    );
    const source = try empty_source_mod.SourceArtifactV2.seal(shape, &leaf);
    const bytes = try source.encodeCanonical(shape);
    return empty_source_mod.ColdInputV2.open(shape, &bytes);
}

fn assertActiveSource(comptime Source: type, comptime role: anytype) void {
    if (!@hasDecl(Source, "ROLE") or Source.ROLE != role)
        @compileError("three-leaf final fixture active-source role mismatch");
    inline for (.{ "validateColdGeometry", "geometryForPaddingTarget" }) |
        name,
    | if (!@hasDecl(Source, name))
        @compileError("three-leaf final fixture active source missing " ++ name);
    rejectCodec(Source);
}

fn rejectCodec(comptime T: type) void {
    inline for (.{ "encode", "decode", "encodeAlloc", "decodeAlloc" }) |name|
        if (@hasDecl(T, name))
            @compileError("three-leaf final fixture capability gained a codec");
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        REAL_LEAF_COUNT != 3 or PADDED_LEAF_COUNT != 4 or
        EMPTY_LEAF_INDEX != 3 or ACTIVE_ROLE0_LEAF_INDEX != 2 or
        FIRST_FOLD_HEIGHT != 1 or FIRST_FOLD_INDEX != 1 or
        PRODUCTION_ACTIVATION or ROUTER_ACTIVATION or
        GENUINE_Q193_GATE_GREEN or SERIALIZABLE_FRESH_CAPABILITY or
        CALLER_AUTHORED_STAGE101_REFS_ADMITTED or !EXACT_STWCIT04_REQUIRED)
    {
        @compileError("genuine three-leaf final-remint fixture drifted");
    }
}
