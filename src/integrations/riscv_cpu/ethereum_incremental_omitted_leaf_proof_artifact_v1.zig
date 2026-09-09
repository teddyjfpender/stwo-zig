//! Canonical cold transport for one omitted-provider Ethereum + incremental
//! memory V4 leaf: the `STWIOL01` envelope (graft G4 of the leaf route flip).
//!
//! Copied from the `STWIEF04` codec and extended in exactly two places:
//!
//!   * section 4 is the omission section -- the pinned residency request, the
//!     projection, the plan, the Stage-A roots, the single shared relation
//!     draw, the projected bridge geometry and the route digests, in one fixed
//!     little-endian layout;
//!   * sections `7 .. 7 + N` are the `N` canonical `STWD5PR1` shard artifacts,
//!     each carried as opaque bytes behind its own `u64` length.
//!
//! The FULL statement lives in section 0 exactly as in `STWIEF04`: ordinary
//! admission requires the omitted 445-column descriptor and can never accept a
//! projected core. Only the claims (section 5) are counted against the
//! projected core, which is why decode is two-phase: `decodeAllocWithRetained`
//! hands back every section but the claims, the verifier prepares its projected
//! core, and only then does `Decoded.decodeClaims` open the claim bytes.
//!
//! The SHA seal is transport custody only; decode never mints proof admission.
//! `OmissionSectionV1.validateAgainst` is the readmission: every field of the
//! decoded section must equal the authority the verifier rebuilt for itself
//! from pins + calls, never one recovered from the decoded shards.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const postcard = @import("interop_postcard");

const profile_mod = @import("ethereum_incremental_full_leaf_profile_v4.zig");
const support = @import("ethereum_incremental_full_leaf_profile_v4_wire.zig");

const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const public_data = frontend.air.public_data;
const public_data_v2 = frontend.air.public_data_v2;
const statement_mod = frontend.air.statement;
const statement_v2 = frontend.air.statement_v2;
const ethereum_statement = frontend.air.guest_precompile.ethereum_statement;
const prover = frontend.prover_mod;
const statement_wire = prover.guest_precompile
    .ethereum_segment_artifact_statement_wire;
const ethereum_wire = prover.guest_precompile.ethereum_proof_artifact_wire;
const base_wire = prover.guest_precompile.proof_artifact_wire;
const ethereum_types = prover.guest_precompile.ethereum_types;
const incremental_bridge = prover.incremental_bridge_external_v3;
const omission = prover.guest_precompile.native_provider_omit_v1;
const route = prover.guest_precompile.incremental_ethereum_omit_protocol_v4;
const provider_authority =
    frontend.testing.narrow_memory_provider_shard_authority;
const orchestration =
    frontend.testing.incremental_ethereum_omit_orchestration_v4_internal;

pub const RESEARCH_ONLY = true;
pub const PRODUCTION_ACTIVE = false;
pub const ACTIVATES_PRODUCTION_PROOF = false;
pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const MAGIC = [8]u8{ 'S', 'T', 'W', 'I', 'O', 'L', '0', '1' };
pub const Limits = base_wire.Limits;

pub const Digest = provider_authority.Digest;
pub const AuthorityId = route.AuthorityId;
/// `std.mem.asBytes` of an `Engine.Hasher.Hash` -- the same convention the
/// omit protocol's `writeRoot` hashes into every manifest identity.
pub const RootBytes = [32]u8;
pub const DecodedOmissionV1 = orchestration.DecodedOmissionV1;

/// Fixed sections before the shard artifacts: statement, role-aware public,
/// extension, profile, omission, claims, core proof.
pub const FIXED_SECTION_COUNT: usize = 7;
/// Header shard-count cap. The header is parsed before the seal is checked,
/// so the count it names must never size an allocation on its own.
pub const MAX_SHARD_ARTIFACT_COUNT: usize = 1024;

pub const Error = error{
    InvalidIncrementalOmittedLeafProofArtifactV1,
    IncrementalOmittedLeafProofArtifactContentMismatchV1,
    IncrementalOmittedLeafProofArtifactShardCountMismatchV1,
    IncrementalOmittedLeafShardArtifactSizeV1,
    InvalidIncrementalOmittedLeafOmissionSectionV1,
    IncrementalOmittedLeafOmissionSectionMismatchV1,
    IncrementalOmittedLeafOmissionProgramMismatchV1,
};

const CONTENT_DOMAIN =
    "stwo.ethereum.incremental-omitted-leaf-proof.v1\x00";
const HEADER_PREFIX_BYTES: usize = 8 + 2 + 2 + 4;
const SEAL_BYTES: usize = 32;
const QM31_BYTES: usize = 4 * @sizeOf(u32);
const DIGEST_BYTES: usize = 32;
const AUTHORITY_ID_BYTES: usize = 8 * @sizeOf(u32);

const SECTION_STATEMENT: usize = 0;
const SECTION_PUBLIC: usize = 1;
const SECTION_EXTENSION: usize = 2;
const SECTION_PROFILE: usize = 3;
const SECTION_OMISSION: usize = 4;
const SECTION_CLAIMS: usize = 5;
const SECTION_PROOF: usize = 6;

// ---------------------------------------------------------------------------
// Omission section
// ---------------------------------------------------------------------------

/// `ProviderOmissionPinsV1` as data. The route's pins are comptime constants;
/// carrying them lets a decoder that has never seen this build name the
/// drifted knob instead of only refusing a foreign pin identity.
pub const OmissionPinsV1 = struct {
    format: u32,
    shard_log_size: u32,
    requested_parallel_shards: u32,
    log_blowup_factor: u32,
    retention_policy: u32,
    host_byte_budget: u64,
    reserved_host_bytes: u64,
    column_count: u64,
    execution_owners: u32,
    engine_workers_per_owner: u32,
    non_column_reserve_per_owner: u64,

    pub const encoded_size: usize = 7 * @sizeOf(u32) + 4 * @sizeOf(u64);

    /// The one pin set this route admits.
    pub fn pinned() OmissionPinsV1 {
        const Pins = route.ProviderOmissionPinsV1;
        return .{
            .format = Pins.format,
            .shard_log_size = Pins.shard_log_size,
            .requested_parallel_shards = Pins.requested_parallel_shards,
            .log_blowup_factor = Pins.log_blowup_factor,
            .retention_policy = @intFromEnum(Pins.retention_policy),
            .host_byte_budget = Pins.host_byte_budget,
            .reserved_host_bytes = Pins.reserved_host_bytes,
            .column_count = Pins.column_count,
            .execution_owners = Pins.execution_owners,
            .engine_workers_per_owner = Pins.engine_workers_per_owner,
            .non_column_reserve_per_owner = Pins.non_column_reserve_per_owner,
        };
    }

    pub fn validate(self: OmissionPinsV1) !void {
        if (!std.meta.eql(self, pinned()))
            return error.ProviderOmissionPinDriftV4;
    }

    fn encode(self: OmissionPinsV1, writer: anytype) !void {
        try base_wire.writeInt(writer, u32, self.format);
        try base_wire.writeInt(writer, u32, self.shard_log_size);
        try base_wire.writeInt(writer, u32, self.requested_parallel_shards);
        try base_wire.writeInt(writer, u32, self.log_blowup_factor);
        try base_wire.writeInt(writer, u32, self.retention_policy);
        try base_wire.writeInt(writer, u64, self.host_byte_budget);
        try base_wire.writeInt(writer, u64, self.reserved_host_bytes);
        try base_wire.writeInt(writer, u64, self.column_count);
        try base_wire.writeInt(writer, u32, self.execution_owners);
        try base_wire.writeInt(writer, u32, self.engine_workers_per_owner);
        try base_wire.writeInt(writer, u64, self.non_column_reserve_per_owner);
    }

    fn decode(cursor: *base_wire.Cursor) !OmissionPinsV1 {
        return .{
            .format = try cursor.readInt(u32),
            .shard_log_size = try cursor.readInt(u32),
            .requested_parallel_shards = try cursor.readInt(u32),
            .log_blowup_factor = try cursor.readInt(u32),
            .retention_policy = try cursor.readInt(u32),
            .host_byte_budget = try cursor.readInt(u64),
            .reserved_host_bytes = try cursor.readInt(u64),
            .column_count = try cursor.readInt(u64),
            .execution_owners = try cursor.readInt(u32),
            .engine_workers_per_owner = try cursor.readInt(u32),
            .non_column_reserve_per_owner = try cursor.readInt(u64),
        };
    }
};

/// One plan shard and the Stage-A roots committed for it.
pub const OmissionShardRecordV1 = struct {
    descriptor_identity: Digest,
    first_call: u64,
    call_count: u32,
    expected_log_size: u32,
    preprocessed_root: RootBytes,
    main_root: RootBytes,

    pub const encoded_size: usize =
        DIGEST_BYTES + @sizeOf(u64) + 2 * @sizeOf(u32) + 2 * @sizeOf(RootBytes);

    fn encode(self: *const OmissionShardRecordV1, writer: anytype) !void {
        try writer.writeAll(&self.descriptor_identity);
        try base_wire.writeInt(writer, u64, self.first_call);
        try base_wire.writeInt(writer, u32, self.call_count);
        try base_wire.writeInt(writer, u32, self.expected_log_size);
        try writer.writeAll(&self.preprocessed_root);
        try writer.writeAll(&self.main_root);
    }

    fn decode(cursor: *base_wire.Cursor) !OmissionShardRecordV1 {
        var result: OmissionShardRecordV1 = undefined;
        try cursor.readExact(&result.descriptor_identity);
        result.first_call = try cursor.readInt(u64);
        result.call_count = try cursor.readInt(u32);
        result.expected_log_size = try cursor.readInt(u32);
        try cursor.readExact(&result.preprocessed_root);
        try cursor.readExact(&result.main_root);
        return result;
    }
};

/// Section 4 of the envelope. Field order is the wire order.
pub const OmissionSectionV1 = struct {
    /// Omit protocol format (`route.FORMAT_VERSION`).
    format: u32,
    pins: OmissionPinsV1,
    pins_identity: Digest,
    projection_identity: Digest,
    omitted_infra_index: u32,
    omitted_descriptor: statement_mod.InfraComponentDesc,
    projected_authority_id: AuthorityId,
    plan_identity: Digest,
    session: Digest,
    call_list_commitment: Digest,
    total_call_count: u64,
    shard_count: u32,
    /// Allocator-owned once decoded or minted; canonical shard order.
    shards: []const OmissionShardRecordV1,
    manifest_identity: Digest,
    interaction_pow: u64,
    relation_context_identity: Digest,
    relation_z: QM31,
    relation_alpha: QM31,
    shared_identity: Digest,
    projected_bridge_geometry: incremental_bridge.GeometryV3,
    frame_identity: Digest,
    leaf_omission_identity: Digest,
    air_program_identity: Digest,
    execution_profile_identity: Digest,

    const Self = @This();

    /// Bytes of the section before and after the shard records.
    pub const fixed_encoded_size: usize =
        @sizeOf(u32) + OmissionPinsV1.encoded_size + 2 * DIGEST_BYTES +
        @sizeOf(u32) + 4 * @sizeOf(u32) + AUTHORITY_ID_BYTES +
        3 * DIGEST_BYTES + @sizeOf(u64) + @sizeOf(u32) +
        DIGEST_BYTES + @sizeOf(u64) + DIGEST_BYTES + 2 * QM31_BYTES +
        DIGEST_BYTES + geometry_encoded_size + 4 * DIGEST_BYTES;

    pub fn encodedSize(shard_count: usize) !usize {
        const records = std.math.mul(
            usize,
            shard_count,
            OmissionShardRecordV1.encoded_size,
        ) catch return error.ArtifactResourceLimitExceeded;
        return std.math.add(usize, fixed_encoded_size, records) catch
            error.ArtifactResourceLimitExceeded;
    }

    /// Mints the section from the live authorities of one proved leaf and
    /// readmits it against them before handing it back.
    pub fn canonical(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        projection: *const omission.ProjectionV1,
        plan: *const provider_authority.ProviderShardPlanV1,
        provider_stage_a: *const ProviderStageAManifest(Engine),
        shared: SharedRelation(Engine),
        projected_bridge: *const incremental_bridge.GeometryV3,
        frame_v4: *const route.IncrementalOmissionFrameV4,
        leaf_omission: *const route.LeafOmissionAuthorityV4,
        air_program_identity: Digest,
        execution_profile_identity: Digest,
    ) !Self {
        if (plan.shards.len == 0 or
            plan.shards.len != provider_stage_a.providers.len or
            plan.shards.len > MAX_SHARD_ARTIFACT_COUNT)
        {
            return error.InvalidIncrementalOmittedLeafOmissionSectionV1;
        }
        const shards = try allocator.alloc(
            OmissionShardRecordV1,
            plan.shards.len,
        );
        errdefer allocator.free(shards);
        for (shards, plan.shards, provider_stage_a.providers) |
            *record,
            descriptor,
            provider,
        | {
            record.* = .{
                .descriptor_identity = descriptor.identity,
                .first_call = descriptor.first_call,
                .call_count = descriptor.call_count,
                .expected_log_size = descriptor.expected_log_size,
                .preprocessed_root = rootBytes(provider.preprocessed_root),
                .main_root = rootBytes(provider.main_root),
            };
        }
        const result = Self{
            .format = route.FORMAT_VERSION,
            .pins = OmissionPinsV1.pinned(),
            .pins_identity = route.ProviderOmissionPinsV1.identity(),
            .projection_identity = projection.identity,
            .omitted_infra_index = projection.omitted_infra_index,
            .omitted_descriptor = projection.omitted_descriptor,
            .projected_authority_id = projection.projected_native.authority_id,
            .plan_identity = plan.identity,
            .session = plan.session,
            .call_list_commitment = plan.call_list_commitment,
            .total_call_count = plan.total_call_count,
            .shard_count = @intCast(plan.shards.len),
            .shards = shards,
            .manifest_identity = provider_stage_a.identity,
            .interaction_pow = shared.interaction_pow,
            .relation_context_identity = shared.relation_context.identity,
            .relation_z = shared.relation_context.z,
            .relation_alpha = shared.relation_context.alpha,
            .shared_identity = shared.identity,
            .projected_bridge_geometry = projected_bridge.*,
            .frame_identity = frame_v4.identity,
            .leaf_omission_identity = leaf_omission.identity,
            .air_program_identity = air_program_identity,
            .execution_profile_identity = execution_profile_identity,
        };
        try result.validateAgainst(
            projection,
            plan,
            provider_stage_a,
            shared,
            projected_bridge,
            frame_v4,
            leaf_omission,
        );
        try result.validateDegree5Program(
            air_program_identity,
            execution_profile_identity,
        );
        return result;
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.shards);
        self.* = undefined;
    }

    pub fn encode(self: *const Self, writer: anytype) !void {
        if (self.shards.len != self.shard_count)
            return error.InvalidIncrementalOmittedLeafOmissionSectionV1;
        try base_wire.writeInt(writer, u32, self.format);
        try self.pins.encode(writer);
        try writer.writeAll(&self.pins_identity);
        try writer.writeAll(&self.projection_identity);
        try base_wire.writeInt(writer, u32, self.omitted_infra_index);
        try base_wire.writeInt(
            writer,
            u32,
            @intFromEnum(self.omitted_descriptor.kind),
        );
        try base_wire.writeInt(writer, u32, self.omitted_descriptor.log_size);
        try base_wire.writeInt(writer, u32, self.omitted_descriptor.n_rows);
        try base_wire.writeInt(writer, u32, self.omitted_descriptor.n_columns);
        for (self.projected_authority_id) |word|
            try base_wire.writeInt(writer, u32, word);
        try writer.writeAll(&self.plan_identity);
        try writer.writeAll(&self.session);
        try writer.writeAll(&self.call_list_commitment);
        try base_wire.writeInt(writer, u64, self.total_call_count);
        try base_wire.writeInt(writer, u32, self.shard_count);
        for (self.shards) |*record| try record.encode(writer);
        try writer.writeAll(&self.manifest_identity);
        try base_wire.writeInt(writer, u64, self.interaction_pow);
        try writer.writeAll(&self.relation_context_identity);
        try base_wire.writeQm31(writer, self.relation_z);
        try base_wire.writeQm31(writer, self.relation_alpha);
        try writer.writeAll(&self.shared_identity);
        try encodeGeometry(writer, &self.projected_bridge_geometry);
        try writer.writeAll(&self.frame_identity);
        try writer.writeAll(&self.leaf_omission_identity);
        try writer.writeAll(&self.air_program_identity);
        try writer.writeAll(&self.execution_profile_identity);
    }

    /// Decodes and self-validates one section. `shards` is owned by
    /// `allocator`; release it with `deinit`.
    pub fn decodeAlloc(allocator: std.mem.Allocator, bytes: []const u8) !Self {
        if (bytes.len < fixed_encoded_size)
            return error.InvalidIncrementalOmittedLeafOmissionSectionV1;
        var cursor = base_wire.Cursor.init(bytes);
        var result: Self = undefined;
        result.format = try cursor.readInt(u32);
        result.pins = try OmissionPinsV1.decode(&cursor);
        try cursor.readExact(&result.pins_identity);
        try cursor.readExact(&result.projection_identity);
        result.omitted_infra_index = try cursor.readInt(u32);
        result.omitted_descriptor = .{
            .kind = try cursor.readKnownEnum(statement_mod.InfraKind),
            .log_size = try cursor.readInt(u32),
            .n_rows = try cursor.readInt(u32),
            .n_columns = try cursor.readInt(u32),
        };
        try cursor.readU32Array(&result.projected_authority_id);
        try cursor.readExact(&result.plan_identity);
        try cursor.readExact(&result.session);
        try cursor.readExact(&result.call_list_commitment);
        result.total_call_count = try cursor.readInt(u64);
        result.shard_count = try cursor.readInt(u32);
        if (result.shard_count == 0 or
            result.shard_count > MAX_SHARD_ARTIFACT_COUNT or
            bytes.len != try encodedSize(result.shard_count))
        {
            return error.InvalidIncrementalOmittedLeafOmissionSectionV1;
        }
        const shards = try allocator.alloc(
            OmissionShardRecordV1,
            result.shard_count,
        );
        errdefer allocator.free(shards);
        for (shards) |*record|
            record.* = try OmissionShardRecordV1.decode(&cursor);
        result.shards = shards;
        try cursor.readExact(&result.manifest_identity);
        result.interaction_pow = try cursor.readInt(u64);
        try cursor.readExact(&result.relation_context_identity);
        result.relation_z = try cursor.readQm31();
        result.relation_alpha = try cursor.readQm31();
        try cursor.readExact(&result.shared_identity);
        result.projected_bridge_geometry = try decodeGeometry(&cursor);
        try cursor.readExact(&result.frame_identity);
        try cursor.readExact(&result.leaf_omission_identity);
        try cursor.readExact(&result.air_program_identity);
        try cursor.readExact(&result.execution_profile_identity);
        try cursor.requireDone();
        try result.validate();
        return result;
    }

    /// Self-consistency only: pinned pin set, non-zero bindings, the omitted
    /// Poseidon2 descriptor shape, contiguous canonical shard coverage, and a
    /// bridge geometry canonical for its own prefix.
    pub fn validate(self: *const Self) !void {
        const decoded = self.toDecodedOmission();
        try decoded.validate();
        try self.pins.validate();
        if (self.omitted_descriptor.kind != .poseidon2 or
            self.omitted_descriptor.n_columns != route.omitted_main_columns or
            self.omitted_descriptor.n_rows == 0 or
            isZeroAuthorityId(self.projected_authority_id) or
            isZero(&self.session) or
            isZero(&self.call_list_commitment) or
            isZero(&self.air_program_identity) or
            isZero(&self.execution_profile_identity) or
            isZero(&self.relation_context_identity))
        {
            return error.InvalidIncrementalOmittedLeafOmissionSectionV1;
        }
        if (self.shard_count == 0 or self.shards.len != self.shard_count or
            self.shard_count > MAX_SHARD_ARTIFACT_COUNT)
        {
            return error.InvalidIncrementalOmittedLeafOmissionSectionV1;
        }
        var next_call: u64 = 0;
        for (self.shards) |record| {
            if (record.call_count == 0 or record.first_call != next_call or
                isZero(&record.descriptor_identity) or
                record.expected_log_size == 0)
            {
                return error.InvalidIncrementalOmittedLeafOmissionSectionV1;
            }
            next_call = std.math.add(u64, next_call, record.call_count) catch
                return error.InvalidIncrementalOmittedLeafOmissionSectionV1;
        }
        if (next_call != self.total_call_count)
            return error.InvalidIncrementalOmittedLeafOmissionSectionV1;
        try self.projected_bridge_geometry.validateAfterPrefix(
            try recoveredPrefix(&self.projected_bridge_geometry),
        );
    }

    /// The verifier-side projection of this section (`DecodedOmissionV1`),
    /// exactly the fields `verifyOmittedProviderWithEngineUsingChannel` reads.
    pub fn toDecodedOmission(self: *const Self) DecodedOmissionV1 {
        return .{
            .format = self.format,
            .pins_identity = self.pins_identity,
            .projection_identity = self.projection_identity,
            .plan_identity = self.plan_identity,
            .manifest_identity = self.manifest_identity,
            .shared_identity = self.shared_identity,
            .relation_context_identity = self.relation_context_identity,
            .interaction_pow = self.interaction_pow,
            .projected_bridge_geometry = self.projected_bridge_geometry,
            .frame_identity = self.frame_identity,
            .leaf_omission_identity = self.leaf_omission_identity,
        };
    }

    /// Fail-closed readmission against the live authorities: every field of
    /// the section must equal the value the caller rebuilt for itself. `plan`
    /// is the plan rebuilt from pins + calls, never one recovered from the
    /// decoded shards; `provider_stage_a` and `shared` are the engine-typed
    /// Stage-A manifest and shared relation authority.
    pub fn validateAgainst(
        self: *const Self,
        projection: *const omission.ProjectionV1,
        plan: *const provider_authority.ProviderShardPlanV1,
        provider_stage_a: anytype,
        shared: anytype,
        projected_bridge: *const incremental_bridge.GeometryV3,
        frame_v4: *const route.IncrementalOmissionFrameV4,
        leaf_omission: *const route.LeafOmissionAuthorityV4,
    ) !void {
        try self.validate();
        const decoded = self.toDecodedOmission();
        try decoded.validateAgainst(
            projection,
            plan,
            provider_stage_a,
            shared,
            projected_bridge,
            frame_v4,
            leaf_omission,
        );
        if (self.omitted_infra_index != projection.omitted_infra_index or
            !std.meta.eql(
                self.omitted_descriptor,
                projection.omitted_descriptor,
            ) or !std.meta.eql(
            self.projected_authority_id,
            projection.projected_native.authority_id,
        ) or !std.mem.eql(
            u8,
            &self.plan_identity,
            &projection.provider_plan_identity,
        ) or !std.mem.eql(
            u8,
            &self.call_list_commitment,
            &projection.call_list_commitment,
        )) return error.IncrementalOmittedLeafOmissionSectionMismatchV1;
        if (!std.mem.eql(u8, &self.session, &plan.session) or
            !std.mem.eql(
                u8,
                &self.call_list_commitment,
                &plan.call_list_commitment,
            ) or self.total_call_count != plan.total_call_count or
            self.shard_count != plan.shard_count or
            self.shards.len != plan.shards.len or
            plan.shards.len != provider_stage_a.providers.len)
        {
            return error.IncrementalOmittedLeafOmissionSectionMismatchV1;
        }
        if (!std.mem.eql(
            u8,
            &provider_stage_a.plan_identity,
            &plan.identity,
        ) or !std.mem.eql(u8, &provider_stage_a.session, &plan.session) or
            !std.mem.eql(
                u8,
                &provider_stage_a.call_list_commitment,
                &plan.call_list_commitment,
            ))
        {
            return error.IncrementalOmittedLeafOmissionSectionMismatchV1;
        }
        for (self.shards, plan.shards, provider_stage_a.providers, 0..) |
            record,
            descriptor,
            provider,
            index,
        | {
            if (descriptor.shard_index != index or
                provider.shard_index != index or
                !std.mem.eql(
                    u8,
                    &record.descriptor_identity,
                    &descriptor.identity,
                ) or !std.mem.eql(
                u8,
                &provider.descriptor_identity,
                &descriptor.identity,
            ) or record.first_call != descriptor.first_call or
                record.call_count != descriptor.call_count or
                record.expected_log_size != descriptor.expected_log_size or
                !std.mem.eql(
                    u8,
                    &record.preprocessed_root,
                    &rootBytes(provider.preprocessed_root),
                ) or !std.mem.eql(
                u8,
                &record.main_root,
                &rootBytes(provider.main_root),
            )) return error.IncrementalOmittedLeafOmissionSectionMismatchV1;
        }
        if (!std.mem.eql(u8, &shared.plan_identity, &plan.identity) or
            !std.mem.eql(
                u8,
                &shared.manifest_identity,
                &provider_stage_a.identity,
            ) or !std.mem.eql(
            u8,
            &shared.projection_identity,
            &projection.identity,
        ) or !std.mem.eql(
            u8,
            &shared.relation_context.session,
            &plan.session,
        ) or !std.meta.eql(self.relation_z, shared.relation_context.z) or
            !std.meta.eql(self.relation_alpha, shared.relation_context.alpha))
        {
            return error.IncrementalOmittedLeafOmissionSectionMismatchV1;
        }
    }

    /// The two D5 program identities are not derivable from the seven route
    /// authorities, so they are readmitted against the verifier's own program
    /// authority and execution profile here.
    pub fn validateDegree5Program(
        self: *const Self,
        air_program_identity: Digest,
        execution_profile_identity: Digest,
    ) !void {
        if (!std.mem.eql(
            u8,
            &self.air_program_identity,
            &air_program_identity,
        ) or !std.mem.eql(
            u8,
            &self.execution_profile_identity,
            &execution_profile_identity,
        ) or isZero(&air_program_identity) or
            isZero(&execution_profile_identity))
        {
            return error.IncrementalOmittedLeafOmissionProgramMismatchV1;
        }
    }
};

fn ProviderStageAManifest(comptime Engine: type) type {
    return prover.ethereum_native_provider_omit_protocol_v1
        .ProviderStageAManifestV1(Engine);
}

fn SharedRelation(comptime Engine: type) type {
    return prover.ethereum_native_provider_omit_protocol_v1
        .SharedRelationAuthorityV1(Engine);
}

/// `std.mem.asBytes` of an engine root, as the omit protocol hashes it.
pub fn rootBytes(root: anytype) RootBytes {
    const Root = @TypeOf(root);
    comptime {
        if (@sizeOf(Root) != @sizeOf(RootBytes))
            @compileError("omitted-leaf envelope expects a 32-byte engine root");
    }
    return std.mem.asBytes(&root).*;
}

const geometry_encoded_size: usize =
    2 * @sizeOf(u32) + 4 * @sizeOf(u64) + 3 * @sizeOf(u32) + DIGEST_BYTES;

fn encodeGeometry(
    writer: anytype,
    geometry: *const incremental_bridge.GeometryV3,
) !void {
    if (geometry.format_version != incremental_bridge.FORMAT_VERSION)
        return error.InvalidIncrementalOmittedLeafOmissionSectionV1;
    try base_wire.writeInt(writer, u32, geometry.n_rows);
    try base_wire.writeInt(writer, u32, geometry.log_size);
    try writeUsize(writer, geometry.placement.is_first_col_idx);
    try writeUsize(writer, geometry.placement.is_active_col_idx);
    try writeUsize(writer, geometry.placement.main_col_offset);
    try writeUsize(writer, geometry.placement.interaction_col_offset);
    try base_wire.writeInt(writer, u32, geometry.total_preprocessed_columns);
    try base_wire.writeInt(writer, u32, geometry.total_main_columns);
    try base_wire.writeInt(writer, u32, geometry.total_interaction_columns);
    try writer.writeAll(&geometry.identity_sha256);
}

fn decodeGeometry(
    cursor: *base_wire.Cursor,
) !incremental_bridge.GeometryV3 {
    var result = incremental_bridge.GeometryV3{
        .format_version = incremental_bridge.FORMAT_VERSION,
        .n_rows = try cursor.readInt(u32),
        .log_size = try cursor.readInt(u32),
        .placement = .{
            .is_first_col_idx = try readUsize(cursor),
            .is_active_col_idx = try readUsize(cursor),
            .main_col_offset = try readUsize(cursor),
            .interaction_col_offset = try readUsize(cursor),
        },
        .total_preprocessed_columns = try cursor.readInt(u32),
        .total_main_columns = try cursor.readInt(u32),
        .total_interaction_columns = try cursor.readInt(u32),
        .identity_sha256 = undefined,
    };
    try cursor.readExact(&result.identity_sha256);
    return result;
}

fn recoveredPrefix(
    geometry: *const incremental_bridge.GeometryV3,
) !incremental_bridge.PrefixColumnsV3 {
    return .{
        .preprocessed = std.math.cast(
            u32,
            geometry.placement.is_first_col_idx,
        ) orelse return error.InvalidIncrementalOmittedLeafOmissionSectionV1,
        .main = std.math.cast(u32, geometry.placement.main_col_offset) orelse
            return error.InvalidIncrementalOmittedLeafOmissionSectionV1,
        .interaction = std.math.cast(
            u32,
            geometry.placement.interaction_col_offset,
        ) orelse return error.InvalidIncrementalOmittedLeafOmissionSectionV1,
    };
}

fn writeUsize(writer: anytype, value: usize) !void {
    try base_wire.writeInt(writer, u64, @intCast(value));
}

fn readUsize(cursor: *base_wire.Cursor) !usize {
    return std.math.cast(usize, try cursor.readInt(u64)) orelse
        error.InvalidIncrementalOmittedLeafOmissionSectionV1;
}

fn isZero(digest: *const Digest) bool {
    var aggregate: u8 = 0;
    for (digest) |byte| aggregate |= byte;
    return aggregate == 0;
}

fn isZeroAuthorityId(value: AuthorityId) bool {
    for (value) |word| {
        if (word != 0) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Framing: header, section lengths, seal
// ---------------------------------------------------------------------------

/// Header bytes for an envelope carrying `shard_count` shard artifacts.
pub fn headerBytes(shard_count: usize) !usize {
    if (shard_count == 0 or shard_count > MAX_SHARD_ARTIFACT_COUNT)
        return error.InvalidIncrementalOmittedLeafProofArtifactV1;
    return HEADER_PREFIX_BYTES +
        (1 + FIXED_SECTION_COUNT + shard_count) * @sizeOf(u64);
}

/// Section slices of one framed envelope, borrowed from the input bytes.
/// `shards` is allocator-owned; release it with `deinit`.
pub const FramedV1 = struct {
    fixed: [FIXED_SECTION_COUNT][]const u8,
    shards: [][]const u8,

    pub fn deinit(self: *FramedV1, allocator: std.mem.Allocator) void {
        allocator.free(self.shards);
        self.* = undefined;
    }
};

/// Transport framing only: magic, versions, shard count, total length, every
/// section length, the sections, the seal. Nothing here admits anything.
pub fn encodeFramedAlloc(
    allocator: std.mem.Allocator,
    fixed: [FIXED_SECTION_COUNT][]const u8,
    shards: []const []const u8,
    limits: Limits,
) ![]u8 {
    try limits.validate();
    const header = try headerBytes(shards.len);
    var total = header + SEAL_BYTES;
    for (fixed) |section| total = std.math.add(usize, total, section.len) catch
        return error.ArtifactResourceLimitExceeded;
    for (shards) |section| {
        if (section.len == 0 or section.len > limits.max_proof_bytes)
            return error.IncrementalOmittedLeafShardArtifactSizeV1;
        total = std.math.add(usize, total, section.len) catch
            return error.ArtifactResourceLimitExceeded;
    }
    if (total > limits.max_artifact_bytes)
        return error.ArtifactResourceLimitExceeded;
    const bytes = try allocator.alloc(u8, total);
    errdefer allocator.free(bytes);
    var stream = std.io.fixedBufferStream(bytes);
    const writer = stream.writer();
    try writer.writeAll(&MAGIC);
    try base_wire.writeInt(writer, u16, FORMAT_VERSION);
    try base_wire.writeInt(writer, u16, SCHEMA_VERSION);
    try base_wire.writeInt(writer, u32, @intCast(shards.len));
    try base_wire.writeInt(writer, u64, @intCast(total));
    for (fixed) |section|
        try base_wire.writeInt(writer, u64, @intCast(section.len));
    for (shards) |section|
        try base_wire.writeInt(writer, u64, @intCast(section.len));
    if (stream.pos != header)
        return error.InvalidIncrementalOmittedLeafProofArtifactV1;
    for (fixed) |section| try writer.writeAll(section);
    for (shards) |section| try writer.writeAll(section);
    const seal = contentIdentity(bytes[0..stream.pos]);
    try writer.writeAll(&seal);
    if (stream.pos != bytes.len)
        return error.InvalidIncrementalOmittedLeafProofArtifactV1;
    return bytes;
}

/// Inverse of `encodeFramedAlloc`. Checks magic, versions, declared total
/// length, section arithmetic and the seal; returns borrowed section slices.
pub fn decodeFramedAlloc(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    limits: Limits,
) !FramedV1 {
    try limits.validate();
    if (bytes.len < HEADER_PREFIX_BYTES + @sizeOf(u64) or
        bytes.len > limits.max_artifact_bytes)
    {
        return error.InvalidIncrementalOmittedLeafProofArtifactV1;
    }
    var cursor = base_wire.Cursor.init(bytes);
    if (!std.mem.eql(u8, try cursor.take(MAGIC.len), &MAGIC) or
        try cursor.readInt(u16) != FORMAT_VERSION or
        try cursor.readInt(u16) != SCHEMA_VERSION)
    {
        return error.InvalidIncrementalOmittedLeafProofArtifactV1;
    }
    const shard_count = std.math.cast(usize, try cursor.readInt(u32)) orelse
        return error.InvalidIncrementalOmittedLeafProofArtifactV1;
    const header = try headerBytes(shard_count);
    if (bytes.len < header + SEAL_BYTES or
        try cursor.readInt(u64) != @as(u64, @intCast(bytes.len)))
    {
        return error.InvalidIncrementalOmittedLeafProofArtifactV1;
    }
    var fixed_lengths: [FIXED_SECTION_COUNT]usize = undefined;
    for (&fixed_lengths) |*length| length.* = std.math.cast(
        usize,
        try cursor.readInt(u64),
    ) orelse return error.ArtifactResourceLimitExceeded;
    const shards = try allocator.alloc([]const u8, shard_count);
    errdefer allocator.free(shards);
    var shard_lengths_total: usize = 0;
    for (shards) |*shard| {
        const length = std.math.cast(usize, try cursor.readInt(u64)) orelse
            return error.ArtifactResourceLimitExceeded;
        if (length == 0 or length > limits.max_proof_bytes)
            return error.IncrementalOmittedLeafShardArtifactSizeV1;
        if (length > bytes.len)
            return error.InvalidIncrementalOmittedLeafProofArtifactV1;
        shard_lengths_total = std.math.add(
            usize,
            shard_lengths_total,
            length,
        ) catch return error.ArtifactResourceLimitExceeded;
        // Filled below once the fixed sections have been taken; the length
        // is parked in the slice so no second pass over the header is needed.
        shard.* = bytes[0..length];
    }
    if (shard_lengths_total > bytes.len)
        return error.InvalidIncrementalOmittedLeafProofArtifactV1;
    if (cursor.position != header)
        return error.InvalidIncrementalOmittedLeafProofArtifactV1;
    var result = FramedV1{ .fixed = undefined, .shards = shards };
    for (&result.fixed, fixed_lengths) |*section, length|
        section.* = try cursor.take(length);
    for (shards) |*shard| shard.* = try cursor.take(shard.len);
    const sealed_prefix_len = cursor.position;
    const retained_seal = try cursor.take(SEAL_BYTES);
    try cursor.requireDone();
    const expected_seal = contentIdentity(bytes[0..sealed_prefix_len]);
    if (!std.mem.eql(u8, retained_seal, &expected_seal))
        return error.IncrementalOmittedLeafProofArtifactContentMismatchV1;
    return result;
}

fn contentIdentity(bytes: []const u8) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CONTENT_DOMAIN);
    hash.update(bytes);
    return hash.finalResult();
}

// ---------------------------------------------------------------------------
// Typed envelope
// ---------------------------------------------------------------------------

pub fn EncodeInput(comptime Engine: type) type {
    return struct {
        /// FULL statement (section 0).
        statement: *const statement_v2.RiscVStatementV2,
        role_aware_public: *const public_data.PublicData,
        extension: *const ethereum_statement.Statement,
        /// Profile bound to the FULL statement (section 3).
        profile: *const profile_mod.AuthorityV4,
        /// Sealed projection; the claims are encoded against its core.
        projection: *const omission.ProjectionV1,
        omission: *const OmissionSectionV1,
        /// Interaction claim counted against the PROJECTED core.
        base_claim: *const statement_mod.RiscVInteractionClaim,
        extension_claim: *const ethereum_types.ExtensionClaim,
        bridge_claim: QM31,
        proof: *const prover.ProofForEngine(Engine),
        /// Canonical `STWD5PR1` shard artifacts in plan order.
        shards: []const []const u8,
    };
}

/// Claims of section 5, decoded against the projected core in phase two.
pub const DecodedClaimsV1 = struct {
    base_claim: *statement_mod.RiscVInteractionClaim,
    extension_claim: ethereum_types.ExtensionClaim,
    bridge_claim: QM31,

    pub fn deinit(self: *DecodedClaimsV1, allocator: std.mem.Allocator) void {
        allocator.destroy(self.base_claim);
        self.* = undefined;
    }
};

pub fn Decoded(comptime Engine: type) type {
    return struct {
        statement: statement_v2.RiscVStatementV2,
        role_aware_public: support.OwnedRolePublicTransportV4,
        extension: ethereum_statement.Statement,
        profile: profile_mod.AuthorityV4,
        omission: OmissionSectionV1,
        proof: prover.ProofForEngine(Engine),
        /// Raw section 5, borrowed from the envelope bytes handed to the
        /// decoder; opened by `decodeClaims` once the projected core exists.
        claim_bytes: []const u8,
        /// Borrowed `STWD5PR1` artifacts in canonical shard order. The slice
        /// itself is allocator-owned; the bytes belong to the envelope.
        shards: [][]const u8,
        canonical_words: ?[]M31,
        statement_lease: ?public_data_v2.PublicDataV2.OwnedValidatedLeaseV2,

        const Self = @This();

        /// Phase two: the claims are counted against the PROJECTED core the
        /// verifier prepared (`Extension.prepareProjectedVerifierCore`).
        pub fn decodeClaims(
            self: *const Self,
            allocator: std.mem.Allocator,
            projected_core: *const statement_mod.RiscVStatement,
            extension: *const ethereum_statement.Statement,
        ) !DecodedClaimsV1 {
            if (self.claim_bytes.len < QM31_BYTES)
                return error.InvalidIncrementalOmittedLeafProofArtifactV1;
            var claims = try ethereum_wire.decodeClaim(
                allocator,
                self.claim_bytes[0 .. self.claim_bytes.len - QM31_BYTES],
                projected_core,
                extension,
            );
            errdefer claims.deinit(allocator);
            var claim_cursor = base_wire.Cursor.init(
                self.claim_bytes[self.claim_bytes.len - QM31_BYTES ..],
            );
            const bridge_claim = try claim_cursor.readQm31();
            try claim_cursor.requireDone();
            if (claims.base.n_infra != projected_core.n_infra or
                claims.base.n_components != projected_core.n_components)
            {
                return error.InvalidIncrementalOmittedLeafProofArtifactV1;
            }
            return .{
                .base_claim = claims.base,
                .extension_claim = claims.extension,
                .bridge_claim = bridge_claim,
            };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            self.proof.deinit(allocator);
            self.releaseMetadata(allocator);
        }

        pub fn deinitAfterProofMoved(
            self: *Self,
            allocator: std.mem.Allocator,
        ) void {
            self.releaseMetadata(allocator);
        }

        fn releaseMetadata(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.shards);
            self.omission.deinit(allocator);
            self.role_aware_public.deinit();
            if (self.statement_lease) |*lease|
                lease.deinit()
            else if (self.canonical_words) |words|
                allocator.free(words);
            self.* = undefined;
        }
    };
}

pub fn encodeAlloc(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    input: EncodeInput(Engine),
    limits: Limits,
) ![]u8 {
    try limits.validate();
    try input.statement.validate();
    try input.extension.validateV2(input.statement);
    try input.extension_claim.validate(input.extension);
    try input.profile.validateAgainstStatement(
        input.statement,
        input.extension,
        input.role_aware_public,
    );
    try input.projection.validateSealAndFull(input.statement, input.extension);
    try input.omission.validate();
    const projected_core = &input.projection.projected_native.core;
    if (!std.mem.eql(
        u8,
        &input.omission.projection_identity,
        &input.projection.identity,
    ) or input.base_claim.n_infra != projected_core.n_infra or
        input.base_claim.n_components != projected_core.n_components or
        input.shards.len != input.omission.shard_count)
    {
        return error.InvalidIncrementalOmittedLeafProofArtifactV1;
    }
    if (input.role_aware_public.io_entries.input_len > limits.max_input_bytes or
        input.role_aware_public.io_entries.output_len > limits.max_output_bytes or
        !std.meta.eql(
            try input.profile.pcsConfig(),
            input.proof.commitment_scheme_proof.config,
        ) or input.proof.commitment_scheme_proof.commitments.items.len !=
        orchestration.COMMITMENT_TREE_COUNT)
    {
        return error.InvalidIncrementalOmittedLeafProofArtifactV1;
    }

    var statement_section: std.ArrayList(u8) = .empty;
    defer statement_section.deinit(allocator);
    try statement_wire.encode(
        statement_section.writer(allocator),
        input.statement,
        limits.max_artifact_bytes,
    );
    var public_section: std.ArrayList(u8) = .empty;
    defer public_section.deinit(allocator);
    try support.encodeRolePublic(
        public_section.writer(allocator),
        input.role_aware_public,
    );
    var extension_section: std.ArrayList(u8) = .empty;
    defer extension_section.deinit(allocator);
    try ethereum_wire.encodeExtension(
        extension_section.writer(allocator),
        input.extension,
    );
    if (extension_section.items.len != ethereum_wire.extension_encoded_size)
        return error.InvalidIncrementalOmittedLeafProofArtifactV1;
    var profile_section: std.ArrayList(u8) = .empty;
    defer profile_section.deinit(allocator);
    try support.encodeProfile(
        profile_section.writer(allocator),
        input.profile,
        input.statement,
        input.extension,
        input.role_aware_public,
    );
    var omission_section: std.ArrayList(u8) = .empty;
    defer omission_section.deinit(allocator);
    try input.omission.encode(omission_section.writer(allocator));
    if (omission_section.items.len !=
        try OmissionSectionV1.encodedSize(input.shards.len))
    {
        return error.InvalidIncrementalOmittedLeafProofArtifactV1;
    }
    var claim_section: std.ArrayList(u8) = .empty;
    defer claim_section.deinit(allocator);
    try ethereum_wire.encodeClaim(
        claim_section.writer(allocator),
        projected_core,
        input.extension,
        input.base_claim,
        input.extension_claim,
    );
    try base_wire.writeQm31(claim_section.writer(allocator), input.bridge_claim);
    var proof_section: std.ArrayList(u8) = .empty;
    defer proof_section.deinit(allocator);
    try postcard.serializeProof(
        Engine.Hasher,
        proof_section.writer(allocator),
        input.proof.*,
    );
    if (proof_section.items.len == 0 or
        proof_section.items.len > limits.max_proof_bytes)
    {
        return error.ProofResourceLimitExceeded;
    }

    return encodeFramedAlloc(
        allocator,
        .{
            statement_section.items,
            public_section.items,
            extension_section.items,
            profile_section.items,
            omission_section.items,
            claim_section.items,
            proof_section.items,
        },
        input.shards,
        limits,
    );
}

pub fn decodeAlloc(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    bytes: []const u8,
    limits: Limits,
) !Decoded(Engine) {
    return decodeAllocWithRetained(
        Engine,
        allocator,
        bytes,
        limits,
        null,
        null,
    );
}

/// Independent cold-boundary decoder, phase one. The retained roots are
/// external STWESG31 authority, not fields trusted from this proof envelope.
/// `bytes` must outlive the result: the claim bytes and the shard artifacts
/// are borrowed from it.
pub fn decodeAllocWithRetainedLease(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    bytes: []const u8,
    limits: Limits,
    retained: public_data_v2.PublicDataV2.RetainedSnapshots,
    counters: ?*public_data_v2.PublicDataV2.ValidationCountersV2,
) !Decoded(Engine) {
    return decodeAllocWithRetained(
        Engine,
        allocator,
        bytes,
        limits,
        retained,
        counters,
    );
}

fn decodeAllocWithRetained(
    comptime Engine: type,
    allocator: std.mem.Allocator,
    bytes: []const u8,
    limits: Limits,
    retained: ?public_data_v2.PublicDataV2.RetainedSnapshots,
    counters: ?*public_data_v2.PublicDataV2.ValidationCountersV2,
) !Decoded(Engine) {
    var framed = try decodeFramedAlloc(allocator, bytes, limits);
    var framed_owned = true;
    errdefer if (framed_owned) framed.deinit(allocator);
    const proof_bytes = framed.fixed[SECTION_PROOF];
    if (proof_bytes.len == 0 or proof_bytes.len > limits.max_proof_bytes or
        framed.fixed[SECTION_EXTENSION].len !=
            ethereum_wire.extension_encoded_size)
    {
        return error.ProofResourceLimitExceeded;
    }

    // The omission section carries the shard count the header must agree
    // with; it is checked before any statement bytes are opened.
    var omission_section = try OmissionSectionV1.decodeAlloc(
        allocator,
        framed.fixed[SECTION_OMISSION],
    );
    var omission_owned = true;
    errdefer if (omission_owned) omission_section.deinit(allocator);
    if (omission_section.shard_count != framed.shards.len)
        return error.IncrementalOmittedLeafProofArtifactShardCountMismatchV1;

    var owned_statement: ?statement_wire.Owned = null;
    var retained_statement: ?statement_wire.RetainedOwned = null;
    if (retained) |snapshots| {
        retained_statement = try statement_wire.decodeWithRetainedLease(
            allocator,
            framed.fixed[SECTION_STATEMENT],
            limits.max_artifact_bytes,
            snapshots,
            counters,
        );
    } else {
        owned_statement = try statement_wire.decode(
            allocator,
            framed.fixed[SECTION_STATEMENT],
            limits.max_artifact_bytes,
        );
    }
    var statement_owned = true;
    errdefer if (statement_owned) {
        if (retained_statement) |*value|
            value.deinit()
        else
            owned_statement.?.deinit(allocator);
    };
    const statement_value = if (retained_statement) |*value|
        &value.value
    else
        &owned_statement.?.value;
    var role_public = try support.decodeRolePublic(
        allocator,
        framed.fixed[SECTION_PUBLIC],
        statement_value,
        limits,
    );
    var role_owned = true;
    errdefer if (role_owned) role_public.deinit();
    const extension = try ethereum_wire.decodeExtension(
        framed.fixed[SECTION_EXTENSION],
    );
    try extension.validateV2(statement_value);
    const profile = try support.decodeProfile(
        framed.fixed[SECTION_PROFILE],
        statement_value,
        &extension,
        &role_public.value,
    );
    if (framed.fixed[SECTION_CLAIMS].len < QM31_BYTES)
        return error.InvalidIncrementalOmittedLeafProofArtifactV1;

    var proof_stream = std.io.fixedBufferStream(proof_bytes);
    var proof = try postcard.deserializeProof(
        Engine.Hasher,
        allocator,
        proof_stream.reader(),
    );
    var proof_owned = true;
    errdefer if (proof_owned) proof.deinit(allocator);
    if (proof_stream.pos != proof_bytes.len or
        !std.meta.eql(
            try profile.pcsConfig(),
            proof.commitment_scheme_proof.config,
        ) or proof.commitment_scheme_proof.commitments.items.len !=
        orchestration.COMMITMENT_TREE_COUNT)
    {
        return error.InvalidIncrementalOmittedLeafProofArtifactV1;
    }
    const result = Decoded(Engine){
        .statement = statement_value.*,
        .role_aware_public = role_public,
        .extension = extension,
        .profile = profile,
        .omission = omission_section,
        .proof = proof,
        .claim_bytes = framed.fixed[SECTION_CLAIMS],
        .shards = framed.shards,
        .canonical_words = if (owned_statement) |value|
            value.canonical_words
        else
            null,
        .statement_lease = if (retained_statement) |value|
            value.lease
        else
            null,
    };
    framed_owned = false;
    omission_owned = false;
    statement_owned = false;
    role_owned = false;
    proof_owned = false;
    return result;
}

comptime {
    if (PRODUCTION_ACTIVE or ACTIVATES_PRODUCTION_PROOF or
        FORMAT_VERSION != 1 or SCHEMA_VERSION != 1 or
        FIXED_SECTION_COUNT != 7 or HEADER_PREFIX_BYTES != 16 or
        SEAL_BYTES != 32 or OmissionPinsV1.encoded_size != 60 or
        OmissionShardRecordV1.encoded_size != 112 or
        geometry_encoded_size != 84 or
        OmissionSectionV1.fixed_encoded_size != 636)
    {
        @compileError("incremental omitted-leaf proof artifact V1 drifted");
    }
    if (std.mem.eql(u8, &MAGIC, "STWIEF04"))
        @compileError("STWIOL01 must not share the STWIEF04 magic");
}
