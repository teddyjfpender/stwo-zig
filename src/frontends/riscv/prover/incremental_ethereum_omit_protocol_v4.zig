//! Route protocol for the V4 incremental leaf with an omitted native
//! Poseidon2 provider (grafts G2 and G3 of the leaf route flip).
//!
//! Three fail-closed authorities live here and nothing else:
//!
//!   * `ProviderOmissionPinsV1` freezes the residency-shard `Request` as
//!     comptime constants. `residency_shard_plan.Request.identity` is hashed
//!     into `Plan.request_identity`, which `planIdentity` hashes into
//!     `Plan.plan_identity`, which `ProjectionV1` hashes into its own
//!     identity, which this module's frame mixes into the core channel before
//!     the single shared relation draw. A host knob (owner count, byte budget,
//!     a worker environment variable) reaching that path would make proof
//!     identity host-dependent, so the request is a pure function of the call
//!     count and of nothing else -- pinned at comptime below.
//!   * `IncrementalOmissionFrameV4` is the pre-Tree0 binder: the projection
//!     identity plus the *projected* bridge geometry, mixed immediately after
//!     `AuthorityV4.mixPreTree0` and before the first root is absorbed. Tree
//!     0's column count and every bridge mask offset depend on the projection,
//!     so they must be fixed before Tree 0.
//!   * `LeafOmissionAuthorityV4` is the digest every shard mixes into its
//!     local prefix. Binding the profile identity, the frame identity, the
//!     shared relation identity and the FULL statement authority id blocks
//!     relabelling a segment-, candidate- or standalone-route shard proof into
//!     this leaf.
//!
//! This tranche is authority and algebra only: no prove or verify path calls
//! it yet, and `ACTIVATES_PRODUCTION_PROOF` stays false.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const prover_engine = @import("stwo_prover_engine");
const residency_estimate = prover_engine.pcs.residency_estimate;
const residency_shard_plan = prover_engine.pcs.residency_shard_plan;

const aggregation_hash = @import("../aggregation/hash.zig");
const poseidon_channel = @import("../recursion/poseidon2_channel.zig");
const protocol = @import("../recursion/protocol.zig");
const statement = @import("../air/statement.zig");
const lookup_physical_v2 =
    @import("../air/lang/lookup_physical_manifest_v2.zig");
const ethereum_statement =
    @import("../air/guest_precompile/ethereum_statement.zig");
const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
const bridge_external = @import("incremental_bridge_external_v3.zig");
const ethereum_types = @import("guest_precompile/ethereum_types.zig");
const provider_authority = @import("memory_provider_shards/authority.zig");
const omission = @import("memory_provider_shards/native_provider_omit_v1.zig");

pub const RESEARCH_ONLY = true;
pub const ACTIVATES_PRODUCTION_PROOF = false;
pub const FORMAT_VERSION: u32 = 1;

pub const Digest = aggregation_hash.Digest;
/// Eight-word Poseidon2 statement authority id (`RiscVStatementV2.authority_id`).
pub const AuthorityId = poseidon_channel.Digest;

pub const Error = error{
    ProviderOmissionPinDriftV4,
    EmptyProviderOmissionCallAuthorityV4,
    InvalidIncrementalOmissionFrameV4,
    InvalidIncrementalOmissionProjectionV4,
    InvalidIncrementalOmissionBridgeGeometryV4,
    IncrementalOmissionColumnOverflowV4,
    InvalidLeafOmissionAuthorityV4,
};

/// Columns the omitted `poseidon2` infrastructure component owns in each tree.
pub const omitted_preprocessed_columns: u32 =
    statement.nPreprocessedColumnsForInfra(.poseidon2);
pub const omitted_main_columns: u32 = poseidon2_air.N_MAIN_COLUMNS;
pub const omitted_interaction_columns: u32 =
    statement.nInteractionColsForInfra(.poseidon2);

// ---------------------------------------------------------------------------
// G2: host knobs frozen as comptime pins
// ---------------------------------------------------------------------------

/// The one residency request this route is permitted to plan with.
///
/// Every field is a comptime constant. `request` takes the total call count
/// and nothing else, so two hosts with different owner counts, byte budgets or
/// worker environments produce the same `Request.identity`, the same
/// `Plan.plan_identity`, the same `ProjectionV1.identity` and therefore the
/// same relation draw.
pub const ProviderOmissionPinsV1 = struct {
    pub const format: u32 = FORMAT_VERSION;
    pub const shard_log_size: u32 = 18;
    pub const requested_parallel_shards: u32 = 18;
    pub const log_blowup_factor: u32 = protocol.FRI_LOG_BLOWUP_FACTOR;
    pub const retention_policy: residency_estimate.RetentionPolicy = .always;
    pub const host_byte_budget: u64 = 51_539_607_552;
    pub const reserved_host_bytes: u64 = 8_589_934_592;
    pub const column_count: u64 = provider_authority.main_column_count;
    /// Host-execution pins. They never enter `Request` (the planner does not
    /// model them) but they do enter `identity`, so a receipt that claims this
    /// pin set cannot have been produced with a different owner fan-out.
    pub const execution_owners: u32 = 18;
    pub const engine_workers_per_owner: u32 = 1;
    pub const non_column_reserve_per_owner: u64 = 536_870_912;

    /// Canonical residency request for `total_call_count` provider calls.
    pub fn request(total_call_count: u64) residency_shard_plan.Request {
        return .{
            .logical_row_count = total_call_count,
            .column_count = column_count,
            .min_shard_log_size = shard_log_size,
            .max_shard_log_size = shard_log_size,
            .log_blowup_factor = log_blowup_factor,
            .retention_policy = retention_policy,
            .host_byte_budget = host_byte_budget,
            .reserved_host_bytes = reserved_host_bytes,
            .requested_parallel_shards = requested_parallel_shards,
        };
    }

    /// Fail-closed readmission of a request that claims to be this pin set.
    /// The per-field checks name the drifted knob; the whole-value comparison
    /// is the backstop that keeps this exhaustive if `Request` grows a field.
    pub fn validateRequest(
        value: residency_shard_plan.Request,
        total_call_count: u64,
    ) Error!void {
        if (total_call_count == 0)
            return error.EmptyProviderOmissionCallAuthorityV4;
        if (value.logical_row_count != total_call_count or
            value.column_count != column_count or
            value.min_shard_log_size != shard_log_size or
            value.max_shard_log_size != shard_log_size or
            value.log_blowup_factor != log_blowup_factor or
            value.retention_policy != retention_policy or
            value.host_byte_budget != host_byte_budget or
            value.reserved_host_bytes != reserved_host_bytes or
            value.requested_parallel_shards != requested_parallel_shards)
        {
            return error.ProviderOmissionPinDriftV4;
        }
        if (!std.meta.eql(value, request(total_call_count)))
            return error.ProviderOmissionPinDriftV4;
    }

    /// Pinned residency plan for `total_call_count` calls, validated by the
    /// provider authority's own policy (445 columns, admissible shard log).
    pub fn residencyAuthority(
        total_call_count: u64,
    ) !provider_authority.ResidencyPlanningAuthorityV1 {
        if (total_call_count == 0)
            return error.EmptyProviderOmissionCallAuthorityV4;
        const result = try provider_authority.ResidencyPlanningAuthorityV1
            .canonical(request(total_call_count));
        try validateRequest(result.request, total_call_count);
        if (result.result.shard_log_size != shard_log_size or
            result.result.requested_parallel_shards != requested_parallel_shards)
        {
            return error.ProviderOmissionPinDriftV4;
        }
        return result;
    }

    /// Statement-independent identity of the pin set. The call count is
    /// deliberately absent: it belongs to `Request.identity`.
    pub fn identity() Digest {
        var sink = aggregation_hash.HashSink.init(pins_domain);
        aggregation_hash.writeU32(&sink, format) catch unreachable;
        aggregation_hash.writeU32(&sink, shard_log_size) catch unreachable;
        aggregation_hash.writeU32(
            &sink,
            requested_parallel_shards,
        ) catch unreachable;
        aggregation_hash.writeU32(&sink, log_blowup_factor) catch unreachable;
        aggregation_hash.writeU32(
            &sink,
            @intFromEnum(retention_policy),
        ) catch unreachable;
        aggregation_hash.writeU64(&sink, host_byte_budget) catch unreachable;
        aggregation_hash.writeU64(&sink, reserved_host_bytes) catch unreachable;
        aggregation_hash.writeU64(&sink, column_count) catch unreachable;
        aggregation_hash.writeU32(&sink, execution_owners) catch unreachable;
        aggregation_hash.writeU32(
            &sink,
            engine_workers_per_owner,
        ) catch unreachable;
        aggregation_hash.writeU64(
            &sink,
            non_column_reserve_per_owner,
        ) catch unreachable;
        return sink.finalize();
    }
};

// ---------------------------------------------------------------------------
// G3a: projected bridge geometry
// ---------------------------------------------------------------------------

/// Committed prefix immediately before the bridge once the 445-column
/// Poseidon2 table has left Trees 0/1/2. Mirrors the full-statement prefix of
/// `ethereum_incremental_full_leaf_profile_v4.prefixColumns`, with the base
/// half taken from the projected core instead of the base geometry.
pub fn projectedPrefixColumns(
    projected_core: *const statement.RiscVStatement,
    extension: *const ethereum_statement.Statement,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    manifest: *const lookup_physical_v2.Manifest,
) !bridge_external.PrefixColumnsV3 {
    const base_interaction = try authenticated.totalInteractionColumns(
        projected_core,
        manifest,
    );
    var result = bridge_external.PrefixColumnsV3{
        .preprocessed = projected_core.nPreprocessedColumns(),
        .main = projected_core.nMainColumns(),
        .interaction = std.math.cast(u32, base_interaction) orelse
            return error.IncrementalOmissionColumnOverflowV4,
    };
    for (extension.components) |descriptor| {
        result.preprocessed = try addColumns(
            result.preprocessed,
            descriptor.preprocessed_columns,
        );
        result.main = try addColumns(result.main, descriptor.main_columns);
        result.interaction = try addColumns(
            result.interaction,
            descriptor.interaction_columns,
        );
    }
    try result.validate();
    return result;
}

/// Projected sibling of `AuthorityV4.bridge_geometry`. The bridge occupies the
/// same rows and the same log size; only its placement slides down by exactly
/// the omitted component's column counts.
pub fn projectedBridgeGeometry(
    full_bridge: *const bridge_external.GeometryV3,
    projected_core: *const statement.RiscVStatement,
    extension: *const ethereum_statement.Statement,
    authenticated: *const lookup_physical_v2.AuthenticatedStatement,
    manifest: *const lookup_physical_v2.Manifest,
) !bridge_external.GeometryV3 {
    const prefix = try projectedPrefixColumns(
        projected_core,
        extension,
        authenticated,
        manifest,
    );
    return projectedBridgeGeometryFromPrefix(full_bridge, prefix);
}

/// Placement-arithmetic core of `projectedBridgeGeometry`, callable without a
/// statement. Fails closed unless the projected geometry differs from the full
/// geometry by exactly (2, 445, 8) columns and by nothing else.
pub fn projectedBridgeGeometryFromPrefix(
    full_bridge: *const bridge_external.GeometryV3,
    projected_prefix: bridge_external.PrefixColumnsV3,
) !bridge_external.GeometryV3 {
    if (full_bridge.format_version != bridge_external.FORMAT_VERSION)
        return error.InvalidIncrementalOmissionBridgeGeometryV4;
    const projected = try bridge_external.GeometryV3.canonicalAfterPrefix(
        full_bridge.n_rows,
        projected_prefix,
    );
    if (projected.n_rows != full_bridge.n_rows or
        projected.log_size != full_bridge.log_size)
    {
        return error.InvalidIncrementalOmissionBridgeGeometryV4;
    }
    try requireRemoved(
        full_bridge.placement.is_first_col_idx,
        projected.placement.is_first_col_idx,
        omitted_preprocessed_columns,
    );
    try requireRemoved(
        full_bridge.placement.is_active_col_idx,
        projected.placement.is_active_col_idx,
        omitted_preprocessed_columns,
    );
    try requireRemoved(
        full_bridge.placement.main_col_offset,
        projected.placement.main_col_offset,
        omitted_main_columns,
    );
    try requireRemoved(
        full_bridge.placement.interaction_col_offset,
        projected.placement.interaction_col_offset,
        omitted_interaction_columns,
    );
    try requireRemoved(
        full_bridge.total_preprocessed_columns,
        projected.total_preprocessed_columns,
        omitted_preprocessed_columns,
    );
    try requireRemoved(
        full_bridge.total_main_columns,
        projected.total_main_columns,
        omitted_main_columns,
    );
    try requireRemoved(
        full_bridge.total_interaction_columns,
        projected.total_interaction_columns,
        omitted_interaction_columns,
    );
    return projected;
}

// ---------------------------------------------------------------------------
// G3b: the pre-Tree0 frame
// ---------------------------------------------------------------------------

/// Pre-Tree0 binder for the omitted-provider route.
///
/// `mixInto` runs immediately after `AuthorityV4.mixPreTree0` and immediately
/// before the Tree 0 root is absorbed, on the producer core channel, on the
/// CPU core verifier channel, and on every shard's replay of that channel.
pub const IncrementalOmissionFrameV4 = struct {
    format: u32,
    projection_identity: Digest,
    projected_bridge_geometry: bridge_external.GeometryV3,
    pins_identity: Digest,
    identity: Digest,

    /// Canonical frame for a prepared projection.
    ///
    /// Only `projection.identity` is read: the projection's own
    /// `validateAgainstValidated` / `validateSealAndFull` remain the caller's
    /// obligation, and `validateAgainst` below re-checks the binding.
    pub fn canonical(
        projection: *const omission.ProjectionV1,
        bridge_n_rows: u32,
        projected_prefix: bridge_external.PrefixColumnsV3,
    ) !IncrementalOmissionFrameV4 {
        return canonicalFromProjectionIdentity(
            projection.identity,
            bridge_n_rows,
            projected_prefix,
        );
    }

    pub fn canonicalFromProjectionIdentity(
        projection_identity: Digest,
        bridge_n_rows: u32,
        projected_prefix: bridge_external.PrefixColumnsV3,
    ) !IncrementalOmissionFrameV4 {
        const geometry = try bridge_external.GeometryV3.canonicalAfterPrefix(
            bridge_n_rows,
            projected_prefix,
        );
        return canonicalFromGeometry(projection_identity, geometry);
    }

    /// Constructor for a caller that already recomputed the projected
    /// geometry (the fresh verifier, which compares it against the decoded
    /// omission section before rebuilding the frame).
    pub fn canonicalFromGeometry(
        projection_identity: Digest,
        geometry: bridge_external.GeometryV3,
    ) !IncrementalOmissionFrameV4 {
        if (aggregation_hash.isZero(projection_identity))
            return error.InvalidIncrementalOmissionProjectionV4;
        var result = IncrementalOmissionFrameV4{
            .format = FORMAT_VERSION,
            .projection_identity = projection_identity,
            .projected_bridge_geometry = geometry,
            .pins_identity = ProviderOmissionPinsV1.identity(),
            .identity = undefined,
        };
        result.identity = frameIdentity(&result);
        try result.validate();
        return result;
    }

    /// Self-consistency: format, non-zero projection binding, pinned pin set,
    /// a geometry that is canonical for its own recovered prefix, and an
    /// identity that is the hash of exactly those fields.
    pub fn validate(self: *const IncrementalOmissionFrameV4) !void {
        if (self.format != FORMAT_VERSION)
            return error.InvalidIncrementalOmissionFrameV4;
        if (aggregation_hash.isZero(self.projection_identity))
            return error.InvalidIncrementalOmissionProjectionV4;
        if (!aggregation_hash.eql(
            self.pins_identity,
            ProviderOmissionPinsV1.identity(),
        )) return error.ProviderOmissionPinDriftV4;
        try self.projected_bridge_geometry.validateAfterPrefix(
            try recoveredPrefix(&self.projected_bridge_geometry),
        );
        if (!aggregation_hash.eql(self.identity, frameIdentity(self)))
            return error.InvalidIncrementalOmissionFrameV4;
    }

    /// Fail-closed readmission against the projection and prefix the caller
    /// believes it prepared.
    pub fn validateAgainst(
        self: *const IncrementalOmissionFrameV4,
        projection: *const omission.ProjectionV1,
        projected_prefix: bridge_external.PrefixColumnsV3,
    ) !void {
        try self.validate();
        if (!aggregation_hash.eql(
            self.projection_identity,
            projection.identity,
        )) return error.InvalidIncrementalOmissionProjectionV4;
        const expected = try bridge_external.GeometryV3.canonicalAfterPrefix(
            self.projected_bridge_geometry.n_rows,
            projected_prefix,
        );
        if (!std.meta.eql(self.projected_bridge_geometry, expected))
            return error.InvalidIncrementalOmissionBridgeGeometryV4;
    }

    /// Pre-Tree0 transcript frame. Order is protocol: domain words, projection
    /// identity, pins identity, projected bridge geometry field authority.
    pub fn mixInto(
        self: *const IncrementalOmissionFrameV4,
        channel: anytype,
    ) void {
        channel.mixU32s(&frame_domain_words);
        mixDigest(channel, self.projection_identity);
        mixDigest(channel, self.pins_identity);
        self.projected_bridge_geometry.mixFieldAuthority(channel);
    }
};

// ---------------------------------------------------------------------------
// G3c: the per-shard leaf omission authority
// ---------------------------------------------------------------------------

/// Digest every shard mixes into its local prefix, after the shared frame and
/// before `finishLocalPrefix`. It is what makes a shard proof non-portable:
/// re-using it under another leaf changes the profile identity, the frame
/// identity, the shared relation identity or the full statement authority id.
pub const LeafOmissionAuthorityV4 = struct {
    format: u32,
    profile_identity_sha256: [32]u8,
    frame_identity: Digest,
    shared_identity: Digest,
    full_statement_authority_id: AuthorityId,
    identity: Digest,

    pub fn canonical(
        profile_identity_sha256: [32]u8,
        frame_identity: Digest,
        shared_identity: Digest,
        full_statement_authority_id: AuthorityId,
    ) !LeafOmissionAuthorityV4 {
        var result = LeafOmissionAuthorityV4{
            .format = FORMAT_VERSION,
            .profile_identity_sha256 = profile_identity_sha256,
            .frame_identity = frame_identity,
            .shared_identity = shared_identity,
            .full_statement_authority_id = full_statement_authority_id,
            .identity = undefined,
        };
        result.identity = leafOmissionIdentity(&result);
        try result.validate();
        return result;
    }

    /// Every bound field must be present: a zero digest or a zero authority id
    /// is a missing binding, not a permitted value.
    pub fn validate(self: *const LeafOmissionAuthorityV4) !void {
        if (self.format != FORMAT_VERSION or
            aggregation_hash.isZero(self.profile_identity_sha256) or
            aggregation_hash.isZero(self.frame_identity) or
            aggregation_hash.isZero(self.shared_identity) or
            isZeroAuthorityId(self.full_statement_authority_id))
        {
            return error.InvalidLeafOmissionAuthorityV4;
        }
        if (!aggregation_hash.eql(self.identity, leafOmissionIdentity(self)))
            return error.InvalidLeafOmissionAuthorityV4;
    }

    /// Fail-closed readmission against the four live inputs.
    pub fn validateAgainst(
        self: *const LeafOmissionAuthorityV4,
        profile_identity_sha256: [32]u8,
        frame: *const IncrementalOmissionFrameV4,
        shared_identity: Digest,
        full_statement_authority_id: AuthorityId,
    ) !void {
        try self.validate();
        try frame.validate();
        if (!aggregation_hash.eql(
            self.profile_identity_sha256,
            profile_identity_sha256,
        ) or !aggregation_hash.eql(self.frame_identity, frame.identity) or
            !aggregation_hash.eql(self.shared_identity, shared_identity) or
            !std.meta.eql(
                self.full_statement_authority_id,
                full_statement_authority_id,
            ))
        {
            return error.InvalidLeafOmissionAuthorityV4;
        }
    }

    /// Shard-local prefix frame: domain words, this authority's identity, the
    /// pin identity. Mixed after `appendProviderLocalFrameV2` and before
    /// `finishLocalPrefix`.
    pub fn mixIntoLocalPrefix(
        self: *const LeafOmissionAuthorityV4,
        channel: anytype,
    ) void {
        channel.mixU32s(&local_prefix_domain_words);
        mixDigest(channel, self.identity);
        mixDigest(channel, ProviderOmissionPinsV1.identity());
    }
};

// ---------------------------------------------------------------------------
// Residual
// ---------------------------------------------------------------------------

/// Diagnostic LogUp residual of the omitted-provider core.
///
/// `logup.verifyGlobalCancellation` requires `boundary + sum(claims) == 0`, so
/// with the native Poseidon2 claim absent this returns exactly the value the
/// omitted component would have had to contribute, i.e. `-r` is the omitted
/// native claim and the shard closure must supply it.
pub fn residualIncrementalV4(
    public_sum: QM31,
    projected_canonical_total: QM31,
    extension_claim: *const ethereum_types.ExtensionClaim,
    bridge_claim: QM31,
) QM31 {
    return public_sum
        .add(projected_canonical_total)
        .add(extension_claim.componentSum())
        .add(bridge_claim);
}

// ---------------------------------------------------------------------------
// Digest and transcript helpers
// ---------------------------------------------------------------------------

fn frameIdentity(value: *const IncrementalOmissionFrameV4) Digest {
    var sink = aggregation_hash.HashSink.init(frame_domain);
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.projection_identity) catch unreachable;
    sink.writeAll(&value.pins_identity) catch unreachable;
    const geometry = &value.projected_bridge_geometry;
    aggregation_hash.writeU32(
        &sink,
        geometry.format_version,
    ) catch unreachable;
    aggregation_hash.writeU32(&sink, geometry.n_rows) catch unreachable;
    aggregation_hash.writeU32(&sink, geometry.log_size) catch unreachable;
    writeUsize(&sink, geometry.placement.is_first_col_idx);
    writeUsize(&sink, geometry.placement.is_active_col_idx);
    writeUsize(&sink, geometry.placement.main_col_offset);
    writeUsize(&sink, geometry.placement.interaction_col_offset);
    aggregation_hash.writeU32(
        &sink,
        geometry.total_preprocessed_columns,
    ) catch unreachable;
    aggregation_hash.writeU32(
        &sink,
        geometry.total_main_columns,
    ) catch unreachable;
    aggregation_hash.writeU32(
        &sink,
        geometry.total_interaction_columns,
    ) catch unreachable;
    sink.writeAll(&geometry.identity_sha256) catch unreachable;
    return sink.finalize();
}

fn leafOmissionIdentity(value: *const LeafOmissionAuthorityV4) Digest {
    var sink = aggregation_hash.HashSink.init(leaf_omission_domain);
    aggregation_hash.writeU32(&sink, value.format) catch unreachable;
    sink.writeAll(&value.profile_identity_sha256) catch unreachable;
    sink.writeAll(&value.frame_identity) catch unreachable;
    sink.writeAll(&value.shared_identity) catch unreachable;
    for (value.full_statement_authority_id) |word|
        aggregation_hash.writeU32(&sink, word) catch unreachable;
    return sink.finalize();
}

fn mixDigest(channel: anytype, digest: Digest) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, index|
        word.* = std.mem.readInt(u32, digest[index * 4 ..][0..4], .little);
    channel.mixU32s(&words);
}

fn writeUsize(sink: anytype, value: usize) void {
    aggregation_hash.writeU64(sink, @intCast(value)) catch unreachable;
}

fn addColumns(left: u32, right: u32) !u32 {
    return std.math.add(u32, left, right) catch
        error.IncrementalOmissionColumnOverflowV4;
}

fn requireRemoved(full: anytype, projected: anytype, removed: u32) !void {
    const full_value: u64 = @intCast(full);
    const projected_value: u64 = @intCast(projected);
    if (projected_value > full_value or
        full_value - projected_value != removed)
    {
        return error.InvalidIncrementalOmissionBridgeGeometryV4;
    }
}

fn recoveredPrefix(
    geometry: *const bridge_external.GeometryV3,
) !bridge_external.PrefixColumnsV3 {
    return .{
        .preprocessed = std.math.cast(
            u32,
            geometry.placement.is_first_col_idx,
        ) orelse return error.IncrementalOmissionColumnOverflowV4,
        .main = std.math.cast(
            u32,
            geometry.placement.main_col_offset,
        ) orelse return error.IncrementalOmissionColumnOverflowV4,
        .interaction = std.math.cast(
            u32,
            geometry.placement.interaction_col_offset,
        ) orelse return error.IncrementalOmissionColumnOverflowV4,
    };
}

fn isZeroAuthorityId(value: AuthorityId) bool {
    for (value) |word| {
        if (word != 0) return false;
    }
    return true;
}

const pins_domain =
    "stwo-zig/riscv/ethereum/incremental-omission-pins/v1\x00";
const frame_domain =
    "stwo-zig/riscv/ethereum/incremental-omission-frame/v4\x00";
const leaf_omission_domain =
    "stwo-zig/riscv/ethereum/incremental-leaf-omission/v4\x00";

const frame_domain_words = [4]u32{
    0x5749_5453, // STIW
    0x3456_4d4f, // OMV4
    FORMAT_VERSION,
    @intFromBool(ACTIVATES_PRODUCTION_PROOF),
};

const local_prefix_domain_words = [4]u32{
    0x5749_5453, // STIW
    0x3456_4c50, // PLV4
    FORMAT_VERSION,
    @intFromBool(ACTIVATES_PRODUCTION_PROOF),
};

// ---------------------------------------------------------------------------
// Comptime pins
// ---------------------------------------------------------------------------

comptime {
    if (ACTIVATES_PRODUCTION_PROOF) {
        @compileError(
            "the omitted-provider leaf route requires fresh joint closure " ++
                "activation before it can claim production",
        );
    }
    if (omitted_preprocessed_columns != 2 or
        omitted_main_columns != 445 or
        omitted_interaction_columns != 8)
    {
        @compileError("omitted narrow-memory Poseidon2 geometry drifted");
    }
    if (ProviderOmissionPinsV1.shard_log_size != 18 or
        ProviderOmissionPinsV1.requested_parallel_shards != 18 or
        ProviderOmissionPinsV1.log_blowup_factor != 1 or
        ProviderOmissionPinsV1.retention_policy != .always or
        ProviderOmissionPinsV1.host_byte_budget != 51_539_607_552 or
        ProviderOmissionPinsV1.reserved_host_bytes != 8_589_934_592 or
        ProviderOmissionPinsV1.column_count != 445 or
        ProviderOmissionPinsV1.execution_owners != 18 or
        ProviderOmissionPinsV1.engine_workers_per_owner != 1 or
        ProviderOmissionPinsV1.non_column_reserve_per_owner != 536_870_912)
    {
        @compileError("provider omission pins drifted from the pinned route");
    }
    if (ProviderOmissionPinsV1.reserved_host_bytes >=
        ProviderOmissionPinsV1.host_byte_budget)
    {
        @compileError("provider omission pins reserve the whole host budget");
    }
    // The request must be a pure function of the call count: normalising the
    // row count away must leave two requests byte-identical.
    var probe = ProviderOmissionPinsV1.request(1);
    const other = ProviderOmissionPinsV1.request(1 << 22);
    if (probe.logical_row_count != 1 or other.logical_row_count != 1 << 22)
        @compileError("residency request ignores the provider call count");
    probe.logical_row_count = other.logical_row_count;
    if (!std.meta.eql(probe, other)) {
        @compileError(
            "residency request depends on something other than the call count",
        );
    }
}
