//! Explicit versioned transcript for detached SegmentV2 verification.
//! Structural validation and a caller-supplied independent pin do not establish
//! that a compiler emitted a fixed circuit. Admission policy must additionally
//! establish that Tree0 and all constant/output anchors are statement-independent.
const std = @import("std");
const core = @import("stwo_core");
const recursion = struct {
    const protocol = @import("protocol.zig");
    const fixed_profile = @import("fixed_profile.zig");
    const poseidon2_channel = @import("poseidon2_channel.zig");
    const outer_parent_child_admission = @import("outer_parent_child_admission_profile.zig");
    const segment_leaf_statement_contract_v2 = @import("segment_leaf_statement_contract_v2.zig");
    const detached_segment_admission_v1 = @import("detached_segment_admission_v1.zig");
    const detached_segment_public_inputs_v1 = @import("detached_segment_public_inputs_v1.zig");
    const detached_segment_authority_boundary_v1 = @import("detached_segment_authority_boundary_v1.zig");
    const air = struct {
        const segment_outer_manifest_contract_v2 = @import("air/segment_outer_manifest_contract_v2.zig");
        const verifier_wire_claims = @import("air/verifier_wire_claims.zig");
        const query_bits_profile = @import("air/query_bits_profile.zig");
        const universal_challenges = @import("air/universal_challenges.zig");
    };
};
const air = recursion.air;
const manifest_mod = air.segment_outer_manifest_contract_v2;
const lowering = air.verifier_wire_claims;
const source = recursion.segment_leaf_statement_contract_v2;
const components = recursion.detached_segment_admission_v1;
const public_inputs = recursion.detached_segment_public_inputs_v1;
const authority_boundary = recursion.detached_segment_authority_boundary_v1;
const PublicData = @import("../air/public_data_v2.zig").PublicDataV2;
const QM31 = core.fields.qm31.QM31;
const Digest = recursion.poseidon2_channel.Digest;
pub const VERSION: u32 = 2;
pub const DEVELOPMENT_ONLY = true;
pub const PCS_CONFIG = recursion.outer_parent_child_admission.OUTER_PCS_CONFIG;
pub const INTERACTION_POW_BITS = recursion.outer_parent_child_admission.INTERACTION_POW_BITS;

/// Exact fixed facts consumed by detached verification. Manifest authority IDs
/// are template bookkeeping: only canonical program geometry enters this key
/// identity. No capture, source receipt, observed claim, or call-buffer digest
/// belongs here. Constant terms must come from independently admitted lowering.
pub const ProfileV1 = enum(u8) {
    development_q3_v1 = 1,
    recursive_q193_v1 = 2,

    pub fn pcsConfig(self: ProfileV1) core.pcs.PcsConfig {
        return switch (self) {
            .development_q3_v1 => PCS_CONFIG,
            .recursive_q193_v1 => recursion.protocol.PCS_CONFIG,
        };
    }

    pub fn interactionPowBits(self: ProfileV1) u32 {
        return switch (self) {
            .development_q3_v1 => INTERACTION_POW_BITS,
            .recursive_q193_v1 => recursion.protocol.INTERACTION_POW_BITS,
        };
    }
};

pub const KeyV1 = struct {
    profile: ProfileV1 = .development_q3_v1,
    pcs_config: core.pcs.PcsConfig = PCS_CONFIG,
    version: u32 = VERSION,
    manifest: manifest_mod.Manifest,
    preprocessed_root: Digest,
    parameters: components.AdmissionParametersV1,
    source_manifest: source.ManifestV2,
    admitted_keys: source.VerifierKeyAuthorityV2,
    native_descriptors: authority_boundary.DescriptorsV1,
    wire_terms: []const lowering.PublicWireTerm,

    pub fn identity(self: *const KeyV1) ![32]u8 {
        if (self.version != VERSION) return error.InvalidSegmentDetachedVersion;
        if (!std.meta.eql(self.pcs_config, self.profile.pcsConfig())) return error.InvalidSegmentDetachedProfile;
        if (self.profile == .recursive_q193_v1) {
            for ([_]air.query_bits_profile.LaneProfile{ self.parameters.query_reference.vm, self.parameters.query_reference.recursion }) |lane| {
                if (lane.query_count != recursion.protocol.FRI_QUERY_COUNT or
                    lane.trace_tree_count != recursion.protocol.COMMITMENT_TREE_COUNT or
                    lane.lifting_log_size <= recursion.protocol.FRI_LOG_BLOWUP_FACTOR)
                    return error.DetachedNativeSecurityProfileMismatch;
                const fri = try recursion.fixed_profile.FriSchedule.init(lane.lifting_log_size - recursion.protocol.FRI_LOG_BLOWUP_FACTOR, recursion.protocol.PCS_CONFIG.fri_config);
                if (lane.fri_layer_count != fri.count) return error.DetachedNativeSecurityProfileMismatch;
            }
        }
        _ = try self.parameters.validate(&self.manifest);
        if (try self.native_descriptors.callCount() > (@as(u64, 1) << @intCast(self.manifest.placements[13].?.geometry.log_size)))
            return error.InvalidSegmentDetachedCircuit;
        try self.source_manifest.validate();
        try self.admitted_keys.validate();
        if (self.source_manifest.trace_log_size != self.manifest.placements[36].?.geometry.log_size or
            self.wire_terms.len == 0 or self.wire_terms.len >= core.fields.m31.Modulus or
            std.mem.allEqual(u32, &self.preprocessed_root, 0))
            return error.InvalidSegmentDetachedCircuit;
        for (self.preprocessed_root) |word| if (word >= core.fields.m31.Modulus)
            return error.InvalidSegmentDetachedCircuit;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(switch (self.profile) {
            .development_q3_v1 => "stwo-zig/segment-v2-detached-development-circuit/v2\x00",
            .recursive_q193_v1 => "stwo-zig/segment-v2-detached-q193-circuit/v1\x00",
        });
        for ([_]u32{ VERSION, @intFromEnum(self.profile), manifest_mod.FORMAT_VERSION, manifest_mod.TRANSCRIPT_FORMAT_VERSION, self.profile.interactionPowBits(), self.pcs_config.pow_bits, self.pcs_config.fri_config.log_blowup_factor, self.pcs_config.fri_config.log_last_layer_degree_bound, @intCast(self.pcs_config.fri_config.n_queries), self.pcs_config.fri_config.fold_step }) |word| hashWord(&hash, word);
        hash.update(&manifest_mod.programGeometryShaId(&self.manifest));
        hash.update(&air.universal_challenges.registryOrderDigest());
        for (recursion.protocol.PROTOCOL_ID_WORDS) |word| hashWord(&hash, word);
        for (self.preprocessed_root) |word| hashWord(&hash, word);
        hash.update(&self.parameters.query_reference.authority_digest);
        hashWord(&hash, self.parameters.poseidon_active_rows);
        for (self.source_manifest.identity) |word| hashWord(&hash, word);
        for (self.admitted_keys.identity) |word| hashWord(&hash, word);
        try self.native_descriptors.mixIdentity(&hash);
        hashWord(&hash, @intCast(self.wire_terms.len));
        for (self.wire_terms) |term| {
            if (term.active_in != .segment or term.role == .request or
                term.circuit_id >= core.fields.m31.Modulus or term.node_id >= core.fields.m31.Modulus or
                term.multiplicity == 0 or term.multiplicity >= core.fields.m31.Modulus or
                (term.role == .consume and (!term.value.isZero() or term.multiplicity != 1)))
                return error.InvalidSegmentDetachedCircuit;
            try canonical(term.value);
            for ([_]u32{ term.lane, @intFromEnum(term.active_in), @intFromEnum(term.role), term.circuit_id, term.node_id, term.multiplicity }) |word|
                hashWord(&hash, word);
            for (term.value.toM31Array()) |word| hashWord(&hash, word.toU32());
        }
        return hash.finalResult();
    }

    pub fn validate(self: *const KeyV1) !void {
        _ = try self.identity();
    }

    /// Validate canonical fields against an independently pinned projection.
    /// This value is not an immutable owner or a compiler-policy certificate;
    /// callers must retain admitted key storage with their normal key custody.
    pub fn admit(candidate: KeyV1, independently_pinned_identity: [32]u8) !KeyV1 {
        if (!std.mem.eql(u8, &independently_pinned_identity, &try candidate.identity()))
            return error.SegmentDetachedCircuitPinMismatch;
        return candidate;
    }

    pub fn wireClaim(self: *const KeyV1, relations: *const air.universal_challenges.UniversalRelations) !QM31 {
        try self.validate();
        const challenge = try relations.getExact(.recursion_wire);
        var total = QM31.zero();
        for (self.wire_terms) |term| total = total.add(try lowering.publicTermClaim(challenge, term));
        return total;
    }
};

pub const FixedAdmissionV1 = KeyV1;

/// Optional semantic annotations consumed by the parent AIR schedule builder.
/// These do not alter transcript bytes or admit any payload value as constant.
/// The native and recorded verifier channels intentionally have no callback.
const payload = @import("detached_payload_v1.zig");
pub const PayloadSourceV1 = payload.Source;
const beginPayload = payload.begin;

/// Called after Tree0/Tree1 commitments and before relation draws. The wire
/// uses the existing canonical PublicDataV2 frame; fixed identity has its own
/// explicit version and never includes a source-specific manifest seal.
pub fn mixAdmission(channel: anytype, admission: *const KeyV1, expected: *const PublicData) !void {
    const fixed_identity = try admission.identity();
    _ = try expected.metadata();
    const shape = try source.ManifestV2.init(expected.words().len);
    if (!std.meta.eql(shape, admission.source_manifest)) return error.SegmentV2PublicInputManifestMismatch;
    beginPayload(channel, .admission_header);
    channel.mixU32s(&.{ 0x5344_4131, VERSION, manifest_mod.COMPONENT_COUNT }); // SDA1
    var pin_words: [8]u32 = undefined;
    for (&pin_words, 0..) |*word, index|
        word.* = std.mem.readInt(u32, fixed_identity[index * 4 ..][0..4], .little);
    beginPayload(channel, .key_identity);
    channel.mixU32s(&pin_words);
    beginPayload(channel, .expected);
    try expected.mixInto(channel);
}

/// The profile owns the work threshold and its transcript position. A missing
/// nonce must never silently select the development transcript.
pub const mixInteractionPow = @import("detached_claims_v1.zig").mixInteractionPow;

/// Claims remain untrusted until STARK verification. The two independent
/// checks bind row36 to expected public input and all39 rows to fixed lowering
/// anchors. Neither public boundary is accepted as a supplied scalar.
pub fn mixClaimsAndBoundary(
    channel: anytype,
    admission: *const KeyV1,
    expected: *const PublicData,
    claims: components.ClaimsV1,
    relations: *const air.universal_challenges.UniversalRelations,
) !void {
    const hash_boundary = try authority_boundary.derive(expected, admission.native_descriptors, relations);
    const wire_claim = (try admission.wireClaim(relations)).add(hash_boundary.claimed_sum);
    _ = try claims.vector(&admission.manifest);
    try public_inputs.verifyStatementClaim(expected, &admission.admitted_keys, &admission.source_manifest, relations, claims.values[36]);
    var total = wire_claim;
    for (claims.values) |claim| total = total.add(claim);
    if (!total.isZero()) return error.SegmentDetachedClaimClosureMismatch;
    beginPayload(channel, .claims_header);
    channel.mixU32s(&.{ 0x5344_4331, VERSION, manifest_mod.COMPONENT_COUNT }); // SDC1
    // Roster order is fixed by the admitted canonical manifest. A source-
    // dependent ClaimVector seal is deliberately not a transcript input.
    beginPayload(channel, .claims);
    channel.mixFelts(&claims.values);
    beginPayload(channel, .boundary_header);
    channel.mixU32s(&.{ 0x5344_4231, VERSION, @intCast(admission.wire_terms.len), hash_boundary.term_count, 2 }); // SDB1
    beginPayload(channel, .boundary);
    channel.mixFelts(&.{wire_claim});
    beginPayload(channel, .partials);
    channel.mixFelts(&claims.poseidon_partials);
}

fn canonical(value: QM31) !void {
    for (value.toM31Array()) |word| if (word.toU32() >= core.fields.m31.Modulus)
        return error.InvalidSegmentDetachedCircuit;
}

fn hashWord(hash: anytype, value: u32) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    hash.update(&bytes);
}
