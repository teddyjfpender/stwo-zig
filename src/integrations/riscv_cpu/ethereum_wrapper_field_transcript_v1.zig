//! Explicit, staged field transcript for an Ethereum outer wrapper.
//! Activation must bind VERSION in the wrapper admission and select these
//! emitters in both native proving and verification. Legacy wrappers keep their
//! original session/claim seals; no existing constructor opts into this profile.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const recursion = frontend.recursion;
const session_mod = @import("recursive_temporal_secure_parent_artifact_v1.zig");
const protocol_mod = @import("recursive_temporal_secure_parent_protocol_v1.zig");
const public = @import("recursive_field_node_public_v2.zig");
const QM31 = core.fields.qm31.QM31;

pub const VERSION: u32 = 1;
pub const AUTHORITY_HEADER = [_]u32{ 0x4546_4131, VERSION, public.AIR_WORD_COUNT }; // EFA1
pub const Error = error{InvalidEthereumFieldTranscriptAdmissionV1};

/// These values must come from an independently admitted cohort/key. This
/// value is a protocol projection, not a certificate of native verification.
pub const AdmissionV1 = struct {
    session: *const session_mod.SessionV1,
    preprocessed_root: recursion.poseidon2_channel.Digest,
    wire_term_count: u32,

    pub fn validate(self: AdmissionV1) !void {
        try self.session.validate();
        try self.session.protocol.requireSecure();
        if (self.session.source_kind != .ethereum_incremental_leaf_wrapper_v4 or
            self.wire_term_count == 0 or self.wire_term_count >= core.fields.m31.Modulus or
            std.mem.allEqual(u32, &self.preprocessed_root, 0))
            return error.InvalidEthereumFieldTranscriptAdmissionV1;
        for (self.preprocessed_root) |word| if (word >= core.fields.m31.Modulus)
            return error.InvalidEthereumFieldTranscriptAdmissionV1;
    }

    pub fn fieldProjection(self: AdmissionV1) !FieldAdmissionV1 {
        try self.validate();
        return .{ .session_fields = try SessionFieldsV1.fromSession(self.session), .preprocessed_root = self.preprocessed_root, .wire_term_count = self.wire_term_count };
    }
};

/// Detached projection of an independently admitted key. Contains no custody
/// session or witness identity; validation alone does not authenticate a key.
pub const FieldAdmissionV1 = struct {
    session_fields: SessionFieldsV1,
    preprocessed_root: recursion.poseidon2_channel.Digest,
    wire_term_count: u32,

    pub fn validate(self: FieldAdmissionV1) !void {
        try self.session_fields.validate();
        if (self.wire_term_count == 0 or self.wire_term_count >= core.fields.m31.Modulus or
            std.mem.allEqual(u32, &self.preprocessed_root, 0)) return error.InvalidEthereumFieldTranscriptAdmissionV1;
        for (self.preprocessed_root) |word| if (word >= core.fields.m31.Modulus)
            return error.InvalidEthereumFieldTranscriptAdmissionV1;
    }
};

/// The semantic session fields in EFS1. Native custody receipts and dynamic
/// parent statements do not belong in a reusable verifier key.
pub const SessionFieldsV1 = struct {
    protocol: protocol_mod.AuthorityV1,
    verification_key_id: recursion.poseidon2_channel.Digest,
    next_parent_vk_id: recursion.poseidon2_channel.Digest,
    air_program_id: recursion.poseidon2_channel.Digest,

    pub fn fromSession(session: *const session_mod.SessionV1) !SessionFieldsV1 {
        try session.validate();
        const fields = SessionFieldsV1{
            .protocol = session.protocol,
            .verification_key_id = session.verification_key_id,
            .next_parent_vk_id = session.next_parent_vk_id,
            .air_program_id = session.air_program_id,
        };
        try fields.validate();
        return fields;
    }

    pub fn validate(self: SessionFieldsV1) !void {
        try self.protocol.requireSecure();
        for ([_]recursion.poseidon2_channel.Digest{ self.verification_key_id, self.next_parent_vk_id, self.air_program_id }) |digest| {
            if (std.mem.allEqual(u32, &digest, 0)) return error.InvalidEthereumFieldTranscriptAdmissionV1;
            for (digest) |word| if (word >= core.fields.m31.Modulus) return error.InvalidEthereumFieldTranscriptAdmissionV1;
        }
    }
};

pub fn sessionHeader(protocol: protocol_mod.AuthorityV1) ![7]u32 {
    try protocol.requireSecure();
    var header = session_mod.sessionTranscriptHeader(protocol);
    header[0] = 0x4546_5331; // EFS1, version 1; remaining fields retain the shared session/protocol ABI.
    return header;
}

pub fn boundaryHeader(wire_term_count: u32) Error![8]u32 {
    if (wire_term_count == 0 or wire_term_count >= core.fields.m31.Modulus)
        return error.InvalidEthereumFieldTranscriptAdmissionV1;
    const Domain = @TypeOf(@import("recursive_common_ethereum_incremental_leaf_public_statement_boundary_v4.zig").DOMAIN);
    return .{ 0x4546_4231, VERSION, wire_term_count, 0, @intFromEnum(Domain.recursion_wire), @intFromEnum(Domain.recursion_statement_word), public.AIR_WORD_COUNT, 2 }; // EFB1
}

/// The admitted immutable publication is already checked when accepted by the
/// cohort. Validate scalar encoding here before writing any transcript frame.
pub fn mixAuthority(channel: anytype, words: *const [public.AIR_WORD_COUNT]u32) !void {
    for (words) |word| if (word >= core.fields.m31.Modulus)
        return error.InvalidEthereumFieldTranscriptAdmissionV1;
    channel.mixU32s(&AUTHORITY_HEADER);
    channel.mixU32s(words);
}

pub fn mixSession(channel: anytype, admission: AdmissionV1) !void {
    try admission.validate();
    try mixSessionFields(channel, try SessionFieldsV1.fromSession(admission.session));
}

pub fn mixSessionFields(channel: anytype, fields: SessionFieldsV1) !void {
    try fields.validate();
    channel.mixU32s(&try sessionHeader(fields.protocol));
    channel.mixU32s(&fields.verification_key_id);
    channel.mixU32s(&fields.next_parent_vk_id);
    channel.mixU32s(&fields.air_program_id);
}

pub fn mixClaims(channel: anytype, manifest: anytype, claims: anytype) !void {
    try claims.mixInteractionClaimValues(manifest, channel);
}

/// Public-statement cancellation is derived from the already-mixed 450 words
/// and relation challenges. The verifier-input boundary is admitted as empty.
/// Neither is an independent scalar claim. The provider's two partials ARE
/// independent inputs and are absorbed in poseidon2, poseidon2_io order.
pub fn mixBoundary(channel: anytype, admission: AdmissionV1, audited: anytype, provider_partials: *const [2]QM31) !void {
    try admission.validate();
    try audited.validate();
    if (audited.wire_boundary.tuple_count != admission.wire_term_count or
        audited.verifier_input_boundary.tuple_count != 0 or
        !audited.verifier_input_boundary.claimed_sum.isZero())
        return error.InvalidEthereumFieldTranscriptAdmissionV1;
    try mixBoundaryValues(channel, admission, audited.wire_boundary.claimed_sum, provider_partials);
}

/// Shared encoding for native and detached verification. The caller derives
/// the wire value from admitted constant/output anchors and relation draws.
pub fn mixBoundaryValues(channel: anytype, admission: AdmissionV1, wire_claim: QM31, provider_partials: *const [2]QM31) !void {
    try admission.validate();
    try mixBoundaryFields(channel, admission.wire_term_count, wire_claim, provider_partials);
}

pub fn mixBoundaryFields(channel: anytype, wire_term_count: u32, wire_claim: QM31, provider_partials: *const [2]QM31) !void {
    for ([_]QM31{ wire_claim, provider_partials[0], provider_partials[1] }) |value|
        for (value.toM31Array()) |limb| if (limb.toU32() >= core.fields.m31.Modulus)
            return error.InvalidEthereumFieldTranscriptAdmissionV1;
    channel.mixU32s(&try boundaryHeader(wire_term_count));
    channel.mixFelts(&.{wire_claim});
    channel.mixFelts(provider_partials);
}
