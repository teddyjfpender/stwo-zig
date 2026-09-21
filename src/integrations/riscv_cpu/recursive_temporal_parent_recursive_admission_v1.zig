//! Verifier-owned recursive admission for one complete temporal-parent proof.
//!
//! The receipt is constructed only inside the successful native verifier
//! transaction.  It binds the exact 36-row geometry and claims, the channel
//! checkpoint immediately before PCS/FRI verification, both public-boundary
//! authorities, and stable program/VK identities.  The resulting seal is the
//! fixed-wire authority consumed by the next binary recursion layer.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const manifest_mod = @import("recursive_temporal_parent_manifest_v3.zig");
const cohort_contract = @import("recursive_temporal_parent_cohort_contract.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const admission = recursion.outer_parent_child_admission;
const channel = recursion.poseidon2_channel;
const fixed_wire = recursion.fixed_wire;
const universal = recursion.air.universal_challenges;

pub const FORMAT_VERSION: u16 = 1;
pub const SCHEMA_VERSION: u16 = 1;
pub const CLAIM_COUNT: usize = manifest_mod.COMPONENT_COUNT;
pub const POINTER_FREE = true;
pub const HEAP_ALLOCATIONS_PER_PREPARE: usize = 0;

const MANIFEST_ID_DOMAIN: u32 = 0x5452_4d31; // "TRM1"
const AIR_PROGRAM_ID_DOMAIN: u32 = 0x5452_4131; // "TRA1"

pub const Digest = channel.Digest;
pub const StatementWords = recursion.span_statement.StatementWords;
pub const OuterProofCapture = stwo_core.pcs.verifier.VerifiedProofCapture(
    recursion.engine.Hasher,
);

pub const Error = admission.Error || manifest_mod.Error || error{
    AdmissionIdentityMismatch,
    BoundaryAuthorityMismatch,
    InvalidAdmission,
};

pub const PreparedAdmissionV1 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    complete_parent: bool = true,
    padding: [3]u8 = .{ 0, 0, 0 },
    receipt: admission.VerifierReceiptV1,
    seal: admission.VerifierSealV1,
    identity: [32]u8,

    pub fn validateRetained(self: *const PreparedAdmissionV1) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or !self.complete_parent or
            !std.mem.allEqual(u8, &self.padding, 0) or
            self.receipt.scope != .complete_parent)
        {
            return error.InvalidAdmission;
        }
        try self.receipt.validate();
        try self.seal.validate();
        if (!std.mem.eql(u8, &self.identity, &identity(self)))
            return error.AdmissionIdentityMismatch;
    }

    pub fn validateAgainst(
        self: *const PreparedAdmissionV1,
        capture: *const OuterProofCapture,
    ) Error!void {
        try self.validateRetained();
        const expected = try admission.deriveVerifierSeal(&self.receipt, capture);
        if (!std.meta.eql(expected, self.seal)) {
            return error.AdmissionIdentityMismatch;
        }
    }
};

pub fn prepare(
    manifest: *const manifest_mod.Manifest,
    statement_words: *const StatementWords,
    parent_vk_id: Digest,
    claims: *const manifest_mod.ClaimVector,
    audited: *const cohort_contract.AuditedInteractionsV2,
    pre_core_channel: admission.ChannelCheckpointV1,
    capture: *const OuterProofCapture,
) Error!PreparedAdmissionV1 {
    return prepareFromBoundaries(
        manifest,
        statement_words,
        parent_vk_id,
        claims,
        audited.wire_boundary,
        audited.verifier_input_boundary,
        pre_core_channel,
        capture,
    );
}

/// Cohort-neutral verifier seam. Both the first temporal parent and every
/// recursively closed node bind the same two independently audited public
/// boundaries; their context receipt types need not be aliases.
pub fn prepareFromBoundaries(
    manifest: *const manifest_mod.Manifest,
    statement_words: *const StatementWords,
    parent_vk_id: Digest,
    claims: *const manifest_mod.ClaimVector,
    wire_boundary: recursion.binary_global_closure_outer_source.BoundaryEvidenceV2,
    verifier_input_boundary: recursion.binary_global_closure_outer_source.BoundaryEvidenceV2,
    pre_core_channel: admission.ChannelCheckpointV1,
    capture: *const OuterProofCapture,
) Error!PreparedAdmissionV1 {
    try manifest.validate();
    try claims.validate(manifest);
    try pre_core_channel.validate();
    if (wire_boundary.tuple_count == 0 or verifier_input_boundary.tuple_count == 0) {
        return error.BoundaryAuthorityMismatch;
    }

    var component_log_sizes: [CLAIM_COUNT]u32 = undefined;
    for (&component_log_sizes, 0..) |*destination, row| {
        const placement = manifest.placements[row] orelse
            return error.InvalidAdmission;
        destination.* = placement.geometry.log_size;
    }
    var claimed_sums: [CLAIM_COUNT]fixed_wire.Qm31Wire = undefined;
    for (&claimed_sums, claims.values) |*destination, value|
        destination.* = qm31Wire(value);

    const geometry_sha_id = geometryIdentity(manifest);
    const manifest_id = channel.hashBytes(&geometry_sha_id, MANIFEST_ID_DOMAIN);
    const air_program_id = airProgramId(manifest_id);
    const statement_id = statementId(statement_words);
    var result = PreparedAdmissionV1{
        .receipt = .{
            .scope = .complete_parent,
            .air_program_id = air_program_id,
            .manifest_id = manifest_id,
            .statement_id = statement_id,
            .verification_key_id = parent_vk_id,
            .component_log_sizes = component_log_sizes,
            .pre_core_channel = pre_core_channel,
            .claimed_sums = claimed_sums,
            .verifier_input_boundary = qm31Wire(
                verifier_input_boundary.claimed_sum,
            ),
            // V1 has two wire slots.  The temporal-parent closure owns one
            // authenticated aggregate, so the second slot is canonical zero;
            // no fictitious second source is introduced.
            .wire_closure = .{
                qm31Wire(wire_boundary.claimed_sum),
                qm31Wire(QM31.zero()),
            },
        },
        .seal = undefined,
        .identity = undefined,
    };
    result.seal = try admission.deriveVerifierSeal(&result.receipt, capture);
    result.identity = identity(&result);
    try result.validateAgainst(capture);
    return result;
}

fn geometryIdentity(manifest: *const manifest_mod.Manifest) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/recursive-temporal-parent-geometry/v1\x00");
    hashInt(&hash, u16, manifest.format_version);
    hashInt(&hash, u16, manifest.schema_version);
    hashInt(&hash, u8, manifest.roster_count);
    hashInt(&hash, u32, manifest.total_preprocessed_columns);
    hashInt(&hash, u32, manifest.total_main_columns);
    hashInt(&hash, u32, manifest.total_interaction_columns);
    hashInt(&hash, u32, manifest.total_constraints);
    hash.update(&universal.registryOrderDigest());
    for (manifest.roster_rows) |row| {
        const placement = manifest.placements[row].?;
        const geometry = placement.geometry;
        hashInt(&hash, u8, row);
        hashInt(&hash, u32, geometry.log_size);
        hashInt(&hash, u16, geometry.preprocessed_columns);
        hashInt(&hash, u16, geometry.main_columns);
        hashInt(&hash, u16, geometry.interaction_columns);
        hashInt(&hash, u16, geometry.direct_constraints);
        hashInt(&hash, u16, geometry.interaction_batches);
        hashInt(&hash, u8, geometry.protocol_constraint_degree);
        hashInt(&hash, u32, placement.preprocessed_offset);
        hashInt(&hash, u32, placement.main_offset);
        hashInt(&hash, u32, placement.interaction_offset);
        hashInt(&hash, u32, placement.constraint_offset);
        hashInt(&hash, u8, placement.claimed_sum_index);
    }
    return hash.finalResult();
}

fn airProgramId(manifest_id: Digest) Digest {
    var hasher = channel.CanonicalWordHasher.init(AIR_PROGRAM_ID_DOMAIN);
    const header = [_]M31{
        M31.fromCanonical(FORMAT_VERSION),
        M31.fromCanonical(CLAIM_COUNT),
        M31.fromCanonical(manifest_mod.TRANSCRIPT_FORMAT_VERSION),
        M31.fromCanonical(admission.QUERY_COUNT),
        M31.fromCanonical(admission.FOLD_STEP),
    };
    hasher.update(&header);
    hasher.update(&digestWords(recursion.protocol.PROTOCOL_ID_WORDS));
    hasher.update(&digestWords(manifest_id));
    return hasher.finalize();
}

fn statementId(words: *const StatementWords) Digest {
    var canonical: [recursion.span_statement.SPAN_STATEMENT_CANONICAL_WORDS]u32 =
        undefined;
    for (&canonical, words) |*destination, word|
        destination.* = word.toU32();
    return recursion.protocol.statementId(&canonical);
}

fn identity(value: *const PreparedAdmissionV1) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/typed-air/recursive-temporal-parent-admission/v1\x00");
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u8, @intFromBool(value.complete_parent));
    hash.update(&value.padding);
    const receipt = value.receipt;
    hashInt(&hash, u32, receipt.format_version);
    hashInt(&hash, u32, receipt.outer_format_version);
    hashInt(&hash, u32, receipt.outer_transcript_domain);
    hashInt(&hash, u8, @intFromEnum(receipt.scope));
    hashNative(&hash, receipt.air_program_id);
    hashNative(&hash, receipt.manifest_id);
    hashNative(&hash, receipt.statement_id);
    hashNative(&hash, receipt.verification_key_id);
    for (receipt.component_log_sizes) |item| hashInt(&hash, u32, item);
    hashNative(&hash, receipt.pre_core_channel.digest);
    hashInt(&hash, u32, receipt.pre_core_channel.draw_count);
    for (receipt.claimed_sums) |item| hashQm31Wire(&hash, item);
    hashQm31Wire(&hash, receipt.verifier_input_boundary);
    for (receipt.wire_closure) |item| hashQm31Wire(&hash, item);
    hashInt(&hash, u64, receipt.interaction_pow_nonce);
    hashNative(&hash, value.seal.profile_id);
    hashNative(&hash, value.seal.capture_id);
    hashNative(&hash, value.seal.receipt_id);
    hashNative(&hash, value.seal.transcript_id);
    hashNative(&hash, value.seal.claimed_sums_id);
    hashQm31Wire(&hash, value.seal.verifier_input_boundary);
    return hash.finalResult();
}

fn qm31Wire(value: QM31) fixed_wire.Qm31Wire {
    const words = value.toM31Array();
    return .{ words[0].toU32(), words[1].toU32(), words[2].toU32(), words[3].toU32() };
}

fn digestWords(value: Digest) [channel.RATE]M31 {
    var words: [channel.RATE]M31 = undefined;
    for (&words, value) |*destination, item|
        destination.* = M31.fromCanonical(item);
    return words;
}

fn hashNative(hash: anytype, value: Digest) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashQm31Wire(hash: anytype, value: fixed_wire.Qm31Wire) void {
    for (value) |word| hashInt(hash, u32, word);
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

fn assertPointerFree(comptime T: type) void {
    switch (@typeInfo(T)) {
        .pointer => @compileError("temporal recursive admission retains a pointer"),
        .optional => |optional| assertPointerFree(optional.child),
        .array => |array| assertPointerFree(array.child),
        .@"struct" => |info| inline for (info.fields) |field|
            assertPointerFree(field.type),
        .@"union" => |info| inline for (info.fields) |field|
            assertPointerFree(field.type),
        else => {},
    }
}

comptime {
    if (CLAIM_COUNT != admission.CLAIMED_SUM_COUNT or
        HEAP_ALLOCATIONS_PER_PREPARE != 0)
    {
        @compileError("temporal recursive admission profile drifted");
    }
    assertPointerFree(PreparedAdmissionV1);
}
