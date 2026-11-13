//! Schema-stable candidate Ethereum execution journal authority.
//!
//! Candidate registry members are represented by an ordered fixed-capacity
//! table. Per-segment captures therefore remain byte-shaped the same when the
//! final guest adds bulk memcpy beside SWAP. This is execution custody only;
//! no field is a proof or fresh-verification receipt.

const std = @import("std");

const registry_mod =
    @import("../../isa/ethereum_candidate_private_registry.zig");
const bulk_authority_mod =
    @import("../../isa/ethereum_bulk_memcpy_candidate.zig");
const bulk_registry = @import("stwo_riscv_isa").bulk_memcpy_private_registry;
const combined_authority_mod =
    @import("../../isa/ethereum_candidate_combined_authority.zig");
const swap_authority_mod =
    @import("../../isa/ethereum_stack_swap_candidate.zig");
const capability_mod = @import("ethereum_candidate_execution_capability.zig");
const combined_result = @import("../ethereum_candidate_combined_result.zig");
const bulk_tape = @import("stwo_riscv_precompiles").runner.bulk_memcpy_session_tape;
const swap_tape = @import("stwo_riscv_precompiles").runner.stack_swap_session_tape;

pub const Digest = [32]u8;
pub const production_active = false;
pub const proof_or_fresh_verification = false;
pub const format_version: u16 = 1;
pub const schema_version: u16 = 1;

pub const CaptureKind = enum(u8) {
    canonical_empty = 0,
    typed_execution_tape = 1,
    canonical_artifact = 2,
    /// Canonical tape bytes were persisted and cold reopened, but no proof or
    /// fresh-verifier receipt exists yet. This value is execution custody only
    /// and is rejected by the candidate Product boundary.
    canonical_execution_artifact = 3,
};

/// Identities are minted by the integration artifact/receipt codec. The
/// frontend validates the raw tape but deliberately does not rehash it under a
/// competing semantic domain.
pub const CanonicalArtifactCustody = struct {
    tape_artifact_identity: Digest,
    joint_receipt_custody_identity: Digest,
    cold_fresh_verified: bool,
    external_base_tables_required: bool,

    pub fn validate(self: CanonicalArtifactCustody) !void {
        if (isZero(self.tape_artifact_identity) or
            isZero(self.joint_receipt_custody_identity) or
            !self.cold_fresh_verified or !self.external_base_tables_required)
        {
            return error.InvalidEthereumCandidateArtifactCustody;
        }
    }
};

/// Typed nonproof custody for the live combined-session bulk tape. The
/// integration artifact codec owns the canonical bytes and supplies its exact
/// cold-reopen identity; this frontend envelope binds that custody to the
/// admitted executable transaction and segment without relabelling it as a
/// proof receipt.
pub const ExecutionArtifactCustody = struct {
    format: u16 = format_version,
    schema: u16 = schema_version,
    capability_identity: Digest,
    admission_receipt_identity: Digest,
    segment_index: u32,
    external_step_origin: u64,
    tape_artifact_identity: Digest,
    cold_reopen_custody_identity: Digest,
    cold_reopened: bool,
    proof_or_fresh_verification: bool,
    identity: Digest,

    pub fn create(
        capability: capability_mod.Capability,
        segment_index: u32,
        external_step_origin: usize,
        tape_artifact_identity: Digest,
        cold_reopen_custody_identity: Digest,
    ) !ExecutionArtifactCustody {
        try capability.validate();
        var result = ExecutionArtifactCustody{
            .capability_identity = capability.identity,
            .admission_receipt_identity = capability.admission_receipt_identity,
            .segment_index = segment_index,
            .external_step_origin = std.math.cast(
                u64,
                external_step_origin,
            ) orelse return error.EthereumCandidateExecutionArtifactOriginOverflow,
            .tape_artifact_identity = tape_artifact_identity,
            .cold_reopen_custody_identity = cold_reopen_custody_identity,
            .cold_reopened = true,
            .proof_or_fresh_verification = false,
            .identity = undefined,
        };
        result.identity = executionArtifactCustodyIdentity(result);
        try result.validateAgainst(
            capability,
            segment_index,
            external_step_origin,
        );
        return result;
    }

    pub fn validateAgainst(
        self: ExecutionArtifactCustody,
        capability: capability_mod.Capability,
        segment_index: u32,
        external_step_origin: usize,
    ) !void {
        try capability.validate();
        const normalized_origin = std.math.cast(
            u64,
            external_step_origin,
        ) orelse return error.EthereumCandidateExecutionArtifactOriginOverflow;
        if (self.format != format_version or self.schema != schema_version or
            capability.executable_class != .combined_candidate or
            !capability.final_candidate_executable or
            !std.mem.eql(
                u8,
                &self.capability_identity,
                &capability.identity,
            ) or !std.mem.eql(
            u8,
            &self.admission_receipt_identity,
            &capability.admission_receipt_identity,
        ) or self.segment_index != segment_index or
            self.external_step_origin != normalized_origin or
            isZero(self.tape_artifact_identity) or
            isZero(self.cold_reopen_custody_identity) or
            !self.cold_reopened or self.proof_or_fresh_verification or
            !std.mem.eql(
                u8,
                &self.identity,
                &executionArtifactCustodyIdentity(self),
            ))
        {
            return error.InvalidEthereumCandidateExecutionArtifactCustody;
        }
    }
};

pub const MemberCapture = struct {
    registry_index: u16,
    kind: registry_mod.MemberKind,
    capture_kind: CaptureKind,
    external_step_origin: u64,
    retirement_count: u32,
    component_witness_row_count: u64,
    tape_identity: Digest,
    capture_custody_identity: Digest,

    pub fn empty(
        registry: registry_mod.Registry,
        registry_index: u16,
        segment_index: u32,
        external_step_origin: u64,
    ) !MemberCapture {
        const member = try memberAt(registry, registry_index);
        var result = MemberCapture{
            .registry_index = registry_index,
            .kind = member.kind,
            .capture_kind = .canonical_empty,
            .external_step_origin = external_step_origin,
            .retirement_count = 0,
            .component_witness_row_count = 0,
            .tape_identity = undefined,
            .capture_custody_identity = undefined,
        };
        result.tape_identity = emptyTapeIdentity(
            registry,
            member,
            segment_index,
            external_step_origin,
        );
        result.capture_custody_identity = result.tape_identity;
        return result;
    }

    pub fn validateAgainst(
        self: MemberCapture,
        registry: registry_mod.Registry,
        segment_index: u32,
    ) !void {
        try registry.validate();
        const member = try memberAt(registry, self.registry_index);
        if (self.kind != member.kind or isZero(self.tape_identity) or
            isZero(self.capture_custody_identity))
            return error.InvalidEthereumCandidateMemberCapture;
        switch (self.capture_kind) {
            .canonical_empty => {
                if (self.retirement_count != 0 or
                    self.component_witness_row_count != 0 or
                    !std.mem.eql(
                        u8,
                        &self.tape_identity,
                        &emptyTapeIdentity(
                            registry,
                            member,
                            segment_index,
                            self.external_step_origin,
                        ),
                    ) or !std.mem.eql(
                    u8,
                    &self.capture_custody_identity,
                    &self.tape_identity,
                )) {
                    return error.InvalidEthereumCandidateEmptyCapture;
                }
            },
            .typed_execution_tape => {
                if (self.retirement_count == 0 or
                    self.component_witness_row_count < self.retirement_count)
                {
                    return error.InvalidEthereumCandidateTypedCapture;
                }
            },
            .canonical_artifact => {
                if (self.retirement_count == 0 or
                    self.component_witness_row_count < self.retirement_count)
                {
                    return error.InvalidEthereumCandidateArtifactCapture;
                }
            },
            .canonical_execution_artifact => {
                if (self.kind != .bulk_memcpy_v1 or
                    self.retirement_count == 0 or
                    self.component_witness_row_count < self.retirement_count)
                {
                    return error.InvalidEthereumCandidateExecutionArtifactCapture;
                }
            },
        }
    }
};

/// Adapt Halley's canonical bulk tape without minting a second tape identity.
/// `custody` comes from the cold-validated artifact/receipt codec.
pub fn captureBulkMemcpyMember(
    registry: registry_mod.Registry,
    segment_index: u32,
    expected_external_step_origin: usize,
    authority: bulk_authority_mod.Authority,
    tape: *const bulk_tape.Frozen,
    custody: CanonicalArtifactCustody,
) !MemberCapture {
    try registry.validate();
    try authority.validate();
    try tape.validate();
    try custody.validate();
    if (tape.externalStepOrigin() != expected_external_step_origin)
        return error.EthereumCandidateBulkCaptureOriginMismatch;
    const member = try registry.member(.bulk_memcpy_v1);
    const descriptor = bulk_registry.memberDescriptor();
    try descriptor.validate();
    if (member.funct7 != authority.bulk_memcpy.allocation.funct7 or
        member.proof_opcode_id != authority.bulk_memcpy.allocation.proof_opcode_id or
        member.fixed_word != authority.bulk_memcpy.fixed_word or
        !std.mem.eql(
            u8,
            &member.semantic_authority_identity,
            &descriptor.semantic_identity,
        ))
    {
        return error.EthereumCandidateBulkRegistryAuthorityMismatch;
    }
    if (tape.rows().len != tape.records().len)
        return error.InvalidEthereumCandidateBulkCapture;
    if (tape.rows().len == 0) return MemberCapture.empty(
        registry,
        0,
        segment_index,
        @intCast(expected_external_step_origin),
    );
    return .{
        .registry_index = 0,
        .kind = .bulk_memcpy_v1,
        .capture_kind = .canonical_artifact,
        .external_step_origin = @intCast(expected_external_step_origin),
        .retirement_count = @intCast(tape.rows().len),
        .component_witness_row_count = @intCast(
            tape.records().len + tape.wordRows().len,
        ),
        .tape_identity = custody.tape_artifact_identity,
        .capture_custody_identity = custody.joint_receipt_custody_identity,
    };
}

/// Capture a nonempty live bulk tape after the integration codec has encoded
/// and cold reopened its canonical bytes. This does not accept or synthesize
/// proof authority and therefore cannot enter `Product` until upgraded.
pub fn captureBulkMemcpyExecutionMember(
    capability: capability_mod.Capability,
    segment_index: u32,
    expected_external_step_origin: usize,
    authority: bulk_authority_mod.Authority,
    tape: *const bulk_tape.Frozen,
    maybe_custody: ?ExecutionArtifactCustody,
) !MemberCapture {
    try capability.validate();
    try authority.validate();
    try tape.validate();
    const combined_authority = capability.combined_candidate_authority orelse
        return error.EthereumCombinedCandidateCapabilityRequired;
    if (!std.meta.eql(capability.registry, combined_authority.registry) or
        !std.meta.eql(authority, combined_authority.bulk_memcpy) or
        tape.externalStepOrigin() != expected_external_step_origin)
    {
        return error.EthereumCandidateBulkCaptureAuthorityMismatch;
    }
    const member = try capability.registry.member(.bulk_memcpy_v1);
    const descriptor = bulk_registry.memberDescriptor();
    try descriptor.validate();
    if (member.funct7 != authority.bulk_memcpy.allocation.funct7 or
        member.proof_opcode_id != authority.bulk_memcpy.allocation.proof_opcode_id or
        member.fixed_word != authority.bulk_memcpy.fixed_word or
        !std.mem.eql(
            u8,
            &member.semantic_authority_identity,
            &descriptor.semantic_identity,
        ) or tape.rows().len != tape.records().len)
    {
        return error.EthereumCandidateBulkRegistryAuthorityMismatch;
    }
    if (tape.rows().len == 0) {
        if (maybe_custody != null)
            return error.UnexpectedEthereumCandidateExecutionArtifactCustody;
        return MemberCapture.empty(
            capability.registry,
            0,
            segment_index,
            @intCast(expected_external_step_origin),
        );
    }
    const custody = maybe_custody orelse
        return error.MissingEthereumCandidateExecutionArtifactCustody;
    try custody.validateAgainst(
        capability,
        segment_index,
        expected_external_step_origin,
    );
    return .{
        .registry_index = 0,
        .kind = .bulk_memcpy_v1,
        .capture_kind = .canonical_execution_artifact,
        .external_step_origin = @intCast(expected_external_step_origin),
        .retirement_count = @intCast(tape.rows().len),
        .component_witness_row_count = @intCast(
            tape.records().len + tape.wordRows().len,
        ),
        .tape_identity = custody.tape_artifact_identity,
        .capture_custody_identity = custody.identity,
    };
}

/// Transactional proof upgrade for the exact execution artifact. A proof
/// receipt for different canonical tape bytes cannot relabel this capture.
pub fn upgradeBulkMemcpyExecutionMember(
    registry: registry_mod.Registry,
    segment_index: u32,
    execution_capture: MemberCapture,
    proof_custody: CanonicalArtifactCustody,
) !MemberCapture {
    try execution_capture.validateAgainst(registry, segment_index);
    try proof_custody.validate();
    if (execution_capture.registry_index != 0 or
        execution_capture.kind != .bulk_memcpy_v1 or
        execution_capture.capture_kind != .canonical_execution_artifact or
        !std.mem.eql(
            u8,
            &execution_capture.tape_identity,
            &proof_custody.tape_artifact_identity,
        ))
    {
        return error.EthereumCandidateExecutionArtifactProofMismatch;
    }
    var result = execution_capture;
    result.capture_kind = .canonical_artifact;
    result.capture_custody_identity = proof_custody.joint_receipt_custody_identity;
    try result.validateAgainst(registry, segment_index);
    return result;
}

/// Adapt the typed SWAP tape under transaction-external receipt custody. The
/// tape owns its exact semantic identity, unlike the bulk artifact codec; the
/// caller still supplies a distinct nonzero custody identity so a self-
/// consistent replacement tape cannot masquerade as an admitted capture.
pub fn captureStackSwapMember(
    registry: registry_mod.Registry,
    segment_index: u32,
    expected_external_step_origin: usize,
    authority: swap_authority_mod.Authority,
    tape: *const swap_tape.Frozen,
    capture_custody_identity: Digest,
) !MemberCapture {
    try registry.validate();
    try authority.validate();
    if (isZero(capture_custody_identity))
        return error.InvalidEthereumCandidateStackSwapCustody;
    try tape.validateAgainst(
        authority.stack_swap,
        expected_external_step_origin,
    );
    const member = try registry.member(.stack_swap_v1);
    if (member.funct7 != authority.stack_swap.allocation.funct7 or
        member.proof_opcode_id != authority.stack_swap.allocation.proof_opcode_id or
        member.fixed_word != authority.stack_swap.fixed_word or
        !std.mem.eql(
            u8,
            &member.semantic_authority_identity,
            &authority.stack_swap.semantic_identity,
        ))
    {
        return error.EthereumCandidateStackSwapRegistryAuthorityMismatch;
    }
    if (tape.rows().len != tape.records().len)
        return error.InvalidEthereumCandidateStackSwapCapture;
    if (tape.rows().len == 0) return MemberCapture.empty(
        registry,
        1,
        segment_index,
        @intCast(expected_external_step_origin),
    );
    return .{
        .registry_index = 1,
        .kind = .stack_swap_v1,
        .capture_kind = .typed_execution_tape,
        .external_step_origin = @intCast(expected_external_step_origin),
        .retirement_count = @intCast(tape.rows().len),
        .component_witness_row_count = @intCast(
            tape.records().len + tape.wordRows().len,
        ),
        .tape_identity = try tape.captureIdentity(),
        .capture_custody_identity = capture_custody_identity,
    };
}

/// Validate Halley's final combined result against transaction-external
/// authority and project both ordered member tapes into the schema-stable
/// journal table. This does not mint a candidate executable capability; the
/// caller must still supply one from a reopened ELF admission receipt before
/// constructing a `Segment`.
pub fn captureCombinedResultMembers(
    registry: registry_mod.Registry,
    segment_index: u32,
    expected_external_step_origin: usize,
    authority: combined_authority_mod.Authority,
    candidate: *const combined_result.SegmentResult,
    bulk_custody: CanonicalArtifactCustody,
    stack_swap_custody_identity: Digest,
) ![registry_mod.max_members]?MemberCapture {
    try registry.validate();
    try authority.validate();
    if (!std.meta.eql(registry, authority.registry) or
        candidate.ethereum.base.segment_index != segment_index)
    {
        return error.EthereumCombinedCandidateJournalAuthorityMismatch;
    }
    try candidate.validateAgainst(authority, expected_external_step_origin);
    var captures: [registry_mod.max_members]?MemberCapture =
        .{null} ** registry_mod.max_members;
    captures[0] = try captureBulkMemcpyMember(
        registry,
        segment_index,
        expected_external_step_origin,
        authority.bulk_memcpy,
        &candidate.bulk_memcpy,
        bulk_custody,
    );
    captures[1] = try captureStackSwapMember(
        registry,
        segment_index,
        expected_external_step_origin,
        authority.stack_swap,
        &candidate.stack_swap,
        stack_swap_custody_identity,
    );
    return captures;
}

/// Execution-only sibling used by the live candidate observer. Every
/// configured combined result is validated, but nonempty bulk custody remains
/// explicitly nonproof until `upgradeBulkMemcpyExecutionMember` succeeds.
pub fn captureCombinedResultExecutionMembers(
    capability: capability_mod.Capability,
    segment_index: u32,
    expected_external_step_origin: usize,
    candidate: *const combined_result.SegmentResult,
    bulk_custody: ?ExecutionArtifactCustody,
    stack_swap_custody_identity: Digest,
) ![registry_mod.max_members]?MemberCapture {
    try capability.validate();
    const authority = capability.combined_candidate_authority orelse
        return error.EthereumCombinedCandidateCapabilityRequired;
    if (!std.meta.eql(capability.registry, authority.registry) or
        candidate.ethereum.base.segment_index != segment_index)
    {
        return error.EthereumCombinedCandidateJournalAuthorityMismatch;
    }
    try candidate.validateAgainst(authority, expected_external_step_origin);
    var captures: [registry_mod.max_members]?MemberCapture =
        .{null} ** registry_mod.max_members;
    captures[0] = try captureBulkMemcpyExecutionMember(
        capability,
        segment_index,
        expected_external_step_origin,
        authority.bulk_memcpy,
        &candidate.bulk_memcpy,
        bulk_custody,
    );
    captures[1] = try captureStackSwapMember(
        capability.registry,
        segment_index,
        expected_external_step_origin,
        authority.stack_swap,
        &candidate.stack_swap,
        stack_swap_custody_identity,
    );
    return captures;
}

pub const Header = @import("ethereum_candidate_journal_records.zig").Header;
pub const Segment = @import("ethereum_candidate_journal_records.zig").Segment;
pub const Summary = @import("ethereum_candidate_journal_records.zig").Summary;
pub const JournalView = @import("ethereum_candidate_journal_records.zig").JournalView;
const memberAt = @import("ethereum_candidate_journal_chain.zig").memberAt;
const emptyTapeIdentity = @import("ethereum_candidate_journal_identity.zig").emptyTapeIdentity;
const executionArtifactCustodyIdentity = @import("ethereum_candidate_journal_identity.zig").executionArtifactCustodyIdentity;
const isZero = @import("ethereum_candidate_journal_identity.zig").isZero;

test {
    _ = @import("ethereum_candidate_journal_test.zig");
}
