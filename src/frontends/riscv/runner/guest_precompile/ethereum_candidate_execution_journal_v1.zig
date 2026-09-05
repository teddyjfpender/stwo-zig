//! Schema-stable candidate Ethereum execution journal authority.
//!
//! Candidate registry members are represented by an ordered fixed-capacity
//! table. Per-segment captures therefore remain byte-shaped the same when the
//! final guest adds bulk memcpy beside SWAP. This is execution custody only;
//! no field is a proof or fresh-verification receipt.

const std = @import("std");

const registry_mod =
    @import("../../isa/ethereum_candidate_private_registry_v1.zig");
const bulk_authority_mod =
    @import("../../isa/ethereum_bulk_memcpy_candidate_v1.zig");
const bulk_registry = @import("../../isa/bulk_memcpy_private_registry_v1.zig");
const combined_authority_mod =
    @import("../../isa/ethereum_candidate_combined_authority_v1.zig");
const swap_authority_mod =
    @import("../../isa/ethereum_stack_swap_candidate_v1.zig");
const capability_mod = @import("ethereum_candidate_execution_capability_v1.zig");
const combined_result = @import("../ethereum_candidate_combined_result_v1.zig");
const candidate_result = @import("../ethereum_stack_swap_candidate_result_v1.zig");
const bulk_tape = @import("bulk_memcpy_session_tape_v1.zig");
const swap_tape = @import("stack_swap_session_tape_v1.zig");
const result_mod = @import("../result.zig");
const ethereum_capture = @import("../minimal_trace/ethereum_capture.zig");
const ethereum_types = @import("../minimal_trace/ethereum_types.zig");

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

pub const Header = struct {
    format: u16 = format_version,
    schema: u16 = schema_version,
    claim_boundary: Digest,
    capability_identity: Digest,
    registry_identity: Digest,
    registry_member_count: u16,
    guest_elf_sha256: Digest,
    program_commitment_identity: Digest,
    program_root: u32,
    input_identity: Digest,
    session_identity: Digest,
    segment_step_budget: u64,
    clock_frame: result_mod.SegmentClockFrame,
    identity: Digest,

    pub fn create(
        capability: capability_mod.Capability,
        input_identity: Digest,
        session_identity: Digest,
        segment_step_budget: u64,
        clock_frame: result_mod.SegmentClockFrame,
    ) !Header {
        try capability.validate();
        if (isZero(input_identity) or isZero(session_identity) or
            segment_step_budget == 0)
        {
            return error.InvalidEthereumCandidateJournalHeader;
        }
        var result = Header{
            .claim_boundary = claimBoundaryIdentity(),
            .capability_identity = capability.identity,
            .registry_identity = capability.registry.identity,
            .registry_member_count = capability.registry.member_count,
            .guest_elf_sha256 = capability.guest_elf_sha256,
            .program_commitment_identity = capability.program_commitment_identity,
            .program_root = capability.program_root,
            .input_identity = input_identity,
            .session_identity = session_identity,
            .segment_step_budget = segment_step_budget,
            .clock_frame = clock_frame,
            .identity = undefined,
        };
        result.identity = headerIdentity(result);
        try result.validateAgainst(capability);
        return result;
    }

    pub fn validateAgainst(
        self: Header,
        capability: capability_mod.Capability,
    ) !void {
        try capability.validate();
        if (production_active or proof_or_fresh_verification or
            self.format != format_version or self.schema != schema_version or
            !std.mem.eql(u8, &self.claim_boundary, &claimBoundaryIdentity()) or
            !std.mem.eql(u8, &self.capability_identity, &capability.identity) or
            !std.mem.eql(u8, &self.registry_identity, &capability.registry.identity) or
            self.registry_member_count != capability.registry.member_count or
            !std.mem.eql(u8, &self.guest_elf_sha256, &capability.guest_elf_sha256) or
            !std.mem.eql(
                u8,
                &self.program_commitment_identity,
                &capability.program_commitment_identity,
            ) or self.program_root != capability.program_root or
            isZero(self.input_identity) or isZero(self.session_identity) or
            self.segment_step_budget == 0 or
            !std.mem.eql(u8, &self.identity, &headerIdentity(self)))
        {
            return error.InvalidEthereumCandidateJournalHeader;
        }
    }
};

pub const Segment = struct {
    format: u16 = format_version,
    schema: u16 = schema_version,
    header_identity: Digest,
    previous_record_identity: Digest,
    base_segment_capture_identity: Digest,
    segment_index: u32,
    global_first_cycle: u64,
    cycle_count: u32,
    core_trace_row_count: u32,
    base_profile_external_retirement_count: u32,
    is_first: bool,
    is_last: bool,
    entry_cpu_identity: Digest,
    exit_cpu_identity: Digest,
    entry_memory_identity: Digest,
    exit_memory_identity: Digest,
    entry_access_clock_identity: Digest,
    exit_access_clock_identity: Digest,
    member_captures: [registry_mod.max_members]?MemberCapture,
    terminal_output_present: bool,
    terminal_output_identity: Digest,
    identity: Digest,

    pub fn createStackSwapFixture(
        capability: capability_mod.Capability,
        header: Header,
        previous_record_identity: Digest,
        base_segment_capture_identity: Digest,
        expected_external_step_origin: usize,
        candidate: *const candidate_result.SegmentResult,
    ) !Segment {
        try header.validateAgainst(capability);
        try candidate.validateAgainst(
            capability.stack_swap_fixture_authority,
            expected_external_step_origin,
        );
        if (isZero(previous_record_identity) or
            isZero(base_segment_capture_identity))
        {
            return error.InvalidEthereumCandidateSegmentAuthority;
        }
        const base = &candidate.ethereum.base;
        if (base.clock_frame != header.clock_frame)
            return error.EthereumCandidateClockFrameMismatch;
        const cycle_count = std.math.cast(u32, base.cycle_count) orelse
            return error.EthereumCandidateSegmentCycleOverflow;
        const core_count = std.math.cast(
            u32,
            base.execution_trace.rows.items.len,
        ) orelse return error.EthereumCandidateSegmentCycleOverflow;
        const base_external = std.math.add(
            usize,
            candidate.ethereum.keccakf_calls.len(),
            candidate.ethereum.signer_recovery_calls.len(),
        ) catch return error.EthereumCandidateSegmentCycleOverflow;
        const swap_retirements = candidate.stack_swap.rows().len;
        const reconstructed = std.math.add(
            usize,
            core_count,
            base_external,
        ) catch return error.EthereumCandidateSegmentCycleOverflow;
        const reconstructed_with_swap = std.math.add(
            usize,
            reconstructed,
            swap_retirements,
        ) catch return error.EthereumCandidateSegmentCycleOverflow;
        if (reconstructed_with_swap != cycle_count or
            candidate.stack_swap.records().len != swap_retirements)
        {
            return error.EthereumCandidateSegmentCycleMismatch;
        }

        var captures: [registry_mod.max_members]?MemberCapture =
            .{null} ** registry_mod.max_members;
        captures[0] = try MemberCapture.empty(
            capability.registry,
            0,
            base.segment_index,
            @intCast(expected_external_step_origin),
        );
        captures[1] = try captureStackSwapMember(
            capability.registry,
            base.segment_index,
            expected_external_step_origin,
            capability.stack_swap_fixture_authority,
            &candidate.stack_swap,
            capability.identity,
        );

        return createFromValidatedMemberCaptures(
            capability,
            header,
            previous_record_identity,
            base_segment_capture_identity,
            &candidate.ethereum,
            captures,
        );
    }

    /// Shared final-candidate seam. The combined session supplies one exact
    /// base Ethereum result and one validated capture per registry member.
    /// This function knows no concrete dispatcher or provider strategy.
    pub fn createFromValidatedMemberCaptures(
        capability: capability_mod.Capability,
        header: Header,
        previous_record_identity: Digest,
        base_segment_capture_identity: Digest,
        ethereum: *const result_mod.EthereumSegmentResult,
        captures: [registry_mod.max_members]?MemberCapture,
    ) !Segment {
        try header.validateAgainst(capability);
        if (isZero(previous_record_identity) or
            isZero(base_segment_capture_identity) or
            ethereum.base.clock_frame != header.clock_frame)
        {
            return error.InvalidEthereumCandidateSegmentAuthority;
        }
        const base = &ethereum.base;
        const cycle_count = std.math.cast(u32, base.cycle_count) orelse
            return error.EthereumCandidateSegmentCycleOverflow;
        const core_count = std.math.cast(
            u32,
            base.execution_trace.rows.items.len,
        ) orelse return error.EthereumCandidateSegmentCycleOverflow;
        const base_external = std.math.add(
            usize,
            ethereum.keccakf_calls.len(),
            ethereum.signer_recovery_calls.len(),
        ) catch return error.EthereumCandidateSegmentCycleOverflow;
        var candidate_external: u64 = 0;
        var expected_origin: ?u64 = null;
        for (captures[0..header.registry_member_count], 0..) |maybe_capture, index| {
            const capture = maybe_capture orelse
                return error.InvalidEthereumCandidateMemberCapture;
            if (capture.registry_index != index)
                return error.InvalidEthereumCandidateMemberCapture;
            try capture.validateAgainst(capability.registry, base.segment_index);
            if (expected_origin) |origin| {
                if (capture.external_step_origin != origin)
                    return error.EthereumCandidateMemberCaptureOriginMismatch;
            } else expected_origin = capture.external_step_origin;
            candidate_external = try add(
                candidate_external,
                capture.retirement_count,
            );
        }
        for (captures[header.registry_member_count..]) |capture|
            if (capture != null) return error.InvalidEthereumCandidateMemberCapture;
        const reconstructed = try add(core_count, base_external);
        const reconstructed_total = try add(reconstructed, candidate_external);
        if (reconstructed_total != cycle_count)
            return error.EthereumCandidateSegmentCycleMismatch;

        const output_identity = if (base.output) |output|
            digestDomainBytes(
                "stwo.riscv.ethereum-candidate-terminal-output.v1\x00",
                output,
            )
        else
            zero_digest;
        var result = Segment{
            .header_identity = header.identity,
            .previous_record_identity = previous_record_identity,
            .base_segment_capture_identity = base_segment_capture_identity,
            .segment_index = base.segment_index,
            .global_first_cycle = base.global_first_cycle,
            .cycle_count = cycle_count,
            .core_trace_row_count = core_count,
            .base_profile_external_retirement_count = @intCast(base_external),
            .is_first = base.segment_role.is_first,
            .is_last = base.segment_role.is_last,
            .entry_cpu_identity = ethereum_types.cpuIdentity(base.entry_cpu),
            .exit_cpu_identity = ethereum_types.cpuIdentity(base.exit_cpu),
            .entry_memory_identity = ethereum_capture.snapshotIdentity(
                base.rw_memory,
                .entry,
            ),
            .exit_memory_identity = ethereum_capture.snapshotIdentity(
                base.rw_memory,
                .exit,
            ),
            .entry_access_clock_identity = accessClockIdentity(
                base.entry_access_clocks,
            ),
            .exit_access_clock_identity = accessClockIdentity(
                base.exit_access_clocks,
            ),
            .member_captures = captures,
            .terminal_output_present = base.output != null,
            .terminal_output_identity = output_identity,
            .identity = undefined,
        };
        result.identity = segmentIdentity(result);
        try result.validateAgainst(capability, header);
        return result;
    }

    pub fn validateAgainst(
        self: Segment,
        capability: capability_mod.Capability,
        header: Header,
    ) !void {
        try header.validateAgainst(capability);
        if (self.format != format_version or self.schema != schema_version or
            !std.mem.eql(u8, &self.header_identity, &header.identity) or
            isZero(self.previous_record_identity) or
            isZero(self.base_segment_capture_identity) or
            self.global_first_cycle == 0 or self.cycle_count == 0 or
            self.core_trace_row_count > self.cycle_count or
            self.is_first != (self.segment_index == 0) or
            self.terminal_output_present != !isZero(self.terminal_output_identity))
        {
            return error.InvalidEthereumCandidateJournalSegment;
        }
        _ = std.math.add(
            u64,
            self.global_first_cycle - 1,
            self.cycle_count,
        ) catch return error.InvalidEthereumCandidateJournalSegment;
        var candidate_retirements: u64 = 0;
        for (self.member_captures[0..header.registry_member_count], 0..) |maybe_capture, index| {
            const capture = maybe_capture orelse
                return error.InvalidEthereumCandidateMemberCapture;
            if (capture.registry_index != index)
                return error.InvalidEthereumCandidateMemberCapture;
            try capture.validateAgainst(
                capability.registry,
                self.segment_index,
            );
            candidate_retirements = std.math.add(
                u64,
                candidate_retirements,
                capture.retirement_count,
            ) catch return error.EthereumCandidateSegmentCycleOverflow;
        }
        for (self.member_captures[header.registry_member_count..]) |capture|
            if (capture != null) return error.InvalidEthereumCandidateMemberCapture;
        const reconstructed = std.math.add(
            u64,
            self.core_trace_row_count,
            self.base_profile_external_retirement_count,
        ) catch return error.EthereumCandidateSegmentCycleOverflow;
        const total = std.math.add(
            u64,
            reconstructed,
            candidate_retirements,
        ) catch return error.EthereumCandidateSegmentCycleOverflow;
        if (total != self.cycle_count or
            !std.mem.eql(u8, &self.identity, &segmentIdentity(self)))
        {
            return error.InvalidEthereumCandidateJournalSegment;
        }
    }
};

pub const Summary = struct {
    format: u16 = format_version,
    schema: u16 = schema_version,
    header_identity: Digest,
    previous_record_identity: Digest,
    completed: bool,
    segment_count: u32,
    total_cycles: u64,
    total_core_trace_rows: u64,
    total_base_profile_external_retirements: u64,
    member_retirement_totals: [registry_mod.max_members]u64,
    member_witness_row_totals: [registry_mod.max_members]u64,
    final_cpu_identity: Digest,
    final_memory_identity: Digest,
    terminal_output_present: bool,
    terminal_output_identity: Digest,
    identity: Digest,

    pub fn create(
        capability: capability_mod.Capability,
        header: Header,
        segments: []const Segment,
    ) !Summary {
        try validateSegments(capability, header, segments);
        const last = segments[segments.len - 1];
        var retirements = [_]u64{0} ** registry_mod.max_members;
        var witness_rows = [_]u64{0} ** registry_mod.max_members;
        var total_cycles: u64 = 0;
        var total_core: u64 = 0;
        var total_base_external: u64 = 0;
        for (segments) |segment| {
            total_cycles = try add(total_cycles, segment.cycle_count);
            total_core = try add(total_core, segment.core_trace_row_count);
            total_base_external = try add(
                total_base_external,
                segment.base_profile_external_retirement_count,
            );
            for (segment.member_captures[0..header.registry_member_count], 0..) |capture, index| {
                retirements[index] = try add(
                    retirements[index],
                    capture.?.retirement_count,
                );
                witness_rows[index] = try add(
                    witness_rows[index],
                    capture.?.component_witness_row_count,
                );
            }
        }
        var result = Summary{
            .header_identity = header.identity,
            .previous_record_identity = last.identity,
            .completed = true,
            .segment_count = @intCast(segments.len),
            .total_cycles = total_cycles,
            .total_core_trace_rows = total_core,
            .total_base_profile_external_retirements = total_base_external,
            .member_retirement_totals = retirements,
            .member_witness_row_totals = witness_rows,
            .final_cpu_identity = last.exit_cpu_identity,
            .final_memory_identity = last.exit_memory_identity,
            .terminal_output_present = last.terminal_output_present,
            .terminal_output_identity = last.terminal_output_identity,
            .identity = undefined,
        };
        result.identity = summaryIdentity(result);
        try result.validateAgainst(capability, header, segments);
        return result;
    }

    pub fn validateAgainst(
        self: Summary,
        capability: capability_mod.Capability,
        header: Header,
        segments: []const Segment,
    ) !void {
        try validateSegments(capability, header, segments);
        const expected = try createUnchecked(header, segments);
        if (!std.meta.eql(self, expected))
            return error.InvalidEthereumCandidateJournalSummary;
    }
};

pub const JournalView = struct {
    header: Header,
    segments: []const Segment,
    summary: Summary,

    pub fn validateAgainst(
        self: JournalView,
        capability: capability_mod.Capability,
    ) !void {
        try self.header.validateAgainst(capability);
        try self.summary.validateAgainst(
            capability,
            self.header,
            self.segments,
        );
    }

    pub fn identity(
        self: JournalView,
        capability: capability_mod.Capability,
    ) !Digest {
        try self.validateAgainst(capability);
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo.riscv.ethereum-candidate-execution-journal.v1\x00");
        hash.update(&self.header.identity);
        for (self.segments) |segment| hash.update(&segment.identity);
        hash.update(&self.summary.identity);
        return hash.finalResult();
    }

    /// Product construction requires genuine fresh proof custody for every
    /// nonempty bulk member. The live execution-only artifact remains useful
    /// for persistence/replay but cannot cross this boundary.
    pub fn requireCanonicalBulkArtifactCustody(
        self: JournalView,
        capability: capability_mod.Capability,
    ) !void {
        try self.validateAgainst(capability);
        for (self.segments) |segment| {
            for (segment.member_captures[0..self.header.registry_member_count]) |capture| {
                const value = capture.?;
                if (value.kind == .bulk_memcpy_v1 and
                    value.retirement_count != 0 and
                    value.capture_kind != .canonical_artifact)
                {
                    return error.EthereumCandidateBulkProofCustodyRequired;
                }
            }
        }
    }
};

fn validateSegments(
    capability: capability_mod.Capability,
    header: Header,
    segments: []const Segment,
) !void {
    try header.validateAgainst(capability);
    if (segments.len == 0 or segments.len > std.math.maxInt(u32))
        return error.InvalidEthereumCandidateJournalSegments;
    var expected_previous = header.identity;
    var expected_cycle: u64 = 1;
    for (segments, 0..) |segment, index| {
        try segment.validateAgainst(capability, header);
        if (segment.segment_index != index or
            segment.global_first_cycle != expected_cycle or
            !std.mem.eql(
                u8,
                &segment.previous_record_identity,
                &expected_previous,
            ) or segment.is_last != (index + 1 == segments.len))
        {
            return error.InvalidEthereumCandidateJournalAdjacency;
        }
        if (index != 0) {
            const previous = segments[index - 1];
            if (!std.mem.eql(
                u8,
                &segment.entry_cpu_identity,
                &previous.exit_cpu_identity,
            ) or !std.mem.eql(
                u8,
                &segment.entry_memory_identity,
                &previous.exit_memory_identity,
            )) {
                return error.InvalidEthereumCandidateJournalBoundary;
            }
        }
        expected_cycle = try add(expected_cycle, segment.cycle_count);
        expected_previous = segment.identity;
    }
}

fn createUnchecked(header: Header, segments: []const Segment) !Summary {
    const last = segments[segments.len - 1];
    var retirements = [_]u64{0} ** registry_mod.max_members;
    var witness_rows = [_]u64{0} ** registry_mod.max_members;
    var total_cycles: u64 = 0;
    var total_core: u64 = 0;
    var total_base_external: u64 = 0;
    for (segments) |segment| {
        total_cycles = try add(total_cycles, segment.cycle_count);
        total_core = try add(total_core, segment.core_trace_row_count);
        total_base_external = try add(
            total_base_external,
            segment.base_profile_external_retirement_count,
        );
        for (segment.member_captures[0..header.registry_member_count], 0..) |capture, index| {
            retirements[index] = try add(retirements[index], capture.?.retirement_count);
            witness_rows[index] = try add(
                witness_rows[index],
                capture.?.component_witness_row_count,
            );
        }
    }
    var result = Summary{
        .header_identity = header.identity,
        .previous_record_identity = last.identity,
        .completed = true,
        .segment_count = @intCast(segments.len),
        .total_cycles = total_cycles,
        .total_core_trace_rows = total_core,
        .total_base_profile_external_retirements = total_base_external,
        .member_retirement_totals = retirements,
        .member_witness_row_totals = witness_rows,
        .final_cpu_identity = last.exit_cpu_identity,
        .final_memory_identity = last.exit_memory_identity,
        .terminal_output_present = last.terminal_output_present,
        .terminal_output_identity = last.terminal_output_identity,
        .identity = undefined,
    };
    result.identity = summaryIdentity(result);
    return result;
}

fn memberAt(registry: registry_mod.Registry, index: u16) !registry_mod.Member {
    if (index >= registry.member_count)
        return error.EthereumCandidateRegistryMemberMissing;
    return registry.members[index] orelse
        error.EthereumCandidateRegistryMemberMissing;
}

fn claimBoundaryIdentity() Digest {
    return digestDomainBytes(
        "stwo.riscv.ethereum-candidate-execution-only-not-proof.v1\x00",
        &.{},
    );
}

fn emptyTapeIdentity(
    registry: registry_mod.Registry,
    member: registry_mod.Member,
    segment_index: u32,
    external_step_origin: u64,
) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-candidate-empty-member-capture.v1\x00");
    hash.update(&registry.identity);
    hash.update(&member.identity);
    putInt(&hash, u32, segment_index);
    putInt(&hash, u64, external_step_origin);
    return hash.finalResult();
}

fn executionArtifactCustodyIdentity(value: ExecutionArtifactCustody) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-candidate-execution-artifact-custody.v1\x00");
    putInt(&hash, u16, value.format);
    putInt(&hash, u16, value.schema);
    hash.update(&value.capability_identity);
    hash.update(&value.admission_receipt_identity);
    putInt(&hash, u32, value.segment_index);
    putInt(&hash, u64, value.external_step_origin);
    hash.update(&value.tape_artifact_identity);
    hash.update(&value.cold_reopen_custody_identity);
    hash.update(&.{
        @intFromBool(value.cold_reopened),
        @intFromBool(value.proof_or_fresh_verification),
    });
    return hash.finalResult();
}

fn headerIdentity(value: Header) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-candidate-journal-header.v1\x00");
    putInt(&hash, u16, value.format);
    putInt(&hash, u16, value.schema);
    hash.update(&value.claim_boundary);
    hash.update(&value.capability_identity);
    hash.update(&value.registry_identity);
    putInt(&hash, u16, value.registry_member_count);
    hash.update(&value.guest_elf_sha256);
    hash.update(&value.program_commitment_identity);
    putInt(&hash, u32, value.program_root);
    hash.update(&value.input_identity);
    hash.update(&value.session_identity);
    putInt(&hash, u64, value.segment_step_budget);
    putInt(&hash, u8, @intFromEnum(value.clock_frame));
    return hash.finalResult();
}

fn segmentIdentity(value: Segment) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-candidate-journal-segment.v1\x00");
    putInt(&hash, u16, value.format);
    putInt(&hash, u16, value.schema);
    hash.update(&value.header_identity);
    hash.update(&value.previous_record_identity);
    hash.update(&value.base_segment_capture_identity);
    putInt(&hash, u32, value.segment_index);
    putInt(&hash, u64, value.global_first_cycle);
    putInt(&hash, u32, value.cycle_count);
    putInt(&hash, u32, value.core_trace_row_count);
    putInt(&hash, u32, value.base_profile_external_retirement_count);
    hash.update(&.{ @intFromBool(value.is_first), @intFromBool(value.is_last) });
    inline for (.{
        value.entry_cpu_identity,
        value.exit_cpu_identity,
        value.entry_memory_identity,
        value.exit_memory_identity,
        value.entry_access_clock_identity,
        value.exit_access_clock_identity,
    }) |digest| hash.update(&digest);
    for (value.member_captures) |maybe_capture| {
        if (maybe_capture) |capture| {
            hash.update(&.{1});
            putInt(&hash, u16, capture.registry_index);
            putInt(&hash, u16, @intFromEnum(capture.kind));
            putInt(&hash, u8, @intFromEnum(capture.capture_kind));
            putInt(&hash, u64, capture.external_step_origin);
            putInt(&hash, u32, capture.retirement_count);
            putInt(&hash, u64, capture.component_witness_row_count);
            hash.update(&capture.tape_identity);
            hash.update(&capture.capture_custody_identity);
        } else hash.update(&.{0});
    }
    hash.update(&.{@intFromBool(value.terminal_output_present)});
    hash.update(&value.terminal_output_identity);
    return hash.finalResult();
}

fn summaryIdentity(value: Summary) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-candidate-journal-summary.v1\x00");
    putInt(&hash, u16, value.format);
    putInt(&hash, u16, value.schema);
    hash.update(&value.header_identity);
    hash.update(&value.previous_record_identity);
    hash.update(&.{@intFromBool(value.completed)});
    putInt(&hash, u32, value.segment_count);
    putInt(&hash, u64, value.total_cycles);
    putInt(&hash, u64, value.total_core_trace_rows);
    putInt(&hash, u64, value.total_base_profile_external_retirements);
    for (value.member_retirement_totals) |count| putInt(&hash, u64, count);
    for (value.member_witness_row_totals) |count| putInt(&hash, u64, count);
    hash.update(&value.final_cpu_identity);
    hash.update(&value.final_memory_identity);
    hash.update(&.{@intFromBool(value.terminal_output_present)});
    hash.update(&value.terminal_output_identity);
    return hash.finalResult();
}

fn accessClockIdentity(value: result_mod.AccessClockBoundary) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.ethereum-candidate-access-clock-boundary.v1\x00");
    for (value.register_clocks) |clock| putInt(&hash, u32, clock);
    putInt(&hash, u64, value.memory_clocks.len);
    for (value.memory_clocks) |entry| {
        putInt(&hash, u32, entry.addr);
        putInt(&hash, u32, entry.clock);
    }
    return hash.finalResult();
}

fn digestDomainBytes(domain: []const u8, bytes: []const u8) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(domain);
    putInt(&hash, u64, bytes.len);
    hash.update(bytes);
    return hash.finalResult();
}

fn putInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

fn add(left: u64, right: anytype) !u64 {
    const normalized: u64 = @intCast(right);
    return std.math.add(u64, left, normalized) catch
        error.EthereumCandidateJournalCountOverflow;
}

fn isZero(value: Digest) bool {
    return std.mem.allEqual(u8, &value, 0);
}

const zero_digest = [_]u8{0} ** 32;

comptime {
    if (production_active or proof_or_fresh_verification or
        format_version != 1 or schema_version != 1 or
        registry_mod.max_members != 8 or registry_mod.production_active or
        capability_mod.production_active or
        capability_mod.proof_or_fresh_verification)
    {
        @compileError("Ethereum candidate execution journal became active");
    }
}

test "combined candidate contract v1: journal slots reject tape and custody mutation" {
    const registry = try registry_mod.Registry.canonical();
    const empty_bulk = try MemberCapture.empty(registry, 0, 3, 9);
    try empty_bulk.validateAgainst(registry, 3);

    var relabelled = empty_bulk;
    relabelled.kind = .stack_swap_v1;
    try std.testing.expectError(
        error.InvalidEthereumCandidateMemberCapture,
        relabelled.validateAgainst(registry, 3),
    );
    var changed_tape = empty_bulk;
    changed_tape.tape_identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidEthereumCandidateEmptyCapture,
        changed_tape.validateAgainst(registry, 3),
    );
    var changed_custody = empty_bulk;
    changed_custody.capture_custody_identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidEthereumCandidateEmptyCapture,
        changed_custody.validateAgainst(registry, 3),
    );
}

test "combined candidate contract v1: artifact custody stays external and fail closed" {
    var custody = CanonicalArtifactCustody{
        .tape_artifact_identity = patternedDigest(1),
        .joint_receipt_custody_identity = patternedDigest(2),
        .cold_fresh_verified = true,
        .external_base_tables_required = true,
    };
    try custody.validate();
    custody.cold_fresh_verified = false;
    try std.testing.expectError(
        error.InvalidEthereumCandidateArtifactCustody,
        custody.validate(),
    );
}

test "combined candidate contract v1: execution artifact cannot self-promote" {
    const registry = try registry_mod.Registry.canonical();
    const execution = MemberCapture{
        .registry_index = 0,
        .kind = .bulk_memcpy_v1,
        .capture_kind = .canonical_execution_artifact,
        .external_step_origin = 7,
        .retirement_count = 2,
        .component_witness_row_count = 18,
        .tape_identity = patternedDigest(30),
        .capture_custody_identity = patternedDigest(31),
    };
    try execution.validateAgainst(registry, 4);

    const proof_custody = CanonicalArtifactCustody{
        .tape_artifact_identity = execution.tape_identity,
        .joint_receipt_custody_identity = patternedDigest(32),
        .cold_fresh_verified = true,
        .external_base_tables_required = true,
    };
    const upgraded = try upgradeBulkMemcpyExecutionMember(
        registry,
        4,
        execution,
        proof_custody,
    );
    try std.testing.expectEqual(
        CaptureKind.canonical_artifact,
        upgraded.capture_kind,
    );

    var mismatched = proof_custody;
    mismatched.tape_artifact_identity[0] ^= 1;
    try std.testing.expectError(
        error.EthereumCandidateExecutionArtifactProofMismatch,
        upgradeBulkMemcpyExecutionMember(registry, 4, execution, mismatched),
    );
}

test "combined candidate contract v1: final result projects both ordered member captures" {
    const test_elf = @import("test_elf.zig");
    const segment_session = @import("../segment_session.zig");
    const elf = test_elf.buildEthereumCombinedCandidate();
    var elf_identity: Digest = undefined;
    std.crypto.hash.sha2.Sha256.hash(&elf, &elf_identity, .{});
    const authority = try combined_authority_mod.Authority.create(elf_identity);
    const CandidateSession =
        segment_session.EthereumCombinedCandidateExecutionSessionV1();
    var session = try CandidateSession.initCandidate(
        std.testing.allocator,
        &elf,
        .{},
        authority,
    );
    defer session.deinit();
    var result = try session.startSegment(24);
    defer result.deinit();

    const custody = CanonicalArtifactCustody{
        .tape_artifact_identity = patternedDigest(10),
        .joint_receipt_custody_identity = patternedDigest(11),
        .cold_fresh_verified = true,
        .external_base_tables_required = true,
    };
    const captures = try captureCombinedResultMembers(
        authority.registry,
        result.ethereum.base.segment_index,
        0,
        authority,
        &result,
        custody,
        patternedDigest(12),
    );
    try std.testing.expectEqual(
        registry_mod.MemberKind.bulk_memcpy_v1,
        captures[0].?.kind,
    );
    try std.testing.expectEqual(@as(u32, 1), captures[0].?.retirement_count);
    try std.testing.expectEqual(@as(u64, 9), captures[0].?.component_witness_row_count);
    try std.testing.expectEqual(
        registry_mod.MemberKind.stack_swap_v1,
        captures[1].?.kind,
    );
    try std.testing.expectEqual(@as(u32, 1), captures[1].?.retirement_count);
    try std.testing.expectEqual(@as(u64, 9), captures[1].?.component_witness_row_count);

    try std.testing.expectError(
        error.InvalidEthereumCandidateStackSwapCustody,
        captureCombinedResultMembers(
            authority.registry,
            result.ethereum.base.segment_index,
            0,
            authority,
            &result,
            custody,
            zero_digest,
        ),
    );
}

fn patternedDigest(seed: u8) Digest {
    var result: Digest = undefined;
    for (&result, 0..) |*byte, index| byte.* = seed +% @as(u8, @truncate(index));
    return result;
}
