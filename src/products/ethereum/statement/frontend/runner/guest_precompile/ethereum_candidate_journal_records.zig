//! Canonical journal records and capability-bound state transitions.
const std = @import("std");
const registry_mod =
    @import("../../isa/ethereum_candidate_private_registry.zig");
const capability_mod = @import("ethereum_candidate_execution_capability.zig");
const candidate_result = @import("../ethereum_stack_swap_candidate_result.zig");
const result_mod = @import("../../../frontend.zig").runner.result_mod;
const ethereum_capture = @import("../minimal_trace/ethereum_capture.zig");
const ethereum_types = @import("../minimal_trace/ethereum_types.zig");
const validateSegments = @import("ethereum_candidate_journal_chain.zig").validateSegments;
const createUnchecked = @import("ethereum_candidate_journal_chain.zig").createUnchecked;
const claimBoundaryIdentity = @import("ethereum_candidate_journal_identity.zig").claimBoundaryIdentity;
const headerIdentity = @import("ethereum_candidate_journal_identity.zig").headerIdentity;
const segmentIdentity = @import("ethereum_candidate_journal_identity.zig").segmentIdentity;
const summaryIdentity = @import("ethereum_candidate_journal_identity.zig").summaryIdentity;
const accessClockIdentity = @import("ethereum_candidate_journal_identity.zig").accessClockIdentity;
const digestDomainBytes = @import("ethereum_candidate_journal_identity.zig").digestDomainBytes;
const add = @import("ethereum_candidate_journal_identity.zig").add;
const isZero = @import("ethereum_candidate_journal_identity.zig").isZero;
const zero_digest = @import("ethereum_candidate_journal_identity.zig").zero_digest;
const Digest = @import("ethereum_candidate_execution_journal.zig").Digest;
const MemberCapture = @import("ethereum_candidate_execution_journal.zig").MemberCapture;
const captureStackSwapMember = @import("ethereum_candidate_execution_journal.zig").captureStackSwapMember;
const format_version = @import("ethereum_candidate_execution_journal.zig").format_version;
const production_active = @import("ethereum_candidate_execution_journal.zig").production_active;
const proof_or_fresh_verification = @import("ethereum_candidate_execution_journal.zig").proof_or_fresh_verification;
const schema_version = @import("ethereum_candidate_execution_journal.zig").schema_version;

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
