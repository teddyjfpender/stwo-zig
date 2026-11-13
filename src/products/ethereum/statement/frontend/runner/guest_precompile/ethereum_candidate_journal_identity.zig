//! Single byte-level journal identity and checked counter authority.
const std = @import("std");
const registry_mod =
    @import("../../isa/ethereum_candidate_private_registry.zig");
const capability_mod = @import("ethereum_candidate_execution_capability.zig");
const result_mod = @import("../../../frontend.zig").runner.result_mod;
const Header = @import("ethereum_candidate_journal_records.zig").Header;
const Segment = @import("ethereum_candidate_journal_records.zig").Segment;
const Summary = @import("ethereum_candidate_journal_records.zig").Summary;
const Digest = @import("ethereum_candidate_execution_journal.zig").Digest;
const ExecutionArtifactCustody = @import("ethereum_candidate_execution_journal.zig").ExecutionArtifactCustody;
const format_version = @import("ethereum_candidate_execution_journal.zig").format_version;
const production_active = @import("ethereum_candidate_execution_journal.zig").production_active;
const proof_or_fresh_verification = @import("ethereum_candidate_execution_journal.zig").proof_or_fresh_verification;
const schema_version = @import("ethereum_candidate_execution_journal.zig").schema_version;

pub fn claimBoundaryIdentity() Digest {
    return digestDomainBytes(
        "stwo.riscv.ethereum-candidate-execution-only-not-proof.v1\x00",
        &.{},
    );
}

pub fn emptyTapeIdentity(
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

pub fn executionArtifactCustodyIdentity(value: ExecutionArtifactCustody) Digest {
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

pub fn headerIdentity(value: Header) Digest {
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

pub fn segmentIdentity(value: Segment) Digest {
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

pub fn summaryIdentity(value: Summary) Digest {
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

pub fn accessClockIdentity(value: result_mod.AccessClockBoundary) Digest {
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

pub fn digestDomainBytes(domain: []const u8, bytes: []const u8) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(domain);
    putInt(&hash, u64, bytes.len);
    hash.update(bytes);
    return hash.finalResult();
}

pub fn putInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

pub fn add(left: u64, right: anytype) !u64 {
    const normalized: u64 = @intCast(right);
    return std.math.add(u64, left, normalized) catch
        error.EthereumCandidateJournalCountOverflow;
}

pub fn isZero(value: Digest) bool {
    return std.mem.allEqual(u8, &value, 0);
}

pub const zero_digest = [_]u8{0} ** 32;

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
