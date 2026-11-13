//! Ordered segment adjacency and checked final summary construction.
const std = @import("std");
const registry_mod =
    @import("../../isa/ethereum_candidate_private_registry.zig");
const capability_mod = @import("ethereum_candidate_execution_capability.zig");
const Header = @import("ethereum_candidate_journal_records.zig").Header;
const Segment = @import("ethereum_candidate_journal_records.zig").Segment;
const Summary = @import("ethereum_candidate_journal_records.zig").Summary;
const summaryIdentity = @import("ethereum_candidate_journal_identity.zig").summaryIdentity;
const add = @import("ethereum_candidate_journal_identity.zig").add;

pub fn validateSegments(
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

pub fn createUnchecked(header: Header, segments: []const Segment) !Summary {
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

pub fn memberAt(registry: registry_mod.Registry, index: u16) !registry_mod.Member {
    if (index >= registry.member_count)
        return error.EthereumCandidateRegistryMemberMissing;
    return registry.members[index] orelse
        error.EthereumCandidateRegistryMemberMissing;
}
