//! Fail-closed coefficient admission for the combined candidate leaf.
//!
//! Ordinary Ethereum admission accounts for Keccak and signer retirements.
//! This deterministic supplement adds bulk-memcpy and U256-SWAP retirements,
//! their word-row memory transitions, and every candidate range-table request.
//! It is verifier-derived from the full statement and candidate profile; no
//! producer-provided counter or digest can replace these field bounds.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;

const table_schema = @import("../../air/lookups/tables/schema.zig");
const statement_v2 = @import("../../air/statement_v2.zig");
const base_statement = @import("../../air/statement.zig");
const bulk_contract = @import("../../air/guest_precompile/bulk_memcpy_component_v1.zig");
const ethereum_statement = @import("../../air/guest_precompile/ethereum_statement.zig");
const swap_contract = @import("../../air/guest_precompile/stack_swap_component_v1.zig");
const swap_words = @import("../../air/guest_precompile/stack_swap_word_candidate_v1.zig");
const statement_validation = @import("../statement_validation.zig");
const profile_mod = @import("ethereum_candidate_leaf_profile_v1.zig");

pub const production_active = false;
pub const format_version: u16 = 1;
pub const fixed_table_count: usize = ethereum_statement.fixed_table_count;

// These counts are derived directly from the caller/word relation schedules.
// Memory coefficients are bounded per relation side: the common validator
// already budgets three accesses for every retirement, while word rows are
// additional non-retirement transitions and contribute two accesses per side.
const bulk_caller_range20: u64 = 3;
const bulk_caller_range8_8: u64 = 16;
const bulk_word_range20: u64 = 2;
const swap_caller_range20: u64 = 2;
const swap_caller_range8_8: u64 = 6;
const swap_word_range20: u64 = 2;
const word_memory_terms_per_side: u64 = 2;

pub const Admission = struct {
    format: u16 = format_version,
    candidate_retirements: u32,
    total_external_retirements: u32,
    candidate_extra_memory_terms: u64,
    total_extra_memory_terms: u64,
    expected_memory_relation_terms: u64,
    extended_fixed_table_bounds: [fixed_table_count]u64,
    production_eligible: bool = false,

    pub fn validateAgainst(
        self: Admission,
        core: *const base_statement.RiscVStatement,
        extension: *const ethereum_statement.Statement,
        base_interaction_columns: u32,
        profile: *const profile_mod.Profile,
    ) !void {
        if (self.format != format_version or self.production_eligible or
            !std.meta.eql(self, try derive(
                core,
                extension,
                base_interaction_columns,
                profile,
            )))
        {
            return error.EthereumCandidateLeafAdmissionMismatch;
        }
    }

    pub fn mixInto(self: Admission, channel: anytype) void {
        channel.mixU32s(&.{
            0x4757_5453, // STWG
            0x3141_4c43, // CLA1
            self.format,
            self.candidate_retirements,
            self.total_external_retirements,
            @intFromBool(self.production_eligible),
        });
        channel.mixU64(self.candidate_extra_memory_terms);
        channel.mixU64(self.total_extra_memory_terms);
        channel.mixU64(self.expected_memory_relation_terms);
        for (self.extended_fixed_table_bounds) |bound| channel.mixU64(bound);
    }

    pub fn retirementSupplementV2(
        self: Admission,
    ) statement_validation.RetirementSupplementV2 {
        return .{
            .rows = self.total_external_retirements,
            .extra_memory_terms = self.total_extra_memory_terms,
            .expected_memory_relation_terms = self.expected_memory_relation_terms,
        };
    }
};

/// V1-shaped fixture admission used only by focused semantic tests. Real leaf
/// proving and verification must call `validateV2` below.
pub fn validate(
    core: *const base_statement.RiscVStatement,
    extension: *const ethereum_statement.Statement,
    base_interaction_columns: u32,
    profile: *const profile_mod.Profile,
    policy: statement_validation.AdmissionPolicy,
) !Admission {
    try extension.validate(core);
    const result = try derive(
        core,
        extension,
        base_interaction_columns,
        profile,
    );
    try result.validateAgainst(
        core,
        extension,
        base_interaction_columns,
        profile,
    );
    try statement_validation.validateWithRetirementSupplementV2(
        core.*,
        policy,
        .{
            .rows = result.total_external_retirements,
            .extra_memory_terms = result.total_extra_memory_terms,
            .expected_memory_relation_terms = result.expected_memory_relation_terms,
        },
    );
    return result;
}

/// Genuine SegmentV2 admission. This authenticates the complete public wire,
/// all four candidate placements/counts, and the exact shared coefficient
/// bounds before any transcript mutation or commitment allocation.
pub fn validateV2(
    native: *const statement_v2.RiscVStatementV2,
    extension: *const ethereum_statement.Statement,
    base_interaction_columns: u32,
    profile: *const profile_mod.Profile,
    policy: statement_validation.AdmissionPolicy,
) !Admission {
    try extension.validateV2(native);
    const result = try derive(
        &native.core,
        extension,
        base_interaction_columns,
        profile,
    );
    try result.validateAgainst(
        &native.core,
        extension,
        base_interaction_columns,
        profile,
    );
    try statement_validation.validateV2WithRetirementSupplementV2(
        native,
        policy,
        .{
            .rows = result.total_external_retirements,
            .extra_memory_terms = result.total_extra_memory_terms,
            .expected_memory_relation_terms = result.expected_memory_relation_terms,
        },
    );
    return result;
}

/// Candidate proof admission separates the full authenticated V2 statement
/// from the provider-projected component layout. Retirement and memory
/// coefficients close against `native`; candidate placements and offsets are
/// derived against `projected_core`. Conflating these geometries either
/// rejects valid provider omission or admits offsets for a tree that is never
/// committed.
pub fn validateProjectedV2(
    native: *const statement_v2.RiscVStatementV2,
    projected_core: *const base_statement.RiscVStatement,
    extension: *const ethereum_statement.Statement,
    base_interaction_columns: u32,
    profile: *const profile_mod.Profile,
    policy: statement_validation.AdmissionPolicy,
) !Admission {
    try extension.validateV2(native);
    const result = try derive(
        projected_core,
        extension,
        base_interaction_columns,
        profile,
    );
    try result.validateAgainst(
        projected_core,
        extension,
        base_interaction_columns,
        profile,
    );
    try statement_validation.validateV2WithRetirementSupplementV2(
        native,
        policy,
        result.retirementSupplementV2(),
    );
    return result;
}

pub fn derive(
    core: *const base_statement.RiscVStatement,
    extension: *const ethereum_statement.Statement,
    base_interaction_columns: u32,
    profile: *const profile_mod.Profile,
) !Admission {
    try profile.validate(core, extension, base_interaction_columns);
    const candidate_retirements = try addU32(
        profile.bulk_memcpy_call_count,
        profile.stack_swap_call_count,
    );
    const total_external = try addU32(
        extension.counts.external_retirements,
        candidate_retirements,
    );
    if (total_external > core.total_steps or total_external >= m31.Modulus)
        return error.EthereumCandidateLeafAdmissionOverflow;

    const swap_word_rows = try mulU64(
        profile.stack_swap_call_count,
        swap_words.lane_count,
    );
    const all_word_rows = try addU64(
        profile.bulk_memcpy_word_row_count,
        swap_word_rows,
    );
    const candidate_extra_memory = try mulU64(
        all_word_rows,
        word_memory_terms_per_side,
    );
    const total_extra_memory = try addU64(
        extension.admission.extra_memory_terms,
        candidate_extra_memory,
    );
    const memory_relation_terms = try addU64(
        extension.admission.memory_relation_terms,
        candidate_extra_memory,
    );
    if (memory_relation_terms >= m31.Modulus)
        return error.EthereumCandidateLeafAdmissionOverflow;

    var bounds = extension.admission.extended_fixed_table_bounds;
    try addDemand(
        &bounds,
        .range_check_20,
        profile.bulk_memcpy_call_count,
        bulk_caller_range20,
    );
    try addDemand(
        &bounds,
        .range_check_8_8,
        profile.bulk_memcpy_call_count,
        bulk_caller_range8_8,
    );
    try addDemand(
        &bounds,
        .range_check_20,
        profile.bulk_memcpy_word_row_count,
        bulk_word_range20,
    );
    try addDemand(
        &bounds,
        .range_check_20,
        profile.stack_swap_call_count,
        swap_caller_range20,
    );
    try addDemand(
        &bounds,
        .range_check_8_8,
        profile.stack_swap_call_count,
        swap_caller_range8_8,
    );
    try addDemand(
        &bounds,
        .range_check_20,
        swap_word_rows,
        swap_word_range20,
    );

    return .{
        .candidate_retirements = candidate_retirements,
        .total_external_retirements = total_external,
        .candidate_extra_memory_terms = candidate_extra_memory,
        .total_extra_memory_terms = total_extra_memory,
        .expected_memory_relation_terms = memory_relation_terms,
        .extended_fixed_table_bounds = bounds,
    };
}

fn addDemand(
    bounds: *[fixed_table_count]u64,
    kind: table_schema.Kind,
    rows: anytype,
    per_row: u64,
) !void {
    const index = @intFromEnum(kind);
    bounds[index] = try addU64(
        bounds[index],
        try mulU64(rows, per_row),
    );
    if (bounds[index] >= m31.Modulus)
        return error.EthereumCandidateLeafAdmissionOverflow;
}

fn addU32(left: u32, right: u32) !u32 {
    return std.math.add(u32, left, right) catch
        error.EthereumCandidateLeafAdmissionOverflow;
}

fn addU64(left: anytype, right: anytype) !u64 {
    return std.math.add(u64, @intCast(left), @intCast(right)) catch
        error.EthereumCandidateLeafAdmissionOverflow;
}

fn mulU64(left: anytype, right: anytype) !u64 {
    return std.math.mul(u64, @intCast(left), @intCast(right)) catch
        error.EthereumCandidateLeafAdmissionOverflow;
}

comptime {
    if (production_active or profile_mod.production_active or
        bulk_contract.production_active or swap_contract.production_active or
        bulk_contract.caller_event_count != 29 or
        bulk_contract.word_event_count != 7 or
        swap_contract.caller_event_count != 17 or
        swap_contract.word_event_count != 7 or
        swap_words.lane_count != 8)
    {
        @compileError("combined Ethereum candidate admission drifted");
    }
}
