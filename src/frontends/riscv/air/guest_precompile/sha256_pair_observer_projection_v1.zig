//! Exact retained prefix-64 projection for fixed SHA-256 pair hashing.
//!
//! This is a no-extrapolation diagnostic authority. It separates the 1,385
//! fixed 64-byte pair hashes from the one variable-length request hash, which
//! remains on the software SHA-256 path.

const std = @import("std");
const sha = @import("sha256_pair_candidate_v1.zig");
const direct = @import("sha256_pair_direct_candidate_v1.zig");
const caller = @import("sha256_pair_caller_candidate_v1.zig");
const opcode_geometry = @import("../lang/opcode_composition_manifest.zig");

pub const production_active = false;
pub const schema_version: u16 = 2;
pub const Digest = sha.Digest;

pub const RemovedFamilyRowsV1 = struct {
    family: opcode_geometry.Family,
    rows: u64,
};

/// Exact fixed-pair share of the retained `compress256` PC range. Every PC
/// count was divisible by the 2,771 observed compression calls; these counts
/// remove 2,770 fixed-pair compressions and retain the one variable request.
pub const fixed_pair_rows_by_family = [_]RemovedFamilyRowsV1{
    .{ .family = .base_alu_imm, .rows = 285_310 },
    .{ .family = .base_alu_reg, .rows = 5_875_170 },
    .{ .family = .branch_eq, .rows = 2_770 },
    .{ .family = .jalr, .rows = 2_770 },
    .{ .family = .load_store, .rows = 1_933_460 },
    .{ .family = .lui, .rows = 177_280 },
    .{ .family = .shifts_imm, .rows = 3_592_690 },
};

pub const ProjectionV1 = struct {
    schema: u16,
    first_segment_index: u32,
    segment_count: u32,
    retained_corpus_segment_count: u32,
    sampled_core_rows: u64,
    compression_entry_pc: u32,
    compression_calls: u64,
    rows_per_compression: u64,
    compression_core_rows: u64,
    fixed_pair_calls: u64,
    fixed_pair_compressions: u64,
    fixed_pair_core_rows: u64,
    variable_hash_calls: u64,
    variable_hash_compressions: u64,
    variable_hash_core_rows_kept_software: u64,
    projected_candidate_retirements: u64,
    projected_net_core_rows_removed: u64,
    projected_round_air_rows: u64,
    aggregate_round_air_padded_rows_lower_bound: u64,
    round_air_active_main_cells: u64,
    aggregate_round_air_padded_main_cells_lower_bound: u64,
    removed_typed_logical_main_cells_upper_bound: u64,
    round_air_main_cell_overhead_lower_bound: u64,
    main_cell_reduction: bool,
    caller_component_cells_included: bool,
    interaction_cells_included: bool,
    no_extrapolation: bool,
    variable_hash_stays_software: bool,
    evidence_file_sha256: Digest,
    evidence_content_sha256: Digest,
    observation_content_sha256: Digest,
    observation_transport_sha256: Digest,
    execution_journal_sha256: Digest,
    input_sha256: Digest,
    elf_sha256: Digest,
    observer_executable_sha256: Digest,
    observer_source_sha256: Digest,
    semantic_program_identity: Digest,
    round_air_program_identity: Digest,
    caller_program_identity: Digest,
    projection_identity: Digest,

    pub fn validate(self: ProjectionV1) !void {
        if (!std.meta.eql(self, prefix64()))
            return error.InvalidObserverProjection;
    }
};

pub fn prefix64() ProjectionV1 {
    const active_rows: u64 = 1_385 * direct.rows_per_call;
    const padded_rows = nextPowerOfTwo(active_rows);
    const active_main_cells = active_rows * direct.main_column_count;
    const padded_main_cells = padded_rows * direct.main_column_count;
    const removed_main_cells = removedTypedLogicalMainCells();
    std.debug.assert(padded_main_cells > removed_main_cells);
    var result = ProjectionV1{
        .schema = schema_version,
        .first_segment_index = 0,
        .segment_count = 64,
        .retained_corpus_segment_count = 72,
        .sampled_core_rows = 268_411_310,
        .compression_entry_pc = 0x1f0670,
        .compression_calls = 2_771,
        .rows_per_compression = 4_285,
        .compression_core_rows = 11_873_735,
        .fixed_pair_calls = 1_385,
        .fixed_pair_compressions = 2_770,
        .fixed_pair_core_rows = 11_869_450,
        .variable_hash_calls = 1,
        .variable_hash_compressions = 1,
        .variable_hash_core_rows_kept_software = 4_285,
        .projected_candidate_retirements = 1_385,
        .projected_net_core_rows_removed = 11_868_065,
        .projected_round_air_rows = active_rows,
        .aggregate_round_air_padded_rows_lower_bound = padded_rows,
        .round_air_active_main_cells = active_main_cells,
        .aggregate_round_air_padded_main_cells_lower_bound = padded_main_cells,
        .removed_typed_logical_main_cells_upper_bound = removed_main_cells,
        .round_air_main_cell_overhead_lower_bound = padded_main_cells -
            removed_main_cells,
        .main_cell_reduction = false,
        .caller_component_cells_included = false,
        .interaction_cells_included = false,
        .no_extrapolation = true,
        .variable_hash_stays_software = true,
        .evidence_file_sha256 = digest(
            "c1b815575c0f2714cd60a312795ed07c9e47544dd8b7758b347cd4dcd74af982",
        ),
        .evidence_content_sha256 = digest(
            "9f63c8ca1fd8e599a8600e1bb4fc85860323a60feceaa61d3c9ae563ffc008cb",
        ),
        .observation_content_sha256 = digest(
            "aaadf04b731db70cb98394332cd6362d25bf41d05272efab71b8e80303dae153",
        ),
        .observation_transport_sha256 = digest(
            "c5f991c8632176b2c82f758883f1f4f46dd9214fa36c2d301720acf446d6bc82",
        ),
        .execution_journal_sha256 = digest(
            "54797de1f32c6cb0e2ffd3780eb5893fba2d9722341f01945d049f9367f05c8b",
        ),
        .input_sha256 = digest(
            "faaf02583929396faed177914da27b4a493766993001357bd1720340ca1ddabb",
        ),
        .elf_sha256 = digest(
            "2414c39ed5387531ed94cccc8a3ee90abb30de38ad6d32d05d2df59ce63a647b",
        ),
        .observer_executable_sha256 = digest(
            "8f60f18e1792ddda4ddf1353c40431196920960457cea2c866c300b3ea66e31d",
        ),
        .observer_source_sha256 = digest(
            "8d05a67cda5f89dab02c6e53b9e6b58b3a6ffd5fdfe829e0ba0f1016c2b66f4b",
        ),
        .semantic_program_identity = sha.verifierProgramIdentity(),
        .round_air_program_identity = direct.airProgramIdentity(),
        .caller_program_identity = caller.callerProgramIdentity(),
        .projection_identity = undefined,
    };
    result.projection_identity = identity(result);
    return result;
}

fn identity(value: ProjectionV1) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.sha256-pair-prefix64-projection.v1\x00");
    hashInt(&hash, value.schema);
    hashInt(&hash, value.first_segment_index);
    hashInt(&hash, value.segment_count);
    hashInt(&hash, value.retained_corpus_segment_count);
    hashInt(&hash, value.sampled_core_rows);
    hashInt(&hash, value.compression_entry_pc);
    hashInt(&hash, value.compression_calls);
    hashInt(&hash, value.rows_per_compression);
    hashInt(&hash, value.compression_core_rows);
    hashInt(&hash, value.fixed_pair_calls);
    hashInt(&hash, value.fixed_pair_compressions);
    hashInt(&hash, value.fixed_pair_core_rows);
    hashInt(&hash, value.variable_hash_calls);
    hashInt(&hash, value.variable_hash_compressions);
    hashInt(&hash, value.variable_hash_core_rows_kept_software);
    hashInt(&hash, value.projected_candidate_retirements);
    hashInt(&hash, value.projected_net_core_rows_removed);
    hashInt(&hash, value.projected_round_air_rows);
    hashInt(&hash, value.aggregate_round_air_padded_rows_lower_bound);
    hashInt(&hash, value.round_air_active_main_cells);
    hashInt(&hash, value.aggregate_round_air_padded_main_cells_lower_bound);
    hashInt(&hash, value.removed_typed_logical_main_cells_upper_bound);
    hashInt(&hash, value.round_air_main_cell_overhead_lower_bound);
    hashInt(&hash, @intFromBool(value.main_cell_reduction));
    hashInt(&hash, @intFromBool(value.caller_component_cells_included));
    hashInt(&hash, @intFromBool(value.interaction_cells_included));
    hashInt(&hash, @intFromBool(value.no_extrapolation));
    hashInt(&hash, @intFromBool(value.variable_hash_stays_software));
    hash.update(&value.evidence_file_sha256);
    hash.update(&value.evidence_content_sha256);
    hash.update(&value.observation_content_sha256);
    hash.update(&value.observation_transport_sha256);
    hash.update(&value.execution_journal_sha256);
    hash.update(&value.input_sha256);
    hash.update(&value.elf_sha256);
    hash.update(&value.observer_executable_sha256);
    hash.update(&value.observer_source_sha256);
    hash.update(&value.semantic_program_identity);
    hash.update(&value.round_air_program_identity);
    hash.update(&value.caller_program_identity);
    for (fixed_pair_rows_by_family) |item| {
        hashInt(&hash, @intFromEnum(item.family));
        hashInt(&hash, item.rows);
        hashInt(&hash, opcode_geometry.mainColumnCount(item.family));
    }
    var result: Digest = undefined;
    hash.final(&result);
    return result;
}

pub fn removedTypedLogicalMainCells() u64 {
    var result: u64 = 0;
    for (fixed_pair_rows_by_family) |item| {
        result += item.rows * opcode_geometry.mainColumnCount(item.family);
    }
    return result;
}

fn nextPowerOfTwo(value: u64) u64 {
    std.debug.assert(value != 0);
    var result: u64 = 1;
    while (result < value) result *= 2;
    return result;
}

fn digest(comptime encoded: *const [64:0]u8) Digest {
    var result: Digest = undefined;
    _ = std.fmt.hexToBytes(&result, encoded) catch unreachable;
    return result;
}

fn hashInt(hash: anytype, value: anytype) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    var removed_rows: u64 = 0;
    for (fixed_pair_rows_by_family) |item| removed_rows += item.rows;
    if (production_active or removed_rows != 11_869_450 or
        removedTypedLogicalMainCells() != 498_904_700)
    {
        @compileError("SHA-256 pair projection geometry drifted");
    }
}
