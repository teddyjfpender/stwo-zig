//! Exact no-extrapolation projection for the retained prefix-64 observer run.

const std = @import("std");
const sponge = @import("keccak256_sponge_candidate_v1.zig");

pub const production_active = false;
pub const schema_version: u16 = 1;
pub const Digest = [32]u8;

pub const ProjectionV1 = struct {
    schema: u16,
    first_segment_index: u32,
    segment_count: u32,
    sampled_core_rows: u64,
    native_entry_pc: u32,
    native_symbol_size_bytes: u32,
    native_invocations: u64,
    native_inclusive_core_rows: u64,
    retained_permutation_calls: u64,
    projected_wrapper_external_retirements: u64,
    projected_core_rows_removed: u64,
    projected_net_execution_retirements_removed: u64,
    semantic_call_rows: u64,
    semantic_block_rows: u64,
    no_extrapolation: bool,
    evidence_file_sha256: Digest,
    evidence_content_sha256: Digest,
    execution_journal_sha256: Digest,
    elf_sha256: Digest,
    verifier_program_identity: Digest,
    projection_identity: Digest,

    pub fn validate(self: ProjectionV1) !void {
        if (!std.meta.eql(self, prefix64()))
            return error.InvalidObserverProjection;
    }
};

pub fn prefix64() ProjectionV1 {
    var result = ProjectionV1{
        .schema = schema_version,
        .first_segment_index = 0,
        .segment_count = 64,
        .sampled_core_rows = 268_413_564,
        .native_entry_pc = 0x3908,
        .native_symbol_size_bytes = 0x148,
        .native_invocations = 4_314,
        .native_inclusive_core_rows = 19_658_986,
        .retained_permutation_calls = 21_826,
        .projected_wrapper_external_retirements = 4_314,
        .projected_core_rows_removed = 19_658_986,
        .projected_net_execution_retirements_removed = 19_654_672,
        .semantic_call_rows = 4_314,
        .semantic_block_rows = 21_826,
        .no_extrapolation = true,
        .evidence_file_sha256 = digest(
            "1a7a7c5393e708fec4c68649094f47506c69f0399124f9aef6ac88e3f283b89d",
        ),
        .evidence_content_sha256 = digest(
            "8a82ac8f434f701f502029f47c80de3110c6dd0023b21e47b0e589425bb249c9",
        ),
        .execution_journal_sha256 = digest(
            "8316cb34b4573f234db76b8f0dcf54ec852a54688f8b68d2a9ffa4dfd25f240e",
        ),
        .elf_sha256 = digest(
            "b751305c0e350918a4a1e692fcfd620a54f5bce6c50322230e156faca95328fa",
        ),
        .verifier_program_identity = sponge.verifierProgramIdentity(),
        .projection_identity = undefined,
    };
    result.projection_identity = identity(result);
    return result;
}

fn identity(value: ProjectionV1) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo.riscv.keccak256-sponge-observer-projection.v1\x00");
    hashInt(&hash, value.schema);
    hashInt(&hash, value.first_segment_index);
    hashInt(&hash, value.segment_count);
    hashInt(&hash, value.sampled_core_rows);
    hashInt(&hash, value.native_entry_pc);
    hashInt(&hash, value.native_symbol_size_bytes);
    hashInt(&hash, value.native_invocations);
    hashInt(&hash, value.native_inclusive_core_rows);
    hashInt(&hash, value.retained_permutation_calls);
    hashInt(&hash, value.projected_wrapper_external_retirements);
    hashInt(&hash, value.projected_core_rows_removed);
    hashInt(&hash, value.projected_net_execution_retirements_removed);
    hashInt(&hash, value.semantic_call_rows);
    hashInt(&hash, value.semantic_block_rows);
    hashInt(&hash, @intFromBool(value.no_extrapolation));
    hash.update(&value.evidence_file_sha256);
    hash.update(&value.evidence_content_sha256);
    hash.update(&value.execution_journal_sha256);
    hash.update(&value.elf_sha256);
    hash.update(&value.verifier_program_identity);
    var result: Digest = undefined;
    hash.final(&result);
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
    if (production_active) @compileError("observer projection is nonproduction");
}
