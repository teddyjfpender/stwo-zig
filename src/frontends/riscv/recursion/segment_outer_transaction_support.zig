const std = @import("std");
const stwo_core = @import("stwo_core");
const verified_publication = @import("segment_verified_publication.zig");
const verified_artifact = @import("segment_verified_artifact.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const recursion = struct {
    const air = struct {
        const segment_outer_adapter_manifest_v2 = @import("air/segment_outer_adapter_manifest.zig");
        const universal_challenges = @import("stwo_riscv_air_lang").framework_universal_challenges;
    };
};
const manifest_mod = recursion.air.segment_outer_adapter_manifest_v2;
const universal = recursion.air.universal_challenges;
const Channel = @import("stwo_riscv_memory").primitives_recursion_poseidon2_channel.Channel;
const OuterProofCapture = stwo_core.pcs.verifier.VerifiedProofCapture(
    @import("stwo_riscv_memory").primitives_recursion_poseidon2_channel.MerkleHasher,
);
const VerifiedSegmentV2PublicationV1 = verified_publication.VerifiedSegmentV2PublicationV1;
const RecursiveWitnessV1 = verified_artifact.RecursiveWitnessV1;
const VerifierScheme = stwo_core.pcs.verifier.CommitmentSchemeVerifier(
    @import("stwo_riscv_memory").primitives_recursion_poseidon2_channel.MerkleHasher,
    @import("stwo_riscv_memory").primitives_recursion_poseidon2_channel.MerkleChannel,
);

pub fn rejectTransactionOutputAlias(
    capture_out: *OuterProofCapture,
    publication_out: *VerifiedSegmentV2PublicationV1,
    witness_out: *RecursiveWitnessV1,
) !void {
    if (memoryOverlaps(
        std.mem.asBytes(capture_out),
        std.mem.asBytes(publication_out),
    ) or memoryOverlaps(
        std.mem.asBytes(capture_out),
        std.mem.asBytes(witness_out),
    ) or memoryOverlaps(
        std.mem.asBytes(publication_out),
        std.mem.asBytes(witness_out),
    )) return error.TransactionOutputAlias;
}

pub fn memoryOverlaps(left: []const u8, right: []const u8) bool {
    if (left.len == 0 or right.len == 0) return false;
    const left_start = @intFromPtr(left.ptr);
    const right_start = @intFromPtr(right.ptr);
    const left_end = std.math.add(usize, left_start, left.len) catch return true;
    const right_end = std.math.add(usize, right_start, right.len) catch return true;
    return left_start < right_end and right_start < left_end;
}

pub fn qm31Words(value: QM31) verified_publication.Qm31Words {
    const limbs = value.toM31Array();
    return .{
        limbs[0].toU32(),
        limbs[1].toU32(),
        limbs[2].toU32(),
        limbs[3].toU32(),
    };
}

pub fn relationDraws(
    relations: *const universal.UniversalRelations,
) [universal.DRAW_COUNT]QM31 {
    var result: [universal.DRAW_COUNT]QM31 = undefined;
    for (relations.elements, 0..) |element, index| {
        result[2 * index] = element.z;
        result[2 * index + 1] = element.alpha;
    }
    return result;
}

pub fn allZeroU32(words: []const u32) bool {
    var aggregate: u32 = 0;
    for (words) |word| aggregate |= word;
    return aggregate == 0;
}

pub fn commitVerifierTree(
    allocator: std.mem.Allocator,
    scheme: *VerifierScheme,
    manifest: *const manifest_mod.Manifest,
    tree: usize,
    commitment: @import("stwo_riscv_memory").primitives_recursion_poseidon2_channel.MerkleHasher.Hash,
    channel: *Channel,
) !void {
    const logs = try allocator.alloc(u32, treeColumnCount(manifest, tree));
    defer allocator.free(logs);
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const placement = manifest.placements[row].?;
        const offset = treeOffset(placement, tree);
        const count = treeGeometryColumns(placement.geometry, tree);
        @memset(logs[offset..][0..count], placement.geometry.log_size);
    }
    try scheme.commit(allocator, commitment, logs, channel);
}

pub fn treeColumnCount(manifest: *const manifest_mod.Manifest, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => manifest.total_main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
        else => unreachable,
    };
}

pub fn treeOffset(placement: manifest_mod.Placement, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
        manifest_mod.MAIN_TREE_INDEX => placement.main_offset,
        manifest_mod.INTERACTION_TREE_INDEX => placement.interaction_offset,
        else => unreachable,
    };
}

pub fn treeGeometryColumns(geometry: manifest_mod.Geometry, tree: usize) usize {
    return switch (tree) {
        manifest_mod.PREPROCESSED_TREE_INDEX => geometry.preprocessed_columns,
        manifest_mod.MAIN_TREE_INDEX => geometry.main_columns,
        manifest_mod.INTERACTION_TREE_INDEX => geometry.interaction_columns,
        else => unreachable,
    };
}
