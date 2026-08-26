const std = @import("std");
const stwo_core = @import("stwo_core");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
const binary_verified_publication = @import("recursive_binary_verified_publication.zig");
const verified_publication = @import("recursive_segment_v2_verified_publication.zig");
const verified_artifact = @import("recursive_segment_v2_verified_artifact.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const recursion = frontend.recursion;
const manifest_mod = recursion.air.segment_outer_adapter_manifest_v2;
const universal = recursion.air.universal_challenges;
const Engine = recursion.engine.ProverEngineForBackend(CpuBackend);
const OuterProofCapture = stwo_core.pcs.verifier.VerifiedProofCapture(
    recursion.engine.Hasher,
);
const VerifiedSegmentV2PublicationV1 = verified_publication.VerifiedSegmentV2PublicationV1;
const RecursiveWitnessV1 = verified_artifact.RecursiveWitnessV1;
const VerifierScheme = stwo_core.pcs.verifier.CommitmentSchemeVerifier(
    recursion.engine.Hasher,
    recursion.engine.MerkleChannel,
);

pub const ProofLengthWriter = struct {
    byte_count: usize = 0,

    pub fn write(self: *ProofLengthWriter, bytes: []const u8) !usize {
        self.byte_count = try std.math.add(
            usize,
            self.byte_count,
            bytes.len,
        );
        return bytes.len;
    }

    pub fn writeAll(self: *ProofLengthWriter, bytes: []const u8) !void {
        _ = try self.write(bytes);
    }

    pub fn writeByte(self: *ProofLengthWriter, byte: u8) !void {
        const bytes = [_]u8{byte};
        _ = try self.write(&bytes);
    }
};

pub fn moveOwnedForVerifier(comptime T: type, value: *T, owned: *bool) T {
    std.debug.assert(owned.*);
    const moved = value.*;
    value.* = undefined;
    owned.* = false;
    return moved;
}

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
    commitment: recursion.engine.Hasher.Hash,
    channel: *Engine.Channel,
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
