//! Verifier-side proof ownership and manifest tree registration.
//! Depends only on the protocol hash suite and core; no witness/session owner.

const std = @import("std");
const Hasher = @import("poseidon2_channel.zig").MerkleHasher;

pub fn moveOwnedForVerifier(
    comptime T: type,
    value: *T,
    owned: *bool,
) T {
    std.debug.assert(owned.*);
    const moved = value.*;
    value.* = undefined;
    owned.* = false;
    return moved;
}

pub fn commitVerifierTreeForManifest(
    comptime manifest_contract: type,
    allocator: std.mem.Allocator,
    scheme: anytype,
    manifest: *const manifest_contract.Manifest,
    tree: usize,
    commitment: Hasher.Hash,
    channel: anytype,
) !void {
    const logs = try allocator.alloc(
        u32,
        treeColumnCount(manifest_contract, manifest, tree),
    );
    defer allocator.free(logs);
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const placement = manifest.placements[row].?;
        const offset = treeOffset(manifest_contract, placement, tree);
        const count = treeGeometryColumns(
            manifest_contract,
            placement.geometry,
            tree,
        );
        @memset(logs[offset..][0..count], placement.geometry.log_size);
    }
    try scheme.commit(allocator, commitment, logs, channel);
}

pub fn treeColumnCount(
    comptime manifest_contract: type,
    manifest: *const manifest_contract.Manifest,
    tree: usize,
) usize {
    return switch (tree) {
        manifest_contract.PREPROCESSED_TREE_INDEX => manifest.total_preprocessed_columns,
        manifest_contract.MAIN_TREE_INDEX => manifest.total_main_columns,
        manifest_contract.INTERACTION_TREE_INDEX => manifest.total_interaction_columns,
        else => unreachable,
    };
}

pub fn treeOffset(
    comptime manifest_contract: type,
    placement: manifest_contract.Placement,
    tree: usize,
) usize {
    return switch (tree) {
        manifest_contract.PREPROCESSED_TREE_INDEX => placement.preprocessed_offset,
        manifest_contract.MAIN_TREE_INDEX => placement.main_offset,
        manifest_contract.INTERACTION_TREE_INDEX => placement.interaction_offset,
        else => unreachable,
    };
}

pub fn treeGeometryColumns(
    comptime manifest_contract: type,
    geometry: manifest_contract.Geometry,
    tree: usize,
) usize {
    return switch (tree) {
        manifest_contract.PREPROCESSED_TREE_INDEX => geometry.preprocessed_columns,
        manifest_contract.MAIN_TREE_INDEX => geometry.main_columns,
        manifest_contract.INTERACTION_TREE_INDEX => geometry.interaction_columns,
        else => unreachable,
    };
}
