//! The recursive tree driver: folds `N` leaf circuit proofs to one root.
//!
//! Ports `stwo_run_and_prove_recursive_tree` and `fold_entries`
//! (`crates/stwo_run_and_prove_recursive_tree/src/lib.rs`) and
//! `write_root_outputs` (`output.rs`) of
//! https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230.
//!
//! Tree shape: each layer pairs adjacent entries left to right and carries
//! an odd last entry up unchanged; the reduction of a two-entry layer is the
//! root. A single leaf folds with itself. The root's outputs are the Cairo
//! verifier's felt stream (`root.proof`), the output digest
//! (`root_outputs.json`) and the nested `PackedNode` tree
//! (`root_packed.json`). A child is released as soon as its parent is proven,
//! so at most one layer of proofs is live.

const std = @import("std");
const wire = @import("stwo_circuit_recursion_wire");
const fold_mod = @import("fold.zig");

const LayerEntry = fold_mod.LayerEntry;
const Fold = fold_mod.Fold;

const log = std.log.scoped(.circuit_recursion);

pub const Error = error{
    /// `RecursiveTreeError::EmptyLeaves`.
    EmptyLeaves,
};

/// `RecursiveTreeStats`.
pub const Stats = struct {
    n_leaves: usize,
    n_layers: usize,
    n_pair_reductions: usize,
};

pub const Folded = struct {
    root: LayerEntry,
    stats: Stats,
};

/// `fold_entries`: folds the layer-0 `entries` (consumed, in order) to the
/// root. On error every entry not yet folded is released.
pub fn foldEntries(gpa: std.mem.Allocator, fold: *const Fold, entries: []LayerEntry) !Folded {
    if (entries.len == 0) return error.EmptyLeaves;
    var stats: Stats = .{ .n_leaves = entries.len, .n_layers = 0, .n_pair_reductions = 0 };
    // `live[0..len]` are the entries of the current layer that are still
    // owned; each iteration writes the next layer over the front.
    var live = entries;
    errdefer for (live) |*entry| entry.deinit();

    if (live.len == 1) {
        log.info("single-leaf tree: folding the leaf with itself for the root pass", .{});
        // `reduceRootSingle` consumes the entry, even on error.
        const single = &live[0];
        live = live[0..0];
        const root = try fold_mod.reduceRootSingle(gpa, fold, single);
        stats.n_layers = 1;
        stats.n_pair_reductions = 1;
        return .{ .root = root, .stats = stats };
    }

    var layer_idx: usize = 0;
    while (live.len > 1) {
        log.info("reducing layer {d} with {d} entries", .{ layer_idx, live.len });
        const is_root = live.len == 2;
        var next_len: usize = 0;
        var index: usize = 0;
        while (index < live.len) : (index += 2) {
            const pair_idx = index / 2;
            if (index + 1 < live.len) {
                // `reducePair` consumes both children, even on error; keep
                // the unconsumed tail owned by shifting it over them.
                const parent = fold_mod.reducePair(gpa, fold, &live[index], &live[index + 1], layer_idx + 1, pair_idx, is_root) catch |err| {
                    releaseAfterFailure(live, next_len, index + 2);
                    live = live[0..0];
                    return err;
                };
                live[next_len] = parent;
                stats.n_pair_reductions += 1;
            } else {
                log.info("layer {d} pair {d}: carrying the unpaired entry to the next layer", .{ layer_idx, pair_idx });
                live[next_len] = live[index];
            }
            next_len += 1;
        }
        live = live[0..next_len];
        layer_idx += 1;
    }
    stats.n_layers = layer_idx;
    const root = live[0];
    live = live[0..0];
    return .{ .root = root, .stats = stats };
}

/// `stwo_run_and_prove_recursive_tree` minus the file I/O: the layer-0
/// entries of `leaves` (`LayerEntry::from_leaf`, in order), folded to the
/// root.
pub fn foldLeaves(gpa: std.mem.Allocator, fold: *const Fold, leaves: []const wire.leaf_proof_json.LeafInput) !Folded {
    if (leaves.len == 0) return error.EmptyLeaves;
    const entries = try gpa.alloc(LayerEntry, leaves.len);
    defer gpa.free(entries);
    var loaded: usize = 0;
    errdefer for (entries[0..loaded]) |*entry| entry.deinit();
    for (entries, leaves) |*entry, leaf| {
        entry.* = try LayerEntry.fromLeaf(gpa, fold, leaf);
        loaded += 1;
    }
    // `foldEntries` owns the entries from here, on success and on error.
    loaded = 0;
    return foldEntries(gpa, fold, entries);
}

/// Releases a layer after a failed reduction: the finished parents
/// `live[0..n_parents]` and the untouched children `live[first_pending..]`.
fn releaseAfterFailure(live: []LayerEntry, n_parents: usize, first_pending: usize) void {
    for (live[0..n_parents]) |*entry| entry.deinit();
    for (live[first_pending..]) |*entry| entry.deinit();
}

/// `write_root_outputs`, to three writers: the root proof (pretty felt JSON,
/// no trailing newline), the output digest (`sonic_rs::to_string`) and the
/// packed tree (`serde_json::to_string`).
pub fn writeRootOutputs(
    root: *const LayerEntry,
    proof_out: *std.Io.Writer,
    outputs_out: *std.Io.Writer,
    packed_out: *std.Io.Writer,
) !void {
    switch (root.proof) {
        .root => |*proof| try wire.circuit_felt_stream.writeJson(proof_out, proof),
        .circuit => return error.NotARootProof,
    }
    try wire.packed_node.writeRootOutputs(outputs_out, root.output_digest);
    try wire.packed_node.writePackedNode(packed_out, root.packed_output);
}

test "tree: an empty leaf list is rejected" {
    var fold: Fold = undefined;
    try std.testing.expectError(error.EmptyLeaves, foldEntries(std.testing.allocator, &fold, &.{}));
}
