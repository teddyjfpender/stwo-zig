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
const prover = @import("stwo_prover_engine");
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
    return foldEntriesBounded(gpa, fold, entries, 1);
}

/// Pair independent siblings concurrently, with at most two reductions live.
/// The caller must provide a thread-safe `gpa` and `fold.packed_allocator`
/// when `max_jobs > 1`. Profiles stay serial because their stage recorder has
/// one stack. The final root remains one ordinary reduction.
pub fn foldEntriesBounded(gpa: std.mem.Allocator, fold: *const Fold, entries: []LayerEntry, max_jobs: usize) !Folded {
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
        const parallel = max_jobs > 1 and live.len >= 4 and fold.options.recorder == null and
            std.mem.eql(u8, fold.provers.backend_name, "cpu");
        if (parallel) {
            const pair_count = live.len / 2;
            const cpu_count = std.Thread.getCpuCount() catch 1;
            const worker_count = @max(1, cpu_count / @min(max_jobs, max_parallel_jobs));
            var pair_idx: usize = 0;
            while (pair_idx < pair_count) {
                const wave = @min(@min(max_jobs, max_parallel_jobs), pair_count - pair_idx);
                var jobs: [max_parallel_jobs]PairJob = undefined;
                var threads: [max_parallel_jobs]?std.Thread = @splat(null);
                for (0..wave) |j| {
                    const child_index = 2 * (pair_idx + j);
                    jobs[j] = .{
                        .gpa = gpa,
                        .fold = fold,
                        .left = &live[child_index],
                        .right = &live[child_index + 1],
                        .layer_idx = layer_idx + 1,
                        .pair_idx = pair_idx + j,
                        .worker_count = worker_count,
                    };
                    if (std.Thread.spawn(.{}, PairJob.run, .{&jobs[j]})) |thread| {
                        threads[j] = thread;
                    } else |_| {
                        // A failed thread creation still consumes its pair.
                        jobs[j].run();
                    }
                }
                for (threads[0..wave]) |thread| if (thread) |running| running.join();
                const first_error: ?anyerror = for (jobs[0..wave]) |job| {
                    if (job.failure) |err| break err;
                } else null;
                if (first_error) |err| {
                    for (jobs[0..wave]) |*job| if (job.parent) |*parent| parent.deinit();
                    releaseAfterFailure(live, next_len, 2 * (pair_idx + wave));
                    live = live[0..0];
                    return err;
                }
                for (jobs[0..wave]) |*job| {
                    live[next_len] = job.parent.?;
                    next_len += 1;
                    stats.n_pair_reductions += 1;
                }
                pair_idx += wave;
            }
            if (live.len % 2 != 0) {
                log.info("layer {d} pair {d}: carrying the unpaired entry to the next layer", .{ layer_idx, pair_count });
                live[next_len] = live[live.len - 1];
                next_len += 1;
            }
            live = live[0..next_len];
            layer_idx += 1;
            continue;
        }
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
    return foldLeavesBounded(gpa, fold, leaves, 1);
}

pub fn foldLeavesBounded(gpa: std.mem.Allocator, fold: *const Fold, leaves: []const wire.leaf_proof_json.LeafInput, max_jobs: usize) !Folded {
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
    return foldEntriesBounded(gpa, fold, entries, max_jobs);
}

const max_parallel_jobs = 2;

const PairJob = struct {
    gpa: std.mem.Allocator,
    fold: *const Fold,
    left: *LayerEntry,
    right: *LayerEntry,
    layer_idx: usize,
    pair_idx: usize,
    worker_count: usize,
    parent: ?LayerEntry = null,
    failure: ?anyerror = null,

    fn run(self: *PairJob) void {
        if (prover.work_pool.currentScopedPool() != null) {
            self.prove();
            return;
        }
        var pool: prover.work_pool.WorkPool = undefined;
        pool.initInPlaceWithOptions(.{ .worker_count = self.worker_count }) catch |err| {
            self.failBeforeReduce(err);
            return;
        };
        defer pool.deinit();
        var binding = prover.work_pool.ScopedPoolBinding.init(&pool) catch |err| {
            self.failBeforeReduce(err);
            return;
        };
        defer binding.deinit();
        self.prove();
    }

    fn prove(self: *PairJob) void {
        self.parent = fold_mod.reducePair(self.gpa, self.fold, self.left, self.right, self.layer_idx, self.pair_idx, false) catch |err| {
            self.failure = err;
            return;
        };
    }

    fn failBeforeReduce(self: *PairJob, err: anyerror) void {
        self.left.deinit();
        self.right.deinit();
        self.failure = err;
    }
};

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

/// A layer entry that owns one allocation, for the ownership tests: its
/// proof is never read, because every reduction fails before it.
fn ownershipTestEntry(gpa: std.mem.Allocator) !LayerEntry {
    var arena = std.heap.ArenaAllocator.init(gpa);
    errdefer arena.deinit();
    _ = try arena.allocator().alloc(u8, 16);
    return .{
        .arena = arena,
        .proof = .{ .root = undefined },
        .preprocessed_root = @splat(0),
        .output_digest = @splat(0),
        .packed_output = .{ .plain = &.{} },
    };
}

test "tree: a failed reduction releases every entry it was given" {
    const gpa = std.testing.allocator;
    // The first packed-output allocation of the first reduction fails, so
    // the fold stops with every entry (the reduced pair and the rest of the
    // layer, or the single leaf) still to release; the testing allocator
    // reports any that leaks.
    var failing = std.testing.FailingAllocator.init(gpa, .{ .fail_index = 0 });
    var fold: Fold = undefined;
    fold.packed_allocator = failing.allocator();
    for ([_]usize{ 1, 2, 3, 5 }) |n_entries| {
        var entries: [5]LayerEntry = undefined;
        var built: usize = 0;
        errdefer for (entries[0..built]) |*entry| entry.deinit();
        while (built < n_entries) : (built += 1) entries[built] = try ownershipTestEntry(gpa);
        built = 0;
        try std.testing.expectError(error.OutOfMemory, foldEntries(gpa, &fold, entries[0..n_entries]));
    }
}
