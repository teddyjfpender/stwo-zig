//! Deferred first-tree commitment.
//!
//! The first committed tree's contents are channel-independent — only the
//! ORDER of Merkle-root mixes into the channel is protocol-bound. This
//! module runs that tree's full build on a dedicated worker thread so it
//! overlaps the next commit's build; the pending root is joined and mixed
//! in original order at the `tree_builders.appendCommittedTree` choke point
//! before any later tree is appended. Proof bytes are identical to the
//! sequential path by construction.
//!
//! Deferral gates (see `canDeferFirstTree`): multi-threaded build, first
//! tree only, and non-empty non-constant columns. Both twiddle-source
//! modes are deferral-safe: borrowed towers are immutable, and the owned
//! cache serializes lookup/insert behind its own mutex, so the worker and
//! the main thread may request trees concurrently.
//! Spawn failure falls back to the sequential path; `discard` drains an
//! unresolved build on abort.

const std = @import("std");
const builtin = @import("builtin");
const work_profile = @import("stwo_prover_api").work_profile;
const column_preparation = @import("columns/preparation.zig");
const column_storage = @import("columns/storage.zig");
const commitment_tree = @import("commitment_tree.zig");
const tree_builders = @import("tree_builders.zig");

const ColumnEvaluation = commitment_tree.ColumnEvaluation;

pub fn Pending(comptime Tree: type) type {
    return struct {
        thread: ?std.Thread,
        slot: *Slot,
        /// True once an observer (e.g. `roots`) joined the build and
        /// appended the tree while its root mix is still owed to the
        /// channel. First-tree-only deferral guarantees the owed tree is
        /// `trees.items[0]`, so the root needs no separate storage.
        appended_unmixed: bool = false,

        pub const Slot = struct {
            tree: ?Tree = null,
            err: ?anyerror = null,
        };
    };
}

pub fn canDeferFirstTree(scheme: anytype, owned_columns: []const ColumnEvaluation) bool {
    if (comptime builtin.single_threaded) return false;
    if (scheme.pending_commit != null) return false;
    if (scheme.trees.items.len != 0) return false;
    if (owned_columns.len == 0) return false;
    return true;
}

/// Spawns the deferred build; returns false (caller runs the sequential
/// path) if the slot allocation or thread spawn fails.
pub fn trySpawn(
    comptime B: type,
    comptime Tree: type,
    scheme: anytype,
    allocator: std.mem.Allocator,
    owned_columns: []ColumnEvaluation,
    work_recorder: ?*work_profile.Recorder(true),
) bool {
    const P = Pending(Tree);
    const slot = allocator.create(P.Slot) catch return false;
    slot.* = .{};
    const Worker = struct {
        fn run(
            scheme_ptr: @TypeOf(scheme),
            worker_allocator: std.mem.Allocator,
            columns: []ColumnEvaluation,
            worker_work_recorder: ?*work_profile.Recorder(true),
            out: *P.Slot,
        ) void {
            var prepared = column_preparation.prepareColumnsForCommitOwnedForBackendWithWorkRecorder(
                B,
                worker_allocator,
                columns,
                scheme_ptr.config.fri_config.log_blowup_factor,
                scheme_ptr.coefficient_retention_policy,
                &scheme_ptr.twiddle_source,
                null,
                null,
                worker_work_recorder,
            ) catch |err| {
                column_storage.freeOwnedColumnEvaluations(worker_allocator, columns);
                out.err = err;
                return;
            };
            if (worker_work_recorder) |work|
                work.expectProducer(.commitment_tree_merkle) catch |err| {
                    prepared.deinit(worker_allocator);
                    out.err = err;
                    return;
                };
            // work-profile-plan:commitment-tree-merkle
            const tree = Tree.initOwnedWithBackingAndWorkRecorder(
                worker_allocator,
                prepared.columns,
                prepared.coefficients,
                prepared.column_backing_buffers,
                prepared.coefficient_backing_buffers,
                worker_work_recorder,
            ) catch |err| {
                prepared.deinit(worker_allocator);
                out.err = err;
                return;
            };
            out.tree = tree;
        }
    };
    const thread = std.Thread.spawn(
        .{},
        Worker.run,
        .{ scheme, allocator, owned_columns, work_recorder, slot },
    ) catch {
        allocator.destroy(slot);
        return false;
    };
    scheme.pending_commit = .{ .thread = thread, .slot = slot };
    return true;
}

/// Joins a deferred first-tree build (if any) and replays its root mix by
/// re-entering the append choke point. Clears the pending slot first, so
/// the recursion terminates and mix order matches the sequential path.
/// A build already appended by `resolveObserved` only owes its root mix,
/// which is replayed here — still ahead of any later tree's mix.
pub fn resolve(
    comptime MC: type,
    scheme: anytype,
    allocator: std.mem.Allocator,
    channel: anytype,
) anyerror!void {
    const pending = scheme.pending_commit orelse return;
    scheme.pending_commit = null;
    if (pending.appended_unmixed) {
        allocator.destroy(pending.slot);
        const root = scheme.trees.items[0].root();
        MC.mixRoot(channel, root);
        if (comptime @hasDecl(@TypeOf(scheme.*), "observePreOpeningRootMix")) {
            scheme.observePreOpeningRootMix(0, std.mem.asBytes(&root));
        }
        return;
    }
    pending.thread.?.join();
    const slot = pending.slot;
    defer allocator.destroy(slot);
    if (slot.err) |err| return err;
    var tree = slot.tree.?;
    errdefer tree.deinit(allocator);
    try tree_builders.appendCommittedTree(MC, scheme, allocator, tree, channel);
}

/// Channel-less resolution for observers (`roots`) that must see the
/// committed tree before any later commit supplies a channel: joins the
/// build and appends the tree, leaving the root mix owed. Single-commit
/// schemes (e.g. standalone commitment validation) never replay the mix —
/// their channel carries no further protocol traffic by construction.
pub fn resolveObserved(scheme: anytype, allocator: std.mem.Allocator) anyerror!void {
    var pending = scheme.pending_commit orelse return;
    if (pending.appended_unmixed) return;
    pending.thread.?.join();
    pending.thread = null;
    const slot = pending.slot;
    if (slot.err) |err| {
        scheme.pending_commit = null;
        allocator.destroy(slot);
        return err;
    }
    var tree = slot.tree.?;
    slot.tree = null;
    scheme.trees.append(allocator, tree) catch |err| {
        // Leave the scheme self-consistent on the rare allocation failure:
        // the worker is joined, so the pending slot must not survive for a
        // later resolve/discard to re-join.
        scheme.pending_commit = null;
        tree.deinit(allocator);
        allocator.destroy(slot);
        return err;
    };
    pending.appended_unmixed = true;
    scheme.pending_commit = pending;
}

test "resolveObserved: failed append clears pending and leaks nothing" {
    const MockTree = struct {
        freed: *bool,
        fn root(self: *const @This()) u64 {
            _ = self;
            return 0;
        }
        fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            _ = allocator;
            self.freed.* = true;
        }
    };
    const MockScheme = struct {
        pending_commit: ?Pending(MockTree) = null,
        trees: std.ArrayListUnmanaged(MockTree) = .{},
    };
    var freed = false;
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    var scheme = MockScheme{};
    const slot = try std.testing.allocator.create(Pending(MockTree).Slot);
    slot.* = .{ .tree = .{ .freed = &freed } };
    const Worker = struct {
        fn run() void {}
    };
    scheme.pending_commit = .{
        .thread = try std.Thread.spawn(.{}, Worker.run, .{}),
        .slot = slot,
    };
    try std.testing.expectError(
        error.OutOfMemory,
        resolveObserved(&scheme, failing.allocator()),
    );
    try std.testing.expect(scheme.pending_commit == null);
    try std.testing.expect(freed);
    try std.testing.expectEqual(@as(usize, 0), scheme.trees.items.len);
    scheme.trees.deinit(std.testing.allocator);
}

/// Abort path: join and discard a deferred build without mixing. A tree
/// already appended by `resolveObserved` is owned by `scheme.trees` and is
/// not freed here.
pub fn discard(scheme: anytype, allocator: std.mem.Allocator) void {
    const pending = scheme.pending_commit orelse return;
    scheme.pending_commit = null;
    if (pending.thread) |thread| thread.join();
    if (pending.slot.tree) |*tree| tree.deinit(allocator);
    allocator.destroy(pending.slot);
}
