//! Proof-independent V3 interval algebra for an unbalanced temporal tree.
//!
//! Unlike the legacy slot statement, an interval may contain any positive
//! number of leaves. An odd node is carried unchanged to the next layer; it
//! is never replaced with an invented empty proof. This module is a witness
//! preflight only. A recursive parent must verify each child's proof and
//! constrain this entire relation against verifier-published child words.
const std = @import("std");
const global = @import("segment_leaf_local_authority_v3.zig");
const span = @import("span_statement.zig");
const segment = @import("segment_statement_v2.zig");
const channel = @import("poseidon2_channel.zig");

pub const PRODUCTION_ACTIVATION = false;
pub const RECURSIVE_PARENT_PROOF_AVAILABLE = false;
pub const MAX_TREE_LEAVES: usize = std.math.maxInt(u32);

pub const Error = global.Error || span.Error || std.mem.Allocator.Error || error{
    EmptyTree,
    JobMismatch,
    MemoryBoundaryMismatch,
    ParentChanged,
    InvalidCompletion,
    InvalidLeaf,
    ParentProofUnavailable,
    TooManyLeaves,
};

pub const ChildFamily = enum(u8) {
    leaf_wrapper_v3 = 1,
    temporal_parent_v3 = 2,
};

/// The statement that a future parent proof must publish. The two leaf IDs
/// prevent an interior node from silently changing its endpoint custody.
/// Neither this value nor its native validation is a proof receipt.
pub const IntervalV3 = struct {
    family: ChildFamily,
    job: span.JobContext,
    executed: span.ExecutedSpan,
    entry: global.BoundaryV3,
    exit: global.BoundaryV3,
    first_leaf_id: channel.Digest,
    last_leaf_id: channel.Digest,
    final_completion: ?segment.CompletionV2,

    pub fn fromLeaf(metadata: *const global.MetadataV3) Error!IntervalV3 {
        // `identityWords` validates the entire metadata once. Hashing those
        // already canonical words avoids a second walk over the leaf custody.
        const identity_words = try metadata.identityWords();
        const statement = try span.SpanStatement.fromCanonicalWords(
            &metadata.base_statement_words,
        );
        if (statement.slots.height != 0 or
            statement.slots.first != metadata.segment_index)
            return error.InvalidLeaf;
        const executed = switch (statement.body) {
            .empty => return error.InvalidLeaf,
            .executed => |value| value,
        };
        if (executed.segment_count != 1 or
            executed.first_segment != metadata.segment_index or
            executed.first_cycle != metadata.global_cycle_start or
            executed.endCycle() != metadata.global_cycle_end)
            return error.InvalidLeaf;
        const id = channel.hashCanonicalWords(
            &identity_words,
            global.METADATA_ID_DOMAIN,
        );
        const result: IntervalV3 = .{
            .family = .leaf_wrapper_v3,
            .job = statement.job,
            .executed = executed,
            .entry = metadata.entry,
            .exit = metadata.exit,
            .first_leaf_id = id,
            .last_leaf_id = id,
            .final_completion = metadata.completion,
        };
        try result.validate();
        return result;
    }

    pub fn validate(self: *const IntervalV3) Error!void {
        try self.job.validate();
        try self.executed.validate();
        const end_segment = self.executed.endSegment();
        if (end_segment > self.job.segment_count or
            self.executed.endCycle() > self.job.complete.total_cycles)
            return error.InvalidLeaf;
        const expected_family: ChildFamily = if (self.executed.segment_count == 1)
            ChildFamily.leaf_wrapper_v3
        else
            ChildFamily.temporal_parent_v3;
        if (self.family != expected_family) return error.InvalidLeaf;
        if (self.executed.first_segment == 0) {
            if (self.executed.first_cycle != 0 or
                !std.meta.eql(self.executed.entry, self.job.complete.initial_state))
                return error.InvalidLeaf;
        } else if (self.executed.input.digest != null) return error.InvalidLeaf;
        if (end_segment == self.job.segment_count) {
            if (self.executed.endCycle() != self.job.complete.total_cycles or
                !std.meta.eql(self.executed.exit, self.job.complete.final_state) or
                self.final_completion == null)
                return error.InvalidCompletion;
        } else if (self.executed.output.digest != null or
            self.final_completion != null)
            return error.InvalidCompletion;
        try validateEndpoint(&self.entry);
        try validateEndpoint(&self.exit);
        // Every produced interval has a canonical statement, even when its
        // two children came from different reduction heights. This validates
        // slot alignment, edge placement and all 412 canonical word rules.
        _ = try self.canonicalStatement();
    }

    pub fn fold(left: *const IntervalV3, right: *const IntervalV3) Error!IntervalV3 {
        try left.validate();
        try right.validate();
        if (!std.meta.eql(left.job, right.job)) return error.JobMismatch;
        const executed = try span.foldExecuted(left.executed, right.executed);
        if (!std.meta.eql(left.exit.snapshot_id, right.entry.snapshot_id) or
            left.exit.snapshot_count != right.entry.snapshot_count or
            left.exit.continuation_root != right.entry.continuation_root)
            return error.MemoryBoundaryMismatch;
        const result: IntervalV3 = .{
            .family = .temporal_parent_v3,
            .job = left.job,
            .executed = executed,
            .entry = left.entry,
            .exit = right.exit,
            .first_leaf_id = left.first_leaf_id,
            .last_leaf_id = right.last_leaf_id,
            .final_completion = right.final_completion,
        };
        try result.validate();
        return result;
    }

    /// Admits the full interval as the existing canonical 412-word root.
    /// Interior intervals use the same canonical statement words while V3's
    /// parent rule admits children of unequal subtree heights.
    pub fn rootWords(self: *const IntervalV3) Error!span.StatementWords {
        try self.validate();
        if (self.executed.first_segment != 0 or
            self.executed.segment_count != self.job.segment_count)
            return error.InvalidLeaf;
        const statement = try self.canonicalStatement();
        _ = try span.RootStatement.init(statement);
        return statement.canonicalWords();
    }

    pub fn statementWords(self: *const IntervalV3) Error!span.StatementWords {
        try self.validate();
        return (try self.canonicalStatement()).canonicalWords();
    }

    fn canonicalStatement(self: *const IntervalV3) Error!span.SpanStatement {
        const height = @as(u8, @intCast(32 - @clz(self.executed.segment_count - 1)));
        return span.SpanStatement.init(
            self.job,
            try span.SlotSpan.init(self.executed.first_segment, height),
            .{ .executed = self.executed },
        );
    }
};

fn validateEndpoint(boundary: *const global.BoundaryV3) Error!void {
    const modulus = @import("stwo_core").fields.m31.Modulus;
    var snapshot_nonzero: u32 = 0;
    var clock_nonzero: u32 = 0;
    for (boundary.snapshot_id) |word| {
        if (word >= modulus) return error.MemoryBoundaryMismatch;
        snapshot_nonzero |= word;
    }
    for (boundary.memory_clock_id) |word| {
        if (word >= modulus) return error.MemoryBoundaryMismatch;
        clock_nonzero |= word;
    }
    if (snapshot_nonzero == 0 or clock_nonzero == 0 or
        boundary.continuation_root >= modulus or
        boundary.snapshot_count > global.MAX_SPARSE_BOUNDARY_ENTRIES or
        boundary.memory_clock_count > global.MAX_SPARSE_BOUNDARY_ENTRIES)
        return error.MemoryBoundaryMismatch;
    for (boundary.register_clocks) |clock| {
        if (clock > global.MAX_LEAF_CYCLES) return error.MemoryBoundaryMismatch;
    }
}

/// Exact public-input preimages for one required parent proof. The AIR must
/// re-establish these joins from two independently verified child proofs;
/// this native value cannot authenticate proof bytes or verifier keys.
pub const PairPreflightV3 = struct {
    child_families: [2]ChildFamily,
    child_statement_words: [2]span.StatementWords,
    parent_statement_words: span.StatementWords,
    child_first_leaf_ids: [2]channel.Digest,
    child_last_leaf_ids: [2]channel.Digest,
    parent_first_leaf_id: channel.Digest,
    parent_last_leaf_id: channel.Digest,
    child_entry_boundaries: [2]global.BoundaryV3,
    child_exit_boundaries: [2]global.BoundaryV3,
    parent_entry_boundary: global.BoundaryV3,
    parent_exit_boundary: global.BoundaryV3,
    child_final_completions: [2]?segment.CompletionV2,
    parent_final_completion: ?segment.CompletionV2,
    global_join_cycle: u64,
    shared_snapshot_id: segment.Digest,
    shared_snapshot_count: u32,
    shared_continuation_root: u32,

    pub fn init(left: *const IntervalV3, right: *const IntervalV3) Error!PairPreflightV3 {
        const parent = try IntervalV3.fold(left, right);
        return .{
            .child_families = .{ left.family, right.family },
            .child_statement_words = .{ try left.statementWords(), try right.statementWords() },
            .parent_statement_words = try parent.statementWords(),
            .child_first_leaf_ids = .{ left.first_leaf_id, right.first_leaf_id },
            .child_last_leaf_ids = .{ left.last_leaf_id, right.last_leaf_id },
            .parent_first_leaf_id = parent.first_leaf_id,
            .parent_last_leaf_id = parent.last_leaf_id,
            .child_entry_boundaries = .{ left.entry, right.entry },
            .child_exit_boundaries = .{ left.exit, right.exit },
            .parent_entry_boundary = parent.entry,
            .parent_exit_boundary = parent.exit,
            .child_final_completions = .{ left.final_completion, right.final_completion },
            .parent_final_completion = parent.final_completion,
            .global_join_cycle = left.executed.endCycle(),
            .shared_snapshot_id = left.exit.snapshot_id,
            .shared_snapshot_count = left.exit.snapshot_count,
            .shared_continuation_root = left.exit.continuation_root,
        };
    }

    pub fn validateAgainst(
        self: *const PairPreflightV3,
        left: *const IntervalV3,
        right: *const IntervalV3,
    ) Error!void {
        const fresh = try init(left, right);
        if (!std.meta.eql(self.*, fresh)) return error.ParentChanged;
    }

    pub fn requireVerifiedParent(_: *const PairPreflightV3) error{ParentProofUnavailable}!void {
        return error.ParentProofUnavailable;
    }
};

pub const ReductionStats = struct {
    leaves: usize,
    pair_reductions: usize,
    layers: usize,
    odd_carries: usize,
};

pub const Reduced = struct {
    /// Native reduction only. `pair_reductions` counts required parent
    /// proofs, not proofs already produced by this function.
    root: IntervalV3,
    stats: ReductionStats,

    pub fn requireVerifiedParent(_: *const Reduced) error{ParentProofUnavailable}!void {
        return error.ParentProofUnavailable;
    }
};

/// Mirrors the Cairo recursion driver's bounded left-to-right layer policy.
/// This is an ownership-free reference for the later proof scheduler: every
/// pair must result in a verified parent proof; a carried odd child retains
/// its original independently verified proof and proof family.
pub fn reduce(
    allocator: std.mem.Allocator,
    leaves: []const IntervalV3,
) Error!Reduced {
    if (leaves.len == 0) return error.EmptyTree;
    if (leaves.len > MAX_TREE_LEAVES) return error.TooManyLeaves;
    const live = try allocator.dupe(IntervalV3, leaves);
    defer allocator.free(live);
    var len = live.len;
    var stats: ReductionStats = .{
        .leaves = len,
        .pair_reductions = 0,
        .layers = 0,
        .odd_carries = 0,
    };
    while (len > 1) {
        var next: usize = 0;
        var index: usize = 0;
        while (index + 1 < len) : (index += 2) {
            live[next] = try IntervalV3.fold(&live[index], &live[index + 1]);
            next += 1;
            stats.pair_reductions += 1;
        }
        if (index < len) {
            live[next] = live[index];
            next += 1;
            stats.odd_carries += 1;
        }
        len = next;
        stats.layers += 1;
    }
    _ = try live[0].rootWords();
    return .{ .root = live[0], .stats = stats };
}
