//! Candidate four-root/two-track Gate transcript with private mutable custody.
//!
//! This wraps the proposed event plan and admitted line-root cache in one
//! stable allocation. The selected verifier still needs sealed-key derivation,
//! checked wire geometry, a complete PCS/FRI verifier, and a security proof.
//! No production proof selector constructs this type.
const std = @import("std");
const framed = @import("../channel/framed_bcs_v2.zig");
const plan_mod = @import("../channel/paired_gate_event_plan_v2.zig");
const uniform = @import("../queries/uniform_v1.zig");
const descriptor = @import("line_descriptor_v2.zig");
const admission = @import("line_admission_v2.zig");

pub const Digest32 = framed.Digest32;
pub const Error = error{
    InvalidQueryGeometry,
    ZeroQueries,
    ManifestPlanMismatch,
    InvalidQueryIndex,
    QueriesNotDrawn,
} || plan_mod.Error || admission.Error || uniform.Error;

const State = struct {
    allocator: std.mem.Allocator,
    plan: plan_mod.PairedGateEventPlanV2,
    admitted: *admission.AdmittedLineManifestV2,
    query_log_size: u32,
    queries: ?uniform.SampledQueriesV1 = null,
};

/// Opaque custody for the candidate S31NAT9F schedule. A caller receives no
/// channel, plan, cache, or mutable query slice. The caller must derive the
/// statement and manifest from one sealed verification key; this API checks
/// their equality but cannot establish the external derivation premise.
pub const OwnedPairedGateVerifierV2 = opaque {
    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        manifest: descriptor.LineTreeManifestV2,
        statement: framed.StatementBinding,
    ) Error!*Self {
        // A one-bit FRI fold at each committed height has a line tree at the
        // next height. The raw query is sampled over the first fold height.
        // This is checked geometry, not a sealed-key derivation.
        try manifest.validate();
        const query_log_size = manifest.fold_heights[0];
        if (query_log_size < 2 or query_log_size > 30) return error.InvalidQueryGeometry;
        for (manifest.fold_heights[1..], 1..) |height, i| {
            if (height + 1 != manifest.fold_heights[i - 1]) return error.InvalidQueryGeometry;
        }
        for (manifest.trees, 0..) |tree, i| {
            const fold_height = manifest.fold_heights[i / 2];
            if (fold_height < 2 or tree.tree_log_size != fold_height - 1)
                return error.InvalidQueryGeometry;
        }
        const state = try allocator.create(State);
        errdefer allocator.destroy(state);
        state.allocator = allocator;
        state.plan = try plan_mod.PairedGateEventPlanV2.init(statement, manifest.fold_heights);
        state.admitted = try admission.AdmittedLineManifestV2.init(
            allocator,
            manifest,
            statement,
            &state.plan.channel,
        );
        state.query_log_size = query_log_size;
        state.queries = null;
        return @ptrCast(state);
    }

    fn privateState(self: *Self) *State {
        return @ptrCast(@alignCast(self));
    }

    fn stateConst(self: *const Self) *const State {
        return @ptrCast(@alignCast(self));
    }

    pub fn deinit(self: *Self) void {
        const state = self.privateState();
        if (state.queries) |*queries| queries.deinit(state.allocator);
        state.admitted.deinit();
        state.allocator.destroy(state);
    }

    pub fn statementDigest(self: *const Self) Digest32 {
        return self.stateConst().admitted.statementDigest();
    }

    pub fn manifestDigest(self: *const Self) Digest32 {
        return self.stateConst().admitted.manifestDigest();
    }

    pub fn transcriptDigest(self: *const Self) Digest32 {
        return self.stateConst().plan.channel.digest;
    }

    pub fn nextEvent(self: *const Self) u64 {
        return self.stateConst().plan.channel.next_event;
    }

    pub fn mixFixedRoot(self: *Self, root: Digest32) Error!void {
        try self.privateState().plan.mixFixedRoot(root);
    }

    pub fn mixCircuitIdentity(self: *Self, identity: Digest32) Error!void {
        try self.privateState().plan.mixCircuitIdentity(identity);
    }

    pub fn mixPublicValues(self: *Self, limbs: []const u32) Error!void {
        try self.privateState().plan.mixPublicValues(limbs);
    }

    pub fn mixMainRoot(self: *Self, root: Digest32) Error!void {
        try self.privateState().plan.mixMainRoot(root);
    }

    pub fn beginInteractionPow(self: *Self, difficulty: u32) Error!framed.PowBarrier {
        return self.privateState().plan.beginInteractionPow(difficulty);
    }

    pub fn acceptInteractionNonce(self: *Self, nonce: u64) Error!void {
        try self.privateState().plan.acceptInteractionNonce(nonce);
    }

    pub fn drawLookupPair(self: *Self) Error![8]u32 {
        return self.privateState().plan.drawLookupPair();
    }

    pub fn mixInteractionClaim(self: *Self, limbs: []const u32) Error!void {
        try self.privateState().plan.mixInteractionClaim(limbs);
    }

    pub fn mixInteractionRoot(self: *Self, root: Digest32) Error!void {
        try self.privateState().plan.mixInteractionRoot(root);
    }

    pub fn drawCompositionGamma(self: *Self) Error![4]u32 {
        return self.privateState().plan.drawCompositionGamma();
    }

    pub fn mixCompositionRoot(self: *Self, root: Digest32) Error!void {
        try self.privateState().plan.mixCompositionRoot(root);
    }

    pub fn drawOodsSeed(self: *Self) Error![4]u32 {
        return self.privateState().plan.drawOodsSeed();
    }

    pub fn mixSampledValues(self: *Self, limbs: []const u32) Error!void {
        try self.privateState().plan.mixSampledValues(limbs);
    }

    pub fn drawBatchLambda(self: *Self) Error![4]u32 {
        return self.privateState().plan.drawBatchLambda();
    }

    pub fn drawFoldAlpha(self: *Self) Error![4]u32 {
        return self.privateState().plan.drawFoldAlpha();
    }

    /// The admitted cache absorbs and retains the root. The plan stage only
    /// advances after that exact absorption succeeds, so there is no second
    /// root mix and no independently supplied root for later opening checks.
    pub fn captureOriginalLineRoot(self: *Self, root: Digest32) Error!void {
        const state = self.privateState();
        if (state.plan.stage != .original_line_root) return error.UnexpectedStage;
        const tree_index = 2 * state.plan.fold_index;
        const shape = try state.admitted.openingShape(tree_index);
        if (shape.track != .original or shape.fold_height != try state.plan.currentFoldHeight())
            return error.ManifestPlanMismatch;
        try state.admitted.captureRootAtNamedEvent(tree_index, root);
        state.plan.stage = .own_quotient_line_root;
    }

    pub fn captureOwnQuotientLineRoot(self: *Self, root: Digest32) Error!void {
        const state = self.privateState();
        if (state.plan.stage != .own_quotient_line_root) return error.UnexpectedStage;
        const tree_index = 2 * state.plan.fold_index + 1;
        const shape = try state.admitted.openingShape(tree_index);
        if (shape.track != .own_quotient or shape.fold_height != try state.plan.currentFoldHeight())
            return error.ManifestPlanMismatch;
        try state.admitted.captureRootAtNamedEvent(tree_index, root);
        state.plan.fold_index += 1;
        state.plan.stage = .fold_alpha;
    }

    pub fn mixOriginalTerminalCoefficients(self: *Self, limbs: []const u32) Error!void {
        try self.privateState().plan.mixOriginalTerminalCoefficients(limbs);
    }

    pub fn mixOwnQuotientTerminalCoefficients(self: *Self, limbs: []const u32) Error!void {
        try self.privateState().plan.mixOwnQuotientTerminalCoefficients(limbs);
    }

    pub fn beginFriPow(self: *Self, difficulty: u32) Error!framed.PowBarrier {
        return self.privateState().plan.beginFriPow(difficulty);
    }

    pub fn acceptFriNonce(self: *Self, nonce: u64) Error!void {
        try self.privateState().plan.acceptFriNonce(nonce);
    }

    /// The raw query channel and position slice remain private. The selected
    /// verifier must additionally prove one sampled query is projected
    /// consistently through every FRI fold and opening geometry.
    pub fn drawQueries(
        self: *Self,
        n_queries: usize,
        max_blocks: u64,
    ) Error!void {
        const state = self.privateState();
        if (n_queries == 0) return error.ZeroQueries;
        if (!state.admitted.allRootsCaptured()) return error.RootNotCaptured;
        var query_channel = try state.plan.beginQueries();
        state.queries = try uniform.drawUniformQueriesV1(
            &query_channel,
            state.allocator,
            state.query_log_size,
            n_queries,
            max_blocks,
        );
    }

    pub fn queryCount(self: *const Self) Error!usize {
        const queries = self.stateConst().queries orelse return error.QueriesNotDrawn;
        return queries.raw.len;
    }

    pub fn queryPosition(self: *const Self, index: usize) Error!usize {
        const queries = self.stateConst().queries orelse return error.QueriesNotDrawn;
        if (index >= queries.raw.len) return error.InvalidQueryIndex;
        return queries.raw[index];
    }

    /// Checks an opening at the line row selected by a previously sampled
    /// raw query. A fold from height h to h-1 removes one high-order bit in
    /// bit-reversed query order: `line_row = raw >> (query_log - tree_log)`.
    /// This authenticates only one selected row, not the adjacent pair needed
    /// for a complete FRI relation or a proof-acceptance decision.
    pub fn verifyCapturedLineOpening(
        self: *const Self,
        tree_index: usize,
        query_ordinal: usize,
        row: []const u32,
        siblings: []const Digest32,
    ) Error!bool {
        const state = self.stateConst();
        const queries = state.queries orelse return error.QueriesNotDrawn;
        if (query_ordinal >= queries.raw.len) return error.InvalidQueryIndex;
        const shape = try state.admitted.openingShape(tree_index);
        const fold_index = tree_index / 2;
        if (fold_index >= state.plan.fold_count or
            shape.fold_height != state.plan.fold_heights[fold_index] or
            shape.tree_log_size + 1 != shape.fold_height or
            shape.tree_log_size >= state.query_log_size)
            return error.InvalidQueryGeometry;
        const raw = queries.raw[query_ordinal];
        if (raw >= (@as(usize, 1) << @intCast(state.query_log_size)))
            return error.InvalidQueryGeometry;
        const shift = state.query_log_size - shape.tree_log_size;
        const leaf_index: u64 = @intCast(raw >> @intCast(shift));
        return state.admitted.verifyCapturedOpening(tree_index, row, leaf_index, siblings);
    }
};

fn testStatement(manifest: descriptor.LineTreeManifestV2, allocator: std.mem.Allocator) !framed.StatementBinding {
    const zero = [_]u8{0} ** 32;
    return .{
        .key_digest = zero,
        .circuit_digest = zero,
        .fri_config_digest = zero,
        .source_tree_descriptors = [_]Digest32{zero} ** 4,
        .line_profile_digest = try manifest.digest(allocator),
    };
}

test "opaque paired verifier owns channel, cached roots and query positions" {
    const allocator = std.testing.allocator;
    const zero = [_]u8{0} ** 32;
    const profile = descriptor.lineHashProfileDigest();
    const columns = [_]Digest32{zero};
    var trees = [_]descriptor.LineTreeDescriptorV2{
        .{ .key_digest = zero, .profile_digest = profile, .track = .original, .fold_height = 2, .tree_log_size = 1, .root_event = 17, .column_descriptors = &columns },
        .{ .key_digest = zero, .profile_digest = profile, .track = .own_quotient, .fold_height = 2, .tree_log_size = 1, .root_event = 18, .column_descriptors = &columns },
    };
    var fold_heights = [_]u32{ 2, 1 };
    const manifest = descriptor.LineTreeManifestV2{ .key_digest = zero, .fold_heights = &fold_heights, .trees = &trees };
    const statement = try testStatement(manifest, allocator);
    const verifier = try OwnedPairedGateVerifierV2.init(allocator, manifest, statement);
    defer verifier.deinit();
    try std.testing.expectEqual(@as(u64, 1), verifier.nextEvent());
    try std.testing.expectError(error.UnexpectedStage, verifier.mixMainRoot(zero));
    try std.testing.expectError(error.UnexpectedStage, verifier.captureOriginalLineRoot(zero));
    try std.testing.expectError(error.QueriesNotDrawn, verifier.queryCount());
    const leaf0 = try @import("blake2s_personalized_line_v2.zig").hashCanonicalRow(&.{0});
    const leaf1 = try @import("blake2s_personalized_line_v2.zig").hashCanonicalRow(&.{1});
    const root = @import("blake2s_personalized_line_v2.zig").LineMerkleHasherV2.hashChildren(.{ .left = leaf0, .right = leaf1 });
    try verifier.mixFixedRoot(zero);
    try verifier.mixCircuitIdentity(zero);
    try verifier.mixPublicValues(&.{ 0, 1, 2, 3 });
    try verifier.mixMainRoot(zero);
    _ = try verifier.beginInteractionPow(0);
    try verifier.acceptInteractionNonce(0);
    _ = try verifier.drawLookupPair();
    try verifier.mixInteractionClaim(&.{ 0, 1, 2, 3 });
    try verifier.mixInteractionRoot(zero);
    _ = try verifier.drawCompositionGamma();
    try verifier.mixCompositionRoot(zero);
    _ = try verifier.drawOodsSeed();
    try verifier.mixSampledValues(&.{ 0, 1, 2, 3 });
    _ = try verifier.drawBatchLambda();
    _ = try verifier.drawFoldAlpha();
    try std.testing.expectEqual(@as(u64, 17), verifier.nextEvent());
    try std.testing.expectError(error.RootNotCaptured, verifier.drawQueries(8, 1));
    const before_root = verifier.transcriptDigest();
    try verifier.captureOriginalLineRoot(root);
    try std.testing.expectEqual(@as(u64, 18), verifier.nextEvent());
    try std.testing.expectEqualDeep(framed.hashRoot(before_root, 17, root), verifier.transcriptDigest());
    try std.testing.expectError(error.UnexpectedStage, verifier.captureOriginalLineRoot(root));
    try verifier.captureOwnQuotientLineRoot(root);
    try std.testing.expectEqual(@as(u64, 19), verifier.nextEvent());
    // The cache copied shapes before this caller-owned descriptor changed.
    trees[0].tree_log_size = 0;
    trees[0].root_event = 99;
    fold_heights[0] = 99;
    _ = try verifier.drawFoldAlpha();
    try verifier.mixOriginalTerminalCoefficients(&.{ 0, 1, 2, 3 });
    try verifier.mixOwnQuotientTerminalCoefficients(&.{ 0, 1, 2, 3 });
    _ = try verifier.beginFriPow(0);
    try verifier.acceptFriNonce(0);
    try verifier.drawQueries(8, 1);
    try std.testing.expectEqual(@as(usize, 8), try verifier.queryCount());
    var seen = [2]bool{ false, false };
    for (0..8) |ordinal| {
        const raw = try verifier.queryPosition(ordinal);
        try std.testing.expect(raw < 4);
        const projected = raw >> 1;
        seen[projected] = true;
        const good_row: u32 = @intCast(projected);
        const good_sibling = if (projected == 0) leaf1 else leaf0;
        try std.testing.expect(try verifier.verifyCapturedLineOpening(0, ordinal, &.{good_row}, &.{good_sibling}));
        try std.testing.expect(try verifier.verifyCapturedLineOpening(1, ordinal, &.{good_row}, &.{good_sibling}));
        // A valid path for the other leaf cannot be replayed at this sampled
        // query ordinal, even though both paths share the captured root.
        const wrong_row: u32 = @intCast(1 - projected);
        const wrong_sibling = if (projected == 0) leaf0 else leaf1;
        try std.testing.expect(!(try verifier.verifyCapturedLineOpening(0, ordinal, &.{wrong_row}, &.{wrong_sibling})));
    }
    try std.testing.expect(seen[0] and seen[1]);
    try std.testing.expectError(error.InvalidQueryIndex, verifier.queryPosition(8));
    try std.testing.expectError(error.InvalidQueryIndex, verifier.verifyCapturedLineOpening(0, 8, &.{0}, &.{leaf1}));
    try std.testing.expectError(error.RowWidthMismatch, verifier.verifyCapturedLineOpening(0, 0, &.{ 0, 1 }, &.{leaf1}));
    try std.testing.expectError(error.UnexpectedStage, verifier.drawQueries(8, 1));
}

test "owned verifier rejects mismatched statement before transcript events" {
    const allocator = std.testing.allocator;
    const zero = [_]u8{0} ** 32;
    const manifest = descriptor.LineTreeManifestV2{ .key_digest = zero, .fold_heights = &.{17}, .trees = &.{} };
    var statement = try testStatement(manifest, allocator);
    statement.line_profile_digest = zero;
    try std.testing.expectError(error.StatementMismatch, OwnedPairedGateVerifierV2.init(allocator, manifest, statement));
}

test "owned verifier rejects inconsistent fold and line-tree geometry" {
    const allocator = std.testing.allocator;
    const zero = [_]u8{0} ** 32;
    const profile = descriptor.lineHashProfileDigest();
    const columns = [_]Digest32{zero};
    var trees = [_]descriptor.LineTreeDescriptorV2{
        .{ .key_digest = zero, .profile_digest = profile, .track = .original, .fold_height = 3, .tree_log_size = 2, .root_event = 17, .column_descriptors = &columns },
        .{ .key_digest = zero, .profile_digest = profile, .track = .own_quotient, .fold_height = 3, .tree_log_size = 2, .root_event = 18, .column_descriptors = &columns },
    };
    var heights = [_]u32{ 3, 1 };
    const manifest = descriptor.LineTreeManifestV2{ .key_digest = zero, .fold_heights = &heights, .trees = &trees };
    try std.testing.expectError(error.InvalidQueryGeometry, OwnedPairedGateVerifierV2.init(
        allocator,
        manifest,
        try testStatement(manifest, allocator),
    ));
    heights[1] = 2;
    trees[0].tree_log_size = 1;
    try std.testing.expectError(error.InvalidQueryGeometry, OwnedPairedGateVerifierV2.init(
        allocator,
        manifest,
        try testStatement(manifest, allocator),
    ));
}

test "zero queries are rejected and failed query sampling is terminal" {
    const allocator = std.testing.allocator;
    const zero = [_]u8{0} ** 32;
    const manifest = descriptor.LineTreeManifestV2{ .key_digest = zero, .fold_heights = &.{2}, .trees = &.{} };
    const verifier = try OwnedPairedGateVerifierV2.init(allocator, manifest, try testStatement(manifest, allocator));
    defer verifier.deinit();
    try verifier.mixFixedRoot(zero);
    try verifier.mixCircuitIdentity(zero);
    try verifier.mixPublicValues(&.{ 0, 1, 2, 3 });
    try verifier.mixMainRoot(zero);
    _ = try verifier.beginInteractionPow(0);
    try verifier.acceptInteractionNonce(0);
    _ = try verifier.drawLookupPair();
    try verifier.mixInteractionClaim(&.{ 0, 1, 2, 3 });
    try verifier.mixInteractionRoot(zero);
    _ = try verifier.drawCompositionGamma();
    try verifier.mixCompositionRoot(zero);
    _ = try verifier.drawOodsSeed();
    try verifier.mixSampledValues(&.{ 0, 1, 2, 3 });
    _ = try verifier.drawBatchLambda();
    _ = try verifier.drawFoldAlpha();
    try verifier.mixOriginalTerminalCoefficients(&.{ 0, 1, 2, 3 });
    try verifier.mixOwnQuotientTerminalCoefficients(&.{ 0, 1, 2, 3 });
    _ = try verifier.beginFriPow(0);
    try verifier.acceptFriNonce(0);
    const before = verifier.nextEvent();
    try std.testing.expectError(error.ZeroQueries, verifier.drawQueries(0, 0));
    try std.testing.expectEqual(before, verifier.nextEvent());
    // Beginning terminal queries commits the plan to completion. A sampler
    // budget failure cannot be retried with a more favorable configuration.
    try std.testing.expectError(error.InsufficientBlockBudget, verifier.drawQueries(1, 0));
    try std.testing.expectEqual(before + 1, verifier.nextEvent());
    try std.testing.expectError(error.QueriesNotDrawn, verifier.queryCount());
    try std.testing.expectError(error.UnexpectedStage, verifier.drawQueries(1, 1));
}
