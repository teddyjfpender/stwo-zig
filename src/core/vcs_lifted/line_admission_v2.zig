//! One-time candidate statement admission and named line-root capture.
//!
//! The admitted cache is opaque so callers cannot edit captured roots or
//! opening shapes. This is still not a selected verifier: callers can mutate
//! the separate channel, and only a future verifier can privately own it and
//! derive the manifest from a sealed key.
const std = @import("std");
const framed = @import("../channel/framed_bcs_v2.zig");
const descriptor = @import("line_descriptor_v2.zig");
const line = @import("blake2s_personalized_line_v2.zig");

pub const Digest32 = framed.Digest32;
pub const max_line_trees = 2 * (descriptor.max_fold_heights - 1);
pub const Error = error{
    ChannelNotFresh,
    DuplicateRootCapture,
    RootNotCaptured,
} || descriptor.Error;

pub const OpeningShape = struct {
    root_event: u64,
    fold_height: u32,
    tree_log_size: u32,
    column_count: u32,
    track: descriptor.Track,
};

const State = struct {
    allocator: std.mem.Allocator,
    channel: *framed.FramedBcsChannelV2,
    statement_digest: Digest32,
    manifest_digest: Digest32,
    shapes: [max_line_trees]OpeningShape,
    roots: [max_line_trees]?Digest32,
    count: usize,
};

/// Admission hashes the full manifest once, copies every opening shape, and
/// pins the initial framed channel by pointer. The opaque cache prevents
/// ordinary callers from changing root/shape entries after admission. The
/// selected verifier must also keep its channel privately owned.
pub const AdmittedLineManifestV2 = opaque {
    const Self = @This();

    pub fn init(
        allocator: std.mem.Allocator,
        manifest: descriptor.LineTreeManifestV2,
        statement: framed.StatementBinding,
        channel: *framed.FramedBcsChannelV2,
    ) Error!*Self {
        const manifest_digest = try manifest.digest(allocator);
        if (!std.mem.eql(u8, &manifest.key_digest, &statement.key_digest) or
            !std.mem.eql(u8, &manifest_digest, &statement.line_profile_digest))
            return error.StatementMismatch;

        const payload = statement.encode();
        const statement_digest = try framed.hashFrameParts(.statement, 0, &.{&payload});
        if (channel.next_event != 1 or
            !std.mem.eql(u8, &channel.digest, &statement_digest) or
            channel.pending_pow != null or channel.active_draw != null or
            channel.pow_barriers_done != 0 or channel.query_started or channel.failed)
            return error.ChannelNotFresh;

        const result = try allocator.create(State);
        result.* = .{
            .allocator = allocator,
            .channel = channel,
            .statement_digest = statement_digest,
            .manifest_digest = manifest_digest,
            .shapes = [_]OpeningShape{.{
                .root_event = 0,
                .fold_height = 0,
                .tree_log_size = 0,
                .column_count = 0,
                .track = .original,
            }} ** max_line_trees,
            .roots = [_]?Digest32{null} ** max_line_trees,
            .count = manifest.trees.len,
        };
        for (manifest.trees, 0..) |tree, i| {
            result.shapes[i] = .{
                .root_event = tree.root_event,
                .fold_height = tree.fold_height,
                .tree_log_size = tree.tree_log_size,
                .column_count = @intCast(tree.column_descriptors.len),
                .track = tree.track,
            };
        }
        return @ptrCast(result);
    }

    fn state(self: *Self) *State {
        return @ptrCast(@alignCast(self));
    }

    fn stateConst(self: *const Self) *const State {
        return @ptrCast(@alignCast(self));
    }

    pub fn deinit(self: *Self) void {
        const result = self.state();
        result.allocator.destroy(result);
    }

    pub fn statementDigest(self: *const Self) Digest32 {
        return self.stateConst().statement_digest;
    }

    pub fn manifestDigest(self: *const Self) Digest32 {
        return self.stateConst().manifest_digest;
    }

    pub fn openingShape(self: *const Self, tree_index: usize) Error!OpeningShape {
        const result = self.stateConst();
        if (tree_index >= result.count) return error.InvalidTreeIndex;
        return result.shapes[tree_index];
    }

    /// Mix the root at the exact planned event and retain that same value for
    /// all later openings. This does not enforce the earlier Gate event roles;
    /// a selected verifier must own the complete event-plan wrapper.
    pub fn captureRootAtNamedEvent(self: *Self, tree_index: usize, root: Digest32) Error!void {
        const result = self.state();
        if (tree_index >= result.count) return error.InvalidTreeIndex;
        if (result.roots[tree_index] != null) return error.DuplicateRootCapture;
        if (result.channel.next_event != result.shapes[tree_index].root_event)
            return error.RootEventMismatch;
        try result.channel.mixRoot(root);
        result.roots[tree_index] = root;
    }

    pub fn allRootsCaptured(self: *const Self) bool {
        const result = self.stateConst();
        for (result.roots[0..result.count]) |root| if (root == null) return false;
        return true;
    }

    /// Opening checks use the copied shape and the exact captured root;
    /// manifest hashing is not repeated per opening.
    pub fn verifyCapturedOpening(
        self: *const Self,
        tree_index: usize,
        row: []const u32,
        leaf_index: u64,
        siblings: []const Digest32,
    ) Error!bool {
        const result = self.stateConst();
        if (tree_index >= result.count) return error.InvalidTreeIndex;
        const root = result.roots[tree_index] orelse return error.RootNotCaptured;
        const shape = result.shapes[tree_index];
        if (row.len != shape.column_count) return error.RowWidthMismatch;
        return line.verifyPath(root, row, leaf_index, shape.tree_log_size, siblings);
    }
};

fn drawOneChallenge(channel: *framed.FramedBcsChannelV2) !void {
    try channel.beginChallengeDraw();
    _ = try channel.drawChallengeQM31Limbs();
    try channel.endChallengeDraw();
}

/// Honest candidate event trace through the first line root; this tests
/// framing/capture, not proof acceptance or the paper's theorem.
fn advanceThroughFirstFoldAlpha(channel: *framed.FramedBcsChannelV2) !void {
    const zero = [_]u8{0} ** 32;
    try channel.mixRoot(zero); // fixed root, event 1
    try channel.mixRoot(zero); // circuit identity, event 2
    try channel.mixField(&.{ 0, 1, 2, 3 }); // public values, event 3
    try channel.mixRoot(zero); // main root, event 4
    _ = try channel.beginPow(0); // prefix and trial, events 5-6
    try channel.acceptPowNonce(0); // event 7
    try drawOneChallenge(channel); // lookup pair, event 8
    try channel.mixField(&.{ 0, 1, 2, 3 }); // interaction claim, event 9
    try channel.mixRoot(zero); // interaction root, event 10
    try drawOneChallenge(channel); // composition gamma, event 11
    try channel.mixRoot(zero); // composition root, event 12
    try drawOneChallenge(channel); // OOD seed, event 13
    try channel.mixField(&.{ 0, 1, 2, 3 }); // sampled values, event 14
    try drawOneChallenge(channel); // batch lambda, event 15
    try drawOneChallenge(channel); // first fold alpha, event 16
}

test "admitted line roots are captured once and openings reuse cached shapes" {
    const allocator = std.testing.allocator;
    const zero = [_]u8{0} ** 32;
    const profile = descriptor.lineHashProfileDigest();
    const columns = [_]Digest32{zero};
    var trees = [_]descriptor.LineTreeDescriptorV2{
        .{ .key_digest = zero, .profile_digest = profile, .track = .original, .fold_height = 17, .tree_log_size = 1, .root_event = 17, .column_descriptors = &columns },
        .{ .key_digest = zero, .profile_digest = profile, .track = .own_quotient, .fold_height = 17, .tree_log_size = 1, .root_event = 18, .column_descriptors = &columns },
    };
    const manifest = descriptor.LineTreeManifestV2{
        .key_digest = zero,
        .fold_heights = &.{ 17, 16 },
        .trees = &trees,
    };
    const statement = framed.StatementBinding{
        .key_digest = zero,
        .circuit_digest = zero,
        .fri_config_digest = zero,
        .source_tree_descriptors = [_]Digest32{zero} ** 4,
        .line_profile_digest = try manifest.digest(allocator),
    };
    var channel = framed.FramedBcsChannelV2.init(statement);
    const admitted = try AdmittedLineManifestV2.init(allocator, manifest, statement, &channel);
    defer admitted.deinit();
    try std.testing.expectEqualDeep(admitted.statementDigest(), channel.digest);
    try std.testing.expectError(error.RootNotCaptured, admitted.verifyCapturedOpening(0, &.{0}, 0, &.{zero}));
    try std.testing.expectError(error.RootEventMismatch, admitted.captureRootAtNamedEvent(0, zero));
    try advanceThroughFirstFoldAlpha(&channel);
    try std.testing.expectEqual(@as(u64, 17), channel.next_event);

    const leaf0 = try line.hashCanonicalRow(&.{0});
    const leaf1 = try line.hashCanonicalRow(&.{1});
    const root = line.LineMerkleHasherV2.hashChildren(.{ .left = leaf0, .right = leaf1 });
    try admitted.captureRootAtNamedEvent(0, root);
    try std.testing.expectError(error.DuplicateRootCapture, admitted.captureRootAtNamedEvent(0, root));
    try admitted.captureRootAtNamedEvent(1, root);
    try std.testing.expect(admitted.allRootsCaptured());
    try std.testing.expect(try admitted.verifyCapturedOpening(0, &.{0}, 0, &.{leaf1}));
    try std.testing.expect(!(try admitted.verifyCapturedOpening(0, &.{1}, 0, &.{leaf1})));
    try std.testing.expectError(error.RowWidthMismatch, admitted.verifyCapturedOpening(0, &.{ 0, 1 }, 0, &.{leaf1}));

    // Input descriptor mutation cannot change the copied opening shape.
    trees[0].root_event = 99;
    trees[0].tree_log_size = 0;
    try std.testing.expectEqual(@as(u64, 17), (try admitted.openingShape(0)).root_event);
    try std.testing.expect(try admitted.verifyCapturedOpening(0, &.{0}, 0, &.{leaf1}));
}

test "admission rejects a mismatched statement or advanced channel" {
    const allocator = std.testing.allocator;
    const zero = [_]u8{0} ** 32;
    const manifest = descriptor.LineTreeManifestV2{
        .key_digest = zero,
        .fold_heights = &.{17},
        .trees = &.{},
    };
    const statement = framed.StatementBinding{
        .key_digest = zero,
        .circuit_digest = zero,
        .fri_config_digest = zero,
        .source_tree_descriptors = [_]Digest32{zero} ** 4,
        .line_profile_digest = try manifest.digest(allocator),
    };
    var channel = framed.FramedBcsChannelV2.init(statement);
    var wrong_statement = statement;
    wrong_statement.line_profile_digest = zero;
    try std.testing.expectError(error.StatementMismatch, AdmittedLineManifestV2.init(allocator, manifest, wrong_statement, &channel));
    try channel.mixRoot(zero);
    try std.testing.expectError(error.ChannelNotFresh, AdmittedLineManifestV2.init(allocator, manifest, statement, &channel));
}
