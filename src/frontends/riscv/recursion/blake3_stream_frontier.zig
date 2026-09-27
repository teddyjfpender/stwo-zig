//! Bounded ownership for an ordered stream of independently verified subtrees.
//! Padding must itself arrive as verified nodes; this never invents empty proofs.
const std = @import("std");
const spans = @import("span_statement_blake3.zig");
pub const Frontier = ForNode(@import("blake3_execution_tree.zig").Node);

fn ForNode(comptime Node: type) type {
    return struct {
        job: spans.JobContext,
        next_slot: u64 = 0,
        levels: [spans.MAX_SLOT_HEIGHT + 1]?Node = @splat(null),

        const Self = @This();
        /// V2 exact-count closure; each member is a proved V1 dyadic subtree.
        pub const ExactForest = @import("blake3_exact_forest.zig").ForNode(Node);
        pub fn init(job: spans.JobContext) !Self {
            try job.validate();
            return .{ .job = job };
        }
        pub fn deinit(self: *Self) void {
            for (&self.levels) |*level| if (level.*) |*node| node.deinit();
            self.* = undefined;
        }
        pub fn retainedNodes(self: *const Self) usize {
            var count: usize = 0;
            for (self.levels) |level| if (level != null) {
                count += 1;
            };
            return count;
        }
        /// Consume incoming only on success. On every failure both incoming and
        /// the frontier remain usable. context.fold borrows both child nodes,
        /// returning an independently verified owning parent.
        pub fn push(self: *Self, incoming: *Node, context: anytype) !void {
            try incoming.validate();
            if (!std.meta.eql(self.job, incoming.statement.job)) return error.StreamJobMismatch;
            if (incoming.statement.slots.first != self.next_slot) return error.StreamOutOfOrder;
            const first_height = incoming.statement.slots.height;
            var height: usize = first_height;
            var candidate: ?Node = null;
            defer if (candidate) |*node| node.deinit();
            while (self.levels[height]) |*left| {
                if (height + 1 >= self.levels.len) return error.StreamCapacityExceeded;
                const right = if (candidate) |*node| node else incoming;
                const expected = try spans.SpanStatement.fold(left.statement, right.statement);
                var parent = try context.fold(left, right);
                errdefer parent.deinit();
                try parent.validate();
                if (!std.meta.eql(expected, parent.statement)) return error.StreamFoldStatementMismatch;
                if (candidate) |*node| node.deinit();
                candidate = parent;
                height += 1;
            }
            // No fallible work follows publication. Older subtrees are released
            // only after the complete carry chain has verified successfully.
            for (first_height..height) |i| {
                self.levels[i].?.deinit();
                self.levels[i] = null;
            }
            self.next_slot = incoming.statement.slots.endExclusive();
            if (candidate) |node| {
                incoming.deinit();
                self.levels[height] = node;
                candidate = null;
            } else self.levels[height] = incoming.*;
            incoming.* = undefined;
        }
        /// Moves the complete independently verified root out. Incomplete jobs
        /// fail without discarding retained nodes.
        pub fn takeRoot(self: *Self) !Node {
            const height = self.job.slot_height;
            if (self.retainedNodes() != 1 or self.levels[height] == null)
                return error.IncompleteStream;
            _ = try self.levels[height].?.root();
            const node = self.levels[height].?;
            self.levels[height] = null;
            return node;
        }

        /// Moves an exact number of verified segment proofs out without
        /// rounding the proof count up to the next power of two. Members are
        /// ordered by slot; the number retained is popcount(segment_count).
        pub fn takeExactForest(self: *Self) !ExactForest {
            if (self.next_slot != self.job.segment_count) return error.IncompleteStream;
            var borrowed = ExactForest{ .job = self.job };
            for (0..self.levels.len) |offset| {
                const level = self.levels.len - offset - 1;
                if (self.levels[level]) |node| {
                    borrowed.nodes[borrowed.count] = node;
                    borrowed.count += 1;
                }
            }
            // No ownership changes before this complete, fallible admission.
            _ = try borrowed.validate();
            for (&self.levels) |*level| level.* = null;
            return borrowed;
        }
    };
}

const TestNode = struct {
    statement: spans.SpanStatement,
    token: *u8,
    fn init(statement: spans.SpanStatement) !TestNode {
        return .{ .statement = statement, .token = try std.testing.allocator.create(u8) };
    }
    pub fn validate(self: *const TestNode) !void {
        try self.statement.validate();
    }
    fn root(self: *const TestNode) !spans.RootStatement {
        return spans.RootStatement.init(self.statement);
    }
    pub fn deinit(self: *TestNode) void {
        std.testing.allocator.destroy(self.token);
        self.* = undefined;
    }
};
const TestFolder = struct {
    calls: usize = 0,
    fail_at: ?usize = null,
    wrong_statement: bool = false,
    fn fold(self: *TestFolder, left: *const TestNode, right: *const TestNode) !TestNode {
        self.calls += 1;
        if (self.fail_at == self.calls) return error.InjectedFailure;
        return TestNode.init(if (self.wrong_statement) left.statement else try spans.SpanStatement.fold(left.statement, right.statement));
    }
};
const fixture = @import("span_statement_blake3_test_fixture.zig");
test "stream frontier ownership scales logarithmically beyond sixteen segments" {
    // Ownership test, not a cryptographic performance measurement. Exercise
    // every carry boundary with allocation-owning nodes so leak checking also
    // covers disposal of superseded subtrees across deep trees.
    for ([_]u32{ 16, 32, 64, 1024, 4096 }) |count| {
        const job = try spans.JobContext.init(try spans.CompleteExecution.init(
            fixture.digest(0xff),
            fixture.digest(0xfe),
            try fixture.state(0, 0x80),
            try fixture.state(count * 4, 0x90),
            fixture.digest(0xfc),
            fixture.digest(0xfd),
            count,
        ), count);
        var stream = try ForNode(TestNode).init(job);
        defer stream.deinit();
        var folder = TestFolder{};
        for (0..count) |i| {
            const index: u32 = @intCast(i);
            var node = try TestNode.init(try spans.SpanStatement.segmentLeaf(job, index, try spans.ExecutedSpan.init(
                index,
                1,
                index,
                1,
                if (index == 0) job.complete.initial_state else try fixture.state(index * 4, 0x88),
                if (index + 1 == count) job.complete.final_state else try fixture.state((index + 1) * 4, 0x88),
                if (index == 0) try spans.EdgeClaim.present(job.complete.public_input) else spans.EdgeClaim.absent(),
                if (index + 1 == count) try spans.EdgeClaim.present(job.complete.public_output) else spans.EdgeClaim.absent(),
            )));
            try stream.push(&node, &folder);
            try std.testing.expectEqual(@as(usize, @popCount(index + 1)), stream.retainedNodes());
        }
        try std.testing.expectEqual(@as(usize, count - 1), folder.calls);
        var root = try stream.takeRoot();
        defer root.deinit();
        _ = try root.root();
        try std.testing.expectEqual(@as(usize, 0), stream.retainedNodes());
    }
}
fn testLeaf(job: spans.JobContext, index: u32) !TestNode {
    if (index >= job.segment_count) return TestNode.init(try spans.SpanStatement.emptyLeaf(job, index));
    return TestNode.init(try fixture.leaf(job, index, if (index == 0) job.complete.initial_state else try fixture.state(index * 4, 0x88), if (index + 1 == job.segment_count) job.complete.final_state else try fixture.state((index + 1) * 4, 0x88)));
}
test "stream frontier retains bounded nodes and requires authenticated padding" {
    const job = try fixture.job(3);
    var stream = try ForNode(TestNode).init(job);
    defer stream.deinit();
    var folder = TestFolder{};
    for (0..3) |index| {
        var node = try testLeaf(job, @intCast(index));
        try stream.push(&node, &folder);
        try std.testing.expect(stream.retainedNodes() <= 2);
    }
    try std.testing.expectError(error.IncompleteStream, stream.takeRoot());
    var padding = try testLeaf(job, 3);
    try stream.push(&padding, &folder);
    var root = try stream.takeRoot();
    defer root.deinit();
    _ = try root.root();
    try std.testing.expectEqual(@as(usize, 0), stream.retainedNodes());
}
test "stream frontier carry failure preserves input and all prior nodes" {
    for ([_]usize{ 1, 2 }) |failure| {
        const job = try fixture.job(4);
        var stream = try ForNode(TestNode).init(job);
        defer stream.deinit();
        var folder = TestFolder{};
        for (0..3) |index| {
            var node = try testLeaf(job, @intCast(index));
            try stream.push(&node, &folder);
        }
        var last = try testLeaf(job, 3);
        const token = last.token;
        folder.fail_at = folder.calls + failure;
        try std.testing.expectError(error.InjectedFailure, stream.push(&last, &folder));
        try std.testing.expectEqual(token, last.token);
        try std.testing.expectEqual(@as(u64, 3), stream.next_slot);
        try std.testing.expectEqual(@as(usize, 2), stream.retainedNodes());
        folder.fail_at = null;
        try stream.push(&last, &folder);
        var root = try stream.takeRoot();
        defer root.deinit();
        _ = try root.root();
    }
}

test "stream frontier rejects wrong order job and returned parent without mutation" {
    const job = try fixture.job(2);
    var stream = try ForNode(TestNode).init(job);
    defer stream.deinit();
    var folder = TestFolder{};
    var right = try testLeaf(job, 1);
    defer right.deinit();
    try std.testing.expectError(error.StreamOutOfOrder, stream.push(&right, &folder));
    var wrong_job = job;
    wrong_job.complete.program.bytes[0] ^= 1;
    var other = try testLeaf(wrong_job, 0);
    defer other.deinit();
    try std.testing.expectError(error.StreamJobMismatch, stream.push(&other, &folder));
    var left = try testLeaf(job, 0);
    try stream.push(&left, &folder);
    folder.wrong_statement = true;
    try std.testing.expectError(error.StreamFoldStatementMismatch, stream.push(&right, &folder));
    try std.testing.expectEqual(@as(usize, 1), stream.retainedNodes());
    try std.testing.expectEqual(@as(u64, 1), stream.next_slot);
}

fn exactJob(count: u32) !spans.JobContext {
    return spans.JobContext.init(try spans.CompleteExecution.init(
        fixture.digest(0xd1),
        fixture.digest(0xd2),
        try fixture.state(0, 0x80),
        try fixture.state(count * 4, 0x90),
        fixture.digest(0xd3),
        fixture.digest(0xd4),
        count * 4,
    ), count);
}

fn exactLeaf(job: spans.JobContext, index: u32) !TestNode {
    return TestNode.init(try spans.SpanStatement.segmentLeaf(job, index, try spans.ExecutedSpan.init(
        index,
        1,
        index * 4,
        4,
        if (index == 0) job.complete.initial_state else try fixture.state(index * 4, 0x88),
        if (index + 1 == job.segment_count) job.complete.final_state else try fixture.state((index + 1) * 4, 0x88),
        if (index == 0) try spans.EdgeClaim.present(job.complete.public_input) else spans.EdgeClaim.absent(),
        if (index + 1 == job.segment_count) try spans.EdgeClaim.present(job.complete.public_output) else spans.EdgeClaim.absent(),
    )));
}

test "exact-count V2 forest closes 3 5 13 and 218 segments without padding proofs" {
    for ([_]u32{ 3, 5, 13, 218 }) |count| {
        const job = try exactJob(count);
        var stream = try ForNode(TestNode).init(job);
        defer stream.deinit();
        var folder = TestFolder{};
        for (0..count) |i| {
            var leaf = try exactLeaf(job, @intCast(i));
            try stream.push(&leaf, &folder);
        }
        try std.testing.expectEqual(@as(usize, count - @popCount(count)), folder.calls);
        var forest = try stream.takeExactForest();
        defer forest.deinit();
        try std.testing.expectEqual(@as(usize, @popCount(count)), forest.count);
        try std.testing.expectEqual(@as(u64, count * 4), (try forest.validate()).cycle_count);
        const digest = try forest.rosterDigest();
        try std.testing.expect(!std.mem.eql(u8, &digest, &([_]u8{0} ** 32)));
        try std.testing.expectError(error.ExactForestTransportUnavailable, forest.validateTransportReady());
        try std.testing.expectEqual(@as(usize, 0), stream.retainedNodes());
    }
}

test "exact-count V2 forest rejects missing and reordered proof coverage" {
    const job = try exactJob(3);
    var stream = try ForNode(TestNode).init(job);
    defer stream.deinit();
    var folder = TestFolder{};
    for (0..2) |i| {
        var leaf = try exactLeaf(job, @intCast(i));
        try stream.push(&leaf, &folder);
    }
    try std.testing.expectError(error.IncompleteStream, stream.takeExactForest());
    try std.testing.expectEqual(@as(usize, 1), stream.retainedNodes());
    var leaf = try exactLeaf(job, 2);
    try stream.push(&leaf, &folder);
    var forest = try stream.takeExactForest();
    defer forest.deinit();
    std.mem.swap(TestNode, &forest.nodes[0], &forest.nodes[1]);
    try std.testing.expectError(error.StreamOutOfOrder, forest.validate());
}
