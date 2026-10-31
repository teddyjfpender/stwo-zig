//! One concrete retained fixed-tree owner. No request/witness data enter here.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const P = @import("../../protocol.zig");
pub const Key = struct {
    allocator: std.mem.Allocator,
    root: [32]u8,
    tree: P.T.Scheme.CommittedTree,
    pub fn seal(a: std.mem.Allocator, columns: []const engine.pcs.ColumnEvaluation) !Key {
        var scheme = try P.T.Scheme.init(a, P.T.P.config());
        defer scheme.deinit(a);
        scheme.setCompactPolynomialStorage(5);
        var ch = P.T.P.Channel{};
        try scheme.commitBorrowedStreaming(a, columns, 8, &ch);
        var roots = try scheme.roots(a);
        defer roots.deinit(a);
        try scheme.trees.items[0].share(a);
        return .{ .allocator = a, .root = roots.items[0], .tree = scheme.trees.pop().? };
    }
    pub fn append(self: *const Key, a: std.mem.Allocator, scheme: *P.T.Scheme, ch: *P.T.P.Channel) !void {
        if (scheme.trees.items.len != 0 or scheme.pending_commit != null or !std.meta.eql(scheme.config, P.T.P.config()) or scheme.revision_config != null) return error.InvalidSharedTruthFixedPhase;
        var tree = self.tree.retainShared();
        errdefer tree.deinit(self.allocator);
        try scheme.appendCommittedTree(a, tree, ch);
    }
    pub fn deinit(self: *Key) void {
        self.tree.deinit(self.allocator);
    }
};
