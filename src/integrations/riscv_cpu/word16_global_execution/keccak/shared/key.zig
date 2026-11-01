//! One concrete retained fixed-tree owner. No request/witness data enter here.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const P = @import("../../protocol.zig");
pub const NativeCache = @import("../../../word16_execution/fixed_native_cache.zig");
const SuiteType = @import("../../../word16_execution/pcs_suite.zig").Suite;
pub const Key = struct {
    pub const Suite = SuiteType;
    suite: Suite = Suite.production(),
    allocator: std.mem.Allocator,
    root: [32]u8,
    tree: P.T.Scheme.CommittedTree,
    pub fn seal(a: std.mem.Allocator, columns: []const engine.pcs.ColumnEvaluation) !Key {
        return sealWithSuite(a, columns, Suite.production());
    }
    pub fn sealWithSuite(a: std.mem.Allocator, columns: []const engine.pcs.ColumnEvaluation, suite: Suite) !Key {
        return sealWithSuiteAndCache(a, columns, suite, null);
    }
    pub fn sealWithCache(a: std.mem.Allocator, columns: []const engine.pcs.ColumnEvaluation, cache: ?*const NativeCache.Cache) !Key {
        return sealWithSuiteAndCache(a, columns, Suite.production(), cache);
    }
    pub fn sealWithSuiteAndCache(a: std.mem.Allocator, columns: []const engine.pcs.ColumnEvaluation, suite: Suite, cache: ?*const NativeCache.Cache) !Key {
        try suite.validate();
        var scheme = try P.T.Scheme.init(a, suite.config());
        defer scheme.deinit(a);
        scheme.setCompactPolynomialStorage(5);
        var ch = P.T.P.Channel{};
        try scheme.commitBorrowedStreaming(a, columns, 8, &ch);
        var roots = try scheme.roots(a);
        defer roots.deinit(a);
        if (cache) |owner| _ = try owner.internTree(a, &scheme.trees.items[0]);
        try scheme.trees.items[0].share(a);
        return .{ .allocator = a, .suite = suite, .root = roots.items[0], .tree = scheme.trees.pop().? };
    }
    pub fn append(self: *const Key, a: std.mem.Allocator, scheme: *P.T.Scheme, ch: *P.T.P.Channel) !void {
        try self.suite.validate();
        if (scheme.trees.items.len != 0 or scheme.pending_commit != null or !std.meta.eql(scheme.config, self.suite.config()) or scheme.revision_config != null) return error.InvalidSharedTruthFixedPhase;
        var tree = self.tree.retainShared();
        errdefer tree.deinit(self.allocator);
        try scheme.appendCommittedTree(a, tree, ch);
    }
    pub fn deinit(self: *Key) void {
        self.tree.deinit(self.allocator);
    }
};
