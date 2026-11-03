//! One concrete retained fixed-tree owner. No request/witness data enter here.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const P = @import("../../protocol.zig");
pub const NativeCache = @import("../../../word16_execution/fixed_native_cache.zig");
const SuiteType = @import("../../../word16_execution/pcs_suite.zig").Suite;
/// Optional receiver-owned setup seam (`ethereum/setup_cache.zig`). The owner
/// arms it on its own thread around exactly one setup component construction
/// whose sealed key is a pure function of receiver-owned identity, and disarms
/// it straight afterwards. Unarmed (every other caller), every seal is the
/// historical commit. The seam may only return a key whose root the receiver
/// itself derived (an authenticated artifact it wrote, or an identity-only
/// source where no statement binds the source root); it never sees producer bytes.
pub const SealSeam = struct {
    ctx: *anyopaque,
    /// A complete key in place of the commit, or null to commit normally.
    seal: *const fn (ctx: *anyopaque, a: std.mem.Allocator, columns: []const engine.pcs.ColumnEvaluation, suite: SuiteType, cache: ?*const NativeCache.Cache) anyerror!?Key,
};
threadlocal var seal_seam: ?SealSeam = null;
pub fn armSealSeam(seam: SealSeam) void {
    seal_seam = seam;
}
pub fn disarmSealSeam() void {
    seal_seam = null;
}
const Tree = P.T.Scheme.CommittedTree;
const Merkle = @FieldType(Tree, "commitment");
const Coefficient = engine.poly.circle.CircleCoefficients;
pub const Key = struct {
    pub const Suite = SuiteType;
    suite: Suite = Suite.production(),
    allocator: std.mem.Allocator,
    root: [32]u8,
    tree: P.T.Scheme.CommittedTree,
    /// No Merkle nodes: the key carries its source identity (root, suite,
    /// column shape) and, for identity-only keys, coefficients. It can feed a
    /// receiver-derived candidate fixed authority but never a PCS (append()).
    root_only: bool = false,
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
        if (seal_seam) |seam| if (try seam.seal(seam.ctx, a, columns, suite, cache)) |key| return key;
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
        if (self.root_only) return error.RootOnlySharedTruthKey;
        if (scheme.trees.items.len != 0 or scheme.pending_commit != null or !std.meta.eql(scheme.config, self.suite.config()) or scheme.revision_config != null) return error.InvalidSharedTruthFixedPhase;
        var tree = self.tree.retainShared();
        errdefer tree.deinit(self.allocator);
        try scheme.appendCommittedTree(a, tree, ch);
    }
    pub fn deinit(self: *Key) void {
        self.tree.deinit(self.allocator);
    }
    /// Root-only key from an authenticated receiver artifact: the tree has the
    /// committed (extended) column log sizes and the root, no values,
    /// coefficients or nodes.
    pub fn rootOnly(a: std.mem.Allocator, suite: Suite, root: [32]u8, column_logs: []const u32) !Key {
        try suite.validate();
        var tree = try shapeTree(a, root, column_logs, null, null);
        errdefer tree.deinit(a);
        try tree.share(a);
        return .{ .allocator = a, .suite = suite, .root = root, .tree = tree, .root_only = true };
    }
    /// Identity-only source: exact interpolated coefficients of `columns`
    /// (the same polynomials a commit retains) under a domain-separated
    /// collision-resistant digest instead of a Merkle root. For receivers whose
    /// statements bind only the derived candidate fixed identity/root, never
    /// this source root. No extension or Merkle commitment is computed.
    pub fn identityOnly(a: std.mem.Allocator, columns: []const engine.pcs.ColumnEvaluation, suite: Suite, cache: ?*const NativeCache.Cache) !Key {
        try suite.validate();
        if (columns.len == 0) return error.EmptySharedTruthKey;
        for (columns) |column| {
            if (column.log_size < 1 or column.log_size > 28 or column.values.len != (@as(usize, 1) << @intCast(column.log_size))) return error.InvalidSharedTruthKeyShape;
        }
        const blowup = suite.config().fri_config.log_blowup_factor;
        const Twiddles = @typeInfo(@typeInfo(@TypeOf(engine.poly.twiddles.precomputeM31)).@"fn".return_type.?).error_union.payload;
        var twiddles: [29]?Twiddles = @splat(null);
        defer for (&twiddles) |*t| if (t.*) |*tree| engine.poly.twiddles.deinitM31(a, tree);
        const coefficients = try a.alloc(Coefficient, columns.len);
        var filled: usize = 0;
        var adopted = false;
        errdefer if (!adopted) {
            for (coefficients[0..filled]) |*c| c.deinit(a);
            a.free(coefficients);
        };
        // Exact field interpolation in column order: these are the very
        // polynomials a commit of `columns` retains.
        for (columns, coefficients) |column, *out| {
            const domain = engine.poly.circle.CanonicCoset.new(column.log_size).circleDomain();
            if (twiddles[column.log_size] == null) twiddles[column.log_size] = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
            const t = twiddles[column.log_size].?;
            const owned = try a.dupe(@TypeOf(column.values[0]), column.values);
            out.* = engine.poly.circle.poly.interpolateOwnedValuesWithTwiddles(domain, owned, .{ .root_coset = t.root_coset, .twiddles = t.twiddles, .itwiddles = t.itwiddles }) catch |err| {
                a.free(owned);
                return err;
            };
            filled += 1;
        }
        const logs = try a.alloc(u32, columns.len);
        defer a.free(logs);
        for (columns, logs) |column, *l| l.* = column.log_size + blowup;
        const root = try identityRoot(a, suite, coefficients, logs);
        var tree = try shapeTree(a, root, logs, coefficients, null);
        adopted = true;
        errdefer tree.deinit(a);
        if (cache) |owner| _ = try owner.internTree(a, &tree);
        try tree.share(a);
        return .{ .allocator = a, .suite = suite, .root = root, .tree = tree, .root_only = true };
    }
};
/// Domain-separated chunked SHA-256 over suite, shape and every coefficient;
/// the identity of an identity-only source (never mixed into a transcript).
fn identityRoot(a: std.mem.Allocator, suite: SuiteType, coefficients: []const Coefficient, logs: []const u32) ![32]u8 {
    var header = std.ArrayList(u8).empty;
    defer header.deinit(a);
    try header.appendSlice(a, "rv64-identity-only-fixed-source/v1\x00");
    try header.appendSlice(a, &(try suite.identity()));
    var word: [8]u8 = undefined;
    std.mem.writeInt(u64, &word, coefficients.len, .little);
    try header.appendSlice(a, &word);
    const slices = try a.alloc([]const u8, coefficients.len);
    defer a.free(slices);
    for (coefficients, logs, slices) |c, log, *slice| {
        std.mem.writeInt(u32, word[0..4], log, .little);
        std.mem.writeInt(u32, word[4..8], c.log_size, .little);
        try header.appendSlice(a, &word);
        slice.* = std.mem.sliceAsBytes(c.coeffs);
    }
    return engine.chunked_sha256.digest(a, header.items, slices, engine.chunked_sha256.default_chunk_bytes);
}
/// Tree descriptor with `logs` (committed heights), optional coefficient views
/// (compact storage) and a root-only node set. Takes ownership of
/// `coefficients` on success.
pub fn shapeTree(a: std.mem.Allocator, root: [32]u8, logs: []const u32, coefficients: ?[]Coefficient, coefficient_backing: ?[][]@import("stwo_core").fields.m31.M31) !Tree {
    if (logs.len == 0) return error.EmptySharedTruthKey;
    var max: u32 = 0;
    for (logs) |log| {
        if (log > 30) return error.InvalidSharedTruthKeyShape;
        max = @max(max, log);
    }
    const columns = try a.alloc(engine.pcs.ColumnEvaluation, logs.len);
    errdefer a.free(columns);
    for (columns, logs, 0..) |*c, log, i| c.* = .{ .log_size = log, .values = &.{}, .coefficient_values = if (coefficients) |cs| cs[i].coeffs else null };
    const layers = try Merkle.allocateLayersPruned(a, max, max);
    layers[0][0] = root;
    var tree = Tree.initPrecommitted(columns, coefficients, null, coefficient_backing, Merkle.fromLayers(a, layers));
    tree.compact_polynomials = true;
    return tree;
}
