//! Reuse admitted CPU fixed polynomials without interpolating/extending them
//! again. The merged Merkle tree is recomputed in exact family/column order.
//! This is prover storage reuse, never verifier fixed-root authority.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const S = core.proof_suites.Blake3;
const Scheme = engine.pcs.CommitmentSchemeProver(Cpu, S.Hasher, S.MerkleChannel);
const Tree = Scheme.CommitmentTree;
const Column = engine.pcs.ColumnEvaluation;
const Polynomial = engine.poly.circle.CircleCoefficients;
const Budget = engine.host_budget_allocator.SharedHostBudget;
/// Storage selection only: never changes transcript, commitment order or keys.
pub const Policy = enum { reuse_if_available, reuse_required, rebuild };

pub const Source = struct {
    allocator: std.mem.Allocator,
    scheme: *Scheme,
    expected_root: [32]u8,
    raw_logs: []const u32,
};
const Lease = struct {
    tree: Tree,
    budget: ?*Budget,
    allocator: std.mem.Allocator,
    fn deinit(self: *Lease) void {
        self.tree.deinit(self.allocator);
        if (self.budget) |budget| budget.destroy();
    }
};
const Owner = struct {
    allocator: std.mem.Allocator,
    leases: []Lease,
    initialized: usize = 0,
    fn deinit(self: *Owner) void {
        const a = self.allocator;
        for (self.leases[0..self.initialized]) |*lease| lease.deinit();
        a.free(self.leases);
        a.destroy(self);
    }
    fn release(context: ?*anyopaque, _: u64) void {
        const self: *Owner = @ptrCast(@alignCast(context.?));
        self.deinit();
    }
};

/// Return false only for a validated source with unavailable resident LDE or
/// coefficients; caller must then use its original raw fixed reconstruction.
/// Every acquired source lease is unwound on error. Original source allocators
/// must remain valid; direct SharedHostBudget allocators are retained here.
pub fn tryAppend(a: std.mem.Allocator, destination: *Scheme, sources: []const Source, channel: *S.Channel) !bool {
    if (destination.trees.items.len != 0 or sources.len == 0 or sources.len > 256) return error.InvalidUnionFixedReuseSources;
    var available = true;
    var total: usize = 0;
    for (sources) |source| {
        if (!std.meta.eql(source.scheme.config, destination.config) or source.scheme.trees.items.len == 0) return error.UntrustedUnionFixedReuseConfig;
        const tree = &source.scheme.trees.items[0];
        if (!std.meta.eql(tree.root(), source.expected_root)) return error.UntrustedUnionFixedReuseRoot;
        if (tree.columns.len != source.raw_logs.len) return error.UntrustedUnionFixedReuseGeometry;
        total = try std.math.add(usize, total, tree.columns.len);
        if (tree.coefficients) |coefficients| {
            if (coefficients.len != tree.columns.len) return error.UntrustedUnionFixedReuseGeometry;
            for (coefficients, source.raw_logs) |coefficient, log| if (coefficient.logSize() != log) return error.UntrustedUnionFixedReuseGeometry;
        } else available = false;
        for (tree.columns, source.raw_logs) |column, log| {
            if (column.log_size != try std.math.add(u32, log, destination.config.fri_config.log_blowup_factor)) return error.UntrustedUnionFixedReuseGeometry;
            try column.validateRetained();
            if (column.values.len == 0) available = false;
        }
    }
    if (!available) return false;
    // Compaction mutates/frees polynomial storage. A borrowed view retains its
    // sources' policy rather than changing those sources through an alias.
    if (destination.compact_polynomial_storage or destination.config.lifting_log_size != null) return false;
    const owner = try a.create(Owner);
    owner.* = .{ .allocator = a, .leases = &.{} };
    var owns = true;
    defer if (owns) owner.deinit();
    owner.leases = try a.alloc(Lease, sources.len);
    for (sources, owner.leases) |source, *lease| {
        const tree = &source.scheme.trees.items[0];
        try tree.share(source.allocator);
        const budget = Budget.fromAllocator(source.allocator);
        lease.* = .{ .tree = tree.retainShared(), .allocator = source.allocator, .budget = if (budget) |b| b.retain() else null };
        owner.initialized += 1;
    }
    var descriptor_ownership = true;
    const columns = try a.alloc(Column, total);
    errdefer if (descriptor_ownership) a.free(columns);
    const coefficients = try a.alloc(Polynomial, total);
    errdefer if (descriptor_ownership) a.free(coefficients);
    const refs = try a.alloc([]const core.fields.m31.M31, total);
    defer a.free(refs);
    var at: usize = 0;
    for (owner.leases) |lease| for (lease.tree.columns, lease.tree.coefficients.?) |column, coefficient| {
        columns[at] = column;
        coefficients[at] = try Polynomial.initBorrowed(coefficient.coefficients());
        refs[at] = column.values;
        at += 1;
    };
    const commitment = try Cpu.commitMerkle(S.Hasher, a, refs);
    // appendCommittedTree takes ownership only on success. Keep the single
    // unwind path above active until descriptor, commitment and lease adoption.
    var tree = Tree.initBorrowedPrecommitted(columns, coefficients, commitment, engine.pcs.BackingTeardownToken.init(owner, 0, Owner.release));
    descriptor_ownership = false;
    owns = false;
    errdefer tree.deinit(a);
    try destination.appendCommittedTree(a, tree, channel);
    return true;
}
