//! A bounded lease of ONLY the endpoint's 23-column PCS tree. This is proving
//! storage, not verification authority. It cannot attest that a local proof
//! verified, and must never stand in for the receiver's exact-root check.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const S = core.proof_suites.Blake3;
pub const Scheme = engine.pcs.CommitmentSchemeProver(Cpu, S.Hasher, S.MerkleChannel);
pub const Tree = Scheme.CommitmentTree;
const Budget = engine.host_budget_allocator.SharedHostBudget;
const Kernel = @import("block_v8_ram_endpoint_kernel_v1.zig");
pub const Owned = struct {
    allocator: std.mem.Allocator,
    budget: *Budget,
    tree: Tree,
    config: core.pcs.PcsConfig,
    raw_log: u32,
    retained_bytes: usize,
    pub fn acquire(a: std.mem.Allocator, scheme: *Scheme, expected_root: [32]u8, raw_log: u32, max_bytes: usize) !*Owned {
        return acquireAt(a, scheme, 2, expected_root, raw_log, max_bytes);
    }
    /// Group placement selects this index independently from public geometry.
    /// An index grants no authority: the exact root, width, logs, coefficients
    /// and owned backing must still satisfy all the original lease checks.
    pub fn acquireAt(a: std.mem.Allocator, scheme: *Scheme, tree_index: usize, expected_root: [32]u8, raw_log: u32, max_bytes: usize) !*Owned {
        const budget = Budget.fromAllocator(a) orelse return error.EndpointRetentionRequiresBudget;
        if (raw_log > 24 or max_bytes == 0 or tree_index >= scheme.trees.items.len) return error.InvalidEndpointRetention;
        const tree = &scheme.trees.items[tree_index];
        if (!std.meta.eql(tree.root(), expected_root) or tree.columns.len != Kernel.COLUMN_COUNT or tree.coefficients == null or tree.coefficients.?.len != Kernel.COLUMN_COUNT or tree.backing_teardown != null or tree.borrowed_column_values)
            return error.InvalidEndpointRetention;
        var bytes: usize = 64 << 10; // bounded descriptors/alignment overhead
        const lde_log = try std.math.add(u32, raw_log, scheme.config.fri_config.log_blowup_factor);
        for (tree.columns, tree.coefficients.?) |column, polynomial| {
            if (column.log_size != lde_log or polynomial.logSize() != raw_log) return error.InvalidEndpointRetention;
            bytes = try std.math.add(usize, bytes, try std.math.mul(usize, column.values.len, @sizeOf(core.fields.m31.M31)));
            bytes = try std.math.add(usize, bytes, try std.math.mul(usize, polynomial.coeffs.len, @sizeOf(core.fields.m31.M31)));
        }
        for (tree.commitment.layers) |layer| bytes = try std.math.add(usize, bytes, try std.math.mul(usize, layer.len, @sizeOf(S.Hasher.Hash)));
        if (bytes > max_bytes) return error.EndpointRetentionResourceLimit;
        const self = try a.create(Owned);
        errdefer a.destroy(self);
        try tree.share(a);
        self.* = .{ .allocator = a, .budget = budget.retain(), .tree = tree.retainShared(), .config = scheme.config, .raw_log = raw_log, .retained_bytes = bytes };
        return self;
    }
    /// The borrowed source lease must remain live during acquisition. The
    /// bridge checks its fresh local-proof roster before adopting this tree.
    pub fn retainTree(self: *const Owned, expected_root: [32]u8, config: core.pcs.PcsConfig, raw_log: u32) !Tree {
        if (!std.meta.eql(self.tree.root(), expected_root) or !std.meta.eql(self.config, config) or self.raw_log != raw_log)
            return error.UntrustedEndpointRetention;
        return self.tree.retainShared();
    }
    pub fn deinit(self: *Owned) void {
        const a = self.allocator;
        const budget = self.budget;
        self.tree.deinit(a);
        a.destroy(self);
        budget.destroy();
    }
};
