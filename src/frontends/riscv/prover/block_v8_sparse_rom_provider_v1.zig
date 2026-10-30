//! Sparse decoded-ROM provider under a new identity. FirstRound is only the
//! shared PCS storage carrier; legacy Plan/authority is never used for subsets.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const S = core.proof_suites.Blake3;
const Q = core.fields.qm31.QM31;
const Source = @import("block_v8_sparse_rom_v1.zig");
const Original = @import("block_v5_program_table_proof_v1.zig");
const Epoch = @import("block_v7_execution_epoch_v1.zig");
const Component = @import("block_v8_sparse_rom_component_v1.zig");
const Column = engine.pcs.ColumnEvaluation;
pub const Policy = struct {
    plan: *const Source.Owned,
    roots: [2][32]u8,
    epoch: Epoch.Epoch,
    entries: []const Epoch.Entry,
    pub fn entry(self: Policy) !Epoch.Entry {
        return firstEntry(self.plan, self.roots);
    }
    pub fn admit(self: Policy) !void {
        try self.epoch.requireEntry(self.entries, try self.entry());
    }
};
pub fn firstEntry(plan: *const Source.Owned, roots: [2][32]u8) !Epoch.Entry {
    return Epoch.Entry.init(.program, 0, plan.digest, &roots);
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        // Pure storage reuse, not legacy validation or proof dispatch.
        pub const FirstRound = Original.ForBackend(Backend).FirstRound;
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, S.Hasher, S.MerkleChannel);
        pub fn commit(a: std.mem.Allocator, plan: *const Source.Owned, config: core.pcs.PcsConfig) !FirstRound {
            const fixed = try plan.fixedColumns(a);
            defer for (fixed) |c| a.free(c.values);
            var scheme = try Scheme.init(a, config);
            errdefer scheme.deinit(a);
            scheme.setCoefficientRetentionPolicy(.always);
            var ch = S.Channel{};
            ch.mixU32s(&.{ Source.TAG, Source.VERSION, 6, 0 });
            ch.mixRoot(plan.digest);
            try scheme.commitBorrowedStreaming(a, &fixed, 8, &ch);
            try scheme.commitBorrowedStreaming(a, &.{}, 8, &ch);
            return .{ .scheme = scheme, .roots = .{ scheme.trees.items[0].root(), scheme.trees.items[1].root() }, .plan_digest = plan.digest };
        }
        pub fn requireFixedRoots(a: std.mem.Allocator, policy: Policy) !void {
            try policy.admit();
            var first = try commit(a, policy.plan, policy.epoch.config);
            defer first.deinit(a);
            if (!std.meta.eql(first.roots, policy.roots)) return error.UntrustedSparseRomFixedKey;
        }
    };
}
pub const Context = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    owner: *Component.Owner,
    policy: Policy,
    claims: Q,
    logs: [3][]u32,
    fixed_columns: []Column,
    interaction: []Column,
    provers: []engine.air.component_prover.ComponentProver,
    verifiers: []core.air.components.Component,
    pub fn recordAfterChallenges(self: *const Context, ch: anytype) !void {
        try Component.recordClaim(ch, self.policy.plan.digest, self.claims);
        (try self.policy.entry()).mix(ch);
    }
    pub fn deinit(self: *Context) void {
        const a = self.allocator;
        self.owner.deinit();
        self.arena.deinit();
        a.destroy(self);
    }
};
fn finish(a: std.mem.Allocator, policy: Policy, claim: ?Q) !*Context {
    const self = try a.create(Context);
    errdefer a.destroy(self);
    self.allocator = a;
    self.arena = std.heap.ArenaAllocator.init(a);
    errdefer self.arena.deinit();
    const t = self.arena.allocator();
    const drawn = try policy.epoch.draw(t);
    const owner = try Component.Owner.create(a, policy.plan, drawn.word.universal_prefix, claim);
    errdefer owner.deinit();
    self.owner = owner;
    self.policy = policy;
    self.claims = owner.claim;
    self.fixed_columns = &owner.fixed;
    self.interaction = owner.interaction;
    inline for (.{ 6, 0, 4 }, 0..) |count, i| {
        self.logs[i] = try t.alloc(u32, count);
        @memset(self.logs[i], policy.plan.log_size);
    }
    self.provers = try t.alloc(engine.air.component_prover.ComponentProver, 1);
    self.provers[0] = owner.prover;
    self.verifiers = try t.alloc(core.air.components.Component, 1);
    self.verifiers[0] = owner.verifier;
    return self;
}
pub fn prepare(comptime Backend: type, a: std.mem.Allocator, first: *const ForBackend(Backend).FirstRound, policy: Policy) !*Context {
    try policy.admit();
    if (!first.owns_scheme or !std.meta.eql(first.scheme.config, policy.epoch.config) or !std.meta.eql(first.plan_digest, policy.plan.digest) or !std.meta.eql(first.roots, policy.roots)) return error.UntrustedSparseRomFirstRound;
    return finish(a, policy, null);
}
pub fn verifier(comptime Backend: type, a: std.mem.Allocator, policy: Policy, claim: Q) !*Context {
    try ForBackend(Backend).requireFixedRoots(a, policy);
    return finish(a, policy, claim);
}
