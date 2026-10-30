//! Independent fixed-key/PCS compiler for a runtime-bounded bridge batch.
//! The complete epoch roster is reconstructed from public metadata; no live
//! endpoint rows, producer key or successful local receipt is accepted.
const std = @import("std");
const core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const S = core.proof_suites.Blake3;
const Original = @import("../prover/block_v8_endpoint_global_bridge_proof_v1.zig");
const Scope = @import("../prover/block_v8_endpoint_global_bridge_scope_v1.zig");
const Statement = @import("block_v8_endpoint_bridge_statement_v1.zig");
const Shape = @import("block_v6_original_fixed_shape_v1.zig");
const Q = core.fields.qm31.QM31;
pub const RELATION_PAIRS: usize = 53;
pub const Limits = struct { original: Original.Limits = .{}, shape: Shape.Limits = .{} };
pub const Owned = struct {
    allocator: std.mem.Allocator,
    statement: *Statement.Owned,
    scope: *const Scope.Owned,
    claims: []Q,
    draw_arena: std.heap.ArenaAllocator,
    components: Original.Components(false),
    fixed: Original.Fixed,
    shape: Shape.Owned,
    fixed_root: [32]u8,
    seal: [32]u8,
    constraint_count: usize,
    limits: Limits,
    pub fn derive(a: std.mem.Allocator, metadata: *const Statement.Owned, proposed: []const Q, limits: Limits) !*Owned {
        if (proposed.len != metadata.scope.sources.len or proposed.len == 0 or proposed.len > Scope.MAX_BATCH_SOURCES) return error.InvalidBridgeRecursiveClaims;
        for (proposed) |claim| if (!@import("air/universal_provider_relations.zig").secureIsCanonical(&claim)) return error.InvalidBridgeRecursiveClaims;
        const p = try a.create(Owned);
        errdefer a.destroy(p);
        p.allocator = a;
        p.limits = limits;
        p.statement = try Statement.Owned.init(a, metadata.trusted, metadata.input);
        errdefer p.statement.deinit();
        p.scope = &p.statement.scope;
        p.claims = try a.dupe(Q, proposed);
        errdefer a.free(p.claims);
        p.draw_arena = std.heap.ArenaAllocator.init(a);
        errdefer p.draw_arena.deinit();
        const drawn = try p.scope.epoch.draw(p.draw_arena.allocator());
        p.fixed = try Original.Fixed.init(a, p.scope.*, limits.original.fixed_bytes);
        errdefer p.fixed.deinit();
        p.components = try Original.Components(false).init(a, p.scope.*, drawn, p.claims);
        errdefer p.components.deinit();
        const all = core.air.components.Components{ .components = p.components.placement.handles, .n_preprocessed_columns = p.fixed.columns.len };
        var logs = try all.columnLogSizes(a);
        defer logs.deinitDeep(a);
        if (logs.items.len != p.scope.traceTrees()) return error.InvalidBridgeRecursiveShape;
        p.shape = try Shape.Owned.initForBoundedTraceTrees(a, logs.items, all, metadata.trusted.config, limits.shape, 255);
        errdefer p.shape.deinit();
        p.constraint_count = p.scope.sources.len;
        for (all.components) |component| if (component.nConstraints() != 1) return error.InvalidBridgeRecursiveConstraintCount;
        var key = try Engine.pcs.CommitmentSchemeProver(Cpu, S.Hasher, S.MerkleChannel).init(a, metadata.trusted.config);
        defer key.deinit(a);
        var ignored = S.Channel{};
        try key.commitBorrowedStreaming(a, p.fixed.columns, 8, &ignored);
        p.fixed_root = key.trees.items[0].root();
        p.seal = p.identity();
        return p;
    }
    pub fn identity(p: *const Owned) [32]u8 {
        var ch = S.Channel{};
        ch.mixU32s(&.{ 0x42384246, 1, @intCast(p.scope.traceTrees()), @intCast(p.scope.roster_count), p.scope.batch_start, @intCast(p.scope.sources.len), RELATION_PAIRS });
        ch.mixRoot(p.scope.epoch.digest);
        ch.mixRoot(p.fixed_root);
        ch.mixRoot(p.shape.deepProfile().identityDigest());
        ch.mixRoot(p.shape.friProfile().identityDigest());
        ch.mixU32s(&.{ p.shape.split, p.shape.composition_log, p.shape.mask_log, p.shape.lifting_log });
        for (p.shape.columns) |logs| {
            ch.mixU64(logs.len);
            ch.mixU32s(logs);
        }
        return ch.digestBytes();
    }
    pub fn validate(p: *const Owned) !void {
        if (!std.meta.eql(p.seal, p.identity())) return error.MutatedBridgeRecursiveProfile;
    }
    pub fn requireCapture(p: *const Owned, capture: *const Original.VerifiedCapture) !void {
        try p.validate();
        if (capture.proof.commitments.len != p.shape.columns.len or !std.meta.eql(capture.proof.commitments[0], p.fixed_root)) return error.UntrustedBridgeRecursiveCapture;
        for (p.scope.sources, 0..) |source, index| if (!std.meta.eql(capture.proof.commitments[1 + index], source.endpoint_root)) return error.UntrustedBridgeRecursiveCapture;
        var sum = Q.zero();
        for (p.claims) |claim| sum = sum.add(claim);
        if (!sum.eql(capture.transition)) return error.UntrustedBridgeRecursiveCapture;
    }
    pub fn deinit(p: *Owned) void {
        const a = p.allocator;
        p.shape.deinit();
        p.components.deinit();
        p.fixed.deinit();
        p.draw_arena.deinit();
        a.free(p.claims);
        p.statement.deinit();
        a.destroy(p);
    }
};
