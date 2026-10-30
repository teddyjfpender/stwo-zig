//! Independent compact-global fixed-key/PCS compiler.
//! The complete epoch roster is reconstructed from public metadata; no live
//! endpoint rows, producer key or successful local receipt is accepted.
const std = @import("std");
const core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const S = core.proof_suites.Blake3;
const Original = @import("../prover/block_v8_compact_ram_proof_v1.zig");
const Scope = @import("../prover/block_v8_compact_ram_scope_v1.zig");
const Statement = @import("block_v8_compact_ram_statement_v1.zig");
const Shape = @import("block_v6_original_fixed_shape_v1.zig");
pub const RELATION_PAIRS: usize = 53;
pub const Limits = struct { original: Original.Limits = .{}, shape: Shape.Limits = .{} };
pub const Owned = struct {
    allocator: std.mem.Allocator,
    statement: *Statement.Owned,
    scope: Scope.Policy,
    claims: Original.Claims,
    draw_arena: std.heap.ArenaAllocator,
    components: *Original.Components(false),
    fixed: Original.Fixed,
    fixed_columns: []Engine.pcs.ColumnEvaluation,
    shape: Shape.Owned,
    fixed_root: [32]u8,
    seal: [32]u8,
    constraint_count: usize,
    limits: Limits,
    pub fn derive(a: std.mem.Allocator, metadata: *const Statement.Owned, proposed: Original.Claims, limits: Limits) !*Owned {
        const p = try a.create(Owned);
        errdefer a.destroy(p);
        p.allocator = a;
        p.limits = limits;
        p.statement = try Statement.Owned.init(a, metadata.trusted, metadata.input);
        errdefer p.statement.deinit();
        p.scope = p.statement.trusted.policy;
        inline for (.{ proposed.ram, proposed.boundary, proposed.ranges }) |group| for (group) |claim| {
            if (!@import("air/universal_provider_relations.zig").secureIsCanonical(&claim)) return error.NonCanonicalCompactRecursiveClaim;
        };
        p.claims = proposed;
        p.draw_arena = std.heap.ArenaAllocator.init(a);
        errdefer p.draw_arena.deinit();
        const drawn = try p.statement.input.epoch.draw(p.draw_arena.allocator());
        p.fixed = try Original.Fixed.init(a, p.scope, limits.original);
        errdefer p.fixed.deinit();
        p.components = try Original.Components(false).init(a, p.scope, drawn, p.claims);
        errdefer p.components.deinit();
        p.fixed_columns = try p.fixed.columns();
        errdefer a.free(p.fixed_columns);
        const all = core.air.components.Components{ .components = p.components.placed.?.handles, .n_preprocessed_columns = p.fixed_columns.len };
        var logs = try all.columnLogSizes(a);
        defer logs.deinitDeep(a);
        if (logs.items.len != Original.TRACE_TREES) return error.InvalidBridgeRecursiveShape;
        p.shape = try Shape.Owned.initForBoundedTraceTrees(a, logs.items, all, metadata.trusted.config, limits.shape, 255);
        errdefer p.shape.deinit();
        p.constraint_count = 0;
        for (all.components) |component| p.constraint_count += component.nConstraints();
        var key = try Engine.pcs.CommitmentSchemeProver(Cpu, S.Hasher, S.MerkleChannel).init(a, metadata.trusted.config);
        defer key.deinit(a);
        var ignored = S.Channel{};
        try key.commitBorrowedStreaming(a, p.fixed_columns, 8, &ignored);
        p.fixed_root = key.trees.items[0].root();
        if (!std.meta.eql(p.fixed_root, p.statement.input.roots[0])) return error.UntrustedCompactRecursiveFixedRoot;
        p.seal = p.identity();
        return p;
    }
    pub fn identity(p: *const Owned) [32]u8 {
        var ch = S.Channel{};
        ch.mixU32s(&.{ 0x42384346, 1, 7, p.scope.event_count, RELATION_PAIRS });
        ch.mixRoot(p.statement.input.epoch.digest);
        ch.mixRoot(p.scope.digest() catch unreachable);
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
        if (!std.meta.eql(capture.proof.commitments[0..4].*, p.statement.input.roots) or !capture.open.transition.eql(p.claims.ram[0])) return error.UntrustedCompactRecursiveCapture;
    }
    pub fn deinit(p: *Owned) void {
        const a = p.allocator;
        p.shape.deinit();
        p.components.deinit();
        p.fixed.deinit();
        p.draw_arena.deinit();
        a.free(p.fixed_columns);
        p.statement.deinit();
        a.destroy(p);
    }
};
