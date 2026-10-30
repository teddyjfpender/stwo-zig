//! Independently reconstructed Mixed original-verifier profile. Runtime tree
//! placement is derived from the finite V1/V2 public member roster, never from
//! a producer key, capture, trace, receipt or arbitrary proposed tree map.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const S = core.proof_suites.Blake3;
const Original = @import("../prover/block_v8_endpoint_mixed_proof_v1.zig");
const Scope = @import("../prover/block_v8_endpoint_mixed_scope_v1.zig");
const Context = @import("../prover/block_v8_endpoint_mixed_context_v1.zig").For(false);
const Ledger = @import("../prover/block_v8_endpoint_mixed_ledger_v1.zig");
const Statement = @import("../prover/block_v8_endpoint_mixed_statement_v1.zig");
const Shape = @import("block_v6_original_fixed_shape_v1.zig");
const MixedShape = @import("../prover/block_v8_endpoint_mixed_shape_v1.zig");
const Fields = @import("../prover/block_v7_union_claim_wire_v1.zig");
pub const production_active = false;
pub const RELATION_PAIRS: usize = 67;
pub const Limits = struct { original: Original.Limits = .{}, shape: Shape.Limits = .{}, max_claim_bytes: usize = 16 << 20, max_claim_items: usize = 1 << 20 };
pub const Owned = struct {
    a: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    statement: *Statement.Owned,
    claims: Ledger.Claims,
    scope: *Scope.Owned,
    context: *Context,
    shape: Shape.Owned,
    fixed_root: [32]u8,
    constraint_count: usize,
    seal: [32]u8,
    limits: Limits,
    pub fn derive(a: std.mem.Allocator, metadata: *const Statement.Owned, claims: Ledger.Claims, limits: Limits) !*Owned {
        if (limits.max_claim_bytes == 0 or limits.max_claim_items == 0) return error.MixedOriginalProfileResourceLimit;
        const self = try a.create(Owned);
        errdefer a.destroy(self);
        self.a = a;
        self.limits = limits;
        self.arena = std.heap.ArenaAllocator.init(a);
        errdefer self.arena.deinit();
        self.statement = try Statement.Owned.init(a, metadata.trusted, metadata.input);
        errdefer self.statement.deinit();
        var writer = @import("../prover/bounded_artifact_writer_v1.zig").Writer.init(a, limits.max_claim_bytes);
        defer writer.deinit();
        var remaining = limits.max_claim_items;
        try Fields.encode(Ledger.Claims, &writer, claims, &remaining);
        var cursor = @import("../prover/guest_precompile/proof_artifact_wire.zig").Cursor.init(writer.bytes.items);
        remaining = limits.max_claim_items;
        self.claims = try Fields.decode(Ledger.Claims, self.arena.allocator(), &cursor, &remaining);
        try cursor.requireDone();
        self.scope = try Scope.Owned.init(a, self.statement.trusted, self.statement.input, limits.original.scope);
        errdefer self.scope.deinit();
        self.context = try Context.create(a, self.scope, self.statement.input, null, self.claims, limits.original.context);
        errdefer self.context.deinit();
        var fixed = try self.context.fixedColumns();
        defer fixed.deinit();
        const all = core.air.components.Components{ .components = self.context.combined.?.handles, .n_preprocessed_columns = fixed.columns.len };
        var geometry = try MixedShape.Owned.init(a, self.scope, self.statement.input);
        defer geometry.deinit();
        self.shape = try Shape.Owned.initForBoundedTraceTrees(a, &geometry.logs, all, metadata.trusted.config, limits.shape, 255);
        errdefer self.shape.deinit();
        if (self.shape.columns.len != 15) return error.InvalidMixedRecursiveShape;
        self.constraint_count = 0;
        for (all.components) |component| self.constraint_count = try std.math.add(usize, self.constraint_count, component.nConstraints());
        var scheme = try E.pcs.CommitmentSchemeProver(Cpu, S.Hasher, S.MerkleChannel).init(a, metadata.trusted.config);
        defer scheme.deinit(a);
        var ignored = S.Channel{};
        try scheme.commitBorrowedStreaming(a, fixed.columns, 8, &ignored);
        self.fixed_root = scheme.trees.items[0].root();
        if (!std.meta.eql(self.fixed_root, metadata.input.native_roots[0])) return error.UntrustedMixedRecursiveFixedRoot;
        self.seal = self.identity();
        return self;
    }
    pub fn identity(self: *const Owned) [32]u8 {
        var ch = S.Channel{};
        ch.mixU32s(&.{ 0x42384d46, 1, 14, 7, self.scope.external, self.statement.input.shape.native_shard_version, RELATION_PAIRS, @intCast(self.constraint_count) });
        ch.mixRoot(self.scope.identity);
        ch.mixRoot(self.scope.epoch.digest);
        ch.mixRoot(self.fixed_root);
        ch.mixRoot(self.shape.deepProfile().identityDigest());
        ch.mixRoot(self.shape.friProfile().identityDigest());
        ch.mixU32s(&.{ self.shape.split, self.shape.composition_log, self.shape.mask_log, self.shape.lifting_log });
        for (self.shape.columns) |columns| {
            ch.mixU64(columns.len);
            ch.mixU32s(columns);
        }
        return ch.digestBytes();
    }
    pub fn validate(self: *const Owned) !void {
        if (!std.meta.eql(self.seal, self.identity())) return error.MutatedMixedRecursiveProfile;
    }
    pub fn requireCapture(self: *const Owned, captured: *const Original.VerifiedCapture) !void {
        try self.validate();
        const roots = captured.proof.commitments;
        const i = self.statement.input;
        if (roots.len != 15 or !std.meta.eql(roots[0], self.fixed_root) or !std.meta.eql(roots[1], i.native_roots[1]) or !std.meta.eql(roots[2], i.native_roots[2]) or !std.meta.eql(roots[3], i.native_roots[3]) or !std.meta.eql(roots[4], i.program_roots[1]) or !std.meta.eql(roots[5], i.lookup_roots[1]) or !std.meta.eql(roots[6], i.caller_roots[1]) or !std.meta.eql(captured.summary, try self.context.close())) return error.UntrustedMixedRecursiveCapture;
    }
    pub fn deinit(self: *Owned) void {
        const a = self.a;
        self.shape.deinit();
        self.context.deinit();
        self.scope.deinit();
        self.statement.deinit();
        self.arena.deinit();
        a.destroy(self);
    }
};
