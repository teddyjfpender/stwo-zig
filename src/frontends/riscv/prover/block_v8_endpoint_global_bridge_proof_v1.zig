//! One narrow STARK for a batch of endpoint roots under a shared late epoch.
//! This is a CONDITIONAL bridge: it proves the claimed transition fractions
//! of the supplied roots, not the local execution proofs or global RAM closure.
//! Publication must verify those obligations too, preferably in one recursive
//! root. No wide native witness is accepted or rebuilt by this module.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const S = core.proof_suites.Blake3;
const Scheme = engine.pcs.CommitmentSchemeProver(Cpu, S.Hasher, S.MerkleChannel);
const Scope = @import("block_v8_endpoint_global_bridge_scope_v1.zig");
const B = @import("block_v8_endpoint_global_bridge_component_v1.zig");
const T = @import("block_v7_memory_trace_v1.zig");
const R = @import("block_v7_memory_relations_v1.zig");
const Component = @import("block_v5_word_quotient_adapter_v1.zig").For(B.Spec);
const Placement = @import("block_v7_heterogeneous_components_v1.zig");
pub const production_active = false;
pub const Limits = struct { fixed_bytes: usize = 512 << 20, interaction_bytes: usize = 1 << 30 };
pub const Stage = struct {
    /// Borrowed exact endpoint matrix; used solely to generate FOUR narrow
    /// interaction columns. Its two fixed columns are independently checked.
    endpoints: T.Matrix,
    /// Shared already-committed endpoint main tree. Local proving retains it
    /// before consuming its scheme, preserving both coefficients and root.
    tree: *Scheme.CommitmentTree,
    tree_allocator: std.mem.Allocator,
};
pub const Proof = struct {
    a: std.mem.Allocator,
    stark: S.Proof,
    claims: []R.Q,
    pub fn deinit(self: *Proof) void {
        self.stark.deinit(self.a);
        self.a.free(self.claims);
        self.* = undefined;
    }
};
pub const Fixed = struct {
    a: std.mem.Allocator,
    matrices: []T.Matrix,
    columns: []engine.pcs.ColumnEvaluation,
    pub fn init(a: std.mem.Allocator, scope: Scope.Owned, maximum: usize) !Fixed {
        const matrices = try a.alloc(T.Matrix, scope.sources.len);
        errdefer a.free(matrices);
        var initialized: usize = 0;
        errdefer for (matrices[0..initialized]) |*matrix| matrix.deinit();
        var used: usize = 0;
        for (scope.sources, matrices) |source, *matrix| {
            matrix.* = try B.prefix(a, source.endpoint_count, try source.log(), maximum - used);
            initialized += 1;
            used = try std.math.add(usize, used, matrix.storage.len * @sizeOf(R.M));
        }
        const columns = try a.alloc(engine.pcs.ColumnEvaluation, matrices.len);
        for (columns, matrices) |*column, matrix| column.* = matrix.columns[0];
        return .{ .a = a, .matrices = matrices, .columns = columns };
    }
    pub fn deinit(self: *Fixed) void {
        for (self.matrices) |*matrix| matrix.deinit();
        self.a.free(self.matrices);
        self.a.free(self.columns);
    }
};
pub fn Components(comptime proving: bool) type {
    const H = if (proving) engine.air.component_prover.ComponentProver else core.air.components.Component;
    return struct {
        a: std.mem.Allocator,
        components: []Component,
        handles: []H,
        maps: [][3]usize,
        placement: Placement.Dynamic(proving),
        pub fn init(a: std.mem.Allocator, scope: Scope.Owned, drawn: @import("block_v7_execution_epoch_v1.zig").Drawn, claims: []const R.Q) !@This() {
            if (claims.len != scope.sources.len) return error.InvalidEndpointBridgeClaims;
            const n = claims.len;
            const components = try a.alloc(Component, n);
            errdefer a.free(components);
            const handles = try a.alloc(H, n);
            errdefer a.free(handles);
            const maps = try a.alloc([3]usize, n);
            errdefer a.free(maps);
            const parts = try a.alloc(Placement.Dynamic(proving).Part, n);
            defer a.free(parts);
            for (scope.sources, claims, 0..) |source, claim, i| {
                components[i] = .{ .log_size = try source.log(), .spec = .{ .policy = source.policy, .challenge = drawn.memory.transition, .sums = .{claim} } };
                handles[i] = if (proving) components[i].asProverComponent() else components[i].asVerifierComponent();
                maps[i] = .{ 0, 1 + i, 1 + n + i };
                parts[i] = .{ .map = &maps[i], .handles = handles[i..][0..1], .fixed_count = 1 };
            }
            return .{ .a = a, .components = components, .handles = handles, .maps = maps, .placement = try Placement.Dynamic(proving).init(a, parts, scope.traceTrees()) };
        }
        pub fn deinit(self: *@This()) void {
            self.placement.deinit(self.a);
            self.a.free(self.maps);
            self.a.free(self.handles);
            self.a.free(self.components);
        }
    };
}
fn checkStage(source: Scope.Source, stage: Stage, config: core.pcs.PcsConfig) !void {
    const log = try source.log();
    const rows = @as(usize, 1) << @intCast(log);
    if (stage.endpoints.log != log or stage.endpoints.columns.len != 25 or stage.endpoints.storage.len != rows * 25 or
        !std.meta.eql(stage.tree.root(), source.endpoint_root) or stage.tree.columns.len != B.Spec.MAIN_COUNT)
        return error.UntrustedEndpointBridgeStage;
    for (stage.endpoints.columns, 0..) |column, i| {
        if (column.log_size != log or column.values.len != rows or column.values.ptr != stage.endpoints.storage[i * rows ..].ptr) return error.UntrustedEndpointBridgeStage;
    }
    for (stage.tree.columns) |column| if (column.log_size != log + config.fri_config.log_blowup_factor) return error.UntrustedEndpointBridgeStage;
    for (0..rows) |i| {
        if (!stage.endpoints.get(0, i).eql(if (i < source.endpoint_count) R.M.one() else R.M.zero()) or
            !stage.endpoints.get(1, i).eql(if (i == 0) R.M.one() else R.M.zero())) return error.UntrustedEndpointBridgeStage;
    }
}
pub fn produceConditional(a: std.mem.Allocator, scope: Scope.Owned, stages: []const Stage, limits: Limits) !Proof {
    if (stages.len != scope.sources.len or stages.len > Scope.MAX_BATCH_SOURCES) return error.InvalidEndpointBridgeRoster;
    var fixed = try Fixed.init(a, scope, limits.fixed_bytes);
    defer fixed.deinit();
    const drawn = try scope.epoch.draw(a);
    const generated = try a.alloc(T.Generated(1), stages.len);
    defer a.free(generated);
    var initialized: usize = 0;
    defer for (generated[0..initialized]) |*columns| columns.deinit();
    const claims = try a.alloc(R.Q, stages.len);
    errdefer a.free(claims);
    var used: usize = 0;
    for (scope.sources, stages, generated, 0..) |source, stage, *columns, i| {
        try checkStage(source, stage, scope.epoch.config);
        columns.* = try T.interactions(1, a, stage.endpoints, B.InteractionContext{ .policy = source.policy, .challenge = drawn.memory.transition }, limits.interaction_bytes - used);
        initialized += 1;
        used = try std.math.add(usize, used, columns.matrix.storage.len * @sizeOf(R.M));
        claims[i] = columns.sums[0];
    }
    var components = try Components(true).init(a, scope, drawn, claims);
    defer components.deinit();
    var scheme = try Scheme.init(a, scope.epoch.config);
    var owns_scheme = true;
    defer if (owns_scheme) scheme.deinit(a);
    scheme.setCoefficientRetentionPolicy(.always);
    var ignored = S.Channel{};
    try scheme.commitBorrowedStreaming(a, fixed.columns, 8, &ignored);
    for (stages) |stage| {
        try stage.tree.share(stage.tree_allocator);
        var shared = stage.tree.retainShared();
        scheme.appendCommittedTree(a, shared, &ignored) catch |err| {
            shared.deinit(stage.tree_allocator);
            return err;
        };
    }
    var channel = try scope.afterClaims(drawn, claims);
    for (generated) |columns| try scheme.commitBorrowedStreaming(a, columns.matrix.columns, 8, &channel);
    owns_scheme = false;
    const stark = try engine.prove.prove(Cpu, S.Hasher, S.MerkleChannel, a, components.placement.handles, &channel, scheme);
    return .{ .a = a, .stark = stark, .claims = claims };
}
/// Fresh fixed-key verification. `scope.sources` MUST be compared against
/// independently verified local statements before accepting the claim. This
/// function does not accept a producer's receipt as a verified local proof.
pub const VerifiedCapture = struct {
    allocator: std.mem.Allocator,
    proof: core.verifier.ProofCapture(S.Hasher),
    final_channel: S.Channel,
    transition: R.Q,
    pub fn deinit(self: *VerifiedCapture) void {
        self.proof.deinit(self.allocator);
        self.* = undefined;
    }
};
pub fn verifyConditional(a: std.mem.Allocator, scope: Scope.Owned, stark: *const S.Proof, claims: []const R.Q, limits: Limits) !R.Q {
    var capture = try verifyConditionalAndCapture(a, scope, stark, claims, limits);
    defer capture.deinit();
    return capture.transition;
}
pub fn verifyConditionalAndCapture(a: std.mem.Allocator, scope: Scope.Owned, stark: *const S.Proof, claims: []const R.Q, limits: Limits) !VerifiedCapture {
    const roots = stark.commitment_scheme_proof.commitments.items;
    const n = scope.sources.len;
    if (n > Scope.MAX_BATCH_SOURCES or roots.len != scope.traceTrees() + 1 or !std.meta.eql(stark.commitment_scheme_proof.config, scope.epoch.config)) return error.UntrustedEndpointBridgeProof;
    for (scope.sources, 0..) |source, i| if (!std.meta.eql(roots[1 + i], source.endpoint_root)) return error.UntrustedEndpointBridgeProof;
    var fixed = try Fixed.init(a, scope, limits.fixed_bytes);
    defer fixed.deinit();
    var key = try Scheme.init(a, scope.epoch.config);
    defer key.deinit(a);
    var ignored = S.Channel{};
    try key.commitBorrowedStreaming(a, fixed.columns, 8, &ignored);
    if (!std.meta.eql(key.trees.items[0].root(), roots[0])) return error.UntrustedEndpointBridgeFixedRoot;
    const drawn = try scope.epoch.draw(a);
    var channel = try scope.afterClaims(drawn, claims);
    var components = try Components(false).init(a, scope, drawn, claims);
    defer components.deinit();
    var verifier = try core.pcs.verifier.CommitmentSchemeVerifier(S.Hasher, S.MerkleChannel).init(a, scope.epoch.config);
    defer verifier.deinit(a);
    const fixed_logs = try a.alloc(u32, n);
    defer a.free(fixed_logs);
    for (scope.sources, fixed_logs) |source, *log| log.* = try source.log();
    try verifier.commit(a, roots[0], fixed_logs, &ignored);
    for (scope.sources, 0..) |source, i| try verifier.commit(a, roots[1 + i], &([_]u32{try source.log()} ** B.Spec.MAIN_COUNT), &ignored);
    for (scope.sources, 0..) |source, i| try verifier.commit(a, roots[1 + n + i], &([_]u32{try source.log()} ** B.Spec.INTERACTION_COUNT), &channel);
    var capture: core.verifier.ProofCapture(S.Hasher) = undefined;
    try core.verifier.verifyBorrowedWithProofCapture(S.Hasher, S.MerkleChannel, a, components.placement.handles, &channel, &verifier, stark, &capture);
    errdefer capture.deinit(a);
    var sum = R.Q.zero();
    for (claims) |claim| sum = sum.add(claim);
    return .{ .allocator = a, .proof = capture, .final_channel = channel, .transition = sum };
}
