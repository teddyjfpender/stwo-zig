//! Actual source geometry, NEW dummy Blake witness, trace-only verifier census.
//! No native P2 proof/root is cast to Blake. This deliberately omits the source
//! AIR and P2-local-GKR/frame body and is not an accepting circuit or new suite.
const std = @import("std");
const Core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const Circuit = @import("stwo_circuit_frontend");
const N = @import("../../rv64_recursion/om31_native/mod.zig");
const PC = @import("../../rv64_recursion/om31_poseidon/common.zig");
const W = @import("../pure_p2_worker_protocol.zig").W;
const Runtime = @import("../sponge_cpu/runtime.zig");
const Receiver = @import("../sponge_cpu/receiver.zig");
const Request = @import("../../rv64_ethereum_request.zig");
const O = Core.fields.om31.OM31;
const M = Core.fields.m31.M31;
const B = Circuit.builder;
const H = Core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
fn zeros(comptime T: type, a: std.mem.Allocator, count: usize, value: T) ![]T {
    const out = try a.alloc(T, count);
    @memset(out, value);
    return out;
}
fn paths(a: std.mem.Allocator, count: usize, height: usize) ![]const []const H.Hash {
    const out = try a.alloc([]const H.Hash, count);
    for (out) |*path| path.* = try zeros(H.Hash, a, height, @splat(0));
    return out;
}
fn blank(a: std.mem.Allocator, shape: *const N.Shape, layer_dimensions: anytype) !N.Captured {
    const samples = try a.alloc([]const []const O, shape.nTrees());
    const queried = try a.alloc([]const []const M, shape.nTrees());
    const auth = try a.alloc([]const []const H.Hash, shape.nTrees());
    for (0..shape.nTrees()) |tree| {
        const cs = try a.alloc([]const O, shape.nColumns(tree));
        const cq = try a.alloc([]const M, cs.len);
        for (cs, cq, 0..) |*s, *q, column| {
            s.* = try zeros(O, a, shape.sampleCount(tree, column), O.zero());
            q.* = try zeros(M, a, shape.nQueries(), M.zero());
        }
        samples[tree] = cs;
        queried[tree] = cq;
        auth[tree] = try paths(a, if (cs.len == 0) 0 else shape.nQueries(), shape.treeHeight(tree));
    }
    const layers = try a.alloc(N.proof.CapturedLayer, layer_dimensions.len);
    for (layers, layer_dimensions) |*out, dims| {
        const cosets = try a.alloc([]const O, dims.cosets.len);
        for (cosets, dims.cosets) |*coset, values| coset.* = try zeros(O, a, values.len, O.zero());
        out.* = .{ .commitment = @splat(0), .cosets = cosets, .auth_paths = try paths(a, dims.auth_paths.len, if (dims.auth_paths.len == 0) 0 else dims.auth_paths[0].len) };
    }
    return .{ .commitments = try zeros(H.Hash, a, shape.nTrees(), @splat(0)), .sampled_values = samples, .queried_values = queried, .auth_paths = auth, .pow_nonce = 0, .layers = layers, .last_layer_coefs = try zeros(O, a, shape.nLastLayerCoefficients(), O.zero()) };
}
fn StatementFor(comptime Channel: type) type {
    return struct {
        shape: *const N.Shape,
        claims: []const N.F,
        pub const Challenges = void;
        pub fn mixPublic(self: *@This(), ctx: *N.common.Context, channel: *Channel) !void {
            try channel.mixConfig(ctx, self.shape.pcs);
            // An explicit AUDIT prefix, not a proposed production profile. Full
            // 8-u32 external identities +full32-byte physical root are represented.
            try channel.mixConstU32s(ctx, &.{ 0x41554449, 0x54424c4b, 1 });
            const Word = B.wrappers.U32Wrapper(B.Var);
            var words: [25]Word = undefined;
            for (&words) |*word| word.* = try B.wrappers.guessU32(N.common.Q, ctx, B.wrappers.u32Value(N.common.Q, 0));
            try channel.mixU32s(ctx, &words);
        }
        pub fn nTreesBeforeChallenges(_: *@This()) usize {
            return 2;
        }
        pub fn drawChallenges(_: *@This(), _: *N.common.Context, _: *Channel) !void {}
        pub fn mixClaims(self: *@This(), ctx: *N.common.Context, channel: *Channel) !void {
            try channel.mixConstU32s(ctx, &.{ 0x41554449, 2, @intCast(self.claims.len) });
            // P2 manifest remains36bytes in the hypothetical mixed suite. Here
            // nine exact31-bit words stand in for it, without claiming P2 binding.
            const Word = B.wrappers.U32Wrapper(B.Var);
            var manifest: [9]Word = undefined;
            for (&manifest) |*word| word.* = try B.wrappers.guessU32(N.common.Q, ctx, B.wrappers.u32Value(N.common.Q, 0));
            try channel.mixU32s(ctx, &manifest);
            try channel.mixFelts(ctx, self.claims);
        }
        pub fn evalComposition(self: *@This(), ctx: *N.common.Context, point: N.Point, sampled: []const []const []const N.F, _: N.F, _: void) !N.F {
            // Explicitly absent AIR body: only the real PCS/hash/FRI source work is
            // measured. Never call circuit-validity or source-key admission here.
            return N.reconstructComposition(ctx, sampled[self.shape.compositionTree()], point, self.shape.global_log, self.shape.composition_log_split);
        }
    };
}
const Statement = StatementFor(N.Channel);
fn p2Control(a: std.mem.Allocator, shape: *const N.Shape, values: *const @import("../../rv64_recursion/om31_poseidon/mod.zig").Captured, claim_count: usize) !void {
    const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
    var owner = try PC.PoseidonContext.initTraceOnly(a, 9);
    defer owner.deinit();
    var structural = N.common.lane.StructuralScope.init();
    defer structural.deinit();
    var multiply = @import("../native_omul/scope.zig").begin();
    defer multiply.deinit();
    var dot = @import("../native_dot/scope.zig").Scope.begin(&owner);
    defer dot.deinit();
    PC.begin(&owner);
    var active = true;
    defer if (active) PC.finish() catch {};
    const proof = try V.proof.guess(owner.algebra(), values, shape);
    const claims = try a.alloc(N.F, claim_count);
    defer a.free(claims);
    for (claims) |*claim| claim.* = try N.F.guess(owner.algebra(), O.zero());
    var statement = StatementFor(PC.Channel){ .shape = shape, .claims = claims };
    const verified = try V.verify(owner.algebra(), shape, &proof, &statement);
    try PC.finish();
    active = false;
    try owner.setOutputs(&verified.channel.raw.inner.value.digest);
    const json = try std.json.Stringify.valueAlloc(a, .{ .scope = "SAME_actualgeometry_P2_PCS_FS_DEEP_FRI_trace_no_AIR_GKR_frame_or_acceptance", .raw = owner.base.gate_counts, .native_om_mul = owner.native_mul_calls.items.len, .dot_calls = owner.native_dot_calls.items.len, .p2_permutations = owner.calls.items.len, .source_identity_admitted = false, .proof_validity_claimed = false }, .{});
    defer a.free(json);
    std.debug.print("NATIVE_P2_MATCHED_PCS_SOURCE {s}\n", .{json});
}
const State = struct {
    cpu: usize = 0,
    complete: bool = false,
    fn fragment(raw: ?*anyopaque, a: std.mem.Allocator, v: Receiver.Verified) !void {
        const self: *State = @ptrCast(@alignCast(raw.?));
        switch (v.source) {
            .cpu => |source| {
                if (self.cpu != 0 or v.ordinal != 0) return error.NativeBlakeSingleCpuControl;
                var arena = std.heap.ArenaAllocator.init(a);
                defer arena.deinit();
                const scratch = arena.allocator();
                const p2_shape = try @import("../sponge_cpu/capture.zig").geometry(scratch, source.value.setup, source.value.key);
                // Explicit geometry-only reconstruction: root types and proof
                // values are fresh. These fields contain no cryptographic hash.
                const shape = N.Shape{ .tree_column_log_sizes = p2_shape.tree_column_log_sizes, .mask_offsets = p2_shape.mask_offsets, .global_log = p2_shape.global_log, .composition_log_split = p2_shape.composition_log_split, .pcs = p2_shape.pcs };
                try shape.validate();
                try std.testing.expectEqual(@as(u32, 2), shape.pcs.fri_config.log_blowup_factor);
                try std.testing.expectEqual(@as(usize, 72), shape.pcs.fri_config.n_queries);
                var parsed = try W.Wire.decodeProofBytesBinary(a, source.encoded.bytes);
                defer parsed.deinit(a);
                const p2_values = try @import("../../rv64_recursion/om31_poseidon/mod.zig").proof.fromNative(scratch, &parsed, v.capture, &p2_shape);
                try std.testing.expectEqual(@as(u32, 0), p2_values.cap_log);
                const values = try blank(scratch, &shape, p2_values.layers);
                var owner = try PC.PoseidonContext.initTraceOnly(a, 8);
                defer owner.deinit();
                var structural = N.common.lane.StructuralScope.init();
                defer structural.deinit();
                var multiply = @import("../native_omul/scope.zig").begin();
                defer multiply.deinit();
                var dot = @import("../native_dot/scope.zig").Scope.begin(&owner);
                defer dot.deinit();
                PC.begin(&owner);
                var active = true;
                defer if (active) PC.finish() catch {};
                const proof = try N.proof.guess(owner.algebra(), &values, &shape);
                const claims = try a.alloc(N.F, source.encoded.claims.len);
                defer a.free(claims);
                for (claims) |*claim| claim.* = try N.F.guess(owner.algebra(), O.zero());
                var statement = Statement{ .shape = &shape, .claims = claims };
                const verified = try N.verify(owner.algebra(), &shape, &proof, &statement);
                try PC.finish();
                active = false;
                var outputs: [8]B.Var = undefined;
                for (&outputs, verified.channel.raw.inner.digest.words) |*out, word| out.* = word.get();
                try owner.setOutputs(&outputs);
                // Deliberately NOT finalize: production R7 rejects these mixed
                // gates and no mixed R7 source authority exists.
                var columns: [4]usize = undefined;
                var heights: [4]u32 = undefined;
                for (&columns, &heights, 0..) |*count, *height, tree| {
                    count.* = shape.nColumns(tree);
                    height.* = shape.treeHeight(tree);
                }
                var terms: usize = 0;
                for (owner.native_dot_calls.items) |call| terms += call.terms.len;
                const json = try std.json.Stringify.valueAlloc(a, .{ .scope = "ACTUAL_CPU_geometry_NEW_dummyBlake_PCS_FS_DEEP_FRI_trace_R7lowering_no_AIR_or_GKR_or_acceptance", .columns = columns, .tree_heights = heights, .global_log = shape.global_log, .composition_split = shape.composition_log_split, .config = shape.pcs, .claim_count = claims.len, .raw = owner.base.gate_counts, .native_om_mul = owner.native_mul_calls.items.len, .dot_calls = owner.native_dot_calls.items.len, .dot_terms = terms, .input_ports = owner.native_input_ids.items.len, .p2_permutations = owner.calls.items.len, .root_bytes = 32, .native_p2_values_not_cast = true, .source_identity_admitted = false, .proof_validity_claimed = false, .production_admission = false }, .{});
                defer a.free(json);
                std.debug.print("NATIVE_BLAKE_ACTUAL_CPU_SOURCE {s}\n", .{json});
                try p2Control(a, &shape, &p2_values, claims.len);
                self.cpu += 1;
            },
            else => {},
        }
    }
    fn done(raw: ?*anyopaque, _: std.mem.Allocator, _: Runtime.SourceDirectory, _: *const Receiver.Closed) !void {
        const self: *State = @ptrCast(@alignCast(raw.?));
        try std.testing.expectEqual(@as(usize, 1), self.cpu);
        self.complete = true;
    }
};
test "native Blake actual CPU geometry source only keeps OM31 q72 B4 fold4" {
    const config_path = std.posix.getenv("STWO_OP_NATIVE_BLAKE_AUDIT_CONFIG") orelse return error.SkipZigTest;
    const directory = std.posix.getenv("STWO_OP_NATIVE_BLAKE_AUDIT_NATIVE") orelse return error.SkipZigTest;
    const bytes = try std.fs.cwd().readFileAlloc(std.testing.allocator, config_path, 16384);
    defer std.testing.allocator.free(bytes);
    const parsed = try std.json.parseFromSlice(Request.Config, std.testing.allocator, bytes, .{});
    defer parsed.deinit();
    if (parsed.value.max_steps > 10_000_000) return error.NativeBlakeSmallSourceControl;
    const budget = try Engine.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 32 << 30);
    defer budget.destroy();
    var pool: Engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var binding = try Engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var state: State = .{};
    try Runtime.verifyDirectoryWithHooks(budget.allocator(), parsed.value, directory, .op_target_b4_q72_p0_fold4_v1, .{}, .{ .fragments = .{ .context = &state, .fragment = State.fragment }, .context = &state, .complete = State.done });
    try std.testing.expect(state.complete);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().external_live_bytes);
}
