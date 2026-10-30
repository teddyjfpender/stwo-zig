//! One heterogeneous native lookup proof; dense and sparse preserve exact buses.
const std = @import("std");
const core = @import("stwo_core");
const Engine = @import("stwo_prover_engine");
const Suite = core.proof_suites.Blake3;
const R = @import("block_v7_memory_relations_v1.zig");
const A = @import("block_v7_lookup_compact_algebra_v1.zig");
const L = @import("block_v7_lookup_compact_layout_v1.zig");
const Trace = @import("block_v7_lookup_compact_trace_v1.zig");
const Matrix = @import("block_v7_memory_trace_v1.zig");
const Air = @import("block_v7_lookup_compact_air_v1.zig");
const E = @import("block_v7_execution_epoch_v1.zig");
const Old = @import("block_v5_native_lookup_proof_v1.zig");
const Tables = @import("../air/lookups/tables/mod.zig");
const Shared = @import("../recursion/air/universal_provider_relations.zig");
const Column = Engine.pcs.ColumnEvaluation;
pub const Limits = struct { max_matrix_bytes: usize = 128 << 20, max_total_cells: usize = 32 << 20 };
pub const Proof = struct {
    claims: [6]R.Q,
    stark: Suite.Proof,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        self.* = undefined;
    }
};
pub const Policy = struct {
    plan: Old.Plan,
    layout: L.Layout,
    roots: [2][32]u8,
    epoch: E.Epoch,
    entries: []const E.Entry,
    pub fn entry(self: Policy) !E.Entry {
        return firstEntry(self.plan, self.layout, self.roots);
    }
    pub fn validate(self: Policy) !void {
        try self.plan.validate();
        try self.layout.validate();
        if (try std.math.add(u32, self.plan.first_execution, self.plan.execution_count) > self.epoch.counts[@intFromEnum(E.Family.native)]) return error.InvalidV7LookupExecutionSpan;
        try self.epoch.requireEntry(self.entries, try self.entry());
    }
};
pub fn firstEntry(plan: Old.Plan, layout: L.Layout, roots: [2][32]u8) !E.Entry {
    try layout.validate();
    var ch = Suite.Channel{};
    ch.mixU32s(&.{ 0x42374349, L.VERSION });
    ch.mixRoot(try plan.identity());
    ch.mixRoot(layout.digest);
    return E.Entry.init(.lookup, plan.index, ch.digestBytes(), &roots);
}
fn firstChannel(plan: Old.Plan, layout: L.Layout, config: core.pcs.PcsConfig) !Suite.Channel {
    var ch = Suite.Channel{};
    ch.mixU32s(&.{ 0x42374346, L.VERSION });
    ch.mixRoot(try plan.identity());
    ch.mixRoot(layout.digest);
    config.mixInto(&ch);
    return ch;
}
pub fn recordAfterChallenges(ch: anytype, policy: Policy, claims: [6]R.Q) !void {
    ch.mixU32s(&.{ 0x42374350, L.VERSION, E.VERSION, 6 });
    (try policy.entry()).mix(ch);
    for (claims) |claim| {
        if (!Shared.secureIsCanonical(&claim)) return error.NonCanonicalV7LookupClaim;
        ch.mixFelts(&.{claim});
    }
}
pub fn interactionChannel(policy: Policy, drawn: E.Drawn, claims: [6]R.Q) !Suite.Channel {
    var ch = drawn.channel;
    try recordAfterChallenges(&ch, policy, claims);
    return ch;
}
pub const Verified = struct { epoch: [32]u8, plan: [32]u8, layout: [32]u8, roots: [2][32]u8, claims: [6]R.Q };
pub const VerifiedCapture = struct {
    allocator: std.mem.Allocator,
    proof: core.verifier.ProofCapture(Suite.Hasher),
    final_channel: Suite.Channel,
    receipt: Verified,
    pub fn deinit(self: *VerifiedCapture) void {
        self.proof.deinit(self.allocator);
        self.* = undefined;
    }
};

fn enforceBudget(layout: L.Layout, limits: Limits) !void {
    var cells: usize = 0;
    for (layout.parts) |p| {
        const n = @as(usize, 1) << @as(u6, @intCast(p.log));
        cells = try std.math.add(usize, cells, try std.math.mul(usize, n, @as(usize, p.width[0]) + p.width[1] + p.width[2]));
    }
    if (cells > limits.max_total_cells) return error.CompactLookupResourceLimit;
}
fn columns(a: std.mem.Allocator, matrices: *const [6]Matrix.Matrix) ![]Column {
    var result: std.ArrayList(Column) = .empty;
    errdefer result.deinit(a);
    for (matrices) |m| try result.appendSlice(a, m.columns);
    return result.toOwnedSlice(a);
}
pub fn For(comptime Backend: type) type {
    return struct {
        const Scheme = Engine.pcs.CommitmentSchemeProver(Backend, Suite.Hasher, Suite.MerkleChannel);
        const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(Suite.Hasher, Suite.MerkleChannel);
        pub const Stage = struct {
            a: std.mem.Allocator,
            plan: Old.Plan,
            layout: L.Layout,
            config: core.pcs.PcsConfig,
            limits: Limits,
            fixed: [6]Matrix.Matrix,
            main: [6]Matrix.Matrix,
            scheme: Scheme,
            roots: [2][32]u8,
            owns: bool = true,
            pub fn init(a: std.mem.Allocator, counters: *const Tables.counter.Set, plan: Old.Plan, config: core.pcs.PcsConfig, modes: ?[6]A.Mode, limits: Limits) !Stage {
                try Old.validateSourceCounters(counters, plan);
                var choices: [6]A.Mode = undefined;
                var logs: [6]u32 = undefined;
                for (&counters.counters, &choices, &logs, 0..) |*counter, *mode, *log, i| {
                    const count = try Trace.distinct(counter);
                    mode.* = if (modes) |selected| selected[i] else try L.choose(counter.kind, count, config.fri_config.log_blowup_factor, (std.math.cast(u32, config.fri_config.n_queries) orelse return error.InvalidCompactLookupGeometry));
                    log.* = if (mode.* == .dense) A.Schema.logSize(counter.kind) else @max(4, std.math.log2_int_ceil(usize, @max(1, count)));
                }
                const layout = try L.Layout.init(choices, logs);
                try enforceBudget(layout, limits);
                var fixed: [6]Matrix.Matrix = undefined;
                var main: [6]Matrix.Matrix = undefined;
                var ready: usize = 0;
                errdefer for (0..ready) |i| {
                    fixed[i].deinit();
                    main[i].deinit();
                };
                for (layout.parts, &counters.counters, 0..) |p, *counter, i| {
                    fixed[i] = try Trace.fixed(a, p, limits.max_matrix_bytes);
                    main[i] = Trace.main(a, p, counter, limits.max_matrix_bytes) catch |err| {
                        fixed[i].deinit();
                        return err;
                    };
                    ready += 1;
                }
                var scheme = try Scheme.init(a, config);
                errdefer scheme.deinit(a);
                scheme.setCoefficientRetentionPolicy(.always);
                const fc = try columns(a, &fixed);
                defer a.free(fc);
                const mc = try columns(a, &main);
                defer a.free(mc);
                var ch = try firstChannel(plan, layout, config);
                try scheme.commitBorrowedStreaming(a, fc, 16, &ch);
                try scheme.commitBorrowedStreaming(a, mc, 16, &ch);
                var roots = try scheme.roots(a);
                defer roots.deinit(a);
                if (roots.items.len != 2) return error.InvalidCompactLookupRoots;
                return .{ .a = a, .plan = plan, .layout = layout, .config = config, .limits = limits, .fixed = fixed, .main = main, .scheme = scheme, .roots = roots.items[0..2].* };
            }
            pub fn deinit(self: *Stage) void {
                if (self.owns) self.scheme.deinit(self.a);
                for (&self.fixed) |*m| m.deinit();
                for (&self.main) |*m| m.deinit();
                self.* = undefined;
            }
            pub fn entry(self: *const Stage) !E.Entry {
                return firstEntry(self.plan, self.layout, self.roots);
            }
            pub fn policy(self: *const Stage, epoch: E.Epoch, entries: []const E.Entry) Policy {
                return .{ .plan = self.plan, .layout = self.layout, .roots = self.roots, .epoch = epoch, .entries = entries };
            }
            pub fn prove(self: *Stage, epoch: E.Epoch, entries: []const E.Entry) !Proof {
                const admitted = self.policy(epoch, entries);
                try admitted.validate();
                if (!self.owns or !std.meta.eql(self.config, epoch.config)) return error.InvalidCompactLookupPhase;
                const drawn = try epoch.draw(self.a);
                const relations = try Shared.SharedProviderRelations.init(&drawn.word.universal_prefix);
                var generated: [6]Matrix.Generated(1) = undefined;
                var ready: usize = 0;
                defer for (generated[0..ready]) |*g| g.deinit();
                var claims: [6]R.Q = undefined;
                inline for (0..6) |i| {
                    inline for (.{ A.Mode.dense, A.Mode.sparse }) |mode| if (self.layout.parts[i].mode == mode) {
                        const S = A.For(@enumFromInt(i), mode);
                        const Context = struct {
                            fixed: Matrix.Matrix,
                            relation: R.Relation(R.Q, A.Schema.arity(@enumFromInt(i))),
                            pub fn termsAt(c: @This(), matrix: Matrix.Matrix, row: usize) ![1]R.Term(R.Q) {
                                return .{S.term(R.Q, c.relation, c.fixed.row(S.FIXED_COUNT, 0, row), matrix.row(S.MAIN_COUNT, 0, row))};
                            }
                        };
                        generated[i] = try Matrix.interactions(1, self.a, self.main[i], Context{ .fixed = self.fixed[i], .relation = .from(@field(relations.native, @tagName(@as(A.Schema.Kind, @enumFromInt(i))))) }, self.limits.max_matrix_bytes);
                        claims[i] = generated[i].sums[0];
                        ready += 1;
                    };
                }
                const owner = try Air.Owner.init(self.a, self.layout, relations, claims);
                defer owner.deinit();
                var ic: std.ArrayList(Column) = .empty;
                defer ic.deinit(self.a);
                for (&generated) |*g| try ic.appendSlice(self.a, g.matrix.columns);
                var ch = try interactionChannel(admitted, drawn, claims);
                try self.scheme.commitBorrowedStreaming(self.a, ic.items, 8, &ch);
                self.owns = false;
                return .{ .claims = claims, .stark = try Engine.prove.prove(Backend, Suite.Hasher, Suite.MerkleChannel, self.a, &owner.provers, &ch, self.scheme) };
            }
        };
        pub fn requireFixedRoots(a: std.mem.Allocator, policy: Policy, limits: Limits) !void {
            try policy.validate();
            try enforceBudget(policy.layout, limits);
            var fixed: [6]Matrix.Matrix = undefined;
            var ready: usize = 0;
            defer for (fixed[0..ready]) |*m| m.deinit();
            for (policy.layout.parts, 0..) |p, i| {
                fixed[i] = try Trace.fixed(a, p, limits.max_matrix_bytes);
                ready += 1;
            }
            const fc = try columns(a, &fixed);
            defer a.free(fc);
            var trusted = try Scheme.init(a, policy.epoch.config);
            defer trusted.deinit(a);
            trusted.setCoefficientRetentionPolicy(.never);
            var checked = try firstChannel(policy.plan, policy.layout, policy.epoch.config);
            try trusted.commitBorrowedStreaming(a, fc, 16, &checked);
            var fixedroots = try trusted.roots(a);
            defer fixedroots.deinit(a);
            if (fixedroots.items.len != 1 or !std.meta.eql(fixedroots.items[0], policy.roots[0])) return error.UntrustedCompactLookupFixedRoot;
        }
        pub fn verify(a: std.mem.Allocator, proof: *const Proof, policy: Policy, limits: Limits) ![6]R.Q {
            var captured = try verifyAndCapture(a, proof, policy, limits);
            defer captured.deinit();
            return captured.receipt.claims;
        }
        pub fn verifyAndCapture(a: std.mem.Allocator, proof: *const Proof, policy: Policy, limits: Limits) !VerifiedCapture {
            try policy.validate();
            try enforceBudget(policy.layout, limits);
            const roots = proof.stark.commitment_scheme_proof.commitments.items;
            if (roots.len != 4 or !std.meta.eql(roots[0..2].*, policy.roots) or !std.meta.eql(proof.stark.commitment_scheme_proof.config, policy.epoch.config)) return error.UntrustedCompactLookupProof;
            try requireFixedRoots(a, policy, limits);
            var initial = try firstChannel(policy.plan, policy.layout, policy.epoch.config);
            const drawn = try policy.epoch.draw(a);
            const relations = try Shared.SharedProviderRelations.init(&drawn.word.universal_prefix);
            const owner = try Air.Owner.init(a, policy.layout, relations, proof.claims);
            defer owner.deinit();
            var verifier = try Verifier.init(a, policy.epoch.config);
            defer verifier.deinit(a);
            const fl = try policy.layout.logs(a, 0);
            defer a.free(fl);
            const ml = try policy.layout.logs(a, 1);
            defer a.free(ml);
            const il = try policy.layout.logs(a, 2);
            defer a.free(il);
            try verifier.commit(a, roots[0], fl, &initial);
            try verifier.commit(a, roots[1], ml, &initial);
            var ch = try interactionChannel(policy, drawn, proof.claims);
            try verifier.commit(a, roots[2], il, &ch);
            var capture: core.verifier.ProofCapture(Suite.Hasher) = undefined;
            try core.verifier.verifyBorrowedWithProofCapture(Suite.Hasher, Suite.MerkleChannel, a, &owner.verifiers, &ch, &verifier, &proof.stark, &capture);
            errdefer capture.deinit(a);
            return .{ .allocator = a, .proof = capture, .final_channel = ch, .receipt = .{ .epoch = policy.epoch.digest, .plan = try policy.plan.identity(), .layout = policy.layout.digest, .roots = policy.roots, .claims = proof.claims } };
        }
    };
}

test "v7 compact genuine prover rejects a recommitted non Boolean tuple witness" {
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const CP = For(Cpu);
    const a = std.testing.allocator;
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8), .lifting_log_size = null };
    var counters = try Tables.counter.Set.init(a);
    defer counters.deinit(a);
    counters.counters[0].values[0] = R.M.one();
    const plan = Old.Plan{ .index = 0, .first_execution = 0, .execution_count = 1, .max_requests = @splat(1) };
    var stage = try CP.Stage.init(a, &counters, plan, config, null, .{});
    defer stage.deinit();
    // Deliberately bypass the honest witness generator and recommit the bad
    // main trace. This is a malicious prover, not a stale-root mutation test.
    stage.main[0].set(1, 0, R.M.fromCanonical(2));
    stage.scheme.deinit(a);
    stage.owns = false;
    stage.scheme = try Engine.pcs.CommitmentSchemeProver(Cpu, Suite.Hasher, Suite.MerkleChannel).init(a, config);
    stage.owns = true;
    stage.scheme.setCoefficientRetentionPolicy(.always);
    const fc = try columns(a, &stage.fixed);
    defer a.free(fc);
    const mc = try columns(a, &stage.main);
    defer a.free(mc);
    var ch = try firstChannel(plan, stage.layout, config);
    try stage.scheme.commitBorrowedStreaming(a, fc, 16, &ch);
    try stage.scheme.commitBorrowedStreaming(a, mc, 16, &ch);
    var roots = try stage.scheme.roots(a);
    defer roots.deinit(a);
    stage.roots = roots.items[0..2].*;
    const entries = [_]E.Entry{ try E.Entry.init(.native, 0, @splat(7), &.{ @splat(1), @splat(2) }), try stage.entry() };
    var counts: E.Counts = @splat(0);
    for (entries) |entry| counts[@intFromEnum(entry.family)] += 1;
    const epoch = try E.Epoch.init(@splat(9), config, counts, &entries, entries.len);
    if (stage.prove(epoch, &entries)) |value| {
        var bad = value;
        bad.deinit(a);
        return error.ExpectedCompactConstraintFailure;
    } else |err| try std.testing.expectEqual(error.ConstraintsNotSatisfied, err);
}
