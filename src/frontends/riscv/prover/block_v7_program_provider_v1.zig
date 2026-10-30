//! Decoded-ROM provider: original AIR/first-round storage, new v7 transcript.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Original = @import("block_v5_program_table_proof_v1.zig");
const Source = @import("block_v5_program_table_v1.zig");
const Epoch = @import("block_v7_execution_epoch_v1.zig");
const Binding = @import("../recursion/air/universal_relation_binding.zig");
const Framework = @import("../recursion/air/framework_interaction.zig");
const Air = Original.Air;
const Column = engine.pcs.ColumnEvaluation;
pub const Proof = Original.Proof;
pub fn firstEntry(plan: Source.Plan, roots: [2][32]u8) !Epoch.Entry {
    return Epoch.Entry.init(.program, 0, try plan.digest(), &roots);
}
pub const Policy = struct {
    plan: Source.Plan,
    expected_program_root: @import("../air/memory_commitment/blake3_state_tree.zig").Digest,
    roots: [2][32]u8,
    epoch: Epoch.Epoch,
    entries: []const Epoch.Entry,
    pub fn entry(self: Policy) !Epoch.Entry {
        return firstEntry(self.plan, self.roots);
    }
    pub fn admit(self: Policy) !void {
        if (!std.meta.eql(self.plan.program_root, self.expected_program_root)) return error.UntrustedV7ProgramRoot;
        try self.epoch.requireEntry(self.entries, try self.entry());
    }
};
pub const Verified = struct {
    epoch: [32]u8,
    plan: [32]u8,
    roots: [2][32]u8,
    claim: Q,
    fetch_count: u64,
};
pub fn recordAfterChallenges(ch: anytype, policy: Policy, claim: Q) !void {
    for (claim.toM31Array()) |cell| if (cell.v >= core.fields.m31.Modulus) return error.NonCanonicalV7ProgramClaim;
    ch.mixU32s(&.{ 0x42375052, Epoch.VERSION });
    (try policy.entry()).mix(ch);
    ch.mixFelts(&.{claim});
}
pub fn channel(policy: Policy, drawn: Epoch.Drawn, claim: Q) !suite.Channel {
    var ch = drawn.channel;
    try recordAfterChallenges(&ch, policy, claim);
    return ch;
}
pub const VerifiedCapture = struct {
    allocator: std.mem.Allocator,
    proof: core.verifier.ProofCapture(suite.Hasher),
    final_channel: suite.Channel,
    receipt: Verified,
    pub fn deinit(self: *VerifiedCapture) void {
        self.proof.deinit(self.allocator);
        self.* = undefined;
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Old = Original.ForBackend(Backend);
        const Runtime = Framework.Runtime(Binding.Binding(Air).Runtime);
        const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel);
        pub const FirstRound = Old.FirstRound;
        pub const commit = Old.commitFirstRound;

        pub fn prove(a: std.mem.Allocator, first: *FirstRound, policy: Policy) !Proof {
            try policy.admit();
            if (!first.owns_scheme or !std.meta.eql(first.scheme.config, policy.epoch.config) or
                !std.meta.eql(first.plan_digest, try policy.plan.digest()) or !std.meta.eql(first.roots, policy.roots)) return error.UntrustedV7ProgramFirstRound;
            const drawn = try policy.epoch.draw(a);
            const relations = &drawn.word.universal_prefix;
            var definition = try Air.build(a);
            defer definition.deinit();
            const relation_plan = try Binding.Binding(Air).authenticate(&definition);
            const rows = try a.alloc(Air.Row, policy.plan.multiplicities.len);
            defer a.free(rows);
            for (rows, 0..) |*row, i| row.* = try policy.plan.row(i);
            var workspace = try Runtime.Workspace.init(a, @min(policy.plan.log_size, Framework.OWNED_TILE_LOG_SIZE));
            defer workspace.deinit();
            const view = Runtime.ColumnRows{ .columns = @splat(&.{}), .count = rows.len, .main_count = 0, .metadata = rows };
            var interaction = try Runtime.generatePreparedOwnedColumnsTiledWithWorkspace(a, &workspace, &relation_plan, view, policy.plan.log_size, relations, @as(Air.Row, @splat(M.zero())));
            defer interaction.deinit(a);
            var ch = try channel(policy, drawn, interaction.claimed_sum);
            var columns: [Air.INTERACTION_COLUMN_COUNT]Column = undefined;
            for (interaction.columns, &columns) |values, *column| column.* = .{ .log_size = policy.plan.log_size, .values = values };
            try first.scheme.commitBorrowedStreaming(a, &columns, 8, &ch);
            const manifest = Original.Roster.Manifest{ .log_sizes = .{policy.plan.log_size} };
            const component = try Original.Roster.Component(Air).init(&definition, relation_plan, &manifest, .program, policy.plan.log_size, .{}, relations, interaction.claimed_sum);
            const handle = try component.asProverComponent().withCompositionGeometryOverrideV1(.{ .max_constraint_log_degree_bound_delta = 1, .composition_log_split = 2 });
            first.owns_scheme = false;
            return .{ .stark = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, &.{handle}, &ch, first.scheme), .claim = interaction.claimed_sum };
        }

        pub fn verifyBorrowed(a: std.mem.Allocator, proof: *const Proof, policy: Policy) !Verified {
            var captured = try verifyAndCapture(a, proof, policy);
            defer captured.deinit();
            return captured.receipt;
        }
        pub fn requireFixedRoots(a: std.mem.Allocator, policy: Policy) !void {
            try policy.admit();
            var fixed = try commit(a, policy.plan, policy.epoch.config);
            defer fixed.deinit(a);
            if (!std.meta.eql(fixed.roots, policy.roots)) return error.UntrustedV7ProgramFixedRoot;
        }
        pub fn verifyAndCapture(a: std.mem.Allocator, proof: *const Proof, policy: Policy) !VerifiedCapture {
            try policy.admit();
            const roots = proof.stark.commitment_scheme_proof.commitments.items;
            if (roots.len != 4 or !std.meta.eql(roots[0..2].*, policy.roots) or !std.meta.eql(proof.stark.commitment_scheme_proof.config, policy.epoch.config)) return error.UntrustedV7ProgramProof;
            // The expected decoded ELF root and exact plan are independent;
            // neither a proof root nor a host counter receipt selects them.
            try requireFixedRoots(a, policy);
            const drawn = try policy.epoch.draw(a);
            var ch = try channel(policy, drawn, proof.claim);
            var verifier = try Verifier.init(a, policy.epoch.config);
            defer verifier.deinit(a);
            var prefix = suite.Channel{};
            try verifier.commit(a, roots[0], &([_]u32{policy.plan.log_size} ** Air.PREPROCESSED_COLUMN_COUNT), &prefix);
            try verifier.commit(a, roots[1], &.{}, &prefix);
            try verifier.commit(a, roots[2], &([_]u32{policy.plan.log_size} ** Air.INTERACTION_COLUMN_COUNT), &ch);
            var definition = try Air.build(a);
            defer definition.deinit();
            const relation_plan = try Binding.Binding(Air).authenticate(&definition);
            const manifest = Original.Roster.Manifest{ .log_sizes = .{policy.plan.log_size} };
            const component = try Original.Roster.Component(Air).init(&definition, relation_plan, &manifest, .program, policy.plan.log_size, .{}, &drawn.word.universal_prefix, proof.claim);
            const handle = try component.asVerifierComponent().withCompositionGeometryOverrideV1(.{ .max_constraint_log_degree_bound_delta = 1, .composition_log_split = 2 });
            var capture: core.verifier.ProofCapture(suite.Hasher) = undefined;
            try core.verifier.verifyBorrowedWithProofCapture(suite.Hasher, suite.MerkleChannel, a, &.{handle}, &ch, &verifier, &proof.stark, &capture);
            errdefer capture.deinit(a);
            return .{ .allocator = a, .proof = capture, .final_channel = ch, .receipt = .{ .epoch = policy.epoch.digest, .plan = try policy.plan.digest(), .roots = policy.roots, .claim = proof.claim, .fetch_count = policy.plan.expected_fetches } };
        }
    };
}
