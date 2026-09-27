//! Standalone PCS proof of the complete decoded-ROM program provider.
//! Native program custody stays enabled until a block verifier fresh-verifies
//! every native request proof and closes their shared relation against this.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
const source = @import("block_v5_program_table_v1.zig");
pub const Air = @import("../recursion/air/blake3_public_program.zig");
const binding = @import("../recursion/air/universal_relation_binding.zig");
const universal = @import("../recursion/air/universal_challenges.zig");
const framework = @import("../recursion/air/framework_interaction.zig");
pub const Roster = @import("../recursion/air/universal_component_roster.zig").ForAirs(.{Air}, &.{"program"});
const Digest = suite.Hasher.Hash;

pub const TAG: u32 = 0x42355054; // B5PT
/// Canonical first-round roster identity, independent of prover proof bytes.
pub fn instanceId(plan: source.Plan) ![32]u8 {
    return plan.digest();
}
pub const Seal = struct {
    /// Independently pinned source/job and native first-round roster digest.
    source_digest: [32]u8,
    native_roster_digest: [32]u8,
    plan_digest: [32]u8,
    program_root: @import("../air/memory_commitment/blake3_state_tree.zig").Digest,
    first_roots: [2]Digest,

    pub fn init(plan: source.Plan, source_digest: [32]u8, native_roster_digest: [32]u8, first_roots: [2]Digest) !Seal {
        return .{ .source_digest = source_digest, .native_roster_digest = native_roster_digest, .plan_digest = try plan.digest(), .program_root = plan.program_root, .first_roots = first_roots };
    }
    pub fn validate(self: Seal, plan: source.Plan, roots: [2]Digest) !void {
        if (!std.meta.eql(self.program_root, plan.program_root) or
            !std.meta.eql(self.first_roots, roots) or
            !std.meta.eql(self.plan_digest, try plan.digest())) return error.UntrustedProgramTableSeal;
    }
    /// Every v5 family draws the same 47 universal challenges from B5SS.
    pub fn sharedChannel(self: Seal) suite.Channel {
        return @import("block_v5_universal_channel_v1.zig").init(self.source_digest);
    }
    /// Program-specific PCS transcript; not the universal relation draw.
    pub fn proofChannel(self: Seal) suite.Channel {
        var channel = suite.Channel{};
        channel.mixU32s(&.{ TAG, source.VERSION });
        channel.mixRoot(self.source_digest);
        channel.mixRoot(self.native_roster_digest);
        channel.mixRoot(self.plan_digest);
        channel.mixRoot(self.program_root.bytes);
        channel.mixRoot(self.first_roots[0]);
        channel.mixRoot(self.first_roots[1]);
        return channel;
    }
};

pub const Proof = struct {
    stark: suite.Proof,
    claim: Q,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        self.* = undefined;
    }
};
pub const VerifiedReceipt = struct {
    claim: Q,
    fetch_count: u64,
    program_root: @TypeOf(@as(Seal, undefined).program_root),
    plan_digest: [32]u8,
    sealed_channel_digest: [32]u8,
    first_roots: [2]Digest,
};
pub const VerifiedNativeRequest = struct {
    claim: Q,
    fetch_count: u64,
    sealed_channel_digest: [32]u8,
};

/// Structural closure only. The caller must pass receipts from fresh proof
/// verification in the same call, never accept these public structs as input.
pub fn closed(table: VerifiedReceipt, requests: []const VerifiedNativeRequest, seal: Seal) !void {
    var channel = seal.sharedChannel();
    const digest = channel.digestBytes();
    if (!std.meta.eql(table.sealed_channel_digest, digest) or
        !std.meta.eql(table.plan_digest, seal.plan_digest) or
        !std.meta.eql(table.program_root, seal.program_root) or
        !std.meta.eql(table.first_roots, seal.first_roots)) return error.UntrustedProgramTableReceipt;
    var count: u64 = 0;
    for (requests) |request| {
        if (!std.meta.eql(request.sealed_channel_digest, digest)) return error.UntrustedProgramRequestReceipt;
        count = std.math.add(u64, count, request.fetch_count) catch return error.ProgramFetchCensusOverflow;
    }
    if (count != table.fetch_count) return error.UnclosedProgramRelation;
    var sink = @import("block_v5_global_join_algebra_v1.zig").ScalarSink{};
    try @import("block_v5_global_join_algebra_v1.zig").Algebra(Q).program(&sink, table.claim, requests);
}

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
        const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel);
        const Runtime = framework.Runtime(binding.Binding(Air).Runtime);

        pub const FirstRound = struct {
            scheme: Scheme,
            roots: [2]Digest,
            plan_digest: [32]u8,
            owns_scheme: bool = true,
            pub fn deinit(self: *FirstRound, a: std.mem.Allocator) void {
                if (self.owns_scheme) self.scheme.deinit(a);
                self.* = undefined;
            }
        };

        pub fn commitFirstRound(a: std.mem.Allocator, plan: source.Plan, config: core.pcs.PcsConfig) !FirstRound {
            const plan_digest = try plan.digest();
            const columns = try plan.fixedColumns(a);
            defer for (columns) |values| a.free(values);
            var scheme = try Scheme.init(a, config);
            errdefer scheme.deinit(a);
            scheme.setCoefficientRetentionPolicy(.always);
            var channel = firstChannel(plan_digest);
            var fixed: [Air.PREPROCESSED_COLUMN_COUNT]Column = undefined;
            for (columns, 0..) |values, i| fixed[i] = .{ .log_size = plan.log_size, .values = values };
            try scheme.commitBorrowedStreaming(a, &fixed, 8, &channel);
            // The authenticated program provider has no witness main columns.
            try scheme.commitBorrowedStreaming(a, &.{}, 8, &channel);
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            if (roots.items.len != 2) return error.InvalidProgramTableFirstRound;
            return .{ .scheme = scheme, .roots = .{ roots.items[0], roots.items[1] }, .plan_digest = plan_digest };
        }

        pub fn prove(a: std.mem.Allocator, first: *FirstRound, plan: source.Plan, seal: Seal) !Proof {
            if (!first.owns_scheme or !std.meta.eql(first.plan_digest, try plan.digest())) return error.UntrustedProgramTableFirstRound;
            try seal.validate(plan, first.roots);
            var definition = try Air.build(a);
            defer definition.deinit();
            const relation_plan = try binding.Binding(Air).authenticate(&definition);
            var relation_channel = seal.sharedChannel();
            const relations = try universal.UniversalRelations.draw(a, &relation_channel);
            const rows = try a.alloc(Air.Row, plan.multiplicities.len);
            defer a.free(rows);
            for (rows, 0..) |*row, i| row.* = try plan.row(i);
            var workspace = try Runtime.Workspace.init(a, @min(plan.log_size, framework.OWNED_TILE_LOG_SIZE));
            defer workspace.deinit();
            const view = Runtime.ColumnRows{ .columns = @splat(&.{}), .count = rows.len, .main_count = 0, .metadata = rows };
            var interaction = try Runtime.generatePreparedOwnedColumnsTiledWithWorkspace(a, &workspace, &relation_plan, view, plan.log_size, &relations, @as(Air.Row, @splat(M.zero())));
            defer interaction.deinit(a);
            var channel = seal.proofChannel();
            channel.mixFelts(&.{interaction.claimed_sum});
            var columns: [Air.INTERACTION_COLUMN_COUNT]Column = undefined;
            for (interaction.columns, 0..) |values, i| columns[i] = .{ .log_size = plan.log_size, .values = values };
            try first.scheme.commitBorrowedStreaming(a, &columns, 8, &channel);
            const manifest = Roster.Manifest{ .log_sizes = .{plan.log_size} };
            const component = try Roster.Component(Air).init(&definition, relation_plan, &manifest, .program, plan.log_size, .{}, &relations, interaction.claimed_sum);
            const handle = try component.asProverComponent().withCompositionGeometryOverrideV1(.{ .max_constraint_log_degree_bound_delta = 1, .composition_log_split = 2 });
            first.owns_scheme = false; // prove owns the scheme on success and error.
            return .{ .stark = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, &.{handle}, &channel, first.scheme), .claim = interaction.claimed_sum };
        }

        pub const Captured = struct {
            proof: core.verifier.ProofCapture(suite.Hasher),
            final_channel: suite.Channel,
            receipt: VerifiedReceipt,
            pub fn deinit(self: *Captured, a: std.mem.Allocator) void {
                self.proof.deinit(a);
                self.* = undefined;
            }
        };
        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, plan: source.Plan, seal: Seal, independently_pinned_root: @TypeOf(plan.program_root), expected_roots: [2]Digest, config: core.pcs.PcsConfig) !VerifiedReceipt {
            return verifyInternal(true, a, &received, plan, seal, independently_pinned_root, expected_roots, config, null, null);
        }
        /// Actual original receiver checks; capture owns its allocations and
        /// never consumes or retains received proof storage.
        pub fn verifyCaptureBorrowed(a: std.mem.Allocator, received: *const Proof, plan: source.Plan, seal: Seal, independently_pinned_root: @TypeOf(plan.program_root), expected_roots: [2]Digest, config: core.pcs.PcsConfig) !Captured {
            var captured: core.verifier.ProofCapture(suite.Hasher) = undefined;
            var end: suite.Channel = undefined;
            const receipt = try verifyInternal(false, a, received, plan, seal, independently_pinned_root, expected_roots, config, &captured, &end);
            return .{ .proof = captured, .final_channel = end, .receipt = receipt };
        }
        fn verifyInternal(comptime take: bool, a: std.mem.Allocator, received: *const Proof, plan: source.Plan, seal: Seal, independently_pinned_root: @TypeOf(plan.program_root), expected_roots: [2]Digest, config: core.pcs.PcsConfig, capture: ?*core.verifier.ProofCapture(suite.Hasher), end: ?*suite.Channel) !VerifiedReceipt {
            var proof = received.*;
            var owns = take;
            defer if (owns) proof.deinit(a);
            if (!std.meta.eql(plan.program_root, independently_pinned_root)) return error.UntrustedProgramRoot;
            try seal.validate(plan, expected_roots);
            if (!std.meta.eql(proof.stark.commitment_scheme_proof.config, config)) return error.InvalidProgramTableConfig;
            const roots = proof.stark.commitment_scheme_proof.commitments.items;
            if (roots.len != 4 or !std.meta.eql(roots[0..2].*, expected_roots)) return error.UntrustedProgramTableFirstRound;
            // Recompute the fixed root from the independently authenticated
            // complete decoded ROM and the exact admitted integer counters.
            var replay = try commitFirstRound(a, plan, config);
            defer replay.deinit(a);
            if (!std.meta.eql(replay.roots, expected_roots)) return error.UntrustedProgramTableFixedRoot;
            var channel = firstChannel(seal.plan_digest);
            var verifier = try Verifier.init(a, config);
            defer verifier.deinit(a);
            try verifier.commit(a, roots[0], &([_]u32{plan.log_size} ** Air.PREPROCESSED_COLUMN_COUNT), &channel);
            try verifier.commit(a, roots[1], &.{}, &channel);
            var relation_channel = seal.sharedChannel();
            const relations = try universal.UniversalRelations.draw(a, &relation_channel);
            channel = seal.proofChannel();
            channel.mixFelts(&.{proof.claim});
            try verifier.commit(a, roots[2], &([_]u32{plan.log_size} ** Air.INTERACTION_COLUMN_COUNT), &channel);
            var definition = try Air.build(a);
            defer definition.deinit();
            const relation_plan = try binding.Binding(Air).authenticate(&definition);
            const manifest = Roster.Manifest{ .log_sizes = .{plan.log_size} };
            const component = try Roster.Component(Air).init(&definition, relation_plan, &manifest, .program, plan.log_size, .{}, &relations, proof.claim);
            const handle = try component.asVerifierComponent().withCompositionGeometryOverrideV1(.{ .max_constraint_log_degree_bound_delta = 1, .composition_log_split = 2 });
            var digest_channel = seal.sharedChannel();
            const receipt = VerifiedReceipt{ .claim = proof.claim, .fetch_count = plan.expected_fetches, .program_root = plan.program_root, .plan_digest = seal.plan_digest, .sealed_channel_digest = digest_channel.digestBytes(), .first_roots = expected_roots };
            if (take) {
                owns = false;
                try core.verifier.verify(suite.Hasher, suite.MerkleChannel, a, &.{handle}, &channel, &verifier, proof.stark);
            } else {
                try core.verifier.verifyBorrowedWithProofCapture(suite.Hasher, suite.MerkleChannel, a, &.{handle}, &channel, &verifier, &received.stark, capture.?);
            }
            if (end) |output| output.* = channel;
            return receipt;
        }
    };
}

pub fn firstChannel(plan_digest: [32]u8) suite.Channel {
    var channel = suite.Channel{};
    channel.mixU32s(&.{ TAG, source.VERSION, 0 });
    channel.mixRoot(plan_digest);
    return channel;
}
