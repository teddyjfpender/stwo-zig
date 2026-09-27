//! One proved 8x8 range table per exact, field-safe block-memory shard.
//! The table main commitment is made before SourceSeal challenge derivation;
//! per-instance range requests are proved separately and canceled only after
//! every proof in the shard has passed fresh verification.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const Column = engine.pcs.ColumnEvaluation;
const counter_mod = @import("../air/lookups/tables/counter.zig");
const table = @import("../air/lookups/tables/component.zig");
const provider = @import("../air/block/memory_range_provider_v2.zig");
const range = @import("../air/block/memory_range_interaction_v2.zig");
const bus = @import("block_memory_relation_v2.zig");
const shard_mod = @import("block_memory_range_shard_v2.zig");
const seal_mod = @import("block_memory_source_seal_v2.zig");
const shared = @import("../recursion/air/universal_provider_relations.zig");

pub const TAG: u32 = 0x42325354; // B2ST
pub const VerifiedTableReceipt = struct {
    shard: shard_mod.Shard,
    claim: core.fields.qm31.QM31,
    first_round_roots: [2]suite.Hasher.Hash,
    sealed_channel_digest: [32]u8,
};

pub const Proof = struct {
    stark: suite.Proof,
    claim: core.fields.qm31.QM31,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        self.* = undefined;
    }
};

/// A structural claim check. Call only with receipts returned by the fresh
/// verifier below and by the matching memory-instance proof verifier.
pub fn closed(plan: *const shard_mod.Plan, sealed: anytype, table_receipts: []const VerifiedTableReceipt, requests: []const range.Claims) !void {
    if (!sealed.bound_rosters or !std.meta.eql(sealed.range_shard_digest, plan.digest))
        return error.UnboundSharedRangeRoster;
    if (table_receipts.len != plan.shards.len or requests.len != plan.total_instances)
        return error.InvalidSharedRangeReceiptCensus;
    var channel = sealed.sharedChannel();
    const digest = channel.digestBytes();
    for (table_receipts, plan.shards) |receipt, shard| {
        if (!std.meta.eql(receipt.shard, shard) or !std.meta.eql(receipt.sealed_channel_digest, digest))
            return error.InvalidSharedRangeShard;
        const first: usize = shard.first_instance;
        const count: usize = shard.instance_count;
        if (!range.closed(requests[first..][0..count], receipt.claim))
            return error.UnclosedSharedRangeRelation;
    }
}

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
        const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel);
        const Digest = suite.Hasher.Hash;

        pub const FirstRound = struct {
            scheme: Scheme,
            roots: [2]Digest,
            precommit: provider.Precommit,
            owns_scheme: bool = true,
            pub fn deinit(self: *FirstRound, a: std.mem.Allocator) void {
                if (self.owns_scheme) self.scheme.deinit(a);
                self.precommit.deinit(a);
                self.* = undefined;
            }
        };

        /// `counter` must have collected exactly the instances in `shard`
        /// before this phase. The global roster/admission checks that fact.
        pub fn commitFirstRound(a: std.mem.Allocator, counter: *const counter_mod.Counter, shard: shard_mod.Shard, config: core.pcs.PcsConfig) !FirstRound {
            try shard.validate();
            var pre = try provider.precommit(a, counter);
            errdefer pre.deinit(a);
            var scheme = try Scheme.init(a, config);
            errdefer scheme.deinit(a);
            scheme.setCoefficientRetentionPolicy(.always);
            var channel = suite.Channel{};
            mixShard(&channel, shard);
            var fixed: [provider.FIXED_COUNT]Column = undefined;
            for (pre.fixed, 0..) |values, i| fixed[i] = .{ .log_size = provider.LOG_SIZE, .values = values };
            try scheme.commitBorrowedStreaming(a, &fixed, 8, &channel);
            try scheme.commitBorrowedStreaming(a, &.{.{ .log_size = provider.LOG_SIZE, .values = pre.multiplicity }}, 8, &channel);
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            if (roots.items.len != 2) return error.InvalidSharedRangeFirstRound;
            return .{ .scheme = scheme, .roots = .{ roots.items[0], roots.items[1] }, .precommit = pre };
        }

        /// Rebuild one table from its persisted exact shard counter after
        /// SourceSeal, rather than retaining all table PCS schemes in RAM.
        pub fn replayFirstRound(a: std.mem.Allocator, counter: *const counter_mod.Counter, shard: shard_mod.Shard, expected_roots: [2]Digest, config: core.pcs.PcsConfig) !FirstRound {
            var replay = try commitFirstRound(a, counter, shard, config);
            errdefer replay.deinit(a);
            if (!std.meta.eql(replay.roots, expected_roots)) return error.SharedRangeCommitmentReplayMismatch;
            return replay;
        }

        pub fn prove(a: std.mem.Allocator, first: *FirstRound, counter: *const counter_mod.Counter, shard: shard_mod.Shard, sealed: anytype, expected_roots: [2]Digest) !Proof {
            if (!first.owns_scheme or !std.meta.eql(first.roots, expected_roots)) return error.UntrustedSharedRangeFirstRound;
            try shard.validate();
            const challenges = try bus.Challenges.draw(a, sealed);
            var interaction = try provider.finishInteraction(a, counter, &challenges, first.precommit.counter_snapshot);
            defer interaction.deinit(a);
            var channel = sealed.sharedChannel();
            mixShard(&channel, shard);
            try interaction.mixClaimInto(&channel);
            var columns: [provider.INTERACTION_COUNT]Column = undefined;
            for (interaction.result.columns, 0..) |values, i| columns[i] = .{ .log_size = provider.LOG_SIZE, .values = values };
            try first.scheme.commitBorrowedStreaming(a, &columns, 8, &channel);
            const component = try interaction.component(0, 0, 0);
            const handle = try component.asProverComponent().withCompositionGeometryOverrideV1(.{ .max_constraint_log_degree_bound_delta = 1, .composition_log_split = 2 });
            first.owns_scheme = false; // engine.prove takes ownership on success and failure.
            return .{ .stark = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, &.{handle}, &channel, first.scheme), .claim = interaction.claim() };
        }

        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, shard: shard_mod.Shard, sealed: anytype, expected_roots: [2]Digest, config: core.pcs.PcsConfig) !VerifiedTableReceipt {
            var proof = received;
            var owns_proof = true;
            defer if (owns_proof) proof.deinit(a);
            try shard.validate();
            if (!std.meta.eql(proof.stark.commitment_scheme_proof.config, config)) return error.InvalidSharedRangeConfig;
            const roots = proof.stark.commitment_scheme_proof.commitments.items;
            if (roots.len != 4 or !std.meta.eql(roots[0..2].*, expected_roots)) return error.UntrustedSharedRangeFirstRound;

            // Recompute the deterministic 8x8 tuple-table fixed root locally.
            var empty = try counter_mod.Counter.init(a, .range_check_8_8);
            defer empty.deinit(a);
            var trusted_fixed = try provider.precommit(a, &empty);
            defer trusted_fixed.deinit(a);
            var fixed: [provider.FIXED_COUNT]Column = undefined;
            for (trusted_fixed.fixed, 0..) |values, i| fixed[i] = .{ .log_size = provider.LOG_SIZE, .values = values };
            var fixed_scheme = try Scheme.init(a, config);
            defer fixed_scheme.deinit(a);
            var fixed_channel = suite.Channel{};
            mixShard(&fixed_channel, shard);
            try fixed_scheme.commitBorrowedStreaming(a, &fixed, 8, &fixed_channel);
            var fixed_roots = try fixed_scheme.roots(a);
            defer fixed_roots.deinit(a);
            if (fixed_roots.items.len != 1 or !std.meta.eql(fixed_roots.items[0], roots[0]))
                return error.UntrustedSharedRangeFixedRoot;

            const challenges = try bus.Challenges.draw(a, sealed);
            const relations = try shared.SharedProviderRelations.init(&challenges.universal_prefix);
            var channel = suite.Channel{};
            mixShard(&channel, shard);
            var verifier = try Verifier.init(a, config);
            defer verifier.deinit(a);
            try verifier.commit(a, roots[0], &([_]u32{provider.LOG_SIZE} ** provider.FIXED_COUNT), &channel);
            try verifier.commit(a, roots[1], &([_]u32{provider.LOG_SIZE} ** provider.MAIN_COUNT), &channel);
            channel = sealed.sharedChannel();
            mixShard(&channel, shard);
            try provider.mixClaimValueInto(proof.claim, &channel);
            try verifier.commit(a, roots[2], &([_]u32{provider.LOG_SIZE} ** provider.INTERACTION_COUNT), &channel);
            const component = try table.LookupTableComponent.initVerifier(.range_check_8_8, 0, &.{ 1, 2 }, 0, 0, &relations.native, proof.claim);
            const handle = try component.asVerifierComponent().withCompositionGeometryOverrideV1(.{ .max_constraint_log_degree_bound_delta = 1, .composition_log_split = 2 });
            var seal_channel = sealed.sharedChannel();
            const receipt = VerifiedTableReceipt{ .shard = shard, .claim = proof.claim, .first_round_roots = expected_roots, .sealed_channel_digest = seal_channel.digestBytes() };
            owns_proof = false;
            try core.verifier.verify(suite.Hasher, suite.MerkleChannel, a, &.{handle}, &channel, &verifier, proof.stark);
            return receipt;
        }
    };
}

fn mixShard(channel: anytype, shard: shard_mod.Shard) void {
    channel.mixU32s(&.{ TAG, 2, shard.index, shard.first_instance, shard.instance_count });
    channel.mixU64(shard.first_event);
    channel.mixU64(shard.event_count);
    channel.mixU64(shard.max_requests);
}

test "block V2 range shared table proves and freshly verifies one shard" {
    const a = std.testing.allocator;
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const api = ForBackend(Cpu);
    var counter = try counter_mod.Counter.init(a, .range_check_8_8);
    defer counter.deinit(a);
    try counter.registerBase(core.fields.m31.M31.one(), &.{ core.fields.m31.M31.zero(), core.fields.m31.M31.zero() });
    const shard = shard_mod.Shard{ .index = 0, .first_instance = 0, .instance_count = 1, .first_event = 0, .event_count = 1, .max_requests = 35 };
    const config = core.pcs.PcsConfig{ .pow_bits = 26, .fri_config = try core.fri.FriConfig.init(0, 1, 70) };
    var timer = try std.time.Timer.start();
    var first = try api.commitFirstRound(a, &counter, shard, config);
    defer first.deinit(a);
    const first_ns = timer.lap();
    const base = @import("block_commitment_manifest.zig").Sealed{ .digest = @splat(21), .instance_count = 1 };
    const entry = seal_mod.FirstRoundEntry{ .family = .range_table, .index = 0, .roots = first.roots };
    const sealed = try seal_mod.SourceSeal.initBound(base, 0, @splat(33), 1, 1, shard_mod.digestRoster(&.{shard}, 1, 1), seal_mod.digestFirstRoundRoster(&.{entry}));
    const tampered_roots: [2]suite.Hasher.Hash = .{ @splat(99), first.roots[1] };
    try std.testing.expectError(error.UntrustedSharedRangeFirstRound, api.prove(a, &first, &counter, shard, sealed, tampered_roots));
    counter.values[0] = core.fields.m31.M31.zero();
    try std.testing.expectError(error.BlockRangeCounterChangedAfterSeal, api.prove(a, &first, &counter, shard, sealed, first.roots));
    counter.values[0] = core.fields.m31.M31.one();
    const proof = try api.prove(a, &first, &counter, shard, sealed, first.roots);
    const prove_ns = timer.lap();
    var bytes = ByteCounter{};
    try @import("interop_postcard").serializeProof(suite.Hasher, &bytes, proof.stark);
    const receipt = try api.verifyOwned(a, proof, shard, sealed, first.roots, config);
    const verify_ns = timer.lap();
    try std.testing.expectEqual(shard, receipt.shard);
    try std.testing.expect(!receipt.claim.isZero());
    std.debug.print("block-v2 shared table q70/pow26 first_ns={d} prove_ns={d} verify_ns={d} proof_bytes={d}\n", .{ first_ns, prove_ns, verify_ns, bytes.bytes_written });
}

const ByteCounter = struct {
    bytes_written: usize = 0,
    pub fn writeAll(self: *ByteCounter, bytes: []const u8) !void { self.bytes_written += bytes.len; }
    pub fn writeByte(self: *ByteCounter, _: u8) !void { self.bytes_written += 1; }
};
