//! Sorted-memory instance STARK with proved universal byte-range requests.
//! The matching 8x8 table is proved once per exact field-safe shard in
//! block_memory_shared_table_proof_v2.zig.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const Column = engine.pcs.ColumnEvaluation;
const memory = @import("../air/block/memory_component.zig");
const trace_mod = @import("../air/block/memory_component_trace.zig");
const stark = @import("../air/block/memory_component_stark.zig");
const range = @import("../air/block/memory_range_interaction_v2.zig");
const counter_mod = @import("../air/lookups/tables/counter.zig");
const bus = @import("block_memory_relation_v2.zig");
const seal_mod = @import("block_memory_source_seal_v2.zig");
const old = @import("block_memory_proof_v2.zig");

pub const VerifiedRequestReceipt = struct {
    memory: old.VerifiedMemoryReceipt,
    range_claims: range.Claims,
};

pub const Proof = struct {
    stark: suite.Proof,
    relation: bus.ComponentClaim,
    range_claims: range.Claims,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        self.* = undefined;
    }
};

pub fn ForBackend(comptime Backend: type) type {
    return ForBackendMode(Backend, false);
}
pub fn ForCompactBackend(comptime Backend: type) type {
    return ForBackendMode(Backend, true);
}
fn ForBackendMode(comptime Backend: type, comptime compact: bool) type {
    return struct {
        const SourceTrace = if (compact) trace_mod.CompactTrace else trace_mod.Trace;
        const AirComponent = if (compact) stark.CompactComponent else stark.Component;
        const main_width = SourceTrace.stored_main_columns;
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
        const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel);
        const Digest = suite.Hasher.Hash;

        pub const FirstRound = struct {
            scheme: Scheme,
            roots: [2]Digest,
            snapshot: range.CounterSnapshot,
            owns_scheme: bool = true,
            pub fn deinit(self: *FirstRound, a: std.mem.Allocator) void {
                if (self.owns_scheme) self.scheme.deinit(a);
                self.* = undefined;
            }
        };

        /// First-pass result when only the prechallenge roots and range
        /// multiplicities are needed. No PCS state survives this call.
        pub const RootsOnly = struct {
            roots: [2]Digest,
            snapshot: range.CounterSnapshot,
        };

        /// Collect exactly this instance's 35 typed range effects into the
        /// shard counter, then commit its fixed/main trace before SourceSeal.
        pub fn commitFirstRound(a: std.mem.Allocator, trace: *const SourceTrace, shard_counter: *counter_mod.Counter, instance_index: u32, config: core.pcs.PcsConfig) !FirstRound {
            return commitWithRetention(a, trace, shard_counter, instance_index, config, true);
        }

        /// Commit the exact same fixed/main columns with no retained
        /// coefficient copies. The caller must replay with `commitFirstRound`
        /// before proving, then compare these prechallenge roots.
        pub fn commitFirstRoundRootsOnly(a: std.mem.Allocator, trace: *const SourceTrace, shard_counter: *counter_mod.Counter, instance_index: u32, config: core.pcs.PcsConfig) !RootsOnly {
            var first = try commitWithRetention(a, trace, shard_counter, instance_index, config, false);
            defer first.deinit(a);
            return .{ .roots = first.roots, .snapshot = first.snapshot };
        }

        fn commitWithRetention(a: std.mem.Allocator, trace: *const SourceTrace, shard_counter: *counter_mod.Counter, instance_index: u32, config: core.pcs.PcsConfig, retain_coefficients: bool) !FirstRound {
            if (!trace.sealed) return error.UnsealedBlockMemoryTrace;
            try trace.claim.validate();
            var definition = try memory.build(a, trace.claim);
            defer definition.deinit();
            const plan = try range.RangePlan.init(&definition);
            const snapshot = try range.collectCounter(a, &plan, &definition, trace, shard_counter);
            var scheme = try Scheme.init(a, config);
            errdefer scheme.deinit(a);
            scheme.setCoefficientRetentionPolicy(if (retain_coefficients) .always else .never);
            var channel = suite.Channel{};
            old.mixStatement(&channel, trace.claim, instance_index);
            var fixed: [trace_mod.fixed_column_count]Column = undefined;
            for (&fixed, 0..) |*column, i| column.* = .{ .log_size = trace.claim.log_size, .values = trace.fixedColumn(i) };
            try scheme.commitBorrowedStreaming(a, &fixed, 16, &channel);
            var main: [main_width]Column = undefined;
            for (&main, 0..) |*column, i| column.* = .{ .log_size = trace.claim.log_size, .values = trace.mainColumn(i) };
            try scheme.commitBorrowedStreaming(a, &main, 16, &channel);
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            if (roots.items.len != 2) return error.InvalidBlockMemoryFirstRound;
            return .{ .scheme = scheme, .roots = .{ roots.items[0], roots.items[1] }, .snapshot = snapshot };
        }

        /// Rebuild one instance from its persisted sorted-transition span
        /// after the complete first-round roster has been sealed. This needs
        /// only one trace/scheme in memory at a time, and catches spool drift.
        pub fn replayFirstRound(a: std.mem.Allocator, trace: *const SourceTrace, instance_index: u32, expected_roots: [2]Digest, config: core.pcs.PcsConfig) !FirstRound {
            var local = try counter_mod.Counter.init(a, .range_check_8_8);
            defer local.deinit(a);
            var replay = try commitFirstRound(a, trace, &local, instance_index, config);
            errdefer replay.deinit(a);
            if (!std.meta.eql(replay.roots, expected_roots)) return error.BlockMemoryCommitmentReplayMismatch;
            return replay;
        }

        pub fn prove(a: std.mem.Allocator, first: *FirstRound, trace: *const SourceTrace, sealed: anytype, instance_index: u32, expected_roots: [2]Digest) !Proof {
            if (!first.owns_scheme or !trace.sealed or !std.meta.eql(first.roots, expected_roots)) return error.UntrustedBlockMemoryFirstRound;
            if (instance_index >= sealed.memory_instance_count) return error.InvalidBlockMemoryInstanceIndex;
            var definition = try memory.build(a, trace.claim);
            defer definition.deinit();
            const plan = try range.RangePlan.init(&definition);
            const challenges = try bus.Challenges.draw(a, sealed);
            var relation = try bus.generateInteractionFromSource(a, &challenges, instance_index, .sorted, trace, trace.claim.log_size);
            defer relation.deinit(a);
            var requests = try range.generate(a, &plan, &definition, trace, challenges.universal_prefix.get(.range_check_8_8), first.snapshot);
            defer requests.deinit(a);
            var channel = sealed.sharedChannel();
            old.mixStatement(&channel, trace.claim, instance_index);
            try relation.claim.mixInto(&channel);
            try range.mixClaimsInto(requests.claims, instance_index, &channel);
            var columns: [12 + range.COLUMN_COUNT]Column = undefined;
            for (relation.columns, 0..) |values, i| columns[i] = .{ .log_size = trace.claim.log_size, .values = values };
            for (requests.columns, 0..) |values, i| columns[12 + i] = .{ .log_size = trace.claim.log_size, .values = values };
            try first.scheme.commitBorrowedStreaming(a, &columns, 8, &channel);
            const component = try AirComponent.init(&definition, trace.claim, relation.claim, &plan, requests.claims, &challenges, .{});
            first.owns_scheme = false;
            return .{ .stark = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, &.{component.asProverComponent()}, &channel, first.scheme), .relation = relation.claim, .range_claims = requests.claims };
        }

        /// Freshly verify the instance quotient and all byte-range request
        /// claims. Its receipt is admitted only after its shard table verifies.
        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, claim: memory.Claim, sealed: anytype, instance_index: u32, expected_roots: [2]Digest, config: core.pcs.PcsConfig) !VerifiedRequestReceipt {
            var proof = received;
            var owns_proof = true;
            defer if (owns_proof) proof.deinit(a);
            try claim.validate();
            if (instance_index >= sealed.memory_instance_count or proof.relation.instance_index != instance_index) return error.InvalidBlockMemoryInstanceIndex;
            if (!std.meta.eql(proof.stark.commitment_scheme_proof.config, config)) return error.InvalidBlockMemoryProofConfig;
            const roots = proof.stark.commitment_scheme_proof.commitments.items;
            if (roots.len != 4 or !std.meta.eql(roots[0..2].*, expected_roots)) return error.UntrustedBlockMemoryFirstRound;
            var trusted_fixed = try trace_mod.FixedTrace.init(a, claim);
            defer trusted_fixed.deinit();
            var fixed: [trace_mod.fixed_column_count]Column = undefined;
            for (&fixed, 0..) |*column, i| column.* = .{ .log_size = claim.log_size, .values = trusted_fixed.column(i) };
            var fixed_scheme = try Scheme.init(a, config);
            defer fixed_scheme.deinit(a);
            var fixed_channel = suite.Channel{};
            old.mixStatement(&fixed_channel, claim, instance_index);
            try fixed_scheme.commitBorrowedStreaming(a, &fixed, 16, &fixed_channel);
            var fixed_roots = try fixed_scheme.roots(a);
            defer fixed_roots.deinit(a);
            if (fixed_roots.items.len != 1 or !std.meta.eql(fixed_roots.items[0], roots[0])) return error.UntrustedBlockMemoryFixedRoot;
            var definition = try memory.build(a, claim);
            defer definition.deinit();
            const plan = try range.RangePlan.init(&definition);
            const challenges = try bus.Challenges.draw(a, sealed);
            var channel = suite.Channel{};
            old.mixStatement(&channel, claim, instance_index);
            var verifier = try Verifier.init(a, config);
            defer verifier.deinit(a);
            try verifier.commit(a, roots[0], &([_]u32{claim.log_size} ** trace_mod.fixed_column_count), &channel);
            try verifier.commit(a, roots[1], &([_]u32{claim.log_size} ** main_width), &channel);
            channel = sealed.sharedChannel();
            old.mixStatement(&channel, claim, instance_index);
            try proof.relation.mixInto(&channel);
            try range.mixClaimsInto(proof.range_claims, instance_index, &channel);
            try verifier.commit(a, roots[2], &([_]u32{claim.log_size} ** (12 + range.COLUMN_COUNT)), &channel);
            const component = try AirComponent.init(&definition, claim, proof.relation, &plan, proof.range_claims, &challenges, .{});
            var seal_channel = sealed.sharedChannel();
            const receipt = VerifiedRequestReceipt{
                .memory = .{ .claim = claim, .relation = proof.relation, .first_round_roots = expected_roots, .sealed_channel_digest = seal_channel.digestBytes() },
                .range_claims = proof.range_claims,
            };
            owns_proof = false;
            try core.verifier.verify(suite.Hasher, suite.MerkleChannel, a, &.{component.asVerifierComponent()}, &channel, &verifier, proof.stark);
            return receipt;
        }
    };
}

test "block V2 range memory request and shared table prove under one source seal" {
    const a = std.testing.allocator;
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const api = ForBackend(Cpu);
    const table_api = @import("block_memory_shared_table_proof_v2.zig").ForBackend(Cpu);
    const shard_mod = @import("block_memory_range_shard_v2.zig");
    const Transition = @import("../air/block/memory_transition.zig").Transition;
    const first_event = Transition{ .space = 1, .address = 4096, .clock = 4, .before = 7, .after = 8 };
    const second_event = Transition{ .space = 1, .address = 4096, .clock = 9, .before = 8, .after = 10 };
    const claim = try memory.Claim.fromSummary(.{ .first_row = 0, .rows = 2, .first = first_event, .last = second_event }, 2, 8, null);
    var trace = try trace_mod.Trace.init(a, claim);
    defer trace.deinit();
    try trace.append(first_event);
    try trace.append(second_event);
    try trace.seal();
    var counter = try counter_mod.Counter.init(a, .range_check_8_8);
    defer counter.deinit(a);
    const config = core.pcs.PcsConfig{ .pow_bits = 26, .fri_config = try core.fri.FriConfig.init(0, 1, 70) };
    var timer = try std.time.Timer.start();
    var memory_first = try api.commitFirstRound(a, &trace, &counter, 0, config);
    defer memory_first.deinit(a);
    var roots_only_counter = try counter_mod.Counter.init(a, .range_check_8_8);
    defer roots_only_counter.deinit(a);
    const roots_only = try api.commitFirstRoundRootsOnly(a, &trace, &roots_only_counter, 0, config);
    try std.testing.expectEqualDeep(memory_first.roots, roots_only.roots);
    try std.testing.expectEqualDeep(memory_first.snapshot, roots_only.snapshot);
    try std.testing.expectEqualDeep(range.counterSnapshot(&counter), range.counterSnapshot(&roots_only_counter));
    var shard_plan = try shard_mod.plan(a, &.{claim}, 2);
    defer shard_plan.deinit(a);
    var table_first = try table_api.commitFirstRound(a, &counter, shard_plan.shards[0], config);
    defer table_first.deinit(a);
    const first_ns = timer.lap();
    const base = @import("block_commitment_manifest.zig").Sealed{ .digest = @splat(43), .instance_count = 1 };
    const entries = [_]seal_mod.FirstRoundEntry{
        .{ .family = .memory, .index = 0, .roots = memory_first.roots },
        .{ .family = .range_table, .index = 0, .roots = table_first.roots },
    };
    const sealed = try seal_mod.SourceSeal.initBound(base, 0, @splat(44), 1, 1, shard_plan.digest, seal_mod.digestFirstRoundRoster(&entries));
    const memory_proof = try api.prove(a, &memory_first, &trace, sealed, 0, memory_first.roots);
    const table_proof = try table_api.prove(a, &table_first, &counter, shard_plan.shards[0], sealed, table_first.roots);
    const prove_ns = timer.lap();
    var memory_bytes = ByteCounter{};
    try @import("interop_postcard").serializeProof(suite.Hasher, &memory_bytes, memory_proof.stark);
    var table_bytes = ByteCounter{};
    try @import("interop_postcard").serializeProof(suite.Hasher, &table_bytes, table_proof.stark);
    const memory_receipt = try api.verifyOwned(a, memory_proof, claim, sealed, 0, memory_first.roots, config);
    const table_receipt = try table_api.verifyOwned(a, table_proof, shard_plan.shards[0], sealed, table_first.roots, config);
    try old.admitMemoryReceipts(a, sealed, &.{memory_receipt.memory}, 2);
    try @import("block_memory_shared_table_proof_v2.zig").closed(&shard_plan, sealed, &.{table_receipt}, &.{memory_receipt.range_claims});
    const verify_ns = timer.lap();
    std.debug.print("block-v2 shared request+table q70/pow26 first_ns={d} prove_ns={d} verify_ns={d} memory_bytes={d} table_bytes={d}\n", .{ first_ns, prove_ns, verify_ns, memory_bytes.bytes_written, table_bytes.bytes_written });
}

const ByteCounter = struct {
    bytes_written: usize = 0,
    pub fn writeAll(self: *ByteCounter, bytes: []const u8) !void {
        self.bytes_written += bytes.len;
    }
    pub fn writeByte(self: *ByteCounter, _: u8) !void {
        self.bytes_written += 1;
    }
};
