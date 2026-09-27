//! Experimental PCS/FRI proof path for a sorted-memory instance and the
//! universal byte-range table. It proves the typed row AIR and all 35 range
//! requests. Production block authority still needs the execution-side
//! transition emitter and authenticated initial-value provider to close the
//! remaining v2 buses under one sealed roster.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const Column = engine.pcs.ColumnEvaluation;
const memory = @import("../air/block/memory_component.zig");
const trace_mod = @import("../air/block/memory_component_trace.zig");
const stark = @import("../air/block/memory_component_stark.zig");
const range = @import("../air/block/memory_range_interaction_v2.zig");
const provider = @import("../air/block/memory_range_provider_v2.zig");
const counter_mod = @import("../air/lookups/tables/counter.zig");
const table = @import("../air/lookups/tables/component.zig");
const shared = @import("../recursion/air/universal_provider_relations.zig");
const bus = @import("block_memory_relation_v2.zig");
const manifest = @import("block_commitment_manifest.zig");
const source_seal = @import("block_memory_source_seal_v2.zig");

/// Returned only after the memory and byte-table STARK quotient and PCS
/// openings have both passed fresh verification under a trusted first round.
pub const VerifiedMemoryReceipt = struct {
    claim: memory.Claim,
    relation: bus.ComponentClaim,
    first_round_roots: [2]suite.Hasher.Hash,
    sealed_channel_digest: [32]u8,
};

/// Admit an exact sorted-memory roster after *every* receipt has been produced
/// by `verifyExperimentalOwned`. The public total must be the independently
/// sealed execution event count. Transition and initial buses are closed by
/// their own proved providers; this function closes only the cross-row link.
pub fn admitMemoryReceipts(a: std.mem.Allocator, sealed: anytype, receipts: []const VerifiedMemoryReceipt, total_rows: u64) !void {
    if (receipts.len != @as(usize, sealed.memory_instance_count)) return error.InvalidMemoryReceiptCensus;
    var channel = sealed.sharedChannel();
    const expected_digest = channel.digestBytes();
    const claims = try a.alloc(memory.Claim, receipts.len);
    defer a.free(claims);
    var link_sum = core.fields.qm31.QM31.zero();
    for (receipts, 0..) |receipt, index| {
        if (@as(usize, receipt.relation.instance_index) != index or !std.meta.eql(receipt.sealed_channel_digest, expected_digest))
            return error.InvalidMemoryReceiptCensus;
        try receipt.relation.validateCanonical();
        claims[index] = receipt.claim;
        link_sum = link_sum.add(receipt.relation.link_sum);
    }
    try memory.admitSequence(claims, total_rows);
    if (!link_sum.isZero()) return error.UnclosedBlockMemoryLink;
}

pub const Proof = struct {
    stark: suite.Proof,
    interaction_claim: bus.ComponentClaim,
    range_claims: range.Claims,
    provider_claim: core.fields.qm31.QM31,
    pub fn deinit(self: *Proof, allocator: std.mem.Allocator) void {
        self.stark.deinit(allocator);
        self.* = undefined;
    }
};

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Self = @This();
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
        const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel);
        const Digest = suite.Hasher.Hash;

        pub const FirstRound = struct {
            scheme: Scheme,
            roots: [2]Digest,
            counter: counter_mod.Counter,
            snapshot: range.CounterSnapshot,
            precommit: provider.Precommit,
            owns_scheme: bool = true,
            pub fn deinit(self: *FirstRound, allocator: std.mem.Allocator) void {
                if (self.owns_scheme) self.scheme.deinit(allocator);
                self.counter.deinit(allocator);
                self.precommit.deinit(allocator);
                self.* = undefined;
            }
            pub fn admit(self: *const FirstRound, expected: [2]Digest) !void {
                if (!std.meta.eql(self.roots, expected)) return error.BlockMemoryCommitmentReplayMismatch;
            }
        };

        /// Commit deterministic fixed columns and private main columns before
        /// the block manifest is sealed. A replayed first round must reproduce
        /// both roots exactly; no relation challenge is drawn in this phase.
        pub fn commitFirstRound(
            allocator: std.mem.Allocator,
            trace: *const trace_mod.Trace,
            config: core.pcs.PcsConfig,
        ) !FirstRound {
            if (!trace.sealed) return error.UnsealedBlockMemoryTrace;
            try trace.claim.validate();
            var definition = try memory.build(allocator, trace.claim);
            defer definition.deinit();
            const range_plan = try range.RangePlan.init(&definition);
            var counter = try counter_mod.Counter.init(allocator, .range_check_8_8);
            errdefer counter.deinit(allocator);
            const snapshot = try range.collectCounter(allocator, &range_plan, &definition, trace, &counter);
            var precommit = try provider.precommit(allocator, &counter);
            errdefer precommit.deinit(allocator);
            var scheme = try Scheme.init(allocator, config);
            errdefer scheme.deinit(allocator);
            // Mixed-size composition needs coefficients for extending the
            // smaller memory component onto the table quotient domain.
            scheme.setCoefficientRetentionPolicy(.always);
            var channel = suite.Channel{};
            mixStatement(&channel, trace.claim, 0);
            var fixed: [trace_mod.fixed_column_count + provider.FIXED_COUNT]Column = undefined;
            for (0..trace_mod.fixed_column_count) |i| fixed[i] = .{ .log_size = trace.claim.log_size, .values = trace.fixedColumn(i) };
            for (precommit.fixed, 0..) |values, i| fixed[trace_mod.fixed_column_count + i] = .{ .log_size = provider.LOG_SIZE, .values = values };
            try scheme.commitBorrowedStreaming(allocator, &fixed, 16, &channel);
            var main: [trace_mod.main_column_count + provider.MAIN_COUNT]Column = undefined;
            for (0..trace_mod.main_column_count) |i| main[i] = .{ .log_size = trace.claim.log_size, .values = trace.mainColumn(i) };
            main[trace_mod.main_column_count] = .{ .log_size = provider.LOG_SIZE, .values = precommit.multiplicity };
            try scheme.commitBorrowedStreaming(allocator, &main, 16, &channel);
            var roots = try scheme.roots(allocator);
            defer roots.deinit(allocator);
            if (roots.items.len != 2) return error.InvalidBlockMemoryFirstRound;
            return .{ .scheme = scheme, .roots = .{ roots.items[0], roots.items[1] }, .counter = counter, .snapshot = snapshot, .precommit = precommit };
        }

        /// This proves the 35 byte-range requests against a shared table in
        /// addition to the sorted row and v2 bus quotient. It remains an
        /// experimental gate until execution and initial providers close the
        /// two block-wide v2 relations in independently verified components.
        pub fn proveExperimental(
            allocator: std.mem.Allocator,
            first: *FirstRound,
            trace: *const trace_mod.Trace,
            sealed: anytype,
            instance_index: u32,
            expected_roots: [2]Digest,
        ) !Proof {
            if (!trace.sealed or !first.owns_scheme) return error.InvalidBlockMemoryProofPhase;
            if (instance_index >= sealedInstanceCount(sealed)) return error.InvalidBlockMemoryInstanceIndex;
            try first.admit(expected_roots);
            var definition = try memory.build(allocator, trace.claim);
            defer definition.deinit();
            const range_plan = try range.RangePlan.init(&definition);
            const challenges = try bus.Challenges.draw(allocator, sealed);
            var interaction = try bus.generateInteractionFromSource(allocator, &challenges, instance_index, .sorted, trace, trace.claim.log_size);
            defer interaction.deinit(allocator);
            var range_result = try range.generate(allocator, &range_plan, &definition, trace, challenges.universal_prefix.get(.range_check_8_8), first.snapshot);
            defer range_result.deinit(allocator);
            var table_interaction = try provider.finishInteraction(allocator, &first.counter, &challenges, first.precommit.counter_snapshot);
            defer table_interaction.deinit(allocator);
            if (!provider.closed(&.{range_result.claims}, &table_interaction)) return error.UnclosedBlockMemoryRangeRelation;
            var channel = sealed.sharedChannel();
            mixStatement(&channel, trace.claim, instance_index);
            try interaction.claim.mixInto(&channel);
            try range.mixClaimsInto(range_result.claims, instance_index, &channel);
            try table_interaction.mixClaimInto(&channel);
            const table_columns = table_interaction.result.columns;
            var columns: [12 + range.COLUMN_COUNT + provider.INTERACTION_COUNT]Column = undefined;
            for (interaction.columns, 0..) |values, i| columns[i] = .{ .log_size = trace.claim.log_size, .values = values };
            for (range_result.columns, 0..) |values, i| columns[12 + i] = .{ .log_size = trace.claim.log_size, .values = values };
            for (table_columns, 0..) |values, i| columns[12 + range.COLUMN_COUNT + i] = .{ .log_size = provider.LOG_SIZE, .values = values };
            try first.scheme.commitBorrowedStreaming(allocator, &columns, 8, &channel);
            const component = try stark.Component.init(&definition, trace.claim, interaction.claim, &range_plan, range_result.claims, &challenges, .{});
            const table_component = try table_interaction.component(trace_mod.fixed_column_count, trace_mod.main_column_count, 12 + range.COLUMN_COUNT);
            const table_handle = try table_component.asProverComponent().withCompositionGeometryOverrideV1(.{ .max_constraint_log_degree_bound_delta = 1, .composition_log_split = 2 });
            const handles = [_]engine.air.component_prover.ComponentProver{ component.asProverComponent(), table_handle };
            // engine.prove takes ownership even on failure (prove.zig's
            // scheme errdefer); the FirstRound must no longer deinit it.
            first.owns_scheme = false;
            return .{
                .stark = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, allocator, &handles, &channel, first.scheme),
                .interaction_claim = interaction.claim,
                .range_claims = range_result.claims,
                .provider_claim = table_interaction.claim(),
            };
        }

        /// Fresh-process verifier for the experimental quotient gate. The
        /// caller supplies a trusted first-round admission from the sealed
        /// manifest; this function also recomputes the fixed root from public
        /// claim geometry before accepting the proof's fixed commitment.
        pub fn verifyExperimentalOwned(
            allocator: std.mem.Allocator,
            received: Proof,
            claim: memory.Claim,
            sealed: anytype,
            instance_index: u32,
            expected_roots: [2]Digest,
            config: core.pcs.PcsConfig,
        ) !VerifiedMemoryReceipt {
            var proof = received;
            var owns_proof = true;
            defer if (owns_proof) proof.deinit(allocator);
            try claim.validate();
            if (instance_index >= sealedInstanceCount(sealed) or proof.interaction_claim.instance_index != instance_index)
                return error.InvalidBlockMemoryInstanceIndex;
            if (!range.closed(&.{proof.range_claims}, proof.provider_claim)) return error.UnclosedBlockMemoryRangeRelation;
            if (!std.meta.eql(proof.stark.commitment_scheme_proof.config, config)) return error.InvalidBlockMemoryProofConfig;
            const roots = proof.stark.commitment_scheme_proof.commitments.items;
            if (roots.len != 4 or !std.meta.eql(roots[0..2].*, expected_roots)) return error.BlockMemoryCommitmentReplayMismatch;
            var trusted = try trace_mod.FixedTrace.init(allocator, claim);
            defer trusted.deinit();
            var empty_counter = try counter_mod.Counter.init(allocator, .range_check_8_8);
            defer empty_counter.deinit(allocator);
            var trusted_table = try provider.precommit(allocator, &empty_counter);
            defer trusted_table.deinit(allocator);
            var fixed_columns: [trace_mod.fixed_column_count + provider.FIXED_COUNT]Column = undefined;
            for (0..trace_mod.fixed_column_count) |i| fixed_columns[i] = .{ .log_size = claim.log_size, .values = trusted.column(i) };
            for (trusted_table.fixed, 0..) |values, i| fixed_columns[trace_mod.fixed_column_count + i] = .{ .log_size = provider.LOG_SIZE, .values = values };
            var fixed_scheme = try Scheme.init(allocator, config);
            defer fixed_scheme.deinit(allocator);
            var fixed_channel = suite.Channel{};
            mixStatement(&fixed_channel, claim, 0);
            try fixed_scheme.commitBorrowedStreaming(allocator, &fixed_columns, 16, &fixed_channel);
            var trusted_roots = try fixed_scheme.roots(allocator);
            defer trusted_roots.deinit(allocator);
            if (trusted_roots.items.len != 1 or !std.meta.eql(trusted_roots.items[0], roots[0]))
                return error.UntrustedBlockMemoryFixedRoot;
            var definition = try memory.build(allocator, claim);
            defer definition.deinit();
            const range_plan = try range.RangePlan.init(&definition);
            const challenges = try bus.Challenges.draw(allocator, sealed);
            const table_relations = try shared.SharedProviderRelations.init(&challenges.universal_prefix);
            var channel = suite.Channel{};
            mixStatement(&channel, claim, 0);
            var verifier = try Verifier.init(allocator, config);
            defer verifier.deinit(allocator);
            const fixed_logs = [_]u32{claim.log_size} ** trace_mod.fixed_column_count ++ [_]u32{provider.LOG_SIZE} ** provider.FIXED_COUNT;
            const main_logs = [_]u32{claim.log_size} ** trace_mod.main_column_count ++ [_]u32{provider.LOG_SIZE} ** provider.MAIN_COUNT;
            const interaction_logs = [_]u32{claim.log_size} ** (12 + range.COLUMN_COUNT) ++ [_]u32{provider.LOG_SIZE} ** provider.INTERACTION_COUNT;
            try verifier.commit(allocator, roots[0], &fixed_logs, &channel);
            try verifier.commit(allocator, roots[1], &main_logs, &channel);
            channel = sealed.sharedChannel();
            mixStatement(&channel, claim, instance_index);
            try proof.interaction_claim.mixInto(&channel);
            try range.mixClaimsInto(proof.range_claims, instance_index, &channel);
            try provider.mixClaimValueInto(proof.provider_claim, &channel);
            try verifier.commit(allocator, roots[2], &interaction_logs, &channel);
            const component = try stark.Component.init(&definition, claim, proof.interaction_claim, &range_plan, proof.range_claims, &challenges, .{});
            const table_component = try table.LookupTableComponent.initVerifier(.range_check_8_8, trace_mod.fixed_column_count, &.{ trace_mod.fixed_column_count + 1, trace_mod.fixed_column_count + 2 }, trace_mod.main_column_count, 12 + range.COLUMN_COUNT, &table_relations.native, proof.provider_claim);
            const table_handle = try table_component.asVerifierComponent().withCompositionGeometryOverrideV1(.{ .max_constraint_log_degree_bound_delta = 1, .composition_log_split = 2 });
            const handles = [_]core.air.components.Component{ component.asVerifierComponent(), table_handle };
            var seal_channel = sealed.sharedChannel();
            const receipt = VerifiedMemoryReceipt{ .claim = claim, .relation = proof.interaction_claim, .first_round_roots = expected_roots, .sealed_channel_digest = seal_channel.digestBytes() };
            owns_proof = false;
            try core.verifier.verify(suite.Hasher, suite.MerkleChannel, allocator, &handles, &channel, &verifier, proof.stark);
            return receipt;
        }
    };
}

fn sealedInstanceCount(sealed: anytype) u32 {
    if (@TypeOf(sealed) == source_seal.SourceSeal) return sealed.memory_instance_count;
    return sealed.instance_count;
}

/// Versioned public claim encoding, replayed identically by the producer and
/// receiver before either fixed/main commitment is processed.
pub fn mixStatement(channel: anytype, claim: memory.Claim, instance_index: u32) void {
    channel.mixU32s(&.{ 0x42324d50, 2, instance_index, claim.rows, claim.log_size }); // B2MP
    channel.mixU64(claim.first_row);
    channel.mixU64(claim.total_rows);
    mixTransition(channel, claim.first);
    mixTransition(channel, claim.last);
    channel.mixU32s(&.{@intFromBool(claim.preceding != null)});
    if (claim.preceding) |preceding| mixTransition(channel, preceding);
}

fn mixTransition(channel: anytype, value: @import("../air/block/memory_transition.zig").Transition) void {
    channel.mixU32s(&.{ value.space, value.address, value.before, value.after });
    channel.mixU64(value.clock);
}

test "block-v2 experimental sorted-memory and range table prove and freshly verify" {
    const a = std.testing.allocator;
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const api = ForBackend(Cpu);
    const transition = @import("../air/block/memory_transition.zig");
    const first = transition.Transition{ .space = 1, .address = 4096, .clock = 4, .before = 7, .after = 8 };
    const second = transition.Transition{ .space = 1, .address = 4096, .clock = 9, .before = 8, .after = 10 };
    const claim = try memory.Claim.fromSummary(.{ .first_row = 0, .rows = 2, .first = first, .last = second }, 2, 8, null);
    var trace = try trace_mod.Trace.init(a, claim);
    defer trace.deinit();
    try trace.append(first);
    try trace.append(second);
    try trace.seal();
    const config = core.pcs.PcsConfig{ .pow_bits = 26, .fri_config = try core.fri.FriConfig.init(0, 1, 70) };
    var timer = try std.time.Timer.start();
    var first_round = try api.commitFirstRound(a, &trace, config);
    defer first_round.deinit(a);
    const first_round_ns = timer.lap();
    const sealed = manifest.Sealed{ .digest = @splat(19), .instance_count = 1 };
    const proof = api.proveExperimental(a, &first_round, &trace, sealed, 0, first_round.roots) catch |err| {
        std.debug.print("proveExperimental: {s}\n", .{@errorName(err)});
        return err;
    };
    const prove_ns = timer.lap();
    var proof_counter = ProofByteCounter{};
    try @import("interop_postcard").serializeProof(suite.Hasher, &proof_counter, proof.stark);
    _ = api.verifyExperimentalOwned(a, proof, claim, sealed, 0, first_round.roots, config) catch |err| {
        std.debug.print("verifyExperimentalOwned: {s}\n", .{@errorName(err)});
        return err;
    };
    const verify_ns = timer.lap();
    std.debug.print("block-v2 canonical q70/pow26 first_round_ns={d} prove_ns={d} verify_ns={d} proof_bytes={d}\n", .{ first_round_ns, prove_ns, verify_ns, proof_counter.bytes_written });
}

const ProofByteCounter = struct {
    bytes_written: usize = 0,
    pub fn writeAll(self: *ProofByteCounter, bytes: []const u8) !void { self.bytes_written += bytes.len; }
    pub fn writeByte(self: *ProofByteCounter, _: u8) !void { self.bytes_written += 1; }
};

test "block-v2 range table proves with the joint composition geometry" {
    const a = std.testing.allocator;
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const Scheme = engine.pcs.CommitmentSchemeProver(Cpu, suite.Hasher, suite.MerkleChannel);
    var counter = try counter_mod.Counter.init(a, .range_check_8_8);
    defer counter.deinit(a);
    var pre = try provider.precommit(a, &counter);
    defer pre.deinit(a);
    const sealed = manifest.Sealed{ .digest = @splat(23), .instance_count = 1 };
    const challenges = try bus.Challenges.draw(a, sealed);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var scheme = try Scheme.init(a, config);
    var owns_scheme = true;
    defer if (owns_scheme) scheme.deinit(a);
    scheme.setCoefficientRetentionPolicy(.always);
    var channel = suite.Channel{};
    var fixed: [provider.FIXED_COUNT]Column = undefined;
    for (pre.fixed, 0..) |values, i| fixed[i] = .{ .log_size = provider.LOG_SIZE, .values = values };
    try scheme.commitBorrowedStreaming(a, &fixed, 8, &channel);
    try scheme.commitBorrowedStreaming(a, &.{.{ .log_size = provider.LOG_SIZE, .values = pre.multiplicity }}, 8, &channel);
    var interaction = try provider.finishInteraction(a, &counter, &challenges, pre.counter_snapshot);
    defer interaction.deinit(a);
    channel = sealed.sharedChannel();
    try interaction.mixClaimInto(&channel);
    var columns: [provider.INTERACTION_COUNT]Column = undefined;
    for (interaction.result.columns, 0..) |values, i| columns[i] = .{ .log_size = provider.LOG_SIZE, .values = values };
    try scheme.commitBorrowedStreaming(a, &columns, 8, &channel);
    const table_component = try interaction.component(0, 0, 0);
    const table_handle = try table_component.asProverComponent().withCompositionGeometryOverrideV1(.{ .max_constraint_log_degree_bound_delta = 1, .composition_log_split = 2 });
    owns_scheme = false;
    var proof = try engine.prove.prove(Cpu, suite.Hasher, suite.MerkleChannel, a, &.{table_handle}, &channel, scheme);
    defer proof.deinit(a);
}

test "block-v2 sorted-memory quotient proves without the shared range table" {
    const a = std.testing.allocator;
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const Scheme = engine.pcs.CommitmentSchemeProver(Cpu, suite.Hasher, suite.MerkleChannel);
    const transition = @import("../air/block/memory_transition.zig");
    const first = transition.Transition{ .space = 1, .address = 4096, .clock = 4, .before = 7, .after = 8 };
    const second = transition.Transition{ .space = 1, .address = 4096, .clock = 9, .before = 8, .after = 10 };
    const claim = try memory.Claim.fromSummary(.{ .first_row = 0, .rows = 2, .first = first, .last = second }, 2, 8, null);
    var trace = try trace_mod.Trace.init(a, claim);
    defer trace.deinit();
    try trace.append(first);
    try trace.append(second);
    try trace.seal();
    var definition = try memory.build(a, claim);
    defer definition.deinit();
    const plan = try range.RangePlan.init(&definition);
    var counter = try counter_mod.Counter.init(a, .range_check_8_8);
    defer counter.deinit(a);
    const snapshot = try range.collectCounter(a, &plan, &definition, &trace, &counter);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    var scheme = try Scheme.init(a, config);
    var owns_scheme = true;
    defer if (owns_scheme) scheme.deinit(a);
    scheme.setCoefficientRetentionPolicy(.always);
    var channel = suite.Channel{};
    var fixed: [trace_mod.fixed_column_count]Column = undefined;
    for (&fixed, 0..) |*column, i| column.* = .{ .log_size = claim.log_size, .values = trace.fixedColumn(i) };
    try scheme.commitBorrowedStreaming(a, &fixed, 8, &channel);
    var main: [trace_mod.main_column_count]Column = undefined;
    for (&main, 0..) |*column, i| column.* = .{ .log_size = claim.log_size, .values = trace.mainColumn(i) };
    try scheme.commitBorrowedStreaming(a, &main, 8, &channel);
    const sealed = manifest.Sealed{ .digest = @splat(29), .instance_count = 1 };
    const challenges = try bus.Challenges.draw(a, sealed);
    var bus_interaction = try bus.generateInteractionFromSource(a, &challenges, 0, .sorted, &trace, claim.log_size);
    defer bus_interaction.deinit(a);
    var range_interaction = try range.generate(a, &plan, &definition, &trace, challenges.universal_prefix.get(.range_check_8_8), snapshot);
    defer range_interaction.deinit(a);
    channel = sealed.sharedChannel();
    try bus_interaction.claim.mixInto(&channel);
    try range.mixClaimsInto(range_interaction.claims, 0, &channel);
    var columns: [12 + range.COLUMN_COUNT]Column = undefined;
    for (bus_interaction.columns, 0..) |values, i| columns[i] = .{ .log_size = claim.log_size, .values = values };
    for (range_interaction.columns, 0..) |values, i| columns[12 + i] = .{ .log_size = claim.log_size, .values = values };
    try scheme.commitBorrowedStreaming(a, &columns, 8, &channel);
    const component = try stark.Component.init(&definition, claim, bus_interaction.claim, &plan, range_interaction.claims, &challenges, .{});
    owns_scheme = false;
    var proof = try engine.prove.prove(Cpu, suite.Hasher, suite.MerkleChannel, a, &.{component.asProverComponent()}, &channel, scheme);
    defer proof.deinit(a);
}
