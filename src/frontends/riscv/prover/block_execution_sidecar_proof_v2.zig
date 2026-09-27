//! Same-root PCS proof for one typed opcode access slot. The first two roots
//! must match a freshly verified native execution proof exactly; this sidecar
//! commits byte witnesses before the bound SourceSeal challenge and proves
//! transition plus universal byte-range interactions afterward.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const Column = engine.pcs.ColumnEvaluation;
const Q = core.fields.qm31.QM31;
const trace_mod = @import("block_execution_sidecar_trace_v2.zig");
const adapter_mod = @import("block_execution_sidecar_stark_v2.zig");
const transition = @import("block_execution_transition_interaction_v2.zig");
const range = @import("block_execution_byte_range_v2.zig");
const counter_mod = @import("../air/lookups/tables/counter.zig");
const bus = @import("block_memory_relation_v2.zig");
const seal_mod = @import("block_memory_source_seal_v2.zig");
const frame_mod = @import("../air/block/memory_event.zig");
const opcode = @import("../runner/trace.zig");

pub const TAG: u32 = 0x42324553; // B2ES
pub const VerifiedSlotReceipt = struct {
    instance_index: u32,
    family: opcode.OpcodeFamily,
    slot: usize,
    transition_sum: Q,
    active_count: u64,
    range_claims: range.Claims,
    native_roots: [2]suite.Hasher.Hash,
    witness_root: suite.Hasher.Hash,
    sealed_channel_digest: [32]u8,
};
pub const Proof = struct {
    stark: suite.Proof,
    transition_sum: Q,
    active_count: u64,
    range_claims: range.Claims,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void { self.stark.deinit(a); self.* = undefined; }
};

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
        const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel);
        const Digest = suite.Hasher.Hash;
        pub const FirstRound = struct {
            scheme: Scheme,
            roots: [3]Digest,
            fixed_logs: []u32,
            main_logs: []u32,
            snapshot: range.SNAPSHOT,
            owns_scheme: bool = true,
            pub fn deinit(self: *FirstRound, a: std.mem.Allocator) void {
                if (self.owns_scheme) self.scheme.deinit(a);
                a.free(self.fixed_logs);
                a.free(self.main_logs);
                self.* = undefined;
            }
        };

        pub fn commitFirstRound(a: std.mem.Allocator, fixed: []const Column, main: []const Column, trace: *const trace_mod.Trace, main_offset: usize, shard_counter: *counter_mod.Counter, instance_index: u32, config: core.pcs.PcsConfig) !FirstRound {
            if (main_offset + trace.main.n_columns > main.len) return error.InvalidExecutionSidecarMainOffset;
            const fixed_logs = try logs(a, fixed);
            errdefer a.free(fixed_logs);
            const main_logs = try logs(a, main);
            errdefer a.free(main_logs);
            const snapshot = try range.collectCounter(a, trace, shard_counter);
            var scheme = try Scheme.init(a, config);
            errdefer scheme.deinit(a);
            scheme.setCoefficientRetentionPolicy(.always);
            var channel = suite.Channel{};
            mixStatement(&channel, instance_index, trace.family, trace.slot, trace.log_size, trace.frame);
            try scheme.commitBorrowedStreaming(a, fixed, 16, &channel);
            try scheme.commitBorrowedStreaming(a, main, 16, &channel);
            var witness: [@import("block_execution_integer_bridge_v2.zig").COLUMN_COUNT]Column = undefined;
            for (trace.witness, &witness) |values, *column| column.* = .{ .log_size = trace.log_size, .values = values };
            try scheme.commitBorrowedStreaming(a, &witness, 16, &channel);
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            if (roots.items.len != 3) return error.InvalidExecutionSidecarFirstRound;
            return .{ .scheme = scheme, .roots = .{ roots.items[0], roots.items[1], roots.items[2] }, .fixed_logs = fixed_logs, .main_logs = main_logs, .snapshot = snapshot };
        }

        pub fn prove(a: std.mem.Allocator, first: *FirstRound, trace: *const trace_mod.Trace, sealed: seal_mod.SourceSeal, instance_index: u32, main_offset: usize, trusted_native_roots: [2]Digest, trusted_witness_root: Digest) !Proof {
            if (!sealed.bound_rosters or !first.owns_scheme or instance_index >= sealed.execution_instance_count or
                !std.meta.eql(first.roots[0..2].*, trusted_native_roots) or
                !std.meta.eql(first.roots[2], trusted_witness_root)) return error.UntrustedExecutionSidecarFirstRound;
            const challenges = try bus.Challenges.draw(a, sealed);
            const rows = try a.alloc(transition.Row, trace.domainSize());
            defer a.free(rows);
            for (rows, 0..) |*row, logical| row.* = try trace.row(logical);
            var transition_result = try transition.generate(a, &challenges, rows, trace.log_size);
            defer transition_result.deinit(a);
            var range_result = try range.generate(a, trace, challenges.universal_prefix.get(.range_check_8_8), first.snapshot);
            defer range_result.deinit(a);
            var channel = sealed.sharedChannel();
            mixStatement(&channel, instance_index, trace.family, trace.slot, trace.log_size, trace.frame);
            try mixTransitionClaim(&channel, transition_result.claim, transition_result.count, instance_index, trace.family, trace.slot);
            try range.mixClaims(range_result.claims, instance_index, trace.family, trace.slot, &channel);
            var columns: [adapter_mod.eval.INTERACTION_COUNT]Column = undefined;
            for (transition_result.columns, 0..) |values, i| columns[i] = .{ .log_size = trace.log_size, .values = values };
            for (range_result.columns, 0..) |values, i| columns[transition.COLUMN_COUNT + i] = .{ .log_size = trace.log_size, .values = values };
            try first.scheme.commitBorrowedStreaming(a, &columns, 8, &channel);
            const component = try (adapter_mod.Component{
                .family = trace.family, .slot = trace.slot, .log_size = trace.log_size,
                .base_clock = trace.base_clock, .fixed_logs = first.fixed_logs, .main_logs = first.main_logs,
                .main_offset = main_offset, .transition_claim = transition_result.claim, .transition_count = transition_result.count,
                .range_claims = range_result.claims, .challenges = &challenges,
            }).init();
            first.owns_scheme = false;
            return .{ .stark = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, &.{component.asProverComponent()}, &channel, first.scheme), .transition_sum = transition_result.claim, .active_count = transition_result.count, .range_claims = range_result.claims };
        }

        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, sealed: seal_mod.SourceSeal, instance_index: u32, family: opcode.OpcodeFamily, slot: usize, log_size: u32, frame: frame_mod.Frame, main_offset: usize, fixed_logs: []const u32, main_logs: []const u32, trusted_native_roots: [2]Digest, trusted_witness_root: Digest, config: core.pcs.PcsConfig) !VerifiedSlotReceipt {
            var proof = received;
            var owns_proof = true;
            defer if (owns_proof) proof.deinit(a);
            if (!sealed.bound_rosters or instance_index >= sealed.execution_instance_count or
                !std.meta.eql(proof.stark.commitment_scheme_proof.config, config)) return error.InvalidExecutionSidecarProof;
            const roots = proof.stark.commitment_scheme_proof.commitments.items;
            if (roots.len != 5 or !std.meta.eql(roots[0..2].*, trusted_native_roots) or
                !std.meta.eql(roots[2], trusted_witness_root)) return error.UntrustedExecutionSidecarFirstRound;
            const base_clock = try @import("block_execution_integer_bridge_v2.zig").baseClockFromPublicFrame(frame);
            const challenges = try bus.Challenges.draw(a, sealed);
            var channel = suite.Channel{};
            mixStatement(&channel, instance_index, family, slot, log_size, frame);
            var verifier = try Verifier.init(a, config);
            defer verifier.deinit(a);
            try verifier.commit(a, roots[0], fixed_logs, &channel);
            try verifier.commit(a, roots[1], main_logs, &channel);
            try verifier.commit(a, roots[2], &([_]u32{log_size} ** @import("block_execution_integer_bridge_v2.zig").COLUMN_COUNT), &channel);
            channel = sealed.sharedChannel();
            mixStatement(&channel, instance_index, family, slot, log_size, frame);
            try mixTransitionClaim(&channel, proof.transition_sum, proof.active_count, instance_index, family, slot);
            try range.mixClaims(proof.range_claims, instance_index, family, slot, &channel);
            try verifier.commit(a, roots[3], &([_]u32{log_size} ** adapter_mod.eval.INTERACTION_COUNT), &channel);
            const component = try (adapter_mod.Component{
                .family = family, .slot = slot, .log_size = log_size, .base_clock = base_clock,
                .fixed_logs = fixed_logs, .main_logs = main_logs, .main_offset = main_offset,
                .transition_claim = proof.transition_sum, .transition_count = proof.active_count, .range_claims = proof.range_claims, .challenges = &challenges,
            }).init();
            var seal_channel = sealed.sharedChannel();
            const receipt = VerifiedSlotReceipt{
                .instance_index = instance_index, .family = family, .slot = slot,
                .transition_sum = proof.transition_sum, .active_count = proof.active_count, .range_claims = proof.range_claims,
                .native_roots = trusted_native_roots, .witness_root = trusted_witness_root,
                .sealed_channel_digest = seal_channel.digestBytes(),
            };
            owns_proof = false;
            try core.verifier.verify(suite.Hasher, suite.MerkleChannel, a, &.{component.asVerifierComponent()}, &channel, &verifier, proof.stark);
            return receipt;
        }
    };
}

fn logs(a: std.mem.Allocator, columns: []const Column) ![]u32 {
    const result = try a.alloc(u32, columns.len);
    for (columns, result) |column, *log_size| log_size.* = column.log_size;
    return result;
}
fn mixStatement(channel: anytype, instance_index: u32, family: opcode.OpcodeFamily, slot: usize, log_size: u32, frame: frame_mod.Frame) void {
    channel.mixU32s(&.{ TAG, 2, instance_index, @intFromEnum(family), @intCast(slot), log_size, @intFromEnum(frame.clock_frame), frame.cycle_count });
    channel.mixU64(frame.global_first_cycle);
}
fn mixTransitionClaim(channel: anytype, claim: Q, count: u64, instance_index: u32, family: opcode.OpcodeFamily, slot: usize) !void {
    if (!@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&claim)) return error.InvalidExecutionTransitionClaim;
    channel.mixU32s(&.{ 0x42324554, 2, instance_index, @intFromEnum(family), @intCast(slot) });
    channel.mixU64(count);
    for (claim.toM31Array()) |limb| channel.mixU32s(&.{limb.toU32()});
}

test "block-v2 same-root sidecar quotient proves and freshly verifies one inactive typed slot" {
    const a = std.testing.allocator;
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const api = ForBackend(Cpu);
    const M = core.fields.m31.M31;
    const family: opcode.OpcodeFamily = .base_alu_imm;
    const frame = frame_mod.Frame{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 2 };
    var main: opcode.TraceColumns = undefined;
    main.n_columns = opcode.nColumnsForFamily(family);
    main.n_real_rows = 0;
    for (main.columns[0..main.n_columns]) |*column| {
        column.* = try a.alloc(M, 2);
        @memset(column.*, M.zero());
    }
    defer main.deinit(a);
    var trace = try trace_mod.Trace.init(a, family, &main, 0, 1, frame);
    defer trace.deinit();
    var counter = try counter_mod.Counter.init(a, .range_check_8_8);
    defer counter.deinit(a);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const fixed_values = [_]M{ M.one(), M.zero() };
    const fixed = [_]Column{.{ .log_size = 1, .values = &fixed_values }};
    const main_columns = try a.alloc(Column, main.n_columns);
    defer a.free(main_columns);
    for (main.columns[0..main.n_columns], main_columns) |values, *column| column.* = .{ .log_size = 1, .values = values };
    var first = try api.commitFirstRound(a, &fixed, main_columns, &trace, 0, &counter, 0, config);
    defer first.deinit(a);
    const native_roots: [2]suite.Hasher.Hash = first.roots[0..2].*;
    const entries = [_]seal_mod.FirstRoundEntry{
        .{ .family = .execution, .index = 0, .roots = native_roots },
        .{ .family = .execution_sidecar_witness, .index = 0, .roots = .{ first.roots[2], @splat(0) } },
    };
    const base = @import("block_commitment_manifest.zig").Sealed{ .digest = @splat(88), .instance_count = 1 };
    const sealed = try seal_mod.SourceSeal.initBound(base, 0, @splat(89), 1, 1, @splat(90), seal_mod.digestFirstRoundRoster(&entries));
    try std.testing.expectError(error.UntrustedExecutionSidecarFirstRound, api.prove(a, &first, &trace, sealed, 0, 0, .{ @splat(77), native_roots[1] }, first.roots[2]));
    const proof = try api.prove(a, &first, &trace, sealed, 0, 0, native_roots, first.roots[2]);
    const receipt = try api.verifyOwned(a, proof, sealed, 0, family, 0, 1, frame, 0, first.fixed_logs, first.main_logs, native_roots, first.roots[2], config);
    try std.testing.expect(receipt.transition_sum.isZero());
    for (receipt.range_claims) |claim| try std.testing.expect(claim.isZero());
}

test "block-v2 same-root sidecar proves an active typed ADDI access" {
    const a = std.testing.allocator;
    const Cpu = @import("stwo_cpu_backend").CpuBackend;
    const api = ForBackend(Cpu);
    const table_api = @import("block_memory_shared_table_proof_v2.zig").ForBackend(Cpu);
    const shard_mod = @import("block_memory_range_shard_v2.zig");
    const family: opcode.OpcodeFamily = .base_alu_imm;
    const frame = frame_mod.Frame{ .clock_frame = .leaf_local, .global_first_cycle = 1, .cycle_count = 1 };
    var execution = opcode.Trace.init(a);
    defer execution.deinit();
    try execution.append(.{
        .clk = 1, .pc = 0x1000, .opcode = .ADDI, .rd = 1, .rs1 = 0, .rs2 = 0,
        .imm = 1, .rs1_val = 0, .rs2_val = 0, .rd_val = 1,
        .mem_addr = 0, .mem_val = 0, .is_load = false, .is_store = false,
        .branch_taken = false, .next_pc = 0x1004, .inst_word = 0x00100093,
    });
    var main = try execution.columnsForFamily(a, family, 1);
    defer main.deinit(a);
    var trace = try trace_mod.Trace.init(a, family, &main, 0, 1, frame);
    defer trace.deinit();
    try std.testing.expect((try trace.row(0)).active);
    var counter = try counter_mod.Counter.init(a, .range_check_8_8);
    defer counter.deinit(a);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = try core.fri.FriConfig.init(0, 1, 8) };
    const M = core.fields.m31.M31;
    const fixed_values = [_]M{ M.one(), M.zero() };
    const fixed = [_]Column{.{ .log_size = 1, .values = &fixed_values }};
    const main_columns = try a.alloc(Column, main.n_columns);
    defer a.free(main_columns);
    for (main.columns[0..main.n_columns], main_columns) |values, *column| column.* = .{ .log_size = 1, .values = values };
    var first = try api.commitFirstRound(a, &fixed, main_columns, &trace, 0, &counter, 0, config);
    defer first.deinit(a);
    try std.testing.expectEqual(@as(u32, range.REQUEST_COUNT), counter.signedTotal().toU32());
    const shard = shard_mod.Shard{ .index = 0, .first_instance = 0, .instance_count = 1, .first_event = 0, .event_count = 1, .max_requests = 35 };
    var table_first = try table_api.commitFirstRound(a, &counter, shard, config);
    defer table_first.deinit(a);
    const native_roots: [2]suite.Hasher.Hash = first.roots[0..2].*;
    const entries = [_]seal_mod.FirstRoundEntry{
        .{ .family = .execution, .index = 0, .roots = native_roots },
        .{ .family = .execution_sidecar_witness, .index = 0, .roots = .{ first.roots[2], @splat(0) } },
        .{ .family = .range_table, .index = 0, .roots = table_first.roots },
    };
    const base = @import("block_commitment_manifest.zig").Sealed{ .digest = @splat(91), .instance_count = 1 };
    const sealed = try seal_mod.SourceSeal.initBound(base, 0, @splat(92), 1, 1, shard_mod.digestRoster(&.{shard}, 1, 1), seal_mod.digestFirstRoundRoster(&entries));
    const proof = try api.prove(a, &first, &trace, sealed, 0, 0, native_roots, first.roots[2]);
    const table_proof = try table_api.prove(a, &table_first, &counter, shard, sealed, table_first.roots);
    const receipt = try api.verifyOwned(a, proof, sealed, 0, family, 0, 1, frame, 0, first.fixed_logs, first.main_logs, native_roots, first.roots[2], config);
    const table_receipt = try table_api.verifyOwned(a, table_proof, shard, sealed, table_first.roots, config);
    try std.testing.expect(!receipt.transition_sum.isZero());
    var range_total = Q.zero();
    for (receipt.range_claims) |claim| range_total = range_total.add(claim);
    try std.testing.expect(!range_total.isZero());
    try std.testing.expect(range_total.add(table_receipt.claim).isZero());
}
