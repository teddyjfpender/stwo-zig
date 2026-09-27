//! One same-root STARK for every typed memory-access slot in an execution
//! segment. The caller derives the ordered roster from the freshly verified
//! native statement; no witness-selected slot can be omitted.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const Column = engine.pcs.ColumnEvaluation;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const opcode = @import("../runner/trace.zig");
const frame_mod = @import("../air/block/memory_event.zig");
const source = @import("block_execution_access_bridge_v2.zig");
const trace_mod = @import("block_execution_sidecar_trace_v2.zig");
const integer = @import("block_execution_integer_bridge_v2.zig");
const transition = @import("block_execution_transition_interaction_v2.zig");
const range = @import("block_execution_byte_range_v2.zig");
const adapter_mod = @import("block_execution_sidecar_stark_v2.zig");
const bus = @import("block_memory_relation_v2.zig");
const seal_mod = @import("block_memory_source_seal_v2.zig");
const counter_mod = @import("../air/lookups/tables/counter.zig");

pub const TAG: u32 = 0x42324542; // B2EB
/// Family-seven preseal root for a segment whose trusted native statement has
/// no typed opcode memory-access slots. Such a segment has no sidecar STARK;
/// the receiver must freshly verify its native proof before issuing a zero
/// access receipt and must reject any nonempty sidecar wire.
pub fn emptyWitnessRoot() suite.Hasher.Hash {
    var digest: suite.Hasher.Hash = undefined;
    std.crypto.hash.Blake3.hash("stwo-zig/block-execution/empty-opcode-witness/v4\x00", &digest, .{});
    return digest;
}
pub const Slot = struct {
    family: opcode.OpcodeFamily,
    slot: usize,
    log_size: u32,
    main_offset: usize,
    frame: frame_mod.Frame,
};
pub const Input = struct { descriptor: Slot, trace: *const trace_mod.Trace };
pub const Claim = struct {
    transition_sum: Q,
    range_claims: range.Claims,
    active_count: u64,
};
pub const VerifiedExecutionReceipt = struct {
    instance_index: u32,
    transition_sum: Q,
    event_count: u64,
    range_claims: []range.Claims,
    native_roots: [2]suite.Hasher.Hash,
    witness_root: suite.Hasher.Hash,
    native_key_id: [32]u8,
    sealed_channel_digest: [32]u8,
    pub fn deinit(self: *VerifiedExecutionReceipt, a: std.mem.Allocator) void {
        a.free(self.range_claims);
        self.* = undefined;
    }
    /// Structural projection for the global transition-closure helper. Only
    /// construct this from a receipt returned by fresh `verifyOwned`.
    pub fn closureReceipt(self: *const VerifiedExecutionReceipt) @import("block_memory_execution_proof_v2.zig").VerifiedExecutionReceipt {
        return .{
            .instance_index = self.instance_index,
            .transition_sum = self.transition_sum,
            .first_round_roots = self.native_roots,
            .sealed_channel_digest = self.sealed_channel_digest,
            .event_count = self.event_count,
        };
    }
};
pub const Proof = struct {
    stark: suite.Proof,
    claims: []Claim,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        a.free(self.claims);
        self.* = undefined;
    }
};

/// The trusted native statement supplies one descriptor per present opcode
/// component. All typed access slots are deterministically enumerated here.
pub fn slotsFromStatement(a: std.mem.Allocator, statement: anytype, frame: frame_mod.Frame) ![]Slot {
    return slotsFromStatementForMode(a, statement, frame, 0);
}
/// Mode one routes only independently typed RW accesses to packed sorted
/// memory. Register accesses remain in the authenticated native/window bus.
pub fn slotsFromStatementForMode(a: std.mem.Allocator, statement: anytype, frame: frame_mod.Frame, mode: u32) ![]Slot {
    if (mode > 1) return error.InvalidV5RegisterCustodyMode;
    var slots: std.ArrayList(Slot) = .empty;
    errdefer slots.deinit(a);
    var offset: usize = 0;
    for (statement.component_descs[0..statement.n_components]) |component| {
        const family = component.family;
        const main_count = opcode.nColumnsForFamily(family);
        if (component.n_columns != main_count) return error.InvalidExecutionSlotStatement;
        const zeros: [opcode.MAX_FAMILY_COLUMNS]Q = @splat(Q.zero());
        const pairs = try source.fromCommittedMain(Q, family, zeros[0..main_count]);
        for (pairs.items[0..pairs.len], 0..) |pair, slot| {
            if (mode == 1 and pair.space.eql(Q.zero()) and !source.hasConditionalSpace(family, slot)) continue;
            if (!pair.space.eql(Q.zero()) and !pair.space.eql(Q.one())) return error.InvalidExecutionSlotSpace;
            try slots.append(a, .{ .family = family, .slot = slot, .log_size = component.log_size, .main_offset = offset, .frame = frame });
        }
        offset += main_count;
    }
    return slots.toOwnedSlice(a);
}

pub fn requireRwSlots(slots: []const Slot, mode: u32) !void {
    if (mode > 1) return error.InvalidV5RegisterCustodyMode;
    if (mode == 0) return;
    for (slots) |slot| {
        const zeros: [opcode.MAX_FAMILY_COLUMNS]Q = @splat(Q.zero());
        const pairs = try source.fromCommittedMain(Q, slot.family, zeros[0..opcode.nColumnsForFamily(slot.family)]);
        if (slot.slot >= pairs.len) return error.MixedV5OpcodeMemoryScope;
        _ = try source.rwPairForMode(Q, slot.family, slot.slot, pairs.items[slot.slot], mode);
    }
}

fn validateInputs(inputs: []const Input, expected: []const Slot) !void {
    if (inputs.len != expected.len or inputs.len == 0) return error.InvalidExecutionSlotRoster;
    for (inputs, expected) |input, descriptor| {
        if (!std.meta.eql(input.descriptor, descriptor) or input.trace.family != descriptor.family or
            input.trace.slot != descriptor.slot or input.trace.log_size != descriptor.log_size or
            !std.meta.eql(input.trace.frame, descriptor.frame)) return error.InvalidExecutionSlotRoster;
    }
}

pub fn mixRoster(channel: anytype, instance_index: u32, native_key_id: [32]u8, slots: []const Slot) void {
    channel.mixU32s(&.{ TAG, 1, instance_index, @intCast(slots.len) });
    channel.mixRoot(native_key_id);
    for (slots) |slot| {
        channel.mixU32s(&.{ @intFromEnum(slot.family), @intCast(slot.slot), slot.log_size, @intCast(slot.main_offset), @intFromEnum(slot.frame.clock_frame), slot.frame.cycle_count });
        channel.mixU64(slot.frame.global_first_cycle);
    }
}
fn mixClaims(channel: anytype, instance_index: u32, slots: []const Slot, claims: []const Claim) !void {
    if (slots.len != claims.len) return error.InvalidExecutionSlotClaims;
    for (slots, claims) |slot, claim| {
        if (!@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&claim.transition_sum)) return error.InvalidExecutionTransitionClaim;
        channel.mixU32s(&.{ TAG, 2, instance_index, @intFromEnum(slot.family), @intCast(slot.slot) });
        channel.mixU64(claim.active_count);
        for (claim.transition_sum.toM31Array()) |limb| channel.mixU32s(&.{limb.toU32()});
        try range.mixClaims(claim.range_claims, instance_index, slot.family, slot.slot, channel);
    }
}

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
            snapshots: []range.SNAPSHOT,
            owns_scheme: bool = true,
            pub fn deinit(self: *FirstRound, a: std.mem.Allocator) void {
                if (self.owns_scheme) self.scheme.deinit(a);
                a.free(self.fixed_logs);
                a.free(self.main_logs);
                a.free(self.snapshots);
                self.* = undefined;
            }
        };

        pub fn commitFirstRound(a: std.mem.Allocator, fixed: []const Column, main: []const Column, inputs: []const Input, expected: []const Slot, counter: *counter_mod.Counter, instance_index: u32, native_key_id: [32]u8, config: core.pcs.PcsConfig) !FirstRound {
            try validateInputs(inputs, expected);
            const fixed_logs = try columnLogs(a, fixed);
            errdefer a.free(fixed_logs);
            const main_logs = try columnLogs(a, main);
            errdefer a.free(main_logs);
            var witness: std.ArrayList(Column) = .empty;
            defer witness.deinit(a);
            const snapshots = try a.alloc(range.SNAPSHOT, inputs.len);
            errdefer a.free(snapshots);
            for (inputs, snapshots) |input, *snapshot| {
                if (input.descriptor.main_offset + input.trace.main.n_columns > main.len) return error.InvalidExecutionSlotRoster;
                snapshot.* = try range.collectCounter(a, input.trace, counter);
                for (input.trace.witness) |values| try witness.append(a, .{ .log_size = input.descriptor.log_size, .values = values });
            }
            var scheme = try Scheme.init(a, config);
            errdefer scheme.deinit(a);
            scheme.setCoefficientRetentionPolicy(.always);
            var channel = suite.Channel{};
            mixRoster(&channel, instance_index, native_key_id, expected);
            try scheme.commitBorrowedStreaming(a, fixed, 16, &channel);
            try scheme.commitBorrowedStreaming(a, main, 16, &channel);
            try scheme.commitBorrowedStreaming(a, witness.items, 16, &channel);
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            if (roots.items.len != 3) return error.InvalidExecutionSidecarFirstRound;
            return .{ .scheme = scheme, .roots = roots.items[0..3].*, .fixed_logs = fixed_logs, .main_logs = main_logs, .snapshots = snapshots };
        }

        pub fn prove(a: std.mem.Allocator, first: *FirstRound, inputs: []const Input, expected: []const Slot, sealed: seal_mod.SourceSeal, instance_index: u32, native_key_id: [32]u8, trusted_native_roots: [2]Digest, trusted_witness_root: Digest) !Proof {
            try validateInputs(inputs, expected);
            if (!sealed.bound_rosters or !first.owns_scheme or instance_index >= sealed.execution_instance_count or
                !std.meta.eql(first.roots[0..2].*, trusted_native_roots) or !std.meta.eql(first.roots[2], trusted_witness_root)) return error.UntrustedExecutionSidecarFirstRound;
            const challenges = try bus.Challenges.draw(a, sealed);
            const claims = try a.alloc(Claim, inputs.len);
            errdefer a.free(claims);
            var interaction: std.ArrayList(Column) = .empty;
            defer interaction.deinit(a);
            var witness_logs: std.ArrayList(u32) = .empty;
            defer witness_logs.deinit(a);
            var interaction_logs: std.ArrayList(u32) = .empty;
            defer interaction_logs.deinit(a);
            for (expected) |slot| {
                for (0..integer.COLUMN_COUNT) |_| try witness_logs.append(a, slot.log_size);
                for (0..adapter_mod.eval.INTERACTION_COUNT) |_| try interaction_logs.append(a, slot.log_size);
            }
            var quotient_cache = try @import("block_v5_quotient_column_cache_v1.zig").Cache.init(a);
            defer quotient_cache.deinit();
            const adapters = try a.alloc(adapter_mod.Component, inputs.len);
            defer a.free(adapters);
            const handles = try a.alloc(engine.air.component_prover.ComponentProver, inputs.len);
            defer a.free(handles);
            const main_open_mask = try a.alloc(bool, first.main_logs.len);
            defer a.free(main_open_mask);
            @memset(main_open_mask, false);
            for (expected) |slot| @memset(main_open_mask[slot.main_offset..][0..opcode.nColumnsForFamily(slot.family)], true);
            for (inputs, claims, adapters, handles, first.snapshots, 0..) |input, *claim, *adapter, *handle, snapshot, index| {
                const rows = try a.alloc(transition.Row, input.trace.domainSize());
                defer a.free(rows);
                for (rows, 0..) |*row, logical| row.* = try input.trace.row(logical);
                var transitions = try transition.generate(a, &challenges, rows, input.descriptor.log_size);
                defer transitions.deinit(a);
                var ranges = try range.generate(a, input.trace, challenges.universal_prefix.get(.range_check_8_8), snapshot);
                defer ranges.deinit(a);
                claim.* = .{ .transition_sum = transitions.claim, .range_claims = ranges.claims, .active_count = transitions.count };
                for (transitions.columns) |values| try interaction.append(a, .{ .log_size = input.descriptor.log_size, .values = try a.dupe(M, values) });
                for (ranges.columns) |values| try interaction.append(a, .{ .log_size = input.descriptor.log_size, .values = try a.dupe(M, values) });
                adapter.* = try (adapter_mod.Component{
                    .quotient_cache = &quotient_cache,
                    .family = input.descriptor.family,
                    .slot = input.descriptor.slot,
                    .log_size = input.descriptor.log_size,
                    .base_clock = input.trace.base_clock,
                    .fixed_logs = first.fixed_logs,
                    .main_logs = first.main_logs,
                    .witness_logs = witness_logs.items,
                    .interaction_logs = interaction_logs.items,
                    .root_owner = index == 0,
                    .main_open_mask = main_open_mask,
                    .main_offset = input.descriptor.main_offset,
                    .witness_offset = index * integer.COLUMN_COUNT,
                    .interaction_offset = index * adapter_mod.eval.INTERACTION_COUNT,
                    .transition_claim = claim.transition_sum,
                    .transition_count = claim.active_count,
                    .range_claims = claim.range_claims,
                    .challenges = &challenges,
                }).init();
                handle.* = adapter.asProverComponent();
            }
            defer for (interaction.items) |column| a.free(column.values);
            var channel = sealed.sharedChannel();
            mixRoster(&channel, instance_index, native_key_id, expected);
            try mixClaims(&channel, instance_index, expected, claims);
            try first.scheme.commitBorrowedStreaming(a, interaction.items, 8, &channel);
            first.owns_scheme = false;
            return .{ .stark = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, handles, &channel, first.scheme), .claims = claims };
        }

        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, sealed: seal_mod.SourceSeal, instance_index: u32, native_key_id: [32]u8, slots: []const Slot, fixed_logs: []const u32, main_logs: []const u32, trusted_native_roots: [2]Digest, trusted_witness_root: Digest, config: core.pcs.PcsConfig) !VerifiedExecutionReceipt {
            var proof = received;
            var owns_proof = true;
            defer if (owns_proof) proof.deinit(a);
            defer if (!owns_proof) a.free(proof.claims);
            if (!sealed.bound_rosters or slots.len == 0 or proof.claims.len != slots.len or instance_index >= sealed.execution_instance_count or
                !std.meta.eql(proof.stark.commitment_scheme_proof.config, config)) return error.InvalidExecutionSidecarProof;
            const roots = proof.stark.commitment_scheme_proof.commitments.items;
            if (roots.len != 5 or !std.meta.eql(roots[0..2].*, trusted_native_roots) or !std.meta.eql(roots[2], trusted_witness_root)) return error.UntrustedExecutionSidecarFirstRound;
            const challenges = try bus.Challenges.draw(a, sealed);
            var channel = suite.Channel{};
            mixRoster(&channel, instance_index, native_key_id, slots);
            var verifier = try Verifier.init(a, config);
            defer verifier.deinit(a);
            try verifier.commit(a, roots[0], fixed_logs, &channel);
            try verifier.commit(a, roots[1], main_logs, &channel);
            var witness_logs: std.ArrayList(u32) = .empty;
            defer witness_logs.deinit(a);
            var interaction_logs: std.ArrayList(u32) = .empty;
            defer interaction_logs.deinit(a);
            for (slots) |slot| {
                for (0..integer.COLUMN_COUNT) |_| try witness_logs.append(a, slot.log_size);
                for (0..adapter_mod.eval.INTERACTION_COUNT) |_| try interaction_logs.append(a, slot.log_size);
            }
            const adapters = try a.alloc(adapter_mod.Component, slots.len);
            defer a.free(adapters);
            const handles = try a.alloc(core.air.components.Component, slots.len);
            defer a.free(handles);
            const main_open_mask = try a.alloc(bool, main_logs.len);
            defer a.free(main_open_mask);
            @memset(main_open_mask, false);
            for (slots) |slot| @memset(main_open_mask[slot.main_offset..][0..opcode.nColumnsForFamily(slot.family)], true);
            const range_claims = try a.alloc(range.Claims, slots.len);
            errdefer a.free(range_claims);
            var transition_sum = Q.zero();
            var event_count: u64 = 0;
            for (slots, proof.claims, adapters, handles, range_claims, 0..) |slot, claim, *adapter, *handle, *range_claim, index| {
                if (slot.main_offset + opcode.nColumnsForFamily(slot.family) > main_logs.len) return error.InvalidExecutionSlotRoster;
                transition_sum = transition_sum.add(claim.transition_sum);
                event_count = try std.math.add(u64, event_count, claim.active_count);
                range_claim.* = claim.range_claims;
                adapter.* = try (adapter_mod.Component{
                    .family = slot.family,
                    .slot = slot.slot,
                    .log_size = slot.log_size,
                    .base_clock = try integer.baseClockFromPublicFrame(slot.frame),
                    .fixed_logs = fixed_logs,
                    .main_logs = main_logs,
                    .witness_logs = witness_logs.items,
                    .interaction_logs = interaction_logs.items,
                    .root_owner = index == 0,
                    .main_open_mask = main_open_mask,
                    .main_offset = slot.main_offset,
                    .witness_offset = index * integer.COLUMN_COUNT,
                    .interaction_offset = index * adapter_mod.eval.INTERACTION_COUNT,
                    .transition_claim = claim.transition_sum,
                    .transition_count = claim.active_count,
                    .range_claims = claim.range_claims,
                    .challenges = &challenges,
                }).init();
                handle.* = adapter.asVerifierComponent();
            }
            try verifier.commit(a, roots[2], witness_logs.items, &channel);
            channel = sealed.sharedChannel();
            mixRoster(&channel, instance_index, native_key_id, slots);
            try mixClaims(&channel, instance_index, slots, proof.claims);
            try verifier.commit(a, roots[3], interaction_logs.items, &channel);
            var seal_channel = sealed.sharedChannel();
            const receipt = VerifiedExecutionReceipt{
                .instance_index = instance_index,
                .transition_sum = transition_sum,
                .event_count = event_count,
                .range_claims = range_claims,
                .native_roots = trusted_native_roots,
                .witness_root = trusted_witness_root,
                .native_key_id = native_key_id,
                .sealed_channel_digest = seal_channel.digestBytes(),
            };
            owns_proof = false;
            try core.verifier.verify(suite.Hasher, suite.MerkleChannel, a, handles, &channel, &verifier, proof.stark);
            return receipt;
        }
    };
}

fn columnLogs(a: std.mem.Allocator, columns: []const Column) ![]u32 {
    const result = try a.alloc(u32, columns.len);
    for (columns, result) |column, *log_size| log_size.* = column.log_size;
    return result;
}
