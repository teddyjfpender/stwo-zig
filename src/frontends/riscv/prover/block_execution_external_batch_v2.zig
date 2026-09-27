//! Same-native-root STARK for SHA/Keccak caller memory effects. Every slot is
//! derived from the authenticated extension statement and sampled from the
//! native fixed/main commitments; host tracker events are never proof input.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const Column = engine.pcs.ColumnEvaluation;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const source = @import("block_execution_external_trace_v2.zig");
const integer = @import("block_execution_integer_bridge_v2.zig");
const transition = @import("block_execution_transition_interaction_v2.zig");
const range = @import("block_execution_byte_range_v2.zig");
const adapter_mod = @import("block_execution_sidecar_stark_v2.zig");
const bus = @import("block_memory_relation_v2.zig");
const seal_mod = @import("block_memory_source_seal_v2.zig");
const counter_mod = @import("../air/lookups/tables/counter.zig");
const keccak_trace = @import("../air/guest_precompile/keccakf_trace.zig");
const keccak_witness = @import("../air/guest_precompile/keccakf_witness.zig");

pub const TAG: u32 = 0x42324558; // B2EX
pub const Input = struct { descriptor: source.Descriptor, trace: *const source.Trace };
pub const Claim = struct { transition_sum: Q, range_claims: range.Claims, active_count: u64 };
pub const VerifiedReceipt = struct {
    instance_index: u32,
    transition_sum: Q,
    event_count: u64,
    range_claims: []range.Claims,
    native_roots: [2]suite.Hasher.Hash,
    witness_root: suite.Hasher.Hash,
    native_key_id: [32]u8,
    sealed_channel_digest: [32]u8,
    pub fn deinit(self: *VerifiedReceipt, a: std.mem.Allocator) void {
        a.free(self.range_claims);
        self.* = undefined;
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

pub fn validateInputs(inputs: []const Input, expected: []const source.Descriptor) !void {
    if (inputs.len != expected.len or expected.len == 0) return error.InvalidExternalAccessRoster;
    for (inputs, expected) |input, descriptor| {
        if (!std.meta.eql(input.descriptor, descriptor) or !std.meta.eql(input.trace.descriptor, descriptor))
            return error.InvalidExternalAccessRoster;
    }
}
pub fn mixRoster(channel: anytype, instance_index: u32, native_key_id: [32]u8, slots: []const source.Descriptor) void {
    channel.mixU32s(&.{ TAG, 1, instance_index, @intCast(slots.len) });
    channel.mixRoot(native_key_id);
    for (slots) |slot| {
        channel.mixU32s(&.{ @intFromEnum(slot.kind), @intCast(slot.slot), slot.log_size, @intCast(slot.fixed_offset), @intCast(slot.main_offset), @intFromEnum(slot.frame.clock_frame), slot.frame.cycle_count });
        channel.mixU64(slot.frame.global_first_cycle);
        if (slot.x0_local_custody_version != 0) channel.mixU32s(&.{ 0x58304350, slot.x0_local_custody_version });
    }
}
fn mixClaims(channel: anytype, instance_index: u32, slots: []const source.Descriptor, claims: []const Claim) !void {
    if (slots.len != claims.len) return error.InvalidExternalAccessClaims;
    for (slots, claims) |slot, claim| {
        if (!@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&claim.transition_sum)) return error.InvalidExternalAccessClaim;
        channel.mixU32s(&.{ TAG, 2, instance_index, @intFromEnum(slot.kind), @intCast(slot.slot) });
        channel.mixU64(claim.active_count);
        for (claim.transition_sum.toM31Array()) |limb| channel.mixU32s(&.{limb.toU32()});
        channel.mixU32s(&.{ TAG, 3, instance_index, @intFromEnum(slot.kind), @intCast(slot.slot) });
        for (claim.range_claims) |part| {
            if (!@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&part)) return error.InvalidExternalRangeClaim;
            for (part.toM31Array()) |limb| channel.mixU32s(&.{limb.toU32()});
        }
    }
}
fn columnLogs(a: std.mem.Allocator, columns: []const Column) ![]u32 {
    const result = try a.alloc(u32, columns.len);
    for (columns, result) |column, *log_size| log_size.* = column.log_size;
    return result;
}
pub const Masks = struct {
    fixed: []bool,
    main: []bool,
    state_offset: ?usize,
    pub fn deinit(self: *Masks, a: std.mem.Allocator) void {
        a.free(self.fixed);
        a.free(self.main);
    }
};
pub fn masks(a: std.mem.Allocator, slots: []const source.Descriptor, fixed_count: usize, main_count: usize) !Masks {
    const fixed = try a.alloc(bool, fixed_count);
    errdefer a.free(fixed);
    @memset(fixed, false);
    const main = try a.alloc(bool, main_count);
    errdefer a.free(main);
    @memset(main, false);
    var state_offset: ?usize = null;
    for (slots) |slot| {
        if (slot.main_offset + slot.mainWidth() > main_count or
            (slot.kind == .sha and slot.fixed_offset >= fixed_count))
            return error.InvalidExternalAccessRoster;
        if (slot.kind == .sha) {
            fixed[slot.fixed_offset] = true;
            @memset(main[slot.main_offset..][0..slot.mainWidth()], true);
        } else if (slot.kind == .signer) {
            @memset(main[slot.main_offset..][0..slot.mainWidth()], true);
        } else {
            @memset(main[slot.main_offset + keccak_trace.Layout.caller ..][0..@import("../air/guest_precompile/keccakf_caller.zig").Layout.main_columns], true);
            const current = slot.main_offset + keccak_trace.Layout.state;
            if (current + keccak_witness.state_cell_count > main_count or
                (state_offset != null and state_offset.? != current)) return error.InvalidExternalAccessRoster;
            state_offset = current;
        }
    }
    return .{ .fixed = fixed, .main = main, .state_offset = state_offset };
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
        pub fn commitFirstRound(a: std.mem.Allocator, fixed: []const Column, main: []const Column, inputs: []const Input, slots: []const source.Descriptor, counter: *counter_mod.Counter, instance_index: u32, native_key_id: [32]u8, config: core.pcs.PcsConfig) !FirstRound {
            try validateInputs(inputs, slots);
            const fixed_logs = try columnLogs(a, fixed);
            errdefer a.free(fixed_logs);
            const main_logs = try columnLogs(a, main);
            errdefer a.free(main_logs);
            var scheme = try Scheme.init(a, config);
            errdefer scheme.deinit(a);
            scheme.setCoefficientRetentionPolicy(.always);
            var channel = suite.Channel{};
            mixRoster(&channel, instance_index, native_key_id, slots);
            try scheme.commitBorrowedStreaming(a, fixed, 16, &channel);
            try scheme.commitBorrowedStreaming(a, main, 16, &channel);
            return finishFirstRound(a, &scheme, fixed, main, fixed_logs, main_logs, inputs, slots, counter, &channel);
        }
        /// Lease a caller's physical prefix; commit only integer witness data.
        /// Shared witness kernel keeps the old standalone commitment unchanged.
        pub fn borrowFirstRound(a: std.mem.Allocator, prefix: *Scheme, fixed: []const Column, main: []const Column, inputs: []const Input, slots: []const source.Descriptor, counter: *counter_mod.Counter, instance_index: u32, caller_key_id: [32]u8) !FirstRound {
            try validateInputs(inputs, slots);
            const fixed_logs = try columnLogs(a, fixed);
            errdefer a.free(fixed_logs);
            const main_logs = try columnLogs(a, main);
            errdefer a.free(main_logs);
            try @import("block_v5_committed_projection_columns_v1.zig").validateTrees(prefix, fixed_logs, main_logs);
            var channel = suite.Channel{};
            mixRoster(&channel, instance_index, caller_key_id, slots);
            var scheme = try @import("block_v5_shared_first_round_v1.zig").copy(Backend, a, prefix, &channel);
            errdefer scheme.deinit(a);
            return finishFirstRound(a, &scheme, fixed, main, fixed_logs, main_logs, inputs, slots, counter, &channel);
        }
        fn finishFirstRound(a: std.mem.Allocator, scheme: *Scheme, fixed: []const Column, main: []const Column, fixed_logs: []u32, main_logs: []u32, inputs: []const Input, slots: []const source.Descriptor, counter: *counter_mod.Counter, channel: *suite.Channel) !FirstRound {
            try validateInputs(inputs, slots);
            var witness: std.ArrayList(Column) = .empty;
            defer witness.deinit(a);
            const snapshots = try a.alloc(range.SNAPSHOT, inputs.len);
            errdefer a.free(snapshots);
            for (inputs, snapshots) |input, *snapshot| {
                try input.descriptor.validate(fixed, main);
                snapshot.* = try range.collectCounter(a, input.trace, counter);
                for (input.trace.witness) |values| try witness.append(a, .{ .log_size = input.descriptor.log_size, .values = values });
            }
            try scheme.commitBorrowedStreaming(a, witness.items, 16, channel);
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            if (roots.items.len != 3) return error.InvalidExternalFirstRound;
            return .{ .scheme = scheme.*, .roots = roots.items[0..3].*, .fixed_logs = fixed_logs, .main_logs = main_logs, .snapshots = snapshots };
        }
        pub fn prove(a: std.mem.Allocator, first: *FirstRound, inputs: []const Input, slots: []const source.Descriptor, sealed: seal_mod.SourceSeal, instance_index: u32, native_key_id: [32]u8, native_roots: [2]Digest, witness_root: Digest) !Proof {
            try validateInputs(inputs, slots);
            if (!sealed.bound_rosters or !sealed.extension_rosters_bound or !first.owns_scheme or instance_index >= sealed.execution_instance_count or
                !std.meta.eql(first.roots[0..2].*, native_roots) or !std.meta.eql(first.roots[2], witness_root)) return error.UntrustedExternalFirstRound;
            const challenges = try bus.Challenges.draw(a, sealed);
            const claims = try a.alloc(Claim, inputs.len);
            errdefer a.free(claims);
            var interaction: std.ArrayList(Column) = .empty;
            defer interaction.deinit(a);
            var witness_logs: std.ArrayList(u32) = .empty;
            defer witness_logs.deinit(a);
            var interaction_logs: std.ArrayList(u32) = .empty;
            defer interaction_logs.deinit(a);
            for (slots) |slot| {
                try witness_logs.appendNTimes(a, slot.log_size, integer.COLUMN_COUNT);
                try interaction_logs.appendNTimes(a, slot.log_size, adapter_mod.eval.INTERACTION_COUNT);
            }
            var mask = try masks(a, slots, first.fixed_logs.len, first.main_logs.len);
            defer mask.deinit(a);
            const adapters = try a.alloc(adapter_mod.Component, slots.len);
            defer a.free(adapters);
            const handles = try a.alloc(engine.air.component_prover.ComponentProver, slots.len);
            defer a.free(handles);
            for (inputs, claims, adapters, handles, first.snapshots, 0..) |input, *claim, *adapter, *handle, snapshot, index| {
                const rows = try a.alloc(transition.Row, input.trace.domainSize());
                defer a.free(rows);
                for (rows, 0..) |*row, logical| row.* = try input.trace.row(logical);
                var terms = try transition.generate(a, &challenges, rows, input.descriptor.log_size);
                defer terms.deinit(a);
                var bytes = try range.generate(a, input.trace, challenges.universal_prefix.get(.range_check_8_8), snapshot);
                defer bytes.deinit(a);
                claim.* = .{ .transition_sum = terms.claim, .range_claims = bytes.claims, .active_count = terms.count };
                for (terms.columns) |values| try interaction.append(a, .{ .log_size = input.descriptor.log_size, .values = try a.dupe(M, values) });
                for (bytes.columns) |values| try interaction.append(a, .{ .log_size = input.descriptor.log_size, .values = try a.dupe(M, values) });
                adapter.* = try (adapter_mod.Component{ .family = .base_alu_imm, .slot = input.descriptor.slot, .external_source = input.descriptor, .log_size = input.descriptor.log_size, .base_clock = input.trace.base_clock, .fixed_logs = first.fixed_logs, .main_logs = first.main_logs, .witness_logs = witness_logs.items, .interaction_logs = interaction_logs.items, .root_owner = index == 0, .fixed_open_mask = mask.fixed, .main_open_mask = mask.main, .shared_keccak_state_offset = mask.state_offset, .main_offset = input.descriptor.main_offset, .witness_offset = index * integer.COLUMN_COUNT, .interaction_offset = index * adapter_mod.eval.INTERACTION_COUNT, .transition_claim = claim.transition_sum, .transition_count = claim.active_count, .range_claims = claim.range_claims, .challenges = &challenges }).init();
                handle.* = adapter.asProverComponent();
            }
            defer for (interaction.items) |column| a.free(column.values);
            var channel = sealed.sharedChannel();
            mixRoster(&channel, instance_index, native_key_id, slots);
            try mixClaims(&channel, instance_index, slots, claims);
            try first.scheme.commitBorrowedStreaming(a, interaction.items, 8, &channel);
            first.owns_scheme = false;
            return .{ .stark = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, handles, &channel, first.scheme), .claims = claims };
        }
        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, sealed: seal_mod.SourceSeal, instance_index: u32, native_key_id: [32]u8, slots: []const source.Descriptor, fixed_logs: []const u32, main_logs: []const u32, native_roots: [2]Digest, witness_root: Digest, config: core.pcs.PcsConfig) !VerifiedReceipt {
            var proof = received;
            var owns_proof = true;
            defer if (owns_proof) proof.deinit(a);
            defer if (!owns_proof) a.free(proof.claims);
            if (!sealed.bound_rosters or !sealed.extension_rosters_bound or slots.len == 0 or proof.claims.len != slots.len or instance_index >= sealed.execution_instance_count or
                !std.meta.eql(proof.stark.commitment_scheme_proof.config, config)) return error.InvalidExternalAccessProof;
            const roots = proof.stark.commitment_scheme_proof.commitments.items;
            if (roots.len != 5 or !std.meta.eql(roots[0..2].*, native_roots) or !std.meta.eql(roots[2], witness_root)) return error.UntrustedExternalFirstRound;
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
                try witness_logs.appendNTimes(a, slot.log_size, integer.COLUMN_COUNT);
                try interaction_logs.appendNTimes(a, slot.log_size, adapter_mod.eval.INTERACTION_COUNT);
            }
            try verifier.commit(a, roots[2], witness_logs.items, &channel);
            var mask = try masks(a, slots, fixed_logs.len, main_logs.len);
            defer mask.deinit(a);
            const adapters = try a.alloc(adapter_mod.Component, slots.len);
            defer a.free(adapters);
            const handles = try a.alloc(core.air.components.Component, slots.len);
            defer a.free(handles);
            const range_claims = try a.alloc(range.Claims, slots.len);
            errdefer a.free(range_claims);
            var sum = Q.zero();
            var count: u64 = 0;
            for (slots, proof.claims, adapters, handles, range_claims, 0..) |slot, claim, *adapter, *handle, *range_claim, index| {
                sum = sum.add(claim.transition_sum);
                count = try std.math.add(u64, count, claim.active_count);
                range_claim.* = claim.range_claims;
                adapter.* = try (adapter_mod.Component{ .family = .base_alu_imm, .slot = slot.slot, .external_source = slot, .log_size = slot.log_size, .base_clock = try integer.baseClockFromPublicFrame(slot.frame), .fixed_logs = fixed_logs, .main_logs = main_logs, .witness_logs = witness_logs.items, .interaction_logs = interaction_logs.items, .root_owner = index == 0, .fixed_open_mask = mask.fixed, .main_open_mask = mask.main, .shared_keccak_state_offset = mask.state_offset, .main_offset = slot.main_offset, .witness_offset = index * integer.COLUMN_COUNT, .interaction_offset = index * adapter_mod.eval.INTERACTION_COUNT, .transition_claim = claim.transition_sum, .transition_count = claim.active_count, .range_claims = claim.range_claims, .challenges = &challenges }).init();
                handle.* = adapter.asVerifierComponent();
            }
            channel = sealed.sharedChannel();
            mixRoster(&channel, instance_index, native_key_id, slots);
            try mixClaims(&channel, instance_index, slots, proof.claims);
            try verifier.commit(a, roots[3], interaction_logs.items, &channel);
            var seal_channel = sealed.sharedChannel();
            const receipt = VerifiedReceipt{ .instance_index = instance_index, .transition_sum = sum, .event_count = count, .range_claims = range_claims, .native_roots = native_roots, .witness_root = witness_root, .native_key_id = native_key_id, .sealed_channel_digest = seal_channel.digestBytes() };
            owns_proof = false;
            try core.verifier.verify(suite.Hasher, suite.MerkleChannel, a, handles, &channel, &verifier, proof.stark);
            return receipt;
        }
    };
}
