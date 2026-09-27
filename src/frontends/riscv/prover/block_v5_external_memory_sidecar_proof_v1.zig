//! B5SS same-precompile-root SHA/Keccak/signer caller memory sidecar. Each slot
//! proves a block transition and the opposite native universal tuple pair.
//! The separate precompile arithmetic/caller AIR must supply the matching
//! request claim before this receipt can help close a complete block.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const Column = engine.pcs.ColumnEvaluation;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const old = @import("block_execution_external_batch_v2.zig");
const source = @import("block_execution_external_trace_v2.zig");
const integer = @import("block_execution_integer_bridge_v2.zig");
const transition = @import("block_execution_transition_interaction_v2.zig");
const range = @import("block_execution_byte_range_v2.zig");
const component = @import("block_execution_sidecar_stark_v2.zig");
const eval = @import("block_v5_opcode_sidecar_eval_v1.zig");
const memory = @import("block_v5_opcode_memory_interaction_v1.zig");
const bus = @import("block_memory_relation_v2.zig");
const seal_mod = @import("block_v5_source_seal_v1.zig");
const word_protocol = @import("block_v5_word_memory_protocol_v1.zig");
const word_transition = @import("block_v5_word_execution_transition_v1.zig");
const canonical = @import("../recursion/air/universal_provider_relations.zig");
const Digest = suite.Hasher.Hash;
const TAG: u32 = 0x42354558; // B5EX
pub const Slot = source.Descriptor;
pub const Input = old.Input;
/// Borrowed binding from a freshly verified family11 proof, supplied only
/// inside the receiver that verified that proof. It is not block authority.
pub const CallerBinding = @import("block_v5_precompile_protocol_v1.zig").CallerBinding;
pub const Claim = struct { transition_sum: Q, universal_sum: Q, range_claims: range.Claims, active_count: u64 };
pub const Proof = struct {
    stark: suite.Proof,
    claims: []Claim,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        a.free(self.claims);
        self.* = undefined;
    }
};
pub const Verified = struct {
    instance_index: u32,
    transition_sum: Q,
    packed_transition: bool = false,
    universal_sum: Q,
    event_count: u64,
    range_claims: []range.Claims,
    caller_roots: [2]Digest,
    witness_root: Digest,
    execution_instance_id: Digest,
    caller_instance_id: Digest,
    sealed_digest: Digest,
    pub fn deinit(self: *Verified, a: std.mem.Allocator) void {
        a.free(self.range_claims);
        self.* = undefined;
    }
};

pub fn instanceId(execution_instance_id: Digest, caller_instance_id: Digest, caller_key_id: Digest, caller_roots: [2]Digest, witness_root: Digest, index: u32, slots: []const Slot) Digest {
    var channel = suite.Channel{};
    channel.mixU32s(&.{ TAG, 1, index, @intCast(slots.len) });
    channel.mixRoot(execution_instance_id);
    channel.mixRoot(caller_instance_id);
    channel.mixRoot(caller_key_id);
    channel.mixRoot(caller_roots[0]);
    channel.mixRoot(caller_roots[1]);
    channel.mixRoot(witness_root);
    for (slots) |slot| {
        channel.mixU32s(&.{ @intFromEnum(slot.kind), @intCast(slot.slot), slot.log_size, @intCast(slot.fixed_offset), @intCast(slot.main_offset), @intFromEnum(slot.frame.clock_frame), slot.frame.cycle_count });
        channel.mixU64(slot.frame.global_first_cycle);
        if (slot.x0_local_custody_version != 0) channel.mixU32s(&.{ 0x58304350, slot.x0_local_custody_version });
    }
    return channel.digestBytes();
}
pub fn entry(execution_instance_id: Digest, caller_instance_id: Digest, caller_key_id: Digest, caller_roots: [2]Digest, witness_root: Digest, index: u32, slots: []const Slot) seal_mod.Entry {
    return .{ .family = .execution_external_sidecar, .index = index, .instance_id = instanceId(execution_instance_id, caller_instance_id, caller_key_id, caller_roots, witness_root, index, slots), .roots = .{ witness_root, @splat(0) } };
}

pub fn packedEntry(execution_instance_id: Digest, caller_instance_id: Digest, caller_key_id: Digest, caller_roots: [2]Digest, witness_root: Digest, index: u32, slots: []const Slot) seal_mod.Entry {
    return entryMode(true, execution_instance_id, caller_instance_id, caller_key_id, caller_roots, witness_root, index, slots);
}
fn entryMode(comptime word_mode: bool, execution_instance_id: Digest, caller_instance_id: Digest, caller_key_id: Digest, caller_roots: [2]Digest, witness_root: Digest, index: u32, slots: []const Slot) seal_mod.Entry {
    var result = entry(execution_instance_id, caller_instance_id, caller_key_id, caller_roots, witness_root, index, slots);
    if (word_mode) {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-zig/block-v5/packed-execution-sidecar/v1\x00");
        hash.update(&word_protocol.abiId());
        hash.update(&result.instance_id);
        result.instance_id = hash.finalResult();
    }
    return result;
}

fn admit(sealed: seal_mod.Sealed, pins: seal_mod.Pins, entries: []const seal_mod.Entry, expected: seal_mod.Entry, receipt: *const CallerBinding) !void {
    try @import("block_v5_precompile_protocol_v1.zig").admit(receipt.*, sealed, pins, entries);
    if (expected.index >= sealed.execution_instance_count or expected.index != receipt.execution_index or receipt.caller_entry_index != receipt.execution_index or
        !std.meta.eql(receipt.sealed_digest, sealed.digest)) return error.UntrustedV5ExternalMemoryNative;
    var has_native = false;
    for (entries) |present| if (present.family == .execution and present.index == expected.index) {
        if (!std.meta.eql(present.instance_id, receipt.execution_instance_id)) return error.UntrustedV5ExternalMemoryNative;
        has_native = true;
        break;
    };
    if (!has_native) return error.MissingV5ExternalMemoryNative;
    var has_caller = false;
    for (entries) |present| if (present.family == .precompile and present.index == receipt.caller_entry_index) {
        if (!std.meta.eql(present.roots, receipt.first_roots) or !std.meta.eql(present.instance_id, receipt.caller_instance_id)) return error.UntrustedV5ExternalMemoryCaller;
        has_caller = true;
        break;
    };
    if (!has_caller) return error.MissingV5ExternalMemoryCaller;
    for (entries) |present| if (present.family == .execution_external_sidecar and present.index == expected.index) {
        if (!std.meta.eql(present, expected)) return error.UntrustedV5ExternalMemoryRoster;
        return;
    };
    return error.MissingV5ExternalMemorySidecar;
}
fn mixClaims(channel: anytype, index: u32, slots: []const Slot, claims: []const Claim) !void {
    if (claims.len != slots.len) return error.InvalidV5ExternalMemoryClaims;
    for (slots, claims) |slot, claim| {
        if (!canonical.secureIsCanonical(&claim.transition_sum) or !canonical.secureIsCanonical(&claim.universal_sum)) return error.InvalidV5ExternalMemoryClaim;
        channel.mixU32s(&.{ TAG, 2, index, @intFromEnum(slot.kind), @intCast(slot.slot) });
        channel.mixU64(claim.active_count);
        for ([_]Q{ claim.transition_sum, claim.universal_sum }) |sum| for (sum.toM31Array()) |limb| channel.mixU32s(&.{limb.toU32()});
        for (claim.range_claims) |part| {
            if (!canonical.secureIsCanonical(&part)) return error.InvalidV5ExternalRangeClaim;
            for (part.toM31Array()) |limb| channel.mixU32s(&.{limb.toU32()});
        }
    }
}
fn witnessLogs(a: std.mem.Allocator, slots: []const Slot) ![]u32 {
    const logs = try a.alloc(u32, slots.len * integer.COLUMN_COUNT);
    for (slots, 0..) |slot, i| @memset(logs[i * integer.COLUMN_COUNT ..][0..integer.COLUMN_COUNT], slot.log_size);
    return logs;
}
fn interactionLogs(a: std.mem.Allocator, slots: []const Slot) ![]u32 {
    const logs = try a.alloc(u32, slots.len * eval.INTERACTION_COUNT);
    for (slots, 0..) |slot, i| @memset(logs[i * eval.INTERACTION_COUNT ..][0..eval.INTERACTION_COUNT], slot.log_size);
    return logs;
}

pub fn ForBackend(comptime Backend: type) type {
    return ForBackendMode(Backend, false);
}
pub fn ForPackedBackend(comptime Backend: type) type {
    return ForBackendMode(Backend, true);
}
fn ForBackendMode(comptime Backend: type, comptime word_mode: bool) type {
    return struct {
        const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel);
        const Old = old.ForBackend(Backend);
        pub const FirstRound = Old.FirstRound;
        pub const commitFirstRound = Old.commitFirstRound;
        pub const borrowFirstRound = Old.borrowFirstRound;

        pub fn prove(a: std.mem.Allocator, first: *FirstRound, inputs: []const Input, slots: []const Slot, sealed: seal_mod.Sealed, pins: seal_mod.Pins, entries: []const seal_mod.Entry, caller: *const CallerBinding, index: u32, witness_root: Digest) !Proof {
            if (!word_mode and sealed.register_custody_mode != 0) return error.MixedV5PackedMemoryProtocol;
            try source.requireRwDescriptors(slots, sealed.register_custody_mode);
            try old.validateInputs(inputs, slots);
            if (!first.owns_scheme or !std.meta.eql(first.roots[0..2].*, caller.first_roots) or !std.meta.eql(first.roots[2], witness_root)) return error.UntrustedV5ExternalMemoryFirstRound;
            try admit(sealed, pins, entries, entryMode(word_mode, caller.execution_instance_id, caller.caller_instance_id, caller.caller_key_id, caller.first_roots, witness_root, index, slots), caller);
            const challenges = try bus.Challenges.draw(a, sealed);
            const packed_elements: ?word_protocol.Challenges = if (word_mode) try word_protocol.Challenges.draw(a, sealed) else null;
            const elements = challenges.universal_prefix.get(.memory_access);
            const claims = try a.alloc(Claim, slots.len);
            errdefer a.free(claims);
            var interaction: std.ArrayList(Column) = .empty;
            defer {
                for (interaction.items) |column| a.free(column.values);
                interaction.deinit(a);
            }
            const witness_logs = try witnessLogs(a, slots);
            defer a.free(witness_logs);
            const logs = try interactionLogs(a, slots);
            defer a.free(logs);
            var mask = try old.masks(a, slots, first.fixed_logs.len, first.main_logs.len);
            defer mask.deinit(a);
            const adapters = try a.alloc(component.Component, slots.len);
            defer a.free(adapters);
            var quotient_cache = try @import("block_v5_quotient_column_cache_v1.zig").Cache.init(a);
            defer quotient_cache.deinit();
            const handles = try a.alloc(engine.air.component_prover.ComponentProver, slots.len);
            defer a.free(handles);
            for (inputs, claims, adapters, handles, first.snapshots, 0..) |input, *claim, *adapter, *handle, snapshot, i| {
                const t_rows = try a.alloc(transition.Row, input.trace.domainSize());
                defer a.free(t_rows);
                const m_rows = try a.alloc(memory.Row, input.trace.domainSize());
                defer a.free(m_rows);
                for (t_rows, m_rows, 0..) |*t, *m, row| {
                    t.* = try input.trace.row(row);
                    m.* = try memory.rowFromPair(try input.trace.pairAt(row));
                }
                var t = if (word_mode) try word_transition.generate(a, &packed_elements.?, t_rows, input.descriptor.log_size) else try transition.generate(a, &challenges, t_rows, input.descriptor.log_size);
                defer t.deinit(a);
                var bytes = try range.generate(a, input.trace, challenges.universal_prefix.get(.range_check_8_8), snapshot);
                defer bytes.deinit(a);
                var m = try memory.generate(a, elements, m_rows, input.descriptor.log_size);
                defer m.deinit(a);
                claim.* = .{ .transition_sum = t.claim, .universal_sum = m.claim, .range_claims = bytes.claims, .active_count = t.count };
                for (t.columns) |values| try interaction.append(a, .{ .log_size = input.descriptor.log_size, .values = try a.dupe(M, values) });
                for (bytes.columns) |values| try interaction.append(a, .{ .log_size = input.descriptor.log_size, .values = try a.dupe(M, values) });
                for (m.columns) |values| try interaction.append(a, .{ .log_size = input.descriptor.log_size, .values = try a.dupe(M, values) });
                adapter.* = try (component.Component{ .quotient_cache = &quotient_cache, .family = .base_alu_imm, .slot = input.descriptor.slot, .external_source = input.descriptor, .log_size = input.descriptor.log_size, .base_clock = input.trace.base_clock, .fixed_logs = first.fixed_logs, .main_logs = first.main_logs, .witness_logs = witness_logs, .interaction_logs = logs, .root_owner = i == 0, .fixed_open_mask = mask.fixed, .main_open_mask = mask.main, .shared_keccak_state_offset = mask.state_offset, .main_offset = input.descriptor.main_offset, .witness_offset = i * integer.COLUMN_COUNT, .interaction_offset = i * eval.INTERACTION_COUNT, .transition_claim = claim.transition_sum, .transition_count = claim.active_count, .range_claims = claim.range_claims, .challenges = &challenges, .v5_packed = if (word_mode) .{ .elements = &packed_elements.? } else null, .v5_universal = .{ .claim = claim.universal_sum, .elements = elements } }).init();
                handle.* = adapter.asProverComponent();
            }
            var channel = sealed.sharedChannel();
            if (word_mode) _ = try word_protocol.Challenges.drawFromChannel(a, &channel);
            old.mixRoster(&channel, index, caller.caller_key_id, slots);
            try mixClaims(&channel, index, slots, claims);
            try first.scheme.commitBorrowedStreaming(a, interaction.items, 8, &channel);
            first.owns_scheme = false;
            return .{ .stark = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, handles, &channel, first.scheme), .claims = claims };
        }

        /// The complete receiver must additionally require a fresh caller
        /// arithmetic receipt and close its universal request sum here.
        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, sealed: seal_mod.Sealed, pins: seal_mod.Pins, entries: []const seal_mod.Entry, caller: *const CallerBinding, index: u32, slots: []const Slot, fixed_logs: []const u32, main_logs: []const u32, witness_root: Digest, config: core.pcs.PcsConfig) !Verified {
            var proof = received;
            var owns = true;
            defer if (owns) proof.deinit(a);
            defer if (!owns) a.free(proof.claims);
            if (!word_mode and sealed.register_custody_mode != 0) return error.MixedV5PackedMemoryProtocol;
            try source.requireRwDescriptors(slots, sealed.register_custody_mode);
            if (slots.len == 0 or proof.claims.len != slots.len or !std.meta.eql(config, pins.config) or
                !std.meta.eql(proof.stark.commitment_scheme_proof.config, config)) return error.InvalidV5ExternalMemoryProof;
            try admit(sealed, pins, entries, entryMode(word_mode, caller.execution_instance_id, caller.caller_instance_id, caller.caller_key_id, caller.first_roots, witness_root, index, slots), caller);
            const roots = proof.stark.commitment_scheme_proof.commitments.items;
            if (roots.len != 5 or !std.meta.eql(roots[0..2].*, caller.first_roots) or !std.meta.eql(roots[2], witness_root)) return error.UntrustedV5ExternalMemoryFirstRound;
            var channel = suite.Channel{};
            old.mixRoster(&channel, index, caller.caller_key_id, slots);
            var verifier = try Verifier.init(a, config);
            defer verifier.deinit(a);
            try verifier.commit(a, roots[0], fixed_logs, &channel);
            try verifier.commit(a, roots[1], main_logs, &channel);
            const witness_logs = try witnessLogs(a, slots);
            defer a.free(witness_logs);
            try verifier.commit(a, roots[2], witness_logs, &channel);
            const logs = try interactionLogs(a, slots);
            defer a.free(logs);
            channel = sealed.sharedChannel();
            if (word_mode) _ = try word_protocol.Challenges.drawFromChannel(a, &channel);
            old.mixRoster(&channel, index, caller.caller_key_id, slots);
            try mixClaims(&channel, index, slots, proof.claims);
            try verifier.commit(a, roots[3], logs, &channel);
            const challenges = try bus.Challenges.draw(a, sealed);
            const packed_elements: ?word_protocol.Challenges = if (word_mode) try word_protocol.Challenges.draw(a, sealed) else null;
            const elements = challenges.universal_prefix.get(.memory_access);
            var mask = try old.masks(a, slots, fixed_logs.len, main_logs.len);
            defer mask.deinit(a);
            const adapters = try a.alloc(component.Component, slots.len);
            defer a.free(adapters);
            const handles = try a.alloc(core.air.components.Component, slots.len);
            defer a.free(handles);
            const ranges = try a.alloc(range.Claims, slots.len);
            errdefer a.free(ranges);
            var transition_sum = Q.zero();
            var universal_sum = Q.zero();
            var count: u64 = 0;
            for (slots, proof.claims, adapters, handles, ranges, 0..) |slot, claim, *adapter, *handle, *range_claim, i| {
                if (slot.main_offset + slot.mainWidth() > main_logs.len or claim.active_count > @as(u64, 1) << @intCast(slot.log_size)) return error.InvalidV5ExternalMemorySlot;
                transition_sum = transition_sum.add(claim.transition_sum);
                universal_sum = universal_sum.add(claim.universal_sum);
                count = try std.math.add(u64, count, claim.active_count);
                range_claim.* = claim.range_claims;
                adapter.* = try (component.Component{ .family = .base_alu_imm, .slot = slot.slot, .external_source = slot, .log_size = slot.log_size, .base_clock = try integer.baseClockFromPublicFrame(slot.frame), .fixed_logs = fixed_logs, .main_logs = main_logs, .witness_logs = witness_logs, .interaction_logs = logs, .root_owner = i == 0, .fixed_open_mask = mask.fixed, .main_open_mask = mask.main, .shared_keccak_state_offset = mask.state_offset, .main_offset = slot.main_offset, .witness_offset = i * integer.COLUMN_COUNT, .interaction_offset = i * eval.INTERACTION_COUNT, .transition_claim = claim.transition_sum, .transition_count = claim.active_count, .range_claims = claim.range_claims, .challenges = &challenges, .v5_packed = if (word_mode) .{ .elements = &packed_elements.? } else null, .v5_universal = .{ .claim = claim.universal_sum, .elements = elements } }).init();
                handle.* = adapter.asVerifierComponent();
            }
            const receipt = Verified{ .packed_transition = word_mode, .instance_index = index, .transition_sum = transition_sum, .universal_sum = universal_sum, .event_count = count, .range_claims = ranges, .caller_roots = caller.first_roots, .witness_root = witness_root, .execution_instance_id = caller.execution_instance_id, .caller_instance_id = caller.caller_instance_id, .sealed_digest = sealed.digest };
            owns = false;
            try core.verifier.verify(suite.Hasher, suite.MerkleChannel, a, handles, &channel, &verifier, proof.stark);
            return receipt;
        }
    };
}
