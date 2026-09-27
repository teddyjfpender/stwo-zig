//! Opt-in B5SS same-native-root opcode sidecar. Its one quotient proves the
//! block transition, byte requests, and opposite universal memory tuple sum
//! from the exact same PCS-opened ordinary opcode main columns.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const Column = engine.pcs.ColumnEvaluation;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const opcode = @import("../runner/trace.zig");
const old = @import("block_execution_sidecar_batch_v2.zig");
const integer = @import("block_execution_integer_bridge_v2.zig");
const transition = @import("block_execution_transition_interaction_v2.zig");
const range = @import("block_execution_byte_range_v2.zig");
const component = @import("block_execution_sidecar_stark_v2.zig");
const eval = @import("block_v5_opcode_sidecar_eval_v1.zig");
const memory = @import("block_v5_opcode_memory_interaction_v1.zig");
const bus = @import("block_memory_relation_v2.zig");
const seal_mod = @import("block_v5_source_seal_v1.zig");
const native = @import("block_v5_native_execution_proof_v1.zig");
const catalog_mod = @import("block_v5_native_template_catalog_v1.zig");
const universal = @import("../air/lang/relation.zig");
const word_protocol = @import("block_v5_word_memory_protocol_v1.zig");
const word_transition = @import("block_v5_word_execution_transition_v1.zig");
const canonical = @import("../recursion/air/universal_provider_relations.zig");
const Digest = suite.Hasher.Hash;
const TAG: u32 = 0x4235454d; // B5EM
pub const Slot = old.Slot;
pub const Input = old.Input;
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
    native_roots: [2]Digest,
    witness_root: Digest,
    native_instance_id: Digest,
    sealed_digest: Digest,
    pub fn deinit(self: *Verified, a: std.mem.Allocator) void {
        a.free(self.range_claims);
        self.* = undefined;
    }
};

pub fn instanceId(native_instance_id: Digest, native_roots: [2]Digest, witness_root: Digest, index: u32, slots: []const Slot) Digest {
    var channel = suite.Channel{};
    channel.mixU32s(&.{ TAG, 1, index, @intCast(slots.len) });
    channel.mixRoot(native_instance_id);
    channel.mixRoot(native_roots[0]);
    channel.mixRoot(native_roots[1]);
    channel.mixRoot(witness_root);
    for (slots) |slot| {
        channel.mixU32s(&.{ @intFromEnum(slot.family), @intCast(slot.slot), slot.log_size, @intCast(slot.main_offset), @intFromEnum(slot.frame.clock_frame), slot.frame.cycle_count });
        channel.mixU64(slot.frame.global_first_cycle);
    }
    return channel.digestBytes();
}
pub fn entry(native_instance_id: Digest, native_roots: [2]Digest, witness_root: Digest, index: u32, slots: []const Slot) seal_mod.Entry {
    return .{ .family = .execution_sidecar, .index = index, .instance_id = instanceId(native_instance_id, native_roots, witness_root, index, slots), .roots = .{ witness_root, @splat(0) } };
}

pub fn packedEntry(native_instance_id: Digest, native_roots: [2]Digest, witness_root: Digest, index: u32, slots: []const Slot) seal_mod.Entry {
    return entryMode(true, native_instance_id, native_roots, witness_root, index, slots);
}
fn entryMode(comptime word_mode: bool, native_instance_id: Digest, native_roots: [2]Digest, witness_root: Digest, index: u32, slots: []const Slot) seal_mod.Entry {
    var result = entry(native_instance_id, native_roots, witness_root, index, slots);
    if (word_mode) {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-zig/block-v5/packed-execution-sidecar/v1\x00");
        hash.update(&word_protocol.abiId());
        hash.update(&result.instance_id);
        result.instance_id = hash.finalResult();
    }
    return result;
}

fn admit(sealed: seal_mod.Sealed, pins: seal_mod.Pins, entries: []const seal_mod.Entry, catalog: ?catalog_mod.Admission, expected: seal_mod.Entry, native_receipt: anytype) !void {
    try sealed.require(pins, entries);
    if (expected.index >= sealed.execution_instance_count or !std.meta.eql(native_receipt.sealed_digest, sealed.digest)) return error.UntrustedV5OpcodeMemoryNative;
    if (catalog) |roster| {
        if (std.meta.eql(pins.native_template_catalog_digest, @as(Digest, @splat(0))) or
            !std.meta.eql(try roster.digest(), pins.native_template_catalog_digest) or
            roster.records.len != @as(usize, sealed.execution_instance_count)) return error.UntrustedV5OpcodeMemoryCatalog;
        const record = roster.records[@as(usize, expected.index)];
        if (!std.meta.eql(record.template_id, native_receipt.template_id) or
            !std.meta.eql(record.fixed_root, native_receipt.first_roots[0])) return error.UntrustedV5OpcodeMemoryCatalog;
    } else if (!std.meta.eql(native_receipt.template_id, pins.native_template_id)) return error.UntrustedV5OpcodeMemoryNative;
    var has_native = false;
    for (entries) |present| if (present.family == .execution and present.index == expected.index) {
        if (!std.meta.eql(present.roots, native_receipt.first_roots) or !std.meta.eql(present.instance_id, native_receipt.instance_id)) return error.UntrustedV5OpcodeMemoryNative;
        has_native = true;
        break;
    };
    if (!has_native) return error.MissingV5OpcodeMemoryNative;
    for (entries) |present| if (present.family == .execution_sidecar and present.index == expected.index) {
        if (!std.meta.eql(present, expected)) return error.UntrustedV5OpcodeMemoryRoster;
        return;
    };
    return error.MissingV5OpcodeMemorySidecar;
}
fn validateInputs(inputs: []const Input, slots: []const Slot) !void {
    if (slots.len == 0 or inputs.len != slots.len) return error.InvalidV5OpcodeMemorySlots;
    for (inputs, slots) |input, slot| if (!std.meta.eql(input.descriptor, slot) or input.trace.family != slot.family or input.trace.slot != slot.slot or input.trace.log_size != slot.log_size) return error.InvalidV5OpcodeMemorySlots;
}
fn mixClaims(channel: anytype, index: u32, slots: []const Slot, claims: []const Claim) !void {
    if (claims.len != slots.len) return error.InvalidV5OpcodeMemoryClaims;
    for (slots, claims) |slot, claim| {
        if (!canonical.secureIsCanonical(&claim.transition_sum) or !canonical.secureIsCanonical(&claim.universal_sum)) return error.InvalidV5OpcodeMemoryClaim;
        channel.mixU32s(&.{ TAG, 2, index, @intFromEnum(slot.family), @intCast(slot.slot) });
        channel.mixU64(claim.active_count);
        for ([_]Q{ claim.transition_sum, claim.universal_sum }) |sum| for (sum.toM31Array()) |limb| channel.mixU32s(&.{limb.toU32()});
        try range.mixClaims(claim.range_claims, index, slot.family, slot.slot, channel);
    }
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

        pub fn prove(a: std.mem.Allocator, first: *FirstRound, inputs: []const Input, slots: []const Slot, sealed: seal_mod.Sealed, pins: seal_mod.Pins, entries: []const seal_mod.Entry, catalog: ?catalog_mod.Admission, native_receipt: *const (if (word_mode) @import("block_v5_native_execution_proof_v3.zig").OpenReceipt else native.OpenReceipt), index: u32, witness_root: Digest) !Proof {
            return proveBound(a, first, inputs, slots, sealed, pins, entries, catalog, native_receipt, index, witness_root);
        }
        /// Producer-only binding from a genuine still-owned native first
        /// round. No OpenReceipt is constructed and no authority is issued.
        pub fn proveForNativeFirstRound(a: std.mem.Allocator, first: *FirstRound, inputs: []const Input, slots: []const Slot, sealed: seal_mod.Sealed, pins: seal_mod.Pins, entries: []const seal_mod.Entry, catalog: catalog_mod.Admission, native_first: *const @import("block_v5_native_execution_proof_v3.zig").ForBackend(Backend).FirstRound, index: u32, witness_root: Digest) !Proof {
            if (!word_mode or !native_first.owns_scheme or native_first.index != index or
                !native_first.native.native_only_v5 or native_first.native.failed or
                !native_first.native.tables_ready or native_first.native.interaction_ready or
                native_first.scheme.trees.items.len != 2 or
                !std.meta.eql(native_first.scheme.config, pins.config)) return error.UntrustedV5WarmOpcodeMemory;
            try native_first.pin.require(pins, &native_first.native.statement.public_data);
            try native_first.template.admit(&native_first.native.statement, native_first.template_id);
            try catalog.admit(pins, sealed, index, native_first.template, native_first.template_id);
            const template_v3 = @import("block_v5_native_template_protocol_v3.zig");
            if (!std.meta.eql(native_first.instance_id, try template_v3.instanceId(native_first.template_id, &native_first.native.statement, native_first.pin, native_first.roots, index))) return error.UntrustedV5WarmOpcodeMemory;
            try @import("block_v5_native_execution_proof_v3.zig").admitEntry(index, native_first.roots, native_first.instance_id, sealed, entries);
            const binding = .{ .template_id = native_first.template_id, .instance_id = native_first.instance_id, .first_roots = native_first.roots, .sealed_digest = sealed.digest };
            return proveBound(a, first, inputs, slots, sealed, pins, entries, catalog, &binding, index, witness_root);
        }
        fn proveBound(a: std.mem.Allocator, first: *FirstRound, inputs: []const Input, slots: []const Slot, sealed: seal_mod.Sealed, pins: seal_mod.Pins, entries: []const seal_mod.Entry, catalog: ?catalog_mod.Admission, native_receipt: anytype, index: u32, witness_root: Digest) !Proof {
            if (!word_mode and sealed.register_custody_mode != 0) return error.MixedV5PackedMemoryProtocol;
            try old.requireRwSlots(slots, sealed.register_custody_mode);
            try validateInputs(inputs, slots);
            for (inputs) |input| if (input.trace.register_custody_mode != sealed.register_custody_mode) return error.MixedV5OpcodeMemoryScope;
            if (!first.owns_scheme or !std.meta.eql(first.roots[0..2].*, native_receipt.first_roots) or !std.meta.eql(first.roots[2], witness_root)) return error.UntrustedV5OpcodeMemoryFirstRound;
            try admit(sealed, pins, entries, catalog, entryMode(word_mode, native_receipt.instance_id, native_receipt.first_roots, witness_root, index, slots), native_receipt);
            const challenges = try bus.Challenges.draw(a, sealed);
            const packed_elements: ?word_protocol.Challenges = if (word_mode) try word_protocol.Challenges.draw(a, sealed) else null;
            const elements = challenges.universal_prefix.get(universal.Domain.memory_access);
            const claims = try a.alloc(Claim, slots.len);
            errdefer a.free(claims);
            var interaction: std.ArrayList(Column) = .empty;
            defer {
                for (interaction.items) |column| a.free(column.values);
                interaction.deinit(a);
            }
            var logs: std.ArrayList(u32) = .empty;
            defer logs.deinit(a);
            for (slots) |slot| try logs.appendNTimes(a, slot.log_size, eval.INTERACTION_COUNT);
            const witness_logs = try witnessLogs(a, slots);
            defer a.free(witness_logs);
            var quotient_cache = try @import("block_v5_quotient_column_cache_v1.zig").Cache.init(a);
            defer quotient_cache.deinit();
            const adapters = try a.alloc(component.Component, slots.len);
            defer a.free(adapters);
            const handles = try a.alloc(engine.air.component_prover.ComponentProver, slots.len);
            defer a.free(handles);
            const mask = try mainMask(a, slots, first.main_logs.len);
            defer a.free(mask);
            for (inputs, claims, adapters, handles, first.snapshots, 0..) |input, *claim, *adapter, *handle, snapshot, i| {
                const transition_rows = try a.alloc(transition.Row, input.trace.domainSize());
                defer a.free(transition_rows);
                const memory_rows = try a.alloc(memory.Row, input.trace.domainSize());
                defer a.free(memory_rows);
                for (transition_rows, memory_rows, 0..) |*t, *m, row| {
                    t.* = try input.trace.row(row);
                    m.* = try memory.rowFromPair(try input.trace.pairAt(row));
                }
                var transitions = if (word_mode) try word_transition.generate(a, &packed_elements.?, transition_rows, input.descriptor.log_size) else try transition.generate(a, &challenges, transition_rows, input.descriptor.log_size);
                defer transitions.deinit(a);
                var bytes = try range.generate(a, input.trace, challenges.universal_prefix.get(.range_check_8_8), snapshot);
                defer bytes.deinit(a);
                var native_memory = try memory.generate(a, elements, memory_rows, input.descriptor.log_size);
                defer native_memory.deinit(a);
                claim.* = .{ .transition_sum = transitions.claim, .universal_sum = native_memory.claim, .range_claims = bytes.claims, .active_count = transitions.count };
                for (transitions.columns) |values| try interaction.append(a, .{ .log_size = input.descriptor.log_size, .values = try a.dupe(M, values) });
                for (bytes.columns) |values| try interaction.append(a, .{ .log_size = input.descriptor.log_size, .values = try a.dupe(M, values) });
                for (native_memory.columns) |values| try interaction.append(a, .{ .log_size = input.descriptor.log_size, .values = try a.dupe(M, values) });
                adapter.* = try (component.Component{ .register_custody_mode = sealed.register_custody_mode, .quotient_cache = &quotient_cache, .family = input.descriptor.family, .slot = input.descriptor.slot, .log_size = input.descriptor.log_size, .base_clock = input.trace.base_clock, .fixed_logs = first.fixed_logs, .main_logs = first.main_logs, .witness_logs = witness_logs, .interaction_logs = logs.items, .root_owner = i == 0, .main_open_mask = mask, .main_offset = input.descriptor.main_offset, .witness_offset = i * integer.COLUMN_COUNT, .interaction_offset = i * eval.INTERACTION_COUNT, .transition_claim = claim.transition_sum, .transition_count = claim.active_count, .range_claims = claim.range_claims, .challenges = &challenges, .v5_packed = if (word_mode) .{ .elements = &packed_elements.? } else null, .v5_universal = .{ .claim = claim.universal_sum, .elements = elements } }).init();
                handle.* = adapter.asProverComponent();
            }
            var channel = sealed.sharedChannel();
            if (word_mode) _ = try word_protocol.Challenges.drawFromChannel(a, &channel);
            old.mixRoster(&channel, index, native_receipt.template_id, slots);
            try mixClaims(&channel, index, slots, claims);
            try first.scheme.commitBorrowedStreaming(a, interaction.items, 8, &channel);
            first.owns_scheme = false;
            return .{ .stark = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, handles, &channel, first.scheme), .claims = claims };
        }

        /// Scoped receipt only. The containing complete verifier must call
        /// this immediately after a fresh native proof, then close every
        /// universal and block relation before issuing block authority.
        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, sealed: seal_mod.Sealed, pins: seal_mod.Pins, entries: []const seal_mod.Entry, catalog: ?catalog_mod.Admission, native_receipt: *const (if (word_mode) @import("block_v5_native_execution_proof_v3.zig").OpenReceipt else native.OpenReceipt), index: u32, slots: []const Slot, fixed_logs: []const u32, main_logs: []const u32, witness_root: Digest, config: core.pcs.PcsConfig) !Verified {
            var proof = received;
            var owns_proof = true;
            defer if (owns_proof) proof.deinit(a);
            defer if (!owns_proof) a.free(proof.claims);
            if (!word_mode and sealed.register_custody_mode != 0) return error.MixedV5PackedMemoryProtocol;
            try old.requireRwSlots(slots, sealed.register_custody_mode);
            if (slots.len == 0 or proof.claims.len != slots.len or !std.meta.eql(config, pins.config) or
                !std.meta.eql(proof.stark.commitment_scheme_proof.config, config)) return error.InvalidV5OpcodeMemoryProof;
            try admit(sealed, pins, entries, catalog, entryMode(word_mode, native_receipt.instance_id, native_receipt.first_roots, witness_root, index, slots), native_receipt);
            const roots = proof.stark.commitment_scheme_proof.commitments.items;
            if (roots.len != 5 or !std.meta.eql(roots[0..2].*, native_receipt.first_roots) or !std.meta.eql(roots[2], witness_root)) return error.UntrustedV5OpcodeMemoryFirstRound;
            var channel = suite.Channel{};
            old.mixRoster(&channel, index, native_receipt.template_id, slots);
            var verifier = try Verifier.init(a, config);
            defer verifier.deinit(a);
            try verifier.commit(a, roots[0], fixed_logs, &channel);
            try verifier.commit(a, roots[1], main_logs, &channel);
            const witness_logs = try witnessLogs(a, slots);
            defer a.free(witness_logs);
            try verifier.commit(a, roots[2], witness_logs, &channel);
            const interaction_logs = try a.alloc(u32, slots.len * eval.INTERACTION_COUNT);
            defer a.free(interaction_logs);
            for (slots, 0..) |slot, i| @memset(interaction_logs[i * eval.INTERACTION_COUNT ..][0..eval.INTERACTION_COUNT], slot.log_size);
            channel = sealed.sharedChannel();
            if (word_mode) _ = try word_protocol.Challenges.drawFromChannel(a, &channel);
            old.mixRoster(&channel, index, native_receipt.template_id, slots);
            try mixClaims(&channel, index, slots, proof.claims);
            try verifier.commit(a, roots[3], interaction_logs, &channel);
            const challenges = try bus.Challenges.draw(a, sealed);
            const packed_elements: ?word_protocol.Challenges = if (word_mode) try word_protocol.Challenges.draw(a, sealed) else null;
            const elements = challenges.universal_prefix.get(universal.Domain.memory_access);
            const mask = try mainMask(a, slots, main_logs.len);
            defer a.free(mask);
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
                const width = opcode.nColumnsForFamily(slot.family);
                if (slot.main_offset + width > main_logs.len or claim.active_count > @as(u64, 1) << @intCast(slot.log_size)) return error.InvalidV5OpcodeMemorySlot;
                for (main_logs[slot.main_offset..][0..width]) |log| if (log != slot.log_size) return error.InvalidV5OpcodeMemorySlot;
                transition_sum = transition_sum.add(claim.transition_sum);
                universal_sum = universal_sum.add(claim.universal_sum);
                count = try std.math.add(u64, count, claim.active_count);
                range_claim.* = claim.range_claims;
                adapter.* = try (component.Component{ .register_custody_mode = sealed.register_custody_mode, .family = slot.family, .slot = slot.slot, .log_size = slot.log_size, .base_clock = try integer.baseClockFromPublicFrame(slot.frame), .fixed_logs = fixed_logs, .main_logs = main_logs, .witness_logs = witness_logs, .interaction_logs = interaction_logs, .root_owner = i == 0, .main_open_mask = mask, .main_offset = slot.main_offset, .witness_offset = i * integer.COLUMN_COUNT, .interaction_offset = i * eval.INTERACTION_COUNT, .transition_claim = claim.transition_sum, .transition_count = claim.active_count, .range_claims = claim.range_claims, .challenges = &challenges, .v5_packed = if (word_mode) .{ .elements = &packed_elements.? } else null, .v5_universal = .{ .claim = claim.universal_sum, .elements = elements } }).init();
                handle.* = adapter.asVerifierComponent();
            }
            const receipt = Verified{ .packed_transition = word_mode, .instance_index = index, .transition_sum = transition_sum, .universal_sum = universal_sum, .event_count = count, .range_claims = ranges, .native_roots = native_receipt.first_roots, .witness_root = witness_root, .native_instance_id = native_receipt.instance_id, .sealed_digest = sealed.digest };
            owns_proof = false;
            try core.verifier.verify(suite.Hasher, suite.MerkleChannel, a, handles, &channel, &verifier, proof.stark);
            return receipt;
        }
    };
}

fn mainMask(a: std.mem.Allocator, slots: []const Slot, main_count: usize) ![]bool {
    const mask = try a.alloc(bool, main_count);
    errdefer a.free(mask);
    @memset(mask, false);
    for (slots) |slot| {
        const width = opcode.nColumnsForFamily(slot.family);
        if (slot.main_offset + width > main_count) return error.InvalidV5OpcodeMemorySlots;
        @memset(mask[slot.main_offset..][0..width], true);
    }
    return mask;
}
fn witnessLogs(a: std.mem.Allocator, slots: []const Slot) ![]u32 {
    const logs = try a.alloc(u32, slots.len * integer.COLUMN_COUNT);
    for (slots, 0..) |slot, i| @memset(logs[i * integer.COLUMN_COUNT ..][0..integer.COLUMN_COUNT], slot.log_size);
    return logs;
}
