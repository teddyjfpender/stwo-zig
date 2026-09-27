//! A single PCS/STARK for native projections AND packed ordinary access.
//! Four trace trees: fixed, main, source-sealed access witness, interaction.
//! The native base AIR remains independently freshly verified. This module
//! emits separate open bus receipts, never complete block authority.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
const Digest = suite.Hasher.Hash;
const Source = @import("block_v5_native_projection_fused_source_v1.zig");
const Projection = @import("block_v5_native_projection_fused_proof_v1.zig");
const Adapter = @import("block_v5_native_projection_fused_component_v2.zig");
const Memory = @import("block_v5_opcode_memory_sidecar_proof_v1.zig");
const Batch = @import("block_execution_sidecar_batch_v2.zig");
const Integer = @import("block_execution_integer_bridge_v2.zig");
const Range = @import("block_execution_byte_range_v2.zig");
const Eval = @import("block_v5_opcode_sidecar_eval_v1.zig");
const Transition = @import("block_execution_transition_interaction_v2.zig");
const PackedTransition = @import("block_v5_word_execution_transition_v1.zig");
const UniversalMemory = @import("block_v5_opcode_memory_interaction_v1.zig");
const Word = @import("block_v5_word_memory_protocol_v1.zig");
const Bus = @import("block_memory_relation_v2.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Catalog = @import("block_v5_native_template_catalog_v1.zig");
const Native = @import("block_v5_native_execution_proof_v3.zig");
const Template = @import("block_v5_native_template_protocol_v3.zig");
const Opcode = @import("../runner/trace.zig");
const Framework = @import("../recursion/air/framework_interaction.zig");
const Canonical = @import("../recursion/air/universal_provider_relations.zig");
const Schema = @import("../air/lookups/tables/schema.zig");
const Frame = @import("../air/block/memory_event.zig").Frame;
const Empty = @import("block_v5_empty_opcode_memory_v1.zig");

pub const TAG: u32 = 0x42354650;
pub const VERSION: u32 = 2;
pub const Claim = Projection.Claim;
pub const Proof = struct {
    stark: suite.Proof,
    claims: []Claim,
    memory_claims: []Memory.Claim,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        a.free(self.claims);
        a.free(self.memory_claims);
        self.* = undefined;
    }
};
pub const Verified = struct {
    projections: ?Projection.VerifiedReceipt,
    memory: ?Memory.Verified,
    pub fn deinit(self: *Verified, a: std.mem.Allocator) void {
        if (self.memory) |*memory| memory.deinit(a);
        self.* = undefined;
    }
};

pub fn instanceId(template: Digest, native: Digest, roots: [2]Digest, access: Digest, index: u32, frame: Frame, projections: []const Source.Slot, slots: []const Memory.Slot) Digest {
    var channel = firstChannel(template, native, index, projections, slots);
    channel.mixRoot(roots[0]);
    channel.mixRoot(roots[1]);
    channel.mixRoot(access);
    channel.mixU32s(&.{ @intFromEnum(frame.clock_frame), frame.cycle_count });
    channel.mixU64(frame.global_first_cycle);
    return channel.digestBytes();
}
pub fn entry(template: Digest, native: Digest, roots: [2]Digest, access: Digest, index: u32, frame: Frame, projections: []const Source.Slot, slots: []const Memory.Slot) Seal.Entry {
    return .{ .family = .program_request, .index = index, .roots = roots, .instance_id = instanceId(template, native, roots, access, index, frame, projections, slots) };
}

/// Exact union of every native main opening. A root owner cannot omit main
/// cells used by an access component merely because it owns a projection.
pub fn mainMask(a: std.mem.Allocator, count: usize, projections: []const Source.Slot, slots: []const Memory.Slot) ![]bool {
    const mask = try a.alloc(bool, count);
    errdefer a.free(mask);
    @memset(mask, false);
    for (projections) |slot| {
        if (slot.main_offset > count or slot.width > count - slot.main_offset) return error.InvalidV5FullFusedRoster;
        @memset(mask[slot.main_offset..][0..slot.width], true);
    }
    for (slots) |slot| {
        const width = Opcode.nColumnsForFamily(slot.family);
        if (slot.main_offset > count or width > count - slot.main_offset) return error.InvalidV5FullFusedRoster;
        @memset(mask[slot.main_offset..][0..width], true);
    }
    return mask;
}
pub fn compositionSplit(projections: []const Source.Slot) u32 {
    var split: u32 = 2;
    for (projections) |slot| split = @max(split, std.math.log2_int_ceil(u32, slot.degree));
    return split;
}
pub fn interactionLogs(a: std.mem.Allocator, projections: []const Source.Slot, slots: []const Memory.Slot) ![]u32 {
    const count = try std.math.add(usize, try std.math.mul(usize, projections.len, 4), try std.math.mul(usize, slots.len, Eval.INTERACTION_COUNT));
    const logs = try a.alloc(u32, count);
    for (projections, 0..) |slot, i| @memset(logs[4 * i ..][0..4], slot.log_size);
    const begin = projections.len * 4;
    for (slots, 0..) |slot, i| @memset(logs[begin + i * Eval.INTERACTION_COUNT ..][0..Eval.INTERACTION_COUNT], slot.log_size);
    return logs;
}
pub fn witnessLogs(a: std.mem.Allocator, slots: []const Memory.Slot) ![]u32 {
    const logs = try a.alloc(u32, try std.math.mul(usize, slots.len, Integer.COLUMN_COUNT));
    for (slots, 0..) |slot, i| @memset(logs[i * Integer.COLUMN_COUNT ..][0..Integer.COLUMN_COUNT], slot.log_size);
    return logs;
}

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub const FirstRound = Memory.ForPackedBackend(Backend).FirstRound;
        const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel);

        /// Both inputs are genuine producer objects; neither is a fabricated
        /// verifier receipt. The access prefix is consumed, native is retained.
        pub fn proveForNativeFirstRound(a: std.mem.Allocator, first: *FirstRound, inputs: []const Memory.Input, slots: []const Memory.Slot, projections: []const Source.Slot, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, catalog: Catalog.Admission, native: *Native.ForBackend(Backend).FirstRound, index: u32, frame: Frame, witness_root: Digest) !Proof {
            if (!native.owns_scheme or native.index != index or !native.native.native_only_v5 or native.native.failed or
                !native.native.tables_ready or native.native.interaction_ready or native.scheme.trees.items.len != 2 or
                !std.meta.eql(native.scheme.config, pins.config)) return error.UntrustedV5FullFusedNativePhase;
            try native.pin.require(pins, &native.native.statement.public_data);
            try native.template.admit(&native.native.statement, native.template_id);
            try catalog.admit(pins, sealed, index, native.template, native.template_id);
            if (!std.meta.eql(native.instance_id, try Template.instanceId(native.template_id, &native.native.statement, native.pin, native.roots, index)))
                return error.UntrustedV5FullFusedNativePhase;
            var actual_native_roots = try native.scheme.roots(a);
            defer actual_native_roots.deinit(a);
            if (actual_native_roots.items.len != 2 or !std.meta.eql(actual_native_roots.items[0..2].*, native.roots) or
                !std.meta.eql(first.scheme.config, pins.config)) return error.UntrustedV5FullFusedNativePhase;
            const fixed_logs = try Template.columnLogs(a, &native.native.statement, native.template.external_retirements, .fixed);
            defer a.free(fixed_logs);
            const main_logs = try Template.columnLogs(a, &native.native.statement, native.template.external_retirements, .main);
            defer a.free(main_logs);
            if (!std.mem.eql(u32, fixed_logs, first.fixed_logs) or !std.mem.eql(u32, main_logs, first.main_logs)) return error.UntrustedV5FullFusedNativePhase;
            const canonical = try Source.slotsFromShapeForMode(a, &native.native.statement, native.template.external_retirements, sealed.register_custody_mode);
            defer a.free(canonical);
            try requireProjectionRoster(projections, canonical);
            const memory_slots = try Batch.slotsFromStatementForMode(a, &native.native.statement, frame, sealed.register_custody_mode);
            defer a.free(memory_slots);
            if (memory_slots.len != slots.len) return error.InvalidV5FullFusedRoster;
            for (memory_slots, slots) |actual, expected| if (!std.meta.eql(actual, expected)) return error.InvalidV5FullFusedRoster;
            if (frame.clock_frame != .leaf_local or frame.global_first_cycle != native.pin.context.first_cycle or frame.cycle_count != native.native.statement.public_data.clock)
                return error.UntrustedV5FullFusedNativePhase;
            try Native.admitEntry(index, native.roots, native.instance_id, sealed, entries);
            const empty_entry: ?Seal.Entry = if (slots.len == 0) try Empty.firstRoundEntryForMode(a, &native.native.statement, frame, native.entry(), 0, sealed.register_custody_mode) else null;
            try admit(sealed, pins, entries, index, native.template_id, native.instance_id, native.roots, witness_root, frame, projections, slots, empty_entry);
            return proveBound(a, first, native.native.main.items, inputs, slots, projections, sealed, native.template_id, native.instance_id, index, witness_root, native.roots);
        }

        fn proveBound(a: std.mem.Allocator, first: *FirstRound, main: []const Column, inputs: []const Memory.Input, slots: []const Memory.Slot, projections: []const Source.Slot, sealed: Seal.Sealed, template: Digest, native: Digest, index: u32, witness_root: Digest, roots: [2]Digest) !Proof {
            try validateRoster(projections, slots, first.main_logs, sealed.register_custody_mode);
            if (!first.owns_scheme or first.scheme.trees.items.len != (if (slots.len == 0) @as(usize, 2) else 3) or inputs.len != slots.len or first.snapshots.len != slots.len or
                !std.meta.eql(first.roots[0..2].*, roots) or !std.meta.eql(first.roots[2], witness_root)) return error.UntrustedV5FullFusedFirstRound;
            var actual_roots = try first.scheme.roots(a);
            defer actual_roots.deinit(a);
            if (!std.meta.eql(actual_roots.items[0..2].*, roots) or (slots.len != 0 and !std.meta.eql(actual_roots.items[2], witness_root))) return error.UntrustedV5FullFusedFirstRound;
            for (inputs, slots) |input, slot| if (!std.meta.eql(input.descriptor, slot) or input.trace.family != slot.family or
                input.trace.slot != slot.slot or input.trace.log_size != slot.log_size or input.trace.register_custody_mode != sealed.register_custody_mode)
                return error.InvalidV5FullFusedInputs;
            const claims = try a.alloc(Claim, projections.len);
            errdefer a.free(claims);
            const memory_claims = try a.alloc(Memory.Claim, slots.len);
            errdefer a.free(memory_claims);
            var interactions: std.ArrayList(Column) = .empty;
            defer {
                for (interactions.items) |column| a.free(column.values);
                interactions.deinit(a);
            }
            const logs = try interactionLogs(a, projections, slots);
            defer a.free(logs);
            const witness_logs = try witnessLogs(a, slots);
            defer a.free(witness_logs);
            const mask = try mainMask(a, first.main_logs.len, projections, slots);
            defer a.free(mask);
            var channel = try proofChannel(a, sealed);
            const word_challenges = try Word.Challenges.draw(a, sealed);
            const challenges = try Bus.Challenges.draw(a, sealed);
            const relations = &word_challenges.universal_prefix;
            const elements = relations.get(.memory_access);
            var cache = try @import("block_v5_quotient_column_cache_v1.zig").Cache.init(a);
            defer cache.deinit();
            const projection_components = try a.alloc(Adapter.ProjectionComponent, projections.len);
            defer a.free(projection_components);
            const memory_components = try a.alloc(Adapter.AccessComponent, slots.len);
            defer a.free(memory_components);
            const handles = try a.alloc(engine.air.component_prover.ComponentProver, try std.math.add(usize, projections.len, slots.len));
            defer a.free(handles);
            for (projections, claims, projection_components, 0..) |slot, *claim, *component, i| {
                try interactions.ensureUnusedCapacity(a, 4);
                const generated = try generateProjection(a, main, slot, relations);
                claim.* = .{ .sum = generated.sum, .row_count = slot.n_rows };
                for (generated.columns) |values| interactions.appendAssumeCapacity(.{ .log_size = slot.log_size, .values = values });
                component.* = try (Adapter.ProjectionComponent{ .has_access_witness = slots.len != 0, .inner = .{ .quotient_cache = &cache, .slot = slot, .fixed_logs = first.fixed_logs, .main_logs = first.main_logs, .root_owner = i == 0, .main_open_mask = mask, .interaction_offset = 4 * i, .interaction_logs = logs, .claim = claim.sum, .relations = relations, .composition_split = compositionSplit(projections) } }).init();
                handles[i] = component.asProverComponent();
            }
            for (inputs, memory_claims, first.snapshots, memory_components, 0..) |input, *claim, snapshot, *component, i| {
                const rows = try a.alloc(Transition.Row, input.trace.domainSize());
                defer a.free(rows);
                const memory_rows = try a.alloc(UniversalMemory.Row, input.trace.domainSize());
                defer a.free(memory_rows);
                for (rows, memory_rows, 0..) |*row, *mem, j| {
                    row.* = try input.trace.row(j);
                    mem.* = try UniversalMemory.rowFromPair(try input.trace.pairAt(j));
                }
                var transition = try PackedTransition.generate(a, &word_challenges, rows, input.descriptor.log_size);
                defer transition.deinit(a);
                var bytes = try Range.generate(a, input.trace, relations.get(.range_check_8_8), snapshot);
                defer bytes.deinit(a);
                var memory = try UniversalMemory.generate(a, elements, memory_rows, input.descriptor.log_size);
                defer memory.deinit(a);
                claim.* = .{ .transition_sum = transition.claim, .universal_sum = memory.claim, .range_claims = bytes.claims, .active_count = transition.count };
                try appendColumns(a, &interactions, input.descriptor.log_size, &transition.columns);
                try appendColumns(a, &interactions, input.descriptor.log_size, &bytes.columns);
                try appendColumns(a, &interactions, input.descriptor.log_size, &memory.columns);
                component.* = try accessComponent(input.descriptor, i, projections.len, first.fixed_logs, first.main_logs, witness_logs, logs, claim.*, &challenges, &word_challenges, compositionSplit(projections), sealed.register_custody_mode);
                component.inner.quotient_cache = &cache;
                handles[projections.len + i] = component.asProverComponent();
            }
            try mixClaims(&channel, template, native, index, projections, slots, claims, memory_claims);
            try first.scheme.commitBorrowedStreaming(a, interactions.items, 8, &channel);
            first.owns_scheme = false;
            return .{ .stark = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, handles, &channel, first.scheme), .claims = claims, .memory_claims = memory_claims };
        }

        /// Internal fresh-native hook seam. The complete receiver must supply
        /// its just-verified native value, not transport a receipt as authority.
        /// This function consumes the STARK and all claims on every path.
        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, native: *const Native.OpenReceipt, index: u32, frame: Frame, projections: []const Source.Slot, slots: []const Memory.Slot, fixed_logs: []const u32, main_logs: []const u32, witness_root: Digest, empty_entry: ?Seal.Entry) !Verified {
            var proof = received;
            var owns = true;
            defer if (owns) proof.deinit(a);
            defer if (!owns) {
                a.free(proof.claims);
                a.free(proof.memory_claims);
            };
            if (!std.meta.eql(native.sealed_digest, sealed.digest)) return error.UntrustedV5FullFusedNativeSeal;
            try admit(sealed, pins, entries, index, native.template_id, native.instance_id, native.first_roots, witness_root, frame, projections, slots, empty_entry);
            try validateRoster(projections, slots, main_logs, sealed.register_custody_mode);
            if (proof.claims.len != projections.len or proof.memory_claims.len != slots.len or !std.meta.eql(proof.stark.commitment_scheme_proof.config, pins.config)) return error.InvalidV5FullFusedProof;
            const roots = proof.stark.commitment_scheme_proof.commitments.items;
            if (roots.len != (if (slots.len == 0) @as(usize, 4) else 5) or !std.meta.eql(roots[0..2].*, native.first_roots) or
                (slots.len != 0 and !std.meta.eql(roots[2], witness_root))) return error.UntrustedV5FullFusedFirstRound;
            var channel = firstChannel(native.template_id, native.instance_id, index, projections, slots);
            var verifier = try Verifier.init(a, pins.config);
            defer verifier.deinit(a);
            try verifier.commit(a, roots[0], fixed_logs, &channel);
            try verifier.commit(a, roots[1], main_logs, &channel);
            const witness_logs = try witnessLogs(a, slots);
            defer a.free(witness_logs);
            if (slots.len != 0) try verifier.commit(a, roots[2], witness_logs, &channel);
            const logs = try interactionLogs(a, projections, slots);
            defer a.free(logs);
            const mask = try mainMask(a, main_logs.len, projections, slots);
            defer a.free(mask);
            const word_challenges = try Word.Challenges.draw(a, sealed);
            const challenges = try Bus.Challenges.draw(a, sealed);
            channel = try proofChannel(a, sealed);
            try mixClaims(&channel, native.template_id, native.instance_id, index, projections, slots, proof.claims, proof.memory_claims);
            try verifier.commit(a, roots[if (slots.len == 0) @as(usize, 2) else 3], logs, &channel);
            const projection_components = try a.alloc(Adapter.ProjectionComponent, projections.len);
            defer a.free(projection_components);
            const memory_components = try a.alloc(Adapter.AccessComponent, slots.len);
            defer a.free(memory_components);
            const handles = try a.alloc(core.air.components.Component, projections.len + slots.len);
            defer a.free(handles);
            for (projections, proof.claims, projection_components, 0..) |slot, claim, *component, i| {
                component.* = try (Adapter.ProjectionComponent{ .has_access_witness = slots.len != 0, .inner = .{ .slot = slot, .fixed_logs = fixed_logs, .main_logs = main_logs, .root_owner = i == 0, .main_open_mask = mask, .interaction_offset = 4 * i, .interaction_logs = logs, .claim = claim.sum, .relations = &word_challenges.universal_prefix, .composition_split = compositionSplit(projections) } }).init();
                handles[i] = component.asVerifierComponent();
            }
            for (slots, proof.memory_claims, memory_components, 0..) |slot, claim, *component, i| {
                component.* = try accessComponent(slot, i, projections.len, fixed_logs, main_logs, witness_logs, logs, claim, &challenges, &word_challenges, compositionSplit(projections), sealed.register_custody_mode);
                handles[projections.len + i] = component.asVerifierComponent();
            }
            var result = try receipts(a, proof.claims, proof.memory_claims, projections, native, witness_root, index, sealed);
            errdefer result.deinit(a);
            owns = false;
            try core.verifier.verify(suite.Hasher, suite.MerkleChannel, a, handles, &channel, &verifier, proof.stark);
            return result;
        }
    };
}

fn accessComponent(slot: Memory.Slot, ordinal: usize, projection_count: usize, fixed: []const u32, main: []const u32, witness: []const u32, interactions: []const u32, claim: Memory.Claim, challenges: *const Bus.Challenges, word_challenges: *const Word.Challenges, split: u32, mode: u32) !Adapter.AccessComponent {
    return (Adapter.AccessComponent{ .composition_split = split, .inner = .{ .register_custody_mode = mode, .family = slot.family, .slot = slot.slot, .log_size = slot.log_size, .base_clock = try Integer.baseClockFromPublicFrame(slot.frame), .fixed_logs = fixed, .main_logs = main, .witness_logs = witness, .interaction_logs = interactions, .root_owner = false, .main_offset = slot.main_offset, .witness_offset = ordinal * Integer.COLUMN_COUNT, .interaction_offset = projection_count * 4 + ordinal * Eval.INTERACTION_COUNT, .transition_claim = claim.transition_sum, .transition_count = claim.active_count, .range_claims = claim.range_claims, .challenges = challenges, .v5_packed = .{ .elements = word_challenges }, .v5_universal = .{ .claim = claim.universal_sum, .elements = word_challenges.universal_prefix.get(.memory_access) } } }).init();
}
pub fn requireProjectionRoster(actual: []const Source.Slot, expected: []const Source.Slot) !void {
    if (actual.len != expected.len) return error.InvalidV5FullFusedRoster;
    for (actual, expected) |left, right| if (!std.meta.eql(left, right)) return error.InvalidV5FullFusedRoster;
}
pub fn validateRoster(projections: []const Source.Slot, slots: []const Memory.Slot, main: []const u32, mode: u32) !void {
    if (projections.len == 0) return error.EmptyV5FullFusedRequiresTypedAbsence;
    try Batch.requireRwSlots(slots, mode);
    for (projections) |slot| {
        if (slot.register_custody_mode != mode or slot.degree == 0 or slot.log_size == 0 or slot.log_size > 24 or
            slot.n_rows > (@as(u32, 1) << @intCast(slot.log_size)) or slot.main_offset > main.len or slot.width > main.len - slot.main_offset)
            return error.InvalidV5FullFusedRoster;
        for (main[slot.main_offset..][0..slot.width]) |log| if (log != slot.log_size) return error.InvalidV5FullFusedRoster;
    }
    for (slots) |slot| {
        const width = Opcode.nColumnsForFamily(slot.family);
        if (slot.log_size == 0 or slot.log_size > 24 or slot.main_offset > main.len or width > main.len - slot.main_offset) return error.InvalidV5FullFusedRoster;
        for (main[slot.main_offset..][0..width]) |log| if (log != slot.log_size) return error.InvalidV5FullFusedRoster;
    }
}
pub fn admit(sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, index: u32, template: Digest, native: Digest, roots: [2]Digest, access: Digest, frame: Frame, projections: []const Source.Slot, slots: []const Memory.Slot, empty_entry: ?Seal.Entry) !void {
    try sealed.require(pins, entries);
    if (index >= sealed.execution_instance_count) return error.UntrustedV5FullFusedIndex;
    const execution = try find(entries, .execution, index);
    if (!std.meta.eql(execution.roots, roots) or !std.meta.eql(execution.instance_id, native)) return error.UntrustedV5FullFusedNativeEntry;
    const request = try find(entries, .program_request, index);
    if (!std.meta.eql(request, entry(template, native, roots, access, index, frame, projections, slots))) return error.UntrustedV5FullFusedProjectionEntry;
    const memory = try find(entries, .execution_sidecar, index);
    if (slots.len == 0) {
        const expected = empty_entry orelse return error.EmptyV5FullFusedRequiresTypedAbsence;
        if (!std.meta.eql(expected.roots[0], access) or !std.meta.eql(memory, expected)) return error.UntrustedV5FullFusedAccessEntry;
    } else {
        if (empty_entry != null or !std.meta.eql(memory, Memory.packedEntry(native, roots, access, index, slots))) return error.UntrustedV5FullFusedAccessEntry;
    }
}
fn find(entries: []const Seal.Entry, family: Seal.Family, index: u32) !Seal.Entry {
    var found: ?Seal.Entry = null;
    for (entries) |item| if (item.family == family and item.index == index) {
        if (found != null) return error.DuplicateV5FullFusedEntry;
        found = item;
    };
    return found orelse error.MissingV5FullFusedEntry;
}
fn firstChannel(template: Digest, native: Digest, index: u32, projections: []const Source.Slot, slots: []const Memory.Slot) suite.Channel {
    var channel = suite.Channel{};
    channel.mixU32s(&.{ TAG, VERSION, 1, index, @intCast(projections.len), @intCast(slots.len) });
    channel.mixRoot(Word.abiId());
    channel.mixRoot(template);
    channel.mixRoot(native);
    for (projections) |slot| Source.mixSlot(&channel, slot);
    Batch.mixRoster(&channel, index, template, slots);
    return channel;
}
fn proofChannel(a: std.mem.Allocator, sealed: Seal.Sealed) !suite.Channel {
    var channel = sealed.sharedChannel();
    _ = try Word.Challenges.drawFromChannel(a, &channel);
    channel.mixU32s(&.{ TAG, VERSION, 3 });
    return channel;
}
pub fn mixClaims(channel: *suite.Channel, template: Digest, native: Digest, index: u32, projections: []const Source.Slot, slots: []const Memory.Slot, claims: []const Claim, memory_claims: []const Memory.Claim) !void {
    if (claims.len != projections.len or memory_claims.len != slots.len) return error.InvalidV5FullFusedClaims;
    channel.mixU32s(&.{ TAG, VERSION, 2, index, @intCast(claims.len), @intCast(memory_claims.len) });
    channel.mixRoot(template);
    channel.mixRoot(native);
    for (projections, claims) |slot, claim| {
        if (claim.row_count != slot.n_rows or !Canonical.secureIsCanonical(&claim.sum)) return error.InvalidV5FullFusedClaims;
        Source.mixSlot(channel, slot);
        channel.mixU64(claim.row_count);
        channel.mixFelts(&.{claim.sum});
    }
    Batch.mixRoster(channel, index, template, slots);
    for (slots, memory_claims) |slot, claim| {
        if (claim.active_count > (@as(u64, 1) << @intCast(slot.log_size)) or !Canonical.secureIsCanonical(&claim.transition_sum) or !Canonical.secureIsCanonical(&claim.universal_sum)) return error.InvalidV5FullFusedClaims;
        channel.mixU64(claim.active_count);
        channel.mixFelts(&.{ claim.transition_sum, claim.universal_sum });
        try Range.mixClaims(claim.range_claims, index, slot.family, slot.slot, channel);
    }
}
const Generated = struct { columns: [4][]M, sum: Q };
fn generateProjection(a: std.mem.Allocator, main: []const Column, slot: Source.Slot, relations: *const @import("../recursion/air/universal_challenges.zig").UniversalRelations) !Generated {
    const size: usize = @as(usize, 1) << @intCast(slot.log_size);
    var columns: [4][]M = undefined;
    var initialized: usize = 0;
    errdefer for (columns[0..initialized]) |values| a.free(values);
    for (&columns) |*values| {
        values.* = try a.alloc(M, size);
        initialized += 1;
    }
    const terms = try a.alloc(Q, size);
    defer a.free(terms);
    for (0..size) |logical| {
        var row: [Opcode.MAX_FAMILY_COLUMNS]Q = undefined;
        const physical = Framework.committedRow(logical, slot.log_size);
        if (slot.main_offset > main.len or slot.width > main.len - slot.main_offset) return error.InvalidV5FullFusedRoster;
        for (row[0..slot.width], main[slot.main_offset..][0..slot.width]) |*value, column| {
            if (column.log_size != slot.log_size or column.values.len != size) return error.InvalidV5FullFusedRoster;
            value.* = Q.fromBase(column.values[physical]);
        }
        const request = try Source.fromCommittedMain(slot, row[0..slot.width], relations);
        terms[logical] = request.numerator().mul(try request.denominator().inv());
    }
    var sum = Q.zero();
    for (terms) |term| sum = sum.add(term);
    const shift = try sum.divM31(M.fromCanonical(@intCast(size)));
    var running = Q.zero();
    for (terms, 0..) |term, logical| {
        running = running.add(term).sub(shift);
        const physical = Framework.committedRow(logical, slot.log_size);
        for (&columns, running.toM31Array()) |*values, limb| values.*[physical] = limb;
    }
    return .{ .columns = columns, .sum = sum };
}
fn appendColumns(a: std.mem.Allocator, output: *std.ArrayList(Column), log: u32, columns: []const []M) !void {
    for (columns) |values| {
        const owned = try a.dupe(M, values);
        errdefer a.free(owned);
        try output.append(a, .{ .log_size = log, .values = owned });
    }
}
fn receipts(a: std.mem.Allocator, claims: []const Claim, memory: []const Memory.Claim, projections: []const Source.Slot, native: *const Native.OpenReceipt, access: Digest, index: u32, sealed: Seal.Sealed) !Verified {
    var totals: [Source.PARTITION_COUNT]Q = @splat(Q.zero());
    var program_sum = Q.zero();
    var fetches: u64 = 0;
    for (projections, claims) |slot, claim| switch (slot.kind) {
        .program => {
            program_sum = program_sum.add(claim.sum);
            fetches = try std.math.add(u64, fetches, claim.row_count);
        },
        .lookup => |lookup| totals[@intFromEnum(lookup.partition)] = totals[@intFromEnum(lookup.partition)].add(claim.sum),
    };
    const ranges = try a.alloc(Range.Claims, memory.len);
    errdefer a.free(ranges);
    var transition = Q.zero();
    var universal = Q.zero();
    var events: u64 = 0;
    for (memory, ranges) |claim, *range| {
        range.* = claim.range_claims;
        transition = transition.add(claim.transition_sum);
        universal = universal.add(claim.universal_sum);
        events = try std.math.add(u64, events, claim.active_count);
    }
    if (memory.len == 0) a.free(ranges);
    return .{
        .projections = .{ .program_sum = program_sum, .fetch_count = fetches, .claims = totals[0..Schema.KIND_COUNT].*, .registers_state_sum = totals[@intFromEnum(Source.Partition.registers_state)], .auxiliary_clock_memory_sum = totals[@intFromEnum(Source.Partition.clock_memory_access)], .register_memory_sum = totals[@intFromEnum(Source.Partition.register_memory_access)], .register_clock_memory_sum = totals[@intFromEnum(Source.Partition.register_clock_memory_access)], .native_roots = native.first_roots, .native_key_id = native.template_id, .native_instance_id = native.instance_id, .execution_index = index, .sealed_digest = sealed.digest },
        .memory = if (memory.len == 0) null else .{ .instance_index = index, .transition_sum = transition, .packed_transition = true, .universal_sum = universal, .event_count = events, .range_claims = ranges, .native_roots = native.first_roots, .witness_root = access, .native_instance_id = native.instance_id, .sealed_digest = sealed.digest },
    };
}
