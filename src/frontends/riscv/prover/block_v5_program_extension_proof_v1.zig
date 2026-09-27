//! Same-native-root program-request PCS sidecar for SHA/Keccak/signer callers.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
const relation = @import("../air/lang/relation.zig");
const source = @import("block_v5_program_extension_source_v1.zig");
const slot_mod = @import("block_v5_program_extension_slots_v1.zig");
const adapter = @import("block_v5_program_extension_component_v1.zig");
const sha = @import("../air/guest_precompile/sha256_memory_caller.zig");
const signer = @import("../air/guest_precompile/secp256k1_recovery_caller.zig");
const keccak = @import("../air/guest_precompile/keccakf_caller.zig");
const MAX_MAIN = @max(sha.PHYSICAL_MAIN_COLUMN_COUNT + 4, @max(signer.Layout.main_columns + 2, keccak.Layout.main_columns + 2));
const table = @import("block_v5_program_table_proof_v1.zig");
const universal = @import("../recursion/air/universal_challenges.zig");
const framework = @import("../recursion/air/framework_interaction.zig");
const Digest = suite.Hasher.Hash;
pub const TAG: u32 = 0x42355045; // B5PE

pub const Slot = slot_mod.Slot;
/// The roster ID commits to the independently prepared native key, segment
/// ordinal, and complete typed caller slot geometry before relation draws.
pub fn instanceId(precompile_instance_id: [32]u8, execution_instance_id: [32]u8, index: u32, slots: []const Slot) [32]u8 {
    var channel = firstChannel(TAG, precompile_instance_id, execution_instance_id, index, slots);
    return channel.digestBytes();
}
pub const Claim = struct { sum: Q, fetch_count: u64 };
pub const Proof = struct {
    stark: suite.Proof,
    claims: []Claim,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        a.free(self.claims);
        self.* = undefined;
    }
};
pub const VerifiedReceipt = struct {
    sum: Q,
    fetch_count: u64,
    precompile_roots: [2]Digest,
    precompile_instance_id: [32]u8,
    execution_instance_id: [32]u8,
    sealed_channel_digest: [32]u8,
    pub fn closureReceipt(self: VerifiedReceipt) table.VerifiedNativeRequest {
        return .{ .claim = self.sum, .fetch_count = self.fetch_count, .sealed_channel_digest = self.sealed_channel_digest };
    }
};

pub fn ForBackend(comptime Backend: type) type {
    return ForProjectionBackend(Backend, .program);
}

/// Shared quotient machinery; state uses a distinct protocol/transcript.
pub fn ForProjectionBackend(comptime Backend: type, comptime projection: adapter.Projection) type {
    return struct {
        const projection_tag: u32 = if (projection == .program) TAG else 0x42355053;
        const Scheme = engine.pcs.CommitmentSchemeProver(Backend, suite.Hasher, suite.MerkleChannel);
        const Verifier = core.pcs.verifier.CommitmentSchemeVerifier(suite.Hasher, suite.MerkleChannel);
        pub const FirstRound = struct {
            scheme: Scheme,
            roots: [2]Digest,
            fixed_logs: []u32,
            main_logs: []u32,
            owns_scheme: bool = true,
            pub fn deinit(self: *FirstRound, a: std.mem.Allocator) void {
                if (self.owns_scheme) self.scheme.deinit(a);
                a.free(self.fixed_logs);
                a.free(self.main_logs);
                self.* = undefined;
            }
        };
        pub fn commitFirstRound(a: std.mem.Allocator, fixed: []const Column, main: []const Column, slots: []const Slot, precompile_instance_id: [32]u8, execution_instance_id: [32]u8, instance_index: u32, config: core.pcs.PcsConfig) !FirstRound {
            try validateSlots(slots, fixed, main);
            const fixed_logs = try logs(a, fixed);
            errdefer a.free(fixed_logs);
            const main_logs = try logs(a, main);
            errdefer a.free(main_logs);
            var scheme = try Scheme.init(a, config);
            errdefer scheme.deinit(a);
            scheme.setCoefficientRetentionPolicy(.always);
            var channel = firstChannel(projection_tag, precompile_instance_id, execution_instance_id, instance_index, slots);
            try scheme.commitBorrowedStreaming(a, fixed, 16, &channel);
            try scheme.commitBorrowedStreaming(a, main, 16, &channel);
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            if (roots.items.len != 2) return error.InvalidProgramRequestFirstRound;
            return .{ .scheme = scheme, .roots = roots.items[0..2].*, .fixed_logs = fixed_logs, .main_logs = main_logs };
        }
        pub fn prove(a: std.mem.Allocator, first: *FirstRound, fixed: []const Column, main: []const Column, slots: []const Slot, seal: table.Seal, precompile_instance_id: [32]u8, execution_instance_id: [32]u8, instance_index: u32, trusted_precompile_roots: [2]Digest) !Proof {
            if (!first.owns_scheme or !std.meta.eql(first.roots, trusted_precompile_roots)) return error.UntrustedProgramRequestFirstRound;
            try validateSlots(slots, fixed, main);
            var relation_channel = seal.sharedChannel();
            const relations = try universal.UniversalRelations.draw(a, &relation_channel);
            const claims = try a.alloc(Claim, slots.len);
            errdefer a.free(claims);
            const components = try a.alloc(adapter.Component, slots.len);
            defer a.free(components);
            const handles = try a.alloc(engine.air.component_prover.ComponentProver, slots.len);
            defer a.free(handles);
            var interactions: std.ArrayList(Column) = .empty;
            defer {
                for (interactions.items) |column| a.free(column.values);
                interactions.deinit(a);
            }
            const interaction_logs = try a.alloc(u32, slots.len * 4);
            defer a.free(interaction_logs);
            const fixed_open_mask = try fixedOpenMask(a, first.fixed_logs.len, slots);
            defer a.free(fixed_open_mask);
            const main_open_mask = try mainOpenMask(a, first.main_logs.len, slots);
            defer a.free(main_open_mask);
            for (slots, claims, components, handles, 0..) |slot, *claim, *component, *handle, index| {
                try interactions.ensureUnusedCapacity(a, 4);
                const generated = try generate(a, fixed, main, slot, &relations, projection);
                claim.* = .{ .sum = generated.claim, .fetch_count = slot.active_calls };
                for (generated.columns, 0..) |values, limb| {
                    interactions.appendAssumeCapacity(.{ .log_size = slot.log_size, .values = values });
                    interaction_logs[4 * index + limb] = slot.log_size;
                }
                component.* = try (adapter.Component{ .projection = projection, .slot = slot, .fixed_logs = first.fixed_logs, .main_logs = first.main_logs, .root_owner = index == 0, .fixed_open_mask = fixed_open_mask, .main_open_mask = main_open_mask, .interaction_offset = 4 * index, .interaction_logs = interaction_logs, .claim = claim.sum, .relations = &relations }).init();
                handle.* = component.asProverComponent();
            }
            var channel = try projectionChannel(a, seal, projection, projection_tag);
            mixClaims(projection_tag, &channel, precompile_instance_id, execution_instance_id, instance_index, slots, claims);
            try first.scheme.commitBorrowedStreaming(a, interactions.items, 8, &channel);
            first.owns_scheme = false;
            return .{ .stark = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, handles, &channel, first.scheme), .claims = claims };
        }
        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, seal: table.Seal, instance_index: u32, precompile_instance_id: [32]u8, execution_instance_id: [32]u8, slots: []const Slot, fixed_logs: []const u32, main_logs: []const u32, trusted_precompile_roots: [2]Digest, pinned_request_roots: [2]Digest, config: core.pcs.PcsConfig) !VerifiedReceipt {
            var proof = received;
            var owns = true;
            defer if (owns) proof.deinit(a);
            defer if (!owns) a.free(proof.claims);
            if (slots.len == 0 or proof.claims.len != slots.len or !std.meta.eql(trusted_precompile_roots, pinned_request_roots) or
                !std.meta.eql(proof.stark.commitment_scheme_proof.config, config)) return error.InvalidProgramRequestProof;
            const roots = proof.stark.commitment_scheme_proof.commitments.items;
            if (roots.len != 4 or !std.meta.eql(roots[0..2].*, trusted_precompile_roots)) return error.UntrustedProgramRequestFirstRound;
            var channel = firstChannel(projection_tag, precompile_instance_id, execution_instance_id, instance_index, slots);
            var verifier = try Verifier.init(a, config);
            defer verifier.deinit(a);
            try verifier.commit(a, roots[0], fixed_logs, &channel);
            try verifier.commit(a, roots[1], main_logs, &channel);
            var relation_channel = seal.sharedChannel();
            const relations = try universal.UniversalRelations.draw(a, &relation_channel);
            channel = try projectionChannel(a, seal, projection, projection_tag);
            mixClaims(projection_tag, &channel, precompile_instance_id, execution_instance_id, instance_index, slots, proof.claims);
            const interaction_logs = try a.alloc(u32, slots.len * 4);
            defer a.free(interaction_logs);
            const fixed_open_mask = try fixedOpenMask(a, fixed_logs.len, slots);
            defer a.free(fixed_open_mask);
            const main_open_mask = try mainOpenMask(a, main_logs.len, slots);
            defer a.free(main_open_mask);
            var total = Q.zero();
            var count: u64 = 0;
            for (slots, proof.claims, 0..) |slot, claim, i| {
                if (claim.fetch_count != slot.active_calls)
                    return error.InvalidProgramRequestCensus;
                try slot_mod.validate(slot, fixed_logs, main_logs);
                @memset(interaction_logs[4 * i ..][0..4], slot.log_size);
                total = total.add(claim.sum);
                count = try std.math.add(u64, count, claim.fetch_count);
            }
            try verifier.commit(a, roots[2], interaction_logs, &channel);
            const components = try a.alloc(adapter.Component, slots.len);
            defer a.free(components);
            const handles = try a.alloc(core.air.components.Component, slots.len);
            defer a.free(handles);
            for (slots, proof.claims, components, handles, 0..) |slot, claim, *component, *handle, i| {
                component.* = try (adapter.Component{ .projection = projection, .slot = slot, .fixed_logs = fixed_logs, .main_logs = main_logs, .root_owner = i == 0, .fixed_open_mask = fixed_open_mask, .main_open_mask = main_open_mask, .interaction_offset = 4 * i, .interaction_logs = interaction_logs, .claim = claim.sum, .relations = &relations }).init();
                handle.* = component.asVerifierComponent();
            }
            var digest_channel = seal.sharedChannel();
            const receipt = VerifiedReceipt{ .sum = total, .fetch_count = count, .precompile_roots = trusted_precompile_roots, .precompile_instance_id = precompile_instance_id, .execution_instance_id = execution_instance_id, .sealed_channel_digest = digest_channel.digestBytes() };
            owns = false;
            try core.verifier.verify(suite.Hasher, suite.MerkleChannel, a, handles, &channel, &verifier, proof.stark);
            return receipt;
        }
    };
}

const Generated = struct { columns: [4][]M, claim: Q };
fn generate(a: std.mem.Allocator, fixed: []const Column, main: []const Column, slot: Slot, relations: *const universal.UniversalRelations, comptime projection: adapter.Projection) !Generated {
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
        var row: [MAX_MAIN]Q = undefined;
        var fixed_row: [sha.PREPROCESSED_COLUMN_COUNT]Q = undefined;
        const physical = framework.committedRow(logical, slot.log_size);
        if (slot.fixed_selector_offset) |offset|
            fixed_row[0] = Q.fromBase(fixed[offset].values[physical]);
        for (row[0..slot.main_columns], main[slot.main_offset..][0..slot.main_columns]) |*value, column|
            value.* = Q.fromBase(column.values[physical]);
        const fixed_slice: []const Q = if (slot.fixed_selector_offset != null)
            fixed_row[0..sha.PREPROCESSED_COLUMN_COUNT]
        else
            &.{};
        if (projection == .state) {
            const state = try @import("block_v5_precompile_state_request_source_v1.zig").fromCommittedCaller(slot.kind, fixed_slice, row[0..slot.main_columns]);
            const bus = relations.get(relation.Domain.registers_state);
            const consume = try bus.combineSecure(&state.consumed);
            const emit = try bus.combineSecure(&state.emitted);
            terms[logical] = state.active.mul((try emit.inv()).sub(try consume.inv()));
        } else {
            const request = try source.fromCommittedCaller(slot.kind, fixed_slice, row[0..slot.main_columns]);
            const denominator = try relations.get(relation.Domain.program_access).combineSecure(&request.tuple);
            terms[logical] = request.numerator.mul(try denominator.inv());
        }
    }
    var claim = Q.zero();
    for (terms) |term| claim = claim.add(term);
    const shift = try claim.divM31(M.fromCanonical(@intCast(size)));
    var running = Q.zero();
    for (terms, 0..) |term, logical| {
        running = running.add(term).sub(shift);
        const limbs = running.toM31Array();
        const physical = framework.committedRow(logical, slot.log_size);
        for (&columns, limbs) |*values, limb| values.*[physical] = limb;
    }
    return .{ .columns = columns, .claim = claim };
}
fn validateSlots(slots: []const Slot, fixed: []const Column, main: []const Column) !void {
    if (slots.len == 0) return error.EmptyProgramRequestRoster;
    for (slots) |slot| {
        if (slot.log_size == 0 or slot.log_size > 24 or
            slot.active_calls > (@as(u32, 1) << @intCast(slot.log_size)) or
            slot.main_offset + slot.main_columns > main.len)
            return error.InvalidProgramRequestRoster;
        if (slot.fixed_selector_offset) |offset| {
            if (offset >= fixed.len or fixed[offset].log_size != slot.log_size or
                fixed[offset].values.len != (@as(usize, 1) << @intCast(slot.log_size)))
                return error.InvalidProgramRequestRoster;
        }
        for (main[slot.main_offset..][0..slot.main_columns]) |column| if (column.log_size != slot.log_size or
            column.values.len != (@as(usize, 1) << @intCast(slot.log_size))) return error.InvalidProgramRequestRoster;
    }
}
fn logs(a: std.mem.Allocator, columns: []const Column) ![]u32 {
    const result = try a.alloc(u32, columns.len);
    for (columns, result) |column, *log| log.* = column.log_size;
    return result;
}
fn fixedOpenMask(a: std.mem.Allocator, len: usize, slots: []const Slot) ![]bool {
    const result = try a.alloc(bool, len);
    errdefer a.free(result);
    @memset(result, false);
    for (slots) |slot| if (slot.fixed_selector_offset) |offset| {
        if (offset >= len) return error.InvalidProgramRequestRoster;
        result[offset] = true;
    };
    return result;
}
fn mainOpenMask(a: std.mem.Allocator, len: usize, slots: []const Slot) ![]bool {
    const result = try a.alloc(bool, len);
    errdefer a.free(result);
    @memset(result, false);
    for (slots) |slot| {
        if (slot.main_offset + slot.main_columns > len) return error.InvalidProgramRequestRoster;
        @memset(result[slot.main_offset..][0..slot.main_columns], true);
    }
    return result;
}
fn firstChannel(tag: u32, precompile_instance_id: [32]u8, execution_instance_id: [32]u8, index: u32, slots: []const Slot) suite.Channel {
    var channel = suite.Channel{};
    channel.mixU32s(&.{ tag, 1, index, @intCast(slots.len) });
    channel.mixRoot(precompile_instance_id);
    channel.mixRoot(execution_instance_id);
    for (slots) |slot| {
        channel.mixU32s(&.{ @intFromEnum(slot.kind), slot.log_size, slot.active_calls, if (slot.fixed_selector_offset) |offset| @intCast(offset) else std.math.maxInt(u32), @intCast(slot.main_offset), @intCast(slot.main_columns) });
        if (slot.x0_local_custody_version != 0) channel.mixU32s(&.{ 0x58304350, slot.x0_local_custody_version });
    }
    return channel;
}
fn proofChannel(seal: table.Seal) suite.Channel {
    var channel = seal.proofChannel();
    channel.mixU32s(&.{ TAG, 3 });
    return channel;
}
fn mixClaims(tag: u32, channel: anytype, precompile_instance_id: [32]u8, execution_instance_id: [32]u8, index: u32, slots: []const Slot, claims: []const Claim) void {
    channel.mixU32s(&.{ tag, 2, index, @intCast(claims.len) });
    channel.mixRoot(precompile_instance_id);
    channel.mixRoot(execution_instance_id);
    for (slots, claims) |slot, claim| {
        channel.mixU32s(&.{ @intFromEnum(slot.kind), slot.active_calls });
        channel.mixU64(claim.fetch_count);
        channel.mixFelts(&.{claim.sum});
    }
}

fn projectionChannel(a: std.mem.Allocator, seal: table.Seal, comptime projection: adapter.Projection, tag: u32) !suite.Channel {
    if (projection == .program) return proofChannel(seal);
    var channel = seal.sharedChannel();
    _ = try universal.UniversalRelations.draw(a, &channel);
    channel.mixU32s(&.{ tag, 1 });
    channel.mixRoot(seal.source_digest);
    return channel;
}
