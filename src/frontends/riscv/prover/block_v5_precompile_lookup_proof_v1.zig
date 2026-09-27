//! Six shared-table partitions at fresh family11 PCS roots.
//! This projection is admitted only against a fresh caller arithmetic proof.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
const Profile = @import("blake3_ethereum_sha_profile.zig");
const Family = @import("block_v5_precompile_family_proof_v1.zig");
const Protocol = @import("block_v5_precompile_protocol_v1.zig");
const source = @import("block_v5_precompile_lookup_source_v1.zig");
const adapter = @import("block_v5_precompile_lookup_component_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const schema = @import("../air/lookups/tables/schema.zig");
const Digest = suite.Hasher.Hash;
const Selected = @import("block_v5_committed_projection_columns_v1.zig");
pub const TAG: u32 = 0x42354354; // B5CT

pub const Slot = source.Slot;
const algebra = @import("block_v5_precompile_lookup_algebra_v1.zig");
pub const Claim = algebra.Claim;
pub const Proof = struct {
    stark: suite.Proof,
    claims: []Claim,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        a.free(self.claims);
        self.* = undefined;
    }
};
pub const Receipt = struct { claims: [schema.KIND_COUNT]Q, memory_event_count: u64, register_memory_sum: Q = Q.zero(), auxiliary_clock_memory_sum: Q = Q.zero(), binding: Protocol.CallerBinding };

pub fn ForBackend(comptime Backend: type) type {
    return struct {
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
        pub fn borrowFirstRound(a: std.mem.Allocator, caller: *Family.ForBackend(Backend).FirstRound, binding: Protocol.CallerBinding) !FirstRound {
            if (!caller.owns_scheme or !std.meta.eql(caller.roots, binding.first_roots)) return error.UntrustedV5CallerLookupRoots;
            try Protocol.validate(&caller.witness.statement, caller.total_steps, caller.config);
            try @import("block_v5_precompile_witness_v1.zig").validateAdmission(a, &caller.witness.statement);
            if (!std.meta.eql(caller.config, caller.scheme.config) or
                !std.meta.eql(caller.key_id, binding.caller_key_id) or
                !std.meta.eql(caller.instance_id, binding.caller_instance_id) or
                !std.meta.eql(caller.execution_instance_id, binding.execution_instance_id) or
                caller.index != binding.execution_index or caller.index != binding.caller_entry_index or
                caller.witness.total_steps != caller.total_steps or
                !std.meta.eql(caller.instance_id, Protocol.instanceId(caller.key_id, caller.execution_instance_id, caller.index, caller.roots)) or
                !std.meta.eql(caller.key_id, try Protocol.keyId(&caller.witness.statement, caller.total_steps, caller.config, caller.roots[0])))
                return error.UntrustedV5CallerLookupKey;
            const fixed_logs = try Protocol.columnLogs(a, &caller.witness.statement, .fixed);
            errdefer a.free(fixed_logs);
            const main_logs = try Protocol.columnLogs(a, &caller.witness.statement, .main);
            errdefer a.free(main_logs);
            try Selected.validateTrees(&caller.scheme, fixed_logs, main_logs);
            var channel = suite.Channel{};
            var scheme = try @import("block_v5_shared_first_round_v1.zig").copy(Backend, a, &caller.scheme, &channel);
            errdefer scheme.deinit(a);
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            if (!std.meta.eql(roots.items[0..2].*, binding.first_roots)) return error.UntrustedV5CallerLookupRoots;
            return .{ .scheme = scheme, .roots = binding.first_roots, .fixed_logs = fixed_logs, .main_logs = main_logs };
        }
        pub fn prove(a: std.mem.Allocator, first: *FirstRound, witness: *const @import("block_v5_precompile_witness_v1.zig").Witness, binding: Protocol.CallerBinding, sealed: Seal.Sealed, pins: Seal.Pins, roster: []const Seal.Entry) !Proof {
            return proveFromCommitted(a, first, &witness.statement, witness.total_steps, binding, sealed, pins, roster);
        }
        pub fn proveFromCommitted(a: std.mem.Allocator, first: *FirstRound, statement: *const Profile.admission.Statement, total_steps: u32, binding: Protocol.CallerBinding, sealed: Seal.Sealed, pins: Seal.Pins, roster: []const Seal.Entry) !Proof {
            try Protocol.admit(binding, sealed, pins, roster);
            try Protocol.validate(statement, total_steps, pins.config);
            if (!first.owns_scheme or !std.meta.eql(first.scheme.config, pins.config) or
                !std.meta.eql(first.roots, binding.first_roots) or
                !std.meta.eql(binding.caller_key_id, try Protocol.keyId(statement, total_steps, pins.config, binding.first_roots[0]))) return error.UntrustedV5CallerLookupKey;
            const owner = try source.Owner.init(a);
            defer owner.destroy(a);
            const slots = try owner.slotsForMode(a, statement, sealed.register_custody_mode);
            defer a.free(slots);
            const fixed_logs = try Protocol.columnLogs(a, statement, .fixed);
            defer a.free(fixed_logs);
            const main_logs = try Protocol.columnLogs(a, statement, .main);
            defer a.free(main_logs);
            if (!std.mem.eql(u32, first.fixed_logs, fixed_logs) or !std.mem.eql(u32, first.main_logs, main_logs))
                return error.UntrustedV5CallerLookupGeometry;
            const ranges = try a.alloc(Selected.Range, slots.len);
            defer a.free(ranges);
            for (slots, ranges) |slot, *range| range.* = .{ .fixed_offset = slot.fixed_offset, .fixed_width = slot.fixed_width, .main_offset = slot.main_offset, .main_width = slot.width, .log_size = slot.log_size };
            var columns = try Selected.Columns.init(a, &first.scheme, fixed_logs, main_logs, ranges);
            defer columns.deinit(a);
            return proveProjection(a, first, columns.main, slots, sealed, binding.caller_key_id, binding.caller_instance_id, binding.execution_index, binding.first_roots, columns.fixed, statement);
        }
        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, sealed: Seal.Sealed, pins: Seal.Pins, roster: []const Seal.Entry, fresh: *const Family.OpenReceipt, statement: *const Profile.admission.Statement, total_steps: u32) !Receipt {
            var proof = received;
            var owned = true;
            defer if (owned) proof.deinit(a);
            try Protocol.admit(fresh.binding, sealed, pins, roster);
            try Protocol.validate(statement, total_steps, pins.config);
            if (!std.meta.eql(fresh.binding.caller_key_id, try Protocol.keyId(statement, total_steps, pins.config, fresh.binding.first_roots[0]))) return error.UntrustedV5CallerLookupKey;
            const owner = try source.Owner.init(a);
            defer owner.destroy(a);
            const slots = try owner.slotsForMode(a, statement, sealed.register_custody_mode);
            defer a.free(slots);
            const census = try owner.memoryPairCensus(statement);
            const fixed = try Protocol.columnLogs(a, statement, .fixed);
            defer a.free(fixed);
            const main = try Protocol.columnLogs(a, statement, .main);
            defer a.free(main);
            owned = false;
            const totals = try verifyProjection(a, proof, sealed, fresh.binding.execution_index, fresh.binding.caller_key_id, fresh.binding.caller_instance_id, slots, fixed, main, fresh.binding.first_roots, fresh.binding.first_roots, pins.config, statement);
            return .{ .claims = totals[0..schema.KIND_COUNT].*, .register_memory_sum = totals[@intFromEnum(source.Partition.register_memory)], .memory_event_count = census, .binding = fresh.binding };
        }
        fn proveProjection(a: std.mem.Allocator, first: *FirstRound, main: []const Column, slots: []const Slot, seal: Seal.Sealed, native_key_id: [32]u8, native_instance_id: [32]u8, instance_index: u32, trusted_native_roots: [2]Digest, fixed: []const Column, statement: *const Profile.admission.Statement) !Proof {
            if (!first.owns_scheme or !std.meta.eql(first.roots, trusted_native_roots)) return error.UntrustedV5LookupRequestFirstRound;
            try algebra.validateSlots(slots, main);
            for (slots) |slot| {
                if (slot.fixed_offset + slot.fixed_width > fixed.len) return error.InvalidV5CallerLookupSlot;
                for (fixed[slot.fixed_offset..][0..slot.fixed_width]) |column| if (column.log_size != slot.log_size or column.values.len != slot.n_rows) return error.InvalidV5CallerLookupSlot;
            }
            const relations = try Protocol.drawRelations(a, seal);
            const source_owner = try source.Owner.init(a);
            defer source_owner.destroy(a);
            _ = try source_owner.memoryPairCensus(statement);
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
            const main_open_mask = try algebra.openMask(a, first.main_logs.len, slots);
            defer a.free(main_open_mask);
            const fixed_open_mask = try algebra.fixedMask(a, first.fixed_logs.len, slots);
            defer a.free(fixed_open_mask);
            for (slots, claims, components, handles, 0..) |slot, *claim, *component, *handle, index| {
                try interactions.ensureUnusedCapacity(a, 4);
                const generated = try algebra.generate(a, fixed, main, slot, &relations, source_owner);
                claim.* = .{ .sum = generated.claim, .row_count = slot.n_rows };
                for (generated.columns, 0..) |values, limb| {
                    interactions.appendAssumeCapacity(.{ .log_size = slot.log_size, .values = values });
                    interaction_logs[4 * index + limb] = slot.log_size;
                }
                component.* = try (adapter.Component{ .slot = slot, .fixed_logs = first.fixed_logs, .main_logs = first.main_logs, .root_owner = index == 0, .main_open_mask = main_open_mask, .interaction_offset = 4 * index, .interaction_logs = interaction_logs, .claim = claim.sum, .relations = &relations, .source_owner = source_owner, .fixed_open_mask = fixed_open_mask, .composition_split = algebra.compositionSplit(slots) }).init();
                handle.* = component.asProverComponent();
            }
            var channel = algebra.proofChannel(seal);
            algebra.mixClaims(&channel, native_key_id, native_instance_id, instance_index, slots, claims);
            try first.scheme.commitBorrowedStreaming(a, interactions.items, 8, &channel);
            first.owns_scheme = false;
            return .{ .stark = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, handles, &channel, first.scheme), .claims = claims };
        }
        fn verifyProjection(a: std.mem.Allocator, received: Proof, seal: Seal.Sealed, instance_index: u32, native_key_id: [32]u8, native_instance_id: [32]u8, slots: []const Slot, fixed_logs: []const u32, main_logs: []const u32, trusted_native_roots: [2]Digest, pinned_request_roots: [2]Digest, config: core.pcs.PcsConfig, statement: *const Profile.admission.Statement) ![source.PARTITION_COUNT]Q {
            var proof = received;
            var owns = true;
            defer if (owns) proof.deinit(a);
            defer if (!owns) a.free(proof.claims);
            if (slots.len == 0 or proof.claims.len != slots.len or !std.meta.eql(trusted_native_roots, pinned_request_roots) or
                !std.meta.eql(proof.stark.commitment_scheme_proof.config, config)) return error.InvalidV5LookupRequestProof;
            const roots = proof.stark.commitment_scheme_proof.commitments.items;
            if (roots.len != 4 or !std.meta.eql(roots[0..2].*, trusted_native_roots)) return error.UntrustedV5LookupRequestFirstRound;
            var channel = algebra.firstChannel(native_key_id, native_instance_id, instance_index, slots);
            var verifier = try Verifier.init(a, config);
            defer verifier.deinit(a);
            try verifier.commit(a, roots[0], fixed_logs, &channel);
            try verifier.commit(a, roots[1], main_logs, &channel);
            const relations = try Protocol.drawRelations(a, seal);
            const source_owner = try source.Owner.init(a);
            defer source_owner.destroy(a);
            _ = try source_owner.memoryPairCensus(statement);
            channel = algebra.proofChannel(seal);
            algebra.mixClaims(&channel, native_key_id, native_instance_id, instance_index, slots, proof.claims);
            const interaction_logs = try a.alloc(u32, slots.len * 4);
            defer a.free(interaction_logs);
            const main_open_mask = try algebra.openMask(a, main_logs.len, slots);
            defer a.free(main_open_mask);
            const fixed_open_mask = try algebra.fixedMask(a, fixed_logs.len, slots);
            defer a.free(fixed_open_mask);
            var totals: [source.PARTITION_COUNT]Q = @splat(Q.zero());
            for (slots, proof.claims, 0..) |slot, claim, i| {
                if (claim.row_count != slot.n_rows or slot.main_offset + slot.width > main_logs.len)
                    return error.InvalidV5LookupRequestCensus;
                for (main_logs[slot.main_offset..][0..slot.width]) |log| if (log != slot.log_size) return error.InvalidV5LookupRequestRoster;
                if (slot.fixed_offset + slot.fixed_width > fixed_logs.len) return error.InvalidV5CallerLookupSlot;
                for (fixed_logs[slot.fixed_offset..][0..slot.fixed_width]) |log| if (log != slot.log_size) return error.InvalidV5CallerLookupSlot;
                @memset(interaction_logs[4 * i ..][0..4], slot.log_size);
                totals[@intFromEnum(slot.table)] = totals[@intFromEnum(slot.table)].add(claim.sum);
            }
            try verifier.commit(a, roots[2], interaction_logs, &channel);
            const components = try a.alloc(adapter.Component, slots.len);
            defer a.free(components);
            const handles = try a.alloc(core.air.components.Component, slots.len);
            defer a.free(handles);
            for (slots, proof.claims, components, handles, 0..) |slot, claim, *component, *handle, i| {
                component.* = try (adapter.Component{ .slot = slot, .fixed_logs = fixed_logs, .main_logs = main_logs, .root_owner = i == 0, .main_open_mask = main_open_mask, .interaction_offset = 4 * i, .interaction_logs = interaction_logs, .claim = claim.sum, .relations = &relations, .source_owner = source_owner, .fixed_open_mask = fixed_open_mask, .composition_split = algebra.compositionSplit(slots) }).init();
                handle.* = component.asVerifierComponent();
            }
            owns = false;
            try core.verifier.verify(suite.Hasher, suite.MerkleChannel, a, handles, &channel, &verifier, proof.stark);
            return totals;
        }
    };
}
