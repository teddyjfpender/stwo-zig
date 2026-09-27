//! One PCS proof for opcode ROM plus native table/state/register/clock claims.
//! This is a new versioned proof format, not concatenated existing proofs.
//! Fresh native admission is provided by the accompanying receiver module.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
const opcode = @import("../runner/trace.zig");
const source = @import("block_v5_native_projection_fused_source_v1.zig");
const adapter = @import("block_v5_native_projection_fused_component_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const schema = @import("../air/lookups/tables/schema.zig");
const universal = @import("../recursion/air/universal_challenges.zig");
const framework = @import("../recursion/air/framework_interaction.zig");
const Digest = suite.Hasher.Hash;
pub const TAG: u32 = 0x42354650; // B5FP
pub const VERSION: u32 = 1;

pub const Slot = source.Slot;
pub const Claim = struct { sum: Q, row_count: u64 };
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
    program_sum: Q,
    fetch_count: u64,
    claims: [schema.KIND_COUNT]Q,
    registers_state_sum: Q,
    auxiliary_clock_memory_sum: Q,
    register_memory_sum: Q = Q.zero(),
    register_clock_memory_sum: Q = Q.zero(),
    native_roots: [2]Digest,
    native_key_id: [32]u8,
    native_instance_id: [32]u8,
    execution_index: u32,
    sealed_digest: [32]u8,
};

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
        /// Source must still own its native first-round scheme. Shared trees
        /// avoid another FFT/LDE/Merkle build; proof authority is unchanged.
        pub fn borrowFirstRound(a: std.mem.Allocator, source_scheme: *Scheme, main: []const Column, slots: []const Slot, native_key_id: [32]u8, native_instance_id: [32]u8, instance_index: u32) !FirstRound {
            try validateSlots(slots, main);
            var channel = firstChannel(native_key_id, native_instance_id, instance_index, slots);
            var scheme = try @import("block_v5_shared_first_round_v1.zig").copy(Backend, a, source_scheme, &channel);
            errdefer scheme.deinit(a);
            const fixed_logs = try logs(a, scheme.trees.items[0].columns);
            errdefer a.free(fixed_logs);
            const main_logs = try logs(a, scheme.trees.items[1].columns);
            errdefer a.free(main_logs);
            // Committed trees retain LDE evaluations, not trace evaluations.
            // Restore their trace geometry before constructing AIR masks.
            for (fixed_logs) |*log| log.* = std.math.sub(u32, log.*, scheme.config.fri_config.log_blowup_factor) catch return error.InvalidV5FusedProjectionFirstRound;
            for (main_logs) |*log| log.* = std.math.sub(u32, log.*, scheme.config.fri_config.log_blowup_factor) catch return error.InvalidV5FusedProjectionFirstRound;
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            return .{ .scheme = scheme, .roots = roots.items[0..2].*, .fixed_logs = fixed_logs, .main_logs = main_logs };
        }
        pub fn prove(a: std.mem.Allocator, first: *FirstRound, main: []const Column, slots: []const Slot, seal: Seal.Sealed, native_key_id: [32]u8, native_instance_id: [32]u8, instance_index: u32, trusted_native_roots: [2]Digest) !Proof {
            for (slots) |slot| if (slot.register_custody_mode != seal.register_custody_mode) return error.UntrustedV5RegisterProjectionMode;
            if (!first.owns_scheme or !std.meta.eql(first.roots, trusted_native_roots)) return error.UntrustedV5FusedProjectionFirstRound;
            try validateSlots(slots, main);
            var relation_channel = seal.sharedChannel();
            const relations = try universal.UniversalRelations.draw(a, &relation_channel);
            const claims = try a.alloc(Claim, slots.len);
            errdefer a.free(claims);
            var quotient_cache = try @import("block_v5_quotient_column_cache_v1.zig").Cache.init(a);
            defer quotient_cache.deinit();
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
            const main_open_mask = try openMask(a, first.main_logs.len, slots);
            defer a.free(main_open_mask);
            for (slots, claims, components, handles, 0..) |slot, *claim, *component, *handle, index| {
                try interactions.ensureUnusedCapacity(a, 4);
                const generated = try generate(a, main, slot, &relations);
                claim.* = .{ .sum = generated.claim, .row_count = slot.n_rows };
                for (generated.columns, 0..) |values, limb| {
                    interactions.appendAssumeCapacity(.{ .log_size = slot.log_size, .values = values });
                    interaction_logs[4 * index + limb] = slot.log_size;
                }
                component.* = try (adapter.Component{ .quotient_cache = &quotient_cache, .slot = slot, .fixed_logs = first.fixed_logs, .main_logs = first.main_logs, .root_owner = index == 0, .main_open_mask = main_open_mask, .interaction_offset = 4 * index, .interaction_logs = interaction_logs, .claim = claim.sum, .relations = &relations, .composition_split = compositionSplit(slots) }).init();
                handle.* = component.asProverComponent();
            }
            var channel = proofChannel(seal);
            mixClaims(&channel, native_key_id, native_instance_id, instance_index, slots, claims);
            try first.scheme.commitBorrowedStreaming(a, interactions.items, 8, &channel);
            first.owns_scheme = false;
            return .{ .stark = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, handles, &channel, first.scheme), .claims = claims };
        }
        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, seal: Seal.Sealed, instance_index: u32, native_key_id: [32]u8, native_instance_id: [32]u8, slots: []const Slot, fixed_logs: []const u32, main_logs: []const u32, trusted_native_roots: [2]Digest, pinned_request_roots: [2]Digest, config: core.pcs.PcsConfig) !VerifiedReceipt {
            var proof = received;
            var owns = true;
            defer if (owns) proof.deinit(a);
            defer if (!owns) a.free(proof.claims);
            if (slots.len == 0 or proof.claims.len != slots.len or !std.meta.eql(trusted_native_roots, pinned_request_roots) or
                !std.meta.eql(proof.stark.commitment_scheme_proof.config, config)) return error.InvalidV5FusedProjectionProof;
            for (slots) |slot| if (slot.register_custody_mode != seal.register_custody_mode) return error.UntrustedV5RegisterProjectionMode;
            const roots = proof.stark.commitment_scheme_proof.commitments.items;
            if (roots.len != 4 or !std.meta.eql(roots[0..2].*, trusted_native_roots)) return error.UntrustedV5FusedProjectionFirstRound;
            var channel = firstChannel(native_key_id, native_instance_id, instance_index, slots);
            var verifier = try Verifier.init(a, config);
            defer verifier.deinit(a);
            try verifier.commit(a, roots[0], fixed_logs, &channel);
            try verifier.commit(a, roots[1], main_logs, &channel);
            var relation_channel = seal.sharedChannel();
            const relations = try universal.UniversalRelations.draw(a, &relation_channel);
            channel = proofChannel(seal);
            mixClaims(&channel, native_key_id, native_instance_id, instance_index, slots, proof.claims);
            const interaction_logs = try a.alloc(u32, slots.len * 4);
            defer a.free(interaction_logs);
            const main_open_mask = try openMask(a, main_logs.len, slots);
            defer a.free(main_open_mask);
            var totals: [source.PARTITION_COUNT]Q = @splat(Q.zero());
            var program_sum = Q.zero();
            var fetch_count: u64 = 0;
            for (slots, proof.claims, 0..) |slot, claim, i| {
                if (claim.row_count != slot.n_rows or slot.main_offset + slot.width > main_logs.len)
                    return error.InvalidV5FusedProjectionCensus;
                for (main_logs[slot.main_offset..][0..slot.width]) |log| if (log != slot.log_size) return error.InvalidV5FusedProjectionRoster;
                @memset(interaction_logs[4 * i ..][0..4], slot.log_size);
                switch (slot.kind) {
                    .program => {
                        program_sum = program_sum.add(claim.sum);
                        fetch_count = try std.math.add(u64, fetch_count, claim.row_count);
                    },
                    .lookup => |lookup| totals[@intFromEnum(lookup.partition)] = totals[@intFromEnum(lookup.partition)].add(claim.sum),
                }
            }
            try verifier.commit(a, roots[2], interaction_logs, &channel);
            const components = try a.alloc(adapter.Component, slots.len);
            defer a.free(components);
            const handles = try a.alloc(core.air.components.Component, slots.len);
            defer a.free(handles);
            for (slots, proof.claims, components, handles, 0..) |slot, claim, *component, *handle, i| {
                component.* = try (adapter.Component{ .slot = slot, .fixed_logs = fixed_logs, .main_logs = main_logs, .root_owner = i == 0, .main_open_mask = main_open_mask, .interaction_offset = 4 * i, .interaction_logs = interaction_logs, .claim = claim.sum, .relations = &relations, .composition_split = compositionSplit(slots) }).init();
                handle.* = component.asVerifierComponent();
            }
            const receipt = VerifiedReceipt{ .program_sum = program_sum, .fetch_count = fetch_count, .claims = totals[0..schema.KIND_COUNT].*, .registers_state_sum = totals[@intFromEnum(source.Partition.registers_state)], .auxiliary_clock_memory_sum = totals[@intFromEnum(source.Partition.clock_memory_access)], .register_memory_sum = totals[@intFromEnum(source.Partition.register_memory_access)], .register_clock_memory_sum = totals[@intFromEnum(source.Partition.register_clock_memory_access)], .native_roots = trusted_native_roots, .native_key_id = native_key_id, .native_instance_id = native_instance_id, .execution_index = instance_index, .sealed_digest = seal.digest };
            owns = false;
            try core.verifier.verify(suite.Hasher, suite.MerkleChannel, a, handles, &channel, &verifier, proof.stark);
            return receipt;
        }
    };
}

const Generated = struct { columns: [4][]M, claim: Q };
fn generate(a: std.mem.Allocator, main: []const Column, slot: Slot, relations: *const universal.UniversalRelations) !Generated {
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
    const width = slot.width;
    for (0..size) |logical| {
        var row: [opcode.MAX_FAMILY_COLUMNS]Q = undefined;
        const physical = framework.committedRow(logical, slot.log_size);
        for (row[0..width], main[slot.main_offset..][0..width]) |*value, column| value.* = Q.fromBase(column.values[physical]);
        const request = try source.fromCommittedMain(slot, row[0..width], relations);
        terms[logical] = request.numerator().mul(try request.denominator().inv());
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
fn validateSlots(slots: []const Slot, main: []const Column) !void {
    if (slots.len == 0) return error.EmptyV5FusedProjectionRoster;
    for (slots) |slot| {
        const width = slot.width;
        if (slot.log_size == 0 or slot.log_size > 24 or slot.n_rows > (@as(u32, 1) << @intCast(slot.log_size)) or
            slot.main_offset + width > main.len) return error.InvalidV5FusedProjectionRoster;
        for (main[slot.main_offset..][0..width]) |column| if (column.log_size != slot.log_size or
            column.values.len != (@as(usize, 1) << @intCast(slot.log_size))) return error.InvalidV5FusedProjectionRoster;
    }
}
fn logs(a: std.mem.Allocator, columns: []const Column) ![]u32 {
    const result = try a.alloc(u32, columns.len);
    for (columns, result) |column, *log| log.* = column.log_size;
    return result;
}
fn openMask(a: std.mem.Allocator, len: usize, slots: []const Slot) ![]bool {
    const result = try a.alloc(bool, len);
    errdefer a.free(result);
    @memset(result, false);
    for (slots) |slot| {
        const width = slot.width;
        if (slot.main_offset + width > len) return error.InvalidV5FusedProjectionRoster;
        @memset(result[slot.main_offset..][0..width], true);
    }
    return result;
}
fn firstChannel(native_key_id: [32]u8, native_instance_id: [32]u8, index: u32, slots: []const Slot) suite.Channel {
    var channel = suite.Channel{};
    channel.mixU32s(&.{ TAG, VERSION, 1, index, @intCast(slots.len) });
    channel.mixRoot(native_key_id);
    channel.mixRoot(native_instance_id);
    for (slots) |slot| source.mixSlot(&channel, slot);
    return channel;
}
fn mixClaims(channel: anytype, native_key_id: [32]u8, native_instance_id: [32]u8, index: u32, slots: []const Slot, claims: []const Claim) void {
    channel.mixU32s(&.{ TAG, VERSION, 2, index, @intCast(claims.len) });
    channel.mixRoot(native_key_id);
    channel.mixRoot(native_instance_id);
    for (slots, claims) |slot, claim| {
        source.mixSlot(channel, slot);
        channel.mixU64(claim.row_count);
        channel.mixFelts(&.{claim.sum});
    }
}

fn proofChannel(sealed: Seal.Sealed) suite.Channel {
    var channel = suite.Channel{};
    channel.mixU32s(&.{ TAG, VERSION, 3 });
    channel.mixRoot(sealed.digest);
    return channel;
}

/// PCS composition chunks use one split for every component in this proof.
/// The maximum is derived from the independently reconstructed slot degrees.
fn compositionSplit(slots: []const Slot) u32 {
    var split: u32 = 2;
    for (slots) |slot| split = @max(split, std.math.log2_int_ceil(u32, slot.degree));
    return split;
}
