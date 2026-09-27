//! Same-native-root program-request PCS sidecar for typed opcode families.
//! Precompile caller program fetches require a companion v5 adapter before
//! this receipt can represent a complete Ethereum-SHA execution segment.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
const opcode = @import("../runner/trace.zig");
const shape = @import("../air/statement.zig");
const relation = @import("../air/lang/relation.zig");
const source = @import("block_v5_program_request_source_v1.zig");
const adapter = @import("block_v5_program_request_component_v1.zig");
const table = @import("block_v5_program_table_proof_v1.zig");
const universal = @import("../recursion/air/universal_challenges.zig");
const framework = @import("../recursion/air/framework_interaction.zig");
const Digest = suite.Hasher.Hash;
pub const TAG: u32 = 0x42355052; // B5PR

pub const Slot = struct { family: opcode.OpcodeFamily, log_size: u32, n_rows: u32, main_offset: usize };
/// The roster ID commits to the independently prepared native key, segment
/// ordinal, and complete typed opcode slot geometry before relation draws.
pub fn instanceId(native_key_id: [32]u8, index: u32, slots: []const Slot) [32]u8 {
    var channel = firstChannel(native_key_id, index, slots);
    return channel.digestBytes();
}
/// The native-v5 execution instance includes its dynamic public authority.
/// Keep the legacy identity unchanged while binding the v5 request roster to
/// both the reusable template and this exact native instance.
pub fn nativeV5InstanceId(template_id: [32]u8, native_instance_id: [32]u8, index: u32, slots: []const Slot) [32]u8 {
    var channel = firstChannel(template_id, index, slots);
    channel.mixU32s(&.{ TAG, 3 });
    channel.mixRoot(native_instance_id);
    return channel.digestBytes();
}
pub fn slotsFromStatement(a: std.mem.Allocator, statement: *const shape.Blake3ExecutionStatement) ![]Slot {
    const result = try a.alloc(Slot, statement.n_components);
    errdefer a.free(result);
    var offset: usize = 0;
    for (statement.component_descs[0..statement.n_components], result) |desc, *slot| {
        if (desc.n_columns != (if (statement.localZeroCustody()) try @import("../air/x0_native_envelope_v1.zig").mainColumnCount(desc.family) else opcode.nColumnsForFamily(desc.family)) or
            desc.log_size > 24 or desc.n_rows > (@as(u32, 1) << @intCast(desc.log_size))) return error.InvalidProgramRequestRoster;
        slot.* = .{ .family = desc.family, .log_size = desc.log_size, .n_rows = desc.n_rows, .main_offset = offset };
        offset += desc.n_columns;
    }
    return result;
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
    native_roots: [2]Digest,
    native_key_id: [32]u8,
    sealed_channel_digest: [32]u8,
    pub fn closureReceipt(self: VerifiedReceipt) table.VerifiedNativeRequest {
        return .{ .claim = self.sum, .fetch_count = self.fetch_count, .sealed_channel_digest = self.sealed_channel_digest };
    }
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
        pub fn commitFirstRound(a: std.mem.Allocator, fixed: []const Column, main: []const Column, slots: []const Slot, native_key_id: [32]u8, instance_index: u32, config: core.pcs.PcsConfig) !FirstRound {
            try validateSlots(slots, main);
            const fixed_logs = try logs(a, fixed);
            errdefer a.free(fixed_logs);
            const main_logs = try logs(a, main);
            errdefer a.free(main_logs);
            var scheme = try Scheme.init(a, config);
            errdefer scheme.deinit(a);
            scheme.setCoefficientRetentionPolicy(.always);
            var channel = firstChannel(native_key_id, instance_index, slots);
            try scheme.commitBorrowedStreaming(a, fixed, 16, &channel);
            try scheme.commitBorrowedStreaming(a, main, 16, &channel);
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            if (roots.items.len != 2) return error.InvalidProgramRequestFirstRound;
            return .{ .scheme = scheme, .roots = roots.items[0..2].*, .fixed_logs = fixed_logs, .main_logs = main_logs };
        }
        /// Source must still own its native first-round scheme. Shared trees
        /// avoid another FFT/LDE/Merkle build; proof authority is unchanged.
        pub fn borrowFirstRound(a: std.mem.Allocator, source_scheme: *Scheme, main: []const Column, slots: []const Slot, native_key_id: [32]u8, instance_index: u32) !FirstRound {
            try validateSlots(slots, main);
            var channel = firstChannel(native_key_id, instance_index, slots);
            var scheme = try @import("block_v5_shared_first_round_v1.zig").copy(Backend, a, source_scheme, &channel);
            errdefer scheme.deinit(a);
            const fixed_logs = try logs(a, scheme.trees.items[0].columns);
            errdefer a.free(fixed_logs);
            const main_logs = try logs(a, scheme.trees.items[1].columns);
            errdefer a.free(main_logs);
            // Committed trees retain LDE evaluations, not trace evaluations.
            // Restore their trace geometry before constructing AIR masks.
            for (fixed_logs) |*log| log.* = std.math.sub(u32, log.*, scheme.config.fri_config.log_blowup_factor) catch return error.InvalidProgramRequestFirstRound;
            for (main_logs) |*log| log.* = std.math.sub(u32, log.*, scheme.config.fri_config.log_blowup_factor) catch return error.InvalidProgramRequestFirstRound;
            var roots = try scheme.roots(a);
            defer roots.deinit(a);
            return .{ .scheme = scheme, .roots = roots.items[0..2].*, .fixed_logs = fixed_logs, .main_logs = main_logs };
        }
        pub fn prove(a: std.mem.Allocator, first: *FirstRound, main: []const Column, slots: []const Slot, seal: table.Seal, native_key_id: [32]u8, instance_index: u32, trusted_native_roots: [2]Digest) !Proof {
            if (!first.owns_scheme or !std.meta.eql(first.roots, trusted_native_roots)) return error.UntrustedProgramRequestFirstRound;
            try validateSlots(slots, main);
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
            const main_open_mask = try openMask(a, first.main_logs.len, slots);
            defer a.free(main_open_mask);
            for (slots, claims, components, handles, 0..) |slot, *claim, *component, *handle, index| {
                try interactions.ensureUnusedCapacity(a, 4);
                const generated = try generate(a, main, slot, &relations);
                claim.* = .{ .sum = generated.claim, .fetch_count = slot.n_rows };
                for (generated.columns, 0..) |values, limb| {
                    interactions.appendAssumeCapacity(.{ .log_size = slot.log_size, .values = values });
                    interaction_logs[4 * index + limb] = slot.log_size;
                }
                component.* = try (adapter.Component{ .family = slot.family, .log_size = slot.log_size, .main_offset = slot.main_offset, .fixed_logs = first.fixed_logs, .main_logs = first.main_logs, .root_owner = index == 0, .main_open_mask = main_open_mask, .interaction_offset = 4 * index, .interaction_logs = interaction_logs, .claim = claim.sum, .relations = &relations }).init();
                handle.* = component.asProverComponent();
            }
            var channel = seal.proofChannel();
            mixClaims(&channel, native_key_id, instance_index, slots, claims);
            try first.scheme.commitBorrowedStreaming(a, interactions.items, 8, &channel);
            first.owns_scheme = false;
            return .{ .stark = try engine.prove.prove(Backend, suite.Hasher, suite.MerkleChannel, a, handles, &channel, first.scheme), .claims = claims };
        }
        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, seal: table.Seal, instance_index: u32, native_key_id: [32]u8, slots: []const Slot, fixed_logs: []const u32, main_logs: []const u32, trusted_native_roots: [2]Digest, pinned_request_roots: [2]Digest, config: core.pcs.PcsConfig) !VerifiedReceipt {
            var proof = received;
            var owns = true;
            defer if (owns) proof.deinit(a);
            defer if (!owns) a.free(proof.claims);
            if (slots.len == 0 or proof.claims.len != slots.len or !std.meta.eql(trusted_native_roots, pinned_request_roots) or
                !std.meta.eql(proof.stark.commitment_scheme_proof.config, config)) return error.InvalidProgramRequestProof;
            const roots = proof.stark.commitment_scheme_proof.commitments.items;
            if (roots.len != 4 or !std.meta.eql(roots[0..2].*, trusted_native_roots)) return error.UntrustedProgramRequestFirstRound;
            var channel = firstChannel(native_key_id, instance_index, slots);
            var verifier = try Verifier.init(a, config);
            defer verifier.deinit(a);
            try verifier.commit(a, roots[0], fixed_logs, &channel);
            try verifier.commit(a, roots[1], main_logs, &channel);
            var relation_channel = seal.sharedChannel();
            const relations = try universal.UniversalRelations.draw(a, &relation_channel);
            channel = seal.proofChannel();
            mixClaims(&channel, native_key_id, instance_index, slots, proof.claims);
            const interaction_logs = try a.alloc(u32, slots.len * 4);
            defer a.free(interaction_logs);
            const main_open_mask = try openMask(a, main_logs.len, slots);
            defer a.free(main_open_mask);
            var total = Q.zero();
            var count: u64 = 0;
            for (slots, proof.claims, 0..) |slot, claim, i| {
                if (claim.fetch_count != slot.n_rows or slot.main_offset + opcode.nColumnsForFamily(slot.family) > main_logs.len)
                    return error.InvalidProgramRequestCensus;
                for (main_logs[slot.main_offset..][0..opcode.nColumnsForFamily(slot.family)]) |log| if (log != slot.log_size) return error.InvalidProgramRequestRoster;
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
                component.* = try (adapter.Component{ .family = slot.family, .log_size = slot.log_size, .main_offset = slot.main_offset, .fixed_logs = fixed_logs, .main_logs = main_logs, .root_owner = i == 0, .main_open_mask = main_open_mask, .interaction_offset = 4 * i, .interaction_logs = interaction_logs, .claim = claim.sum, .relations = &relations }).init();
                handle.* = component.asVerifierComponent();
            }
            var digest_channel = seal.sharedChannel();
            const receipt = VerifiedReceipt{ .sum = total, .fetch_count = count, .native_roots = trusted_native_roots, .native_key_id = native_key_id, .sealed_channel_digest = digest_channel.digestBytes() };
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
    const width = opcode.nColumnsForFamily(slot.family);
    for (0..size) |logical| {
        var row: [opcode.MAX_FAMILY_COLUMNS]Q = undefined;
        const physical = framework.committedRow(logical, slot.log_size);
        for (row[0..width], main[slot.main_offset..][0..width]) |*value, column| value.* = Q.fromBase(column.values[physical]);
        const request = try source.fromCommittedOpcodeMain(Q, slot.family, row[0..width]);
        const denominator = try relations.get(relation.Domain.program_access).combineSecure(&request.tuple);
        terms[logical] = request.numerator.mul(try denominator.inv());
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
    if (slots.len == 0) return error.EmptyProgramRequestRoster;
    for (slots) |slot| {
        const width = opcode.nColumnsForFamily(slot.family);
        if (slot.log_size == 0 or slot.log_size > 24 or slot.n_rows > (@as(u32, 1) << @intCast(slot.log_size)) or
            slot.main_offset + width > main.len) return error.InvalidProgramRequestRoster;
        for (main[slot.main_offset..][0..width]) |column| if (column.log_size != slot.log_size or
            column.values.len != (@as(usize, 1) << @intCast(slot.log_size))) return error.InvalidProgramRequestRoster;
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
        const width = opcode.nColumnsForFamily(slot.family);
        if (slot.main_offset + width > len) return error.InvalidProgramRequestRoster;
        @memset(result[slot.main_offset..][0..width], true);
    }
    return result;
}
fn firstChannel(native_key_id: [32]u8, index: u32, slots: []const Slot) suite.Channel {
    var channel = suite.Channel{};
    channel.mixU32s(&.{ TAG, 1, index, @intCast(slots.len) });
    channel.mixRoot(native_key_id);
    for (slots) |slot| channel.mixU32s(&.{ @intFromEnum(slot.family), slot.log_size, slot.n_rows, @intCast(slot.main_offset) });
    return channel;
}
fn mixClaims(channel: anytype, native_key_id: [32]u8, index: u32, slots: []const Slot, claims: []const Claim) void {
    channel.mixU32s(&.{ TAG, 2, index, @intCast(claims.len) });
    channel.mixRoot(native_key_id);
    for (slots, claims) |slot, claim| {
        channel.mixU32s(&.{ @intFromEnum(slot.family), slot.n_rows });
        channel.mixU64(claim.fetch_count);
        channel.mixFelts(&.{claim.sum});
    }
}
