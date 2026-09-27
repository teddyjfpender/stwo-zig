//! A single PCS/STARK for native projections AND packed ordinary access.
//! Four trace trees: fixed, main, source-sealed access witness, interaction.
//! The capacity-native base AIR remains independently freshly verified. This module
//! emits separate open bus receipts, never complete block authority.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const suite = core.proof_suites.Blake3;
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Column = engine.pcs.ColumnEvaluation;
const Digest = suite.Hasher.Hash;
const Source = @import("block_v5_native_capacity_fused_source_v1.zig");
const Projection = @import("block_v5_native_projection_fused_proof_v1.zig");
const Adapter = @import("block_v5_native_capacity_fused_component_v1.zig");
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
const Catalog = @import("block_v5_native_capacity_catalog_v1.zig");
const Native = @import("block_v5_native_capacity_proof_v1.zig");
const Template = @import("block_v5_native_capacity_protocol_v1.zig");
const Opcode = @import("../runner/trace.zig");
const Framework = @import("../recursion/air/framework_interaction.zig");
const Canonical = @import("../recursion/air/universal_provider_relations.zig");
const Schema = @import("../air/lookups/tables/schema.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Frame = @import("../air/block/memory_event.zig").Frame;

pub const TAG: u32 = 0x42354346; // B5CF, distinct from exact-row B5FP
pub const VERSION: u32 = 1;
pub const Claim = Projection.Claim;
pub const ProjectionReceipt = struct {
    program_sum: Q,
    fetch_count: u64,
    claims: [Schema.KIND_COUNT]Q,
    registers_state_sum: Q,
    auxiliary_clock_memory_sum: Q,
    register_memory_sum: Q,
    register_clock_memory_sum: Q,
    native_roots: Seal.Roots,
    native_key_id: Digest,
    native_instance_id: Digest,
    execution_index: u32,
    sealed_digest: Digest,
};
pub const Limits = struct {
    native: Native.Limits = .{},
    max_projection_slots: usize = 32768,
    max_memory_slots: usize = 4096,
    max_interaction_cells: usize = 1 << 29,
    max_witness_cells: usize = 1 << 29,
    max_metadata_bytes: usize = 64 << 20,
    pub fn requireShape(self: Limits, shape: *const Shape, external: u32) !void {
        const plan = try Template.Plan.fromShape(shape, external);
        try self.native.require(&plan, shape);
    }
    pub fn require(self: Limits, shape: *const Shape, external: u32, projections: []const Source.Slot, memory: []const Memory.Slot) !void {
        try self.requireShape(shape, external);
        if (projections.len > self.max_projection_slots or memory.len > self.max_memory_slots) return error.CapacityFusedResourceLimit;
        const metadata = try std.math.add(usize, try std.math.mul(usize, projections.len, @sizeOf(Source.Slot) + @sizeOf(Claim) + @sizeOf(Adapter.ProjectionComponent)), try std.math.mul(usize, memory.len, @sizeOf(Memory.Slot) + @sizeOf(Memory.Claim) + @sizeOf(Adapter.AccessComponent)));
        if (metadata > self.max_metadata_bytes) return error.CapacityFusedResourceLimit;
        var interaction_cells: usize = 0;
        var witness_cells: usize = 0;
        for (projections) |slot| {
            _ = try Source.binding(shape, external, slot.main_offset, slot.log_size, slot.n_rows);
            interaction_cells = try std.math.add(usize, interaction_cells, try std.math.mul(usize, 4, @as(usize, 1) << @intCast(slot.log_size)));
        }
        for (memory) |slot| {
            _ = try Source.binding(shape, external, slot.main_offset, slot.log_size, null);
            interaction_cells = try std.math.add(usize, interaction_cells, try std.math.mul(usize, Eval.INTERACTION_COUNT, @as(usize, 1) << @intCast(slot.log_size)));
            witness_cells = try std.math.add(usize, witness_cells, try std.math.mul(usize, Integer.COLUMN_COUNT, @as(usize, 1) << @intCast(slot.log_size)));
        }
        if (interaction_cells > self.max_interaction_cells or witness_cells > self.max_witness_cells) return error.CapacityFusedResourceLimit;
    }
};
pub const Proof = struct {
    stark: suite.Proof,
    claims: []Claim,
    memory_claims: []Memory.Claim,
    protocol_version: u32 = VERSION,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.stark.deinit(a);
        a.free(self.claims);
        a.free(self.memory_claims);
        self.* = undefined;
    }
};
pub const Verified = struct {
    projections: ?ProjectionReceipt,
    memory: ?Memory.Verified,
    pub fn deinit(self: *Verified, a: std.mem.Allocator) void {
        if (self.memory) |*memory| memory.deinit(a);
        self.* = undefined;
    }
};

/// Independently supplied policy for this scoped fused verifier. `native`
/// must be the just-verified B5CT result from the enclosing receiver; this
/// descriptor cannot turn a transported native receipt into proof authority.
pub const CaptureAdmission = struct {
    sealed: Seal.Sealed,
    pins: Seal.Pins,
    entries: []const Seal.Entry,
    native: *const Native.OpenReceipt,
    index: u32,
    frame: Frame,
    projections: []const Source.Slot,
    slots: []const Memory.Slot,
    fixed_logs: []const u32,
    main_logs: []const u32,
    witness_root: Digest,
    empty_entry: ?Seal.Entry,
    shape: *const Shape,
    external_retirements: u32,
    limits: Limits,
    pub fn require(self: CaptureAdmission, a: std.mem.Allocator) !void {
        try self.limits.require(self.shape, self.external_retirements, self.projections, self.slots);
        try Source.requireLogs(self.shape, self.external_retirements, self.fixed_logs, self.main_logs);
        const canonical = try Source.slotsFromShapeForMode(a, self.shape, self.external_retirements, self.sealed.register_custody_mode);
        defer a.free(canonical);
        try requireProjectionRoster(self.projections, canonical);
        const memory_slots = try Source.memorySlots(a, self.shape, self.external_retirements, self.frame, self.sealed.register_custody_mode);
        defer a.free(memory_slots);
        if (memory_slots.len != self.slots.len) return error.InvalidV5FullFusedRoster;
        for (memory_slots, self.slots) |actual, expected| if (!std.meta.eql(actual, expected)) return error.InvalidV5FullFusedRoster;
        if (!std.meta.eql(self.native.exact_geometry_digest, try @import("block_v5_native_template_protocol_v3.zig").geometryDigest(self.shape, self.external_retirements))) return error.UntrustedCapacityFusedExactGeometry;
        if (!std.meta.eql(self.native.sealed_digest, self.sealed.digest)) return error.UntrustedV5FullFusedNativeSeal;
        try admit(self.sealed, self.pins, self.entries, self.index, self.native.template_id, self.native.instance_id, self.native.first_roots, self.witness_root, self.frame, self.projections, self.slots, self.empty_entry);
        try validateRoster(self.projections, self.slots, self.main_logs, self.sealed.register_custody_mode);
    }
};

/// Deep-owned claim and inventory custody, not a proof verification result.
/// No trace columns, public IO arrays, source shape or policy pointers survive.
pub const CaptureMetadata = struct {
    allocator: std.mem.Allocator,
    claims: []Claim,
    memory_claims: []Memory.Claim,
    projections: []Source.Slot,
    slots: []Memory.Slot,
    logs: [4][]u32,
    native: Native.OpenReceipt,
    sealed: Seal.Sealed,
    config: core.pcs.PcsConfig,
    index: u32,
    frame: Frame,
    witness_root: Digest,
    pub fn init(a: std.mem.Allocator, policy: CaptureAdmission, claims: []const Claim, memory_claims: []const Memory.Claim, witness_logs: []const u32, interaction_logs: []const u32) !CaptureMetadata {
        if (claims.len != policy.projections.len or memory_claims.len != policy.slots.len) return error.InvalidV5FullFusedClaims;
        var bytes = try std.math.mul(usize, claims.len, @sizeOf(Claim) + @sizeOf(Source.Slot));
        bytes = try std.math.add(usize, bytes, try std.math.mul(usize, memory_claims.len, @sizeOf(Memory.Claim) + @sizeOf(Memory.Slot)));
        const borrowed = [4][]const u32{ policy.fixed_logs, policy.main_logs, witness_logs, interaction_logs };
        for (borrowed) |column_logs| bytes = try std.math.add(usize, bytes, try std.math.mul(usize, column_logs.len, @sizeOf(u32)));
        if (bytes > policy.limits.max_metadata_bytes) return error.CapacityFusedResourceLimit;
        const copied_claims = try a.dupe(Claim, claims);
        errdefer a.free(copied_claims);
        const copied_memory = try a.dupe(Memory.Claim, memory_claims);
        errdefer a.free(copied_memory);
        const projections = try a.dupe(Source.Slot, policy.projections);
        errdefer a.free(projections);
        const slots = try a.dupe(Memory.Slot, policy.slots);
        errdefer a.free(slots);
        var logs: [4][]u32 = undefined;
        var initialized: usize = 0;
        errdefer for (logs[0..initialized]) |column_logs| a.free(column_logs);
        for (&logs, borrowed) |*destination, column_logs| {
            destination.* = try a.dupe(u32, column_logs);
            initialized += 1;
        }
        return .{ .allocator = a, .claims = copied_claims, .memory_claims = copied_memory, .projections = projections, .slots = slots, .logs = logs, .native = policy.native.*, .sealed = policy.sealed, .config = policy.pins.config, .index = policy.index, .frame = policy.frame, .witness_root = policy.witness_root };
    }
    pub fn deinit(self: *CaptureMetadata) void {
        self.allocator.free(self.claims);
        self.allocator.free(self.memory_claims);
        self.allocator.free(self.projections);
        self.allocator.free(self.slots);
        for (self.logs) |column_logs| self.allocator.free(column_logs);
        self.* = undefined;
    }
    pub fn require(self: *const CaptureMetadata, policy: CaptureAdmission) !void {
        if (self.claims.len != self.projections.len or self.memory_claims.len != self.slots.len) return error.InvalidV5FullFusedClaims;
        if (!std.meta.eql(self.native, policy.native.*) or !std.meta.eql(self.sealed, policy.sealed) or
            !std.meta.eql(self.config, policy.pins.config) or self.index != policy.index or
            !std.meta.eql(self.frame, policy.frame) or !std.meta.eql(self.witness_root, policy.witness_root)) return error.InvalidCapacityFusedCapturePolicy;
        try requireProjectionRoster(self.projections, policy.projections);
        if (self.slots.len != policy.slots.len) return error.InvalidCapacityFusedCapturePolicy;
        for (self.slots, policy.slots) |actual, expected| if (!std.meta.eql(actual, expected)) return error.InvalidCapacityFusedCapturePolicy;
        if (!std.mem.eql(u32, self.logs[0], policy.fixed_logs) or
            !std.mem.eql(u32, self.logs[1], policy.main_logs)) return error.InvalidCapacityFusedCapturePolicy;
        const witness = try witnessLogs(self.allocator, policy.slots);
        defer self.allocator.free(witness);
        const interactions = try interactionLogs(self.allocator, policy.projections, policy.slots);
        defer self.allocator.free(interactions);
        if (!std.mem.eql(u32, self.logs[2], witness) or !std.mem.eql(u32, self.logs[3], interactions)) return error.InvalidCapacityFusedCapturePolicy;
    }
    pub fn identity(self: *const CaptureMetadata) !Digest {
        var channel = firstChannel(self.native.template_id, self.native.instance_id, self.index, self.projections, self.slots);
        channel.mixU32s(&.{ 0x42354643, 1, @intFromEnum(self.frame.clock_frame), self.frame.cycle_count, self.sealed.register_custody_mode }); // B5FC
        channel.mixU64(self.frame.global_first_cycle);
        channel.mixRoot(self.native.exact_geometry_digest);
        channel.mixRoot(self.native.sealed_digest);
        channel.mixFelts(&.{self.native.open_sum});
        for (self.native.first_roots) |root| channel.mixRoot(root);
        channel.mixRoot(self.witness_root);
        self.config.mixInto(&channel);
        for (self.logs) |column_logs| {
            channel.mixU64(column_logs.len);
            channel.mixU32s(column_logs);
        }
        try mixClaims(&channel, self.native.template_id, self.native.instance_id, self.index, self.projections, self.slots, self.claims, self.memory_claims);
        return channel.digestBytes();
    }
};

/// Only the successful genuine verifier publishes this owner. The mutation
/// seal protects capture custody; later recursion must constrain the actual
/// verifier equations, not accept this seal or exports as scalar authority.
pub const VerifiedCapture = struct {
    allocator: std.mem.Allocator,
    proof: core.verifier.ProofCapture(suite.Hasher),
    metadata: CaptureMetadata,
    word_challenges: Word.Challenges,
    challenges: Bus.Challenges,
    final_channel: suite.Channel,
    verified: Verified,
    seal: Digest,
    pub fn deinit(self: *VerifiedCapture) void {
        self.proof.deinit(self.allocator);
        self.verified.deinit(self.allocator);
        self.metadata.deinit();
        self.* = undefined;
    }
    pub fn identity(self: *const VerifiedCapture) !Digest {
        var channel = suite.Channel{};
        channel.mixU32s(&.{ 0x42354652, VERSION }); // B5FR
        channel.mixRoot(try self.metadata.identity());
        channel.mixRoot(@import("proof_capture_sha256.zig").compute(&self.proof));
        inline for (.{ self.word_challenges.transition, self.word_challenges.link, self.word_challenges.initial, self.word_challenges.endpoint, self.word_challenges.range16, self.challenges.transition, self.challenges.link, self.challenges.initial }) |element| channel.mixFelts(&.{ element.z, element.alpha });
        for (self.word_challenges.universal_prefix.elements) |element| channel.mixFelts(&.{ element.z, element.alpha });
        for (self.challenges.universal_prefix.elements) |element| channel.mixFelts(&.{ element.z, element.alpha });
        channel.mixRoot(self.final_channel.digestBytes());
        channel.mixU64(self.final_channel.n_draws);
        return channel.digestBytes();
    }
    pub fn validate(self: *const VerifiedCapture, policy: CaptureAdmission) !void {
        try policy.require(self.allocator);
        try self.metadata.require(policy);
        if (!std.meta.eql(self.word_challenges, try Word.Challenges.draw(self.allocator, policy.sealed)) or
            !std.meta.eql(self.challenges, try Bus.Challenges.draw(self.allocator, policy.sealed))) return error.InvalidCapacityFusedCaptureChallenges;
        const accesses = self.metadata.slots.len != 0;
        if (self.proof.commitments.len != (if (accesses) @as(usize, 5) else 4) or
            !std.meta.eql(self.proof.commitments[0..2].*, policy.native.first_roots) or
            (accesses and !std.meta.eql(self.proof.commitments[2], policy.witness_root))) return error.InvalidCapacityFusedCaptureRoots;
        const trace_count: usize = if (accesses) 4 else 3;
        if (self.proof.column_log_sizes.len != trace_count + 1) return error.InvalidCapacityFusedCaptureGeometry;
        for (self.proof.column_log_sizes[0..trace_count], 0..) |column_logs, i| {
            const original: usize = if (!accesses and i == 2) 3 else i;
            const source_logs = self.metadata.logs[original];
            if (column_logs.len != source_logs.len) return error.InvalidCapacityFusedCaptureGeometry;
            for (column_logs, source_logs) |extended, log| if (extended != try std.math.add(u32, log, policy.pins.config.fri_config.log_blowup_factor)) return error.InvalidCapacityFusedCaptureGeometry;
        }
        var expected = try receipts(self.allocator, self.metadata.claims, self.metadata.memory_claims, self.metadata.projections, &self.metadata.native, self.metadata.witness_root, self.metadata.index, self.metadata.sealed);
        defer expected.deinit(self.allocator);
        if (!sameVerified(self.verified, expected) or !std.meta.eql(self.seal, try self.identity())) return error.InvalidCapacityFusedRecursiveCapture;
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
pub fn mainMask(a: std.mem.Allocator, count: usize, projections: []const Source.Slot, slots: []const Memory.Slot, shape: *const Shape, external: u32) ![]bool {
    const plan = try Template.Plan.fromShape(shape, external);
    if (count != plan.mainCount()) return error.InvalidCapacityFusedColumnRoster;
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
    for (plan.active()) |shard| mask[shard.main_index] = true;
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
        pub fn proveForNativeFirstRound(a: std.mem.Allocator, first: *FirstRound, inputs: []const Memory.Input, slots: []const Memory.Slot, projections: []const Source.Slot, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, catalog: Catalog.Admission, native: *Native.ForBackend(Backend).FirstRound, index: u32, frame: Frame, witness_root: Digest, limits: Limits) !Proof {
            try limits.requireShape(&native.source.statement, native.source.external_retirements);
            if (!native.owns_scheme or native.index != index or !native.source.native_only_v5 or native.source.failed or
                !native.source.tables_ready or native.source.interaction_ready or native.scheme.trees.items.len != 2 or
                !std.meta.eql(native.scheme.config, pins.config)) return error.UntrustedV5FullFusedNativePhase;
            try native.pin.require(pins, &native.source.statement.public_data);
            try native.template.admit(&native.source.statement, native.source.external_retirements, native.template_id);
            try catalog.admit(pins, sealed, index, native.template, native.template_id);
            if (!std.meta.eql(native.instance_id, try Template.instanceId(native.template_id, &native.source.statement, native.source.external_retirements, native.pin, native.roots, index)))
                return error.UntrustedV5FullFusedNativePhase;
            var actual_native_roots = try native.scheme.roots(a);
            defer actual_native_roots.deinit(a);
            if (actual_native_roots.items.len != 2 or !std.meta.eql(actual_native_roots.items[0..2].*, native.roots) or
                !std.meta.eql(first.scheme.config, pins.config)) return error.UntrustedV5FullFusedNativePhase;
            const fixed_logs = try Template.columnLogs(a, &native.source.statement, native.source.external_retirements, .fixed);
            defer a.free(fixed_logs);
            const main_logs = try Template.columnLogs(a, &native.source.statement, native.source.external_retirements, .main);
            defer a.free(main_logs);
            if (!std.mem.eql(u32, fixed_logs, first.fixed_logs) or !std.mem.eql(u32, main_logs, first.main_logs)) return error.UntrustedV5FullFusedNativePhase;
            const canonical = try Source.slotsFromShapeForMode(a, &native.source.statement, native.source.external_retirements, sealed.register_custody_mode);
            defer a.free(canonical);
            try requireProjectionRoster(projections, canonical);
            const memory_slots = try Source.memorySlots(a, &native.source.statement, native.source.external_retirements, frame, sealed.register_custody_mode);
            defer a.free(memory_slots);
            if (memory_slots.len != slots.len) return error.InvalidV5FullFusedRoster;
            for (memory_slots, slots) |actual, expected| if (!std.meta.eql(actual, expected)) return error.InvalidV5FullFusedRoster;
            if (frame.clock_frame != .leaf_local or frame.global_first_cycle != native.pin.context.first_cycle or frame.cycle_count != native.source.statement.public_data.clock)
                return error.UntrustedV5FullFusedNativePhase;
            try Native.admitWithCatalog(a, &native.source.statement, native.source.external_retirements, native.pin, native.template, native.template_id, native.instance_id, native.roots, index, sealed, pins, entries, catalog);
            const empty_entry: ?Seal.Entry = if (slots.len == 0) try Source.emptyEntry(a, &native.source.statement, native.source.external_retirements, frame, native.entry(), 0, sealed.register_custody_mode) else null;
            try admit(sealed, pins, entries, index, native.template_id, native.instance_id, native.roots, witness_root, frame, projections, slots, empty_entry);
            return proveBound(a, first, native.source.main.items, inputs, slots, projections, sealed, native.template_id, native.instance_id, index, witness_root, native.roots, &native.source.statement, native.source.external_retirements, limits);
        }

        fn proveBound(a: std.mem.Allocator, first: *FirstRound, main: []const Column, inputs: []const Memory.Input, slots: []const Memory.Slot, projections: []const Source.Slot, sealed: Seal.Sealed, template: Digest, native: Digest, index: u32, witness_root: Digest, roots: [2]Digest, shape: *const Shape, external: u32, limits: Limits) !Proof {
            try limits.require(shape, external, projections, slots);
            try Source.requireLogs(shape, external, first.fixed_logs, first.main_logs);
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
            const mask = try mainMask(a, first.main_logs.len, projections, slots, shape, external);
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
                component.* = try (Adapter.ProjectionComponent{ .binding = try Source.binding(shape, external, slot.main_offset, slot.log_size, slot.n_rows), .inner = .{ .has_access_witness = slots.len != 0, .inner = .{ .quotient_cache = &cache, .slot = slot, .fixed_logs = first.fixed_logs, .main_logs = first.main_logs, .root_owner = i == 0, .main_open_mask = mask, .interaction_offset = 4 * i, .interaction_logs = logs, .claim = claim.sum, .relations = relations, .composition_split = compositionSplit(projections) } } }).init();
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
                component.* = try accessComponent(input.descriptor, i, projections.len, first.fixed_logs, first.main_logs, witness_logs, logs, claim.*, &challenges, &word_challenges, compositionSplit(projections), sealed.register_custody_mode, try Source.binding(shape, external, input.descriptor.main_offset, input.descriptor.log_size, null));
                component.inner.inner.quotient_cache = &cache;
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
        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, native: *const Native.OpenReceipt, index: u32, frame: Frame, projections: []const Source.Slot, slots: []const Memory.Slot, fixed_logs: []const u32, main_logs: []const u32, witness_root: Digest, empty_entry: ?Seal.Entry, shape: *const Shape, external: u32, limits: Limits) !Verified {
            return verifyInternal(false, true, a, &received, sealed, pins, entries, native, index, frame, projections, slots, fixed_logs, main_logs, witness_root, empty_entry, shape, external, limits);
        }
        /// Consumes source proof and claims on every path. Successful capture
        /// owns all copied claims, inventory, exports and core witness vectors.
        pub fn verifyCaptureOwned(a: std.mem.Allocator, received: Proof, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, native: *const Native.OpenReceipt, index: u32, frame: Frame, projections: []const Source.Slot, slots: []const Memory.Slot, fixed_logs: []const u32, main_logs: []const u32, witness_root: Digest, empty_entry: ?Seal.Entry, shape: *const Shape, external: u32, limits: Limits) !VerifiedCapture {
            return verifyInternal(true, true, a, &received, sealed, pins, entries, native, index, frame, projections, slots, fixed_logs, main_logs, witness_root, empty_entry, shape, external, limits);
        }
        /// Source proof/claims remain immutable and owned by the caller. The
        /// capture retains no source pointers and performs no proof byte clone.
        pub fn verifyCaptureBorrowed(a: std.mem.Allocator, received: *const Proof, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, native: *const Native.OpenReceipt, index: u32, frame: Frame, projections: []const Source.Slot, slots: []const Memory.Slot, fixed_logs: []const u32, main_logs: []const u32, witness_root: Digest, empty_entry: ?Seal.Entry, shape: *const Shape, external: u32, limits: Limits) !VerifiedCapture {
            return verifyInternal(true, false, a, received, sealed, pins, entries, native, index, frame, projections, slots, fixed_logs, main_logs, witness_root, empty_entry, shape, external, limits);
        }
        fn verifyInternal(comptime capture: bool, comptime take: bool, a: std.mem.Allocator, received: *const Proof, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, native: *const Native.OpenReceipt, index: u32, frame: Frame, projections: []const Source.Slot, slots: []const Memory.Slot, fixed_logs: []const u32, main_logs: []const u32, witness_root: Digest, empty_entry: ?Seal.Entry, shape: *const Shape, external: u32, limits: Limits) !(if (capture) VerifiedCapture else Verified) {
            var proof = received.*;
            var owns = take;
            defer if (owns) proof.deinit(a);
            defer if (take and !owns) {
                a.free(proof.claims);
                a.free(proof.memory_claims);
            };
            try requireProtocol(proof.protocol_version);
            const policy = CaptureAdmission{ .sealed = sealed, .pins = pins, .entries = entries, .native = native, .index = index, .frame = frame, .projections = projections, .slots = slots, .fixed_logs = fixed_logs, .main_logs = main_logs, .witness_root = witness_root, .empty_entry = empty_entry, .shape = shape, .external_retirements = external, .limits = limits };
            try policy.require(a);
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
            const mask = try mainMask(a, main_logs.len, projections, slots, shape, external);
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
                component.* = try (Adapter.ProjectionComponent{ .binding = try Source.binding(shape, external, slot.main_offset, slot.log_size, slot.n_rows), .inner = .{ .has_access_witness = slots.len != 0, .inner = .{ .slot = slot, .fixed_logs = fixed_logs, .main_logs = main_logs, .root_owner = i == 0, .main_open_mask = mask, .interaction_offset = 4 * i, .interaction_logs = logs, .claim = claim.sum, .relations = &word_challenges.universal_prefix, .composition_split = compositionSplit(projections) } } }).init();
                handles[i] = component.asVerifierComponent();
            }
            for (slots, proof.memory_claims, memory_components, 0..) |slot, claim, *component, i| {
                component.* = try accessComponent(slot, i, projections.len, fixed_logs, main_logs, witness_logs, logs, claim, &challenges, &word_challenges, compositionSplit(projections), sealed.register_custody_mode, try Source.binding(shape, external, slot.main_offset, slot.log_size, null));
                handles[projections.len + i] = component.asVerifierComponent();
            }
            var result = try receipts(a, proof.claims, proof.memory_claims, projections, native, witness_root, index, sealed);
            errdefer result.deinit(a);
            if (capture) {
                var metadata = try CaptureMetadata.init(a, policy, proof.claims, proof.memory_claims, witness_logs, logs);
                errdefer metadata.deinit();
                var captured: core.verifier.ProofCapture(suite.Hasher) = undefined;
                if (take) {
                    owns = false;
                    try core.verifier.verifyWithProofCapture(suite.Hasher, suite.MerkleChannel, a, handles, &channel, &verifier, proof.stark, &captured);
                } else {
                    try core.verifier.verifyBorrowedWithProofCapture(suite.Hasher, suite.MerkleChannel, a, handles, &channel, &verifier, &proof.stark, &captured);
                }
                errdefer captured.deinit(a);
                var output = VerifiedCapture{ .allocator = a, .proof = captured, .metadata = metadata, .word_challenges = word_challenges, .challenges = challenges, .final_channel = channel, .verified = result, .seal = undefined };
                output.seal = try output.identity();
                return output;
            } else {
                owns = false;
                try core.verifier.verify(suite.Hasher, suite.MerkleChannel, a, handles, &channel, &verifier, proof.stark);
                return result;
            }
        }
    };
}

fn accessComponent(slot: Memory.Slot, ordinal: usize, projection_count: usize, fixed: []const u32, main: []const u32, witness: []const u32, interactions: []const u32, claim: Memory.Claim, challenges: *const Bus.Challenges, word_challenges: *const Word.Challenges, split: u32, mode: u32, binding: Source.Binding) !Adapter.AccessComponent {
    return (Adapter.AccessComponent{ .binding = binding, .inner = .{ .composition_split = split, .inner = .{ .register_custody_mode = mode, .family = slot.family, .slot = slot.slot, .log_size = slot.log_size, .base_clock = try Integer.baseClockFromPublicFrame(slot.frame), .fixed_logs = fixed, .main_logs = main, .witness_logs = witness, .interaction_logs = interactions, .root_owner = false, .main_offset = slot.main_offset, .witness_offset = ordinal * Integer.COLUMN_COUNT, .interaction_offset = projection_count * 4 + ordinal * Eval.INTERACTION_COUNT, .transition_claim = claim.transition_sum, .transition_count = claim.active_count, .range_claims = claim.range_claims, .challenges = challenges, .v5_packed = .{ .elements = word_challenges }, .v5_universal = .{ .claim = claim.universal_sum, .elements = word_challenges.universal_prefix.get(.memory_access) } } } }).init();
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
pub fn firstChannel(template: Digest, native: Digest, index: u32, projections: []const Source.Slot, slots: []const Memory.Slot) suite.Channel {
    var channel = suite.Channel{};
    channel.mixU32s(&.{ TAG, VERSION, 1, index, @intCast(projections.len), @intCast(slots.len) });
    channel.mixRoot(Word.abiId());
    channel.mixU32s(&.{ Template.TAG, Template.VERSION, 1 }); // selector-link ABI
    channel.mixRoot(template);
    channel.mixRoot(native);
    for (projections) |slot| Source.mixSlot(&channel, slot);
    Batch.mixRoster(&channel, index, template, slots);
    return channel;
}
pub fn proofChannel(a: std.mem.Allocator, sealed: Seal.Sealed) !suite.Channel {
    var channel = sealed.sharedChannel();
    _ = try Word.Challenges.drawFromChannel(a, &channel);
    channel.mixU32s(&.{ TAG, VERSION, 3 });
    return channel;
}
pub fn requireProtocol(version: u32) !void {
    if (version != VERSION) return error.UntrustedCapacityFusedProtocol;
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
    const ranges = if (memory.len == 0) null else try a.alloc(Range.Claims, memory.len);
    errdefer if (ranges) |owned| a.free(owned);
    var transition = Q.zero();
    var universal = Q.zero();
    var events: u64 = 0;
    if (ranges) |owned_ranges| for (memory, owned_ranges) |claim, *range| {
        range.* = claim.range_claims;
        transition = transition.add(claim.transition_sum);
        universal = universal.add(claim.universal_sum);
        events = try std.math.add(u64, events, claim.active_count);
    };
    return .{
        .projections = .{ .program_sum = program_sum, .fetch_count = fetches, .claims = totals[0..Schema.KIND_COUNT].*, .registers_state_sum = totals[@intFromEnum(Source.Partition.registers_state)], .auxiliary_clock_memory_sum = totals[@intFromEnum(Source.Partition.clock_memory_access)], .register_memory_sum = totals[@intFromEnum(Source.Partition.register_memory_access)], .register_clock_memory_sum = totals[@intFromEnum(Source.Partition.register_clock_memory_access)], .native_roots = native.first_roots, .native_key_id = native.template_id, .native_instance_id = native.instance_id, .execution_index = index, .sealed_digest = sealed.digest },
        .memory = if (memory.len == 0) null else .{ .instance_index = index, .transition_sum = transition, .packed_transition = true, .universal_sum = universal, .event_count = events, .range_claims = ranges.?, .native_roots = native.first_roots, .witness_root = access, .native_instance_id = native.instance_id, .sealed_digest = sealed.digest },
    };
}

fn sameVerified(actual: Verified, expected: Verified) bool {
    if (!std.meta.eql(actual.projections, expected.projections) or (actual.memory == null) != (expected.memory == null)) return false;
    const left = actual.memory orelse return true;
    const right = expected.memory.?;
    if (left.instance_index != right.instance_index or !left.transition_sum.eql(right.transition_sum) or
        left.packed_transition != right.packed_transition or !left.universal_sum.eql(right.universal_sum) or
        left.event_count != right.event_count or !std.meta.eql(left.native_roots, right.native_roots) or
        !std.meta.eql(left.witness_root, right.witness_root) or !std.meta.eql(left.native_instance_id, right.native_instance_id) or
        !std.meta.eql(left.sealed_digest, right.sealed_digest) or left.range_claims.len != right.range_claims.len) return false;
    for (left.range_claims, right.range_claims) |have, want| if (!std.meta.eql(have, want)) return false;
    return true;
}
