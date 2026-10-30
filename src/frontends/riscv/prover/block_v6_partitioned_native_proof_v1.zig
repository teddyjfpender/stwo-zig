//! B6JP-v3: original native semantics and one complete typed relation basis.
//! No original native lookup interactions or physical native claims survive.
//! All global provider obligations remain explicit until separately closed.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Native = @import("block_v5_native_execution_proof_v3.zig");
const Fused = @import("block_v5_native_projection_fused_proof_v2.zig");
const Receiver = @import("block_v5_native_projection_fused_receiver_v2.zig");
const Template = @import("block_v5_native_template_protocol_v3.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Catalog = @import("block_v5_native_template_catalog_v1.zig");
const Layout = @import("block_v6_relation_layout_v1.zig").Layout;
const Base = @import("block_v6_partitioned_native_components_v1.zig");
const Memory = @import("block_v5_opcode_memory_sidecar_proof_v1.zig");
const Batch = @import("block_execution_sidecar_batch_v2.zig");
pub const Proof = Fused.Proof;
pub const VERSION: u32 = 3;
pub const Identity = struct { template_id: [32]u8, instance_id: [32]u8, first_roots: Seal.Roots, sealed_digest: [32]u8 };
pub const Receipt = struct {
    template_id: [32]u8,
    instance_id: [32]u8,
    first_roots: Seal.Roots,
    sealed_digest: [32]u8,
    layout_digest: [32]u8,
    open_sum: Q,
    partition_sums: [@import("block_v5_native_lookup_request_source_v1.zig").PARTITION_COUNT]Q,
    program_sum: Q,
};
pub const Open = struct {
    native: Receipt,
    companion: Fused.Verified,
    pub fn deinit(self: *Open, a: std.mem.Allocator) void {
        self.companion.deinit(a);
        self.* = undefined;
    }
};
pub const Capture = struct {
    a: std.mem.Allocator,
    proof: core.verifier.ProofCapture(core.proof_suites.Blake3.Hasher),
    final_channel: core.proof_suites.Blake3.Channel,
    claims: []Fused.Claim,
    memory_claims: []Memory.Claim,
    receipt: Receipt,
    seal: [32]u8 = @splat(0),
    pub fn identity(self: *const Capture) [32]u8 {
        var channel = core.proof_suites.Blake3.Channel{};
        channel.mixU32s(&.{ 0x42365243, VERSION });
        channel.mixRoot(@import("proof_capture_sha256.zig").compute(&self.proof));
        inline for (.{ self.receipt.template_id, self.receipt.instance_id, self.receipt.first_roots[0], self.receipt.first_roots[1], self.receipt.sealed_digest, self.receipt.layout_digest }) |digest| channel.mixRoot(digest);
        channel.mixFelts(&.{ self.receipt.open_sum, self.receipt.program_sum });
        channel.mixFelts(&self.receipt.partition_sums);
        for (self.claims) |claim| {
            channel.mixFelts(&.{claim.sum});
            channel.mixU64(claim.row_count);
        }
        for (self.memory_claims) |claim| {
            channel.mixFelts(&.{ claim.transition_sum, claim.universal_sum });
            channel.mixFelts(&claim.range_claims);
            channel.mixU64(claim.active_count);
        }
        channel.mixRoot(self.final_channel.digestBytes());
        channel.mixU64(self.final_channel.n_draws);
        return channel.digestBytes();
    }
    pub fn deinit(self: *Capture) void {
        self.proof.deinit(self.a);
        self.a.free(self.claims);
        self.a.free(self.memory_claims);
        self.* = undefined;
    }
};

pub fn admitIdentity(a: std.mem.Allocator, index: u32, pin: Receiver.InstancePin, memory: Receiver.MemoryPin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, catalog: Catalog.Admission, layout: *const Layout) !Identity {
    // Experimental local-zero native geometry has not passed genuine proof qualification.
    // Both producer and recursive/native receiver must reject it, without fallback.
    if (pin.shape.localZeroCustody()) return error.UnqualifiedPartitionedLocalZeroRecipe;
    try Receiver.requirePin(index, pin, memory, sealed, pins, entries, catalog);
    var found: ?Seal.Entry = null;
    for (entries) |entry| if (entry.family == .execution and entry.index == index) {
        if (found != null) return error.DuplicatePartitionedExecution;
        found = entry;
    };
    const execution = found orelse return error.MissingPartitionedExecution;
    const instance = try Template.instanceId(pin.template_id, pin.shape, pin.admission, execution.roots, index);
    if (!std.meta.eql(execution.instance_id, instance) or !std.meta.eql(execution.roots[0], pin.template.fixed_root)) return error.UntrustedPartitionedExecution;
    const slots = try Batch.slotsFromStatementForMode(a, pin.shape, memory.frame, sealed.register_custody_mode);
    defer a.free(slots);
    const empty: ?Seal.Entry = if (slots.len == 0) try @import("block_v5_empty_opcode_memory_v1.zig").firstRoundEntryForMode(a, pin.shape, memory.frame, execution, memory.expected_events, sealed.register_custody_mode) else null;
    try Fused.admit(sealed, pins, entries, index, pin.template_id, instance, execution.roots, memory.witness_root, memory.frame, layout.slots, slots, empty);
    // Independent public/root identity only. No accounting claim or proof
    // success is represented by this value.
    return .{ .template_id = pin.template_id, .instance_id = instance, .first_roots = execution.roots, .sealed_digest = sealed.digest };
}

/// Empty logical native geometry owns one constrained frame pad, not a lookup.
pub fn interactionLogs(a: std.mem.Allocator, projections: []const @import("block_v5_native_projection_fused_source_v1.zig").Slot, slots: []const Memory.Slot) ![]u32 {
    if (projections.len == 0) {
        if (slots.len != 0) return error.InvalidPartitionedFrameMemory;
        return a.dupe(u32, &.{@import("block_v5_native_frame_v1.zig").LOG_SIZE});
    }
    return Fused.interactionLogs(a, projections, slots);
}
/// Reconstruct the ledger from authenticated physical claims. This pure
/// conversion grants no proof authority; fresh verification or an independently
/// verified recursive public bus must precede acceptance of the result.
pub fn nativeExports(a: std.mem.Allocator, shape: *const @import("../air/statement.zig").Blake3ExecutionStatement, identity: Identity, sealed: Seal.Sealed, layout: *const Layout, claims: []const Fused.Claim) !Receipt {
    if (claims.len != layout.slots.len) return error.InvalidPartitionedClaims;
    for (claims, layout.slots) |claim, slot| if (claim.row_count != slot.n_rows or !@import("../recursion/air/universal_provider_relations.zig").secureIsCanonical(&claim.sum)) return error.InvalidPartitionedClaims;
    const challenges = try @import("block_memory_relation_v2.zig").Challenges.draw(a, sealed);
    const relations = try @import("../recursion/air/universal_provider_relations.zig").SharedProviderRelations.init(&challenges.universal_prefix);
    var total = try @import("../air/public_logup_arithmetic.zig").registersStateSumFor(Q, &shape.public_data, &relations.native);
    var partition_sums: [@import("block_v5_native_lookup_request_source_v1.zig").PARTITION_COUNT]Q = @splat(Q.zero());
    var program_sum = Q.zero();
    for (claims, layout.slots) |claim, slot| {
        total = total.add(claim.sum);
        switch (slot.kind) {
            .program => program_sum = program_sum.add(claim.sum),
            .lookup => |lookup| partition_sums[@intFromEnum(lookup.partition)] = partition_sums[@intFromEnum(lookup.partition)].add(claim.sum),
        }
    }
    return Receipt{ .template_id = identity.template_id, .instance_id = identity.instance_id, .first_roots = identity.first_roots, .sealed_digest = sealed.digest, .layout_digest = layout.digest, .open_sum = total, .partition_sums = partition_sums, .program_sum = program_sum };
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        pub fn prove(a: std.mem.Allocator, first: *Native.ForBackend(Backend).FirstRound, access: *Fused.ForBackend(Backend).FirstRound, inputs: []const Memory.Input, slots: []const Memory.Slot, memory: Receiver.MemoryPin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, catalog: Catalog.Admission) !Proof {
            if (first.native.interaction_ready or first.native.failed) return error.InvalidPartitionedNativePhase;
            var layout = try Layout.init(a, &first.native.statement, first.template.external_retirements, sealed.register_custody_mode);
            defer layout.deinit();
            const pin = Receiver.InstancePin{ .shape = &first.native.statement, .admission = first.pin, .template = first.template, .template_id = first.template_id, .profile = first.template.execution_profile };
            _ = try admitIdentity(a, first.index, pin, memory, sealed, pins, entries, catalog, &layout);
            const base = try Base.Owner.init(a, pin.shape, pin.template.external_retirements);
            defer base.deinit();
            return Fused.ForBackend(Backend).proveForNativeFirstRoundWithJoint(a, access, inputs, slots, layout.slots, sealed, pins, entries, catalog, first, first.index, memory.frame, memory.witness_root, .{ .partitioned = base, .layout_digest = layout.digest });
        }
        pub fn verifyOwned(a: std.mem.Allocator, proof: Proof, index: u32, pin: Receiver.InstancePin, memory: Receiver.MemoryPin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, catalog: Catalog.Admission) !Open {
            return verify(a, proof, index, pin, memory, sealed, pins, entries, catalog, null);
        }
        /// Fresh verifier capture owns copied physical claims and authenticated
        /// PCS openings. The caller never supplies a success receipt as proof.
        pub fn verifyOwnedCapture(a: std.mem.Allocator, proof: Proof, index: u32, pin: Receiver.InstancePin, memory: Receiver.MemoryPin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, catalog: Catalog.Admission, capture: *Capture) !Open {
            return verify(a, proof, index, pin, memory, sealed, pins, entries, catalog, capture);
        }
        fn verify(a: std.mem.Allocator, received: Proof, index: u32, pin: Receiver.InstancePin, memory: Receiver.MemoryPin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, catalog: Catalog.Admission, capture: ?*Capture) !Open {
            var proof = received;
            var owns = true;
            defer if (owns) proof.deinit(a);
            var layout = try Layout.init(a, pin.shape, pin.template.external_retirements, sealed.register_custody_mode);
            defer layout.deinit();
            const identity = try admitIdentity(a, index, pin, memory, sealed, pins, entries, catalog, &layout);
            try Native.ForBackend(Backend).verifyFixed(a, pin.shape, pin.template, pins.config);
            const base = try Base.Owner.init(a, pin.shape, pin.template.external_retirements);
            defer base.deinit();
            const slots = try Batch.slotsFromStatementForMode(a, pin.shape, memory.frame, sealed.register_custody_mode);
            defer a.free(slots);
            const empty: ?Seal.Entry = if (slots.len == 0) try @import("block_v5_empty_opcode_memory_v1.zig").firstRoundEntryForMode(a, pin.shape, memory.frame, .{ .family = .execution, .index = index, .instance_id = identity.instance_id, .roots = identity.first_roots }, memory.expected_events, sealed.register_custody_mode) else null;
            const fixed = try Template.columnLogs(a, pin.shape, pin.template.external_retirements, .fixed);
            defer a.free(fixed);
            const main = try Template.columnLogs(a, pin.shape, pin.template.external_retirements, .main);
            defer a.free(main);
            if (proof.claims.len != layout.slots.len) return error.InvalidPartitionedClaims;
            const receipt = try nativeExports(a, pin.shape, identity, sealed, &layout, proof.claims);
            const claim_copy = if (capture != null) try a.dupe(Fused.Claim, proof.claims) else null;
            errdefer if (claim_copy) |copy| a.free(copy);
            const memory_copy = if (capture != null) try a.dupe(Memory.Claim, proof.memory_claims) else null;
            errdefer if (memory_copy) |copy| a.free(copy);
            var captured: core.verifier.ProofCapture(core.proof_suites.Blake3.Hasher) = undefined;
            var channel: core.proof_suites.Blake3.Channel = undefined;
            owns = false;
            var result = try Fused.ForBackend(Backend).verifyOwnedWithJointCaptured(a, proof, sealed, pins, entries, &identity, index, memory.frame, layout.slots, slots, fixed, main, memory.witness_root, empty, .{ .partitioned = base, .layout_digest = layout.digest }, if (capture != null) &captured else null, &channel);
            errdefer result.deinit(a);
            errdefer if (capture != null) captured.deinit(a);
            if (result.memory) |verified| {
                if (verified.event_count != memory.expected_events) return error.UntrustedPartitionedMemoryCensus;
            } else if (memory.expected_events != 0) return error.UntrustedPartitionedMemoryCensus;
            if (capture) |out| {
                out.* = .{ .a = a, .proof = captured, .final_channel = channel, .claims = claim_copy.?, .memory_claims = memory_copy.?, .receipt = receipt };
                out.seal = out.identity();
            }
            return .{ .native = receipt, .companion = result };
        }
    };
}
