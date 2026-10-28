//! One STARK verifies native execution, all native request projections and
//! ordinary memory access constraints. Shared fixed/main; one composition/FRI.
//! New B6JP transcript. Global providers and recursive closure remain open.
const std = @import("std");
const core = @import("stwo_core");
const Native = @import("block_v5_native_execution_proof_v3.zig");
const Fused = @import("block_v5_native_projection_fused_proof_v2.zig");
const Receiver = @import("block_v5_native_projection_fused_receiver_v2.zig");
const Shape = @import("../air/statement.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Catalog = @import("block_v5_native_template_catalog_v1.zig");
const Template = @import("block_v5_native_template_protocol_v3.zig");
const Source = @import("block_v5_native_projection_fused_source_v1.zig");
const Memory = @import("block_v5_opcode_memory_sidecar_proof_v1.zig");
const Batch = @import("block_execution_sidecar_batch_v2.zig");
const Components = @import("block_v5_native_components_v3.zig");
const Bus = @import("block_memory_relation_v2.zig");
const Providers = @import("../recursion/air/universal_provider_relations.zig");
const Empty = @import("block_v5_empty_opcode_memory_v1.zig");

pub const Proof = struct {
    body: Fused.Proof,
    native_claims: *Shape.RiscVInteractionClaim,
    pub fn deinit(self: *Proof, a: std.mem.Allocator) void {
        self.body.deinit(a);
        a.destroy(self.native_claims);
        self.* = undefined;
    }
};
pub const Open = struct {
    native: Native.OpenReceipt,
    companion: Fused.Verified,
    joint_native_and_companion_stark_verified: void = {},
    pub fn deinit(self: *Open, a: std.mem.Allocator) void {
        self.companion.deinit(a);
        self.* = undefined;
    }
};

pub fn ForBackend(comptime Backend: type) type {
    return ForBackendWithProjectionReuse(Backend, false);
}
/// Explicit B6JP-v2 experiment. The caller independently selects the expected
/// protocol; a proof cannot opt itself into a different relation schedule.
pub fn ForBackendWithProjectionReuse(comptime Backend: type, comptime reuse: bool) type {
    return struct {
        /// A real native prefix and a real source-sealed memory prefix are
        /// borrowed. The companion prefix is consumed; native storage stays
        /// owned by its caller until the shared proof has finished.
        pub fn prove(a: std.mem.Allocator, first: *Native.ForBackend(Backend).FirstRound, access: *Fused.ForBackend(Backend).FirstRound, inputs: []const Memory.Input, slots: []const Memory.Slot, memory: Receiver.MemoryPin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, catalog: Catalog.Admission) !Proof {
            if (!first.owns_scheme or first.native.interaction_ready or first.native.failed) return error.InvalidJointNativePhase;
            const pin = Receiver.InstancePin{ .shape = &first.native.statement, .admission = first.pin, .template = first.template, .template_id = first.template_id, .profile = first.template.execution_profile };
            _ = try Receiver.admit(a, first.index, pin, memory, sealed, pins, entries, catalog);
            const projections = try Source.slotsFromShapeForMode(a, pin.shape, first.template.external_retirements, sealed.register_custody_mode);
            defer a.free(projections);
            // No fabricated companion for an empty projection schedule.
            if (projections.len == 0) return error.EmptyJointComponentRoster;
            const challenges = try Bus.Challenges.draw(a, sealed);
            const shared = try Providers.SharedProviderRelations.init(&challenges.universal_prefix);
            try first.native.generateInteractions(&shared.native);
            const claims = try a.create(Shape.RiscVInteractionClaim);
            errdefer a.destroy(claims);
            claims.* = first.native.claims;
            const native = try Components.Owner.initWithExternalForProfile(a, pin.shape, claims, challenges.universal_prefix, pin.admission, pin.template.external_retirements, pin.profile);
            defer native.deinit();
            const logs = try Template.columnLogs(a, pin.shape, pin.template.external_retirements, .interaction);
            defer a.free(logs);
            const body = try Fused.ForBackend(Backend).proveForNativeFirstRoundWithJoint(a, access, inputs, slots, projections, sealed, pins, entries, catalog, first, first.index, memory.frame, memory.witness_root, .{ .native = native, .columns = first.native.interaction.items, .logs = logs, .reuse_projections = reuse });
            return .{ .body = body, .native_claims = claims };
        }

        /// Consume the complete joint proof on every path. Original native
        /// receipts cannot substitute for independently admitted equations.
        pub fn verifyOwned(a: std.mem.Allocator, received: Proof, index: u32, pin: Receiver.InstancePin, memory: Receiver.MemoryPin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, catalog: Catalog.Admission) !Open {
            var proof = received;
            var owns = true;
            defer if (owns) proof.body.deinit(a);
            defer a.destroy(proof.native_claims);
            const roots = try Receiver.admit(a, index, pin, memory, sealed, pins, entries, catalog);
            if (!std.meta.eql(roots[0], pin.template.fixed_root)) return error.UntrustedNativeV5FixedRoot;
            try Native.ForBackend(Backend).verifyFixed(a, pin.shape, pin.template, pins.config);
            const instance = try Template.instanceId(pin.template_id, pin.shape, pin.admission, roots, index);
            const projections = try Source.slotsFromShapeForMode(a, pin.shape, pin.template.external_retirements, sealed.register_custody_mode);
            defer a.free(projections);
            const slots = try Batch.slotsFromStatementForMode(a, pin.shape, memory.frame, sealed.register_custody_mode);
            defer a.free(slots);
            const empty: ?Seal.Entry = if (slots.len == 0) try Empty.firstRoundEntryForMode(a, pin.shape, memory.frame, .{ .family = .execution, .index = index, .instance_id = instance, .roots = roots }, memory.expected_events, sealed.register_custody_mode) else null;
            const challenges = try Bus.Challenges.draw(a, sealed);
            const native = try Components.Owner.initWithExternalForProfile(a, pin.shape, proof.native_claims, challenges.universal_prefix, pin.admission, pin.template.external_retirements, pin.profile);
            defer native.deinit();
            // This provisional value stays private until the one joint STARK
            // verifies all native and companion equations below.
            const receipt = Native.OpenReceipt{ .template_id = pin.template_id, .instance_id = instance, .first_roots = roots, .sealed_digest = sealed.digest, .open_sum = try Native.openSum(native, pin.shape, proof.native_claims) };
            const fixed = try Template.columnLogs(a, pin.shape, pin.template.external_retirements, .fixed);
            defer a.free(fixed);
            const main = try Template.columnLogs(a, pin.shape, pin.template.external_retirements, .main);
            defer a.free(main);
            const logs = try Template.columnLogs(a, pin.shape, pin.template.external_retirements, .interaction);
            defer a.free(logs);
            owns = false;
            var result = try Fused.ForBackend(Backend).verifyOwnedWithJoint(a, proof.body, sealed, pins, entries, &receipt, index, memory.frame, projections, slots, fixed, main, memory.witness_root, empty, .{ .native = native, .logs = logs, .reuse_projections = reuse });
            errdefer result.deinit(a);
            if (result.memory) |verified| {
                if (verified.event_count != memory.expected_events) return error.UntrustedV5FullFusedMemoryCensus;
            } else if (memory.expected_events != 0) return error.UntrustedV5FullFusedMemoryCensus;
            return .{ .native = receipt, .companion = result };
        }
    };
}
