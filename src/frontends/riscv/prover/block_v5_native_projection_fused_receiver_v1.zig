//! Fresh native admission followed by the one fused projection STARK.
//! Separate bus claims stay OPEN: no ROM/provider/memory/recursive authority.
const std = @import("std");
const core = @import("stwo_core");
const Seal = @import("block_v5_source_seal_v1.zig");
const Catalog = @import("block_v5_native_template_catalog_v1.zig");
const Native = @import("block_v5_native_execution_proof_v3.zig");
const Template = @import("block_v5_native_template_protocol_v3.zig");
const Projection = @import("block_v5_native_projection_fused_proof_v1.zig");
const Source = @import("block_v5_native_projection_fused_source_v1.zig");
const Shape = @import("../air/statement.zig").Blake3ExecutionStatement;
const Admission = @import("block_v5_native_public_admission_v1.zig").Admission;
const Profile = @import("../isa/execution_profile.zig").ExecutionProfile;
pub const InstancePin = struct {
    shape: *const Shape,
    admission: Admission,
    template: Native.Template,
    template_id: [32]u8,
    profile: Profile,
};
pub const Open = struct {
    native: Native.OpenReceipt,
    projections: Projection.VerifiedReceipt,
};

/// A new program_request ID explicitly selects this composite protocol. Old
/// receivers/old B5PR artifacts cannot be relabelled as fused proofs.
pub fn instanceId(template: [32]u8, native: [32]u8, index: u32, slots: []const Source.Slot) [32]u8 {
    var channel = core.proof_suites.Blake3.Channel{};
    channel.mixU32s(&.{ Projection.TAG, Projection.VERSION, index, @intCast(slots.len) });
    channel.mixRoot(template);
    channel.mixRoot(native);
    for (slots) |slot| Source.mixSlot(&channel, slot);
    return channel.digestBytes();
}
pub fn admit(index: u32, pin: InstancePin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, catalog: Catalog.Admission, slots: []const Source.Slot) !Seal.Roots {
    try sealed.require(pins, entries);
    try pin.admission.require(pins, &pin.shape.public_data);
    if (pin.admission.context.execution_index != index or pin.profile != pin.template.execution_profile or
        !std.meta.eql(pin.template.config, pins.config)) return error.UntrustedV5FusedNativePin;
    try pin.template.admit(pin.shape, pin.template_id);
    try catalog.admit(pins, sealed, index, pin.template, pin.template_id);
    const native = try find(entries, .execution, index);
    const request = try find(entries, .program_request, index);
    const expected = try Template.instanceId(pin.template_id, pin.shape, pin.admission, native.roots, index);
    if (!std.meta.eql(native.instance_id, expected) or !std.meta.eql(request.roots, native.roots) or
        !std.meta.eql(request.instance_id, instanceId(pin.template_id, expected, index, slots)))
        return error.UntrustedV5FusedProjectionEntry;
    return native.roots;
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        /// Typed absence still fresh-verifies the real native frame STARK.
        /// No fused artifact is present and no caller zero receipt is accepted.
        pub fn verifyEmptyNativeOwned(a: std.mem.Allocator, received: Native.Proof, index: u32, pin: InstancePin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, catalog: Catalog.Admission) !Open {
            var proof = received;
            var owns = true;
            defer if (owns) proof.deinit(a);
            const slots = try Source.slotsFromShapeForMode(a, pin.shape, pin.template.external_retirements, sealed.register_custody_mode);
            defer a.free(slots);
            if (slots.len != 0) return error.NonemptyV5FusedProjectionRequiresProof;
            _ = try admit(index, pin, sealed, pins, entries, catalog, slots);
            try @import("block_v5_empty_native_tables_v1.zig").validateShape(a, pin.shape, pin.template.external_retirements);
            owns = false;
            const fresh = try Native.ForBackend(Backend).verifyOwnedWithCatalog(a, proof, pin.shape, pin.admission, pin.template, pin.template_id, pin.profile, index, sealed, pins, entries, catalog);
            _ = try @import("block_v5_empty_native_tables_v1.zig").fromFresh(a, .{ .shape = pin.shape, .admission = pin.admission, .template = pin.template, .template_id = pin.template_id, .catalog = catalog }, &fresh, index, sealed, pins, entries);
            return .{ .native = fresh, .projections = .{ .program_sum = core.fields.qm31.QM31.zero(), .fetch_count = 0, .claims = @splat(core.fields.qm31.QM31.zero()), .registers_state_sum = core.fields.qm31.QM31.zero(), .auxiliary_clock_memory_sum = core.fields.qm31.QM31.zero(), .native_roots = fresh.first_roots, .native_key_id = fresh.template_id, .native_instance_id = fresh.instance_id, .execution_index = index, .sealed_digest = sealed.digest } };
        }
        /// Both proof arguments transfer ownership, including every error path.
        /// Public receipt structs cannot replace either fresh verification.
        pub fn verifyOwned(a: std.mem.Allocator, native_received: Native.Proof, received: Projection.Proof, index: u32, pin: InstancePin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, catalog: Catalog.Admission) !Open {
            var native = native_received;
            var owns_native = true;
            defer if (owns_native) native.deinit(a);
            var proof = received;
            var owns_projection = true;
            defer if (owns_projection) proof.deinit(a);
            const slots = try Source.slotsFromShapeForMode(a, pin.shape, pin.template.external_retirements, sealed.register_custody_mode);
            defer a.free(slots);
            // Truly empty logical projections need the independent empty-frame
            // admission path. Never invent a zero STARK or accept a zero receipt.
            if (slots.len == 0) return error.EmptyV5FusedProjectionRequiresTypedAbsence;
            const roots = try admit(index, pin, sealed, pins, entries, catalog, slots);
            const fixed_logs = try Template.columnLogs(a, pin.shape, pin.template.external_retirements, .fixed);
            defer a.free(fixed_logs);
            const main_logs = try Template.columnLogs(a, pin.shape, pin.template.external_retirements, .main);
            defer a.free(main_logs);
            owns_native = false;
            const fresh = try Native.ForBackend(Backend).verifyOwnedWithCatalog(a, native, pin.shape, pin.admission, pin.template, pin.template_id, pin.profile, index, sealed, pins, entries, catalog);
            if (!std.meta.eql(fresh.first_roots, roots)) return error.UntrustedV5FusedNativeRoots;
            owns_projection = false;
            const projections = try Projection.ForBackend(Backend).verifyOwned(a, proof, sealed, index, pin.template_id, fresh.instance_id, slots, fixed_logs, main_logs, fresh.first_roots, roots, pins.config);
            return .{ .native = fresh, .projections = projections };
        }
    };
}
fn find(entries: []const Seal.Entry, family: Seal.Family, index: u32) !Seal.Entry {
    var found: ?Seal.Entry = null;
    for (entries) |entry| if (entry.family == family and entry.index == index) {
        if (found != null) return error.DuplicateV5FusedProjectionEntry;
        found = entry;
    };
    return found orelse error.MissingV5FusedProjectionEntry;
}
