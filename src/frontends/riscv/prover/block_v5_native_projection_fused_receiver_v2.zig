//! Fresh-native receiver for one ordinary-memory + projection STARK.
//! Exact schedules come from independent shape/frame pins, never transport.
const std = @import("std");
const Seal = @import("block_v5_source_seal_v1.zig");
const Catalog = @import("block_v5_native_template_catalog_v1.zig");
const Native = @import("block_v5_native_execution_proof_v3.zig");
const Template = @import("block_v5_native_template_protocol_v3.zig");
const Previous = @import("block_v5_native_projection_fused_receiver_v1.zig");
const Proof = @import("block_v5_native_projection_fused_proof_v2.zig");
const Source = @import("block_v5_native_projection_fused_source_v1.zig");
const Memory = @import("block_execution_sidecar_batch_v2.zig");
const Frame = @import("../air/block/memory_event.zig").Frame;
const Empty = @import("block_v5_empty_opcode_memory_v1.zig");
pub const InstancePin = Previous.InstancePin;
pub const MemoryPin = struct { frame: Frame, expected_events: u64, witness_root: [32]u8 };
pub const Open = struct {
    native: Native.OpenReceipt,
    fused: Proof.Verified,
    pub fn deinit(self: *Open, a: std.mem.Allocator) void {
        self.fused.deinit(a);
        self.* = undefined;
    }
};
pub const instanceId = Proof.instanceId;
pub const entry = Proof.entry;

pub fn requireProofPresence(projection_count: usize, access_count: usize, has_proof: bool) !void {
    if (projection_count == 0) {
        if (access_count != 0 or has_proof) return error.UntrustedV5FullFusedTypedAbsence;
    } else if (!has_proof) return error.MissingV5FullFusedProof;
}

/// Sealed producer/receiver admission from independently pinned shape/frame.
/// Proposals remain proposals; this method does not issue verifier authority.
pub fn admit(a: std.mem.Allocator, index: u32, pin: InstancePin, memory: MemoryPin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, catalog: Catalog.Admission) !Seal.Roots {
    try requirePin(index, pin, memory, sealed, pins, entries, catalog);
    const projections = try Source.slotsFromShapeForMode(a, pin.shape, pin.template.external_retirements, sealed.register_custody_mode);
    defer a.free(projections);
    const slots = try Memory.slotsFromStatementForMode(a, pin.shape, memory.frame, sealed.register_custody_mode);
    defer a.free(slots);
    const execution = try findExecution(entries, index);
    const expected = try Template.instanceId(pin.template_id, pin.shape, pin.admission, execution.roots, index);
    if (!std.meta.eql(execution.instance_id, expected)) return error.UntrustedV5FullFusedFreshNative;
    const empty_entry: ?Seal.Entry = if (slots.len == 0) try Empty.firstRoundEntryForMode(a, pin.shape, memory.frame, execution, memory.expected_events, sealed.register_custody_mode) else null;
    try Proof.admit(sealed, pins, entries, index, pin.template_id, expected, execution.roots, memory.witness_root, memory.frame, projections, slots, empty_entry);
    return execution.roots;
}

pub fn ForBackend(comptime Backend: type) type {
    return struct {
        /// Both proof arguments transfer ownership on every path. The fresh
        /// native verification is performed here; no receipt alone suffices.
        pub fn verifyOwned(a: std.mem.Allocator, native_received: Native.Proof, received: ?Proof.Proof, index: u32, pin: InstancePin, memory: MemoryPin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, catalog: Catalog.Admission) !Open {
            var native = native_received;
            var owns_native = true;
            defer if (owns_native) native.deinit(a);
            var proof = received;
            var owns_proof = true;
            defer if (owns_proof) if (proof) |*present| present.deinit(a);
            _ = try admit(a, index, pin, memory, sealed, pins, entries, catalog);
            owns_native = false;
            const fresh = try Native.ForBackend(Backend).verifyOwnedWithCatalog(a, native, pin.shape, pin.admission, pin.template, pin.template_id, pin.profile, index, sealed, pins, entries, catalog);
            owns_proof = false;
            const verified = try verifyAfterFreshNative(a, proof, &fresh, index, pin, memory, sealed, pins, entries, catalog);
            return .{ .native = fresh, .fused = verified };
        }

        /// For a private complete-receiver hook whose base loop already freshly
        /// verified native. Scope remains open; all global providers, register
        /// windows, caller proofs and recursion still have to close separately.
        pub fn verifyAfterFreshNative(a: std.mem.Allocator, received: ?Proof.Proof, fresh: *const Native.OpenReceipt, index: u32, pin: InstancePin, memory: MemoryPin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, catalog: Catalog.Admission) !Proof.Verified {
            var proof = received;
            var owns = true;
            defer if (owns) if (proof) |*present| present.deinit(a);
            _ = try admit(a, index, pin, memory, sealed, pins, entries, catalog);
            const projections = try Source.slotsFromShapeForMode(a, pin.shape, pin.template.external_retirements, sealed.register_custody_mode);
            defer a.free(projections);
            const slots = try Memory.slotsFromStatementForMode(a, pin.shape, memory.frame, sealed.register_custody_mode);
            defer a.free(slots);
            const execution = try findExecution(entries, index);
            const expected = try Template.instanceId(pin.template_id, pin.shape, pin.admission, execution.roots, index);
            if (!std.meta.eql(fresh.instance_id, expected) or !std.meta.eql(fresh.template_id, pin.template_id) or
                !std.meta.eql(fresh.first_roots, execution.roots) or !std.meta.eql(fresh.sealed_digest, sealed.digest))
                return error.UntrustedV5FullFusedFreshNative;
            const empty_entry: ?Seal.Entry = if (slots.len == 0) try Empty.firstRoundEntryForMode(a, pin.shape, memory.frame, execution, memory.expected_events, sealed.register_custody_mode) else null;
            if (slots.len == 0) try Empty.admit(a, pin.shape, memory.frame, fresh, index, memory.expected_events, sealed, pins, entries);
            try requireProofPresence(projections.len, slots.len, proof != null);
            if (projections.len == 0) {
                if (slots.len != 0 or proof != null) return error.UntrustedV5FullFusedTypedAbsence;
                // Genuine native verification has already succeeded. There
                // are no projection or access AIR rows, hence no loader/STARK
                // and no invented zero claim/receipt for either obligation.
                return .{ .projections = null, .memory = null };
            }
            const actual_proof = proof orelse return error.MissingV5FullFusedProof;
            const fixed_logs = try Template.columnLogs(a, pin.shape, pin.template.external_retirements, .fixed);
            defer a.free(fixed_logs);
            const main_logs = try Template.columnLogs(a, pin.shape, pin.template.external_retirements, .main);
            defer a.free(main_logs);
            owns = false;
            var result = try Proof.ForBackend(Backend).verifyOwned(a, actual_proof, sealed, pins, entries, fresh, index, memory.frame, projections, slots, fixed_logs, main_logs, memory.witness_root, empty_entry);
            errdefer result.deinit(a);
            if (result.memory) |verified| {
                if (verified.event_count != memory.expected_events) return error.UntrustedV5FullFusedMemoryCensus;
            } else if (memory.expected_events != 0) return error.UntrustedV5FullFusedMemoryCensus;
            return result;
        }
    };
}

fn requirePin(index: u32, pin: InstancePin, memory: MemoryPin, sealed: Seal.Sealed, pins: Seal.Pins, entries: []const Seal.Entry, catalog: Catalog.Admission) !void {
    try sealed.require(pins, entries);
    try pin.admission.require(pins, &pin.shape.public_data);
    if (pin.admission.context.execution_index != index or pin.profile != pin.template.execution_profile or
        !std.meta.eql(pin.template.config, pins.config) or memory.frame.clock_frame != .leaf_local or
        memory.frame.global_first_cycle != pin.admission.context.first_cycle or
        memory.frame.cycle_count != pin.shape.public_data.clock) return error.UntrustedV5FullFusedPin;
    try pin.template.admit(pin.shape, pin.template_id);
    try catalog.admit(pins, sealed, index, pin.template, pin.template_id);
}
fn findExecution(entries: []const Seal.Entry, index: u32) !Seal.Entry {
    var found: ?Seal.Entry = null;
    for (entries) |item| if (item.family == .execution and item.index == index) {
        if (found != null) return error.DuplicateV5FullFusedEntry;
        found = item;
    };
    return found orelse error.MissingV5FullFusedEntry;
}
