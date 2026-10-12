//! Admission metadata for the sealed S31 V4 selected adapters.
//!
//! This checks byte and native-program provenance, but does not parse S31 or
//! authenticate canonical node IDs. Only the source-pinned S31 wrapper may
//! derive descriptors and admit proof bytes.
const std = @import("std");
const air = @import("air.zig");
const schedule = @import("direct_many_schedule.zig");
const registry = @import("direct_many_registry.zig");
const chip = @import("tagged_many_chip.zig");
const bridge = @import("tagged_many_bridge.zig");

const Digest = [32]u8;
const Sha256 = std.crypto.hash.sha2.Sha256;
pub const descriptor_version: u32 = 1;
comptime {
    if (descriptor_version != registry.registry_version)
        @compileError("V4 descriptor and source-kind registry versions must advance together");
}

/// The descriptor version is separate from V4 proof bytes. New native AIRs
/// require explicit registration and a reviewed profile/version decision.
pub const ComponentDescriptor = struct {
    version: u32 = descriptor_version,
    source_kind: schedule.SourceKind,
    call_id: ?u32,
    program_binding_sha256: Digest,
    source_node_id: ?u32 = null,
    input_node_id: ?u32 = null,
};

pub const SourcePin = struct {
    source_bytes: []const u8,
    air_bundle_bytes: []const u8,
    /// The circuit source lives in a separate Zig package. The adapter checks
    /// its fixed V4 source hash before using these bytes in the template hash.
    direct_circuit_source_bytes: []const u8,
    native_template_sha256: Digest,
    descriptors: []const ComponentDescriptor,
};

pub fn validate(
    selected: *const schedule.SelectedSchedule,
    pin: SourcePin,
) !void {
    try selected.validateShape();
    var expected_direct_source: Digest = undefined;
    _ = std.fmt.hexToBytes(&expected_direct_source, "72f00e3e4f6481cae641a48a8507e733c95f97a15963149027a6488fc46d2d7c") catch unreachable;
    if (pin.descriptors.len != selected.geometry.slot_count or
        !std.meta.eql(digest(pin.source_bytes), selected.geometry.source_digest) or
        !std.meta.eql(digest(pin.direct_circuit_source_bytes), expected_direct_source) or
        !std.meta.eql(pin.native_template_sha256, nativeTemplateDigest(pin.direct_circuit_source_bytes)))
        return error.InvalidManyProvenance;
    var bundle_digest: Digest = undefined;
    _ = std.fmt.hexToBytes(&bundle_digest, air.bundle_sha256) catch
        return error.InvalidManyProvenance;
    if (!std.meta.eql(digest(pin.air_bundle_bytes), bundle_digest))
        return error.InvalidManyProvenance;
    for (selected.slotSlice(), pin.descriptors, 0..) |slot, descriptor, index| {
        if (descriptor.version != descriptor_version or
            descriptor.source_kind != slot.source_kind or
            descriptor.call_id != slot.call_id or
            !std.meta.eql(descriptor.program_binding_sha256, slot.program_binding_sha256))
            return error.InvalidManyProvenance;
        if (index == 0) {
            if (slot.source_kind != .bundled_circuit or descriptor.call_id != null or
                descriptor.source_node_id != null or descriptor.input_node_id != null or
                !std.meta.eql(slot.bundle_sha256, bundle_digest))
                return error.InvalidManyProvenance;
            continue;
        }
        const id: usize = @intCast(descriptor.call_id orelse return error.InvalidManyProvenance);
        if (id >= selected.geometry.call_count) return error.InvalidManyProvenance;
        const source_node_id = descriptor.source_node_id orelse return error.InvalidManyProvenance;
        const input_node_id = descriptor.input_node_id orelse return error.InvalidManyProvenance;
        if (slot.source_kind == .bundled_circuit or
            !std.meta.eql(
                nativeProgramDigest(slot.source_kind, pin.native_template_sha256, source_node_id, input_node_id, selected.geometry.calls[id]),
                descriptor.program_binding_sha256,
            ))
            return error.InvalidManyProvenance;
    }
}

/// Called after the guarded adapter binds the pinned AIR to the selected
/// direct circuit. A jointly forged slot-0 and descriptor hash must still
/// equal the actual bound program identity.
pub fn validateCircuitProgram(
    selected: *const schedule.SelectedSchedule,
    pin: SourcePin,
    bound: *const air.Bundle,
) !void {
    if (selected.geometry.slot_count == 0 or pin.descriptors.len == 0)
        return error.InvalidManyProvenance;
    const actual = try air.directProgramBindingDigest(pin.air_bundle_bytes, bound);
    if (!std.meta.eql(actual, selected.geometry.slots[0].program_binding_sha256) or
        !std.meta.eql(actual, pin.descriptors[0].program_binding_sha256))
        return error.InvalidManyProvenance;
}

/// Check the concrete chip and bridge objects that the guarded prover or
/// verifier passes as AIR handles. The bridge carries the full compiled call;
/// the chip carries its ID, constant, height, and trace offsets. Native AIR
/// source bytes remain closed and embedded in `nativeProgramDigest`.
pub fn validateBoundNativeComponents(
    selected: *const schedule.SelectedSchedule,
    pin: SourcePin,
    chips: []const chip.Component,
    bridges: []const bridge.Component,
) !void {
    try selected.validateShape();
    const count: usize = selected.geometry.call_count;
    if (chips.len != count or bridges.len != count or pin.descriptors.len != selected.geometry.slot_count)
        return error.InvalidManyProvenance;
    for (chips, bridges, 0..) |live_chip, live_bridge, id| {
        const chip_index = 1 + id;
        const bridge_index = 1 + count + id;
        const chip_slot = selected.geometry.slots[chip_index];
        const bridge_slot = selected.geometry.slots[bridge_index];
        const chip_descriptor = pin.descriptors[chip_index];
        const bridge_descriptor = pin.descriptors[bridge_index];
        const call = live_bridge.boundary;
        const log_size = chip.validateRounds(call.rounds) catch return error.InvalidManyProvenance;
        if (call.call_id != id or !std.meta.eql(call, selected.geometry.calls[id]) or
            live_chip.call_id != call.call_id or !std.meta.eql(live_chip.constant, call.constant) or
            live_chip.log_size != log_size or
            live_chip.main_offset != chip_slot.main_offset or
            live_chip.interaction_offset != chip_slot.interaction_offset or
            live_bridge.main_offset != bridge_slot.main_offset or
            live_bridge.interaction_offset != bridge_slot.interaction_offset or
            chip_slot.trace_log_size != log_size or
            bridge_slot.trace_log_size != bridge.log_size or
            chip_slot.source_kind != .tagged_chip or bridge_slot.source_kind != .tagged_bridge or
            chip_slot.kind != .chip or bridge_slot.kind != .bridge or
            chip_slot.call_id == null or chip_slot.call_id.? != call.call_id or
            bridge_slot.call_id == null or bridge_slot.call_id.? != call.call_id or
            chip_descriptor.source_kind != .tagged_chip or bridge_descriptor.source_kind != .tagged_bridge or
            chip_descriptor.version != descriptor_version or bridge_descriptor.version != descriptor_version or
            chip_descriptor.call_id == null or chip_descriptor.call_id.? != call.call_id or
            bridge_descriptor.call_id == null or bridge_descriptor.call_id.? != call.call_id or
            chip_descriptor.source_node_id == null or chip_descriptor.input_node_id == null or
            chip_descriptor.source_node_id != bridge_descriptor.source_node_id or
            chip_descriptor.input_node_id != bridge_descriptor.input_node_id)
            return error.InvalidManyProvenance;
        const source_node_id = chip_descriptor.source_node_id.?;
        const input_node_id = chip_descriptor.input_node_id.?;
        const chip_digest = nativeProgramDigest(.tagged_chip, pin.native_template_sha256, source_node_id, input_node_id, call);
        const bridge_digest = nativeProgramDigest(.tagged_bridge, pin.native_template_sha256, source_node_id, input_node_id, call);
        if (!std.meta.eql(chip_digest, chip_slot.program_binding_sha256) or
            !std.meta.eql(chip_digest, chip_descriptor.program_binding_sha256) or
            !std.meta.eql(bridge_digest, bridge_slot.program_binding_sha256) or
            !std.meta.eql(bridge_digest, bridge_descriptor.program_binding_sha256))
            return error.InvalidManyProvenance;
    }
}

fn nativeTemplateDigest(direct_circuit_source_bytes: []const u8) Digest {
    var h = Sha256.init(.{});
    h.update("S31-BOUNDED-NATIVE-AIR-TEMPLATE-V4\x00");
    inline for (.{
        @embedFile("private_pair_boundary.zig"),
        @embedFile("private_many_boundary.zig"),
        @embedFile("direct_many_preflight.zig"),
        direct_circuit_source_bytes,
        @embedFile("tagged_many_chip.zig"),
        @embedFile("tagged_many_bridge.zig"),
    }) |source| hashBytes(&h, source);
    var result: Digest = undefined;
    h.final(&result);
    return result;
}

fn nativeProgramDigest(
    kind: schedule.SourceKind,
    native_template_sha256: Digest,
    source_node_id: u32,
    input_node_id: u32,
    call: @import("private_many_boundary.zig").Call,
) Digest {
    var h = Sha256.init(.{});
    h.update("S31-BOUNDED-NATIVE-COMPONENT-V4\x00");
    hashInt(&h, @as(u8, switch (kind) {
        .tagged_chip => 0,
        .tagged_bridge => 1,
        .bundled_circuit => unreachable,
    }));
    h.update(&native_template_sha256);
    hashBytes(&h, switch (kind) {
        .tagged_chip => @embedFile("tagged_many_chip.zig"),
        .tagged_bridge => @embedFile("tagged_many_bridge.zig"),
        .bundled_circuit => unreachable,
    });
    hashInt(&h, call.call_id);
    hashInt(&h, source_node_id);
    hashInt(&h, input_node_id);
    hashInt(&h, call.rounds);
    hashInt(&h, call.constant.toU32());
    hashInt(&h, @as(u8, 1)); // Source-pinned native calls require endpoints.
    for (call.input) |address| hashInt(&h, address);
    for (call.output) |address| hashInt(&h, address);
    var result: Digest = undefined;
    h.final(&result);
    return result;
}

fn digest(bytes: []const u8) Digest {
    var result: Digest = undefined;
    Sha256.hash(bytes, &result, .{});
    return result;
}

fn hashInt(h: *Sha256, value: anytype) void {
    var bytes: [@sizeOf(@TypeOf(value))]u8 = undefined;
    std.mem.writeInt(@TypeOf(value), &bytes, value, .little);
    h.update(&bytes);
}

fn hashBytes(h: *Sha256, bytes: []const u8) void {
    hashInt(h, @as(u64, @intCast(bytes.len)));
    h.update(bytes);
}
