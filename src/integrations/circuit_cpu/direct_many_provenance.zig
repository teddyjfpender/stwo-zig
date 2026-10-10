//! Admission metadata for the sealed S31 V4 selected adapters.
//!
//! This checks byte and native-program provenance, but does not parse S31 or
//! authenticate canonical node IDs. Only the source-pinned S31 wrapper may
//! derive descriptors and admit proof bytes.
const std = @import("std");
const air = @import("air.zig");
const schedule = @import("direct_many_schedule.zig");

const Digest = [32]u8;
const Sha256 = std.crypto.hash.sha2.Sha256;
pub const descriptor_version: u32 = 1;

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
