//! Independently admitted positive byte requests for family14 groups. Both
//! packed execution sidecars keep exactly14 range88 queries per access.
const std = @import("std");
const core = @import("stwo_core");
const counter = @import("../air/lookups/tables/counter.zig");
const bytes = @import("block_execution_byte_range_v2.zig");
const opcode = @import("block_v5_opcode_memory_sidecar_proof_v1.zig");
const external = @import("block_v5_external_memory_sidecar_proof_v1.zig");
const source = @import("block_execution_external_trace_v2.zig");
const frame_mod = @import("../air/block/memory_event.zig");
const Q = core.fields.qm31.QM31;
/// The exact independently pinned census is the byte provider's admitted
/// bound. Slot capacity is checked separately and never inflates that bound.
pub const Demand = struct { event_count: u64, request_count: u64, max_requests: u64 };
/// Slots must be independently derived from the trusted native statement,
/// never selected by proof claims. The fresh slot count recurrence later
/// proves the exact census; this only bounds admitted first-round counters.
pub fn opcodeDemand(slots: []const opcode.Slot, expected_events: u64) !Demand {
    return demand(slots, expected_events);
}
pub fn opcodeDemandFromShape(a: std.mem.Allocator, shape: *const @import("../air/statement.zig").Blake3ExecutionStatement, frame: frame_mod.Frame, expected_events: u64) !Demand {
    return opcodeDemandFromShapeForMode(a, shape, frame, expected_events, 0);
}
pub fn opcodeDemandFromShapeForMode(a: std.mem.Allocator, shape: *const @import("../air/statement.zig").Blake3ExecutionStatement, frame: frame_mod.Frame, expected_events: u64, mode: u32) !Demand {
    const slots = try @import("block_execution_sidecar_batch_v2.zig").slotsFromStatementForMode(a, shape, frame, mode);
    defer a.free(slots);
    return opcodeDemand(slots, expected_events);
}
pub fn externalDemand(statement: *const @import("blake3_ethereum_sha_profile.zig").admission.Statement, slots: []const external.Slot) !Demand {
    return externalDemandForMode(statement, slots, 0);
}
pub fn externalDemandForMode(statement: *const @import("blake3_ethereum_sha_profile.zig").admission.Statement, slots: []const external.Slot, mode: u32) !Demand {
    try source.requireRwDescriptors(slots, mode);
    return demand(slots, try source.expectedEventCountForMode(statement, mode));
}
fn demand(slots: anytype, events: u64) !Demand {
    var capacity: u64 = 0;
    for (slots) |slot| {
        if (slot.log_size == 0 or slot.log_size > 24) return error.InvalidV5MemoryByteGeometry;
        capacity = try std.math.add(u64, capacity, @as(u64, 1) << @intCast(slot.log_size));
    }
    if (events > capacity) return error.InvalidV5MemoryByteCensus;
    const requests = try std.math.mul(u64, events, bytes.REQUEST_COUNT);
    if (requests >= core.fields.m31.Modulus) return error.V5MemoryByteInstanceCountOverflow;
    return .{ .event_count = events, .request_count = requests, .max_requests = requests };
}
/// Transactional first-round accumulation. A failed census leaves the caller
/// counter unchanged. Signed native effects may share this output counter;
/// the sidecar contribution itself is a canonical positive integer census.
pub fn collectOpcode(a: std.mem.Allocator, inputs: []const opcode.Input, slots: []const opcode.Slot, expected: Demand, global: *counter.Counter) ![32]u8 {
    if (inputs.len != slots.len or !std.meta.eql(try opcodeDemand(slots, expected.event_count), expected)) return error.InvalidV5MemoryByteCensus;
    for (inputs, slots) |input, slot| if (!std.meta.eql(input.descriptor, slot) or input.trace.family != slot.family or input.trace.slot != slot.slot or input.trace.log_size != slot.log_size) return error.InvalidV5MemoryByteDescriptor;
    return collect(a, inputs, expected, global);
}
pub fn collectExternal(a: std.mem.Allocator, inputs: []const external.Input, slots: []const external.Slot, expected: Demand, global: *counter.Counter) ![32]u8 {
    if (inputs.len != slots.len or !std.meta.eql(try demand(slots, expected.event_count), expected)) return error.InvalidV5MemoryByteCensus;
    for (inputs, slots) |input, slot| if (!std.meta.eql(input.descriptor, slot) or !std.meta.eql(input.trace.descriptor, slot)) return error.InvalidV5MemoryByteDescriptor;
    return collect(a, inputs, expected, global);
}
fn collect(a: std.mem.Allocator, inputs: anytype, expected: Demand, global: *counter.Counter) ![32]u8 {
    if (global.kind != .range_check_8_8 or global.values.len != @import("../air/lookups/tables/schema.zig").size(.range_check_8_8)) return error.InvalidV5MemoryByteCounter;
    var local = try counter.Counter.init(a, .range_check_8_8);
    defer local.deinit(a);
    var events: u64 = 0;
    for (inputs) |input| {
        for (0..input.trace.domainSize()) |logical| events += @intFromBool((try input.trace.row(logical)).active);
        _ = try bytes.collectCounter(a, input.trace, &local);
    }
    if (events != expected.event_count) return error.InvalidV5MemoryByteCensus;
    var total: u64 = 0;
    for (local.values) |value| total = try std.math.add(u64, total, value.toU32());
    if (total != expected.request_count) return error.InvalidV5MemoryByteCounter;
    const digest = @import("../air/block/memory_range_interaction_v2.zig").counterSnapshot(&local);
    for (global.values, local.values) |*value, addend| value.* = value.add(addend);
    return digest;
}
pub fn freshRequests(verified: anytype, expected: Demand, sealed_digest: [32]u8) !Q {
    if (!verified.packed_transition or verified.event_count != expected.event_count or !std.meta.eql(verified.sealed_digest, sealed_digest)) return error.InvalidFreshV5MemoryByteReceipt;
    var result = Q.zero();
    for (verified.range_claims) |parts| {
        comptime std.debug.assert(parts.len == bytes.BATCH_COUNT);
        for (parts) |part| result = result.add(part);
    }
    return result;
}
