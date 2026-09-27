//! Packed initial/final relations reuse canonical independently pinned file
//! validation. The public sums never authorize proof receipts on their own.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const sources = @import("block_v5_initial_sources_v1.zig");
const initial = @import("block_v5_initial_source_receiver_v1.zig");
const endpoints = @import("block_v5_rw_endpoint_sources_v1.zig");
const seal = @import("block_v5_source_seal_v1.zig");
const protocol = @import("block_v5_word_memory_protocol_v1.zig");
const Transition = @import("../air/block/memory_transition.zig").Transition;
pub const Claims = struct { initial_sum: Q, endpoint_sum: Q, initial: initial.SourceClaims, endpoints: endpoints.Claims };
pub fn check(a: std.mem.Allocator, pins: endpoints.Pins, public_input: []const u8, files: endpoints.Sources, v5_pins: seal.Pins, entries: []const seal.Entry, sealed: seal.Sealed) !Claims {
    // These routines authenticate canonical ordering, classification, values,
    // full sparse roots and independent plan pins. Their old bus sums are not
    // used as packed relation authority; both selected suffixes stay distinct.
    const initial_claims = try initial.check(a, pins.initial, public_input, files.initial, v5_pins, entries, sealed);
    const endpoint_claims = try endpoints.check(a, pins, public_input, files, v5_pins, entries, sealed);
    const touches = try sources.readPinned(a, files.initial.first_touches, pins.initial.first_touches, sources.TOUCH_RECORD_BYTES);
    defer a.free(touches);
    const final = try sources.readPinned(a, files.endpoints, pins.endpoints, endpoints.RECORD_BYTES);
    defer a.free(final);
    const challenges = try protocol.Challenges.draw(a, sealed);
    var initial_sum = Q.zero();
    var endpoint_sum = Q.zero();
    var denominators: [1024]Q = undefined;
    var inverses: [1024]Q = undefined;
    var pending: usize = 0;
    for (0..@intCast(pins.initial.first_touches.records)) |index| {
        const record = touches[index * sources.TOUCH_RECORD_BYTES ..][0..sources.TOUCH_RECORD_BYTES];
        const value = Transition{ .space = @intCast(record[0]), .address = sources.readWord(record[1..5]), .clock = 0, .before = sources.readWord(record[5..9]), .after = 0 };
        denominators[pending] = challenges.initial.combineBase(protocol.initialTuple(value));
        pending += 1;
        if (pending == denominators.len) {
            try flush(&initial_sum, denominators[0..pending], inverses[0..pending]);
            pending = 0;
        }
    }
    try flush(&initial_sum, denominators[0..pending], inverses[0..pending]);
    pending = 0;
    for (0..@intCast(pins.endpoints.records)) |index| {
        const record = final[index * endpoints.RECORD_BYTES ..][0..endpoints.RECORD_BYTES];
        const clock_bytes: [8]u8 = record[4..12].*;
        const value = Transition{ .space = 1, .address = sources.readWord(record[0..4]), .clock = std.mem.readInt(u64, &clock_bytes, .little), .before = 0, .after = sources.readWord(record[12..16]) };
        denominators[pending] = challenges.endpoint.combineBase(protocol.endpointTuple(value));
        pending += 1;
        if (pending == denominators.len) {
            try flush(&endpoint_sum, denominators[0..pending], inverses[0..pending]);
            pending = 0;
        }
    }
    try flush(&endpoint_sum, denominators[0..pending], inverses[0..pending]);
    return .{ .initial_sum = initial_sum, .endpoint_sum = endpoint_sum, .initial = initial_claims, .endpoints = endpoint_claims };
}
fn flush(sum: *Q, denominators: []Q, inverses: []Q) !void {
    if (denominators.len == 0) return;
    try core.fields.batchInverseInPlace(Q, denominators, inverses);
    for (inverses) |inverse| sum.* = sum.add(inverse);
}
