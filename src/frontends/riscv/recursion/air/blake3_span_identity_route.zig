//! Verifier-owned routing for the exact native Span identity preimage.
//! Source endpoints must be emitted by canonical field-byte encoding of the
//! authenticated statement. This plan alone does not authenticate that producer.
const std = @import("std");
const core = @import("stwo_core");
const identity = @import("../span_identity_blake3.zig");
const graph = @import("blake3_hash_plan.zig");
const route = @import("blake3_byte_route.zig");
const WORD_COUNT = @typeInfo(identity.StatementWords).array.len;
pub const Caller = struct { circuit: u32, first_wire: u32 };
pub const Plan = struct {
    allocator: std.mem.Allocator,
    schedules: []route.Schedule,
    statement_uses: [WORD_COUNT]u32,
    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.schedules);
        self.* = undefined;
    }
};

/// Depends only on protocol purpose and verifier-assigned circuit coordinates.
/// In particular, no statement values or claimed digest enter preprocessing.
pub fn build(a: std.mem.Allocator, purpose: identity.Purpose, caller: Caller, hash_circuit: u32) !Plan {
    const p = core.fields.m31.Modulus;
    if (caller.circuit >= p or hash_circuit >= p or caller.circuit == hash_circuit or
        @as(u64, caller.first_wire) + WORD_COUNT > p) return error.InvalidSpanIdentityCaller;
    var hash = try graph.build(a, identity.byteCount(purpose));
    defer hash.deinit();
    var schedules: std.ArrayList(route.Schedule) = .empty;
    defer schedules.deinit(a);
    var uses: [WORD_COUNT]u32 = @splat(0);
    for (hash.sources) |source| switch (source.value) {
        .constant => {},
        .input => |part| {
            // The identity header and every canonical word are u32 aligned.
            if (part.offset % 4 != 0 or part.len != 4) return error.InvalidSpanIdentityAlignment;
            var schedule = route.Schedule{
                .sources = .{ null, null },
                .destination = .{ .circuit = hash_circuit, .wire = source.wire },
                .uses = hash.uses[source.wire],
                .bytes = @splat(.{ .constant = 0 }),
            };
            switch (try identity.sourceAt(purpose, part.offset / 4)) {
                .constant => |word| for (&schedule.bytes, 0..) |*byte, i| {
                    byte.* = .{ .constant = @truncate(word >> @as(u5, @intCast(i * 8))) };
                },
                .statement_word => |index| {
                    schedule.sources[0] = .{ .circuit = caller.circuit, .wire = caller.first_wire + index };
                    for (&schedule.bytes, 0..) |*byte, i| byte.* = .{ .source = .{ .word = 0, .byte = @intCast(i) } };
                    uses[index] = try std.math.add(u32, uses[index], 1);
                },
            }
            _ = try route.fixedRow(schedule);
            try schedules.append(a, schedule);
        },
    };
    return .{ .allocator = a, .schedules = try schedules.toOwnedSlice(a), .statement_uses = uses };
}
