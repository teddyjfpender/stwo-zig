const std = @import("std");
const core = @import("stwo_core");
const Types = @import("block_v6_mixed_claim_types_v1.zig");
const Codec = @import("block_v6_mixed_claim_codec_v1.zig");
const Reconstruct = @import("block_v6_mixed_claim_reconstruct_v1.zig");
fn fixture() struct { records: [9]Types.Record, expected: [9]Types.Bus.Expected } {
    var records: [9]Types.Record = undefined;
    var expected: [9]Types.Bus.Expected = undefined;
    inline for (std.meta.fields(Types.Family), 0..) |field, i| {
        const family: Types.Family = @enumFromInt(field.value);
        const payload: Types.Payload(family) = switch (family) {
            .native => .{ .projection = &.{}, .memory = &.{} },
            .caller_fused => .{ .program_claims = &.{}, .state_claims = &.{}, .table_claims = &.{}, .memory_claims = &.{} },
            else => std.mem.zeroes(Types.Payload(family)),
        };
        records[i] = .{ .index = 0, .claim = @unionInit(Types.Claim, field.name, payload) };
        expected[i] = switch (family) {
            .native => .{ .native = .{ .index = 0, .template = @splat(1) } },
            .range16, .ram_lanes, .program_table, .native_lookup => .{ .provider = .{ .family = @field(Types.Bus.Provider.Family, field.name), .index = 0, .template = @splat(1), .sealed = @splat(2), .roots = .{ @splat(3), @splat(4) } } },
            else => .{ .auxiliary = .{ .family = @field(Types.Bus.Auxiliary.Family, field.name), .index = 0, .template = @splat(1) } },
        };
    }
    return .{ .records = records, .expected = expected };
}
test "mixed claims codec all nine families canonical bounded and independent roster" {
    const a = std.testing.allocator;
    const f = fixture();
    const bytes = try Codec.encode(a, &f.records, &f.expected, .{});
    defer a.free(bytes);
    var decoded = try Codec.decode(a, bytes, &f.expected, .{});
    defer decoded.deinit();
    try std.testing.expectEqual(@as(usize, 9), decoded.records.len);
    const canonical = try Codec.encode(a, decoded.records, &f.expected, .{});
    defer a.free(canonical);
    try std.testing.expectEqualSlices(u8, bytes, canonical);
    // Claims remain proposals; fake all-zero arithmetic is never reconstructed
    // or called a proof. The original admission remains mandatory.
    try std.testing.expectError(error.InvalidMixedDirectCount, Reconstruct.reconstruct(a, &.{}, &.{}, &.{}));
    try std.testing.expectError(error.UntrustedMixedClaimHeader, Codec.decode(a, bytes, f.expected[0..8], .{}));
}
test "mixed claims codec rejects truncation noncanonical fields count bombs and trailing bytes" {
    const a = std.testing.allocator;
    const f = fixture();
    const bytes = try Codec.encode(a, &f.records, &f.expected, .{});
    defer a.free(bytes);
    for ([_]usize{ 0, Codec.MAGIC.len, Codec.HEADER_BYTES - 1, bytes.len - 1 }) |length| {
        if (Codec.decode(a, bytes[0..length], &f.expected, .{})) |value| {
            var got = value;
            got.deinit();
            return error.AcceptedTruncatedMixedClaims;
        } else |_| {}
    }
    const changed = try a.dupe(u8, bytes);
    defer a.free(changed);
    // The first native proposal has two empty slice counts.
    std.mem.writeInt(u32, changed[Codec.HEADER_BYTES + 8 ..][0..4], std.math.maxInt(u32), .little);
    try std.testing.expectError(error.MixedClaimResourceLimit, Codec.decode(a, changed, &f.expected, .{}));
    @memcpy(changed, bytes);
    std.mem.writeInt(u32, changed[Codec.HEADER_BYTES + 24 ..][0..4], core.fields.m31.Modulus, .little);
    try std.testing.expectError(error.NonCanonicalM31, Codec.decode(a, changed, &f.expected, .{}));
    @memcpy(changed, bytes);
    std.mem.writeInt(u32, changed[Codec.HEADER_BYTES + 4 ..][0..4], 1, .little);
    try std.testing.expectError(error.UntrustedMixedClaimRoster, Codec.decode(a, changed, &f.expected, .{}));
    const trailing = try std.mem.concat(a, u8, &.{ bytes, &.{0} });
    defer a.free(trailing);
    try std.testing.expectError(error.TrailingMixedClaimBytes, Codec.decode(a, trailing, &f.expected, .{}));
    try std.testing.expectError(error.MixedClaimResourceLimit, Codec.decode(a, bytes, &f.expected, .{ .max_owned_bytes = 1 }));
    try std.testing.expectError(error.MixedClaimResourceLimit, Codec.decode(a, bytes, &f.expected, .{ .max_bytes = bytes.len - 1 }));
}

fn allocationRoundTrip(a: std.mem.Allocator) !void {
    var f = fixture();
    const Projection = std.meta.Elem(@FieldType(Types.Payload(.native), "projection"));
    const Memory = std.meta.Elem(@FieldType(Types.Payload(.native), "memory"));
    const projection = [_]Projection{ .{ .sum = .one(), .row_count = 2 }, .{ .sum = .zero(), .row_count = 4 } };
    const memory = [_]Memory{.{ .transition_sum = .one(), .universal_sum = .zero(), .active_count = 3, .range_claims = @splat(.zero()) }};
    f.records[0].claim.native = .{ .projection = &projection, .memory = &memory };
    const bytes = try Codec.encode(a, &f.records, &f.expected, .{});
    defer a.free(bytes);
    var decoded = try Codec.decode(a, bytes, &f.expected, .{});
    defer decoded.deinit();
    try std.testing.expectEqual(@as(usize, 2), decoded.records[0].claim.native.projection.len);
    try std.testing.expectEqual(@as(u64, 3), decoded.records[0].claim.native.memory[0].active_count);
}
test "mixed claims codec allocation failures release every partial typed claim" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationRoundTrip, .{});
}
