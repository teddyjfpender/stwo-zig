//! Public codec qualifications; this does not claim a live felt-decoding CLI.
const std = @import("std");
const core = @import("stwo_core");
const felt = @import("interop_felt_json");
const stream = @import("circuit_felt_stream.zig");
const codes = @import("error_codes.zig");
const Q = core.fields.qm31.QM31;
const a = std.testing.allocator;
fn fixture(poly: []Q) stream.CairoCircuitProof {
    return .{ .output_values = &.{}, .interaction_pow = 0, .claimed_sums = @splat(Q.zero()), .channel_salt = 0, .stark_proof = .{
        .fri_config = .{ .pow_bits = 0, .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 3, .fold_step = 1 },
        .commitments = &.{},
        .sampled_values = &.{},
        .decommitments = &.{},
        .queried_values = &.{},
        .proof_of_work = 0,
        .fri_proof = .{ .first_layer = .{ .fri_witness = &.{}, .decommitment = &.{}, .commitment = @splat(0) }, .inner_layers = &.{}, .last_layer_poly = poly },
    } };
}

test "felt framing public codecs preserve canonical bytes and every allocation cleanup" {
    var poly = [_]Q{Q.zero()};
    const proof = fixture(&poly);
    var output: std.Io.Writer.Allocating = .init(a);
    defer output.deinit();
    var detail: ?core.error_codes.Entry = null;
    try stream.writeJsonDiagnosed(&output.writer, &proof, &detail);
    try std.testing.expect(detail == null);
    const Runner = struct {
        fn run(allocator: std.mem.Allocator, bytes: []const u8) !void {
            var failure: ?core.error_codes.Entry = null;
            var decoded = stream.decodeJsonDiagnosed(allocator, bytes, &failure) catch |err| {
                try std.testing.expect(err == error.OutOfMemory);
                try std.testing.expect(failure.?.code == 0x5606 or failure.?.code == 0x5704);
                return err;
            };
            defer decoded.deinit();
            try std.testing.expect(failure == null);
            var storage: [8192]u8 = undefined;
            var back = std.Io.Writer.fixed(&storage);
            try stream.writeJson(&back, &decoded.proof);
            try std.testing.expectEqualStrings(bytes, back.buffered());
        }
    };
    try Runner.run(a, output.written());
    try std.testing.checkAllAllocationFailures(a, Runner.run, .{output.written()});
    var values: std.ArrayList(u64) = .empty;
    defer values.deinit(a);
    try stream.encode(felt.FeltList{ .list = &values, .allocator = a }, &proof);
    for (0..values.items.len) |end| {
        // At the line-poly length, the declared one element exceeds the
        // remaining zero felts. Every other prefix exhausts a scalar read.
        const expected = if (end == values.items.len - 6) error.ValueOutOfRange else error.EndOfStream;
        try std.testing.expectError(expected, stream.decodeDiagnosed(a, values.items[0..end], &detail));
        try std.testing.expectEqual(@as(u16, if (expected == error.EndOfStream) 0x5601 else 0x5602), detail.?.code);
    }
    try std.testing.expectEqual(@as(u16, 0x5601), detail.?.code);
    values.items[values.items.len - 1] = @as(u64, 1) << 32;
    try std.testing.expectError(error.ValueOutOfRange, stream.decodeDiagnosed(a, values.items, &detail));
    try std.testing.expectEqual(@as(u16, 0x5602), detail.?.code);
    values.items[values.items.len - 1] = 0;
    values.items[values.items.len - 2] = 1;
    try std.testing.expectError(error.InvalidLinePoly, stream.decodeDiagnosed(a, values.items, &detail));
    try std.testing.expectEqual(@as(u16, 0x5604), detail.?.code);
    values.items[values.items.len - 2] = 0;
    try values.append(a, 0);
    try std.testing.expectError(error.TrailingData, stream.decodeDiagnosed(a, values.items, &detail));
    try std.testing.expectEqual(@as(u16, 0x5605), detail.?.code);
    var option = felt.FeltReader{ .felts = &.{2} };
    if (option.isSome()) |_| return error.ExpectedDiscriminantFailure else |err| try std.testing.expectEqual(@as(u16, 0x5603), codes.fromFeltPrimitive(err).code);
}

test "felt framing separates JSON scalar and concrete writer failures" {
    var detail: ?core.error_codes.Entry = null;
    try std.testing.expectError(error.InvalidFeltJson, stream.decodeJsonDiagnosed(a, "!", &detail));
    try std.testing.expectEqual(@as(u16, 0x5701), detail.?.code);
    try std.testing.expectError(error.NonCanonicalFelt, stream.decodeJsonDiagnosed(a, "[\"0x00\"]", &detail));
    try std.testing.expectEqual(@as(u16, 0x5702), detail.?.code);
    try std.testing.expectError(error.ValueOutOfRange, stream.decodeJsonDiagnosed(a, "[\"0x10000000000000000\"]", &detail));
    try std.testing.expectEqual(@as(u16, 0x5703), detail.?.code);
    const invalid = fixture(&.{});
    var legacy: std.Io.Writer.Allocating = .init(a);
    defer legacy.deinit();
    var diagnosed: std.Io.Writer.Allocating = .init(a);
    defer diagnosed.deinit();
    try std.testing.expectError(error.InvalidLinePoly, stream.writeJson(&legacy.writer, &invalid));
    try std.testing.expectError(error.InvalidLinePoly, stream.writeJsonDiagnosed(&diagnosed.writer, &invalid, &detail));
    try std.testing.expectEqualStrings(legacy.written(), diagnosed.written());
    try std.testing.expectEqual(@as(u16, 0x5902), detail.?.code);
    var poly = [_]Q{Q.zero()};
    const valid = fixture(&poly);
    var none: [0]u8 = .{};
    var failing = std.Io.Writer.fixed(&none);
    try std.testing.expectError(error.WriteFailed, stream.writeJsonDiagnosed(&failing, &valid, &detail));
    try std.testing.expect(detail == null);
    const Foreign = struct {
        pub fn felt(_: @This(), _: u64) anyerror!void {
            return error.InvalidLinePoly;
        }
    };
    try std.testing.expectError(error.InvalidLinePoly, stream.encode(Foreign{}, &valid));
}
