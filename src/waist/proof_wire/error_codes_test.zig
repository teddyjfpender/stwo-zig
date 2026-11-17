//! Origin-specific decoder diagnostics; these never participate in proof bytes.
const std = @import("std");
const wire = @import("mod.zig");
const core = @import("stwo_core");
const Entry = core.error_codes.Entry;

test "proof wire diagnostics pin owned codes and refuse unknown provider bands" {
    const Codes = wire.error_codes;
    const info = @typeInfo(@TypeOf(Codes.fromCodec)).@"fn";
    try std.testing.expect(info.params[0].type.? == wire.CodecError);
    try std.testing.expect(info.return_type.? == Entry);
    const errors = [_]wire.CodecError{ error.NonCanonicalM31, error.ValueOutOfRange, error.InvalidBinaryProof, error.UnsupportedBinaryVersion, error.NonCanonicalPoseidonDigest };
    try std.testing.expectEqual(@as(usize, 21), Codes.table.len);
    for (errors, 0..) |err, index| {
        const entry = Codes.fromCodec(err);
        try std.testing.expectEqual(@as(u16, @intCast(0x4001 + index)), entry.code);
        try std.testing.expectEqualStrings(@errorName(err), entry.tag);
        try std.testing.expectEqualStrings("1.0.0-rc.2", entry.since);
        try std.testing.expectEqual(if (err == error.UnsupportedBinaryVersion) core.error_codes.Class.unsupported else .invalid_input, entry.class);
        try std.testing.expectEqualStrings(entry.tag, Codes.lookup(entry.code).?.tag);
    }
    for ([_]u16{ 0, 0x1001, 0x3001, 0x4000, 0x4006, 0x5002, 65535 }) |code| try std.testing.expect(Codes.lookup(code) == null);
}

test "proof wire diagnostics retain exact decode errors and code owned parser allocation origins" {
    inline for (.{ core.fields.qm31.QM31, core.fields.om31.OM31 }) |Secure| {
        const W = wire.ForField(Secure);
        var diagnostic: ?Entry = wire.error_codes.fromCodec(error.ValueOutOfRange);
        try std.testing.expectError(error.InvalidBinaryProof, W.decodeProofBytesBinaryWithDiagnostic(std.testing.allocator, "", &diagnostic));
        try std.testing.expectEqual(@as(u16, 0x4003), diagnostic.?.code);
        try std.testing.expectError(error.UnsupportedBinaryVersion, W.decodeProofBytesBinaryWithDiagnostic(std.testing.allocator, "NOTSTWO!", &diagnostic));
        try std.testing.expectEqual(@as(u16, 0x4004), diagnostic.?.code);
        try std.testing.expectError(error.SyntaxError, W.decodeProofBytesWithDiagnostic(std.testing.allocator, "!", &diagnostic));
        try std.testing.expectEqual(@as(u16, 0x4101), diagnostic.?.code);
        var fail = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        try std.testing.expectError(error.OutOfMemory, W.decodeProofBytesWithDiagnostic(fail.allocator(), "{}", &diagnostic));
        try std.testing.expectEqual(@as(u16, 0x410e), diagnostic.?.code);
        try std.testing.expectEqual(fail.allocated_bytes, fail.freed_bytes);
        try std.testing.expectError(error.InvalidBinaryProof, W.decodeProofBytesBinaryWithDiagnostic(std.testing.allocator, "", null));
    }
}

test "proof wire complete-buffer input codes pin parser config and resource origins" {
    const C = wire.error_codes;
    try std.testing.expect(@typeInfo(@TypeOf(C.fromJsonInput)).@"fn".params[0].type.? == std.json.ParseError(std.json.Scanner));
    const errors = [_]C.JsonInputError{ error.SyntaxError, error.UnexpectedEndOfInput, error.UnexpectedToken, error.InvalidNumber, error.Overflow, error.InvalidEnumTag, error.DuplicateField, error.UnknownField, error.MissingField, error.LengthMismatch, error.InvalidCharacter, error.BufferUnderrun, error.ValueTooLong, error.OutOfMemory };
    for (errors, 0..) |err, index| {
        const entry = C.fromJsonInput(err);
        try std.testing.expectEqual(@as(u16, @intCast(0x4101 + index)), entry.code);
        try std.testing.expectEqualStrings(@errorName(err), entry.tag);
        try std.testing.expectEqualStrings("1.0.0-rc.3", entry.since);
        try std.testing.expectEqual(if (err == error.ValueTooLong or err == error.OutOfMemory) core.error_codes.Class.resource_exhausted else .invalid_input, entry.class);
    }
    try std.testing.expectEqual(@as(u16, 0x4201), C.fromConfig(error.InvalidLastLayerDegreeBound).code);
    try std.testing.expectEqual(@as(u16, 0x4202), C.fromConfig(error.InvalidBlowupFactor).code);
    for ([_]u16{ 0x4100, 0x410f, 0x4200, 0x4203 }) |code| try std.testing.expect(C.lookup(code) == null);
}

fn inputFixture(comptime W: type, a: std.mem.Allocator) !W.Proof {
    var polynomial = [_]W.SecureWire{@splat(0)};
    return W.wireToProof(a, .{
        .config = .{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 3 } },
        .commitments = &.{},
        .sampled_values = &.{},
        .decommitments = &.{},
        .queried_values = &.{},
        .proof_of_work = 0,
        .fri_proof = .{ .first_layer = .{ .fri_witness = &.{}, .decommitment = .{ .hash_witness = &.{} }, .commitment = @splat(0) }, .inner_layers = &.{}, .last_layer_poly = &polynomial },
    });
}

test "proof wire real byte decoders bind parser config and owned allocation errors" {
    const a = std.testing.allocator;
    inline for (.{ core.fields.qm31.QM31, core.fields.om31.OM31 }) |S| {
        const W = wire.ForField(S);
        var proof = try inputFixture(W, a);
        defer proof.deinit(a);
        const json = try W.encodeProofBytes(a, proof);
        defer a.free(json);
        const binary = try W.encodeProofBytesBinary(a, proof);
        defer a.free(binary);
        var diagnostic: ?Entry = null;
        try std.testing.expectError(error.MissingField, W.decodeProofBytesWithDiagnostic(a, "{}", &diagnostic));
        try std.testing.expectEqual(@as(u16, 0x4109), diagnostic.?.code);
        try std.testing.expectError(error.UnexpectedToken, W.decodeProofBytesWithDiagnostic(a, "[]", &diagnostic));
        try std.testing.expectEqual(@as(u16, 0x4103), diagnostic.?.code);
        const invalid_json = try std.mem.replaceOwned(u8, a, json, "\"log_blowup_factor\":1", "\"log_blowup_factor\":0");
        defer a.free(invalid_json);
        try std.testing.expectError(error.InvalidBlowupFactor, W.decodeProofBytesWithDiagnostic(a, invalid_json, &diagnostic));
        try std.testing.expectEqual(@as(u16, 0x4202), diagnostic.?.code);
        const malformed = [_]struct { old: []const u8, replacement: []const u8, cause: wire.error_codes.JsonInputError, code: u16 }{
            .{ .old = "\"pow_bits\":0", .replacement = "\"pow_bits\":0,\"pow_bits\":0", .cause = error.DuplicateField, .code = 0x4107 },
            .{ .old = "\"pow_bits\":0", .replacement = "\"unknown\":0,\"pow_bits\":0", .cause = error.UnknownField, .code = 0x4108 },
            .{ .old = "\"pow_bits\":0", .replacement = "\"pow_bits\":4294967296", .cause = error.Overflow, .code = 0x4105 },
            .{ .old = "\"pow_bits\":0", .replacement = "\"pow_bits\":\"bad\"", .cause = error.InvalidCharacter, .code = 0x410b },
            .{ .old = "\"pow_bits\":0", .replacement = "\"pow_bits\":1.5", .cause = error.InvalidNumber, .code = 0x4104 },
        };
        for (malformed) |case| {
            const bytes = try std.mem.replaceOwned(u8, a, json, case.old, case.replacement);
            defer a.free(bytes);
            try std.testing.expectError(case.cause, W.decodeProofBytesWithDiagnostic(a, bytes, &diagnostic));
            try std.testing.expectEqual(case.code, diagnostic.?.code);
        }
        const bad_binary = try a.dupe(u8, binary);
        defer a.free(bad_binary);
        std.mem.writeInt(u32, bad_binary[16..20], 11, .little);
        try std.testing.expectError(error.InvalidLastLayerDegreeBound, W.decodeProofBytesBinaryWithDiagnostic(a, bad_binary, &diagnostic));
        try std.testing.expectEqual(@as(u16, 0x4201), diagnostic.?.code);
        const Runner = struct {
            fn run(allocator: std.mem.Allocator, bytes: []const u8, is_binary: bool) !void {
                var detail: ?Entry = null;
                var decoded = (if (is_binary) W.decodeProofBytesBinaryWithDiagnostic(allocator, bytes, &detail) else W.decodeProofBytesWithDiagnostic(allocator, bytes, &detail)) catch |err| {
                    try std.testing.expectEqual(@as(u16, 0x410e), detail.?.code);
                    return err;
                };
                defer decoded.deinit(allocator);
                try std.testing.expect(detail == null);
                const back = if (is_binary) try W.encodeProofBytesBinary(allocator, decoded) else try W.encodeProofBytes(allocator, decoded);
                defer allocator.free(back);
                try std.testing.expectEqualSlices(u8, bytes, back);
            }
        };
        try std.testing.checkAllAllocationFailures(a, Runner.run, .{ json, false });
        try std.testing.checkAllAllocationFailures(a, Runner.run, .{ binary, true });
    }
}

test "proof wire custom hash JSON callback same-tag refusal remains foreign" {
    const Custom = struct {
        pub const Hash = extern struct {
            bytes: [32]u8,
            pub fn jsonParse(_: std.mem.Allocator, source: anytype, _: std.json.ParseOptions) std.json.ParseError(@TypeOf(source.*))!@This() {
                return error.SyntaxError;
            }
        };
    };
    const W = @import("family.zig").ForHasher(core.fields.qm31.QM31, Custom);
    var diagnostic: ?Entry = null;
    try std.testing.expectError(error.SyntaxError, W.decodeProofBytesWithDiagnostic(std.testing.allocator,
        \\{"config":{"pow_bits":0,"fri_config":{"log_blowup_factor":1,"log_last_layer_degree_bound":0,"n_queries":3}},"commitments":[{}]}
    , &diagnostic));
    try std.testing.expect(diagnostic == null);
}
