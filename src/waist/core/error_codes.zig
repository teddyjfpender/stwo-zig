const std = @import("std");

/// Diagnostic metadata only; never part of a proof or transcript.
pub const Class = enum { invalid_input, verification_failed, resource_exhausted, unsupported, internal };
pub const Entry = struct { tag: []const u8, code: u16, class: Class, since: []const u8 };

pub const table = [_]Entry{
    .{ .tag = "InvalidLastLayerDegreeBound", .code = 0x1001, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "InvalidBlowupFactor", .code = 0x1002, .class = .invalid_input, .since = "1.0.0-rc.2" },
    .{ .tag = "InvalidStructure", .code = 0x1101, .class = .verification_failed, .since = "1.0.0-rc.3" },
    .{ .tag = "OodsNotMatching", .code = 0x1102, .class = .verification_failed, .since = "1.0.0-rc.3" },
    .{ .tag = "ProofOfWork", .code = 0x1103, .class = .verification_failed, .since = "1.0.0-rc.3" },
    .{ .tag = "ShapeMismatch", .code = 0x1104, .class = .verification_failed, .since = "1.0.0-rc.3" },
    .{ .tag = "EmptySampledSet", .code = 0x1105, .class = .verification_failed, .since = "1.0.0-rc.3" },
    .{ .tag = "EmptyTrees", .code = 0x1106, .class = .verification_failed, .since = "1.0.0-rc.3" },
    .{ .tag = "InvalidPreprocessedTree", .code = 0x1107, .class = .verification_failed, .since = "1.0.0-rc.3" },
    .{ .tag = "QueryPositionOutOfRange", .code = 0x1108, .class = .verification_failed, .since = "1.0.0-rc.3" },
    .{ .tag = "ColumnIndexOutOfBounds", .code = 0x1109, .class = .verification_failed, .since = "1.0.0-rc.3" },
    .{ .tag = "DivisionByZero", .code = 0x110a, .class = .verification_failed, .since = "1.0.0-rc.3" },
    .{ .tag = "DegenerateLine", .code = 0x110b, .class = .verification_failed, .since = "1.0.0-rc.3" },
    .{ .tag = "NonCanonical", .code = 0x110c, .class = .verification_failed, .since = "1.0.0-rc.3" },
    .{ .tag = "NonUniqueXCoordinates", .code = 0x110d, .class = .verification_failed, .since = "1.0.0-rc.3" },
    .{ .tag = "InvalidEvaluationLength", .code = 0x110e, .class = .verification_failed, .since = "1.0.0-rc.3" },
    .{ .tag = "InvalidNumFriLayers", .code = 0x110f, .class = .verification_failed, .since = "1.0.0-rc.3" },
    .{ .tag = "FirstLayerEvaluationsInvalid", .code = 0x1110, .class = .verification_failed, .since = "1.0.0-rc.3" },
    .{ .tag = "FirstLayerCommitmentInvalid", .code = 0x1111, .class = .verification_failed, .since = "1.0.0-rc.3" },
    .{ .tag = "InnerLayerCommitmentInvalid", .code = 0x1112, .class = .verification_failed, .since = "1.0.0-rc.3" },
    .{ .tag = "InnerLayerEvaluationsInvalid", .code = 0x1113, .class = .verification_failed, .since = "1.0.0-rc.3" },
    .{ .tag = "LastLayerDegreeInvalid", .code = 0x1114, .class = .verification_failed, .since = "1.0.0-rc.3" },
    .{ .tag = "LastLayerEvaluationsInvalid", .code = 0x1115, .class = .verification_failed, .since = "1.0.0-rc.3" },
    .{ .tag = "WitnessTooShort", .code = 0x1116, .class = .verification_failed, .since = "1.0.0-rc.3" },
    .{ .tag = "WitnessTooLong", .code = 0x1117, .class = .verification_failed, .since = "1.0.0-rc.3" },
    .{ .tag = "RootMismatch", .code = 0x1118, .class = .verification_failed, .since = "1.0.0-rc.3" },
    .{ .tag = "InvalidQueryShape", .code = 0x1119, .class = .verification_failed, .since = "1.0.0-rc.3" },
    .{ .tag = "DuplicateQueryMismatch", .code = 0x111a, .class = .verification_failed, .since = "1.0.0-rc.3" },
    .{ .tag = "OutOfMemory", .code = 0x111b, .class = .resource_exhausted, .since = "1.0.0-rc.3" },
    .{ .tag = "InvalidTreeHeight", .code = 0x1201, .class = .invalid_input, .since = "1.0.0-rc.4" },
    .{ .tag = "InvalidLiftingLogSize", .code = 0x1202, .class = .invalid_input, .since = "1.0.0-rc.4" },
};

pub fn fromFriConfig(err: @import("fri/config.zig").FriConfig.Error) Entry {
    return switch (err) {
        error.InvalidLastLayerDegreeBound => table[0],
        error.InvalidBlowupFactor => table[1],
    };
}

/// Complete typed error set of PCS verification, excluding caller component callbacks.
pub const PcsVerificationError = @import("verifier_types.zig").VerificationError || std.mem.Allocator.Error;

pub fn fromPcs(err: PcsVerificationError) Entry {
    return switch (err) {
        error.InvalidStructure => table[2],
        error.OodsNotMatching => table[3],
        error.ProofOfWork => table[4],
        error.ShapeMismatch => table[5],
        error.EmptySampledSet => table[6],
        error.EmptyTrees => table[7],
        error.InvalidPreprocessedTree => table[8],
        error.QueryPositionOutOfRange => table[9],
        error.ColumnIndexOutOfBounds => table[10],
        error.DivisionByZero => table[11],
        error.DegenerateLine => table[12],
        error.NonCanonical => table[13],
        error.NonUniqueXCoordinates => table[14],
        error.InvalidEvaluationLength => table[15],
        error.InvalidNumFriLayers => table[16],
        error.FirstLayerEvaluationsInvalid => table[17],
        error.FirstLayerCommitmentInvalid => table[18],
        error.InnerLayerCommitmentInvalid => table[19],
        error.InnerLayerEvaluationsInvalid => table[20],
        error.LastLayerDegreeInvalid => table[21],
        error.LastLayerEvaluationsInvalid => table[22],
        error.WitnessTooShort => table[23],
        error.WitnessTooLong => table[24],
        error.RootMismatch => table[25],
        error.InvalidQueryShape => table[26],
        error.DuplicateQueryMismatch => table[27],
        error.OutOfMemory => table[28],
    };
}

pub fn recordPcsFailure(output: ?*?Entry, err: PcsVerificationError) PcsVerificationError {
    if (output) |sink| if (sink.* == null) {
        sink.* = fromPcs(err);
    };
    return err;
}

pub const RevisionConfigurationError = @import("pcs/config.zig").PcsConfigV2.Error;
pub const RevisionConfigurationFailure = struct { cause: RevisionConfigurationError, entry: Entry };
pub fn fromRevisionConfig(err: RevisionConfigurationError) Entry {
    return switch (err) {
        error.InvalidTreeHeight => table[29],
        error.InvalidLiftingLogSize => table[30],
    };
}
pub fn recordRevisionConfig(failure: ?*?RevisionConfigurationFailure, err: RevisionConfigurationError) void {
    if (failure) |sink| sink.* = .{ .cause = err, .entry = fromRevisionConfig(err) };
}

pub fn lookup(code: u16) ?Entry {
    for (table) |entry| if (entry.code == code) return entry;
    return null;
}

test "api signature: boundary metadata uses u16 codes and stable class tags" {
    try std.testing.expect(@typeInfo(Entry).@"struct".fields[1].type == u16);
    const names = [_][]const u8{ "invalid_input", "verification_failed", "resource_exhausted", "unsupported", "internal" };
    try std.testing.expectEqual(names.len, std.meta.fields(Class).len);
    inline for (std.meta.fields(Class), 0..) |field, i| try std.testing.expectEqualStrings(names[i], field.name);
}

test "core FRI configuration diagnostics retain exact typed origin and meanings" {
    const F = @import("fri/config.zig").FriConfig;
    try std.testing.expect(@typeInfo(@TypeOf(fromFriConfig)).@"fn".params[0].type.? == F.Error);
    const invalid_degree = F.init(11, 1, 70) catch |err| {
        const entry = fromFriConfig(err);
        try std.testing.expectEqual(@as(u16, 0x1001), entry.code);
        try std.testing.expectEqualStrings("InvalidLastLayerDegreeBound", entry.tag);
        try std.testing.expectEqual(Class.invalid_input, entry.class);
        try std.testing.expectEqualStrings("1.0.0-rc.2", entry.since);
        try std.testing.expectEqualStrings(entry.tag, lookup(entry.code).?.tag);
        return;
    };
    _ = invalid_degree;
    return error.ExpectedRejection;
}

test "core FRI configuration codes reject foreign IDs without changing admission" {
    const F = @import("fri/config.zig").FriConfig;
    try std.testing.expectError(error.InvalidBlowupFactor, F.init(0, 0, 70));
    try std.testing.expectEqual(@as(u16, 0x1002), fromFriConfig(error.InvalidBlowupFactor).code);
    try std.testing.expectEqualStrings("InvalidBlowupFactor", fromFriConfig(error.InvalidBlowupFactor).tag);
    try std.testing.expectEqual(Class.invalid_input, fromFriConfig(error.InvalidBlowupFactor).class);
    try std.testing.expectEqualStrings("1.0.0-rc.2", fromFriConfig(error.InvalidBlowupFactor).since);
    try std.testing.expectEqual(@as(u32, 1), (try F.init(0, 1, 70)).log_blowup_factor);
    for ([_]u16{ 0, 0x1000, 0x1003, 0x2001, 0x4001, 0x5002, 65535 }) |code| try std.testing.expect(lookup(code) == null);
}

test "Core verification diagnostics pin typed owned meanings and foreign refusal" {
    const V = @import("verifier_types.zig").VerificationError;
    try std.testing.expect(@typeInfo(@TypeOf(fromPcs)).@"fn".params[0].type.? == (V || std.mem.Allocator.Error));
    const failures = [_]PcsVerificationError{ error.InvalidStructure, error.OodsNotMatching, error.ProofOfWork, error.ShapeMismatch, error.EmptySampledSet, error.EmptyTrees, error.InvalidPreprocessedTree, error.QueryPositionOutOfRange, error.ColumnIndexOutOfBounds, error.DivisionByZero, error.DegenerateLine, error.NonCanonical, error.NonUniqueXCoordinates, error.InvalidEvaluationLength, error.InvalidNumFriLayers, error.FirstLayerEvaluationsInvalid, error.FirstLayerCommitmentInvalid, error.InnerLayerCommitmentInvalid, error.InnerLayerEvaluationsInvalid, error.LastLayerDegreeInvalid, error.LastLayerEvaluationsInvalid, error.WitnessTooShort, error.WitnessTooLong, error.RootMismatch, error.InvalidQueryShape, error.DuplicateQueryMismatch, error.OutOfMemory };
    for (failures, 0..) |err, index| {
        const entry = fromPcs(err);
        try std.testing.expectEqual(@as(u16, @intCast(0x1101 + index)), entry.code);
        try std.testing.expectEqualStrings(@errorName(err), entry.tag);
        try std.testing.expectEqualStrings("1.0.0-rc.3", entry.since);
        try std.testing.expectEqual(if (err == error.OutOfMemory) Class.resource_exhausted else .verification_failed, entry.class);
        try std.testing.expectEqualStrings(entry.tag, lookup(entry.code).?.tag);
    }
    for ([_]u16{ 0x1000, 0x1003, 0x1100, 0x111c, 0x2001, 0x4001, 65535 }) |code| try std.testing.expect(lookup(code) == null);
    var retained: ?Entry = null;
    try std.testing.expectEqual(error.RootMismatch, recordPcsFailure(&retained, error.RootMismatch));
    try std.testing.expectEqual(error.OodsNotMatching, recordPcsFailure(&retained, error.OodsNotMatching));
    try std.testing.expectEqual(@as(u16, 0x1118), retained.?.code);
}

test "revision configuration diagnostics pin exact owned lifting errors" {
    const Error = @import("pcs/config.zig").PcsConfigV2.Error;
    try std.testing.expect(@typeInfo(@TypeOf(fromRevisionConfig)).@"fn".params[0].type.? == Error);
    for ([_]Error{ error.InvalidTreeHeight, error.InvalidLiftingLogSize }, [_]u16{ 0x1201, 0x1202 }) |err, code| {
        const entry = fromRevisionConfig(err);
        try std.testing.expectEqual(code, entry.code);
        try std.testing.expectEqualStrings(@errorName(err), entry.tag);
        try std.testing.expectEqualStrings("1.0.0-rc.4", entry.since);
        try std.testing.expectEqual(Class.invalid_input, entry.class);
    }
}
