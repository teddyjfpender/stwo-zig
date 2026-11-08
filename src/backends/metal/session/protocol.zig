const std = @import("std");

pub const protocol_name = "stwo-zig-metal-prover-session";
// Version 4 requires a pinned canonical Rust verifier at session startup and
// digest-bound Rust verification evidence for every published proof.
pub const protocol_version: u32 = 4;
pub const prove_timing_scope = "recorded_witness_start_to_verified_proof";
pub const max_frame_bytes: usize = 4 * 1024 * 1024;

pub const ObjectArtifactRef = struct {
    object_id: []const u8,
    bytes: u64,
    diagnostic_path: []const u8,
};

pub const ArtifactRef = union(enum) {
    path: []const u8,
    object: ObjectArtifactRef,

    pub fn diagnosticPath(self: ArtifactRef) []const u8 {
        return switch (self) {
            .path => |path| path,
            .object => |object| object.diagnostic_path,
        };
    }
};

pub const Artifacts = struct {
    adapted_input: ArtifactRef,
    schedule: ArtifactRef,
    witness_programs: ArtifactRef,
    multiplicity_feeds: ArtifactRef,
    relation_templates: ArtifactRef,
    fixed_tables: ArtifactRef,
    composition: ArtifactRef,
    composition_program: ArtifactRef,
    preprocessed_evaluations: ArtifactRef,
    preprocessed_tree0_merkle: ArtifactRef,
    preprocessed_coefficients: ArtifactRef,
    transcript_reference: ?ArtifactRef,
    quotient_reference: ?ArtifactRef,
};

pub const Request = struct {
    sequence: u64,
    request_id: []const u8,
    artifacts: Artifacts,
    proof_output: []const u8,
    report_output: []const u8,
    budget_gib: []const u8,
    expected_tree0_root_hex: []const u8,
};

pub const ParsedRequest = struct {
    parsed: std.json.Parsed(std.json.Value),
    request: Request,

    pub fn deinit(self: *ParsedRequest) void {
        self.parsed.deinit();
        self.* = undefined;
    }
};

pub const FrameKind = enum { prove, shutdown };

pub fn frameKind(allocator: std.mem.Allocator, line: []const u8) !FrameKind {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, line, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidFrame;
    const value = parsed.value.object.get("type") orelse return error.InvalidFrame;
    if (value != .string) return error.InvalidFrame;
    if (std.mem.eql(u8, value.string, "prove")) return .prove;
    if (std.mem.eql(u8, value.string, "shutdown")) return .shutdown;
    return error.InvalidFrame;
}

pub fn parseRequest(
    allocator: std.mem.Allocator,
    line: []const u8,
    expected_sequence: u64,
    validate_files: bool,
) !ParsedRequest {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, line, .{});
    errdefer parsed.deinit();
    if (parsed.value != .object) return error.InvalidRequest;
    const object = parsed.value.object;
    try exactKeys(object, &.{
        "protocol", "version", "type", "sequence", "request_id", "artifacts", "outputs", "budget_gib", "expected_tree0_root_hex",
    });
    try expectString(object, "protocol", protocol_name);
    try expectInteger(object, "version", protocol_version);
    try expectString(object, "type", "prove");

    const sequence_value = object.get("sequence").?;
    if (sequence_value != .integer or sequence_value.integer < 0) return error.InvalidSequence;
    const sequence: u64 = @intCast(sequence_value.integer);
    if (sequence != expected_sequence) return error.InvalidSequence;
    const request_id = try stringField(object, "request_id");
    if (!validRequestId(request_id)) return error.InvalidRequestId;
    const budget_gib = try stringField(object, "budget_gib");
    const budget = std.fmt.parseFloat(f64, budget_gib) catch return error.InvalidBudget;
    if (!std.math.isFinite(budget) or budget <= 0) return error.InvalidBudget;
    const expected_tree0_root_hex = try stringField(object, "expected_tree0_root_hex");
    if (!validLowercaseHexDigest(expected_tree0_root_hex)) return error.InvalidTreeRoot;

    const artifact_value = object.get("artifacts").?;
    if (artifact_value != .object) return error.InvalidArtifacts;
    const artifact_object = artifact_value.object;
    try requiredOptionalKeys(artifact_object, &.{
        "adapted_input",
        "schedule",
        "witness_programs",
        "multiplicity_feeds",
        "relation_templates",
        "fixed_tables",
        "composition",
        "composition_program",
        "preprocessed_evaluations",
        "preprocessed_tree0_merkle",
        "preprocessed_coefficients",
    }, &.{
        "transcript_reference",
        "quotient_reference",
    });
    const artifacts = Artifacts{
        .adapted_input = try artifactRefField(artifact_object, "adapted_input"),
        .schedule = try artifactRefField(artifact_object, "schedule"),
        .witness_programs = try artifactRefField(artifact_object, "witness_programs"),
        .multiplicity_feeds = try artifactRefField(artifact_object, "multiplicity_feeds"),
        .relation_templates = try artifactRefField(artifact_object, "relation_templates"),
        .fixed_tables = try artifactRefField(artifact_object, "fixed_tables"),
        .composition = try artifactRefField(artifact_object, "composition"),
        .composition_program = try artifactRefField(artifact_object, "composition_program"),
        .preprocessed_evaluations = try artifactRefField(artifact_object, "preprocessed_evaluations"),
        .preprocessed_tree0_merkle = try artifactRefField(artifact_object, "preprocessed_tree0_merkle"),
        .preprocessed_coefficients = try artifactRefField(artifact_object, "preprocessed_coefficients"),
        .transcript_reference = try optionalArtifactRefField(artifact_object, "transcript_reference"),
        .quotient_reference = try optionalArtifactRefField(artifact_object, "quotient_reference"),
    };
    if (!validTreeCompanionRefs(artifacts.preprocessed_evaluations, artifacts.preprocessed_tree0_merkle))
        return error.InvalidTreeCompanion;

    const output_value = object.get("outputs").?;
    if (output_value != .object) return error.InvalidOutputs;
    const output_object = output_value.object;
    try exactKeys(output_object, &.{ "proof", "report" });
    const proof_output = try pathField(output_object, "proof");
    const report_output = try pathField(output_object, "report");
    if (std.mem.eql(u8, proof_output, report_output)) return error.InvalidOutputs;

    const request = Request{
        .sequence = sequence,
        .request_id = request_id,
        .artifacts = artifacts,
        .proof_output = proof_output,
        .report_output = report_output,
        .budget_gib = budget_gib,
        .expected_tree0_root_hex = expected_tree0_root_hex,
    };
    if (validate_files) try validatePaths(request);
    return .{ .parsed = parsed, .request = request };
}

pub fn validateShutdown(allocator: std.mem.Allocator, line: []const u8, next_sequence: u64) !void {
    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, line, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidShutdown;
    const object = parsed.value.object;
    try exactKeys(object, &.{ "protocol", "version", "type", "next_sequence" });
    try expectString(object, "protocol", protocol_name);
    try expectInteger(object, "version", protocol_version);
    try expectString(object, "type", "shutdown");
    const value = object.get("next_sequence").?;
    if (value != .integer or value.integer < 0 or @as(u64, @intCast(value.integer)) != next_sequence)
        return error.InvalidSequence;
}

fn validatePaths(request: Request) !void {
    inline for (std.meta.fields(Artifacts)) |field| {
        if (comptime field.type == ArtifactRef) {
            try validateArtifactRefPath(@field(request.artifacts, field.name));
        } else if (@field(request.artifacts, field.name)) |path| {
            try validateArtifactRefPath(path);
        }
    }
    inline for (.{ request.proof_output, request.report_output }) |path| {
        if (std.fs.accessAbsolute(path, .{})) |_| return error.OutputAlreadyExists else |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        }
        const parent = std.fs.path.dirname(path) orelse return error.InvalidPath;
        var directory = try std.fs.openDirAbsolute(parent, .{});
        directory.close();
    }
}

fn validateArtifactRefPath(reference: ArtifactRef) !void {
    switch (reference) {
        .path => |path| try validateArtifactPath(path),
        .object => {},
    }
}

fn validateArtifactPath(path: []const u8) !void {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    if ((try file.stat()).kind != .file) return error.InvalidArtifact;
}

fn artifactRefField(object: std.json.ObjectMap, name: []const u8) !ArtifactRef {
    const value = object.get(name) orelse return error.MissingField;
    if (value != .object) return error.InvalidArtifactRef;
    const reference = value.object;

    if (reference.count() == 1 and reference.contains("path")) {
        return .{ .path = try pathField(reference, "path") };
    }
    if (reference.count() == 3 and
        reference.contains("object_id") and
        reference.contains("bytes") and
        reference.contains("diagnostic_path"))
    {
        const object_id = try stringField(reference, "object_id");
        if (!validLowercaseHexDigest(object_id)) return error.InvalidObjectId;
        const bytes = try positiveU64Field(reference, "bytes");
        const diagnostic_path = try pathField(reference, "diagnostic_path");
        return .{ .object = .{
            .object_id = object_id,
            .bytes = bytes,
            .diagnostic_path = diagnostic_path,
        } };
    }
    return error.InvalidArtifactRef;
}

fn optionalArtifactRefField(object: std.json.ObjectMap, name: []const u8) !?ArtifactRef {
    if (!object.contains(name)) return null;
    return try artifactRefField(object, name);
}

fn positiveU64Field(object: std.json.ObjectMap, name: []const u8) !u64 {
    const value = object.get(name) orelse return error.MissingField;
    const parsed = switch (value) {
        .integer => |integer| if (integer > 0) @as(u64, @intCast(integer)) else return error.InvalidArtifactBytes,
        .number_string => |number| std.fmt.parseInt(u64, number, 10) catch return error.InvalidArtifactBytes,
        else => return error.InvalidArtifactBytes,
    };
    if (parsed == 0) return error.InvalidArtifactBytes;
    return parsed;
}

fn pathField(object: std.json.ObjectMap, name: []const u8) ![]const u8 {
    const path = try stringField(object, name);
    if (path.len == 0 or !std.fs.path.isAbsolute(path)) return error.InvalidPath;
    return path;
}

fn stringField(object: std.json.ObjectMap, name: []const u8) ![]const u8 {
    const value = object.get(name) orelse return error.MissingField;
    if (value != .string) return error.InvalidField;
    return value.string;
}

fn expectString(object: std.json.ObjectMap, name: []const u8, expected: []const u8) !void {
    if (!std.mem.eql(u8, try stringField(object, name), expected)) return error.InvalidField;
}

fn expectInteger(object: std.json.ObjectMap, name: []const u8, expected: u32) !void {
    const value = object.get(name) orelse return error.MissingField;
    if (value != .integer or value.integer != expected) return error.InvalidField;
}

fn exactKeys(object: std.json.ObjectMap, names: []const []const u8) !void {
    if (object.count() != names.len) return error.InvalidFields;
    for (names) |name| if (!object.contains(name)) return error.InvalidFields;
}

fn requiredOptionalKeys(
    object: std.json.ObjectMap,
    required: []const []const u8,
    optional: []const []const u8,
) !void {
    for (required) |name| if (!object.contains(name)) return error.InvalidFields;
    var iterator = object.iterator();
    while (iterator.next()) |entry| {
        var allowed = false;
        for (required) |name| allowed = allowed or std.mem.eql(u8, entry.key_ptr.*, name);
        for (optional) |name| allowed = allowed or std.mem.eql(u8, entry.key_ptr.*, name);
        if (!allowed) return error.InvalidFields;
    }
}

fn validRequestId(value: []const u8) bool {
    if (value.len == 0 or value.len > 128 or !std.ascii.isAlphanumeric(value[0])) return false;
    for (value[1..]) |byte| if (!std.ascii.isAlphanumeric(byte) and
        byte != '.' and byte != '_' and byte != ':' and byte != '-') return false;
    return true;
}

fn validLowercaseHexDigest(value: []const u8) bool {
    if (value.len != 64) return false;
    for (value) |byte| if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f')) return false;
    return true;
}

fn validTreeCompanionRefs(evaluations: ArtifactRef, tree: ArtifactRef) bool {
    const evaluation_path = switch (evaluations) {
        .path => |path| path,
        .object => return true,
    };
    const tree_path = switch (tree) {
        .path => |path| path,
        .object => return true,
    };
    return isTreeCompanion(evaluation_path, tree_path);
}

fn isTreeCompanion(evaluations: []const u8, tree: []const u8) bool {
    const suffix = ".tree0-merkle";
    return tree.len == evaluations.len + suffix.len and
        std.mem.eql(u8, tree[0..evaluations.len], evaluations) and
        std.mem.eql(u8, tree[evaluations.len..], suffix);
}

fn testArtifacts(
    allocator: std.mem.Allocator,
    adapted_input: []const u8,
    evaluations: []const u8,
    tree: []const u8,
    tail: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(allocator,
        \\{{"adapted_input":{s},"schedule":{{"path":"/b"}},"witness_programs":{{"path":"/c"}},"multiplicity_feeds":{{"path":"/d"}},"relation_templates":{{"path":"/e"}},"fixed_tables":{{"path":"/f"}},"composition":{{"path":"/g"}},"composition_program":{{"path":"/g.metallib"}},"preprocessed_evaluations":{s},"preprocessed_tree0_merkle":{s},"preprocessed_coefficients":{{"path":"/i"}}{s}}}
    , .{ adapted_input, evaluations, tree, tail });
}

fn testRequest(allocator: std.mem.Allocator, version: u32, sequence: u64, artifacts: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator,
        \\{{"protocol":"stwo-zig-metal-prover-session","version":{d},"type":"prove","sequence":{d},"request_id":"sn-{d}","artifacts":{s},"outputs":{{"proof":"/tmp/p","report":"/tmp/r"}},"budget_gib":"24","expected_tree0_root_hex":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}
    , .{ version, sequence, sequence, artifacts });
}

test "strict v4 parser accepts path references and explicit composition program" {
    const artifacts = try testArtifacts(
        std.testing.allocator,
        "{\"path\":\"/a\"}",
        "{\"path\":\"/h\"}",
        "{\"path\":\"/h.tree0-merkle\"}",
        ",\"transcript_reference\":{\"path\":\"/j\"},\"quotient_reference\":{\"path\":\"/k\"}",
    );
    defer std.testing.allocator.free(artifacts);
    const encoded = try testRequest(std.testing.allocator, protocol_version, 0, artifacts);
    defer std.testing.allocator.free(encoded);

    var parsed = try parseRequest(std.testing.allocator, encoded, 0, false);
    defer parsed.deinit();
    try std.testing.expectEqualStrings("/a", parsed.request.artifacts.adapted_input.diagnosticPath());
    try std.testing.expectEqualStrings("/g.metallib", parsed.request.artifacts.composition_program.diagnosticPath());
    try std.testing.expectEqualStrings("/j", parsed.request.artifacts.transcript_reference.?.diagnosticPath());
    try std.testing.expectEqualStrings(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        parsed.request.expected_tree0_root_hex,
    );
}

test "strict v4 parser accepts authenticated object references and full u64 bytes" {
    const object_ref =
        \\{"object_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bytes":18446744073709551615,"diagnostic_path":"/source/a"}
    ;
    const tree_ref =
        \\{"object_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","bytes":2,"diagnostic_path":"/source/tree"}
    ;
    const artifacts = try testArtifacts(std.testing.allocator, object_ref, object_ref, tree_ref, "");
    defer std.testing.allocator.free(artifacts);
    const encoded = try testRequest(std.testing.allocator, protocol_version, 0, artifacts);
    defer std.testing.allocator.free(encoded);

    var parsed = try parseRequest(std.testing.allocator, encoded, 0, false);
    defer parsed.deinit();
    switch (parsed.request.artifacts.adapted_input) {
        .object => |object| {
            try std.testing.expectEqual(std.math.maxInt(u64), object.bytes);
            try std.testing.expectEqualStrings("/source/a", object.diagnostic_path);
        },
        .path => return error.TestExpectedObjectReference,
    }
    try std.testing.expectEqual(null, parsed.request.artifacts.transcript_reference);
    try std.testing.expectEqual(null, parsed.request.artifacts.quotient_reference);
}

test "strict v4 parser fails closed on prior versions and missing composition program" {
    const artifacts = try testArtifacts(
        std.testing.allocator,
        "{\"path\":\"/a\"}",
        "{\"path\":\"/h\"}",
        "{\"path\":\"/h.tree0-merkle\"}",
        "",
    );
    defer std.testing.allocator.free(artifacts);
    const v2 = try testRequest(std.testing.allocator, 2, 0, artifacts);
    defer std.testing.allocator.free(v2);
    try std.testing.expectError(error.InvalidField, parseRequest(std.testing.allocator, v2, 0, false));

    const missing =
        \\{"adapted_input":{"path":"/a"},"schedule":{"path":"/b"},"witness_programs":{"path":"/c"},"multiplicity_feeds":{"path":"/d"},"relation_templates":{"path":"/e"},"fixed_tables":{"path":"/f"},"composition":{"path":"/g"},"preprocessed_evaluations":{"path":"/h"},"preprocessed_tree0_merkle":{"path":"/h.tree0-merkle"},"preprocessed_coefficients":{"path":"/i"}}
    ;
    const missing_request = try testRequest(std.testing.allocator, protocol_version, 0, missing);
    defer std.testing.allocator.free(missing_request);
    try std.testing.expectError(error.InvalidFields, parseRequest(std.testing.allocator, missing_request, 0, false));
}

test "strict artifact references reject mixed extra and legacy path shapes" {
    const invalid_refs = [_][]const u8{
        "\"/legacy/path\"",
        "{\"path\":\"/a\",\"object_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"bytes\":1,\"diagnostic_path\":\"/a\"}",
        "{\"path\":\"/a\",\"extra\":1}",
        "{\"object_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"bytes\":1,\"diagnostic_path\":\"/a\",\"extra\":1}",
    };
    for (invalid_refs) |invalid_ref| {
        const artifacts = try testArtifacts(
            std.testing.allocator,
            invalid_ref,
            "{\"path\":\"/h\"}",
            "{\"path\":\"/h.tree0-merkle\"}",
            "",
        );
        defer std.testing.allocator.free(artifacts);
        const encoded = try testRequest(std.testing.allocator, protocol_version, 0, artifacts);
        defer std.testing.allocator.free(encoded);
        try std.testing.expectError(error.InvalidArtifactRef, parseRequest(std.testing.allocator, encoded, 0, false));
    }
}

test "strict object references reject invalid ids byte counts and diagnostic paths" {
    const invalid_refs = [_]struct { encoded: []const u8, expected: anyerror }{
        .{ .encoded = "{\"object_id\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"bytes\":1,\"diagnostic_path\":\"/a\"}", .expected = error.InvalidObjectId },
        .{ .encoded = "{\"object_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"bytes\":true,\"diagnostic_path\":\"/a\"}", .expected = error.InvalidArtifactBytes },
        .{ .encoded = "{\"object_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"bytes\":0,\"diagnostic_path\":\"/a\"}", .expected = error.InvalidArtifactBytes },
        .{ .encoded = "{\"object_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"bytes\":-1,\"diagnostic_path\":\"/a\"}", .expected = error.InvalidArtifactBytes },
        .{ .encoded = "{\"object_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"bytes\":\"1\",\"diagnostic_path\":\"/a\"}", .expected = error.InvalidArtifactBytes },
        .{ .encoded = "{\"object_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"diagnostic_path\":\"/a\"}", .expected = error.InvalidArtifactRef },
        .{ .encoded = "{\"object_id\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"bytes\":1,\"diagnostic_path\":\"relative\"}", .expected = error.InvalidPath },
    };
    for (invalid_refs) |invalid| {
        const artifacts = try testArtifacts(
            std.testing.allocator,
            invalid.encoded,
            "{\"path\":\"/h\"}",
            "{\"path\":\"/h.tree0-merkle\"}",
            "",
        );
        defer std.testing.allocator.free(artifacts);
        const encoded = try testRequest(std.testing.allocator, protocol_version, 0, artifacts);
        defer std.testing.allocator.free(encoded);
        try std.testing.expectError(invalid.expected, parseRequest(std.testing.allocator, encoded, 0, false));
    }
}

test "tree companion constraint applies only to two path references" {
    const invalid_artifacts = try testArtifacts(
        std.testing.allocator,
        "{\"path\":\"/a\"}",
        "{\"path\":\"/h\"}",
        "{\"path\":\"/wrong\"}",
        "",
    );
    defer std.testing.allocator.free(invalid_artifacts);
    const invalid_request = try testRequest(std.testing.allocator, protocol_version, 0, invalid_artifacts);
    defer std.testing.allocator.free(invalid_request);
    try std.testing.expectError(error.InvalidTreeCompanion, parseRequest(std.testing.allocator, invalid_request, 0, false));

    const object_tree =
        \\{"object_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","bytes":2,"diagnostic_path":"/wrong"}
    ;
    const valid_artifacts = try testArtifacts(
        std.testing.allocator,
        "{\"path\":\"/a\"}",
        "{\"path\":\"/h\"}",
        object_tree,
        "",
    );
    defer std.testing.allocator.free(valid_artifacts);
    const valid_request = try testRequest(std.testing.allocator, protocol_version, 0, valid_artifacts);
    defer std.testing.allocator.free(valid_request);
    var parsed = try parseRequest(std.testing.allocator, valid_request, 0, false);
    parsed.deinit();
}

test "shutdown requires v4 and the next sequence" {
    const encoded =
        \\{"protocol":"stwo-zig-metal-prover-session","version":4,"type":"shutdown","next_sequence":3}
    ;
    try validateShutdown(std.testing.allocator, encoded, 3);
    try std.testing.expectError(error.InvalidSequence, validateShutdown(std.testing.allocator, encoded, 2));
}
