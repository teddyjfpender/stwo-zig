//! Authenticated artifact identities and proof-protocol manifests.

const std = @import("std");
const shared_artifacts = @import("stwo_artifact_store");

pub const schema_version: u32 = 1;
pub const domain = "stwo-zig-artifact-manifest\x00";
pub const protocol_domain = "stwo-zig-proof-protocol\x00";

pub const ProofProtocol = struct {
    channel: []const u8,
    channel_salt: u32,
    log_blowup_factor: u32,
    n_queries: u32,
    interaction_pow_bits: u32,
    query_pow_bits: u32,
    fri_fold_step: u32,
    fri_lifting: ?u32,
    fri_log_last_layer_degree_bound: u32,
};

pub const Role = enum(u16) {
    backend_executable = 1,
    adapted_input = 2,
    schedule = 3,
    witness_programs = 4,
    multiplicity_feeds = 5,
    relation_templates = 6,
    fixed_tables = 7,
    composition = 8,
    composition_program = 9,
    preprocessed_evaluations = 10,
    preprocessed_tree0_merkle = 11,
    preprocessed_coefficients = 12,
    transcript_reference = 13,
    quotient_reference = 14,
    raw_pie = 15,
    adapter_executable = 16,
    bootloader = 17,
    schedule_generator = 18,
    semantic_air = 19,
    verifier_executable = 20,
    verifier_lockfile = 21,
};

pub const Provenance = enum(u8) {
    canonical_generated = 1,
    unattested = 2,
    proof_derived = 3,
    diagnostic_fixture = 4,
    raw = 5,
};

pub const GeneratorIdentity = struct {
    executable_sha256: [32]u8,
    semantic_version: []const u8,
    compiler_identity: []const u8,
    arguments_sha256: [32]u8,
};

pub const FileIdentity = shared_artifacts.FileIdentity;
pub const Measurement = shared_artifacts.Measurement;

pub const Entry = struct {
    role: Role,
    /// A canonical semantic name, never an arbitrary filesystem path. It is
    /// empty for singleton roles and distinguishes repeated PIE members.
    logical_name: []const u8 = "",
    format_version: u32,
    provenance: Provenance,
    measurement: Measurement,
    generator: ?GeneratorIdentity = null,
    source_digests: []const [32]u8 = &.{},
    source_chain_complete: bool = false,
};

pub const Classification = struct {
    production_source_chain_complete: bool,
    parity_fixture_used: bool,
    proof_derived_artifact_used: bool,
};

pub const Manifest = struct {
    protocol_digest: [32]u8,
    entries: []const Entry,
    sha256: [32]u8,

    pub fn build(
        allocator: std.mem.Allocator,
        protocol_digest: [32]u8,
        entries: []const Entry,
    ) !Manifest {
        const digest = try manifestDigest(allocator, protocol_digest, entries);
        return .{
            .protocol_digest = protocol_digest,
            .entries = entries,
            .sha256 = digest,
        };
    }
};

pub const JsonEvidence = struct {
    manifest: *const Manifest,

    pub fn jsonStringify(self: JsonEvidence, writer: anytype) !void {
        const classification = classify(self.manifest.entries);
        try writer.beginObject();
        try writer.objectField("schema_version");
        try writer.write(schema_version);
        try writer.objectField("canonical_encoding");
        try writer.write("STWZAM/1-little-endian");
        try writer.objectField("protocol_sha256");
        try writeHexDigest(writer, self.manifest.protocol_digest);
        try writer.objectField("sha256");
        try writeHexDigest(writer, self.manifest.sha256);
        try writer.objectField("classification");
        try writer.write(classification);
        try writer.objectField("entries");
        try writer.beginArray();
        for (self.manifest.entries) |entry| {
            try writer.beginObject();
            try writer.objectField("role");
            try writer.write(@tagName(entry.role));
            try writer.objectField("logical_name");
            try writer.write(entry.logical_name);
            try writer.objectField("format_version");
            try writer.write(entry.format_version);
            try writer.objectField("provenance");
            try writer.write(@tagName(entry.provenance));
            try writer.objectField("bytes");
            try writer.write(entry.measurement.bytes);
            try writer.objectField("sha256");
            try writeHexDigest(writer, entry.measurement.sha256);
            try writer.objectField("source_chain_complete");
            try writer.write(entry.source_chain_complete);
            try writer.objectField("source_digests");
            try writer.beginArray();
            for (entry.source_digests) |source_digest| try writeHexDigest(writer, source_digest);
            try writer.endArray();
            try writer.objectField("generator");
            if (entry.generator) |generator| {
                try writer.beginObject();
                try writer.objectField("executable_sha256");
                try writeHexDigest(writer, generator.executable_sha256);
                try writer.objectField("semantic_version");
                try writer.write(generator.semantic_version);
                try writer.objectField("compiler_identity");
                try writer.write(generator.compiler_identity);
                try writer.objectField("arguments_sha256");
                try writeHexDigest(writer, generator.arguments_sha256);
                try writer.endObject();
            } else {
                try writer.write(null);
            }
            try writer.endObject();
        }
        try writer.endArray();
        try writer.endObject();
    }
};

pub const measureFile = shared_artifacts.measureFile;
pub const digestBytes = shared_artifacts.digestBytes;

pub fn protocolDigest(value: ProofProtocol) ![32]u8 {
    if (value.channel.len == 0 or value.channel.len > std.math.maxInt(u16))
        return error.InvalidProofProtocol;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(protocol_domain);
    updateInt(&hasher, u32, 1);
    updateInt(&hasher, u16, @intCast(value.channel.len));
    hasher.update(value.channel);
    updateInt(&hasher, u32, value.channel_salt);
    updateInt(&hasher, u32, value.log_blowup_factor);
    updateInt(&hasher, u32, value.n_queries);
    updateInt(&hasher, u32, value.interaction_pow_bits);
    updateInt(&hasher, u32, value.query_pow_bits);
    updateInt(&hasher, u32, value.fri_fold_step);
    if (value.fri_lifting) |lifting| {
        updateInt(&hasher, u8, 1);
        updateInt(&hasher, u32, lifting);
    } else {
        updateInt(&hasher, u8, 0);
    }
    updateInt(&hasher, u32, value.fri_log_last_layer_degree_bound);
    return hasher.finalResult();
}

pub fn manifestDigest(
    allocator: std.mem.Allocator,
    protocol_digest: [32]u8,
    entries: []const Entry,
) ![32]u8 {
    if (entries.len == 0 or entries.len > std.math.maxInt(u16))
        return error.InvalidArtifactManifest;
    const order = try allocator.alloc(usize, entries.len);
    defer allocator.free(order);
    for (order, 0..) |*index, value| index.* = value;
    std.mem.sort(usize, order, entries, struct {
        fn lessThan(context: []const Entry, lhs: usize, rhs: usize) bool {
            const lhs_role = @intFromEnum(context[lhs].role);
            const rhs_role = @intFromEnum(context[rhs].role);
            if (lhs_role != rhs_role) return lhs_role < rhs_role;
            return std.mem.order(
                u8,
                context[lhs].logical_name,
                context[rhs].logical_name,
            ) == .lt;
        }
    }.lessThan);

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(domain);
    updateInt(&hasher, u32, schema_version);
    hasher.update(&protocol_digest);
    updateInt(&hasher, u16, @intCast(entries.len));
    var previous_index: ?usize = null;
    for (order) |index| {
        const entry = entries[index];
        if (previous_index) |previous| {
            const previous_entry = entries[previous];
            if (previous_entry.role == entry.role and
                std.mem.eql(u8, previous_entry.logical_name, entry.logical_name))
                return error.DuplicateArtifactRole;
        }
        previous_index = index;
        if (entry.format_version == 0 or entry.measurement.bytes == 0)
            return error.InvalidArtifactManifest;
        if (entry.logical_name.len > std.math.maxInt(u16) or
            entry.source_digests.len > std.math.maxInt(u16))
            return error.InvalidArtifactManifest;
        updateInt(&hasher, u16, @intFromEnum(entry.role));
        updateInt(&hasher, u16, @intCast(entry.logical_name.len));
        hasher.update(entry.logical_name);
        updateInt(&hasher, u32, entry.format_version);
        updateInt(&hasher, u8, @intFromEnum(entry.provenance));
        updateInt(&hasher, u64, entry.measurement.bytes);
        hasher.update(&entry.measurement.sha256);
        updateInt(&hasher, u8, @intFromBool(entry.source_chain_complete));
        updateInt(&hasher, u16, @intCast(entry.source_digests.len));
        for (entry.source_digests) |source_digest| hasher.update(&source_digest);
        if (entry.generator) |generator| {
            if (generator.semantic_version.len == 0 or
                generator.semantic_version.len > std.math.maxInt(u16) or
                generator.compiler_identity.len == 0 or
                generator.compiler_identity.len > std.math.maxInt(u16))
                return error.InvalidArtifactManifest;
            updateInt(&hasher, u8, 1);
            hasher.update(&generator.executable_sha256);
            updateInt(&hasher, u16, @intCast(generator.semantic_version.len));
            hasher.update(generator.semantic_version);
            updateInt(&hasher, u16, @intCast(generator.compiler_identity.len));
            hasher.update(generator.compiler_identity);
            hasher.update(&generator.arguments_sha256);
        } else {
            updateInt(&hasher, u8, 0);
        }
    }
    return hasher.finalResult();
}

pub fn classify(entries: []const Entry) Classification {
    if (entries.len == 0) return .{
        .production_source_chain_complete = false,
        .parity_fixture_used = true,
        .proof_derived_artifact_used = true,
    };
    var result = Classification{
        .production_source_chain_complete = true,
        .parity_fixture_used = false,
        .proof_derived_artifact_used = false,
    };
    for (entries) |entry| switch (entry.provenance) {
        .raw => {
            if (!entry.source_chain_complete or entry.generator != null)
                result.production_source_chain_complete = false;
        },
        .canonical_generated => {
            if (!entry.source_chain_complete or entry.generator == null or
                entry.source_digests.len == 0)
                result.production_source_chain_complete = false;
        },
        .diagnostic_fixture => {
            result.production_source_chain_complete = false;
            result.parity_fixture_used = true;
        },
        .proof_derived, .unattested => {
            result.production_source_chain_complete = false;
            result.proof_derived_artifact_used = true;
        },
    };
    return result;
}

fn updateInt(hasher: *std.crypto.hash.sha2.Sha256, comptime T: type, value: T) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    hasher.update(&encoded);
}

fn writeHexDigest(writer: anytype, digest: [32]u8) !void {
    const hex = std.fmt.bytesToHex(digest, .lower);
    try writer.write(&hex);
}

fn testMeasurement(contents: []const u8) Measurement {
    return .{
        .bytes = contents.len,
        .sha256 = digestBytes(contents),
        .identity = .{
            .inode = 1,
            .size = contents.len,
            .mtime = 2,
            .ctime = 3,
        },
    };
}

test "manifest digest is role ordered and path independent" {
    const protocol_digest = digestBytes("canonical protocol");
    const a = Entry{
        .role = .schedule,
        .format_version = 1,
        .provenance = .proof_derived,
        .measurement = testMeasurement("schedule"),
    };
    const b = Entry{
        .role = .adapted_input,
        .format_version = 1,
        .provenance = .unattested,
        .measurement = testMeasurement("input"),
    };
    const forward = [_]Entry{ a, b };
    const reverse = [_]Entry{ b, a };
    try std.testing.expectEqual(
        try manifestDigest(std.testing.allocator, protocol_digest, &forward),
        try manifestDigest(std.testing.allocator, protocol_digest, &reverse),
    );
}

test "protocol digest is typed and binds every field" {
    var proof_protocol = ProofProtocol{
        .channel = "blake2s",
        .channel_salt = 0,
        .log_blowup_factor = 1,
        .n_queries = 70,
        .interaction_pow_bits = 24,
        .query_pow_bits = 26,
        .fri_fold_step = 3,
        .fri_lifting = null,
        .fri_log_last_layer_degree_bound = 0,
    };
    const before = try protocolDigest(proof_protocol);
    proof_protocol.query_pow_bits = 25;
    const after = try protocolDigest(proof_protocol);
    try std.testing.expect(!std.mem.eql(u8, &before, &after));
}

test "manifest rejects duplicate roles and empty artifacts" {
    const protocol_digest = digestBytes("protocol");
    const duplicate = [_]Entry{
        .{
            .role = .schedule,
            .format_version = 1,
            .provenance = .proof_derived,
            .measurement = testMeasurement("one"),
        },
        .{
            .role = .schedule,
            .format_version = 1,
            .provenance = .proof_derived,
            .measurement = testMeasurement("two"),
        },
    };
    try std.testing.expectError(
        error.DuplicateArtifactRole,
        manifestDigest(std.testing.allocator, protocol_digest, &duplicate),
    );
    var empty = duplicate[0];
    empty.measurement.bytes = 0;
    try std.testing.expectError(
        error.InvalidArtifactManifest,
        manifestDigest(std.testing.allocator, protocol_digest, &.{empty}),
    );
}

test "logical names distinguish repeated artifact roles" {
    const protocol_digest = digestBytes("protocol");
    const members = [_]Entry{
        .{
            .role = .raw_pie,
            .logical_name = "execution_resources.json",
            .format_version = 1,
            .provenance = .raw,
            .measurement = testMeasurement("resources"),
            .source_chain_complete = true,
        },
        .{
            .role = .raw_pie,
            .logical_name = "memory.bin",
            .format_version = 1,
            .provenance = .raw,
            .measurement = testMeasurement("memory"),
            .source_chain_complete = true,
        },
    };
    _ = try manifestDigest(std.testing.allocator, protocol_digest, &members);
}

test "generator and source-chain metadata are digest bound" {
    const protocol_digest = digestBytes("protocol");
    const sources = [_][32]u8{digestBytes("raw-pie")};
    var generated = Entry{
        .role = .adapted_input,
        .format_version = 1,
        .provenance = .canonical_generated,
        .measurement = testMeasurement("adapted"),
        .generator = .{
            .executable_sha256 = digestBytes("adapter"),
            .semantic_version = "adapter-v1",
            .compiler_identity = "zig-0.15.2",
            .arguments_sha256 = digestBytes("arguments"),
        },
        .source_digests = &sources,
        .source_chain_complete = true,
    };
    const before = try manifestDigest(std.testing.allocator, protocol_digest, &.{generated});
    generated.generator.?.semantic_version = "adapter-v2";
    const after = try manifestDigest(std.testing.allocator, protocol_digest, &.{generated});
    try std.testing.expect(!std.mem.eql(u8, &before, &after));
}

test "classification fails closed on fixtures proof derivation and incomplete generators" {
    const sources = [_][32]u8{digestBytes("raw")};
    const eligible = [_]Entry{
        .{
            .role = .raw_pie,
            .format_version = 1,
            .provenance = .raw,
            .measurement = testMeasurement("raw"),
            .source_chain_complete = true,
        },
        .{
            .role = .adapted_input,
            .format_version = 1,
            .provenance = .canonical_generated,
            .measurement = testMeasurement("adapted"),
            .generator = .{
                .executable_sha256 = digestBytes("adapter"),
                .semantic_version = "v1",
                .compiler_identity = "zig-0.15.2",
                .arguments_sha256 = digestBytes("args"),
            },
            .source_digests = &sources,
            .source_chain_complete = true,
        },
    };
    try std.testing.expect(classify(&eligible).production_source_chain_complete);

    var fixture = eligible[1];
    fixture.provenance = .diagnostic_fixture;
    const fixture_classification = classify(&.{ eligible[0], fixture });
    try std.testing.expect(!fixture_classification.production_source_chain_complete);
    try std.testing.expect(fixture_classification.parity_fixture_used);

    var incomplete = eligible[1];
    incomplete.generator = null;
    incomplete.provenance = .canonical_generated;
    try std.testing.expect(!classify(&.{ eligible[0], incomplete }).production_source_chain_complete);
}

test "JSON evidence embeds the manifest and canonical digest strings" {
    const entry = Entry{
        .role = .adapted_input,
        .format_version = 1,
        .provenance = .proof_derived,
        .measurement = testMeasurement("adapted"),
    };
    const protocol_digest = digestBytes("protocol");
    const manifest = try Manifest.build(std.testing.allocator, protocol_digest, &.{entry});
    var encoded: [4096]u8 = undefined;
    var writer = std.Io.Writer.fixed(&encoded);
    try std.json.Stringify.value(JsonEvidence{ .manifest = &manifest }, .{}, &writer);
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        writer.buffered(),
        .{},
    );
    defer parsed.deinit();
    const object = parsed.value.object;
    try std.testing.expectEqualStrings("STWZAM/1-little-endian", object.get("canonical_encoding").?.string);
    const digest_hex = std.fmt.bytesToHex(manifest.sha256, .lower);
    try std.testing.expectEqualStrings(&digest_hex, object.get("sha256").?.string);
    try std.testing.expectEqual(@as(usize, 1), object.get("entries").?.array.items.len);
}

test "same-size mutation with restored mtime changes measured identity" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(.{ .sub_path = "artifact.bin", .data = "abcdefgh" });
    const path = try temporary.dir.realpathAlloc(std.testing.allocator, "artifact.bin");
    defer std.testing.allocator.free(path);
    const before_file = try std.fs.openFileAbsolute(path, .{ .mode = .read_write });
    const original_stat = try before_file.stat();
    before_file.close();
    const before = try measureFile(std.testing.allocator, path);

    const mutate = try std.fs.openFileAbsolute(path, .{ .mode = .read_write });
    try mutate.pwriteAll("abcdWXYZ", 0);
    try mutate.updateTimes(original_stat.atime, original_stat.mtime);
    try mutate.sync();
    mutate.close();
    const after = try measureFile(std.testing.allocator, path);
    try std.testing.expectEqual(before.bytes, after.bytes);
    try std.testing.expect(!std.mem.eql(u8, &before.sha256, &after.sha256));
}
