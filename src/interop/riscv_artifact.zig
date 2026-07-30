//! Versioned proof envelope for the release-gated Sail RV32IM frontend.
//!
//! This is a publication contract, not a release claim. V4 binds completion,
//! source ELF identity, and the exact security profile.

const std = @import("std");
/// Public because a product facade whose module root is not `src/` cannot reach
/// this file with a relative import and cannot be handed a second module rooted
/// at it either (a file belongs to exactly one module). Such a facade re-exports
/// the atomic publication primitive from here, which is where this artifact
/// writer already publishes through.
pub const atomic_file = @import("atomic_file.zig");
const schema = @import("riscv_artifact/schema.zig");
const validation = @import("riscv_artifact/validation.zig");
const digest = @import("riscv_artifact/digest.zig");
const preflight = @import("riscv_artifact/preflight.zig");

pub const wire_protocol = @import("riscv_artifact/protocol.zig");

pub const SCHEMA_VERSION = schema.SCHEMA_VERSION;
pub const ARTIFACT_KIND = schema.ARTIFACT_KIND;
pub const EXCHANGE_MODE = schema.EXCHANGE_MODE;
pub const RELEASE_STATUS = "release_gated";
pub const GENERATOR = schema.GENERATOR;
pub const AIR = schema.AIR;
pub const ORACLE_REPOSITORY = schema.ORACLE_REPOSITORY;
pub const ORACLE_COMMIT = schema.ORACLE_COMMIT;
pub const IMPLEMENTATION_REPOSITORY = schema.IMPLEMENTATION_REPOSITORY;
pub const MAX_ARTIFACT_BYTES = schema.MAX_ARTIFACT_BYTES;
pub const MAX_PROOF_BYTES = schema.MAX_PROOF_BYTES;
pub const MAX_COMPONENTS = schema.MAX_COMPONENTS;
pub const MAX_INFRA_COMPONENTS = schema.MAX_INFRA_COMPONENTS;

pub const Qm31Wire = schema.Qm31Wire;
pub const SecurityPolicy = schema.SecurityPolicy;
pub const FriConfigWire = schema.FriConfigWire;
pub const PcsConfigWire = schema.PcsConfigWire;
pub const SourceWire = schema.SourceWire;
pub const ProvenanceWire = schema.ProvenanceWire;
pub const OutputWordWire = schema.OutputWordWire;
pub const CompletionKindWire = schema.CompletionKindWire;
pub const CompletionWire = schema.CompletionWire;
pub const PublicDataWire = schema.PublicDataWire;
pub const ComponentWire = schema.ComponentWire;
pub const InfraComponentWire = schema.InfraComponentWire;
pub const StatementWire = schema.StatementWire;
pub const OpcodeClaimWire = schema.OpcodeClaimWire;
pub const InfraClaimWire = schema.InfraClaimWire;
pub const InteractionClaimWire = schema.InteractionClaimWire;
pub const Artifact = schema.Artifact;

pub const ClassifiedArtifact = union(enum) {
    riscv: std.json.Parsed(Artifact),
    other: []u8,

    pub fn deinit(self: *ClassifiedArtifact, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .riscv => |*parsed| parsed.deinit(),
            .other => |raw| allocator.free(raw),
        }
        self.* = undefined;
    }
};

/// Reads a candidate exactly once. Recognized RISC-V modes are parsed or
/// rejected explicitly; all other inputs retain the same bytes for fallback.
pub fn classifyPath(allocator: std.mem.Allocator, path: []const u8) !ClassifiedArtifact {
    const raw = try std.fs.cwd().readFileAlloc(allocator, path, MAX_ARTIFACT_BYTES);
    errdefer allocator.free(raw);
    const routing = try preflight.route(raw);
    if (!routing.isRiscV()) return .{ .other = raw };
    try routing.validateRiscV();
    const parsed = try parseArtifactBytes(allocator, raw);
    allocator.free(raw);
    return .{ .riscv = parsed };
}

pub fn isRiscVArtifactPath(allocator: std.mem.Allocator, path: []const u8) !bool {
    const raw = try std.fs.cwd().readFileAlloc(allocator, path, MAX_ARTIFACT_BYTES);
    defer allocator.free(raw);
    return (try preflight.route(raw)).isRiscV();
}

pub fn readArtifact(allocator: std.mem.Allocator, path: []const u8) !std.json.Parsed(Artifact) {
    const raw = try std.fs.cwd().readFileAlloc(allocator, path, MAX_ARTIFACT_BYTES);
    defer allocator.free(raw);
    const routing = try preflight.route(raw);
    if (!routing.isRiscV()) return error.UnsupportedArtifactKind;
    try routing.validateRiscV();
    return parseArtifactBytes(allocator, raw);
}

fn parseArtifactBytes(allocator: std.mem.Allocator, raw: []const u8) !std.json.Parsed(Artifact) {
    try preflight.validate(raw);
    return std.json.parseFromSlice(Artifact, allocator, raw, .{
        .ignore_unknown_fields = false,
        .allocate = .alloc_always,
    });
}

pub fn validatePath(allocator: std.mem.Allocator, path: []const u8) !void {
    var parsed = try readArtifact(allocator, path);
    defer parsed.deinit();
    try validate(parsed.value);
}

pub fn validate(artifact: Artifact) !void {
    return validation.validate(artifact, RELEASE_STATUS);
}

pub fn validateForPolicy(artifact: Artifact, policy: SecurityPolicy) !void {
    return validation.validateForPolicy(artifact, policy, RELEASE_STATUS);
}

pub fn statementDigest(
    protocol: []const u8,
    pcs_config: PcsConfigWire,
    source: SourceWire,
    statement: StatementWire,
) [32]u8 {
    return digest.statement(protocol, pcs_config, source, statement);
}

pub fn writeArtifact(
    allocator: std.mem.Allocator,
    path: []const u8,
    artifact: Artifact,
) !void {
    try validate(artifact);
    const rendered = try std.json.Stringify.valueAlloc(allocator, artifact, .{});
    defer allocator.free(rendered);
    if (rendered.len + 1 > MAX_ARTIFACT_BYTES) return error.ArtifactTooLarge;
    const output = try std.mem.concat(allocator, u8, &.{ rendered, "\n" });
    defer allocator.free(output);
    try atomic_file.writeExclusive(allocator, path, output);
}

test "RISC-V artifact header rejects legacy and unknown schemas explicitly" {
    try std.testing.expectError(
        error.LegacySchemaVersion,
        (try preflight.route(
            "{\"schema_version\":1,\"exchange_mode\":\"riscv_proof_json_wire_v1\"}",
        )).validateRiscV(),
    );
    try std.testing.expectError(
        error.LegacySchemaVersion,
        (try preflight.route(
            "{\"schema_version\":2,\"exchange_mode\":\"riscv_proof_json_wire_v2\"}",
        )).validateRiscV(),
    );
    try std.testing.expectError(
        error.LegacySchemaVersion,
        (try preflight.route(
            "{\"schema_version\":3,\"exchange_mode\":\"riscv_proof_json_wire_v3\"}",
        )).validateRiscV(),
    );
    try std.testing.expectError(
        error.UnsupportedSchemaVersion,
        (try preflight.route(
            "{\"artifact_kind\":\"stwo_riscv_proof\",\"schema_version\":99," ++
                "\"exchange_mode\":\"riscv_proof_json_wire_v99\"}",
        )).validateRiscV(),
    );
    try std.testing.expectError(
        error.UnsupportedExchangeMode,
        (try preflight.route(
            "{\"artifact_kind\":\"stwo_riscv_proof\",\"schema_version\":4," ++
                "\"exchange_mode\":\"unknown\"}",
        )).validateRiscV(),
    );
}

test "RISC-V artifact routing preserves explicit legacy rejection" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "legacy.json" });
    defer std.testing.allocator.free(path);

    try atomic_file.writeExclusive(
        std.testing.allocator,
        path,
        "{\"schema_version\":2,\"exchange_mode\":\"riscv_proof_json_wire_v2\"}\n",
    );
    try std.testing.expect(try isRiscVArtifactPath(std.testing.allocator, path));
    try std.testing.expectError(
        error.LegacySchemaVersion,
        classifyPath(std.testing.allocator, path),
    );
}

test "artifact classification owns non-RISC-V fallback bytes across replacement" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = try temporary.dir.realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(root);
    const path = try std.fs.path.join(std.testing.allocator, &.{ root, "artifact.json" });
    defer std.testing.allocator.free(path);
    const original = "{\"exchange_mode\":\"proof_exchange_json_wire_v1\"}\n";
    const replacement = "{\"exchange_mode\":\"riscv_proof_json_wire_v2\"}\n";
    try atomic_file.writeExclusive(std.testing.allocator, path, original);

    var classified = try classifyPath(std.testing.allocator, path);
    defer classified.deinit(std.testing.allocator);
    try std.fs.cwd().deleteFile(path);
    try atomic_file.writeExclusive(std.testing.allocator, path, replacement);
    switch (classified) {
        .other => |raw| try std.testing.expectEqualStrings(original, raw),
        .riscv => return error.UnexpectedRiscVClassification,
    }
}

test {
    _ = @import("riscv_artifact/validation_test.zig");
}
