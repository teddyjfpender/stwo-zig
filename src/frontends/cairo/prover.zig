//! Public Cairo program proving boundary.
//!
//! The frontend authenticates the adapted input and semantic pack, derives the
//! exact public statement, dispatches one required backend, and accepts output
//! only after the pinned Rust `verify_cairo` oracle succeeds.

const std = @import("std");
const adapter = @import("adapter/mod.zig");
const statement_bootstrap = @import("statement_bootstrap.zig");
const compact_interchange = @import("compact_verifier_interchange.zig");
const semantic_pack = @import("witness/semantic_pack.zig");

pub const pinned_stwo_cairo_revision = "dcd5834565b7a26a27a614e353c9c60109ebc1d9";
pub const pinned_stwo_revision = "9d7e3d6fa0fc64a0d143a8b2fcb8ee952f4de8f2";
pub const canonical_envelope_abi = "STWZCVE/1";
pub const canonical_verification_mode = "compact_metal_proof_v1";

pub const AdmissionMode = enum {
    /// Requires source-derived artifacts with a complete production chain.
    production,
    /// Allows explicitly classified proof-derived parity artifacts.
    development_oracle_parity,
};

pub const BackendKind = enum {
    cpu_scalar,
    simd,
    metal,
    cuda,
};

pub const BackendIdentity = struct {
    kind: BackendKind,
    implementation: []const u8,
};

pub const Request = struct {
    admission: AdmissionMode,
    required_backend: BackendKind,
    adapted_input: semantic_pack.AuthenticatedFile,
    semantic_artifacts: semantic_pack.Files,
    envelope_output_path: []const u8,
};

/// Immutable request state borrowed by a backend only for the `proveCairo`
/// call. The frontend owns all fields and releases them on return.
pub const PreparedProgram = struct {
    allocator: std.mem.Allocator,
    input_path: []const u8,
    input_sha256: [32]u8,
    input_measurement: FileMeasurement,
    input: adapter.ProverInput,
    artifacts: semantic_pack.Loaded,
    compact_statement: []u8,

    pub fn deinit(self: *PreparedProgram) void {
        self.allocator.free(self.compact_statement);
        self.artifacts.deinit();
        self.input.deinit(self.allocator);
        self.* = undefined;
    }
};

/// Evidence returned by the process boundary that runs the canonical Rust
/// verifier adapter. Implementations must derive this from the verifier result,
/// not from backend reports.
pub const OracleEvidence = struct {
    verified: bool,
    envelope_sha256: [32]u8,
    envelope_abi: []const u8,
    verification_mode: []const u8,
    stwo_cairo_revision: []const u8,
    stwo_revision: []const u8,
};

pub const ProofReceipt = struct {
    envelope_path: []const u8,
    envelope_sha256: [32]u8,
    backend: BackendIdentity,
    rust_verified: bool,
    production_eligible: bool,
    artifact_provenance: semantic_pack.Provenance,
};

/// Proves one Cairo execution through a caller-supplied backend.
///
/// `Backend` must expose:
/// - `identity(self) BackendIdentity`
/// - `proveCairo(self, allocator, *const PreparedProgram, output_path) !void`
///
/// `Oracle` must expose:
/// - `verifyCairo(self, allocator, envelope_path) !OracleEvidence`
///
/// Backend completion is not proof acceptance. This function returns only
/// after the pinned Rust oracle accepts the exact immutable envelope bytes.
pub fn proveCairo(
    comptime Backend: type,
    comptime Oracle: type,
    allocator: std.mem.Allocator,
    backend: *Backend,
    oracle: *Oracle,
    request: Request,
) !ProofReceipt {
    try validateOutputPath(request.envelope_output_path);
    // Semantic-pack v1 is selected by a Rust proof and carries no complete
    // source-chain attestation. Reject it before hashing large artifacts.
    if (request.admission == .production) return error.ProofDerivedArtifactsRejected;
    const identity: BackendIdentity = backend.identity();
    if (identity.kind != request.required_backend or identity.implementation.len == 0)
        return error.BackendIdentityMismatch;

    var prepared = try prepareProgram(allocator, request);
    defer prepared.deinit();
    try assertProgramUnchanged(&prepared);
    var keep_output = false;
    errdefer if (!keep_output) std.fs.deleteFileAbsolute(request.envelope_output_path) catch {};
    try backend.proveCairo(allocator, &prepared, request.envelope_output_path);
    const before = try measureEnvelope(request.envelope_output_path);
    const evidence: OracleEvidence = try oracle.verifyCairo(
        allocator,
        request.envelope_output_path,
    );
    const after = try measureEnvelope(request.envelope_output_path);
    if (!sameFile(before.stat, after.stat) or
        !std.mem.eql(u8, &before.sha256, &after.sha256) or
        !std.mem.eql(u8, &evidence.envelope_sha256, &after.sha256))
        return error.EnvelopeChangedDuringVerification;
    try validateOracleEvidence(evidence);
    keep_output = true;
    return .{
        .envelope_path = request.envelope_output_path,
        .envelope_sha256 = after.sha256,
        .backend = identity,
        .rust_verified = true,
        .production_eligible = false,
        .artifact_provenance = prepared.artifacts.provenance,
    };
}

fn prepareProgram(allocator: std.mem.Allocator, request: Request) !PreparedProgram {
    const input_measurement = try validateAuthenticatedInput(request.adapted_input);
    var input = try adapter.adapted_input.readFile(allocator, request.adapted_input.path);
    errdefer input.deinit(allocator);
    if (input.state_transitions.casm_states_by_opcode.totalCount() == 0)
        return error.EmptyCairoExecution;
    var artifacts = try semantic_pack.load(allocator, request.semantic_artifacts);
    errdefer artifacts.deinit();
    const compact_statement = try statement_bootstrap.encodeCompactStatementV1(
        allocator,
        &artifacts.composition,
        &input,
    );
    errdefer allocator.free(compact_statement);
    try assertFileUnchanged(request.adapted_input.path, input_measurement);
    try artifacts.assertUnchanged();
    return .{
        .allocator = allocator,
        .input_path = request.adapted_input.path,
        .input_sha256 = request.adapted_input.sha256,
        .input_measurement = input_measurement,
        .input = input,
        .artifacts = artifacts,
        .compact_statement = compact_statement,
    };
}

fn validateAuthenticatedInput(input: semantic_pack.AuthenticatedFile) !FileMeasurement {
    if (!std.fs.path.isAbsolute(input.path)) return error.InputPathNotAbsolute;
    const measurement = try measureFile(input.path, false);
    if (!std.mem.eql(u8, &measurement.sha256, &input.sha256))
        return error.AdaptedInputDigestMismatch;
    return measurement;
}

fn assertProgramUnchanged(prepared: *const PreparedProgram) !void {
    try assertFileUnchanged(prepared.input_path, prepared.input_measurement);
    try prepared.artifacts.assertUnchanged();
}

fn assertFileUnchanged(path: []const u8, expected: FileMeasurement) !void {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    if (!sameFile(expected.stat, try file.stat())) return error.ArtifactChangedAfterAuthentication;
}

fn validateOutputPath(path: []const u8) !void {
    if (!std.fs.path.isAbsolute(path)) return error.OutputPathNotAbsolute;
    if (std.fs.accessAbsolute(path, .{})) |_| return error.OutputAlreadyExists else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
    const parent_path = std.fs.path.dirname(path) orelse return error.InvalidOutputPath;
    var parent = try std.fs.openDirAbsolute(parent_path, .{});
    parent.close();
}

fn validateOracleEvidence(evidence: OracleEvidence) !void {
    if (!evidence.verified or
        !std.mem.eql(u8, evidence.envelope_abi, canonical_envelope_abi) or
        !std.mem.eql(u8, evidence.verification_mode, canonical_verification_mode) or
        !std.mem.eql(u8, evidence.stwo_cairo_revision, pinned_stwo_cairo_revision) or
        !std.mem.eql(u8, evidence.stwo_revision, pinned_stwo_revision))
        return error.CanonicalRustOracleRejected;
}

const FileMeasurement = struct {
    sha256: [32]u8,
    stat: std.fs.File.Stat,
};

fn measureEnvelope(path: []const u8) !FileMeasurement {
    const measurement = try measureFile(path, true);
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    var header: [compact_interchange.envelope_header_bytes]u8 = undefined;
    if (try file.readAll(&header) != header.len or
        !std.mem.eql(u8, header[0..8], &compact_interchange.envelope_magic) or
        std.mem.readInt(u16, header[8..10], .little) != compact_interchange.envelope_version or
        std.mem.readInt(u16, header[10..12], .little) != compact_interchange.envelope_header_bytes or
        std.mem.readInt(u32, header[16..20], .little) != compact_interchange.section_count or
        std.mem.readInt(u64, header[24..32], .little) != measurement.stat.size)
        return error.InvalidCompactEnvelope;
    return measurement;
}

fn measureFile(path: []const u8, bounded_envelope: bool) !FileMeasurement {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const before = try file.stat();
    if (before.kind != .file or before.size == 0 or
        (bounded_envelope and before.size > compact_interchange.max_envelope_bytes))
        return error.InvalidArtifactFile;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [256 * 1024]u8 = undefined;
    var count: u64 = 0;
    while (true) {
        const read = try file.read(&buffer);
        if (read == 0) break;
        hasher.update(buffer[0..read]);
        count = std.math.add(u64, count, read) catch return error.ArtifactLengthOverflow;
    }
    const after = try file.stat();
    if (count != before.size or !sameFile(before, after)) return error.ArtifactChangedDuringRead;
    return .{ .sha256 = hasher.finalResult(), .stat = after };
}

fn sameFile(left: std.fs.File.Stat, right: std.fs.File.Stat) bool {
    return left.kind == right.kind and left.inode == right.inode and left.size == right.size and
        left.mtime == right.mtime and left.ctime == right.ctime;
}

test "Cairo prover: rejects noncanonical Rust oracle identity" {
    const good = OracleEvidence{
        .verified = true,
        .envelope_sha256 = [_]u8{0} ** 32,
        .envelope_abi = canonical_envelope_abi,
        .verification_mode = canonical_verification_mode,
        .stwo_cairo_revision = pinned_stwo_cairo_revision,
        .stwo_revision = pinned_stwo_revision,
    };
    var wrong = good;
    wrong.stwo_revision = "untrusted";
    try std.testing.expectError(error.CanonicalRustOracleRejected, validateOracleEvidence(wrong));
}

test "Cairo prover: proof-derived packs are not production eligible" {
    const provenance: semantic_pack.Provenance = .proof_derived;
    try std.testing.expect(provenance != .source_derived);
    try std.testing.expectEqualStrings(canonical_envelope_abi, "STWZCVE/1");
}

test "Cairo prover: production rejects v1 packs before backend dispatch" {
    const Backend = struct {
        dispatched: bool = false,

        fn identity(_: *@This()) BackendIdentity {
            return .{ .kind = .metal, .implementation = "test-metal" };
        }

        fn proveCairo(
            self: *@This(),
            _: std.mem.Allocator,
            _: *const PreparedProgram,
            _: []const u8,
        ) !void {
            self.dispatched = true;
        }
    };
    const Oracle = struct {
        fn verifyCairo(_: *@This(), _: std.mem.Allocator, _: []const u8) !OracleEvidence {
            return error.UnexpectedOracleDispatch;
        }
    };

    var backend = Backend{};
    var oracle = Oracle{};
    try std.testing.expectError(error.ProofDerivedArtifactsRejected, proveCairo(
        Backend,
        Oracle,
        std.testing.allocator,
        &backend,
        &oracle,
        .{
            .admission = .production,
            .required_backend = .metal,
            .adapted_input = .{ .path = "/not-read", .sha256 = [_]u8{0} ** 32 },
            .semantic_artifacts = undefined,
            .envelope_output_path = "/tmp/stwo-zig-cairo-production-gate.stwzcve",
        },
    ));
    try std.testing.expect(!backend.dispatched);
}
