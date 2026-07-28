//! Authenticated Cairo Metal backend behind the public prover contract.

const std = @import("std");
const prover = @import("stwo_cairo_frontend").prover;
const compact = @import("stwo_cairo_frontend").compact_verifier_interchange;
const composition_bundle = @import("stwo_cairo_frontend").witness.composition_bundle;
const semantic_pack = @import("stwo_cairo_frontend").witness.semantic_pack;
const metal_session = @import("stwo_metal_session");
const artifact_manifest = metal_session.artifact_manifest;
const artifact_views = metal_session.artifact_views;
const runner = @import("runner.zig");

pub const AuthenticatedFile = semantic_pack.AuthenticatedFile;

pub const CompositionProgram = union(runner.CompositionProgramKind) {
    metal: AuthenticatedFile,
    metallib: AuthenticatedFile,

    fn file(self: CompositionProgram) AuthenticatedFile {
        return switch (self) {
            inline else => |value| value,
        };
    }
};

/// Runtime inputs omitted from `prover.Request` because they are an
/// implementation detail of this backend. Every pathname is authenticated at
/// backend initialization and rebound into the proof provenance manifest.
pub const Config = struct {
    runner_executable: AuthenticatedFile,
    schedule: AuthenticatedFile,
    composition_program: CompositionProgram,
    preprocessed_evaluations: AuthenticatedFile,
    preprocessed_tree0_merkle: AuthenticatedFile,
    expected_tree0_root: [32]u8,
    arena_budget_gib: u32,
    timeout_ns: u64 = 30 * 60 * std.time.ns_per_s,
    termination_grace_ns: u64 = 5 * std.time.ns_per_s,
};

const RuntimeMeasurements = struct {
    runner_executable: artifact_manifest.Measurement,
    schedule: artifact_manifest.Measurement,
    composition_program: artifact_manifest.Measurement,
    preprocessed_evaluations: artifact_manifest.Measurement,
    preprocessed_tree0_merkle: artifact_manifest.Measurement,
};

pub const MetalBackend = struct {
    config: Config,
    measurements: RuntimeMeasurements,

    pub fn init(allocator: std.mem.Allocator, config: Config) !MetalBackend {
        try validateConfigPaths(allocator, config);
        const measurements = RuntimeMeasurements{
            .runner_executable = try authenticate(allocator, config.runner_executable, true),
            .schedule = try authenticate(allocator, config.schedule, false),
            .composition_program = try authenticate(allocator, config.composition_program.file(), false),
            .preprocessed_evaluations = try authenticate(allocator, config.preprocessed_evaluations, false),
            .preprocessed_tree0_merkle = try authenticate(allocator, config.preprocessed_tree0_merkle, false),
        };
        const derived_root = try artifact_views.deriveTree0Root(config.preprocessed_tree0_merkle.path);
        if (!std.mem.eql(u8, &derived_root, &config.expected_tree0_root))
            return error.PreprocessedTreeRootMismatch;
        return .{ .config = config, .measurements = measurements };
    }

    pub fn identity(_: *const MetalBackend) prover.BackendIdentity {
        return .{ .kind = .metal, .implementation = "cairo-metal-arena-process-v1" };
    }

    /// Runs the existing resident arena prover in an isolated process, then
    /// publishes the exact raw bundle under the authenticated STWZCVE envelope.
    pub fn proveCairo(
        self: *MetalBackend,
        allocator: std.mem.Allocator,
        prepared: *const prover.PreparedProgram,
        output_path: []const u8,
    ) !void {
        try self.assertRuntimeUnchanged();
        try validateCompositionProgramPath(prepared.artifacts.files.composition, self.config.composition_program);
        var temporary = try TemporaryFiles.create(allocator, output_path);
        defer temporary.deinit(allocator);
        const tree0_root_hex = std.fmt.bytesToHex(self.config.expected_tree0_root, .lower);
        const report = try runner.execute(allocator, .{
            .executable = self.config.runner_executable.path,
            .schedule = self.config.schedule.path,
            .budget_gib = self.config.arena_budget_gib,
            .artifacts = .{
                .adapted_input = prepared.input_path,
                .witness_programs = prepared.artifacts.files.witness_programs,
                .multiplicity_feeds = prepared.artifacts.files.multiplicity_feeds,
                .relation_templates = prepared.artifacts.files.relation_templates,
                .fixed_tables = prepared.artifacts.files.fixed_tables,
                .composition = prepared.artifacts.files.composition,
                .composition_program = self.config.composition_program.file().path,
                .composition_program_kind = std.meta.activeTag(self.config.composition_program),
                .preprocessed_evaluations = self.config.preprocessed_evaluations.path,
                .preprocessed_coefficients = prepared.artifacts.files.preprocessed_coefficients,
                .tree0_root_hex = &tree0_root_hex,
            },
            .proof_output = temporary.proof,
            .statement_output = temporary.statement,
            .timeout_ns = self.config.timeout_ns,
            .termination_grace_ns = self.config.termination_grace_ns,
        });
        try self.assertRuntimeUnchanged();
        try prepared.artifacts.assertUnchanged();
        try requireExactStatement(allocator, temporary.statement, prepared.compact_statement);

        const geometry = try protocolGeometry(prepared.artifacts.composition);
        const columns = try traceColumns(prepared.artifacts.composition, prepared.artifacts.fixed_tables.preprocessed_identities.len);
        const protocol = try (compact.CompactProofLayoutV1{
            .interaction_claim_words = report.proof_layout.interaction_claim_words,
            .sampled_value_words = report.proof_layout.sampled_value_words,
            .decommitment_capacity_words = report.proof_layout.decommitment_capacity_words,
        }).protocolRuntime(0, geometry, columns);
        if (report.proof_output_bytes != try protocol.proofByteCount())
            return error.ArenaProofLengthMismatch;

        const manifest_sha256 = try runtimeManifestDigest(allocator, self, prepared);
        const adapted_hex = std.fmt.bytesToHex(prepared.input_sha256, .lower);
        const manifest_hex = std.fmt.bytesToHex(manifest_sha256, .lower);
        const runner_hex = std.fmt.bytesToHex(self.measurements.runner_executable.sha256, .lower);
        const output = try std.fs.createFileAbsolute(output_path, .{ .read = true, .exclusive = true, .mode = 0o600 });
        var output_open = true;
        defer if (output_open) output.close();
        errdefer std.fs.deleteFileAbsolute(output_path) catch {};
        var buffer: [256 * 1024]u8 = undefined;
        var file_writer = output.writer(&buffer);
        _ = try compact.writeEnvelopeFromProofPathV1(
            &file_writer.interface,
            protocol,
            prepared.compact_statement,
            temporary.proof,
            .{
                .adapted_input_sha256 = &adapted_hex,
                .artifact_manifest_sha256 = &manifest_hex,
                .runner_executable_sha256 = &runner_hex,
                .backend_executable_sha256 = &runner_hex,
            },
        );
        try file_writer.interface.flush();
        try output.sync();
        output.close();
        output_open = false;
        try self.assertRuntimeUnchanged();
    }

    fn assertRuntimeUnchanged(self: *const MetalBackend) !void {
        try assertUnchanged(self.config.runner_executable.path, self.measurements.runner_executable);
        try assertUnchanged(self.config.schedule.path, self.measurements.schedule);
        try assertUnchanged(self.config.composition_program.file().path, self.measurements.composition_program);
        try assertUnchanged(self.config.preprocessed_evaluations.path, self.measurements.preprocessed_evaluations);
        try assertUnchanged(self.config.preprocessed_tree0_merkle.path, self.measurements.preprocessed_tree0_merkle);
    }
};

fn validateConfigPaths(allocator: std.mem.Allocator, config: Config) !void {
    if (config.arena_budget_gib == 0 or config.arena_budget_gib > 1024 or
        config.timeout_ns == 0 or config.termination_grace_ns == 0)
        return error.InvalidMetalBackendConfig;
    inline for (.{
        config.runner_executable.path,
        config.schedule.path,
        config.composition_program.file().path,
        config.preprocessed_evaluations.path,
        config.preprocessed_tree0_merkle.path,
    }) |path| try requireCanonicalAbsolutePath(allocator, path);
    const expected_tree_path = try std.fmt.allocPrint(
        allocator,
        "{s}.tree0-merkle",
        .{config.preprocessed_evaluations.path},
    );
    defer allocator.free(expected_tree_path);
    if (!std.mem.eql(u8, expected_tree_path, config.preprocessed_tree0_merkle.path))
        return error.PreprocessedArtifactsNotCompanions;
    const program_path = config.composition_program.file().path;
    switch (config.composition_program) {
        .metal => if (!std.mem.endsWith(u8, program_path, ".metal"))
            return error.InvalidCompositionProgram,
        .metallib => if (!std.mem.endsWith(u8, program_path, ".metallib"))
            return error.InvalidCompositionProgram,
    }
}

fn validateCompositionProgramPath(composition_path: []const u8, program: CompositionProgram) !void {
    if (!std.mem.endsWith(u8, composition_path, ".bin")) return error.InvalidCompositionArtifact;
    if (program == .metal) return;
    const expected = composition_path[0 .. composition_path.len - ".bin".len];
    const program_path = program.file().path;
    if (program_path.len != expected.len + ".metallib".len or
        !std.mem.eql(u8, program_path[0..expected.len], expected) or
        !std.mem.eql(u8, program_path[expected.len..], ".metallib"))
        return error.CompositionProgramNotCompanion;
}

fn requireCanonicalAbsolutePath(allocator: std.mem.Allocator, path: []const u8) !void {
    if (!std.fs.path.isAbsolute(path)) return error.RuntimePathNotAbsolute;
    const canonical = try std.fs.realpathAlloc(allocator, path);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, path)) return error.RuntimePathNotCanonical;
}

fn authenticate(
    allocator: std.mem.Allocator,
    configured: AuthenticatedFile,
    require_executable: bool,
) !artifact_manifest.Measurement {
    const measurement = try artifact_manifest.measureFile(allocator, configured.path);
    if (measurement.bytes == 0 or !std.mem.eql(u8, &measurement.sha256, &configured.sha256))
        return error.RuntimeArtifactDigestMismatch;
    if (require_executable) {
        const file = try std.fs.openFileAbsolute(configured.path, .{});
        defer file.close();
        if ((try file.stat()).mode & 0o111 == 0) return error.RunnerNotExecutable;
    }
    return measurement;
}

fn assertUnchanged(path: []const u8, expected: artifact_manifest.Measurement) !void {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const actual = artifact_manifest.FileIdentity.fromStat(try file.stat());
    if (!actual.eql(expected.identity)) return error.RuntimeArtifactChanged;
}

fn protocolGeometry(bundle: composition_bundle.Bundle) !compact.RuntimeProtocolGeometryV1 {
    var geometry = compact.RuntimeProtocolGeometryV1.sn2();
    geometry.max_log_degree_bound = bundle.verifierMaxLogDegreeBound() catch
        return error.InvalidCairoProtocolGeometry;
    geometry.fri_tree_count = 1 + (geometry.max_log_degree_bound - 1) / geometry.fri_fold_step;
    geometry.decommitment_record_count = std.math.add(
        u32,
        geometry.commitment_count,
        geometry.fri_tree_count,
    ) catch return error.InvalidCairoProtocolGeometry;
    geometry.validate() catch return error.InvalidCairoProtocolGeometry;
    return geometry;
}

fn traceColumns(bundle: composition_bundle.Bundle, preprocessed_count: usize) ![4]u32 {
    var columns = [4]u32{
        std.math.cast(u32, preprocessed_count) orelse return error.InvalidTraceColumnCount,
        0,
        0,
        8,
    };
    for (bundle.components) |component| for (component.trace_spans) |span| {
        if (span.tree == 1 or span.tree == 2)
            columns[span.tree] = @max(columns[span.tree], span.end);
    };
    for (columns) |count| if (count == 0) return error.InvalidTraceColumnCount;
    return columns;
}

fn requireExactStatement(
    allocator: std.mem.Allocator,
    path: []const u8,
    expected: []const u8,
) !void {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    const stat = try file.stat();
    if (stat.kind != .file or stat.size != expected.len) return error.RunnerStatementMismatch;
    const actual = try allocator.alloc(u8, expected.len);
    defer allocator.free(actual);
    if (try file.readAll(actual) != actual.len or !std.mem.eql(u8, actual, expected))
        return error.RunnerStatementMismatch;
}

fn runtimeManifestDigest(
    allocator: std.mem.Allocator,
    backend: *const MetalBackend,
    prepared: *const prover.PreparedProgram,
) ![32]u8 {
    const measurements = prepared.artifacts.measurements;
    const entries = [_]artifact_manifest.Entry{
        manifestEntry(.backend_executable, "metal-arena-plan", backend.measurements.runner_executable),
        manifestEntry(.adapted_input, "", fromStat(prepared.input_sha256, prepared.input_measurement.stat)),
        manifestEntry(.schedule, "", backend.measurements.schedule),
        manifestEntry(.witness_programs, "", fromSemantic(measurements.witness_programs)),
        manifestEntry(.multiplicity_feeds, "", fromSemantic(measurements.multiplicity_feeds)),
        manifestEntry(.relation_templates, "", fromSemantic(measurements.relation_templates)),
        manifestEntry(.fixed_tables, "", fromSemantic(measurements.fixed_tables)),
        manifestEntry(.composition, "", fromSemantic(measurements.composition)),
        manifestEntry(.composition_program, "", backend.measurements.composition_program),
        manifestEntry(.preprocessed_evaluations, "", backend.measurements.preprocessed_evaluations),
        manifestEntry(.preprocessed_tree0_merkle, "", backend.measurements.preprocessed_tree0_merkle),
        manifestEntry(.preprocessed_coefficients, "", fromSemantic(measurements.preprocessed_coefficients)),
        manifestEntry(.semantic_air, "semantic-pack", fromSemantic(measurements.manifest)),
        manifestEntry(.semantic_air, "composition-projection", fromSemantic(measurements.composition_projection_manifest)),
    };
    const protocol_digest = try artifact_manifest.protocolDigest(.{
        .channel = "blake2s",
        .channel_salt = 0,
        .log_blowup_factor = 1,
        .n_queries = 70,
        .interaction_pow_bits = 24,
        .query_pow_bits = 26,
        .fri_fold_step = 3,
        .fri_lifting = null,
        .fri_log_last_layer_degree_bound = 0,
    });
    return artifact_manifest.manifestDigest(allocator, protocol_digest, &entries);
}

fn manifestEntry(
    role: artifact_manifest.Role,
    logical_name: []const u8,
    measurement: artifact_manifest.Measurement,
) artifact_manifest.Entry {
    return .{
        .role = role,
        .logical_name = logical_name,
        .format_version = 1,
        .provenance = .proof_derived,
        .measurement = measurement,
        .source_chain_complete = false,
    };
}

fn fromSemantic(measurement: semantic_pack.Measurement) artifact_manifest.Measurement {
    return fromStat(measurement.sha256, measurement.stat);
}

fn fromStat(sha256: [32]u8, stat: std.fs.File.Stat) artifact_manifest.Measurement {
    return .{
        .bytes = stat.size,
        .sha256 = sha256,
        .identity = artifact_manifest.FileIdentity.fromStat(stat),
    };
}

const TemporaryFiles = struct {
    directory: []u8,
    proof: []u8,
    statement: []u8,

    fn create(allocator: std.mem.Allocator, output_path: []const u8) !TemporaryFiles {
        const parent = std.fs.path.dirname(output_path) orelse return error.InvalidOutputPath;
        var entropy: [16]u8 = undefined;
        for (0..16) |_| {
            std.crypto.random.bytes(&entropy);
            const name = std.fmt.bytesToHex(entropy, .lower);
            const directory = try std.fmt.allocPrint(allocator, "{s}/.stwo-metal-{s}", .{ parent, name });
            std.posix.mkdir(directory, 0o700) catch |err| switch (err) {
                error.PathAlreadyExists => {
                    allocator.free(directory);
                    continue;
                },
                else => {
                    allocator.free(directory);
                    return err;
                },
            };
            errdefer std.fs.deleteTreeAbsolute(directory) catch {};
            const proof = try std.fs.path.join(allocator, &.{ directory, "proof.bin" });
            errdefer allocator.free(proof);
            const statement = try std.fs.path.join(allocator, &.{ directory, "statement.bin" });
            return .{ .directory = directory, .proof = proof, .statement = statement };
        }
        return error.TemporaryDirectoryConflict;
    }

    fn deinit(self: *TemporaryFiles, allocator: std.mem.Allocator) void {
        std.fs.deleteTreeAbsolute(self.directory) catch {};
        allocator.free(self.statement);
        allocator.free(self.proof);
        allocator.free(self.directory);
        self.* = undefined;
    }
};

test "Cairo Metal backend derives SN2 runtime protocol and trace columns" {
    const allocator = std.testing.allocator;
    var composition = try composition_bundle.Bundle.readFile(allocator, "vectors/cairo/sn_pie_2_composition.bin");
    defer composition.deinit();
    const geometry = try protocolGeometry(composition);
    try std.testing.expectEqual(@as(u32, 24), geometry.max_log_degree_bound);
    try std.testing.expectEqual(@as(u32, 8), geometry.fri_tree_count);
    try std.testing.expectEqual(
        [4]u32{ 161, 3449, 2268, 8 },
        try traceColumns(composition, 161),
    );
}

test "Cairo Metal backend derives Fib-like seven-round protocol" {
    const composition = composition_bundle.Bundle{
        .allocator = undefined,
        .format_version = composition_bundle.projected_version,
        .max_kernel_instructions = 1,
        .total_constraints = 1,
        .max_evaluation_log_size = 21,
        .plan_hash = 1,
        .components = &.{},
    };
    const geometry = try protocolGeometry(composition);
    try std.testing.expectEqual(@as(u32, 20), geometry.max_log_degree_bound);
    try std.testing.expectEqual(@as(u32, 7), geometry.fri_tree_count);
    try std.testing.expectEqual(@as(u32, 11), geometry.decommitment_record_count);
}

test {
    std.testing.refAllDecls(MetalBackend);
}
