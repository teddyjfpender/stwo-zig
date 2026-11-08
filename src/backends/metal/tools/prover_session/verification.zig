//! Compact-proof validation, Rust verifier execution, and atomic publication.

const std = @import("std");
const stwo = @import("stwo");
const artifact_manifest = stwo.metal_session.artifact_manifest;
const compact_interchange = stwo.frontends.cairo.compact_verifier_interchange;
const composition_bundle = stwo.frontends.cairo.witness.composition_bundle;
const fixed_table_bundle = stwo.frontends.cairo.witness.fixed_table_bundle;
const one_shot = @import("one_shot");
const protocol = stwo.metal_session.protocol;
const state = @import("state.zig");
const io = @import("io.zig");

const persistent_report_schema_version = state.persistent_report_schema_version;
const in_process_runner_linkage = state.in_process_runner_linkage;
const rust_verifier_adapter_version = state.rust_verifier_adapter_version;
const rust_verifier_envelope_abi = state.rust_verifier_envelope_abi;
const rust_verifier_mode = state.rust_verifier_mode;
const rust_verifier_cargo_lock_sha256 = state.rust_verifier_cargo_lock_sha256;
const rust_verifier_stwo_cairo_revision = state.rust_verifier_stwo_cairo_revision;
const rust_verifier_stwo_revision = state.rust_verifier_stwo_revision;
const RustVerifierConfig = state.RustVerifierConfig;
const RustVerifierEvidence = state.RustVerifierEvidence;
const PreparedGeometryKey = state.PreparedGeometryKey;
const PreparedGeometryPolicy = state.PreparedGeometryPolicy;
const PreparedHostGeometryCache = state.PreparedHostGeometryCache;
const ProofResult = state.ProofResult;
const ArtifactObjectEvidence = state.ArtifactObjectEvidence;
const ArtifactObjectsEvidence = state.ArtifactObjectsEvidence;
const ExecutableIdentity = state.ExecutableIdentity;
const ProvenanceEvidence = state.ProvenanceEvidence;
const EnvironmentValue = state.EnvironmentValue;
const VerifierScratch = state.VerifierScratch;
const ArtifactSlot = state.ArtifactSlot;
const artifact_slot_count = state.artifact_slot_count;
const PreparedArtifacts = state.PreparedArtifacts;
const RunnerArtifacts = state.RunnerArtifacts;
const RunnerRequest = state.RunnerRequest;
const ViewCache = state.ViewCache;

pub const copyFileExclusive = io.copyFileExclusive;

pub fn cliProofLayout(object: std.json.ObjectMap) !compact_interchange.CompactProofLayoutV1 {
    const value = object.get("proof_layout") orelse return error.InvalidProofLayout;
    if (value != .object or value.object.count() != 3) return error.InvalidProofLayout;
    const layout = value.object;
    inline for (.{
        "interaction_claim_words",
        "sampled_value_words",
        "decommitment_capacity_words",
    }) |name| {
        if (!layout.contains(name)) return error.InvalidProofLayout;
    }
    return .{
        .interaction_claim_words = std.math.cast(
            u32,
            try positiveIntegerField(layout, "interaction_claim_words"),
        ) orelse return error.InvalidProofLayout,
        .sampled_value_words = std.math.cast(
            u32,
            try positiveIntegerField(layout, "sampled_value_words"),
        ) orelse return error.InvalidProofLayout,
        .decommitment_capacity_words = std.math.cast(
            u32,
            try positiveIntegerField(layout, "decommitment_capacity_words"),
        ) orelse return error.InvalidProofLayout,
    };
}

pub const CompactRuntimeProtocol = struct {
    geometry: compact_interchange.RuntimeProtocolGeometryV1,
    trace_columns: [4]u32,
};

pub fn compactRuntimeProtocolFromArtifacts(
    allocator: std.mem.Allocator,
    composition_path: []const u8,
    fixed_tables_path: []const u8,
) !CompactRuntimeProtocol {
    var composition = try composition_bundle.Bundle.readFile(allocator, composition_path);
    defer composition.deinit();
    var fixed_tables = try fixed_table_bundle.Bundle.readFile(allocator, fixed_tables_path);
    defer fixed_tables.deinit();
    const max_log_degree_bound = composition.verifierMaxLogDegreeBound() catch
        return error.InvalidCompactProtocolGeometry;
    return compactRuntimeProtocolFromComponents(
        composition.components,
        fixed_tables.preprocessed_identities.len,
        max_log_degree_bound,
    );
}

pub fn compactRuntimeProtocolFromComponents(
    components: anytype,
    preprocessed_count: usize,
    max_log_degree_bound: u32,
) !CompactRuntimeProtocol {
    const preprocessed_columns = std.math.cast(u32, preprocessed_count) orelse
        return error.InvalidCompactProtocolGeometry;
    var trace_columns = [4]u32{ preprocessed_columns, 0, 0, 8 };
    for (components) |component| {
        if (component.trace_spans.len != 3) return error.InvalidCompactProtocolGeometry;
        for (component.trace_spans, 0..) |span, tree_index| {
            if (span.tree != @as(u32, @intCast(tree_index)))
                return error.InvalidCompactProtocolGeometry;
            switch (tree_index) {
                0 => if (span.start != 0 or span.end != 0)
                    return error.InvalidCompactProtocolGeometry,
                1, 2 => {
                    if (span.start != trace_columns[tree_index] or span.end < span.start)
                        return error.InvalidCompactProtocolGeometry;
                    trace_columns[tree_index] = span.end;
                },
                else => unreachable,
            }
        }
    }
    if (max_log_degree_bound == 0 or trace_columns[0] == 0 or
        trace_columns[1] == 0 or trace_columns[2] == 0)
        return error.InvalidCompactProtocolGeometry;

    var geometry = compact_interchange.RuntimeProtocolGeometryV1.sn2();
    geometry.max_log_degree_bound = max_log_degree_bound;
    const folds = geometry.max_log_degree_bound - geometry.log_last_layer_degree_bound;
    if (geometry.fri_fold_step == 0 or folds < geometry.fri_fold_step)
        return error.InvalidCompactProtocolGeometry;
    geometry.fri_tree_count = 1 + (folds - 1) / geometry.fri_fold_step;
    geometry.decommitment_record_count = std.math.add(
        u32,
        geometry.commitment_count,
        geometry.fri_tree_count,
    ) catch return error.InvalidCompactProtocolGeometry;
    geometry.validate() catch return error.InvalidCompactProtocolGeometry;
    _ = compact_interchange.PreprocessedTraceVariantV1.fromTraceTree0ColumnCount(
        trace_columns[0],
    ) catch return error.InvalidCompactProtocolGeometry;
    return .{ .geometry = geometry, .trace_columns = trace_columns };
}

test "session compact protocol derives checked-in SN2 artifact geometry" {
    const runtime = try compactRuntimeProtocolFromArtifacts(
        std.testing.allocator,
        "vectors/cairo/sn_pie_2_composition.bin",
        "vectors/cairo/cairo_fixed_tables.bin",
    );
    try std.testing.expectEqual(@as(u32, 24), runtime.geometry.max_log_degree_bound);
    try std.testing.expectEqual(@as(u32, 8), runtime.geometry.fri_tree_count);
    try std.testing.expectEqual(@as(u32, 12), runtime.geometry.decommitment_record_count);
    try std.testing.expectEqual([4]u32{ 161, 3449, 2268, 8 }, runtime.trace_columns);
}

test "session compact protocol derives projected Fib geometry from authenticated bound" {
    const Component = struct { trace_spans: []const composition_bundle.TraceSpan };
    const first_spans = [_]composition_bundle.TraceSpan{
        .{ .tree = 0, .start = 0, .end = 0 },
        .{ .tree = 1, .start = 0, .end = 200 },
        .{ .tree = 2, .start = 0, .end = 100 },
    };
    const second_spans = [_]composition_bundle.TraceSpan{
        .{ .tree = 0, .start = 0, .end = 0 },
        .{ .tree = 1, .start = 200, .end = 396 },
        .{ .tree = 2, .start = 100, .end = 324 },
    };
    const components = [_]Component{
        .{ .trace_spans = &first_spans },
        .{ .trace_spans = &second_spans },
    };
    const runtime = try compactRuntimeProtocolFromComponents(&components, 105, 20);
    try std.testing.expectEqual(@as(u32, 20), runtime.geometry.max_log_degree_bound);
    try std.testing.expectEqual(@as(u32, 7), runtime.geometry.fri_tree_count);
    try std.testing.expectEqual(@as(u32, 11), runtime.geometry.decommitment_record_count);
    try std.testing.expectEqual([4]u32{ 105, 396, 324, 8 }, runtime.trace_columns);

    const compact_protocol = try (compact_interchange.CompactProofLayoutV1{
        .interaction_claim_words = 4,
        .sampled_value_words = 4,
        .decommitment_capacity_words = 324,
    }).protocolRuntime(0, runtime.geometry, runtime.trace_columns);
    const encoded = try compact_protocol.encode();
    try std.testing.expectEqual(@as(u32, 2), std.mem.readInt(u32, encoded[24..28], .little));
    try std.testing.expectEqual(@as(u32, 20), std.mem.readInt(u32, encoded[108..112], .little));
}

test "session compact protocol rejects unauthenticated trace geometry" {
    const Component = struct { trace_spans: []const composition_bundle.TraceSpan };
    const spans = [_]composition_bundle.TraceSpan{
        .{ .tree = 0, .start = 0, .end = 0 },
        .{ .tree = 1, .start = 1, .end = 2 },
        .{ .tree = 2, .start = 0, .end = 1 },
    };
    const components = [_]Component{.{ .trace_spans = &spans }};
    try std.testing.expectError(
        error.InvalidCompactProtocolGeometry,
        compactRuntimeProtocolFromComponents(&components, 105, 20),
    );
    try std.testing.expectError(
        error.InvalidCompactProtocolGeometry,
        compactRuntimeProtocolFromComponents(&components, 160, 20),
    );
}

pub const VerifierWatchdog = struct {
    pid: std.posix.pid_t,
    complete: std.Thread.ResetEvent = .{},
    timeout_ns: u64,
    grace_ns: u64,
    timed_out: bool = false,
    signal_failed: bool = false,

    pub fn signalGroup(self: *VerifierWatchdog, signal: u8) void {
        std.posix.kill(-self.pid, signal) catch |group_error| switch (group_error) {
            error.ProcessNotFound => return,
            else => std.posix.kill(self.pid, signal) catch |leader_error| switch (leader_error) {
                error.ProcessNotFound => return,
                else => self.signal_failed = true,
            },
        };
    }

    pub fn run(self: *VerifierWatchdog) void {
        self.complete.timedWait(self.timeout_ns) catch |wait_error| switch (wait_error) {
            error.Timeout => {
                self.timed_out = true;
                self.signalGroup(std.posix.SIG.TERM);
                self.complete.timedWait(self.grace_ns) catch |grace_error| switch (grace_error) {
                    error.Timeout => {},
                };
                self.signalGroup(std.posix.SIG.KILL);
            },
        };
    }
};

pub fn runDirectWithTimeout(
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    cwd: ?[]const u8,
    timeout_ns: u64,
    grace_ns: u64,
) !std.process.Child.Term {
    if (argv.len == 0 or !std.fs.path.isAbsolute(argv[0])) return error.InvalidChildExecutable;
    var empty_environment = std.process.EnvMap.init(allocator);
    defer empty_environment.deinit();
    var child = std.process.Child.init(argv, allocator);
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    child.env_map = &empty_environment;
    child.cwd = cwd;
    child.expand_arg0 = .no_expand;
    child.pgid = 0;
    try child.spawn();
    child.waitForSpawn() catch |err| {
        _ = child.wait() catch {};
        return err;
    };

    var watchdog = VerifierWatchdog{
        .pid = child.id,
        .timeout_ns = timeout_ns,
        .grace_ns = grace_ns,
    };
    const watchdog_thread = std.Thread.spawn(.{}, VerifierWatchdog.run, .{&watchdog}) catch |err| {
        watchdog.signalGroup(std.posix.SIG.KILL);
        _ = child.wait() catch {};
        return err;
    };
    const wait_result = child.wait();
    watchdog.complete.set();
    watchdog_thread.join();
    const term = try wait_result;
    if (watchdog.signal_failed) return error.ProcessGroupTerminationFailed;
    if (watchdog.timed_out) return error.RustVerifierTimedOut;
    return term;
}

pub fn runRustVerifier(
    allocator: std.mem.Allocator,
    config: RustVerifierConfig,
    envelope_path: []const u8,
    result_path: []const u8,
    expected: compact_interchange.EnvelopeSummary,
) !RustVerifierEvidence {
    try config.assertUnchanged();
    try requireAbsent(result_path);
    var service_timer = try std.time.Timer.start();
    const term = try runDirectWithTimeout(
        allocator,
        &.{
            config.executable_path,
            "verify",
            "--envelope",
            envelope_path,
            "--result",
            result_path,
        },
        std.fs.path.dirname(envelope_path),
        30 * std.time.ns_per_s,
        2 * std.time.ns_per_s,
    );
    const service_wall_time_ns = service_timer.read();
    try config.assertUnchanged();
    switch (term) {
        .Exited => |code| if (code != 0) return error.RustVerifierRejected,
        else => return error.RustVerifierAbnormalTermination,
    }

    const result_file = try std.fs.openFileAbsolute(result_path, .{});
    defer result_file.close();
    const before = try result_file.stat();
    if (before.kind != .file or before.size == 0 or before.size > 1024 * 1024)
        return error.InvalidRustVerifierResult;
    const encoded = try result_file.readToEndAlloc(allocator, 1024 * 1024);
    defer allocator.free(encoded);
    const after = try result_file.stat();
    if (!artifact_manifest.FileIdentity.fromStat(before).eql(
        artifact_manifest.FileIdentity.fromStat(after),
    )) return error.RustVerifierResultChanged;
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, encoded, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidRustVerifierResult;
    const object = parsed.value.object;
    const required_keys = [_][]const u8{
        "schema_version",
        "envelope_abi",
        "adapter_version",
        "cargo_lock_sha256",
        "executable_sha256",
        "stwo_cairo_revision",
        "stwo_revision",
        "protocol_digest",
        "statement_digest",
        "proof_digest",
        "provenance_digest",
        "verification_mode",
        "verified",
        "wall_time_ns",
        "error",
    };
    if (object.count() != required_keys.len) return error.InvalidRustVerifierResult;
    for (required_keys) |name| if (!object.contains(name)) return error.InvalidRustVerifierResult;
    if (!jsonIntegerIs(object.get("schema_version"), 1) or
        !jsonStringIs(object.get("envelope_abi"), rust_verifier_envelope_abi) or
        !jsonStringIs(object.get("adapter_version"), rust_verifier_adapter_version) or
        !jsonStringIs(object.get("cargo_lock_sha256"), rust_verifier_cargo_lock_sha256) or
        !jsonStringIs(object.get("executable_sha256"), &config.executable_sha256) or
        !jsonStringIs(object.get("stwo_cairo_revision"), rust_verifier_stwo_cairo_revision) or
        !jsonStringIs(object.get("stwo_revision"), rust_verifier_stwo_revision) or
        !jsonStringIs(object.get("verification_mode"), rust_verifier_mode) or
        !(optionalBoolField(object, "verified") orelse false) or
        object.get("error").? != .null)
        return error.InvalidRustVerifierResult;

    const protocol_digest = std.fmt.bytesToHex(expected.protocol_sha256, .lower);
    const statement_digest = std.fmt.bytesToHex(expected.statement_sha256, .lower);
    const proof_digest = std.fmt.bytesToHex(expected.proof_sha256, .lower);
    const provenance_digest = std.fmt.bytesToHex(expected.provenance_sha256, .lower);
    if (!jsonStringIs(object.get("protocol_digest"), &protocol_digest) or
        !jsonStringIs(object.get("statement_digest"), &statement_digest) or
        !jsonStringIs(object.get("proof_digest"), &proof_digest) or
        !jsonStringIs(object.get("provenance_digest"), &provenance_digest))
        return error.RustVerifierDigestMismatch;
    const wall_time_value = object.get("wall_time_ns").?;
    if (wall_time_value != .integer or wall_time_value.integer <= 0)
        return error.InvalidRustVerifierResult;
    var result_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(encoded, &result_digest, .{});
    return .{
        .protocol_digest = protocol_digest,
        .statement_digest = statement_digest,
        .proof_digest = proof_digest,
        .provenance_digest = provenance_digest,
        .executable_sha256 = config.executable_sha256,
        .wall_time_ns = @intCast(wall_time_value.integer),
        .service_wall_time_ns = service_wall_time_ns,
        .result_sha256 = std.fmt.bytesToHex(result_digest, .lower),
    };
}

pub fn jsonStringIs(value: ?std.json.Value, expected: []const u8) bool {
    const actual = value orelse return false;
    return actual == .string and std.mem.eql(u8, actual.string, expected);
}

pub fn jsonIntegerIs(value: ?std.json.Value, expected: u64) bool {
    const actual = value orelse return false;
    return actual == .integer and actual.integer >= 0 and actual.integer == expected;
}

pub fn measureExecutableIdentity(allocator: std.mem.Allocator) !ExecutableIdentity {
    const executable_path = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(executable_path);
    const measurement = try artifact_manifest.measureFile(allocator, executable_path);
    const digest_hex = std.fmt.bytesToHex(measurement.sha256, .lower);
    return .{
        .daemon_executable_sha256 = digest_hex,
        .runner_executable_sha256 = digest_hex,
        .measurement = measurement,
    };
}

pub fn temporaryPath(allocator: std.mem.Allocator, output: []const u8, sequence: u64, label: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}.session-{}-{}-{s}.tmp", .{
        output,
        std.c.getpid(),
        sequence,
        label,
    });
}

pub fn requireAbsent(path: []const u8) !void {
    if (std.fs.accessAbsolute(path, .{})) |_| return error.TemporaryOutputExists else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
}

/// Publish a sibling temporary without replacing an output created after the
/// request's initial stale-output check.
pub fn publishExclusive(temporary: []const u8, output: []const u8) !void {
    try std.posix.link(temporary, output);
    std.fs.deleteFileAbsolute(temporary) catch {};
}

pub fn publishOutputsExclusive(
    proof_temporary: []const u8,
    proof_output: []const u8,
    report_temporary: []const u8,
    report_output: []const u8,
) !void {
    try publishExclusive(proof_temporary, proof_output);
    errdefer std.fs.deleteFileAbsolute(proof_output) catch {};
    try publishExclusive(report_temporary, report_output);
}

pub fn boolField(object: std.json.ObjectMap, name: []const u8) !bool {
    const value = object.get(name) orelse return error.InvalidCliReport;
    if (value != .bool) return error.InvalidCliReport;
    return value.bool;
}

pub fn requireCanonicalCliProtocol(object: std.json.ObjectMap) !void {
    if (!(optionalBoolField(object, "protocol_complete") orelse false) or
        !one_shot.protocolObjectIsCanonical(object.get("protocol")))
        return error.InvalidCliProtocol;
}

pub fn cliProvenance(object: std.json.ObjectMap) ProvenanceEvidence {
    const artifact_manifest_digest = optionalSha256HexField(object, "artifact_manifest_digest");
    const self_contained = optionalBoolField(object, "self_contained") orelse
        return .failClosed();
    const parity_fixture_used = optionalBoolField(object, "parity_fixture_used") orelse
        return .failClosed();
    const proof_derived_artifact_used = optionalBoolField(object, "proof_derived_artifact_used") orelse
        return .failClosed();
    const statement_self_derived = optionalBoolField(object, "statement_self_derived") orelse
        return .failClosed();

    // A self-contained classification cannot contradict its constituent
    // execution evidence. Preserve verified proofs, but classify malformed
    // provenance conservatively rather than publishing an impossible state.
    if (self_contained and
        (parity_fixture_used or proof_derived_artifact_used or !statement_self_derived))
    {
        return .failClosed();
    }

    if (artifact_manifest_digest == null) {
        return .{
            .self_contained = false,
            .parity_fixture_used = parity_fixture_used,
            .proof_derived_artifact_used = true,
            .statement_self_derived = statement_self_derived,
            .artifact_manifest_digest = null,
            .provenance_complete = false,
        };
    }
    return .{
        .self_contained = self_contained,
        .parity_fixture_used = parity_fixture_used,
        .proof_derived_artifact_used = proof_derived_artifact_used,
        .statement_self_derived = statement_self_derived,
        .artifact_manifest_digest = artifact_manifest_digest,
        .provenance_complete = true,
    };
}

pub fn optionalBoolField(object: std.json.ObjectMap, name: []const u8) ?bool {
    const value = object.get(name) orelse return null;
    if (value != .bool) return null;
    return value.bool;
}

pub fn optionalSha256HexField(object: std.json.ObjectMap, name: []const u8) ?[64]u8 {
    const value = object.get(name) orelse return null;
    if (value != .string or value.string.len != 64) return null;
    for (value.string) |byte| switch (byte) {
        '0'...'9', 'a'...'f' => {},
        else => return null,
    };
    var digest: [64]u8 = undefined;
    @memcpy(&digest, value.string);
    return digest;
}

pub fn stringField(object: std.json.ObjectMap, name: []const u8) ![]const u8 {
    const value = object.get(name) orelse return error.InvalidCliReport;
    if (value != .string) return error.InvalidCliReport;
    return value.string;
}

pub fn positiveNumberField(object: std.json.ObjectMap, name: []const u8) !f64 {
    const value = object.get(name) orelse return error.InvalidCliReport;
    const number: f64 = switch (value) {
        .float => |number| number,
        .integer => |number| @floatFromInt(number),
        else => return error.InvalidCliReport,
    };
    if (!std.math.isFinite(number) or number <= 0) return error.InvalidCliReport;
    return number;
}

pub fn positiveIntegerField(object: std.json.ObjectMap, name: []const u8) !u64 {
    const value = object.get(name) orelse return error.InvalidCliReport;
    if (value != .integer or value.integer <= 0) return error.InvalidCliReport;
    return @intCast(value.integer);
}

pub const writeFrame = io.writeFrame;
