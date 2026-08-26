//! Internal schemas and arithmetic shared by RISC-V benchmark orchestration.

const std = @import("std");
const stwo = @import("stwo");
const resource_usage = @import("../resource_usage.zig");
const verified_request_attempt = @import("verified_request_attempt.zig");

pub const UNPROFILED_PROVE_SCHEMA = "riscv_prove_v1";
pub const PROFILED_PROVE_SCHEMA = "riscv_profiled_prove_attempt_v2";
pub const NATIVE_BENCHMARK_SCHEMA = "riscv_proof_v3";

pub fn proveSchema(profiled: bool) []const u8 {
    return if (profiled) PROFILED_PROVE_SCHEMA else UNPROFILED_PROVE_SCHEMA;
}

pub fn seconds(nanoseconds: u64) f64 {
    return @as(f64, @floatFromInt(nanoseconds)) / std.time.ns_per_s;
}

pub fn witnessSeconds(nodes: []const stwo.prover.stage_profile.StageNode) f64 {
    var total: f64 = 0;
    for (nodes) |node| {
        if (std.mem.eql(u8, node.id, "riscv_opcode_trace_generation") or
            std.mem.eql(u8, node.id, "riscv_infrastructure_trace_generation"))
            total += node.seconds;
        if (node.children) |children| total += witnessSeconds(children);
    }
    return total;
}

/// Fail closed if a stage from the recursive/outer pipeline is ever attached
/// to the ordinary native benchmark recorder. The public
/// `recursion_enabled=false` attestation is emitted only after this complete
/// depth-first scan succeeds for every warmup and measured sample.
pub fn requireNativeOnlyStages(
    nodes: []const stwo.prover.stage_profile.StageNode,
) error{RecursiveStageInNativeBenchmark}!void {
    for (nodes) |node| {
        if (isRecursiveStageText(node.id) or isRecursiveStageText(node.label))
            return error.RecursiveStageInNativeBenchmark;
        if (node.children) |children| try requireNativeOnlyStages(children);
    }
}

fn isRecursiveStageText(value: []const u8) bool {
    for ([_][]const u8{ "recurs", "outer", "pair_node", "pair-node" }) |marker| {
        if (containsAsciiIgnoreCase(value, marker)) return true;
    }
    return false;
}

fn containsAsciiIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or haystack.len < needle.len) return false;
    for (0..haystack.len - needle.len + 1) |offset| {
        if (std.ascii.eqlIgnoreCase(haystack[offset..][0..needle.len], needle))
            return true;
    }
    return false;
}

pub const ResidentPolynomialTelemetry = struct {
    eligible_base_components: u64 = 0,
    eligible_lookup_components: u64 = 0,
    base_batch_dispatches: u64 = 0,
    lookup_batch_dispatches: u64 = 0,
    declines: u64 = 0,
    verified_samples_with_dispatch: u64 = 0,

    pub fn fromDelta(delta: anytype) ResidentPolynomialTelemetry {
        const counters = delta.counters;
        return .{
            .eligible_base_components = counters.riscv_base_polynomial_eligible_components,
            .eligible_lookup_components = counters.riscv_lookup_polynomial_eligible_components,
            .base_batch_dispatches = counters.metal_riscv_base_polynomial_batch_dispatches,
            .lookup_batch_dispatches = counters.metal_riscv_lookup_polynomial_batch_dispatches,
            .declines = counters.cpu_riscv_polynomial_composition_declines,
        };
    }

    pub fn add(self: *ResidentPolynomialTelemetry, other: ResidentPolynomialTelemetry) !void {
        const sum = ResidentPolynomialTelemetry{
            .eligible_base_components = try std.math.add(
                u64,
                self.eligible_base_components,
                other.eligible_base_components,
            ),
            .eligible_lookup_components = try std.math.add(
                u64,
                self.eligible_lookup_components,
                other.eligible_lookup_components,
            ),
            .base_batch_dispatches = try std.math.add(
                u64,
                self.base_batch_dispatches,
                other.base_batch_dispatches,
            ),
            .lookup_batch_dispatches = try std.math.add(
                u64,
                self.lookup_batch_dispatches,
                other.lookup_batch_dispatches,
            ),
            .declines = try std.math.add(u64, self.declines, other.declines),
            .verified_samples_with_dispatch = try std.math.add(
                u64,
                self.verified_samples_with_dispatch,
                other.verified_samples_with_dispatch,
            ),
        };
        self.* = sum;
    }
};

pub const ProveReport = struct {
    schema: []const u8,
    release_status: []const u8,
    experimental: bool,
    verified_in_process: bool,
    total_steps: u32,
    n_components: u32,
    execution_seconds: f64,
    witness_seconds: f64,
    proving_seconds: f64,
    verification_seconds: f64,
    total_seconds: f64,
    statement_sha256: []const u8,
    transcript_state_blake2s: []const u8,
    implementation_commit: []const u8,
    implementation_dirty: bool,
    executable_sha256: []const u8,
    proof_path: []const u8,
    resident_polynomial_telemetry: ?ResidentPolynomialTelemetry = null,
    profiled_attempt: ?verified_request_attempt.Attempt = null,
};

pub const ProveReportExpectation = struct {
    schema: []const u8,
    release_status: []const u8,
    experimental: bool,
    implementation_commit: []const u8,
    implementation_dirty: bool,
    executable_sha256: [32]u8,
};

pub const ValidatedDigests = struct {
    statement: [32]u8,
    transcript_state: [32]u8,
};

pub fn validateProveReport(
    report: *const ProveReport,
    expected: ProveReportExpectation,
) !ValidatedDigests {
    if (!std.mem.eql(u8, report.schema, expected.schema) or
        !std.mem.eql(u8, report.release_status, expected.release_status) or
        !report.verified_in_process or
        report.experimental != expected.experimental)
    {
        return error.InvalidProveReportEnvelope;
    }
    if (!std.mem.eql(u8, report.implementation_commit, expected.implementation_commit) or
        report.implementation_dirty != expected.implementation_dirty)
    {
        return error.ImplementationIdentityMismatch;
    }
    const executable_hex = std.fmt.bytesToHex(expected.executable_sha256, .lower);
    if (!std.mem.eql(u8, report.executable_sha256, &executable_hex)) {
        return error.ExecutableIdentityMismatch;
    }
    var result: ValidatedDigests = undefined;
    if (report.statement_sha256.len != result.statement.len * 2) {
        return error.InvalidStatementDigest;
    }
    _ = std.fmt.hexToBytes(&result.statement, report.statement_sha256) catch
        return error.InvalidStatementDigest;
    if (report.transcript_state_blake2s.len != result.transcript_state.len * 2) {
        return error.InvalidTranscriptStateDigest;
    }
    _ = std.fmt.hexToBytes(
        &result.transcript_state,
        report.transcript_state_blake2s,
    ) catch return error.InvalidTranscriptStateDigest;
    return result;
}

pub const BenchmarkReport = struct {
    schema: []const u8,
    release_status: []const u8,
    mode: []const u8 = "bench",
    experimental: bool,
    profiled: bool,
    recursion_enabled: bool,
    warmups: usize,
    samples: usize,
    verified_samples: usize,
    total_steps: u32,
    n_components: u32,
    throughput_numerator: []const u8 = "vm_steps",
    median_seconds: f64,
    throughput_mhz: f64,
    mean_execution_seconds: f64,
    mean_witness_seconds: f64,
    mean_proving_seconds: f64,
    mean_verification_seconds: f64,
    sample_seconds: []const f64,
    statement_sha256: []const u8,
    transcript_state_blake2s: []const u8,
    implementation_commit: []const u8,
    implementation_dirty: bool,
    executable_sha256: []const u8,
    artifact_sha256: []const u8,
    proof_path: ?[]const u8,
    resources: resource_usage.Report,
    resident_polynomial_telemetry: ?ResidentPolynomialTelemetry,
    timing_authority: ?verified_request_attempt.BenchmarkTimingAuthority = null,
    verified_request_attempts: ?[]const *const verified_request_attempt.Attempt = null,
};

fn proveReportFixture(schema: []const u8) ProveReport {
    return .{
        .schema = schema,
        .release_status = "staged",
        .experimental = true,
        .verified_in_process = true,
        .total_steps = 1,
        .n_components = 2,
        .execution_seconds = 0.1,
        .witness_seconds = 0.2,
        .proving_seconds = 0.3,
        .verification_seconds = 0.4,
        .total_seconds = 1.0,
        .statement_sha256 = "00" ** 32,
        .transcript_state_blake2s = "00" ** 32,
        .implementation_commit = "commit",
        .implementation_dirty = false,
        .executable_sha256 = "00" ** 32,
        .proof_path = "proof.json",
    };
}

test "unprofiled child report preserves the exact riscv_prove_v1 field set" {
    const report = proveReportFixture(proveSchema(false));
    const encoded = try std.json.Stringify.valueAlloc(std.testing.allocator, report, .{
        .emit_null_optional_fields = false,
    });
    defer std.testing.allocator.free(encoded);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, encoded, .{});
    defer parsed.deinit();

    const expected = [_][]const u8{
        "schema",                   "release_status",
        "experimental",             "verified_in_process",
        "total_steps",              "n_components",
        "execution_seconds",        "witness_seconds",
        "proving_seconds",          "verification_seconds",
        "total_seconds",            "statement_sha256",
        "transcript_state_blake2s", "implementation_commit",
        "implementation_dirty",     "executable_sha256",
        "proof_path",
    };
    const object = parsed.value.object;
    try std.testing.expectEqual(expected.len, object.count());
    for (expected) |field| try std.testing.expect(object.contains(field));
    try std.testing.expectEqualStrings(UNPROFILED_PROVE_SCHEMA, object.get("schema").?.string);
    try std.testing.expect(!object.contains("profiled_attempt"));
    try std.testing.expect(!object.contains("resident_polynomial_telemetry"));
}

test "profiled child reports require their distinct internal schema" {
    const executable_sha256 = [_]u8{0} ** 32;
    var report = proveReportFixture(UNPROFILED_PROVE_SCHEMA);
    const expected = ProveReportExpectation{
        .schema = PROFILED_PROVE_SCHEMA,
        .release_status = "staged",
        .experimental = true,
        .implementation_commit = "commit",
        .implementation_dirty = false,
        .executable_sha256 = executable_sha256,
    };
    try std.testing.expectError(
        error.InvalidProveReportEnvelope,
        validateProveReport(&report, expected),
    );
    report.schema = PROFILED_PROVE_SCHEMA;
    const validated = try validateProveReport(&report, expected);
    try std.testing.expectEqual(executable_sha256, validated.statement);
    try std.testing.expectEqual(executable_sha256, validated.transcript_state);
}

test "resident telemetry aggregation is checked and atomic" {
    var total = ResidentPolynomialTelemetry{
        .eligible_base_components = 7,
        .declines = std.math.maxInt(u64),
    };
    const before = total;
    try std.testing.expectError(
        error.Overflow,
        total.add(.{ .eligible_base_components = 5, .declines = 1 }),
    );
    try std.testing.expectEqualDeep(before, total);
}

test "unprofiled native benchmark preserves its exact recursion-disabled field set" {
    const sample_seconds = [_]f64{1.0};
    const report = BenchmarkReport{
        .schema = NATIVE_BENCHMARK_SCHEMA,
        .release_status = "staged",
        .experimental = true,
        .profiled = false,
        .recursion_enabled = false,
        .warmups = 1,
        .samples = 1,
        .verified_samples = 1,
        .total_steps = 1,
        .n_components = 1,
        .median_seconds = 1.0,
        .throughput_mhz = 0.000001,
        .mean_execution_seconds = 0.1,
        .mean_witness_seconds = 0.2,
        .mean_proving_seconds = 0.3,
        .mean_verification_seconds = 0.4,
        .sample_seconds = &sample_seconds,
        .statement_sha256 = "00" ** 32,
        .transcript_state_blake2s = "00" ** 32,
        .implementation_commit = "00" ** 20,
        .implementation_dirty = false,
        .executable_sha256 = "00" ** 32,
        .artifact_sha256 = "00" ** 32,
        .proof_path = "proof.json",
        .resources = .{
            .availability = .unavailable,
            .unavailable_reason = .unsupported_platform,
            .before_warmups = null,
            .after_verified_samples = null,
            .interval_delta = null,
        },
        .resident_polynomial_telemetry = null,
    };
    const encoded = try std.json.Stringify.valueAlloc(std.testing.allocator, report, .{
        .emit_null_optional_fields = false,
    });
    defer std.testing.allocator.free(encoded);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, encoded, .{});
    defer parsed.deinit();

    const expected = [_][]const u8{
        "schema",                   "release_status",
        "mode",                     "experimental",
        "profiled",                 "recursion_enabled",
        "warmups",                  "samples",
        "verified_samples",         "total_steps",
        "n_components",             "throughput_numerator",
        "median_seconds",           "throughput_mhz",
        "mean_execution_seconds",   "mean_witness_seconds",
        "mean_proving_seconds",     "mean_verification_seconds",
        "sample_seconds",           "statement_sha256",
        "transcript_state_blake2s", "implementation_commit",
        "implementation_dirty",     "executable_sha256",
        "artifact_sha256",          "proof_path",
        "resources",
    };
    const object = parsed.value.object;
    try std.testing.expectEqual(expected.len, object.count());
    for (expected) |field| try std.testing.expect(object.contains(field));
    try std.testing.expectEqualStrings(
        NATIVE_BENCHMARK_SCHEMA,
        object.get("schema").?.string,
    );
    try std.testing.expect(!object.get("recursion_enabled").?.bool);
    try std.testing.expect(!object.contains("timing_authority"));
    try std.testing.expect(!object.contains("verified_request_attempts"));
    try std.testing.expect(!object.contains("resident_polynomial_telemetry"));
}

test "native stage contract rejects recursive outer stages at any depth" {
    var native_children = [_]stwo.prover.stage_profile.StageNode{.{
        .id = "composition_domain",
        .label = "native quotient composition",
        .seconds = 0.1,
    }};
    var native = [_]stwo.prover.stage_profile.StageNode{.{
        .id = "riscv_main_trace_commit",
        .label = "RISC-V main trace commit",
        .seconds = 0.2,
        .children = &native_children,
    }};
    try requireNativeOnlyStages(&native);

    var recursive_children = [_]stwo.prover.stage_profile.StageNode{.{
        .id = "recursive_fri_outer_prove",
        .label = "recursive FRI outer proof",
        .seconds = 0.1,
    }};
    var recursive = [_]stwo.prover.stage_profile.StageNode{.{
        .id = "riscv_main_trace_commit",
        .label = "RISC-V main trace commit",
        .seconds = 0.2,
        .children = &recursive_children,
    }};
    try std.testing.expectError(
        error.RecursiveStageInNativeBenchmark,
        requireNativeOnlyStages(&recursive),
    );
}

test "ordinary execution options contain no active policy or recursion hook" {
    const options = stwo.frontends.riscv.prover_mod.ExecutionOptions{};
    try std.testing.expect(options.cpu == null);
    try std.testing.expect(options.statement_admission == null);

    const fields = @typeInfo(@TypeOf(options)).@"struct".fields;
    try std.testing.expectEqual(@as(usize, 2), fields.len);
    try std.testing.expectEqualStrings("cpu", fields[0].name);
    try std.testing.expectEqualStrings("statement_admission", fields[1].name);
}
