//! Authenticated-AOT Metal producer for the shared native full-leaf transaction.
//! The transaction serializes, destroys producer state, freshly verifies on CPU,
//! and only then publishes. A CPU reference proof is not a production input.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const metal = @import("stwo_metal_backend");
const cpu = @import("stwo_riscv_cpu_stage101_degree5_metal");
const replay = cpu.ethereum_incremental_full_leaf_replay_command_v4;
const execution = cpu.ethereum_incremental_full_leaf_throughput_execution_v1;
const Backend = metal.MetalCommitBackend;
const Engine = frontend.recursion.engine.ProverEngineForBackend(Backend);
const ClaimAdmission = @FieldType(replay.Options, "claim_admission");

pub const command_name = "ethereum-incremental-full-leaf-replay-prepared-metal-v1";

pub const Options = struct {
    prepared: replay.PreparedCpuOptionsV1,
    aot_bundle: []const u8,
    aot_manifest_sha256: [32]u8,

    pub fn parse(arguments: []const []const u8) !Options {
        // The shared parser owns replay option validation and its size bound.
        const replay_limit = @typeInfo(@FieldType(replay.PreparedCpuOptionsV1, "replay_arguments")).array.len;
        var forwarded: [replay_limit + 6][]const u8 = undefined;
        var count: usize = 0;
        var bundle: ?[]const u8 = null;
        var manifest: ?[32]u8 = null;
        var at: usize = 0;
        while (at < arguments.len) : (at += 2) {
            if (at + 1 == arguments.len) return error.InvalidArguments;
            const key = arguments[at];
            const value = arguments[at + 1];
            if (std.mem.eql(u8, key, "--aot-bundle")) {
                if (bundle != null) return error.DuplicateArgument;
                if (value.len == 0) return error.InvalidArguments;
                bundle = value;
            } else if (std.mem.eql(u8, key, "--aot-manifest-sha256")) {
                if (manifest != null) return error.DuplicateArgument;
                if (value.len != 64) return error.InvalidManifestSha256;
                var digest: [32]u8 = undefined;
                _ = std.fmt.hexToBytes(&digest, value) catch return error.InvalidManifestSha256;
                manifest = digest;
            } else {
                if (count + 2 > forwarded.len) return error.InvalidArguments;
                forwarded[count] = key;
                forwarded[count + 1] = value;
                count += 2;
            }
        }
        return .{
            .prepared = try replay.PreparedCpuOptionsV1.parse(forwarded[0..count]),
            .aot_bundle = bundle orelse return error.MissingAotBundle,
            .aot_manifest_sha256 = manifest orelse return error.MissingAotManifestSha256,
        };
    }
};

fn aotProfile(admission: ClaimAdmission) metal.shaders.aot_profile.Profile {
    return switch (admission) {
        .legacy_aggregate_v2, .selected_detailed_v3, .field_authority_v4 => .core_v2,
        .fixed_program_narrow_v5 => .ethereum_fixed_program_narrow_v1,
    };
}

fn validateRuntime(
    lifecycle: Backend.RuntimeLifecycleSnapshot,
    manifest: [32]u8,
    profile: metal.shaders.aot_profile.Profile,
) !void {
    const identity = lifecycle.identity orelse return error.AuthenticatedMetalRuntimeMissing;
    if (!lifecycle.initialized or identity.origin != .authenticated_core_aot or
        identity.manifest_sha256 == null or !std.meta.eql(identity.manifest_sha256.?, manifest) or
        identity.metallib_sha256 == null or identity.metallib_bytes == null or identity.metallib_bytes.? == 0 or
        !std.meta.eql(identity.source_sha256, profile.sourceDigest()))
        return error.AuthenticatedMetalRuntimeMismatch;
}

const Release = struct {
    lifecycle: Backend.RuntimeLifecycleSnapshot,
    telemetry: metal.telemetry.Snapshot,
    manifest: [32]u8,
    admission: ClaimAdmission,
    initialization_ns: u64,

    fn validateOpaque(context: *anyopaque, evidence: replay.ReleaseEvidenceV1) anyerror!void {
        const self: *const Release = @ptrCast(@alignCast(context));
        const current = Backend.runtimeLifecycleSnapshot();
        try validateRuntime(current, self.manifest, aotProfile(self.admission));
        if (!std.meta.eql(current.identity, self.lifecycle.identity) or
            current.initialization_count != self.lifecycle.initialization_count or
            current.shutdown_count != self.lifecycle.shutdown_count or
            evidence.claim_admission != self.admission)
            return error.PreparedMetalReleaseAdmissionMismatch;
        const delta = (try Backend.telemetrySnapshot()).delta(self.telemetry);
        try delta.requireMetalDispatch();
        std.debug.print(
            "ETHEREUM_PREPARED_METAL_V1 claim_schema={} aot_manifest_sha256={s} " ++
                "initialization_ns={} producer_ns={} cold_verify_ns={} " ++
                "device_dispatches={} host_fallbacks={} independently_cold_verified=true\n",
            .{ @intFromEnum(self.admission), std.fmt.bytesToHex(self.manifest, .lower), self.initialization_ns, evidence.producer_elapsed_ns, evidence.cold_verify_elapsed_ns, delta.counters.metalDispatchTotal(), delta.counters.cpuFallbackTotal() },
        );
    }
};

pub fn run(allocator: std.mem.Allocator, arguments: []const []const u8) !void {
    const options = try Options.parse(arguments);
    const prepared = &options.prepared;
    const replay_arguments = prepared.replay_arguments[0..prepared.replay_argument_count];
    const admitted = try replay.Options.parse(replay_arguments);
    const policy = try execution.PolicyV1.init(prepared.worker_count, prepared.host_byte_budget, try execution.HostCapacityV1.detect(prepared.host_byte_limit));
    if (Backend.runtimeLifecycleSnapshot().initialized) return error.MetalRuntimeAlreadyInitialized;
    var timer = try std.time.Timer.start();
    try Backend.initializeRuntime(allocator, .{ .authenticated_aot = .{
        .bundle_path = options.aot_bundle,
        .manifest_sha256 = options.aot_manifest_sha256,
        .profile = aotProfile(admitted.claim_admission),
    } });
    defer Backend.shutdown() catch unreachable;
    const lifecycle = Backend.runtimeLifecycleSnapshot();
    try validateRuntime(lifecycle, options.aot_manifest_sha256, aotProfile(admitted.claim_admission));
    var release = Release{
        .lifecycle = lifecycle,
        .telemetry = try Backend.telemetrySnapshot(),
        .manifest = options.aot_manifest_sha256,
        .admission = admitted.claim_admission,
        .initialization_ns = timer.read(),
    };
    try replay.runPreparedWithEnginesAndExecution(Engine, replay.CpuEngine, allocator, replay_arguments, .{ .context = &release, .validate_fn = Release.validateOpaque }, policy);
}

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const arguments = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, arguments);
    const options = if (arguments.len > 1 and std.mem.eql(u8, arguments[1], command_name)) arguments[2..] else arguments[1..];
    try run(allocator, options);
}

const test_arguments = [_][]const u8{
    "--retained-materialization-result", "/retained/materialization.json",
    "--publication-root",                "/retained/publication",
    "--segment-index",                   "9",
    "--output",                          "/proof.bin",
    "--claim-admission",                 "fixed_program_narrow_v5",
    "--campaign-geometry",               "authenticated-v1",
    "--selected-leaf-admission-root",    "/selected/leaf9",
    "--global-metadata-output",          "/leaf.json",
    "--pcs-retained-byte-budget",        "25769803776",
    "--workers",                         "1",
    "--host-byte-budget",                "17179869184",
    "--host-byte-limit",                 "34359738368",
};
const test_aot_arguments = [_][]const u8{ "--aot-bundle", "/aot", "--aot-manifest-sha256", "01" ** 32 };

test "prepared Metal accepts complete shared leaf options without a CPU reference" {
    const options = try Options.parse(&(test_arguments ++ test_aot_arguments));
    const prepared = options.prepared;
    const shared = try replay.Options.parse(prepared.replay_arguments[0..prepared.replay_argument_count]);
    try std.testing.expectEqual(@as(u32, 9), shared.segment_index);
    try std.testing.expectEqual(@as(usize, 24 * 1024 * 1024 * 1024), shared.pcs_retained_byte_budget.?);
    try std.testing.expectEqual(@as(usize, 1), prepared.worker_count);
    try std.testing.expectEqual(ClaimAdmission.fixed_program_narrow_v5, shared.claim_admission);
    try std.testing.expectEqualSlices(u8, &(.{1} ** 32), &options.aot_manifest_sha256);
}

test "prepared Metal rejects missing malformed duplicate AOT and unknown shared options" {
    try std.testing.expectError(error.MissingAotBundle, Options.parse(&test_arguments));
    try std.testing.expectError(error.MissingAotManifestSha256, Options.parse(&(test_arguments ++ .{ "--aot-bundle", "/aot" })));
    try std.testing.expectError(error.InvalidManifestSha256, Options.parse(&(test_arguments ++ .{ "--aot-bundle", "/aot", "--aot-manifest-sha256", "bad" })));
    try std.testing.expectError(error.DuplicateArgument, Options.parse(&(test_arguments ++ test_aot_arguments ++ .{ "--aot-bundle", "/other" })));
    try std.testing.expectError(error.InvalidArguments, Options.parse(&(test_arguments ++ test_aot_arguments ++ .{ "--reference-proof", "/unused" })));
}

test "prepared Metal runtime admission binds exact manifest and claim source profile" {
    const profile = aotProfile(.fixed_program_narrow_v5);
    const lifecycle = Backend.RuntimeLifecycleSnapshot{
        .initialized = true,
        .identity = .{ .origin = .authenticated_core_aot, .source_sha256 = profile.sourceDigest(), .manifest_sha256 = .{1} ** 32, .metallib_sha256 = .{2} ** 32, .metallib_bytes = 100 },
        .active_call_leases = 0,
        .live_resident_resources = 0,
        .initialization_count = 1,
        .shutdown_count = 0,
    };
    try validateRuntime(lifecycle, .{1} ** 32, profile);
    try std.testing.expectError(error.AuthenticatedMetalRuntimeMismatch, validateRuntime(lifecycle, .{3} ** 32, profile));
    try std.testing.expectError(error.AuthenticatedMetalRuntimeMismatch, validateRuntime(lifecycle, .{1} ** 32, aotProfile(.field_authority_v4)));
    var jit = lifecycle;
    jit.identity.?.origin = .diagnostic_source_jit;
    try std.testing.expectError(error.AuthenticatedMetalRuntimeMismatch, validateRuntime(jit, .{1} ** 32, profile));
}
