//! Canonical success and failure report encoding for one recursive CSP attempt.

const std = @import("std");
const product_identity = @import("product_identity");
const stwo = @import("stwo");
const contract = @import("contract.zig");
const pipeline = @import("pipeline.zig");

const atomic_file = stwo.interop.atomic_file;

pub fn success(
    allocator: std.mem.Allocator,
    artifact_path: []const u8,
    request: contract.Request,
    executable_sha256: [32]u8,
    produced: *const pipeline.Produced,
) ![]u8 {
    const executable_hex = hexDigest(executable_sha256);
    const request_hex = hexDigest(produced.identities.request_sha256);
    const public_values_hex = hexDigest(produced.identities.public_values_sha256);
    const leaf_statement_hex = hexDigest(
        produced.identities.leaf_statement_words_sha256,
    );
    const base_proof_hex = hexDigest(produced.identities.base_proof_sha256);
    const payload_hex = hexDigest(produced.identities.payload_sha256);
    const outer_statement_hex = hexWords(produced.identities.outer_statement_id);
    const outer_vk_hex = hexWords(produced.identities.outer_verification_key_id);
    const profile_hex = hexWords(produced.identities.profile_id);
    const capture_hex = hexWords(produced.identities.capture_id);
    const receipt_hex = hexWords(produced.identities.receipt_id);
    const transcript_hex = hexWords(produced.identities.transcript_id);
    const sums_hex = hexWords(produced.identities.claimed_sums_id);
    const proof_hex = hexWords(produced.identities.proof_id);
    const recursive_profile_shape_hex = hexDigest(
        produced.identities.recursive_profile_shape_sha256,
    );
    const profile_registry_hex = hexDigest(
        produced.identities.profile_registry_sha256,
    );
    const phase_sum_ns = try phaseDurationSum(produced.phases);
    const unattributed_ns = std.math.sub(
        u64,
        produced.verified_end_to_end_ns,
        phase_sum_ns,
    ) catch return error.InvalidTimingPartition;

    const encoded = .{
        .schema = contract.ATTEMPT_SCHEMA,
        .schema_version = contract.ATTEMPT_SCHEMA_VERSION,
        .status = "verified",
        .classification = "verified_verifier_subsystem_diagnostic",
        .comparison_eligible = false,
        .unavailable_reason = "the active 36-row outer proof is verifier-subsystem scoped; " ++
            "a complete recursive parent proof is not yet production-active",
        .request = .{
            .schema = request.schema,
            .schema_version = request.schema_version,
            .request_sha256 = &request_hex,
            .plan_digest = request.plan_digest,
            .workload_id = request.workload_id,
            .target = request.target,
            .input_size = request.input_size,
            .max_steps = request.max_steps,
        },
        .source = .{
            .guest_path = request.guest_path,
            .guest_sha256 = request.guest_sha256,
            .input_path = request.input_path,
            .input_sha256 = request.input_sha256,
            .expected_output_digest = request.expected_output_digest,
            .expected_cycles = request.expected_cycles,
            .observed_cycles = produced.execution_cycles,
            .native_measurement_commit = request.native_measurement_commit,
            .expected_public_values_sha256 = request.expected_public_values_sha256,
            .observed_public_values_sha256 = &public_values_hex,
            .native_baseline_statement_sha256 = request.native_statement_sha256,
        },
        .producer = .{
            .name = "stwo-zig-riscv-recursive-csp-producer",
            .backend = "cpu",
            .optimization_mode = product_identity.optimize,
            .worker_count = produced.worker_count,
            .mutation_probe_mode = @tagName(produced.outer.mutation_probe_mode),
            .executable_sha256 = &executable_hex,
            .product_identity_sha256 = product_identity.identity_sha256,
            .product = product_identity.product,
            .protocol_features = product_identity.protocol_features,
            .implementation_repository = product_identity.implementation_repository,
            .implementation_commit = product_identity.implementation_commit,
            .implementation_tree = if (product_identity.implementation_tree_available)
                @as(?[]const u8, product_identity.implementation_tree)
            else
                null,
            .implementation_dirty = product_identity.implementation_dirty,
            .dirty_content_sha256 = if (product_identity.dirty_content_sha256_available)
                @as(?[]const u8, product_identity.dirty_content_sha256)
            else
                null,
            .zig_version = product_identity.zig_version,
            .target_arch = product_identity.target_arch,
            .target_os = product_identity.target_os,
            .target_abi = product_identity.target_abi,
            .cpu_model = product_identity.cpu_model,
        },
        .security = .{
            .leaf_protocol = "poseidon2_m31_recursion_v1",
            .outer_protocol = "poseidon2_m31_functional_outer_v1",
            .proof_scope = @tagName(produced.proof_scope),
            .production_ready = produced.production_ready,
            .roster_count = produced.outer.roster_count,
            .active_verifier_rows = produced.outer.active_verifier_rows,
            .active_provider_rows = produced.outer.active_provider_rows,
            .recursive_profile_id = request.expected_recursive_profile_id,
            .recursive_profile_shape_sha256 = &recursive_profile_shape_hex,
            .profile_registry_sha256 = &profile_registry_hex,
            .profile_dispatch_status = "outer_wired",
        },
        .timing = .{
            .clock = "monotonic",
            .unit = "nanoseconds",
            .partition = "guest+base_witness+base_prove+base_verify+recursive_prepare+" ++
                "recursive_witness+recursive_prove+recursive_verify",
            .phase_partition_complete = false,
            .phases = produced.phases,
            .phase_sum_ns = phase_sum_ns,
            .unattributed_ns = unattributed_ns,
            .verified_end_to_end_ns = produced.verified_end_to_end_ns,
        },
        .poseidon2_counter = .{
            .scope = "authenticated_recursive_air_poseidon2_rows_materialized",
            .system_wide = false,
            .exact_within_scope = true,
            .permutations = produced.outer.poseidon2_call_count,
        },
        .resources = .{
            .scope = "fresh_self_process_lifetime_including_independent_verification",
            .source = @tagName(produced.resources.source),
            .peak_rss_bytes = produced.resources.peak_rss_bytes,
            .lifetime_peak_physical_footprint_bytes = produced.resources.lifetime_peak_physical_footprint_bytes,
            .process_cpu_ns = produced.resources.process_cpu_ns,
            .energy_nj = produced.resources.energy_nj,
            .instructions = produced.resources.instructions,
            .cycles = produced.resources.cycles,
            .unavailable_reason = produced.resources.unavailable_reason,
        },
        .identities = .{
            .leaf_statement_words_sha256 = &leaf_statement_hex,
            .base_proof_sha256 = &base_proof_hex,
            .outer_statement_id = &outer_statement_hex,
            .outer_verification_key_id = &outer_vk_hex,
            .profile_id = &profile_hex,
            .capture_id = &capture_hex,
            .receipt_id = &receipt_hex,
            .transcript_id = &transcript_hex,
            .claimed_sums_id = &sums_hex,
            .proof_id = &proof_hex,
        },
        .artifact = .{
            .artifact_kind = contract.ARTIFACT_KIND,
            .artifact_schema_version = contract.ARTIFACT_SCHEMA_VERSION,
            .exchange_mode = contract.EXCHANGE_MODE,
            .payload_encoding = contract.PAYLOAD_ENCODING,
            .payload_scope = contract.PAYLOAD_SCOPE,
            .verification_receipt_schema = contract.RECEIPT_SCHEMA,
            .path = artifact_path,
            .payload_sha256 = &payload_hex,
            .payload_bytes = produced.payload.len,
            .artifact_sha256 = &payload_hex,
            .artifact_bytes = produced.payload.len,
            .outer_stark_proof_size_estimate_bytes = produced.outer.proof_size_estimate,
        },
        .verification_receipt = .{
            .schema = contract.RECEIPT_SCHEMA,
            .status = "verified",
            .proof_scope = @tagName(produced.proof_scope),
            .production_ready = produced.production_ready,
            .statement_id = &outer_statement_hex,
            .verification_key_id = &outer_vk_hex,
            .proof_id = &proof_hex,
            .mutation_probe_mode = @tagName(produced.outer.mutation_probe_mode),
            .mutation_rejections = produced.outer.mutation_rejections,
        },
        .outer_receipt = produced.outer,
        .failure = @as(?struct {
            stage: []const u8,
            error_name: []const u8,
        }, null),
    };
    return std.json.Stringify.valueAlloc(allocator, encoded, .{});
}

pub fn failure(
    allocator: std.mem.Allocator,
    request_path: []const u8,
    artifact_path: []const u8,
    attempt_path: []const u8,
    context: anytype,
    failure_error: anyerror,
) !void {
    const request_hex = if (context.request_sha256) |digest| hexDigest(digest) else null;
    const plan_hex = if (context.plan_digest) |digest| hexDigest(digest) else null;
    const workload_hex = if (context.workload_id) |digest| hexDigest(digest) else null;
    const encoded_report = .{
        .schema = contract.ATTEMPT_SCHEMA,
        .schema_version = contract.ATTEMPT_SCHEMA_VERSION,
        .status = "failed",
        .classification = "failed_recursive_csp_attempt_not_performance_evidence",
        .comparison_eligible = false,
        .request = .{
            .path = request_path,
            .request_sha256 = if (request_hex) |*value| @as(?[]const u8, value) else null,
            .plan_digest = if (plan_hex) |*value| @as(?[]const u8, value) else null,
            .workload_id = if (workload_hex) |*value| @as(?[]const u8, value) else null,
        },
        .requested_artifact_path = artifact_path,
        .failure = .{
            .stage = context.stage,
            .error_name = @errorName(failure_error),
        },
    };
    const encoded = try std.json.Stringify.valueAlloc(allocator, encoded_report, .{});
    defer allocator.free(encoded);
    try atomic_file.writeExclusive(allocator, attempt_path, encoded);
}

fn phaseDurationSum(phases: pipeline.Phases) !u64 {
    var total: u64 = 0;
    inline for (std.meta.fields(pipeline.Phases)) |field| {
        total = try std.math.add(u64, total, @field(phases, field.name).duration_ns);
    }
    return total;
}

fn hexDigest(value: [32]u8) [64]u8 {
    return std.fmt.bytesToHex(value, .lower);
}

fn hexWords(value: [8]u32) [64]u8 {
    var bytes: [32]u8 = undefined;
    for (value, 0..) |word, index|
        std.mem.writeInt(u32, bytes[index * 4 ..][0..4], word, .little);
    return hexDigest(bytes);
}
