//! Machine-readable report contract for the staged mixed CUDA service.

const std = @import("std");
const product_identity = @import("product_identity");
const stwo = @import("stwo_native_cuda");
const cli = @import("cli.zig");

const service_module = stwo.prover.execution.request_service;

pub const workload_id = "mixed_native_wide_poseidon_state_machine_v1";

pub const Statement = struct {
    family: []const u8,
    log_n_rows: ?u32 = null,
    sequence_len: ?u32 = null,
    log_n_instances: ?u32 = null,
    initial_x: ?u32 = null,
    initial_y: ?u32 = null,
    trace_rows: u64,
    trace_cells: u64,
};

pub const Row = struct {
    ordinal: usize,
    family: []const u8,
    statement: Statement,
    receipt: struct {
        ticket: u64,
        runtime_generation: u64,
        queue_depth_at_admission: usize,
        queue_wait_ns: u64,
        service_ns: u64,
        service_cold: bool,
        shape_cache_hit: bool,
        shape_retained_after: bool,
        shape_key_sha256: [64]u8,
        predicted_device_bytes: u64,
        retained_input_bytes_upper_bound: u64,
    },
    proof: struct {
        artifact_path: []const u8,
        format: []const u8,
        canonical_bytes: usize,
        canonical_sha256: [64]u8,
        artifact_sha256: [64]u8,
        zig_verified: bool,
        exact_for_repeated_family_input: bool,
    },
    oracle_hook: struct {
        required: bool,
        authority: []const u8,
        upstream_commit: []const u8,
        artifact_path: []const u8,
        artifact_sha256: [64]u8,
        receipt: ?[]const u8,
    },
    timing_ns: struct {
        resident_prove: u64,
        terminal_decode: u64,
        independent_verification: u64,
        verified_request: u64,
        device_critical_path: u64,
    },
    residency: struct {
        resident: bool,
        strict_aot: bool,
        runtime_proof_index: u64,
        cpu_fallback_attempts: u64,
        cpu_fallbacks_completed: u64,
        terminal_d2h_operations: u64,
        terminal_d2h_bytes: u64,
        kernel_launches: u64,
        graph_launches: u64,
        sync_calls: u64,
        peak_live_bytes: u64,
    },
    device: struct {
        uuid: [32]u8,
        sm: u32,
        ordinal: u32,
        total_global_memory: u64,
        multiprocessors: u32,
        driver_version: u32,
        runtime_version: u32,
        toolkit_version: u32,
    },
};

pub const Timings = struct {
    runtime_init_ns: u64,
    shape_prepare_ns: u64,
    service_wall_ns: u64,
    runtime_teardown_ns: u64,
    total_ns: u64,
};

pub const Totals = struct {
    trace_rows: u64,
    trace_cells: u64,
    device_ns: u64,
};

pub fn render(
    allocator: std.mem.Allocator,
    request: cli.Sustain,
    rows: []const Row,
    telemetry: service_module.Telemetry,
    queue_digest: [64]u8,
    totals: Totals,
    timings: Timings,
) ![]u8 {
    const seconds =
        @as(f64, @floatFromInt(timings.service_wall_ns)) / 1e9;
    return std.json.Stringify.valueAlloc(allocator, .{
        .schema = "native_cuda_mixed_service_v1",
        .schema_version = @as(u32, 1),
        .product = "stwo-native-cuda",
        .backend = cli.backend_name,
        .execution_mode = @tagName(request.execution_mode),
        .workload = .{
            .id = workload_id,
            .structural_class = "sustained",
            .deterministic = true,
            .cycles = request.cycles,
            .request_count = rows.len,
            .cycle_order = [_][]const u8{
                "wide_fibonacci",
                "poseidon",
                "state_machine",
            },
            .queue_sha256 = &queue_digest,
        },
        .product_identity = .{
            .schema_version = product_identity.schema_version,
            .identity_sha256 = product_identity.identity_sha256,
            .implementation_repository = product_identity.implementation_repository,
            .implementation_commit = product_identity.implementation_commit,
            .implementation_dirty = product_identity.implementation_dirty,
            .zig_version = product_identity.zig_version,
            .target_arch = product_identity.target_arch,
            .target_os = product_identity.target_os,
            .optimize = product_identity.optimize,
            .runtime_manifest = product_identity.runtime_manifest,
            .aot_manifest = product_identity.aot_manifest,
        },
        .promotion = .{
            .registry_enabled = false,
            .headline_eligible = false,
            .evidence_class = "diagnostic_unjudged",
            .blockers = [_][]const u8{
                "hardware exact-proof receipt package absent",
                "pinned Rust-oracle receipt package absent",
            },
        },
        .proof_contract = .{
            .all_zig_verified = true,
            .all_repeated_family_proofs_exact = true,
            .ordered_publication = true,
            .oracle_receipts_present = false,
        },
        .runtime_contract = .{
            .process_count = @as(u32, 1),
            .runtime_generation_count = @as(u32, 1),
            .execution_lane_count = telemetry.execution_lane_count,
            .sequential_proof_indices = true,
            .cpu_fallbacks_allowed = false,
        },
        .service = telemetry,
        .aggregate = .{
            .trace_rows = totals.trace_rows,
            .committed_trace_cells = totals.trace_cells,
            .service_wall_ns = timings.service_wall_ns,
            .device_critical_path_ns = totals.device_ns,
            .verified_trace_row_mhz = @as(f64, @floatFromInt(totals.trace_rows)) /
                seconds / 1e6,
            .verified_committed_mcells_per_second = @as(f64, @floatFromInt(totals.trace_cells)) /
                seconds / 1e6,
        },
        .timing_ns = .{
            .runtime_init = timings.runtime_init_ns,
            .shape_preparation = timings.shape_prepare_ns,
            .service_wall = timings.service_wall_ns,
            .runtime_teardown = timings.runtime_teardown_ns,
            .total_before_report_publication = timings.total_ns,
        },
        .requests = rows,
    }, .{});
}

test "mixed service report policy remains fail closed" {
    const policy = .{
        .registry_enabled = false,
        .headline_eligible = false,
        .oracle_receipts_present = false,
    };
    try std.testing.expect(!policy.registry_enabled);
    try std.testing.expect(!policy.headline_eligible);
    try std.testing.expect(!policy.oracle_receipts_present);
}
