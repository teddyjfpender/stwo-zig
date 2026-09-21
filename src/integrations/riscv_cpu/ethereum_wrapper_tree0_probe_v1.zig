//! Same admitted wrapper Tree0 on CPU and authenticated Metal PCS. This
//! command produces no wrapper proof and grants no new verification authority.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const native = @import("recursive_temporal_secure_parent_native_engine_v1.zig");
const manifest = @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const cohort_mod = @import("recursive_common_ethereum_incremental_leaf_secure_cohort_v4.zig");

pub fn compare(
    comptime NativeEngine: type,
    comptime MetalBackend: type,
    allocator: std.mem.Allocator,
    materialized: anytype,
    workers: usize,
) !void {
    const MetalEngine = frontend.recursion.engine.ProverEngineForBackend(MetalBackend);
    const Cohort = cohort_mod.CohortV4(NativeEngine);
    if (try materialized.base.input.stage101.profile.claimAdmission() != .field_authority_v4)
        return error.EthereumTree0ProbeRequiresFieldAuthority;
    try materialized.base.input.requireGlobalAdmission();
    const bundle = try std.process.getEnvVarOwned(allocator, "STWO_RISCV_METAL_AOT_BUNDLE");
    defer allocator.free(bundle);
    const pin = try std.process.getEnvVarOwned(allocator, "STWO_ETHEREUM_TREE0_AOT_MANIFEST_SHA256");
    defer allocator.free(pin);
    if (pin.len != 64) return error.InvalidTree0AotManifestSha256;
    var digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, pin) catch return error.InvalidTree0AotManifestSha256;
    if (MetalBackend.runtimeLifecycleSnapshot().initialized)
        return error.EthereumTree0ProbeRequiresFreshRuntime;
    // Demonstrate that device preparation cannot silently start source JIT.
    if (native.requirePreparationEngine(MetalEngine)) |_| {
        return error.EthereumTree0ProbeAcceptedUninitializedRuntime;
    } else |err| if (err != error.EthereumTree0AuthenticatedAotRequired) return err;
    var scope: @import("ethereum_native_verification_scope_v1.zig").ScopeV1 = undefined;
    try scope.initInPlace(workers);
    defer scope.deinit();
    // One preparation owner. Its CPU Tree0 is independently derived during
    // construction; the second derivation reads exactly those admitted rows.
    var cohort = try Cohort.init(allocator, .{ .materialized = materialized });
    var cohort_live = true;
    defer if (cohort_live) cohort.deinit();
    const session = try cohort.session();
    const cpu = (try cohort.fieldTranscriptAdmission(&session)).preprocessed_root;
    @import("ethereum_wrapper_resources_v1.zig").progress("ETHEREUM_TREE0_CPU_ADMISSION cpu_root={any}\n", .{cpu});
    const fixed = cohort.manifest().*;
    const config = try session.protocol.pcsConfig();
    const logs = try allocator.alloc(u32, fixed.total_preprocessed_columns);
    defer allocator.free(logs);
    var cursor: usize = 0;
    const blowup = config.fri_config.log_blowup_factor;
    for (fixed.roster_rows[0..fixed.roster_count]) |row| {
        const geometry = fixed.placements[row].?.geometry;
        const count = geometry.preprocessed_columns;
        @memset(logs[cursor..][0..count], geometry.log_size + blowup);
        cursor += count;
    }
    if (cursor != logs.len) return error.EthereumTree0ProbeGeometryMismatch;
    std.sort.heap(u32, logs, {}, std.sort.asc(u32));
    const traffic = MetalBackend.stagedPoseidonTrafficReceiptV1(logs, logs[logs.len - 1]) orelse
        return error.EthereumTree0ProbeRequiresHeterogeneousColumns;
    var preparation = @import("ethereum_wrapper_resources_v1.zig").Measurements.init();
    const TreeStorage = @import("recursive_binary_outer_support.zig").TreeStorageForManifest(manifest);
    var tree = try TreeStorage.initGroupedByLog(allocator, &fixed, manifest.PREPROCESSED_TREE_INDEX);
    defer tree.deinit();
    try cohort.fillPreprocessedInto(&fixed, tree.columns);
    preparation.mark("tree0.admitted-preprocessing-copied");
    cohort.deinit();
    cohort_live = false;
    preparation.mark("tree0.unrelated-cohort-released");
    @import("ethereum_wrapper_resources_v1.zig").progress(
        "ETHEREUM_TREE0_PREPARATION cohort_destroyed_before_metal=true preprocessed_source_bytes={d} lde_bytes={d} wide_leaf_permutations={d} staged_leaf_permutations={d}\n",
        .{ tree.storage.len * @sizeOf(@import("stwo_core").fields.m31.M31), traffic.staged_column_reads * 4, traffic.wide_leaf_permutations, traffic.staged_leaf_permutations },
    );
    var initialization_timer = try std.time.Timer.start();
    try MetalBackend.initializeRuntime(allocator, .{ .authenticated_aot = .{
        .bundle_path = bundle,
        .manifest_sha256 = digest,
    } });
    const initialization_ns = initialization_timer.read();
    defer MetalBackend.shutdown() catch unreachable;
    const before = try MetalBackend.telemetrySnapshot();
    const device = try native.commitPreparedTree0WithEngine(MetalEngine, manifest, allocator, &tree, config, false);
    const after = try MetalBackend.telemetrySnapshot();
    const delta = after.delta(before).counters;
    if (delta.resident_merkle_commits != 1 or
        delta.metal_poseidon2_merkle_commits != 1 or
        delta.host_merkle_commits != 0)
        return error.EthereumTree0ProbeMissingMetalMerkleDispatch;
    if (!std.meta.eql(cpu, device)) return error.EthereumTree0CpuMetalRootMismatch;
    if (delta.metal_heterogeneous_commit_epochs > 1)
        return error.EthereumTree0ProbeUnexpectedCommitEpochs;
    const staged = delta.metal_heterogeneous_commit_epochs == 1 and
        MetalBackend.admitsStagedPoseidonTrafficV1(traffic);
    @import("ethereum_wrapper_resources_v1.zig").progress(
        "ETHEREUM_TREE0_HASH_WORK route={s} route_evidence=completed_epoch_and_shared_admission column_count={d} lifting_log={d} wide_column_reads={d} staged_column_reads={d} wide_leaf_permutations={d} staged_leaf_permutations={d} selected_column_reads={d} selected_leaf_permutations={d} heterogeneous_epochs={d} heterogeneous_arena_bytes={d}\n",
        .{ if (staged) "staged-native-height" else "direct-lifted-leaves", traffic.column_count, traffic.lifting_log_size, traffic.wide_column_reads, traffic.staged_column_reads, traffic.wide_leaf_permutations, traffic.staged_leaf_permutations, if (staged) traffic.staged_column_reads else traffic.wide_column_reads, if (staged) traffic.staged_leaf_permutations else traffic.wide_leaf_permutations, delta.metal_heterogeneous_commit_epochs, delta.metal_heterogeneous_commit_arena_bytes },
    );
    const lifecycle = MetalBackend.runtimeLifecycleSnapshot();
    if (lifecycle.active_call_leases != 0 or lifecycle.live_resident_resources != 0)
        return error.EthereumTree0ProbeResidentOwnerLeak;
    @import("ethereum_wrapper_resources_v1.zig").progress(
        "ETHEREUM_TREE0_PARITY exact=true cpu_reuse_bounded_tail=true metal_reuse_bounded_tail=false workers={d} cpu_root={any} metal_root={any} metal_poseidon_commits={d} host_merkle_commits={d} aot_manifest_sha256={x} aot_source_sha256={x} aot_metallib_sha256={x} runtime_initialization_ns={d} endpoint=tree0_admission_only wrapper_proof=false\n",
        .{ workers, cpu, device, delta.metal_poseidon2_merkle_commits, delta.host_merkle_commits, digest, lifecycle.identity.?.source_sha256, lifecycle.identity.?.metallib_sha256.?, initialization_ns },
    );
}
