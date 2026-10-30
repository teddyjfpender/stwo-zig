//! Actual bounded NativeV3 driver: original base proofs -> direct native batch
//! -> cold complete receiver. No individual recursive wrappers or V5 forest.
//! Limited to one batch; not a standalone recursively closed block root.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Legacy = @import("block_v5_cpu_driver_common_v1.zig").ForCapacity(false);
const Runner = @import("block_v4_cpu_runner_source.zig");
const Admission = @import("block_v5_cpu_driver_admission_v1.zig");
const Collect = @import("block_v5_cpu_collect_v1.zig").ForCapacity(false);
const Assembly = @import("block_v5_cpu_assembly_v1.zig").ForCapacity(false);
const Store = @import("block_v5_cpu_bundle_store_v1.zig");
const Stage = @import("block_v6_native_batch_stage_v1.zig");
const Receive = @import("block_v6_cpu_native_batch_receive_v1.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
pub const Options = Legacy.Options;
pub const Result = struct {
    verified: @import("block_v5_global_receiver_v1.zig").VerifiedNativeBatchBundle,
    pins: Receive.Pins,
    collection_ns: u64,
    base_ns: u64,
    recursive_ns: u64,
    verification_ns: u64,
    prepare_ns: u64,
    setup_ns: u64,
    prove_ns: u64,
    encode_ns: u64,
    peak_bytes: usize,
    base_files: usize,
    base_file_bytes: u64,
    families: @import("block_v5_cpu_family_queue_v1.zig").Statistics,
    native_commitments: @import("block_v6_native_commitment_staging_v1.zig").Statistics,
    access_commitments: @import("block_v6_access_commitment_staging_v1.zig").Statistics,
    program_commitments: @import("block_v6_provider_commitment_staging_v1.zig").Statistics,
    lookup_commitments: @import("block_v6_provider_commitment_staging_v1.zig").Statistics,
    ram_commitments: @import("block_v6_provider_commitment_staging_v1.zig").Statistics,
    ram_raw_written_bytes: u64,
    ram_raw_read_bytes: u64,
    caller_commitments: @import("block_v6_caller_commitment_staging_v1.zig").Statistics,
    external_commitments: @import("block_v6_caller_commitment_staging_v1.zig").ExternalStatistics,
};
pub fn run(backing: std.mem.Allocator, dir: std.fs.Dir, source: *Runner.Source, policy: Admission.InputPolicy, options: Options) !Result {
    try options.validate();
    try policy.runner_pins.execution_recipe.requireCompiled();
    if (source.execution_recipe != policy.runner_pins.execution_recipe) return error.MixedV5ExecutionRecipe;
    if (source.schedule.segments == 0 or source.schedule.segments > @import("../recursion/block_v6_native_batch_public_v1.zig").MAX_CHILDREN)
        return error.InvalidNativeBatchCount;
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(backing, options.total_host_limit);
    defer budget.destroy();
    const a = budget.allocator();
    var timer = try std.time.Timer.start();
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = options.workers, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const collected = try Collect.collect(a, dir, source, policy, options.profile.config(), options.collection);
    defer collected.deinit();
    const assembly = try Assembly.assemble(a, collected, policy, options.max_roster_entries);
    defer assembly.deinit();
    const policies = try @import("block_v5_cpu_bundle_policy_v1.zig").build(a, assembly.global_pins, options.store);
    defer a.free(policies);
    var writer = try Store.Store.initWriter(a, dir, policies, options.profile.config(), options.store);
    defer writer.deinit();
    const collection_ns = timer.lap();
    var pins: Receive.Pins = undefined;
    var base_ns: u64 = undefined;
    var recursive_ns: u64 = undefined;
    var phases: [4]u64 = undefined;
    var family_statistics: @import("block_v5_cpu_family_queue_v1.zig").Statistics = undefined;
    var file_count: usize = 0;
    var file_bytes: u64 = 0;
    {
        var stage = try Stage.Stage.init(a, assembly.global_pins, options.profile);
        defer stage.deinit();
        family_statistics = try Legacy.publishNativeBase(a, dir, collected, assembly, &writer, &pool, options, .{ .context = &stage, .run = Stage.Stage.capture });
        const files = try writer.filePins(a);
        defer a.free(files);
        const bundle = try Store.writePins(a, dir, files, options.store);
        file_count = files.len;
        // Store's own accounting supplies the published base-byte count.
        file_bytes = writer.total_bytes;
        base_ns = timer.lap();
        var artifact = try stage.prove();
        defer artifact.deinit(a);
        if (artifact.bytes.len > options.forest.max_proof_bytes) return error.V5BundleFileResourceLimit;
        try Files.publish(dir, Receive.PROOF_FILE, artifact.bytes);
        errdefer dir.deleteFile(Receive.PROOF_FILE) catch {};
        const metadata = try Receive.Metadata.write(a, dir, assembly.global_pins, artifact.pins, options.metadata);
        pins = .{ .identity = .{ .execution_recipe = policy.runner_pins.execution_recipe, .job_id = policy.job_id, .source_image_digest = assembly.seal_pins.source_image_digest, .program_root = policy.runner_pins.program_root.bytes, .initial_rw_root = policy.runner_pins.initial_rw_root.bytes, .final_rw_root = policy.expected_final_rw_root, .config = options.profile.config() }, .policy_sha256 = metadata, .bundle_sha256 = bundle, .proof_sha256 = Files.hash(artifact.bytes), .proof_bytes = artifact.bytes.len };
        phases = .{ artifact.prepare_ns, artifact.setup_ns, artifact.prove_ns, artifact.encode_ns };
    }
    recursive_ns = timer.lap();
    const verified = try Receive.verify(a, dir, source.input, pins, .{ .metadata = options.metadata, .store = options.store, .max_proof_bytes = options.forest.max_proof_bytes });
    const verification_ns = timer.lap();
    return .{
        .verified = verified,
        .pins = pins,
        .collection_ns = collection_ns,
        .base_ns = base_ns,
        .recursive_ns = recursive_ns,
        .verification_ns = verification_ns,
        .prepare_ns = phases[0],
        .setup_ns = phases[1],
        .prove_ns = phases[2],
        .encode_ns = phases[3],
        .peak_bytes = budget.snapshot().peak_live_bytes,
        .base_files = file_count,
        .base_file_bytes = file_bytes,
        .families = family_statistics,
        .native_commitments = collected.native_commitments,
        .access_commitments = collected.access_commitments,
        .program_commitments = collected.globals.program_statistics,
        .lookup_commitments = collected.groups.commitment_statistics,
        .ram_commitments = if (collected.globals.ram_checkpoints) |cache| cache.statistics else .{},
        .ram_raw_written_bytes = if (collected.globals.ram_checkpoints) |cache| cache.raw_written_bytes else 0,
        .ram_raw_read_bytes = if (collected.globals.ram_checkpoints) |cache| cache.raw_read_bytes else 0,
        .caller_commitments = collected.caller_commitments,
        .external_commitments = collected.external_commitments,
    };
}
