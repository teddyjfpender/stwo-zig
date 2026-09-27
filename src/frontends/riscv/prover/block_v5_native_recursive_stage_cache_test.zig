//! One actual two-instance production callback cycle, without a comparative
//! baseline proof. Both native artifacts remain usable after leaf publication.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Runner = @import("../runner/mod.zig");
const Fixture = @import("block_v5_lightweight_native_proof_test.zig").Fixture;
const Native = @import("block_v5_native_execution_proof_v3.zig");
const Catalog = @import("block_v5_native_template_catalog_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Stage = @import("block_v5_native_recursive_leaf_stage_v1.zig");
const Cache = @import("block_v5_native_recursive_setup_cache_v1.zig").ForBackend(Cpu);
const ProducerModule = @import("block_v5_block_producer_v1.zig");
const Producer = ProducerModule.ForLightweightBackend(Cpu);
const Files = @import("block_v5_open_forest_stage_v1.zig");
const Exact = @import("../recursion/block_v5_open_exact_forest_receiver_v1.zig");
const Transport = struct {
    dir: std.fs.Dir,
    outputs: [2]?Stage.Artifact = @splat(null),
    files: [2]?Exact.FilePin = @splat(null),
    next: u32 = 0,
    fn put(raw: *anyopaque, index: u32, artifact: *Stage.Artifact) !void {
        const self: *Transport = @ptrCast(@alignCast(raw));
        if (index != self.next or index >= 2) return error.InvalidV5CachedLeafOrder;
        var path: [80]u8 = undefined;
        self.files[index] = try Files.writeProof(self.dir, try Files.leafPath(index, &path), artifact.bytes, 1024 * 1024);
        self.outputs[index] = artifact.*;
        self.next += 1;
    }
    fn release(_: *anyopaque, _: *ProducerModule.LightweightReplay) void {}
    fn deinit(self: *Transport, a: std.mem.Allocator) void {
        for (&self.outputs) |*output| if (output.*) |*owned| owned.deinit(a);
    }
};
test "block-v5 cached production native leaf stage rebinds two real same-key worker instances" {
    const a = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const instructions = [_]u32{ 0x00500093, 0x00600093, 0x0000006f };
    const elf = @import("../runner/guest_precompile/test_elf.zig").buildProgram(instructions.len, &instructions, 0, .rv32im_zkvm_v1);
    var session = try Runner.BaseExecutionSession.init(a, &elf, .{ .trace_retention = .segment_owned, .clock_frame = .leaf_local });
    defer session.deinit();
    var segment_a = try session.startSegment(1);
    defer segment_a.deinit();
    var segment_b = try session.resumeSegment(segment_a.continuation.?, 1);
    defer segment_b.deinit();
    var counts: [Seal.family_count]u32 = @splat(0);
    counts[@intFromEnum(Seal.Family.program) - 1] = 1;
    counts[@intFromEnum(Seal.Family.execution) - 1] = 2;
    counts[@intFromEnum(Seal.Family.execution_sidecar) - 1] = 2;
    counts[@intFromEnum(Seal.Family.program_request) - 1] = 2;
    counts[@intFromEnum(Seal.Family.memory) - 1] = 1;
    var pins_a = Seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .program_root = @splat(3), .program_plan_digest = @splat(4), .memory_plan_digest = @splat(5), .initial_source_plan_digest = @splat(6), .rw_endpoint_plan_digest = @splat(25), .native_template_catalog_digest = @splat(26), .config = @import("../recursion/blake3_execution_parent_protocol.zig").PCS_CONFIG, .counts = counts };
    var pins_b = pins_a;
    pins_b.job_id[0] ^= 1;
    var fixture_a = try Fixture.init(a, &segment_a, pins_a);
    defer fixture_a.deinit();
    var fixture_b = try Fixture.init(a, &segment_b, pins_b);
    defer fixture_b.deinit();
    const Api = Native.ForBackend(Cpu);
    var first_a = try Api.commitFirstRound(a, fixture_a.owner, fixture_a.pin, pins_a.config, .rv32im_zkvm_v1, 0);
    defer first_a.deinit(a);
    var first_b = try Api.commitFirstRound(a, fixture_b.owner, fixture_b.pin, pins_b.config, .rv32im_zkvm_v1, 1);
    defer first_b.deinit(a);
    try std.testing.expectEqualDeep(first_a.template_id, first_b.template_id);
    const records = [_]Catalog.Record{
        .{ .index = 0, .template_id = first_a.template_id, .geometry_digest = first_a.template.geometry_digest, .fixed_root = first_a.roots[0] },
        .{ .index = 1, .template_id = first_b.template_id, .geometry_digest = first_b.template.geometry_digest, .fixed_root = first_b.roots[0] },
    };
    const catalog = Catalog.Admission{ .records = &records };
    pins_a.native_template_catalog_digest = try catalog.digest();
    pins_b.native_template_catalog_digest = pins_a.native_template_catalog_digest;
    const entries = [_]Seal.Entry{
        .{ .family = .program, .index = 0, .instance_id = @splat(7), .roots = .{ @splat(8), @splat(9) } },
        first_a.entry(),
        first_b.entry(),
        .{ .family = .execution_sidecar, .index = 0, .instance_id = @splat(10), .roots = .{ @splat(11), @splat(12) } },
        .{ .family = .execution_sidecar, .index = 1, .instance_id = @splat(13), .roots = .{ @splat(14), @splat(15) } },
        .{ .family = .program_request, .index = 0, .instance_id = @splat(16), .roots = .{ @splat(17), @splat(18) } },
        .{ .family = .program_request, .index = 1, .instance_id = @splat(19), .roots = .{ @splat(20), @splat(21) } },
        .{ .family = .memory, .index = 0, .instance_id = @splat(22), .roots = .{ @splat(23), @splat(24) } },
    };
    const sealed_a = try Seal.seal(pins_a, &entries);
    const sealed_b = try Seal.seal(pins_b, &entries);
    var originals: [2]?Native.Proof = @splat(null);
    defer for (&originals) |*original| if (original.*) |*owned| owned.deinit(a);
    originals[0] = try Api.proveWithCatalog(a, &first_a, sealed_a, pins_a, &entries, catalog);
    originals[1] = try Api.proveWithCatalog(a, &first_b, sealed_b, pins_b, &entries, catalog);
    var cache = try Cache.init(a, .{ .profile = .diagnostic_q8_pow0, .max_entries = 1, .aggregate_host_byte_limit = 12 * 1024 * 1024 * 1024, .worker_options = .{ .worker_count = 2, .host_byte_limit = 8 * 1024 * 1024 * 1024, .retained_scratch_limit = 64 * 1024 * 1024 } });
    defer cache.deinit();
    var transport = Transport{ .dir = tmp.dir };
    defer transport.deinit(a);
    var stage = Stage.ForBackend(Cpu){ .options = .{ .profile = .diagnostic_q8_pow0, .cache = &cache }, .sink = .{ .context = &transport, .put_leaf = Transport.put } };
    const hooks = stage.hooks();
    // Actual warm callbacks can run under an existing coordinator binding.
    // The cache must use its own joined lane without altering this binding.
    const WorkPool = @import("stwo_prover_engine").work_pool;
    var caller_pool: WorkPool.WorkPool = undefined;
    try caller_pool.initInPlaceWithOptions(.{ .worker_count = 2, .backing_allocator = a });
    defer caller_pool.deinit();
    var caller_binding = try WorkPool.ScopedPoolBinding.init(&caller_pool);
    defer caller_binding.deinit();
    const fixtures = [_]*Fixture{ &fixture_a, &fixture_b };
    const rounds = [_]*Api.FirstRound{ &first_a, &first_b };
    const seals = [_]Seal.Sealed{ sealed_a, sealed_b };
    const pins = [_]Seal.Pins{ pins_a, pins_b };
    // Both actual callbacks use one cached worker and one immutable fixed tree.
    // The second changes the seal, ordinal, roots and public/open claim tuple.
    var worker_pointer: ?*const anyopaque = null;
    inline for (0..2) |i| {
        var replay = ProducerModule.LightweightReplay{ .owner = fixtures[i].owner, .admission = fixtures[i].pin, .profile = .rv32im_zkvm_v1, .context = fixtures[i], .release = Transport.release };
        const warm = Producer.WarmExecution{ .index = i, .replay = &replay, .first = rounds[i], .sealed = seals[i], .pins = pins[i], .entries = &entries, .catalog = catalog };
        try std.testing.expect(WorkPool.getGlobalPool() == &caller_pool);
        try hooks.on_proof.?(hooks.context, a, warm, &originals[i].?);
        try std.testing.expect(WorkPool.getGlobalPool() == &caller_pool);
        const current: *const anyopaque = cache.entry.?.worker;
        if (worker_pointer) |previous| try std.testing.expect(previous == current) else worker_pointer = current;
        // The actual stage output owns its current public tuple. A persistent
        // scoped worker retains no borrow after the joined request returns;
        // the fresh original/recursive checks below authenticate those outputs.
        try std.testing.expect(cache.entry.?.worker.plan.admission.current == null);
        try std.testing.expectError(error.ParentDynamicAdmissionNotBound, cache.entry.?.worker.plan.admission.require());
        try std.testing.expect(transport.outputs[i].?.schedule.ptr != cache.entry.?.schedule.ptr);
    }
    try std.testing.expectEqual(@as(usize, 1), cache.stats.misses);
    try std.testing.expectEqual(@as(usize, 1), cache.stats.hits);
    try std.testing.expectEqualDeep(transport.outputs[0].?.expected_key_id, transport.outputs[1].?.expected_key_id);
    try std.testing.expect(!std.meta.eql(transport.outputs[0].?.public_values, transport.outputs[1].?.public_values));
    try std.testing.expect(!std.meta.eql(transport.outputs[0].?.public_values.roots[1], transport.outputs[1].?.public_values.roots[1]));
    // Reopen the earlier output after rebinding: its tuple remains owned, and
    // the new admission cannot retroactively change the preceding leaf proof.
    inline for (0..2) |i| {
        const original = originals[i].?;
        originals[i] = null;
        const fresh = try Api.verifyOwnedWithCatalog(a, original, &fixtures[i].owner.statement, fixtures[i].pin, rounds[i].template, rounds[i].template_id, .rv32im_zkvm_v1, i, seals[i], pins[i], &entries, catalog);
        try std.testing.expectEqualDeep(fresh, transport.outputs[i].?.native);
        var admitted = try @import("block_v5_native_recursive_admission_v3.zig").Prepared.init(a, &fixtures[i].owner.statement, fixtures[i].pin, rounds[i].template, rounds[i].template_id, i, seals[i], pins[i], &entries, catalog);
        defer admitted.deinit();
        var path: [80]u8 = undefined;
        const bytes = try Files.openPinned(a, tmp.dir, try Files.leafPath(i, &path), transport.files[i].?, 1024 * 1024);
        defer a.free(bytes);
        const output = transport.outputs[i].?;
        var verified = try @import("../recursion/block_v5_reusable_native_leaf_v1.zig").verify(a, bytes, output.key, output.expected_key_id, output.schedule, &admitted, fresh);
        defer verified.deinit();
        try std.testing.expectEqualDeep(output.public_values, verified.public_values);
        try std.testing.expectEqualDeep(output.span, verified.pc_clock_span.?);
    }
    std.debug.print("BLOCK_V5_NATIVE_STAGE_CACHE verified=true native_instances=2 native_produced_once_each=true cold_misses={d} setup_hits={d} immutable_worker_reused=true same_key_dynamic_admission_rebound=true caller_scoped_pool_preserved=true both_original_natives_preserved=true both_leaf_files_fresh_verified=true leaf_bytes={d}+{d} cache_owned_peak_bytes={d} global_claims_open=true\n", .{ cache.stats.misses, cache.stats.hits, transport.files[0].?.byte_len, transport.files[1].?.byte_len, cache.budget.snapshot().peak_live_bytes });
}
