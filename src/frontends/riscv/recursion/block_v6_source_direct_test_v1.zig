//! Genuine original raw+fold PAGE proofs through a single direct parent.
//! The source is empty but its padded SHA streams, root fold and original
//! ten-tree verifier equations are real. This is not a complete block proof.
const std = @import("std");
const core = @import("stwo_core");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Parent = @import("blake3_execution_parent_proof.zig");
const Bus = @import("block_v6_auxiliary_direct_public_v1.zig");
const Prep = @import("block_v6_auxiliary_direct_prepare_v1.zig");
const Mixed = @import("block_v6_mixed_direct_public_v1.zig");
const MixedPrep = @import("block_v6_mixed_direct_prepare_v1.zig");
const Protocol = @import("block_v6_mixed_direct_protocol_v1.zig");
const Job = @import("../prover/block_v5_memory_source_page_job_v1.zig");
const Semantic = @import("../prover/block_v5_memory_source_page_semantic_columns_v1.zig");
const Source = @import("../prover/block_v5_memory_source_auth_protocol_v1.zig");
const Codec = @import("../prover/block_v5_memory_source_unified_page_codec_v1.zig");
const Admission = @import("../prover/block_v5_memory_source_page_recursive_admission_v1.zig");
const Capture = @import("../prover/block_v5_memory_source_page_recursive_capture_v1.zig");
const Observer = struct {
    raw: usize = 0,
    fold: usize = 0,
    fn emptyRead(_: *anyopaque, _: Source.Stream, _: u64, out: []u8) !void {
        if (out.len != 0) return error.UnexpectedEmptySourceRead;
    }
    fn onRaw(ctx: *anyopaque, _: *const Job.RawPage.VerifiedPage, _: Job.ArtifactPin) !void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.raw += 1;
    }
    fn onFold(ctx: *anyopaque, _: *const Job.FoldPage.VerifiedPage, _: Job.ArtifactPin) !void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.fold += 1;
    }
};
test "auxiliary source direct genuine raw fold PAGE proofs merge before one parent proof" {
    const a = std.testing.allocator;
    const profile: Parent.protocol.Profile = .diagnostic_q8_pow0;
    var pool: @import("stwo_prover_engine").work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 8, .backing_allocator = a });
    defer pool.deinit();
    var binding = try @import("stwo_prover_engine").work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const Seal = @import("../prover/block_v5_source_seal_v1.zig");
    const LanePlan = @import("../prover/block_v5_ram_lanes_plan_v1.zig");
    const LaneReceiver = @import("../prover/block_v5_ram_lanes_receiver_v1.zig");
    const Batch = @import("../prover/block_v5_memory_source_batch_protocol_v1.zig");
    const seed = try @import("../prover/block_v5_memory_source_page_raw_recursive_parity_test_v1.zig").emptyAdmission();
    var endpoint_pins = seed.source.pins;
    endpoint_pins.memory_plan_digest = try LanePlan.digest(a, &.{}, 0, &.{}, .{});
    var counts: [Seal.family_count]u32 = @splat(0);
    const families = [_]Seal.Family{ .program, .execution, .execution_sidecar, .program_request };
    var entries: [4]Seal.Entry = undefined;
    for (families, &entries, 0..) |family, *entry, i| {
        counts[@intFromEnum(family) - 1] = 1;
        entry.* = .{ .family = family, .index = 0, .instance_id = @splat(@intCast(i + 1)), .roots = .{ @splat(@intCast(i + 10)), @splat(@intCast(i + 20)) } };
    }
    // Synthetic execution/ROM roots are only a fixture transcript seed. They
    // grant no execution authority. PAGE/source closure is independently real.
    const seal_pins = Seal.Pins{ .job_id = @splat(1), .source_image_digest = @splat(2), .native_template_id = @splat(3), .program_root = @splat(4), .program_plan_digest = @splat(5), .memory_plan_digest = endpoint_pins.memory_plan_digest, .initial_source_plan_digest = try endpoint_pins.initial.digest(), .expected_final_rw_root = endpoint_pins.expected_final_rw_root, .rw_endpoint_plan_digest = try endpoint_pins.digest(), .register_endpoint_plan_digest = @splat(9), .register_custody_mode = 1, .config = profile.config(), .counts = counts };
    const base = try Seal.seal(seal_pins, &entries);
    const source = try Source.admit(endpoint_pins, seal_pins, &entries, base, .{});
    const admitted = try Batch.Admission.init(source, .{});
    const memory = LaneReceiver.Pins{ .seal = seal_pins, .expected_seal_digest = base.digest, .first_round = &entries, .pins = &.{}, .range_roots = &.{}, .expected_total_events = 0, .source = endpoint_pins };
    var limits = Job.Limits{};
    limits.proof.raw.first.page_row_log = 3;
    limits.proof.protocol.raw = limits.proof.raw;
    limits.proof.protocol.page_row_log = 1;
    limits.proof.fold.protocol = limits.proof.protocol;
    const raw_plan = try @import("../prover/block_v5_memory_source_batch_raw_schema_v1.zig").Protocol.init(&admitted.source, profile.config(), limits.proof.raw.first);
    const fold_plan = try @import("../prover/block_v5_memory_source_unified_page_protocol_v1.zig").FoldPlan.init(&admitted, .{ .empty = 1, .roots = 1 }, profile.config(), limits.proof.protocol);
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var observer = Observer{};
    const job = try Job.ForBackend(Cpu).Job.collect(a, tmp.dir, admitted, raw_plan, fold_plan, .{ .context = &observer, .read = Observer.emptyRead }, base, limits);
    defer job.deinit() catch @panic("source direct fixture lifetime");
    try job.publishAll(.{ .context = &observer, .raw = Observer.onRaw, .fold = Observer.onFold });
    try std.testing.expectEqual(@as(usize, 1), observer.raw);
    try std.testing.expectEqual(@as(usize, 1), observer.fold);
    const rows = [_]Semantic.FoldRow{
        .{ .descriptor = .{ .kind = .empty, .height = 30 }, .recipes = &.{}, .first_compression = 0, .compressions = 0 },
        .{ .descriptor = .{ .kind = .root, .height = 30 }, .recipes = &.{}, .first_compression = 0, .compressions = 0 },
    };
    var raw_path_buffer: [96]u8 = undefined;
    var fold_path_buffer: [96]u8 = undefined;
    const raw_path = try Job.name(&raw_path_buffer, .raw, 0, true);
    const fold_path = try Job.name(&fold_path_buffer, .fold, 0, true);
    var expected: [2]Mixed.Expected = undefined;
    var prepared = build: {
        const raw_bytes = try tmp.dir.readFileAlloc(a, raw_path, limits.artifact.max_artifact_bytes);
        defer a.free(raw_bytes);
        const fold_bytes = try tmp.dir.readFileAlloc(a, fold_path, limits.artifact.max_artifact_bytes);
        defer a.free(fold_bytes);
        var raw_proof = try Codec.ForKind(.raw).decode(a, raw_bytes, &job.context.?, job.raws[0].pin, &.{}, limits.proof, limits.artifact);
        defer raw_proof.deinit(a);
        var fold_proof = try Codec.ForKind(.fold).decode(a, fold_bytes, &job.context.?, job.folds[0].pin, &rows, limits.proof, limits.artifact);
        defer fold_proof.deinit(a);
        const raw_admission = try Admission.ForKind(.raw).Prepared.init(a, &job.context.?, job.raws[0].pin, &.{}, job.sha_setup.?, job.arithmetic_setup.?, .{ .page = limits.proof });
        const fold_admission = try Admission.ForKind(.fold).Prepared.init(a, &job.context.?, job.folds[0].pin, &rows, job.blake_setup.?, job.arithmetic_setup.?, .{ .page = limits.proof });
        var raw_capture = try Capture.ForKind(.raw).verifyBorrowed(a, &raw_proof, &raw_admission);
        defer raw_capture.deinit();
        var fold_capture = try Capture.ForKind(.fold).verifyBorrowed(a, &fold_proof, &fold_admission);
        defer fold_capture.deinit();
        const SourceClose = @import("../prover/block_v6_source_public_closure_v1.zig");
        const RawBus = Bus.Definition(.source_raw).Bus;
        const FoldBus = Bus.Definition(.source_fold).Bus;
        const raw_claims = RawBus.Claims{ .semantic = raw_capture.original.frame.semantic, .components = raw_capture.original.frame.claims };
        const fold_claims = FoldBus.Claims{ .semantic = fold_capture.original.frame.semantic, .components = fold_capture.original.frame.claims };
        try @import("../prover/tests/block_v6_page_scratch_allocator_test_support.zig").check(.fold, a, &fold_admission, fold_claims);
        var raw_values = try RawBus.Values.init(a, &raw_admission, raw_claims);
        defer raw_values.deinit();
        var fold_values = try FoldBus.Values.init(a, &fold_admission, fold_claims);
        defer fold_values.deinit();
        const raw_entry = SourceClose.Page(.raw){ .admitted = &raw_admission, .claims = raw_claims, .public = raw_values };
        const fold_entry = SourceClose.Page(.fold){ .admitted = &fold_admission, .claims = fold_claims, .public = fold_values };
        const source_limits = @import("../prover/block_v5_memory_source_page_join_owner_v1.zig").Limits{ .pages = limits.proof };
        const closed = try SourceClose.close(a, &job.context.?, memory, .{ .raw = &.{raw_entry}, .fold = &.{fold_entry}, .lanes = &.{}, .ranges = &.{} }, source_limits);
        try std.testing.expectEqual(@as(u64, 0), closed.events);
        try std.testing.expectError(error.IncompleteSourcePublicRoster, SourceClose.close(a, &job.context.?, memory, .{ .raw = &.{}, .fold = &.{fold_entry}, .lanes = &.{}, .ranges = &.{} }, source_limits));
        var changed_raw = raw_entry;
        changed_raw.claims.semantic.claims.source.bytes = changed_raw.claims.semantic.claims.source.bytes.add(core.fields.qm31.QM31.one());
        if (SourceClose.close(a, &job.context.?, memory, .{ .raw = &.{changed_raw}, .fold = &.{fold_entry}, .lanes = &.{}, .ranges = &.{} }, source_limits)) |_| return error.AcceptedChangedRawSourceClaim else |_| {}
        const inputs = [_]Prep.Input{ .{ .source_raw = .{ .admitted = &raw_admission, .capture = &raw_capture } }, .{ .source_fold = .{ .admitted = &fold_admission, .capture = &fold_capture } } };
        const raw_expected = inputs[0].expected();
        const fold_expected = inputs[1].expected();
        expected = .{ .{ .auxiliary = raw_expected }, .{ .auxiliary = fold_expected } };
        var raw_piece = try Prep.prepare(a, inputs[0..1], &.{raw_expected}, 2);
        defer raw_piece.deinit();
        var fold_piece = try Prep.prepare(a, inputs[1..2], &.{fold_expected}, 2);
        defer fold_piece.deinit();
        break :build try MixedPrep.prepareDraining(a, &.{ .{ .auxiliary = &raw_piece }, .{ .auxiliary = &fold_piece } }, &expected);
    };
    defer prepared.deinit();
    // All original captures/decoded proofs are gone before the parent proof.
    try tmp.dir.deleteFile(raw_path);
    try tmp.dir.deleteFile(fold_path);
    const geometry = try Parent.ForBackend(Cpu).deriveKeyWithProfile(a, &prepared.recursive, profile);
    const key = try Protocol.Key.fromGeometry(geometry, prepared.wires, &expected);
    const key_id = try key.identity();
    const admission = try Protocol.Admission.init(key, key_id, prepared.wires, prepared.values(), &expected);
    const Plan = @import("blake3_native_parent_producer.zig").PlanForProtocol(Cpu, Protocol);
    const plan = try Plan.init(a, &prepared.recursive.rows, admission);
    defer plan.deinit();
    var proof = try plan.prove(a, &prepared.recursive.rows);
    defer proof.deinit();
    const bytes = try Parent.codec.encode(a, &proof, &admission);
    defer a.free(bytes);
    var decoded = try Parent.codec.decode(a, bytes, &admission);
    var verified = try Parent.verify(&decoded, &admission);
    defer verified.deinit();
    try verified.validate(&admission, key_id);
    prepared.children[0].auxiliary.value.source_raw.public[0] = prepared.children[0].auxiliary.value.source_raw.public[0].add(core.fields.qm31.QM31.one());
    const changed = try Protocol.Admission.init(key, key_id, prepared.wires, prepared.values(), &expected);
    var bad = try Parent.codec.decode(a, bytes, &changed);
    if (Parent.verify(&bad, &changed)) |accepted| {
        var invalid = accepted;
        invalid.deinit();
        return error.AcceptedChangedSourceClaim;
    } else |_| {}
}
