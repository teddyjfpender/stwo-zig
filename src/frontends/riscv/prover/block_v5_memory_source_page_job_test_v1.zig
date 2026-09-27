//! Bounded nonproving source job contracts. Publication bodies are retained
//! separately; these fixtures invoke no PCS/proof/FRI/guest/device path.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Job = @import("block_v5_memory_source_page_job_v1.zig");
const Claims = @import("block_v5_memory_source_page_claim_proposal_v1.zig");
const Batch = @import("block_v5_memory_source_batch_protocol_v1.zig");
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
const Initial = @import("block_v5_initial_sources_v1.zig");
const Defaults = @import("block_v5_memory_source_batch_defaults_v1.zig");
const Eq = @import("../recursion/air/block_v5_memory_source_batch_equations_v1.zig");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const Place = @import("../air/block/memory_component_trace.zig");
const Schema = @import("block_v5_memory_source_batch_raw_schema_v1.zig");
const SHA = @import("block_v5_memory_source_packed_sha_columns_v1.zig");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
fn admission() !Batch.Admission {
    const sha = Initial.sha256("");
    const root = Defaults.get().defaults[0].bytes;
    const source = try Source.make(.{ .initial = .{
        .layout = .{ .program_base = 0, .program_end = 16, .data_base = 32, .data_end = 256, .stack_bottom = 128, .stack_top = 512, .io_base = 256, .io_end = 768, .input_base = 32, .input_end = 64, .output_len_addr = 64, .output_data_addr = 68, .output_base = 64, .output_end = 256 },
        .initial_rw_root = root,
        .initial_registers = @splat(0),
        .public_input_sha256 = sha,
        .public_input_len = 0,
        .input_words = .{ .records = 0, .sha256 = sha },
        .rw_words = .{ .records = 0, .sha256 = sha },
        .first_touches = .{ .records = 0, .sha256 = sha },
    }, .memory_plan_digest = @splat(7), .expected_final_rw_root = root, .endpoints = .{ .records = 0, .sha256 = sha } }, @splat(8), .{});
    return Batch.Admission.init(source, .{});
}
fn challenges() Batch.Challenges {
    return .{ .source = .{ .word = .{ .transition = .dummy(), .link = .dummy(), .initial = .dummy(), .endpoint = .dummy(), .range16 = .dummy(), .universal_prefix = .dummy() }, .bytes = .dummy(), .input = .dummy(), .insertion = .dummy(), .before = .dummy(), .after = .dummy(), .route = .dummy(), .roots = .dummy(), .ordering = .dummy(), .sha_chain = .dummy() }, .route = .dummy(), .indexed = .dummy(), .hash = .dummy() };
}
test "source PAGE job: aggregate disk and metadata caps check exact boundary and arithmetic overflow" {
    try Job.requireLimits(.{});
    try std.testing.expectEqual(@as(u64, 100), try Job.FilesBudget.requireNext(71, 29, 100));
    try std.testing.expectError(error.SourcePageJobFileResourceLimit, Job.FilesBudget.requireNext(71, 30, 100));
    try std.testing.expectError(error.Overflow, Job.FilesBudget.requireNext(std.math.maxInt(u64), 1, std.math.maxInt(u64)));
    try std.testing.expectError(error.InvalidSourcePageJobLimits, Job.FilesBudget.requireNext(0, 0, 100));
    try std.testing.expectEqual(@sizeOf(Job.RawRecord) + 2 * @sizeOf(@import("block_v5_memory_source_packed_sha_replay_v1.zig").Pin) + @sizeOf(Job.FoldRecord) + 2 * @sizeOf(@import("block_v5_memory_source_unified_page_protocol_v1.zig").FoldPin), try Job.metadataBytes(1, 1));
    try std.testing.expectError(error.Overflow, Job.metadataBytes(std.math.maxInt(usize), 1));
}
test "source PAGE job: invalid budget failed phase and live owner reject before any proof or reader" {
    const T = Job.ForBackend(Cpu).Job;
    var deny = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.InvalidSourcePageJobLimits, T.collect(deny.allocator(), undefined, undefined, undefined, undefined, undefined, undefined, .{ .max_job_heap_bytes = 0 }));
    try std.testing.expectEqual(@as(usize, 0), deny.alloc_index);
    var failed: T = undefined;
    failed.active = false;
    failed.phase = .failed;
    try std.testing.expectError(error.InvalidSourcePageJobPhase, failed.publishNext(undefined));
    try std.testing.expectError(error.IncompleteSourcePageJobPublication, failed.requirePublished());
    failed.active = true;
    try std.testing.expectError(error.SourcePageJobPageLive, failed.deinit());
}
const EmptyFold = struct {
    cells: [2][Eq.BIT_COUNT]Q = undefined,
    fn init(self: *@This()) !void {
        const root = Defaults.get().defaults[0].bytes;
        try Eq.writeInputs(.{ .ordinal = 0, .kind = .empty, .coordinate = .{ .height = 30, .index = 0 }, .value = .{ .before = root, .after = root } }, &self.cells[0]);
        try Eq.writeInputs(.{ .ordinal = 1, .kind = .root, .coordinate = .{ .height = 30, .index = 0 }, .value = .{ .before = root, .after = root } }, &self.cells[1]);
    }
    fn read(raw: *anyopaque, group: Semantic.Group, logical: u32, column: u32) !M {
        const self: *@This() = @ptrCast(@alignCast(raw));
        if (group != .source or logical >= 2 or column >= Eq.BIT_COUNT) return error.InvalidSourcePageCell;
        return self.cells[logical][column].toM31Array()[0];
    }
};
test "source PAGE job: actual fold proposal graph closure and full root mutation are checked independently" {
    const admitted = try admission();
    const rows = [_]Semantic.FoldRow{
        .{ .descriptor = .{ .kind = .empty, .height = 30 }, .recipes = &.{}, .first_compression = 0, .compressions = 0 },
        .{ .descriptor = .{ .kind = .root, .height = 30 }, .recipes = &.{}, .first_compression = 0, .compressions = 0 },
    };
    var source = EmptyFold{};
    try source.init();
    const reader = Semantic.Reader{ .context = &source, .read = EmptyFold.read };
    const proposed = try Claims.fold(&admitted, &rows, reader, challenges());
    try std.testing.expect(proposed.fold.roots.eql(Q.one()));
    try std.testing.expect(proposed.fold.route.isZero());
    const graph = try Semantic.prepareFold(std.testing.allocator, &admitted, &rows, @splat(13), challenges(), proposed, 99, .{});
    defer graph.deinit();
    try graph.readAndMaterialize(reader, .{});
    source.cells[1][320] = source.cells[1][320].add(Q.one());
    if (Claims.fold(&admitted, &rows, reader, challenges())) |_| return error.TestExpectedError else |failure| try std.testing.expectEqual(error.UnsatisfiedSourcePageClaimProposal, failure);
}
const RawView = struct {
    source: *const Schema.Columns.Columns,
    captures: *const SHA.Matrix,
    fn read(raw: *anyopaque, group: Semantic.Group, row: u32, column: u32) !M {
        const self: *@This() = @ptrCast(@alignCast(raw));
        const values = if (group == .source) self.source.mainColumn(column) else self.captures.columns[column].values;
        return values[Place.committedRow(row, self.source.page.row_log)];
    }
    fn none(_: *anyopaque, _: Source.Stream, _: u64, out: []u8) !void {
        if (out.len != 0) return error.InvalidSourcePageEmptyFixture;
    }
};
test "source PAGE job: actual original five-stream packed SHA claim proposal matches semantic graph" {
    const a = std.testing.allocator;
    const admitted = try admission();
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .n_queries = 1, .log_last_layer_degree_bound = 0, .fold_step = 1 } };
    const limits = Schema.Protocol.Limits{ .page_row_log = 3 };
    const plan = try Schema.Protocol.init(&admitted.source, config, limits);
    const page = try plan.page(0);
    var dummy: u8 = 0;
    var cursor = try Schema.cursorInit(admitted.source, .{ .context = &dummy, .read = RawView.none });
    var source = try Schema.Columns.Columns.init(a, &admitted.source, plan, page, limits);
    defer source.deinit();
    for (0..page.chunks) |_| try source.append(&admitted.source, try cursor.next() orelse return error.InvalidSourcePageEmptyFixture);
    const setup = try SHA.Setup.create(a);
    defer setup.release();
    var cores = try SHA.Columns.regenerateWithSetup(a, &admitted.source, &source, .{}, setup);
    defer cores.deinit();
    var view = RawView{ .source = &source, .captures = &cores.captures };
    const reader = Semantic.Reader{ .context = &view, .read = RawView.read };
    const proposed = try Claims.raw(&admitted, page, reader, challenges());
    inline for (std.meta.fields(@TypeOf(proposed.source))) |field| try std.testing.expect(@field(proposed.source, field.name).isZero());
    try std.testing.expect(proposed.indexed.isZero());
    const pin = Schema.Protocol.Pin{ .plan_id = plan.identity, .page = page, .roots = @splat(@splat(7)), .config = config };
    const graph = try Semantic.prepareRaw(a, &admitted, plan, pin, challenges(), proposed, 101, limits, .{});
    defer graph.deinit();
    try graph.readAndMaterialize(reader, .{});
}

fn metadataPlans() !struct { admitted: Batch.Admission, raw: Schema.Protocol.Plan, fold: @import("block_v5_memory_source_unified_page_protocol_v1.zig").FoldPlan, base: @import("block_v5_source_seal_v1.zig").Sealed } {
    const admitted = try admission();
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .n_queries = 1, .log_last_layer_degree_bound = 0, .fold_step = 1 } };
    const limits = Job.Limits{};
    const raw_plan = try Schema.Protocol.init(&admitted.source, config, limits.proof.raw.first);
    const fold_plan = try @import("block_v5_memory_source_unified_page_protocol_v1.zig").FoldPlan.init(&admitted, .{ .empty = 1, .roots = 1 }, config, limits.proof.protocol);
    // Independent policy metadata for constructor/lifetime tests only, never
    // supplied as a freshly checked block/source/proof receipt.
    const base = @import("block_v5_source_seal_v1.zig").Sealed{
        .digest = admitted.source.sealed_digest,
        .native_roster_digest = @splat(0),
        .native_template_catalog_digest = @splat(0),
        .expected_final_rw_root = admitted.source.pins.expected_final_rw_root,
        .rw_endpoint_plan_digest = try admitted.source.pins.digest(),
        .register_endpoint_plan_digest = @splat(9),
        .register_custody_mode = 1,
        .program_first_roots = @splat(@splat(0)),
        .program_plan_digest = @splat(0),
        .program_root = @splat(0),
        .initial_source_plan_digest = try admitted.source.pins.initial.digest(),
        .counts = @splat(0),
        .memory_instance_count = 0,
        .execution_instance_count = 0,
    };
    return .{ .admitted = admitted, .raw = raw_plan, .fold = fold_plan, .base = base };
}
test "source PAGE job: actual constructor retains parent and setup lease until page release" {
    const B = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
    const T = Job.ForBackend(Cpu).Job;
    const plans = try metadataPlans();
    const parent = try B.create(std.testing.allocator, 256 << 20);
    var owns_parent = true;
    defer if (owns_parent) parent.destroy();
    const owner = try T.init(parent.allocator(), undefined, plans.admitted, plans.raw, plans.fold, plans.base, .{});
    errdefer owner.deinit() catch @panic("setup fixture rollback");
    var page_lease = try owner.sha_setup.?.lease();
    defer page_lease.deinit();
    const live = owner.budget.snapshot().live_bytes;
    try std.testing.expect(live >= @sizeOf(T) + @sizeOf(B));
    try std.testing.expect(owner.sha_setup.?.allocation_owner == owner.budget);
    parent.destroy(); // Drop coordinator; Job explicitly retains parent.
    owns_parent = false;
    try std.testing.expectError(error.SourcePageJobSetupLeaseLive, owner.deinit());
    try std.testing.expectEqual(live, owner.budget.snapshot().live_bytes);
    page_lease.deinit();
    try owner.deinit();
}
test "source PAGE job: initial budget control and setup allocation failures release parent references" {
    const B = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
    const T = Job.ForBackend(Cpu).Job;
    const plans = try metadataPlans();
    for (0..4) |position| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        const parent = try B.create(failing.allocator(), 256 << 20);
        defer parent.destroy();
        failing.fail_index = failing.alloc_index + position;
        try std.testing.expectError(error.OutOfMemory, T.init(parent.allocator(), undefined, plans.admitted, plans.raw, plans.fold, plans.base, .{}));
        try std.testing.expectEqual(@as(usize, 1), parent.references.load(.acquire));
        try std.testing.expectEqual(@as(usize, 0), parent.snapshot().live_bytes);
    }
}
fn inventoryFault(a: std.mem.Allocator) !void {
    const recipe = @import("block_v5_memory_source_blake_semantics_v1.zig").Recipe{ .slot = 0, .multiplicity = 2, .default_height = null, .compression_count = 1, .first_compression = 0 };
    var originals = [_]Semantic.FoldRow{.{ .descriptor = .{ .kind = .leaf, .height = 0 }, .recipes = &.{recipe}, .first_compression = 0, .compressions = 1 }};
    var copied = try Job.FoldInventory.copy(a, &originals, 1024);
    defer copied.deinit();
    originals[0].first_compression = 7;
    try std.testing.expectEqual(@as(u32, 0), copied.rows[0].first_compression);
    try std.testing.expect(std.meta.eql(recipe, copied.rows[0].recipes[0]));
    try std.testing.expectError(error.SourcePageJobMetadataResourceLimit, Job.FoldInventory.copy(a, &originals, 1));
}
test "source PAGE job: detached bounded fold recipe inventory has independent lifetime and every allocation fault" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, inventoryFault, .{});
}

// These guards exercise the actual publication entry, without supplying any
// synthetic accepted proof or invoking a PCS/STARK/FRI backend.
test "source PAGE publisher: exact roster resource guard cannot replay or publish a proposal" {
    const Pages = @import("block_v5_memory_source_unified_page_proof_v1.zig");
    inline for (.{ Semantic.Kind.raw, Semantic.Kind.fold }) |kind| {
        const P = Pages.ForKind(kind);
        const Producer = P.ForBackend(Cpu);
        const StageOwner = if (kind == .raw) @import("block_v5_memory_source_packed_sha_replay_v1.zig").ForBackend(Cpu).Owner else @import("block_v5_memory_source_fold_premix_v1.zig").ForBackend(Cpu).Owner;
        const Publisher = struct {
            calls: usize = 0,
            const Prepared = struct {
                owner: ?*StageOwner,
                claims: Semantic.Claims,
                rows: []const Semantic.FoldRow,
                pub fn releaseProducer(_: *@This()) void {
                    @panic("unexpected producer release");
                }
                pub fn deinit(_: *@This()) void {
                    @panic("unexpected producer owner");
                }
            };
            pub fn prepare(self: *@This(), _: std.mem.Allocator, _: u32) !Prepared {
                self.calls += 1;
                return error.FixtureCannotProduceProof;
            }
            pub fn accept(self: *@This(), _: u32, _: P.VerifiedPage, _: []const u8) !void {
                self.calls += 1;
                return error.FixtureCannotProduceProof;
            }
        };
        var publisher = Publisher{};
        var deny = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
        try std.testing.expectError(error.SourcePageReceiverResourceLimit, Producer.publishRoster(deny.allocator(), undefined, undefined, undefined, .{ .max_receiver_heap_bytes = 0 }, .{}, &publisher));
        try std.testing.expectEqual(@as(usize, 0), publisher.calls);
        try std.testing.expectEqual(@as(usize, 0), deny.alloc_index);
    }
}
test "source PAGE publisher: partial and failed jobs cannot resume through exact-roster publication" {
    const T = Job.ForBackend(Cpu).Job;
    var job: T = undefined;
    job.active = false;
    job.phase = .failed;
    try std.testing.expectError(error.InvalidSourcePageJobPhase, job.publishAll(undefined));
    job.phase = .publishing;
    try std.testing.expectError(error.InvalidSourcePageJobPhase, job.publishAll(undefined));
    job.phase = .sealed;
    job.active = true;
    try std.testing.expectError(error.InvalidSourcePageJobPhase, job.publishAll(undefined));
    job.active = false;
    job.next_raw = 1;
    try std.testing.expectError(error.InvalidSourcePageJobPhase, job.publishAll(undefined));
    job.next_raw = 0;
    job.next_fold = 1;
    try std.testing.expectError(error.InvalidSourcePageJobPhase, job.publishAll(undefined));
}
test "source PAGE publisher: stale complete context poisons job before any replay or callback" {
    const T = Job.ForBackend(Cpu).Job;
    var job: T = undefined;
    job.active = false;
    job.phase = .sealed;
    job.next_raw = 0;
    job.next_fold = 0;
    var context: @import("block_v5_memory_source_unified_page_proof_v1.zig").Context = undefined;
    context.admitted = try admission();
    context.admitted.identity[0] ^= 1;
    job.context = context;
    job.limits = .{};
    const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 1 << 20);
    defer budget.destroy();
    job.budget = budget;
    // No setup methods or I/O may be reached for an invalid complete context.
    const sha: SHA.Setup = undefined;
    const arithmetic: @import("block_v5_memory_source_unified_page_components_v1.zig").ArithmeticSetup = undefined;
    job.sha_setup = &sha;
    job.arithmetic_setup = &arithmetic;
    try std.testing.expectError(error.InvalidSourceFoldAdmission, job.publishAll(undefined));
    try std.testing.expectEqual(Job.Phase.failed, job.phase);
    try std.testing.expect(!job.active);
    try std.testing.expectEqual(@as(u32, 0), job.next_raw);
    try std.testing.expectEqual(@as(u32, 0), job.next_fold);
    try std.testing.expectError(error.IncompleteSourcePageJobPublication, job.requirePublished());
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().host_live_bytes);
}
