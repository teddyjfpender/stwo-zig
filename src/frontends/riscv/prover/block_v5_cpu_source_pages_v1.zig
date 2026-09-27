//! Capacity-CPU source PAGE collection and durable publication. The driver
//! reopens the independent policy and all proofs in one complete fresh receiver.
//! Final recursive source/global compression remains a separate obligation.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const core = @import("stwo_core");
const JobModule = @import("block_v5_memory_source_page_job_v1.zig");
pub const Job = JobModule.ForBackend(Cpu).Job;
const Reader = @import("block_v5_memory_source_page_reader_v1.zig").Reader;
const Source = @import("block_v5_memory_source_auth_protocol_v1.zig");
const Batch = @import("block_v5_memory_source_batch_protocol_v1.zig");
const Fold = @import("block_v5_memory_source_batch_fold_v1.zig");
const Spool = @import("block_v5_memory_source_fold_spool_v1.zig");
const Draft = @import("block_v5_memory_source_fold_draft_pages_v1.zig");
const Schema = @import("block_v5_memory_source_batch_raw_schema_v1.zig");
const Protocol = @import("block_v5_memory_source_unified_page_protocol_v1.zig");
const Writer = @import("block_v5_memory_source_writer_v1.zig");
const Seal = @import("block_v5_source_seal_v1.zig");
const Join = @import("block_v5_memory_source_page_join_owner_v1.zig");
const Transition = @import("block_v5_memory_source_page_transition_receiver_v1.zig");
const Loader = @import("block_v5_memory_source_page_job_loader_v1.zig").Loader;
const Bundle = @import("block_v5_cpu_bundle_store_v1.zig").ForCapacity(true);
const Global = @import("block_v5_capacity_global_receiver_v1.zig");
const PagePolicy = @import("block_v5_memory_source_page_policy_file_v1.zig");
const Export = @import("block_v5_memory_source_page_policy_export_v1.zig");
const Semantic = @import("block_v5_memory_source_page_semantic_columns_v1.zig");
const FoldStore = @import("block_v5_memory_source_fold_operand_store_v1.zig");
pub const PolicyPin = PagePolicy.Pin;
pub const Options = struct {
    job: JobModule.Limits = .{},
    source: Source.Limits = .{},
    fold: Fold.Limits = .{},
    spool: Spool.Limits = .{},
    join: Join.Limits = .{},
    transition: Transition.Limits = .{},
    policy: PagePolicy.Limits = .{},
    loader_owned_bytes: usize = 1 << 30,
    verification_heap_bytes: usize = 40 << 30,
    pub fn validate(self: Options) !void {
        try JobModule.requireLimits(self.job);
        try Spool.validateLimits(self.spool);
        _ = try draftLimits(self);
        try self.policy.validate();
        if (self.loader_owned_bytes == 0 or self.verification_heap_bytes == 0 or
            !std.meta.eql(self.policy.source, self.source) or !std.meta.eql(self.policy.fold, self.fold) or
            !std.meta.eql(self.policy.pages, self.job.proof) or !std.meta.eql(self.policy.codec, self.job.artifact))
            return error.InvalidV5CpuSourcePageOptions;
        if (!std.meta.eql(self.join.pages, self.job.proof) or self.join.max_pages == 0 or self.join.max_memory_instances == 0 or
            self.join.max_setup_bytes == 0 or self.join.max_live_bytes == 0 or self.transition.max_live_bytes == 0 or self.transition.max_executions == 0)
            return error.InvalidV5CpuSourcePageOptions;
        if (self.source.max_stream_bytes == 0 or self.source.max_records == 0 or self.source.max_nodes == 0 or
            self.source.max_nodes >= core.fields.m31.Modulus or self.source.max_chunk_heap_bytes == 0 or
            self.fold.max_leaves == 0 or self.fold.max_operations == 0 or self.fold.max_compressions == 0 or
            self.fold.max_operations >= core.fields.m31.Modulus or self.fold.max_compressions >= core.fields.m31.Modulus)
            return error.InvalidV5CpuSourcePageOptions;
    }
};
pub const Report = struct {
    page_seal: [32]u8,
    raw_pages: u32,
    fold_pages: u32,
    operand_bytes: u64,
    artifact_bytes: u64,
    artifact_files: usize,
    fresh_transition_events: u64,
    /// Includes replay/proving/encoding and initial fresh publication checks.
    /// It is deliberately not labeled isolated STARK proving time.
    publication_ns: u64,
    independent_verification_ns: u64,
    /// The driver completes the entire independently loaded bundle, sharing
    /// its native/caller/provider/forest pass with the source verification.
    verification_scope: enum { source_transition, complete_bundle } = .source_transition,
    pub const recursive_global_authority = false;
};
pub const Published = struct { policy: PolicyPin, report: Report };
/// Runs after exact first-pass sourcewriter and final B5SS seal. Reader/input
/// are borrowed only for this synchronous collection. No guest is replayed.
pub fn collect(a: std.mem.Allocator, dir: std.fs.Dir, sources: *const Writer.Result, seal_pins: Seal.Pins, entries: []const Seal.Entry, sealed: Seal.Sealed, input: []const u8, config: core.pcs.PcsConfig, options: Options) !*Job {
    try options.validate();
    const source = try Source.admit(sources.endpointPins(seal_pins.memory_plan_digest), seal_pins, entries, sealed, options.source);
    const admitted = try Batch.Admission.init(source, options.fold);
    var reader = try Reader.init(source, sources.files(), input);
    // Preserve each original record directly in its private PAGE inode while
    // counting the single tree traversal. Job later promotes that same payload
    // only after its genuine six-root owner/pin checks; no whole spool remains.
    const drafts = try Draft.collect(a, dir, &admitted, reader.provider(), try draftLimits(options));
    defer drafts.deinit() catch @panic("CPU source draft reader lifetime");
    const raw_plan = try Schema.Protocol.init(&source, config, options.job.proof.raw.first);
    const fold_plan = try Protocol.FoldPlan.init(&admitted, drafts.census, config, options.job.proof.protocol);
    return Job.collectWithDrafts(a, dir, admitted, raw_plan, fold_plan, reader.provider(), drafts, sealed, options.job);
}
/// Existing spool limits remain source-compatible workload caps. They now cap
/// the once-stored final PAGE payload, not a duplicate whole-stream artifact.
/// Metadata/control allocations use the ORIGINAL caller aggregate allocator.
pub fn draftLimits(options: Options) !Draft.Limits {
    const limits = Draft.Limits{
        .row_log = options.job.proof.protocol.page_row_log,
        .max_pages = options.job.proof.protocol.max_fold_pages,
        .max_operations = @min(options.spool.max_operations, options.fold.max_operations),
        .max_metadata_bytes = @min(options.job.max_metadata_bytes, options.job.proof.protocol.max_roster_bytes),
        .max_total_bytes = @min(options.spool.max_file_bytes, options.job.max_operand_bytes),
        .stored = options.job.proof.fold.stored,
    };
    try Draft.validateLimits(limits);
    return limits;
}
const Observations = struct {
    // Deliberately never accumulate source claims or mint a source receipt.
    fn raw(_: *anyopaque, _: *const JobModule.RawPage.VerifiedPage, _: JobModule.ArtifactPin) !void {}
    fn fold(_: *anyopaque, _: *const JobModule.FoldPage.VerifiedPage, _: JobModule.ArtifactPin) !void {}
};
/// Publish proofs and independently reconstructible normative policy only.
/// No source transition/native/caller proof is loaded here. The caller can
/// release the complete producer Job before the fresh detached receive.
pub fn publish(job: *Job, globals: Global.Pins, options: Options) !Published {
    try options.validate();
    if (!std.meta.eql(job.limits, options.job)) return error.ChangedV5CpuSourcePageOptions;
    var timer = try std.time.Timer.start();
    var observations: u8 = 0;
    try job.publishAll(.{ .context = &observations, .raw = Observations.raw, .fold = Observations.fold });
    try job.requirePublished();
    const a = job.allocator();
    const raws = try a.alloc(PagePolicy.Artifact, job.raws.len);
    defer a.free(raws);
    const folds = try a.alloc(PagePolicy.Artifact, job.folds.len);
    defer a.free(folds);
    const operands = try a.alloc(FoldStore.Pin, job.folds.len);
    defer a.free(operands);
    const raw_claims = try a.alloc(Semantic.Claims, job.raws.len);
    defer a.free(raw_claims);
    const fold_claims = try a.alloc(Semantic.Claims, job.folds.len);
    defer a.free(fold_claims);
    for (raws, raw_claims, job.raws) |*artifact, *claims, record| {
        const pin = record.artifact orelse return error.IncompleteSourcePageJobPublication;
        artifact.* = .{ .byte_len = pin.byte_len, .sha256 = pin.sha256 };
        claims.* = record.expected_claims orelse return error.MissingIndependentSourcePageClaims;
    }
    for (folds, operands, fold_claims, job.folds) |*artifact, *operand, *claims, record| {
        const pin = record.artifact orelse return error.IncompleteSourcePageJobPublication;
        artifact.* = .{ .byte_len = pin.byte_len, .sha256 = pin.sha256 };
        operand.* = record.stored;
        claims.* = record.expected_claims orelse return error.MissingIndependentSourcePageClaims;
    }
    const policy = try Export.write(a, job.dir, globals, &job.context.?, .{ .raw = raws, .fold = folds, .fold_operands = operands, .raw_claims = raw_claims, .fold_claims = fold_claims }, options.policy);
    return .{ .policy = policy, .report = .{
        .page_seal = job.context.?.sealed.digest,
        .raw_pages = @intCast(job.raws.len),
        .fold_pages = @intCast(job.folds.len),
        .operand_bytes = job.files.operands,
        .artifact_bytes = job.files.artifacts,
        .artifact_files = try std.math.add(usize, job.raws.len, job.folds.len),
        .fresh_transition_events = 0,
        .publication_ns = timer.lap(),
        .independent_verification_ns = 0,
    } };
}
/// Called after base family workers join and all genuine original files exist.
/// Load and freshly verify PAGE/lane/range/native/caller proofs, not callbacks.
pub fn publishAndVerify(job: *Job, pins: Global.Pins, policies: []const Bundle.Policy, files: []const Bundle.FilePin, bundle_limits: Bundle.Limits, options: Options) !Report {
    try options.validate();
    if (!std.meta.eql(job.limits, options.job)) return error.ChangedV5CpuSourcePageOptions;
    var timer = try std.time.Timer.start();
    var observations: u8 = 0;
    try job.publishAll(.{ .context = &observations, .raw = Observations.raw, .fold = Observations.fold });
    try job.requirePublished();
    const publication_ns = timer.lap();
    const lanes = switch (pins.memory.memory) {
        .lanes => |value| value,
        .word => return error.NoncanonicalSourcePageTransitionMemory,
    };
    // Join metadata and live decode/proof scratch are beneath the SAME job
    // cap and driver global parent, with exact immutable setup leases.
    const a = job.allocator();
    const receiver = try Join.Owner.createWithSetups(a, &job.context.?, lanes, options.join, job.sha_setup.?, job.blake_setup.?, job.arithmetic_setup.?);
    defer receiver.deinit();
    var loader = try Loader.init(job, policies, files, job.fold_plan.config, bundle_limits);
    defer {
        loader.requireReleased() catch @panic("source PAGE loader descriptor lifetime");
        loader.deinit();
    }
    var fresh = try Transition.verify(a, pins, receiver, loader.pageLoader(), loader.transitionLoader(), options.transition);
    defer fresh.deinit();
    return .{ .page_seal = fresh.source.page_seal, .raw_pages = fresh.source.raw_pages, .fold_pages = fresh.source.fold_pages, .operand_bytes = job.files.operands, .artifact_bytes = job.files.artifacts, .artifact_files = try std.math.add(usize, job.raws.len, job.folds.len), .fresh_transition_events = fresh.source.events, .publication_ns = publication_ns, .independent_verification_ns = timer.lap() };
}
