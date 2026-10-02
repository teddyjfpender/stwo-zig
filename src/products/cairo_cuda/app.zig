//! Production Cairo CUDA CLI dispatch.

const std = @import("std");
const cli = @import("cli.zig");
const stwo = @import("stwo_cairo_cuda");
const publication = @import("publication.zig");
const CanonicalSource = stwo.integration.canonical_source.Prepared;
const Decoded = stwo.integration.canonical_verify.Decoded;
const ProofCapture = stwo.frontend.witness.resident_verifier.ProofCapture;
pub const NativeRuntime = stwo.backend.runtime.NativeRuntime;
const DeviceImage = stwo.executor.preprocessed_cache.DeviceImage;
const CanonicalAssets = stwo.integration.canonical_source.Assets;

/// The verified proof and its authenticated openings are borrowed only during
/// this callback. A recursive leaf builder can consume them without proving
/// the same Cairo execution again or serializing a large capture sidecar.
pub const VerifiedLeafSink = struct {
    context: *anyopaque,
    receive: *const fn (*anyopaque, *const CanonicalSource, *const Decoded, *const ProofCapture, u64) anyerror!void,
};
pub const BatchItem = struct {
    request: cli.Prove,
    sink: ?VerifiedLeafSink,
};
const Mode = enum { repeated, distinct };
const ResidentStatic = struct {
    arena_key: [32]u8,
    receipt: stwo.executor.preprocessed_cache.Receipt,
};

const ingress_jobs = @import("ingress_jobs.zig");
pub const PrefetchJob = ingress_jobs.FixedAssetJob;
const SourcePrepareJob = ingress_jobs.SourcePrepareJob;

/// Retains authenticated source assets and the checked fixed device image
/// across separate batches on one resident runtime. Dynamic PIE inputs,
/// transcripts, and proof transactions remain request-local.
pub const BatchSession = struct {
    allocator: std.mem.Allocator,
    runtime: *NativeRuntime,
    assets: ?CanonicalAssets = null,
    device_image: ?DeviceImage = null,
    resident_static: ?ResidentStatic = null,
    executable_digest: ?[32]u8 = null,
    /// Caller-owned job; it must outlive the first proof and can be released
    /// once that proof has admitted the immutable static receipt.
    early_prefetch: ?*PrefetchJob = null,

    pub fn deinit(self: *BatchSession) !void {
        var assets = self.assets;
        self.assets = null;
        defer if (assets) |*owned| owned.deinit();
        if (self.device_image) |*image| try image.deinit(self.runtime);
        self.device_image = null;
        self.resident_static = null;
    }
};

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const process_args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, process_args);

    const parsed = cli.parse(process_args[1..]) catch |err| {
        try cli.writeUsage(std.fs.File.stderr().deprecatedWriter());
        return err;
    };
    switch (parsed) {
        .help => try cli.writeUsage(std.fs.File.stdout().deprecatedWriter()),
        .prove => |request| try prove(allocator, request),
    }
}

fn prove(allocator: std.mem.Allocator, request: cli.Prove) !void {
    return proveWithSink(allocator, request, null);
}

pub fn proveWithSink(allocator: std.mem.Allocator, request: cli.Prove, sink: ?VerifiedLeafSink) !void {
    return proveWithSinkUsingPrefetch(allocator, request, sink, null);
}

pub fn proveWithSinkUsingPrefetch(allocator: std.mem.Allocator, request: cli.Prove, sink: ?VerifiedLeafSink, early_prefetch: ?*PrefetchJob) !void {
    if (sink != null and (request.circuit_registry == null or request.repeat != 1))
        return error.InvalidRecursiveLeafRequest;
    if (request.repeat == 0 or request.repeat > 16) return error.InvalidRepeatCount;
    const items = try allocator.alloc(BatchItem, request.repeat);
    defer allocator.free(items);
    for (items) |*item| item.* = .{ .request = request, .sink = sink };
    return runItems(allocator, items, .repeated, null, null, early_prefetch);
}

/// Prove distinct adapted PIEs in one process. The authenticated arena key
/// decides whether a later item may reuse static preprocessing; no witness or
/// transcript state is shared between items.
pub fn proveBatchWithSinks(allocator: std.mem.Allocator, items: []const BatchItem) !void {
    if (items.len == 0 or items.len > 256) return error.InvalidBatchSize;
    for (items) |item| {
        if (item.sink == null or item.request.circuit_registry == null or item.request.repeat != 1)
            return error.InvalidRecursiveLeafRequest;
    }
    return runItems(allocator, items, .distinct, null, null, null);
}

/// The circuit receiver borrows this runtime after each Cairo proof. Its
/// prepared Cairo arena is evicted before the callback so a large circuit
/// arena can fit on one GPU; the context and AOT modules remain live.
pub fn proveBatchWithSinksUsingRuntime(allocator: std.mem.Allocator, items: []const BatchItem, runtime: *NativeRuntime) !void {
    if (items.len == 0 or items.len > 256) return error.InvalidBatchSize;
    for (items) |item| {
        if (item.sink == null or item.request.circuit_registry == null or item.request.repeat != 1)
            return error.InvalidRecursiveLeafRequest;
    }
    return runItems(allocator, items, .distinct, runtime, null, null);
}

pub fn proveBatchWithSinksUsingSession(allocator: std.mem.Allocator, items: []const BatchItem, session: *BatchSession) !void {
    if (items.len == 0 or items.len > 256) return error.InvalidBatchSize;
    for (items) |item| {
        if (item.sink == null or item.request.circuit_registry == null or item.request.repeat != 1)
            return error.InvalidRecursiveLeafRequest;
    }
    return runItems(allocator, items, .distinct, session.runtime, session, session.early_prefetch);
}

fn runItems(allocator: std.mem.Allocator, items: []const BatchItem, mode: Mode, external_runtime: ?*NativeRuntime, persistent: ?*BatchSession, early_prefetch: ?*PrefetchJob) !void {
    const receipts = try allocator.alloc(publication.Receipt, items.len);
    defer allocator.free(receipts);
    const executable_digest = if (persistent) |session| blk: {
        if (session.executable_digest) |digest| break :blk digest;
        const executable = try std.fs.selfExePathAlloc(allocator);
        defer allocator.free(executable);
        const digest = try publication.sha256File(executable);
        session.executable_digest = digest;
        break :blk digest;
    } else blk: {
        const executable = try std.fs.selfExePathAlloc(allocator);
        defer allocator.free(executable);
        break :blk try publication.sha256File(executable);
    };
    var startup = try std.time.Timer.start();
    var first_paths = try @import("canonical_paths.zig").Paths.init(
        allocator,
        items[0].request.input,
        items[0].request.circuit_registry,
    );
    defer first_paths.deinit();
    var prefetch = PrefetchJob{ .allocator = allocator, .path = first_paths.preprocessed };
    defer prefetch.deinit();
    const image_setting = std.process.getEnvVarOwned(allocator, "STWO_CAIRO_CUDA_STATIC_IMAGE") catch null;
    defer if (image_setting) |value| allocator.free(value);
    const use_device_image = external_runtime != null and (items.len > 1 or persistent != null) and
        image_setting != null and std.mem.eql(u8, image_setting.?, "1");
    // A verified leaf sink lends CUDA to the circuit prover. Its prepared
    // Cairo arena may be evicted before the next leaf, so an old static
    // receipt alone does not mean later leaves can skip the artifact. Retain
    // one checked host snapshot for this batch and revalidate its columns on
    // every reload. An admitted device image supersedes that host snapshot.
    const needs_prefetch = if (persistent) |session|
        (session.resident_static == null or items[0].sink != null) and
            (!use_device_image or session.device_image == null or session.device_image.?.receipt == null)
    else
        true;
    if (needs_prefetch and early_prefetch == null) try prefetch.start();
    var local_assets: ?CanonicalAssets = null;
    defer if (local_assets) |*assets| assets.deinit();
    const assets_slot = if (persistent) |session| &session.assets else &local_assets;
    var asset_init_ns: u64 = 0;
    if ((items.len > 1 or persistent != null) and assets_slot.* == null) {
        assets_slot.* = try CanonicalAssets.load(allocator, first_paths.source);
        asset_init_ns = startup.lap();
    }
    var owned_runtime: NativeRuntime = undefined;
    var owned_runtime_live = false;
    defer if (owned_runtime_live) owned_runtime.abort() catch {};
    if (external_runtime == null) {
        const accepted_sms = try stwo.backend.runtime.device_admission.parseArchitectures(allocator, @import("cuda_architectures").architectures);
        defer allocator.free(accepted_sms);
        owned_runtime = try NativeRuntime.open(accepted_sms);
        owned_runtime_live = true;
    }
    const runtime = external_runtime orelse &owned_runtime;
    const runtime_init_ns = if (external_runtime == null) startup.read() else 0;
    var local_image: ?DeviceImage = null;
    defer if (local_image) |*image| image.deinit(runtime) catch {};
    const image_slot = if (persistent) |session| &session.device_image else &local_image;
    var expected_digest: ?[32]u8 = null;
    var local_static: ?ResidentStatic = null;
    const static_slot = if (persistent) |session| &session.resident_static else &local_static;
    const lookahead_setting = std.process.getEnvVarOwned(allocator, "STWO_CAIRO_CUDA_SOURCE_LOOKAHEAD") catch null;
    defer if (lookahead_setting) |value| allocator.free(value);
    const lookahead = mode == .distinct and items.len > 1 and assets_slot.* != null and
        lookahead_setting != null and std.mem.eql(u8, lookahead_setting.?, "1");
    const source_jobs = try allocator.alloc(?SourcePrepareJob, items.len);
    defer allocator.free(source_jobs);
    @memset(source_jobs, null);
    defer for (source_jobs) |*slot| {
        if (slot.*) |*job| job.deinit();
    };
    for (items, 0..) |item, index| {
        if (lookahead and index + 1 < items.len and ingress_jobs.sourceEligible(items[index + 1].request.input)) {
            const target = try compileTarget(runtime.planningSession());
            source_jobs[index + 1] = .{
                .allocator = allocator,
                .request = items[index + 1].request,
                .target = target,
                .assets = &assets_slot.*.?,
            };
            source_jobs[index + 1].?.start() catch {
                source_jobs[index + 1] = null;
            };
        }
        const assets: ?*const CanonicalAssets = if (assets_slot.*) |*shared| shared else null;
        const receipt = try proveOnce(allocator, runtime, static_slot, if (use_device_image) image_slot else null, item.request, executable_digest, @intCast(if (mode == .repeated) index + 1 else 1), if (index == 0) runtime_init_ns else 0, if (index == 0) asset_init_ns else 0, item.sink, external_runtime != null, assets, if (needs_prefetch) early_prefetch orelse &prefetch else null, if (source_jobs[index]) |*job| job else null);
        if (mode == .repeated) {
            if (expected_digest) |expected| {
                if (!std.mem.eql(u8, &expected, &receipt.proof_sha256)) return error.NondeterministicCairoCudaProof;
            } else expected_digest = receipt.proof_sha256;
        }
        receipts[index] = receipt;
        try publication.writeReport(item.request.report_out, if (mode == .repeated) receipts[0 .. index + 1] else receipts[index .. index + 1]);
    }
    var teardown = try std.time.Timer.start();
    if (local_image) |*image| {
        try image.deinit(runtime);
        local_image = null;
        std.debug.print("cairo-cuda static-image release_ns={}\n", .{teardown.read()});
    }
    if (owned_runtime_live) {
        try owned_runtime.close();
        owned_runtime_live = false;
    }
    const teardown_ns = if (external_runtime == null) teardown.read() else 0;
    if (mode == .repeated) {
        try publication.writeFinalReport(items[0].request.report_out, receipts, teardown_ns);
    } else {
        for (items, 0..) |item, index| {
            try publication.writeFinalReport(item.request.report_out, receipts[index .. index + 1], if (index + 1 == items.len) teardown_ns else 0);
        }
    }
}

fn proveOnce(
    allocator: std.mem.Allocator,
    runtime: *stwo.backend.runtime.NativeRuntime,
    resident_static: *?ResidentStatic,
    device_image_slot: ?*?DeviceImage,
    request: cli.Prove,
    executable_digest: [32]u8,
    index: u32,
    runtime_init_ns: u64,
    asset_init_ns: u64,
    sink: ?VerifiedLeafSink,
    release_arena_for_sink: bool,
    assets: ?*const CanonicalAssets,
    prefetch: ?*PrefetchJob,
    source_job: ?*SourcePrepareJob,
) !publication.Receipt {
    var timer = try std.time.Timer.start();
    var phase: []const u8 = "resolve_input";
    errdefer |err| std.debug.print("cairo-cuda phase={s} failed: {s}\n", .{ phase, @errorName(err) });
    var paths = try @import("canonical_paths.zig").Paths.init(allocator, request.input, request.circuit_registry);
    defer paths.deinit();
    const paths_end_ns = timer.read();
    const runtime_end_ns = timer.read();

    phase = "compile_canonical_source";
    const target = try compileTarget(runtime.planningSession());
    var diagnostic = if (source_job) |job|
        try job.take()
    else
        try stwo.integration.canonical_source.prepareWithAssets(allocator, paths.source, target, assets);
    defer diagnostic.deinit();
    if (!std.meta.eql(diagnostic.request.plan.target, target)) return error.CairoSourceTargetChanged;
    if (diagnostic.request.missing_lowerings.len != 0)
        return error.IncompleteCairoCudaLowering;
    const source_end_ns = timer.read();

    phase = "prepare_controllers";
    var controllers_prepared = try stwo.executor.ingress.controller_bundle
        .Prepared.init(
        allocator,
        &diagnostic.request,
        diagnostic.protocol,
        diagnostic.composition,
        diagnostic.preprocessed_logs,
    );
    defer controllers_prepared.deinit();
    const controllers_end_ns = timer.read();
    var device_image: ?*DeviceImage = null;
    if (device_image_slot) |slot| {
        const prepared = &controllers_prepared.preprocessed_commit;
        const key = stwo.executor.preprocessed_cache.deviceImageKey(
            paths.preprocessed,
            diagnostic.fixed.preprocessed_identities,
            prepared,
        );
        if (slot.*) |*image| {
            if (!std.mem.eql(u8, &image.key, &key)) {
                try image.deinit(runtime);
                slot.* = null;
            }
        }
        if (slot.* == null) {
            const words = prepared.column_offsets[prepared.column_offsets.len - 1];
            slot.* = try DeviceImage.init(runtime, words, key);
        }
        device_image = &slot.*.?;
    }
    var twiddles = try stwo.executor.canonical_twiddles.Pack.init(
        allocator,
        &diagnostic.request.resident,
    );
    defer twiddles.deinit();
    const twiddles_end_ns = timer.read();

    const arena_plan = controllers_prepared.resident.combined_arena;
    std.debug.print("cairo-cuda arena reservation bytes={} slots={}\n", .{ arena_plan.total_words * 4, arena_plan.placements.len });
    for (arena_plan.placements) |placement| {
        if (placement.requirement.words >= 1 << 24) std.debug.print("cairo-cuda arena slot={} bytes={} offset={} lifetime={s}..{s}\n", .{ placement.requirement.id, placement.requirement.words * 4, placement.offset_words * 4, @tagName(placement.requirement.live_from), @tagName(placement.requirement.live_through) });
    }
    phase = "allocate_arena";
    var arena_key_hash = std.crypto.hash.sha2.Sha256.init(.{});
    arena_key_hash.update("stwo-zig/cairo-cuda-combined-arena/v1\x00");
    arena_key_hash.update(&diagnostic.request.plan.cache_key);
    arena_key_hash.update(&controllers_prepared.resident.identity);
    const arena_key = arena_key_hash.finalResult();
    const arena_reused = runtime.hasPreparedExecution(arena_key);
    if (!arena_reused) {
        resident_static.* = null;
        try runtime.prepareExecution(allocator, arena_key, try arena_plan.clone(allocator));
    }
    const session = try runtime.beginProof();
    var transaction = try stwo.backend.runtime.proof_transaction
        .ResidentProofTransaction.openPreparedCachedRetained(
        allocator,
        session,
        arena_key,
    );
    var transaction_live = true;
    defer if (transaction_live) transaction.abort() catch {};
    const allocation_end_ns = timer.read();

    const Transaction = @TypeOf(transaction);
    const Provider = stwo.executor.resident_session.ProviderFor(
        *Transaction,
        *Transaction,
    );
    const provider = try Provider.init(
        &diagnostic.request.resident,
        &controllers_prepared.resident,
        &transaction,
        &transaction,
    );
    phase = "bind_controllers";
    var controllers = try controllers_prepared.bindControllers(
        &transaction,
        provider,
        &diagnostic.request,
        diagnostic.protocol,
        diagnostic.composition,
    );
    defer controllers.deinit();
    const binding_end_ns = timer.read();
    phase = "initialize_static";
    // --repeat retains one immutable preprocessing snapshot. The combined
    // arena key binds its full geometry/lifetimes; a cache miss reloads it.
    const cached_preprocessed = if (resident_static.*) |cached|
        if (std.mem.eql(u8, &cached.arena_key, &arena_key)) cached.receipt else null
    else
        null;
    const prefetched = if (cached_preprocessed == null and
        (device_image == null or device_image.?.receipt == null))
        if (prefetch) |job| try job.wait() else null
    else
        null;
    const static_receipt = try controllers.initializeStatic(
        &transaction,
        provider,
        &diagnostic.request,
        .{
            .adapted_input = diagnostic.adapted_bytes,
            .forward_twiddles = twiddles.forwardWords(),
            .inverse_twiddles = twiddles.inverseWords(),
            .preprocessed_path = paths.preprocessed,
            .preprocessed_column_identities = diagnostic.fixed.preprocessed_identities,
            .preprocessed_prefetch = prefetched,
            .resident_preprocessed = cached_preprocessed,
            .device_image = device_image,
        },
    );
    resident_static.* = .{ .arena_key = arena_key, .receipt = static_receipt.preprocessed };
    const static_end_ns = timer.read();
    phase = "prepare_writers";
    var registry = try stwo.backend.product_aot.Registry.initCanonicalCairo(
        allocator,
    );
    defer registry.deinit();
    var uploader = Uploader{ .session = transaction.proofSession() };
    var writers = try stwo.executor.ingress.writer_binding.prepare(
        allocator,
        transaction.proofSession(),
        &uploader,
        provider,
        registry,
        &diagnostic.request,
        &diagnostic.request.proof,
        diagnostic.composition,
        diagnostic.witnesses,
        diagnostic.feeds,
        diagnostic.fixed,
        &diagnostic.input,
        &controllers,
    );
    defer writers.deinit();
    const writers_end_ns = timer.read();
    phase = "bind_statement";
    const statement = try controllers.bindStatement(
        allocator,
        &uploader,
        provider,
        &diagnostic.request,
    );
    phase = "bind_transcript";
    const transcript = try controllers.transcriptBindings(
        statement,
        try stwo.executor.ingress.writer_binding.relationElements(
            provider,
            &diagnostic.request,
        ),
    );
    phase = "prepare_proof_session";
    var proof = try stwo.executor.proof_session.Prepared.init(
        &diagnostic.request,
        diagnostic.protocol,
        controllers.sessionControllers(
            writers.writers(),
            writers.relation(),
            &writers.relation_sources,
        ),
        transcript,
    );
    const ingress_ns = timer.read();
    phase = "execute_proof";
    _ = try proof.executeDevelopment(
        &transaction,
        &diagnostic.request.resident,
        diagnostic.protocol,
    );
    phase = "finish_proof";
    errdefer publication.writeFailureInputs(allocator, &diagnostic) catch |dump_error| {
        std.debug.print("cairo-cuda failure inputs write failed: {s}\n", .{@errorName(dump_error)});
    };
    try @import("source_diagnostic.zig").runIfRequested(allocator, &transaction, &diagnostic, &writers);
    var output = try proof.finish(
        allocator,
        &transaction,
        &diagnostic.request.resident,
        diagnostic.protocol,
    );
    const proof_end_ns = timer.read();
    transaction_live = false;
    defer output.deinit(allocator);

    phase = "verify_canonical_proof";
    var capture: ProofCapture = undefined;
    var decoded = if (sink != null)
        try stwo.integration.canonical_verify.verifyAndDecodeWithCapture(allocator, &diagnostic, output.proof, &capture)
    else
        try stwo.integration.canonical_verify.verifyAndDecode(allocator, &diagnostic, output.proof);
    defer decoded.deinit(allocator);
    defer if (sink != null) capture.deinit(allocator);
    if (device_image) |image| {
        if (image.pending != null) try image.admit();
    }
    phase = "publish_official_proof";
    const proof_bytes = try publication.writeCanonicalProof(request.output, &diagnostic, &decoded, output.proof.structural.interactionNonce());
    const receipt: publication.Receipt = .{
        .index = index,
        .protocol = diagnostic.protocol,
        .input_sha256 = diagnostic.input_sha256,
        .executable_sha256 = executable_digest,
        .planned_arena_bytes = @as(u64, arena_plan.total_words) * 4,
        .prepared_arena_reused = arena_reused,
        .preprocessed_reused = cached_preprocessed != null,
        .ingress_ns = ingress_ns + runtime_init_ns + asset_init_ns,
        .source_lookahead_prepare_ns = if (source_job) |job| job.preparation_ns else 0,
        .source_lookahead_wait_ns = if (source_job) |job| job.wait_ns else 0,
        .ingress_timings = .{
            .paths_ns = paths_end_ns,
            .runtime_ns = runtime_init_ns + runtime_end_ns - paths_end_ns,
            .source_ns = source_end_ns - runtime_end_ns + asset_init_ns,
            .controllers_ns = controllers_end_ns - source_end_ns,
            .twiddles_ns = twiddles_end_ns - controllers_end_ns,
            .allocation_ns = allocation_end_ns - twiddles_end_ns,
            .binding_ns = binding_end_ns - allocation_end_ns,
            .static_ns = static_end_ns - binding_end_ns,
            .writers_ns = writers_end_ns - static_end_ns,
            .statement_and_session_ns = ingress_ns - writers_end_ns,
        },
        .proof_execute_and_decode_ns = proof_end_ns - ingress_ns,
        .adapted_input_until_publication_ns = if (source_job) |job| job.elapsed() else timer.read() + runtime_init_ns + asset_init_ns,
        .proof_sha256 = try publication.sha256File(request.output),
        .proof_bytes = proof_bytes,
        .verdict = output.verdict,
    };
    if (sink) |receiver| {
        phase = "deliver_verified_leaf";
        if (release_arena_for_sink) {
            var release_timer = try std.time.Timer.start();
            try runtime.releasePreparedExecution();
            resident_static.* = null;
            std.debug.print("cairo-cuda handoff prepared_arena_release_ns={}\n", .{release_timer.read()});
        }
        try receiver.receive(receiver.context, &diagnostic, &decoded, &capture, output.proof.structural.interactionNonce());
    }
    return receipt;
}

const Uploader = struct {
    session: *stwo.backend.runtime.NativeSession,

    pub fn uploadSlice(
        self: *Uploader,
        comptime F: type,
        destination: anytype,
        values: []const F,
    ) !void {
        if (destination.len != values.len)
            return error.InvalidIngressUploadExtent;
        try self.session.context.uploadSlice(F, destination, values);
    }
};

fn compileTarget(session: anytype) !stwo.backend.runtime
    .execution_plan.CompileOptions {
    const major = std.math.mul(u32, session.device.sm_major, 10) catch
        return error.InvalidDeviceArchitecture;
    const sm = std.math.add(u32, major, session.device.sm_minor) catch
        return error.InvalidDeviceArchitecture;
    return .{
        .sm = sm,
        .device_uuid = session.platform.uuid,
        .driver_version = session.platform.driver_version,
        .runtime_version = session.platform.runtime_version,
        .toolkit_version = session.platform.toolkit_version,
        .runtime_build_identity = session.build_identity,
        .host_toolchain_identity = session.build_identity,
        .kernel_pack_identity = session.build_identity,
        .lane_streams = 0,
        .enable_graphs = true,
    };
}

test {
    _ = cli;
    _ = stwo.executor.ingress.controller_bundle;
    _ = stwo.integration.canonical_source;
}
