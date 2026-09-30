//! Production Cairo CUDA CLI dispatch.

const std = @import("std");
const cli = @import("cli.zig");
const stwo = @import("stwo_cairo_cuda");
const publication = @import("publication.zig");
const ResidentStatic = struct {
    arena_key: [32]u8,
    receipt: stwo.executor.preprocessed_cache.Receipt,
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
    var receipts = std.ArrayList(publication.Receipt).empty;
    defer receipts.deinit(allocator);
    const executable = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(executable);
    const executable_digest = try publication.sha256File(executable);
    var startup = try std.time.Timer.start();
    const accepted_sms = try stwo.backend.runtime.device_admission.parseArchitectures(allocator, @import("cuda_architectures").architectures);
    defer allocator.free(accepted_sms);
    var runtime = try stwo.backend.runtime.NativeRuntime.open(accepted_sms);
    var runtime_live = true;
    defer if (runtime_live) runtime.abort() catch {};
    const runtime_init_ns = startup.read();
    var expected_digest: ?[32]u8 = null;
    var resident_static: ?ResidentStatic = null;
    for (0..request.repeat) |index| {
        const receipt = try proveOnce(allocator, &runtime, &resident_static, request, executable_digest, @intCast(index + 1), if (index == 0) runtime_init_ns else 0);
        if (expected_digest) |expected| {
            if (!std.mem.eql(u8, &expected, &receipt.proof_sha256)) return error.NondeterministicCairoCudaProof;
        } else expected_digest = receipt.proof_sha256;
        try receipts.append(allocator, receipt);
        try publication.writeReport(request.report_out, receipts.items);
    }
    var teardown = try std.time.Timer.start();
    try runtime.close();
    runtime_live = false;
    try publication.writeFinalReport(request.report_out, receipts.items, teardown.read());
}

fn proveOnce(
    allocator: std.mem.Allocator,
    runtime: *stwo.backend.runtime.NativeRuntime,
    resident_static: *?ResidentStatic,
    request: cli.Prove,
    executable_digest: [32]u8,
    index: u32,
    runtime_init_ns: u64,
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
    var diagnostic = try stwo.integration.canonical_source.prepare(allocator, paths.source, target);
    defer diagnostic.deinit();
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
            .resident_preprocessed = cached_preprocessed,
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
    var decoded = try stwo.integration.canonical_verify.verifyAndDecode(allocator, &diagnostic, output.proof);
    defer decoded.deinit(allocator);
    phase = "publish_official_proof";
    const proof_bytes = try publication.writeCanonicalProof(request.output, &diagnostic, &decoded, output.proof.structural.interactionNonce());
    return .{
        .index = index,
        .protocol = diagnostic.protocol,
        .input_sha256 = diagnostic.input_sha256,
        .executable_sha256 = executable_digest,
        .planned_arena_bytes = @as(u64, arena_plan.total_words) * 4,
        .prepared_arena_reused = arena_reused,
        .preprocessed_reused = cached_preprocessed != null,
        .ingress_ns = ingress_ns + runtime_init_ns,
        .ingress_timings = .{
            .paths_ns = paths_end_ns,
            .runtime_ns = runtime_init_ns + runtime_end_ns - paths_end_ns,
            .source_ns = source_end_ns - runtime_end_ns,
            .controllers_ns = controllers_end_ns - source_end_ns,
            .twiddles_ns = twiddles_end_ns - controllers_end_ns,
            .allocation_ns = allocation_end_ns - twiddles_end_ns,
            .binding_ns = binding_end_ns - allocation_end_ns,
            .static_ns = static_end_ns - binding_end_ns,
            .writers_ns = writers_end_ns - static_end_ns,
            .statement_and_session_ns = ingress_ns - writers_end_ns,
        },
        .proof_execute_and_decode_ns = proof_end_ns - ingress_ns,
        .adapted_input_until_publication_ns = timer.read() + runtime_init_ns,
        .proof_sha256 = try publication.sha256File(request.output),
        .proof_bytes = proof_bytes,
        .verdict = output.verdict,
    };
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
