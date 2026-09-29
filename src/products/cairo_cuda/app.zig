//! Production Cairo CUDA CLI dispatch.

const std = @import("std");
const cli = @import("cli.zig");
const stwo = @import("stwo_cairo_cuda");
const publication = @import("publication.zig");

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
    var expected_digest: ?[32]u8 = null;
    for (0..request.repeat) |index| {
        const receipt = try proveOnce(allocator, request, executable_digest, @intCast(index + 1));
        if (expected_digest) |expected| {
            if (!std.mem.eql(u8, &expected, &receipt.proof_sha256)) return error.NondeterministicCairoCudaProof;
        } else expected_digest = receipt.proof_sha256;
        try receipts.append(allocator, receipt);
        try publication.writeReport(request.report_out, receipts.items);
    }
}

fn proveOnce(
    allocator: std.mem.Allocator,
    request: cli.Prove,
    executable_digest: [32]u8,
    index: u32,
) !publication.Receipt {
    var timer = try std.time.Timer.start();
    var phase: []const u8 = "resolve_input";
    errdefer |err| std.debug.print("cairo-cuda phase={s} failed: {s}\n", .{ phase, @errorName(err) });
    var paths = try @import("canonical_paths.zig").Paths.init(allocator, request.input);
    defer paths.deinit();
    phase = "open_runtime";
    const accepted_sms = try stwo.backend.runtime.device_admission.parseArchitectures(allocator, @import("cuda_architectures").architectures);
    defer allocator.free(accepted_sms);
    var runtime = try stwo.backend.runtime.NativeRuntime.open(accepted_sms);
    var runtime_live = true;
    defer if (runtime_live) runtime.abort() catch {};

    phase = "compile_canonical_source";
    const target = try compileTarget(runtime.planningSession());
    var diagnostic = try stwo.integration.canonical_source.prepare(allocator, paths.source, target);
    defer diagnostic.deinit();
    if (diagnostic.request.missing_lowerings.len != 0)
        return error.IncompleteCairoCudaLowering;

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
    var twiddles = try stwo.executor.canonical_twiddles.Pack.init(
        allocator,
        &diagnostic.request.resident,
    );
    defer twiddles.deinit();

    const arena_plan = try controllers_prepared.resident.combined_arena.clone(
        allocator,
    );
    std.debug.print("cairo-cuda arena reservation bytes={} slots={}\n", .{ arena_plan.total_words * 4, arena_plan.placements.len });
    for (arena_plan.placements) |placement| {
        if (placement.requirement.words >= 1 << 24) std.debug.print("cairo-cuda arena slot={} bytes={} offset={} lifetime={s}..{s}\n", .{ placement.requirement.id, placement.requirement.words * 4, placement.offset_words * 4, @tagName(placement.requirement.live_from), @tagName(placement.requirement.live_through) });
    }
    phase = "allocate_arena";
    const session = try runtime.beginProof();
    var transaction = try stwo.backend.runtime.proof_transaction
        .ResidentProofTransaction.openPreparedRetained(
        allocator,
        session,
        arena_plan,
    );
    var transaction_live = true;
    defer if (transaction_live) transaction.abort() catch {};

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
    phase = "initialize_static";
    _ = try controllers.initializeStatic(
        &transaction,
        provider,
        &diagnostic.request,
        .{
            .adapted_input = diagnostic.adapted_bytes,
            .forward_twiddles = twiddles.forwardWords(),
            .inverse_twiddles = twiddles.inverseWords(),
            .preprocessed_path = paths.preprocessed,
            .preprocessed_artifact_identity = paths.preprocessed_identity,
            .preprocessed_column_identities = diagnostic.fixed.preprocessed_identities,
        },
    );
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

    phase = "close_runtime";
    try runtime.close();
    runtime_live = false;
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
        .ingress_ns = ingress_ns,
        .proof_execute_and_decode_ns = proof_end_ns - ingress_ns,
        .adapted_input_until_publication_ns = timer.read(),
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
