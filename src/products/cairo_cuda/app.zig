//! Production Cairo CUDA CLI dispatch.

const std = @import("std");
const cli = @import("cli.zig");
const stwo = @import("stwo_cairo_cuda");

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

fn prove(
    allocator: std.mem.Allocator,
    request: cli.Prove,
) !void {
    var paths = try ResolvedPaths.init(allocator, request.input);
    defer paths.deinit();
    var runtime = try stwo.backend.runtime.NativeRuntime.open(&.{90});
    var runtime_live = true;
    defer if (runtime_live) runtime.abort() catch {};

    const target = try compileTarget(runtime.planningSession());
    var diagnostic = try stwo.integration.diagnostic_sn2
        .compileDiagnosticSn2(allocator, paths.artifacts(), target);
    defer diagnostic.deinit();
    if (diagnostic.request.missing_lowerings.len != 0)
        return error.IncompleteCairoCudaLowering;

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
    var controllers = try controllers_prepared.bindControllers(
        &transaction,
        provider,
        &diagnostic.request,
        diagnostic.protocol,
        diagnostic.composition,
    );
    defer controllers.deinit();
    _ = try controllers.initializeStatic(
        &transaction,
        provider,
        &diagnostic.request,
        .{
            .adapted_input = diagnostic.adapted_bytes,
            .forward_twiddles = twiddles.forwardWords(),
            .inverse_twiddles = twiddles.inverseWords(),
            .preprocessed_path = paths.preprocessed,
            .preprocessed_artifact_identity = diagnostic.digests.preprocessed_coefficients,
            .preprocessed_column_identities = diagnostic.fixed.preprocessed_identities,
        },
    );
    var registry = try stwo.backend.product_aot.Registry.initProduct(
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
    const statement = try controllers.bindStatement(
        allocator,
        &uploader,
        provider,
        &diagnostic.request,
    );
    const transcript = try controllers.transcriptBindings(
        statement,
        try stwo.executor.ingress.writer_binding.relationElements(
            provider,
            &diagnostic.request,
        ),
    );
    var proof = try stwo.executor.proof_session.Prepared.init(
        &diagnostic.request,
        diagnostic.protocol,
        controllers.sessionControllers(
            writers.writers(),
            writers.relation(),
        ),
        transcript,
    );
    _ = try proof.executeDevelopment(
        &transaction,
        &diagnostic.request.resident,
        diagnostic.protocol,
    );
    var output = try proof.finish(
        allocator,
        &transaction,
        &diagnostic.request.resident,
        diagnostic.protocol,
    );
    transaction_live = false;
    defer output.deinit(allocator);

    runtime_live = false;
    try runtime.close();
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

const ResolvedPaths = struct {
    allocator: std.mem.Allocator,
    composition: []u8,
    witness_programs: []u8,
    multiplicity_feeds: []u8,
    relation_templates: []u8,
    fixed_tables: []u8,
    preprocessed: []u8,
    adapted_input: []const u8,

    fn init(
        allocator: std.mem.Allocator,
        adapted_input: []const u8,
    ) !ResolvedPaths {
        if (!std.fs.path.isAbsolute(adapted_input))
            return error.InputPathNotAbsolute;
        const artifact_dir = std.process.getEnvVarOwned(
            allocator,
            "STWO_CAIRO_CUDA_ARTIFACT_DIR",
        ) catch |err| switch (err) {
            error.EnvironmentVariableNotFound => try allocator.dupe(
                u8,
                std.fs.path.dirname(adapted_input) orelse
                    return error.InvalidInputPath,
            ),
            else => return err,
        };
        defer allocator.free(artifact_dir);
        const preprocessed = try std.process.getEnvVarOwned(
            allocator,
            "STWO_CAIRO_CUDA_PREPROCESSED_COEFFICIENTS",
        );
        errdefer allocator.free(preprocessed);
        if (!std.fs.path.isAbsolute(artifact_dir) or
            !std.fs.path.isAbsolute(preprocessed))
        {
            return error.DiagnosticArtifactPathNotAbsolute;
        }
        const composition = try artifactPath(
            allocator,
            artifact_dir,
            "sn_pie_2_composition.bin",
        );
        errdefer allocator.free(composition);
        const witnesses = try artifactPath(
            allocator,
            artifact_dir,
            "sn_pie_2_witness_programs.bin",
        );
        errdefer allocator.free(witnesses);
        const feeds = try artifactPath(
            allocator,
            artifact_dir,
            "sn_pie_2_multiplicity_feeds.bin",
        );
        errdefer allocator.free(feeds);
        const relations = try artifactPath(
            allocator,
            artifact_dir,
            "cairo_relation_templates.bin",
        );
        errdefer allocator.free(relations);
        const fixed = try artifactPath(
            allocator,
            artifact_dir,
            "cairo_fixed_tables.bin",
        );
        errdefer allocator.free(fixed);
        return .{
            .allocator = allocator,
            .composition = composition,
            .witness_programs = witnesses,
            .multiplicity_feeds = feeds,
            .relation_templates = relations,
            .fixed_tables = fixed,
            .preprocessed = preprocessed,
            .adapted_input = adapted_input,
        };
    }

    fn deinit(self: *ResolvedPaths) void {
        self.allocator.free(self.preprocessed);
        self.allocator.free(self.fixed_tables);
        self.allocator.free(self.relation_templates);
        self.allocator.free(self.multiplicity_feeds);
        self.allocator.free(self.witness_programs);
        self.allocator.free(self.composition);
        self.* = undefined;
    }

    fn artifacts(
        self: *const ResolvedPaths,
    ) stwo.integration.diagnostic_sn2.ArtifactPaths {
        return .{
            .adapted_input = self.adapted_input,
            .composition = self.composition,
            .witness_programs = self.witness_programs,
            .multiplicity_feeds = self.multiplicity_feeds,
            .relation_templates = self.relation_templates,
            .fixed_tables = self.fixed_tables,
            .preprocessed_coefficients = self.preprocessed,
        };
    }
};

fn artifactPath(
    allocator: std.mem.Allocator,
    directory: []const u8,
    basename: []const u8,
) ![]u8 {
    return std.fs.path.join(allocator, &.{ directory, basename });
}

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
    _ = stwo.integration.diagnostic_sn2;
}
