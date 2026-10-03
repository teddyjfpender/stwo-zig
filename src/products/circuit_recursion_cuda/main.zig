//! Fully resident CUDA proving for a verified Cairo PIE, its leaf wrap, and
//! the recursive fold tree. The host builds verifier circuits and checks
//! published proofs; every Cairo and circuit STARK is proved on CUDA.
const std = @import("std");
const cairo_app = @import("cairo_cuda_app");
const circuit_app = @import("circuit_recursion_app");
const circuit_cpu = @import("stwo_circuit_cpu_integration");
const circuit_cuda = @import("stwo_circuit_cuda_integration");
const wire = @import("stwo_circuit_recursion_wire");
const sink = @import("verified_sink.zig");
const CampaignJob = @import("campaign_contract.zig").CampaignJob;

const max_file = 64 << 20;

pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    if (args.len < 2) return error.MissingCommand;
    if (std.mem.eql(u8, args[1], "leaf-wrap")) return leafWrap(allocator, args[2..]);
    if (std.mem.eql(u8, args[1], "leaf-wrap-batch")) return leafWrapBatch(allocator, args[2..]);
    if (std.mem.eql(u8, args[1], "leaf-wrap-campaign")) return leafWrapCampaign(allocator, args[2..]);
    if (std.mem.eql(u8, args[1], "fold-tree")) return foldTree(allocator, args[2..]);
    if (std.mem.eql(u8, args[1], "fold-stage")) return foldStage(allocator, args[2..], false);
    if (std.mem.eql(u8, args[1], "fold-stage-root")) return foldStage(allocator, args[2..], true);
    return error.UnknownCommand;
}

fn leafWrap(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var wall = try std.time.Timer.start();
    const registry = try flag(args, "--registry");
    const program = try flag(args, "--program");
    const input = try flag(args, "--input");
    const leaf_path = try flag(args, "--output");
    const cairo_proof = try flag(args, "--cairo-proof");
    const cairo_report = try flag(args, "--cairo-report");
    var prefetch = cairo_app.PrefetchJob{ .allocator = allocator, .path = "" };
    try prefetch.startFromEnvironment();
    defer prefetch.deinit();
    var catalog = try circuit_cuda.air_aot.build(allocator, try circuit_app.authenticatedAirPrograms());
    defer catalog.deinit();
    const catalog_ns = wall.lap();
    var backend = circuit_cuda.recursion_source.Context{ .catalog = &catalog };
    var receiver = sink.Context{
        .allocator = allocator,
        .request = .{
            .registry_path = registry,
            .program_path = program,
            .prover_input_path = input,
            .source = backend.source(),
        },
        .output_path = leaf_path,
    };
    var total = try std.time.Timer.start();
    try cairo_app.proveWithSinkUsingPrefetch(allocator, .{
        .input = input,
        .output = cairo_proof,
        .report_out = cairo_report,
        .repeat = 1,
        .circuit_registry = registry,
    }, receiver.sink(), &prefetch);
    if (!receiver.delivered) return error.MissingVerifiedCairoLeaf;
    std.debug.print("circuit-cuda leaf-wrap total_ns={} wrap_ns={} proof={s}\n", .{ total.read(), receiver.wrap_ns, leaf_path });
    std.debug.print("circuit-cuda leaf-wrap setup_ns={} execution_ns={}\n", .{ catalog_ns, wall.lap() });
}

const BatchManifestItem = struct {
    registry: []const u8,
    program: []const u8,
    input: []const u8,
    output: []const u8,
    cairo_proof: []const u8,
    cairo_report: []const u8,
    /// Decimal felt strings for an optional in-process root reduction.
    output_preimage: ?[]const []const u8 = null,
};

/// A bounded sequence of independent roots in one long-lived CUDA process.
/// The static Cairo image, AIR catalog, and authenticated leaf topology are
/// shared; each job gets its own manifest arena, proofs, and output paths.
fn leafWrapCampaign(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const jobs_path = try flag(args, "--jobs");
    const jobs = try std.json.parseFromSlice([]CampaignJob, a, try readFile(a, jobs_path), .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    if (jobs.value.len == 0 or jobs.value.len > 256) return error.InvalidCampaignSize;
    const first_job = jobs.value[0];
    const first_manifest = try std.json.parseFromSlice([]BatchManifestItem, a, try readFile(a, first_job.manifest), .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    if (first_manifest.value.len == 0 or first_manifest.value.len > 256) return error.InvalidBatchSize;
    const first = first_manifest.value[0];
    // An operator may trade one authenticated 2.17 GB host snapshot for
    // avoiding fixed-asset reads between separate roots. This stays inside
    // the same process and scoring clock; default release is memory-bounded.
    const retain_setting = std.process.getEnvVarOwned(allocator, "STWO_CAIRO_CUDA_RETAIN_FIXED_HOST") catch null;
    defer if (retain_setting) |value| allocator.free(value);
    const retain_fixed_host = retain_setting != null and std.mem.eql(u8, retain_setting.?, "1");
    var prefetch = cairo_app.PrefetchJob{ .allocator = allocator, .path = "" };
    try prefetch.startFromEnvironment();
    var prefetch_live = true;
    defer if (prefetch_live) prefetch.deinit();
    var catalog = try circuit_cuda.air_aot.build(allocator, try circuit_app.authenticatedAirPrograms());
    defer catalog.deinit();
    var runtime = try circuit_cuda.recursion_source.Runtime.open(&.{ 80, 90 });
    var runtime_live = true;
    defer if (runtime_live) runtime.abort() catch {};
    var cairo_session = cairo_app.BatchSession{ .allocator = allocator, .runtime = &runtime, .early_prefetch = &prefetch };
    var cairo_session_live = true;
    defer if (cairo_session_live) cairo_session.deinit() catch {};
    var backend = circuit_cuda.recursion_source.Context{ .catalog = &catalog, .runtime = &runtime };
    var shared = try circuit_app.VerifiedLeafSession.init(allocator, .{
        .registry_path = first.registry,
        .program_path = first.program,
        .prover_input_path = first.input,
        .source = backend.source(),
    });
    defer shared.deinit();
    for (jobs.value, 0..) |job, index| {
        try job.validate();
        var job_arena = std.heap.ArenaAllocator.init(allocator);
        defer job_arena.deinit();
        const job_a = job_arena.allocator();
        const parsed = try std.json.parseFromSlice([]BatchManifestItem, job_a, try readFile(job_a, job.manifest), .{
            .allocate = .alloc_always,
            .ignore_unknown_fields = false,
        });
        if (parsed.value.len == 0 or parsed.value.len > 256) return error.InvalidBatchSize;
        const compact = std.mem.eql(u8, job.root_mode, "compact");
        const integrated = job.root_proof != null;
        var timer = try std.time.Timer.start();
        try runOneBatch(allocator, job_a, parsed.value, job.root_proof, job.root_outputs, job.root_packed, compact, &backend, &shared, &cairo_session, 0, retain_fixed_host);
        if (index == 0 and !retain_fixed_host) {
            cairo_session.early_prefetch = null;
            prefetch.deinit();
            prefetch_live = false;
        }
        std.debug.print("circuit-cuda campaign-job index={} wall_ns={} mode={s}\n", .{
            index, timer.read(), if (integrated) "integrated-root" else "leaves-only",
        });
    }
    try cairo_session.deinit();
    cairo_session_live = false;
    try runtime.close();
    runtime_live = false;
}

fn leafWrapBatch(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var wall = try std.time.Timer.start();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const manifest_path = try flag(args, "--manifest");
    const root_proof_path = optionalFlag(args, "--root-proof");
    const root_outputs_path = optionalFlag(args, "--root-outputs");
    const root_packed_path = optionalFlag(args, "--root-packed");
    const integrated = root_proof_path != null;
    if (integrated != (root_outputs_path != null) or integrated != (root_packed_path != null))
        return error.IncompleteRootOutputPaths;
    const root_mode = optionalFlag(args, "--root-mode") orelse "canonical";
    const compact_root = std.mem.eql(u8, root_mode, "compact");
    if (!std.mem.eql(u8, root_mode, "canonical") and !compact_root) return error.InvalidRootMode;
    if (compact_root and !integrated) return error.CompactRootRequiresIntegratedFold;
    const parsed = try std.json.parseFromSlice([]BatchManifestItem, a, try readFile(a, manifest_path), .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    if (parsed.value.len == 0 or parsed.value.len > 256) return error.InvalidBatchSize;
    var prefetch = cairo_app.PrefetchJob{ .allocator = allocator, .path = "" };
    try prefetch.startFromEnvironment();
    defer prefetch.deinit();
    var catalog = try circuit_cuda.air_aot.build(allocator, try circuit_app.authenticatedAirPrograms());
    defer catalog.deinit();
    var runtime = try circuit_cuda.recursion_source.Runtime.open(&.{ 80, 90 });
    var runtime_live = true;
    defer if (runtime_live) runtime.abort() catch {};
    var cairo_session = cairo_app.BatchSession{ .allocator = allocator, .runtime = &runtime, .early_prefetch = &prefetch };
    var cairo_session_live = true;
    defer if (cairo_session_live) cairo_session.deinit() catch {};
    var backend = circuit_cuda.recursion_source.Context{ .catalog = &catalog, .runtime = &runtime };
    const first = parsed.value[0];
    for (parsed.value[1..]) |entry| {
        if (!std.mem.eql(u8, entry.registry, first.registry) or
            !std.mem.eql(u8, entry.program, first.program))
            return error.MixedLeafPrograms;
    }
    var shared = try circuit_app.VerifiedLeafSession.init(allocator, .{
        .registry_path = first.registry,
        .program_path = first.program,
        .prover_input_path = first.input,
        .source = backend.source(),
    });
    defer shared.deinit();
    const setup_ns = wall.lap();
    try runOneBatch(allocator, a, parsed.value, root_proof_path, root_outputs_path, root_packed_path, compact_root, &backend, &shared, &cairo_session, setup_ns, false);
    try cairo_session.deinit();
    cairo_session_live = false;
    try runtime.close();
    runtime_live = false;
}

fn runOneBatch(
    allocator: std.mem.Allocator,
    a: std.mem.Allocator,
    entries: []const BatchManifestItem,
    root_proof_path: ?[]const u8,
    root_outputs_path: ?[]const u8,
    root_packed_path: ?[]const u8,
    compact_root: bool,
    backend: *circuit_cuda.recursion_source.Context,
    shared: *circuit_app.VerifiedLeafSession,
    cairo_session: *cairo_app.BatchSession,
    setup_ns: u64,
    retain_fixed_host: bool,
) !void {
    const integrated = root_proof_path != null;
    const first = entries[0];
    for (entries[1..]) |entry| {
        if (!std.mem.eql(u8, entry.registry, first.registry) or
            !std.mem.eql(u8, entry.program, first.program)) return error.MixedLeafPrograms;
    }
    if (!std.mem.eql(u8, first.registry, shared.request.registry_path) or
        !std.mem.eql(u8, first.program, shared.request.program_path)) return error.MixedLeafPrograms;
    const receivers = try a.alloc(sink.Context, entries.len);
    const items = try a.alloc(cairo_app.BatchItem, entries.len);
    for (entries, receivers, items) |entry, *receiver, *item| {
        receiver.* = .{
            .allocator = allocator,
            .request = .{
                .registry_path = entry.registry,
                .program_path = entry.program,
                .prover_input_path = entry.input,
                .source = backend.source(),
            },
            .output_path = entry.output,
            .shared_session = shared,
        };
        item.* = .{
            .request = .{
                .input = entry.input,
                .output = entry.cairo_proof,
                .report_out = entry.cairo_report,
                .repeat = 1,
                .circuit_registry = entry.registry,
            },
            .sink = receiver.sink(),
        };
    }
    var total = try std.time.Timer.start();
    try cairo_app.proveBatchWithSinksUsingSession(allocator, items, cairo_session);
    // The verified static receipt is enough after Cairo. Drop the 2.17 GB
    // host snapshot before parsing leaves or running the integrated fold.
    if (!retain_fixed_host) {
        if (cairo_session.early_prefetch) |prefetch| {
            prefetch.releaseSnapshot();
            cairo_session.early_prefetch = null;
        }
    }
    for (receivers, 0..) |receiver, index| {
        if (!receiver.delivered) return error.MissingVerifiedCairoLeaf;
        std.debug.print("circuit-cuda batch-leaf index={} wrap_ns={} proof={s}\n", .{
            index, receiver.wrap_ns, receiver.output_path,
        });
    }
    const leaves_ns = total.read();
    std.debug.print("circuit-cuda leaf-wrap-batch leaves={} total_ns={}\n", .{ receivers.len, leaves_ns });
    if (integrated) {
        const leaves = try a.alloc(wire.leaf_proof_json.LeafInput, entries.len);
        const parsed_proofs = try a.alloc(wire.leaf_proof_json.Owned(wire.leaf_proof_json.SerializedLeafProof), entries.len);
        var parsed_count: usize = 0;
        defer for (parsed_proofs[0..parsed_count]) |*proof| proof.deinit();
        for (entries, leaves, parsed_proofs) |entry, *leaf, *proof| {
            const preimage = entry.output_preimage orelse return error.MissingRootPreimage;
            proof.* = try wire.leaf_proof_json.parseSerializedLeafProof(allocator, try readFile(a, entry.output));
            parsed_count += 1;
            leaf.* = .{ .proof = proof.value, .output_preimage = preimage };
        }
        var parsed_registry = try wire.registry.parseRegistry(a, try readFile(a, first.registry));
        defer parsed_registry.deinit();
        var fold_timer = try std.time.Timer.start();
        var files = try circuit_app.foldTreeWithSourceMode(
            allocator,
            parsed_registry.registry,
            leaves,
            &circuit_cpu.prove.cpu_provers,
            null,
            backend.source(),
            compact_root,
        );
        defer files.deinit();
        const fold_ns = fold_timer.read();
        try std.fs.cwd().writeFile(.{ .sub_path = root_proof_path.?, .data = files.proof.written() });
        try std.fs.cwd().writeFile(.{ .sub_path = root_outputs_path.?, .data = files.outputs.written() });
        try std.fs.cwd().writeFile(.{ .sub_path = root_packed_path.?, .data = files.packed_tree.written() });
        std.debug.print("circuit-cuda integrated-fold leaves={} reductions={} fold_ns={} proof_bytes={}\n", .{
            files.stats.n_leaves, files.stats.n_pair_reductions, fold_ns, files.proof.written().len,
        });
    }
    std.debug.print("circuit-cuda leaf-wrap-batch setup_ns={} execution_ns={} cache_hits={} cache_misses={}\n", .{
        setup_ns, leaves_ns, shared.cache.stats.hits, shared.cache.stats.misses,
    });
}

fn foldTree(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var wall = try std.time.Timer.start();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const registry_path = try flag(args, "--registry");
    const manifest_path = try flag(args, "--manifest");
    const proof_path = try flag(args, "--proof");
    const outputs_path = try flag(args, "--outputs");
    const packed_path = try flag(args, "--packed");
    const root_mode = optionalFlag(args, "--root-mode") orelse "canonical";
    const compact_root = std.mem.eql(u8, root_mode, "compact");
    if (!std.mem.eql(u8, root_mode, "canonical") and !compact_root) return error.InvalidRootMode;
    const parsed_registry = try wire.registry.parseRegistry(a, try readFile(a, registry_path));
    const manifest = try wire.leaf_proof_json.parseLeavesManifest(a, try readFile(a, manifest_path));
    const leaves = try a.alloc(wire.leaf_proof_json.LeafInput, manifest.value.len);
    for (leaves, manifest.value) |*leaf, path| {
        const parsed = try wire.leaf_proof_json.parseLeafInput(a, try readFile(a, path));
        leaf.* = parsed.value;
    }
    const parse_ns = wall.lap();
    var catalog = try circuit_cuda.air_aot.build(allocator, try circuit_app.authenticatedAirPrograms());
    defer catalog.deinit();
    const catalog_ns = wall.lap();
    var runtime = try circuit_cuda.recursion_source.Runtime.open(&.{ 80, 90 });
    var runtime_live = true;
    defer if (runtime_live) runtime.abort() catch {};
    var backend = circuit_cuda.recursion_source.Context{ .catalog = &catalog, .runtime = &runtime };
    var timer = try std.time.Timer.start();
    var files = try circuit_app.foldTreeWithSourceMode(
        allocator,
        parsed_registry.registry,
        leaves,
        &circuit_cpu.prove.cpu_provers,
        null,
        backend.source(),
        compact_root,
    );
    defer files.deinit();
    try runtime.close();
    runtime_live = false;
    const fold_ns = timer.read();
    try std.fs.cwd().writeFile(.{ .sub_path = proof_path, .data = files.proof.written() });
    try std.fs.cwd().writeFile(.{ .sub_path = outputs_path, .data = files.outputs.written() });
    try std.fs.cwd().writeFile(.{ .sub_path = packed_path, .data = files.packed_tree.written() });
    std.debug.print("circuit-cuda fold-tree leaves={} reductions={} prove_ns={} proof_bytes={}\n", .{
        files.stats.n_leaves, files.stats.n_pair_reductions, fold_ns, files.proof.written().len,
    });
    std.debug.print("circuit-cuda fold-tree parse_ns={} catalog_ns={} fold_ns={} publish_ns={}\n", .{
        parse_ns, catalog_ns, fold_ns, wall.lap() - fold_ns,
    });
}

fn foldStage(allocator: std.mem.Allocator, args: []const []const u8, terminal_root: bool) !void {
    var wall = try std.time.Timer.start();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const registry_path = try flag(args, "--registry");
    const manifest_path = try flag(args, "--manifest");
    const checkpoint_path = if (terminal_root) null else try flag(args, "--checkpoint");
    const proof_path = if (terminal_root) try flag(args, "--proof") else null;
    const outputs_path = if (terminal_root) try flag(args, "--outputs") else null;
    const packed_path = if (terminal_root) try flag(args, "--packed") else null;
    const registry = try wire.registry.parseRegistry(a, try readFile(a, registry_path));
    const inputs = try circuit_app.loadStageInputs(a, manifest_path);
    const parse_ns = wall.lap();
    var catalog = try circuit_cuda.air_aot.build(allocator, try circuit_app.authenticatedAirPrograms());
    defer catalog.deinit();
    var runtime = try circuit_cuda.recursion_source.Runtime.open(&.{ 80, 90 });
    var runtime_live = true;
    defer if (runtime_live) runtime.abort() catch {};
    var backend = circuit_cuda.recursion_source.Context{ .catalog = &catalog, .runtime = &runtime };
    var files = try circuit_app.foldStageWithSource(
        allocator,
        registry.registry,
        inputs,
        &circuit_cpu.prove.cpu_provers,
        backend.source(),
        terminal_root,
    );
    defer files.deinit();
    try runtime.close();
    runtime_live = false;
    const prove_ns = wall.lap();
    if (terminal_root) {
        try std.fs.cwd().writeFile(.{ .sub_path = proof_path.?, .data = files.proof.written() });
        try std.fs.cwd().writeFile(.{ .sub_path = outputs_path.?, .data = files.outputs.written() });
        try std.fs.cwd().writeFile(.{ .sub_path = packed_path.?, .data = files.packed_tree.written() });
    } else {
        try std.fs.cwd().writeFile(.{ .sub_path = checkpoint_path.?, .data = files.checkpoint.written() });
    }
    std.debug.print("circuit-cuda fold-stage mode={s} entries={} reductions={} parse_ns={} prove_ns={} publish_ns={}\n", .{
        if (terminal_root) "root" else "internal", inputs.len, files.stats.n_pair_reductions,
        parse_ns,                                  prove_ns,   wall.lap(),
    });
}

fn flag(args: []const []const u8, name: []const u8) ![]const u8 {
    if (args.len % 2 != 0) return error.InvalidArguments;
    for (0..args.len / 2) |index| {
        const key = args[index * 2];
        if (std.mem.eql(u8, key, name)) return args[index * 2 + 1];
    }
    return error.MissingArgument;
}

fn optionalFlag(args: []const []const u8, name: []const u8) ?[]const u8 {
    if (args.len % 2 != 0) return null;
    for (0..args.len / 2) |index| {
        if (std.mem.eql(u8, args[index * 2], name)) return args[index * 2 + 1];
    }
    return null;
}

fn readFile(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    return std.fs.cwd().readFileAlloc(allocator, path, max_file);
}

test "resident pipeline command requires an explicit source" {
    try std.testing.expectError(error.MissingArgument, flag(&.{ "--input", "x" }, "--registry"));
}
