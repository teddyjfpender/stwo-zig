//! Explicit pinned real-window benchmark, inactive unless requested. Input
//! loading and proof/verification are distinct. No skipped-prefix claim.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Run = @import("../block_v8_endpoint_local_compact_execution_v1.zig");
fn number(comptime T: type, name: [:0]const u8, default: T) !T {
    return std.fmt.parseInt(T, std.posix.getenv(name) orelse return default, 10);
}
fn digest(name: [:0]const u8) ![32]u8 {
    var result: [32]u8 = undefined;
    const text = std.posix.getenv(name) orelse return error.MissingEndpointBenchmarkPin;
    if (text.len != 64) return error.InvalidEndpointBenchmarkPin;
    _ = try std.fmt.hexToBytes(&result, text);
    return result;
}
test "real clean local compact pipeline performance benchmark" {
    if (std.posix.getenv("STWO_B8_LOCAL_ENABLE") == null) return error.SkipZigTest;
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 48 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var whole = try std.time.Timer.start();
    var timer = try std.time.Timer.start();
    const elf = try std.fs.cwd().readFileAlloc(a, std.posix.getenv("STWO_B8_LOCAL_ELF") orelse return error.MissingEndpointBenchmarkInput, 32 << 20);
    defer a.free(elf);
    const incoming_bytes = try std.fs.cwd().readFileAlloc(a, std.posix.getenv("STWO_B8_LOCAL_INCOMING") orelse return error.MissingEndpointBenchmarkInput, 256 << 20);
    defer a.free(incoming_bytes);
    const outgoing_bytes = try std.fs.cwd().readFileAlloc(a, std.posix.getenv("STWO_B8_LOCAL_OUTGOING") orelse return error.MissingEndpointBenchmarkInput, 256 << 20);
    defer a.free(outgoing_bytes);
    const incoming_pin = try digest("STWO_B8_LOCAL_INCOMING_SHA256");
    const outgoing_pin = try digest("STWO_B8_LOCAL_OUTGOING_SHA256");
    var incoming = try Capture.Snapshot.decode(a, incoming_bytes, incoming_pin, .{});
    defer incoming.deinit(a);
    var outgoing = try Capture.Snapshot.decode(a, outgoing_bytes, outgoing_pin, .{});
    defer outgoing.deinit(a);
    const loading_ns = timer.lap();
    const workers = try number(usize, "STWO_B8_LOCAL_WORKERS", 8);
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = workers, .backing_allocator = a });
    defer pool.deinit();
    const span = Capture.Window{ .skip_cycles = try number(u64, "STWO_B8_LOCAL_SKIP", 0), .cycles = try number(u32, "STWO_B8_LOCAL_CYCLES", 1 << 22) };
    const elf_pin = try digest("STWO_B8_LOCAL_ELF_SHA256");
    var full_boundary = try @import("../block_v8_full_boundary_policy_v1.zig").fromEnvironment(a, elf, elf_pin, @import("../../recursion/blake3_execution_parent_protocol.zig").CSP_CONFIG);
    defer if (full_boundary) |*full| full.deinit();
    const boundary = if (full_boundary) |*full| try full.windowOptions(span.skip_cycles, span.cycles) else @import("../block_v8_execution_boundary_ports_v1.zig").Options{};
    var output = try std.fs.cwd().openDir(std.posix.getenv("STWO_B8_LOCAL_OUTPUT") orelse return error.MissingEndpointBenchmarkOutput, .{});
    defer output.close();
    try output.makeDir("artifacts");
    var artifacts = try output.openDir("artifacts", .{ .iterate = true });
    defer artifacts.close();
    var producer_call = try std.time.Timer.start();
    const result = try Run.run(budget, &pool, artifacts, .{ .elf = elf, .elf_sha256 = elf_pin, .config = @import("../../recursion/blake3_execution_parent_protocol.zig").CSP_CONFIG, .incoming = incoming, .outgoing = outgoing, .trusted_window = .{ .elf_sha256 = elf_pin, .incoming_sha256 = incoming_pin, .outgoing_sha256 = outgoing_pin, .window = span } }, .{ .boundary = boundary, .program_flavor = if (try number(u32, "STWO_B8_LOCAL_SPARSE_ROM", 0) != 0) .sparse_elf else .legacy_complete, .cohort_cycles = try number(u32, "STWO_B8_LOCAL_COHORT_CYCLES", 1 << 17), .parallel_local_proofs = try number(u32, "STWO_B8_LOCAL_PARALLEL_PROOFS", 1), .proof_workers = workers });
    defer result.deinit();
    const producer_call_ns = producer_call.read();
    const config = result.global_memory.stark.commitment_scheme_proof.config;
    const Artifact = struct { name: []const u8, bytes: u64, sha256: [64]u8 };
    var manifest: std.ArrayList(Artifact) = .empty;
    defer {
        for (manifest.items) |entry| a.free(entry.name);
        manifest.deinit(a);
    }
    var entries = artifacts.iterate();
    while (try entries.next()) |entry| {
        if (entry.kind != .file) return error.UnexpectedEndpointArtifactEntry;
        const bytes = try artifacts.readFileAlloc(a, entry.name, 128 << 20);
        defer a.free(bytes);
        const name = try a.dupe(u8, entry.name);
        errdefer a.free(name);
        try manifest.append(a, .{ .name = name, .bytes = bytes.len, .sha256 = std.fmt.bytesToHex(Capture.sha(bytes), .lower) });
    }
    const Ordering = struct {
        fn less(_: void, left: Artifact, right: Artifact) bool {
            return std.mem.lessThan(u8, left.name, right.name);
        }
    };
    std.mem.sort(Artifact, manifest.items, {}, Ordering.less);
    const report = try std.json.Stringify.valueAlloc(a, .{
        .schema = "stwo-b8-local-endpoint-compact-global-pipeline-benchmark-v1",
        .full_boundary_digest = if (full_boundary) |full| @as(?[32]u8, full.digest) else null,
        .boundary = boundary,
        .initial_boundary = boundary.initial != null,
        .terminal_boundary = boundary.terminal != null,
        .scope = if (boundary.terminal != null) "declared terminal native-only window; RAM-authenticated halt and expected output; not a complete block until initial-to-terminal root closure" else "declared nonterminal native-only window; separately verified local+bridge+compact-global originals; not a single recursive root, skipped-prefix proof or complete Ethereum block",
        .security_queries = config.fri_config.n_queries,
        .security_pow_bits = config.pow_bits,
        .program_flavor = result.stats.program_flavor,
        .layout_version = @import("../block_v8_native_endpoint_layout_v1.zig").VERSION,
        .window = span,
        .workers = workers,
        .cohort_policy = result.cohort_policy,
        .loading_ns = loading_ns,
        .producer_call_ns = producer_call_ns,
        .stats = result.stats,
        .artifacts = manifest.items,
        .charged_peak_including_publication_bytes = budget.snapshot().peak_live_bytes,
        .whole_including_loading_and_publication_ns = whole.read(),
        .verified = result.verified,
    }, .{ .whitespace = .indent_2 });
    defer a.free(report);
    try output.writeFile(.{ .sub_path = "report.json", .data = report });
}
