//! Explicit pinned full Group/bridge/compact-global ORIGINAL bundle benchmark.
const std = @import("std");
const E = @import("stwo_prover_engine");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Run = @import("../block_v8_endpoint_group_pipeline_v1.zig");
fn number(comptime T: type, name: [:0]const u8, default: T) !T {
    return std.fmt.parseInt(T, std.posix.getenv(name) orelse return default, 10);
}
fn digest(name: [:0]const u8) ![32]u8 {
    var result: [32]u8 = undefined;
    const text = std.posix.getenv(name) orelse return error.MissingGroupBenchmarkPin;
    if (text.len != 64) return error.InvalidGroupBenchmarkPin;
    _ = try std.fmt.hexToBytes(&result, text);
    return result;
}
test "real shared group complete original bundle performance benchmark" {
    if (std.posix.getenv("STWO_B8_GROUP_BUNDLE_ENABLE") == null) return error.SkipZigTest;
    const profile: @import("../block_v8_endpoint_group_layout_v1.zig").Profile = if (std.posix.getenv("STWO_B8_GROUP_BUNDLE_NATIVE_WIDE") != null) .native_wide_v2 else .compact_v1;
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, try number(usize, "STWO_B8_GROUP_BUNDLE_BUDGET_BYTES", 48 << 30));
    defer budget.destroy();
    const a = budget.allocator();
    var whole = try std.time.Timer.start();
    var timer = try std.time.Timer.start();
    const elf = try std.fs.cwd().readFileAlloc(a, std.posix.getenv("STWO_B8_GROUP_BUNDLE_ELF") orelse return error.MissingGroupBenchmarkInput, 32 << 20);
    defer a.free(elf);
    const incoming_bytes = try std.fs.cwd().readFileAlloc(a, std.posix.getenv("STWO_B8_GROUP_BUNDLE_INCOMING") orelse return error.MissingGroupBenchmarkInput, 256 << 20);
    defer a.free(incoming_bytes);
    const outgoing_bytes = try std.fs.cwd().readFileAlloc(a, std.posix.getenv("STWO_B8_GROUP_BUNDLE_OUTGOING") orelse return error.MissingGroupBenchmarkInput, 256 << 20);
    defer a.free(outgoing_bytes);
    const incoming_pin = try digest("STWO_B8_GROUP_BUNDLE_INCOMING_SHA256");
    const outgoing_pin = try digest("STWO_B8_GROUP_BUNDLE_OUTGOING_SHA256");
    const elf_pin = try digest("STWO_B8_GROUP_BUNDLE_ELF_SHA256");
    var incoming = try Capture.Snapshot.decode(a, incoming_bytes, incoming_pin, .{});
    defer incoming.deinit(a);
    var outgoing = try Capture.Snapshot.decode(a, outgoing_bytes, outgoing_pin, .{});
    defer outgoing.deinit(a);
    const loading_ns = timer.lap();
    const workers = try number(usize, "STWO_B8_GROUP_BUNDLE_WORKERS", 8);
    var pool: E.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = workers, .backing_allocator = a });
    defer pool.deinit();
    const span = Capture.Window{ .skip_cycles = try number(u64, "STWO_B8_GROUP_BUNDLE_SKIP", 0), .cycles = try number(u32, "STWO_B8_GROUP_BUNDLE_CYCLES", 1 << 22) };
    const cohort_cycles = try number(u32, "STWO_B8_GROUP_BUNDLE_COHORT_CYCLES", 1 << 19);
    var output = try std.fs.cwd().openDir(std.posix.getenv("STWO_B8_GROUP_BUNDLE_OUTPUT") orelse return error.MissingGroupBenchmarkOutput, .{});
    defer output.close();
    try output.makeDir("artifacts");
    var artifacts = try output.openDir("artifacts", .{ .iterate = true });
    defer artifacts.close();
    var call = try std.time.Timer.start();
    const result = try Run.run(budget, &pool, artifacts, .{ .elf = elf, .elf_sha256 = elf_pin, .config = @import("../../recursion/blake3_execution_parent_protocol.zig").CSP_CONFIG, .incoming = incoming, .outgoing = outgoing, .trusted_window = .{ .elf_sha256 = elf_pin, .incoming_sha256 = incoming_pin, .outgoing_sha256 = outgoing_pin, .window = span } }, .{ .source = .{ .batch_native_projections = std.posix.getenv("STWO_B8_GROUP_BUNDLE_NATIVE_BATCH") != null, .profile = profile, .max_cycles = if (profile == .compact_v1) 1 << 22 else 1 << 24, .cohort_cycles = cohort_cycles, .max_retained_endpoint_bytes = 16 << 30 } });
    const producer_call_ns = call.read();
    const Artifact = struct { name: []const u8, bytes: u64, sha256: [64]u8 };
    var manifest: std.ArrayList(Artifact) = .empty;
    defer {
        for (manifest.items) |entry| a.free(entry.name);
        manifest.deinit(a);
    }
    var entries = artifacts.iterate();
    while (try entries.next()) |entry| {
        if (entry.kind != .file) return error.UnexpectedGroupArtifactEntry;
        const bytes = try artifacts.readFileAlloc(a, entry.name, 128 << 20);
        defer a.free(bytes);
        const name = try a.dupe(u8, entry.name);
        errdefer a.free(name);
        try manifest.append(a, .{ .name = name, .bytes = bytes.len, .sha256 = std.fmt.bytesToHex(Capture.sha(bytes), .lower) });
    }
    const Ordering = struct {
        fn less(_: void, l: Artifact, r: Artifact) bool {
            return std.mem.lessThan(u8, l.name, r.name);
        }
    };
    std.mem.sort(Artifact, manifest.items, {}, Ordering.less);
    const report = try std.json.Stringify.valueAlloc(a, .{ .schema = "stwo-b8-group-compact-global-original-bundle-benchmark-v1", .scope = "declared nonterminal native-only window, one Group plus late same-root bridge and compact global original, freshly file-verified once per Group; NOT a recursive root or complete Ethereum block", .group_profile = profile, .security_queries = 70, .security_pow_bits = 26, .workers = workers, .window = span, .cohort_cycles = cohort_cycles, .loading_ns = loading_ns, .producer_call_ns = producer_call_ns, .stats = result.stats, .verified = result.verified, .artifacts = manifest.items, .charged_peak_including_publication_bytes = budget.snapshot().peak_live_bytes, .whole_including_loading_and_publication_ns = whole.read() }, .{ .whitespace = .indent_2 });
    defer a.free(report);
    try output.writeFile(.{ .sub_path = "report.json", .data = report });
}
