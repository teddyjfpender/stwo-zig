//! Explicit pinned real-window benchmark, inactive unless requested. Input
//! loading and proof/verification are distinct. No skipped-prefix claim.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Run = @import("../block_v8_endpoint_group_execution_v1.zig");
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
test "real shared group original performance benchmark" {
    if (std.posix.getenv("STWO_B8_GROUP_ENABLE") == null) return error.SkipZigTest;
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 48 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var whole = try std.time.Timer.start();
    var timer = try std.time.Timer.start();
    const elf = try std.fs.cwd().readFileAlloc(a, std.posix.getenv("STWO_B8_GROUP_ELF") orelse return error.MissingEndpointBenchmarkInput, 32 << 20);
    defer a.free(elf);
    const incoming_bytes = try std.fs.cwd().readFileAlloc(a, std.posix.getenv("STWO_B8_GROUP_INCOMING") orelse return error.MissingEndpointBenchmarkInput, 256 << 20);
    defer a.free(incoming_bytes);
    const outgoing_bytes = try std.fs.cwd().readFileAlloc(a, std.posix.getenv("STWO_B8_GROUP_OUTGOING") orelse return error.MissingEndpointBenchmarkInput, 256 << 20);
    defer a.free(outgoing_bytes);
    const incoming_pin = try digest("STWO_B8_GROUP_INCOMING_SHA256");
    const outgoing_pin = try digest("STWO_B8_GROUP_OUTGOING_SHA256");
    var incoming = try Capture.Snapshot.decode(a, incoming_bytes, incoming_pin, .{});
    defer incoming.deinit(a);
    var outgoing = try Capture.Snapshot.decode(a, outgoing_bytes, outgoing_pin, .{});
    defer outgoing.deinit(a);
    const loading_ns = timer.lap();
    const workers = try number(usize, "STWO_B8_GROUP_WORKERS", 8);
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = workers, .backing_allocator = a });
    defer pool.deinit();
    const span = Capture.Window{ .skip_cycles = try number(u64, "STWO_B8_GROUP_SKIP", 0), .cycles = try number(u32, "STWO_B8_GROUP_CYCLES", 1 << 22) };
    const elf_pin = try digest("STWO_B8_GROUP_ELF_SHA256");
    var output = try std.fs.cwd().openDir(std.posix.getenv("STWO_B8_GROUP_OUTPUT") orelse return error.MissingEndpointBenchmarkOutput, .{});
    defer output.close();
    var producer_call = try std.time.Timer.start();
    const result = try Run.run(budget, &pool, .{ .elf = elf, .elf_sha256 = elf_pin, .config = @import("../../recursion/blake3_execution_parent_protocol.zig").CSP_CONFIG, .incoming = incoming, .outgoing = outgoing, .trusted_window = .{ .elf_sha256 = elf_pin, .incoming_sha256 = incoming_pin, .outgoing_sha256 = outgoing_pin, .window = span } }, .{ .cohort_cycles = try number(u32, "STWO_B8_GROUP_COHORT_CYCLES", 1 << 19), .max_retained_endpoint_bytes = 4 << 30 });
    defer result.deinit();
    const producer_call_ns = producer_call.read();
    try output.writeFile(.{ .sub_path = "group.proof", .data = result.proof_bytes });
    try output.writeFile(.{ .sub_path = "group.json", .data = result.metadata_bytes });
    const report = try std.json.Stringify.valueAlloc(a, .{
        .schema = "stwo-b8-shared-group-original-benchmark-v1",
        .scope = "declared native-only nonterminal execution window; one Group original freshly verified once; endpoint global RAM remains OPEN; not a root or complete Ethereum block",
        .security_queries = 70,
        .security_pow_bits = 26,
        .window = span,
        .workers = workers,
        .loading_ns = loading_ns,
        .producer_call_ns = producer_call_ns,
        .stats = result.stats,
        .proof_sha256 = std.fmt.bytesToHex(Capture.sha(result.proof_bytes), .lower),
        .elf_sha256 = std.fmt.bytesToHex(elf_pin, .lower),
        .incoming_sha256 = std.fmt.bytesToHex(incoming_pin, .lower),
        .outgoing_sha256 = std.fmt.bytesToHex(outgoing_pin, .lower),
        .charged_peak_including_publication_bytes = budget.snapshot().peak_live_bytes,
        .whole_including_loading_and_publication_ns = whole.read(),
        .verified_once = true,
        .endpoint_sources = result.verified.summary.sources,
    }, .{ .whitespace = .indent_2 });
    defer a.free(report);
    try output.writeFile(.{ .sub_path = "report.json", .data = report });
}
