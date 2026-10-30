//! Explicit pinned real-window benchmark, inactive unless requested. Input
//! loading and proof/verification are distinct. No skipped-prefix claim.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Run = @import("../block_v8_endpoint_execution_v1.zig");
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
test "real native endpoint-only window performance benchmark" {
    if (std.posix.getenv("STWO_B8_WINDOW_ENABLE") == null) return error.SkipZigTest;
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 48 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var whole = try std.time.Timer.start();
    var timer = try std.time.Timer.start();
    const elf = try std.fs.cwd().readFileAlloc(a, std.posix.getenv("STWO_B8_WINDOW_ELF") orelse return error.MissingEndpointBenchmarkInput, 32 << 20);
    defer a.free(elf);
    const incoming_bytes = try std.fs.cwd().readFileAlloc(a, std.posix.getenv("STWO_B8_WINDOW_INCOMING") orelse return error.MissingEndpointBenchmarkInput, 256 << 20);
    defer a.free(incoming_bytes);
    const outgoing_bytes = try std.fs.cwd().readFileAlloc(a, std.posix.getenv("STWO_B8_WINDOW_OUTGOING") orelse return error.MissingEndpointBenchmarkInput, 256 << 20);
    defer a.free(outgoing_bytes);
    const incoming_pin = try digest("STWO_B8_WINDOW_INCOMING_SHA256");
    const outgoing_pin = try digest("STWO_B8_WINDOW_OUTGOING_SHA256");
    var incoming = try Capture.Snapshot.decode(a, incoming_bytes, incoming_pin, .{});
    defer incoming.deinit(a);
    var outgoing = try Capture.Snapshot.decode(a, outgoing_bytes, outgoing_pin, .{});
    defer outgoing.deinit(a);
    const loading_ns = timer.lap();
    const workers = try number(usize, "STWO_B8_WINDOW_WORKERS", 8);
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = workers, .backing_allocator = a });
    defer pool.deinit();
    const span = Capture.Window{ .skip_cycles = try number(u64, "STWO_B8_WINDOW_SKIP", 0), .cycles = try number(u32, "STWO_B8_WINDOW_CYCLES", 1 << 22) };
    const elf_pin = try digest("STWO_B8_WINDOW_ELF_SHA256");
    const result = try Run.run(budget, &pool, .{ .elf = elf, .elf_sha256 = elf_pin, .config = @import("../../recursion/blake3_execution_parent_protocol.zig").CSP_CONFIG, .incoming = incoming, .outgoing = outgoing, .trusted_window = .{ .elf_sha256 = elf_pin, .incoming_sha256 = incoming_pin, .outgoing_sha256 = outgoing_pin, .window = span } }, .{});
    var result_live = true;
    defer if (result_live) result.deinit();
    var output = try std.fs.cwd().openDir(std.posix.getenv("STWO_B8_WINDOW_OUTPUT") orelse return error.MissingEndpointBenchmarkOutput, .{});
    defer output.close();
    timer.reset();
    const codec_limits = @import("../block_v8_endpoint_whole_codec_v1.zig").Limits{ .original = (Run.Options{}).proof };
    const proof = try @import("../block_v8_endpoint_whole_codec_v1.zig").encode(a, result.proof, result.statement.trusted, result.statement.input, codec_limits);
    defer a.free(proof);
    const metadata = try @import("../block_v8_endpoint_whole_statement_wire_v1.zig").encode(a, result.statement.trusted, result.statement.input, .{});
    defer a.free(metadata);
    const artifact_encoding_ns = timer.lap();
    const stats = result.stats;
    const summary = result.proof.summary;
    const config = result.proof.stark.commitment_scheme_proof.config;
    result.deinit();
    result_live = false;
    const producer_result_release_ns = timer.lap();
    const detached = try @import("../block_v8_endpoint_whole_loader_v1.zig").admitMetadata(a, metadata, .{ .elf = elf, .incoming = incoming, .outgoing = outgoing, .trusted = .{ .elf_sha256 = elf_pin, .incoming_sha256 = incoming_pin, .outgoing_sha256 = outgoing_pin, .window = span }, .config = config }, .{});
    defer detached.deinit();
    const metadata_admission_ns = timer.lap();
    const verified = try @import("../block_v8_endpoint_whole_codec_v1.zig").verifyBytes(a, proof, detached.trusted, detached.input, codec_limits);
    try std.testing.expectEqualDeep(summary, verified);
    const artifact_verification_ns = timer.lap();
    try output.writeFile(.{ .sub_path = "original.proof", .data = proof });
    try output.writeFile(.{ .sub_path = "public-metadata.json", .data = metadata });
    const artifact_write_ns = timer.lap();
    const report = try std.json.Stringify.valueAlloc(a, .{ .schema = "stwo-b8-native-endpoint-window-benchmark-v1", .scope = "experimental nonterminal native-only original STARK; no skipped-prefix proof and no recursive root", .security_queries = config.fri_config.n_queries, .security_pow_bits = config.pow_bits, .layout_version = @import("../block_v8_native_endpoint_layout_v1.zig").VERSION, .window = span, .workers = workers, .loading_ns = loading_ns, .stats = stats, .artifact_encoding_ns = artifact_encoding_ns, .producer_result_release_ns = producer_result_release_ns, .metadata_admission_ns = metadata_admission_ns, .artifact_verification_ns = artifact_verification_ns, .artifact_write_ns = artifact_write_ns, .charged_peak_bytes = budget.snapshot().peak_live_bytes, .proof_bytes = proof.len, .proof_sha256 = std.fmt.bytesToHex(Capture.sha(proof), .lower), .metadata_sha256 = std.fmt.bytesToHex(Capture.sha(metadata), .lower), .whole_including_loading_and_publication_ns = whole.read(), .verified = verified }, .{ .whitespace = .indent_2 });
    defer a.free(report);
    try output.writeFile(.{ .sub_path = "report.json", .data = report });
}
