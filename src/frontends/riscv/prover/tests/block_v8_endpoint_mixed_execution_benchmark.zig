//! Opt-in captured Ethereum window original; global RAM and recursion OPEN.
const std = @import("std");
const E = @import("stwo_prover_engine");
const Capture = @import("../block_v7_real_window_capture_v1.zig");
const Source = @import("../block_v8_endpoint_mixed_execution_v1.zig");
const Proof = @import("../block_v8_endpoint_mixed_proof_v1.zig");
const Codec = @import("../block_v8_endpoint_mixed_codec_v1.zig");
const Metadata = @import("../block_v8_endpoint_mixed_statement_wire_v1.zig");
fn number(comptime T: type, name: [:0]const u8, default: T) !T {
    return std.fmt.parseInt(T, std.posix.getenv(name) orelse return default, 10);
}
fn pin(name: [:0]const u8) ![32]u8 {
    const text = std.posix.getenv(name) orelse return error.MissingMixedBenchmarkPin;
    if (text.len != 64) return error.InvalidMixedBenchmarkPin;
    var out: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&out, text);
    return out;
}
fn path(name: [:0]const u8) ![]const u8 {
    return std.posix.getenv(name) orelse error.MissingMixedBenchmarkInput;
}
test "real mixed endpoint original benchmark" {
    if (std.posix.getenv("STWO_B8_MIXED_ENABLE") == null) return error.SkipZigTest;
    // Production allocator is intentional; leak checking stays in proof fixtures.
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 48 << 30);
    defer budget.destroy();
    const a = budget.allocator();
    var whole = try std.time.Timer.start();
    var phase = try std.time.Timer.start();
    const elf = try std.fs.cwd().readFileAlloc(a, try path("STWO_B8_MIXED_ELF"), 32 << 20);
    defer a.free(elf);
    const in_bytes = try std.fs.cwd().readFileAlloc(a, try path("STWO_B8_MIXED_INCOMING"), 256 << 20);
    defer a.free(in_bytes);
    const out_bytes = try std.fs.cwd().readFileAlloc(a, try path("STWO_B8_MIXED_OUTGOING"), 256 << 20);
    defer a.free(out_bytes);
    const in_pin = try pin("STWO_B8_MIXED_INCOMING_SHA256");
    const out_pin = try pin("STWO_B8_MIXED_OUTGOING_SHA256");
    const elf_pin = try pin("STWO_B8_MIXED_ELF_SHA256");
    var incoming = try Capture.Snapshot.decode(a, in_bytes, in_pin, .{});
    defer incoming.deinit(a);
    var outgoing = try Capture.Snapshot.decode(a, out_bytes, out_pin, .{});
    defer outgoing.deinit(a);
    const loading_ns = phase.lap();
    const workers = try number(usize, "STWO_B8_MIXED_WORKERS", 8);
    if (workers == 0 or workers > 64) return error.InvalidMixedBenchmarkWorkers;
    var pool: E.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = workers, .backing_allocator = a });
    defer pool.deinit();
    var binding = try E.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const window = Capture.Window{ .skip_cycles = try number(u64, "STWO_B8_MIXED_SKIP", 0), .cycles = try number(u32, "STWO_B8_MIXED_CYCLES", 131072) };
    const config = @import("../../recursion/blake3_execution_parent_protocol.zig").CSP_CONFIG;
    const FullBoundary = @import("../block_v8_full_boundary_policy_v1.zig");
    var full_boundary = try FullBoundary.fromEnvironment(a, elf, elf_pin, config);
    defer if (full_boundary) |*value| value.deinit();
    const boundary_options = if (full_boundary) |*value| try value.windowOptions(window.skip_cycles, window.cycles) else @import("../block_v8_execution_boundary_ports_v1.zig").Options{};
    const boundary_preparation_ns = phase.lap();
    if (std.posix.getenv("STWO_B8_MIXED_COMPLETE_BUNDLE")) |complete| if (std.mem.eql(u8, complete, "1")) {
        const Pipeline = @import("../block_v8_endpoint_mixed_pipeline_v1.zig");
        var output = try std.fs.cwd().openDir(try path("STWO_B8_MIXED_OUTPUT"), .{});
        defer output.close();
        try output.makeDir("artifacts");
        var artifacts = try output.openDir("artifacts", .{ .iterate = true });
        defer artifacts.close();
        const native_wide = if (std.posix.getenv("STWO_B8_MIXED_NATIVE_WIDE")) |value| std.mem.eql(u8, value, "1") else false;
        const result = try Pipeline.produceDirectory(a, .{ .elf = elf, .elf_sha256 = elf_pin, .config = config, .incoming = incoming, .outgoing = outgoing, .trusted_window = .{ .elf_sha256 = elf_pin, .incoming_sha256 = in_pin, .outgoing_sha256 = out_pin, .window = window } }, artifacts, .{
            .source = .{ .boundary = boundary_options, .native_wide_shards = native_wide, .max_cycles = try number(u32, "STWO_B8_MIXED_MAX_CYCLES", 1 << 20), .caller = .{ .max_live_bytes = try number(usize, "STWO_B8_MIXED_CALLER_BYTES", 4 << 30) } },
        });
        const report = try std.json.Stringify.valueAlloc(a, .{ .schema = "stwo-b8-real-mixed-complete-bundle-benchmark-v1", .scope = "declared native/caller window with fresh original bridge and compact-memory closure; recursion OPEN", .allocator = "std.heap.smp_allocator", .cpu_only = true, .security_queries = config.fri_config.n_queries, .security_pow_bits = config.pow_bits, .window = window, .workers = workers, .native_wide_shards = native_wide, .initial_boundary = boundary_options.initial != null, .terminal_boundary = boundary_options.terminal != null, .loading_ns = loading_ns, .boundary_preparation_ns = boundary_preparation_ns, .stages = result.stats, .whole_ns = whole.read(), .charged_peak_bytes = budget.snapshot().peak_live_bytes, .verified = result.verified }, .{ .whitespace = .indent_2 });
        defer a.free(report);
        try output.writeFile(.{ .sub_path = "report.json", .data = report });
        return;
    };
    if (!boundary_options.isEmpty()) return error.FullBoundaryRequiresCompleteMixedBundle;
    const source = try Source.Owned.init(a, .{ .elf = elf, .elf_sha256 = elf_pin, .config = config, .incoming = incoming, .outgoing = outgoing, .trusted_window = .{ .elf_sha256 = elf_pin, .incoming_sha256 = in_pin, .outgoing_sha256 = out_pin, .window = window } }, .{});
    var source_live = true;
    defer if (source_live) source.deinit();
    const source_ns = phase.lap();
    const preparation = source.stats;
    const profiled = if (std.posix.getenv("STWO_B8_MIXED_PROFILE")) |value| std.mem.eql(u8, value, "1") else false;
    var recorder = E.stage_profile.Recorder.initWithOptions(a, "cpu", "real-mixed-window", .{ .capture_tasks = false, .capture_work = false });
    defer recorder.deinit();
    var timing: Proof.Timings = .{};
    const batch_native = if (std.posix.getenv("STWO_B8_MIXED_BATCH_NATIVE")) |value| std.mem.eql(u8, value, "1") else false;
    const original = try Proof.produceWithOptions(a, source.trusted, source.input(), source.current.?.owner.preprocessed.items, source.stages(), .{}, .{ .program = &source.image.?, .timings = &timing, .recorder = if (profiled) &recorder else null, .batch_native_projections = batch_native });
    var original_live = true;
    defer if (original_live) original.deinit();
    const original_ns = phase.lap();
    var input = source.input();
    input.native_roots = original.native_roots;
    input.caller_roots = original.caller_roots;
    var external = source.trusted;
    external.elf = elf;
    const statement = try Metadata.encode(a, external, input, .{});
    defer a.free(statement);
    const bytes = try Codec.encode(a, original, external, input, .{});
    defer a.free(bytes);
    const encoding_ns = phase.lap();
    const expected = original.summary;
    const census = source.caller.?.witness.statement;
    original.deinit();
    original_live = false;
    source.deinit();
    source_live = false;
    const release_ns = phase.lap();
    const public = try Metadata.decode(a, statement, external, .{});
    defer public.deinit();
    const metadata_admission_ns = phase.lap();
    const received = try Codec.verifyBytes(a, bytes, public.trusted, public.input, .{});
    const verification_ns = phase.lap();
    if (!std.meta.eql(expected, received)) return error.MixedBenchmarkVerificationMismatch;
    var output = try std.fs.cwd().openDir(try path("STWO_B8_MIXED_OUTPUT"), .{});
    defer output.close();
    try output.makeDir("artifacts");
    var dir = try output.openDir("artifacts", .{ .iterate = true });
    defer dir.close();
    var iter = dir.iterate();
    if (try iter.next() != null) return error.NonemptyMixedBenchmarkOutput;
    try dir.writeFile(.{ .sub_path = "original.proof", .data = bytes });
    try dir.writeFile(.{ .sub_path = "source.json", .data = statement });
    const publication_ns = phase.lap();
    var profile = if (profiled) try recorder.snapshot(a) else null;
    defer if (profile) |*value| value.deinit(a);
    const report = try std.json.Stringify.valueAlloc(a, .{ .schema = "stwo-b8-real-mixed-original-benchmark-v1", .scope = "declared nonterminal captured native/caller original; global RAM and recursion OPEN; no skipped-prefix or full-block proof", .allocator = "std.heap.smp_allocator", .profiled = profiled, .batch_native_projections = batch_native, .core_profile = profile, .cpu_only = true, .security_queries = config.fri_config.n_queries, .security_pow_bits = config.pow_bits, .window = window, .workers = workers, .program_flavor = "sparse_elf", .loading_ns = loading_ns, .source_preparation_ns = source_ns, .preparation = preparation, .original_ns = original_ns, .original = timing, .encoding_ns = encoding_ns, .producer_release_ns = release_ns, .metadata_admission_ns = metadata_admission_ns, .verification_ns = verification_ns, .publication_ns = publication_ns, .whole_ns = whole.read(), .charged_peak_bytes = budget.snapshot().peak_live_bytes, .proof_bytes = bytes.len, .proof_sha256 = std.fmt.bytesToHex(Capture.sha(bytes), .lower), .metadata_bytes = statement.len, .metadata_sha256 = std.fmt.bytesToHex(Capture.sha(statement), .lower), .caller_statement = census, .verified = received }, .{ .whitespace = .indent_2 });
    defer a.free(report);
    try output.writeFile(.{ .sub_path = "report.json", .data = report });
}
